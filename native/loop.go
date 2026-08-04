// loop.go — the Go-owned JavaScript event loop.
//
// QuickJS cannot drive I/O and wazero is single-threaded, so Go owns the loop:
// it holds the timer wheel, pumps the JS job queue, and only re-enters JS to
// deliver an event (a fired timer, a socket frame) — then pumps so the resulting
// promise reactions run. quickjs's own os.setTimeout is overridden with Go-backed
// timers, which means js_std_loop never has an os timer to block on (it just
// drains jobs and returns — see qjs.Context.Pump). This is what lets the shared
// host JS (transport-host.ts's driver, the transport bundle's guest program,
// the socket seams) run unmodified instead of being re-implemented in Go.
//
// Threading: all QuickJS calls happen on the one goroutine that runs the loop.
// Other goroutines (socket readers, in later phases) hand work in via post(),
// which the loop executes on its own goroutine before pumping. Timers are touched
// only from JS callbacks (setTimeout/clearTimeout), which already run on the loop
// goroutine, so the heap needs no lock.
package main

import (
	"container/heap"
	"fmt"
	"time"

	"seedloader/qjs"
)

type eventLoop struct {
	c       *qjs.Context
	timers  timerHeap
	byID    map[int64]*jsTimer
	nextID  int64
	tasks   chan func()
	stopped bool

	// extra contexts pumped alongside el.c (e.g. a confined guest realm sharing this
	// loop, so a net result that settles on the host realm can resume the guest).
	// Each entry pumps one registered context. A guest realm supplies a pump that runs
	// under its execution budget (guestRealm.pump) rather than the bare Context.Pump:
	// a continuation queued by a plain `await` is guest code like any other, and
	// pumping it directly would run it outside every budget the realm has — an escape
	// hatch worth exactly one `await Promise.resolve()`.
	extra []pumpEntry

	// awaitIn installs one persistent __settle per context (tracked here) that routes
	// into the in-flight await's onSettle, instead of creating — and leaking, since the
	// callback registry has no unregister — a fresh JS function (and retaining its result
	// payload) on every await.
	settleInstalled map[*qjs.Context]bool
	onSettle        func(kind int, bytes []byte, msg string)

	// runGen tags each bounded run (awaitIn / runUntilSignal). A safety timer captures
	// the gen it was armed under; if it fires late — after the run completed and a new
	// one began — its queued stop is ignored, so a stale timeout can't abort the next run.
	runGen int64

	// stepTimer is one reusable wait timer for step(); reused via Reset instead of a
	// fresh time.NewTimer per turn, which was per-frame GC churn in the tight pump loop.
	stepTimer *time.Timer
}

type jsTimer struct {
	id       int64
	deadline time.Time
	cb       *qjs.Value // a retained (Dup'd) JS callback; Free()d when fired or cleared
	index    int        // heap index, maintained by timerHeap
}

// timerHeap is a min-heap of pending timers ordered by deadline.
type timerHeap []*jsTimer

func (h timerHeap) Len() int           { return len(h) }
func (h timerHeap) Less(i, j int) bool { return h[i].deadline.Before(h[j].deadline) }
func (h timerHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *timerHeap) Push(x any)        { t := x.(*jsTimer); t.index = len(*h); *h = append(*h, t) }
func (h *timerHeap) Pop() any {
	old := *h
	n := len(old)
	t := old[n-1]
	old[n-1] = nil
	t.index = -1
	*h = old[:n-1]
	return t
}

// newEventLoop binds a loop to a QuickJS context and installs the timer surface the
// shared JS expects (setTimeout/clearTimeout), which only a Go-owned loop can back.
func newEventLoop(c *qjs.Context) *eventLoop {
	el := &eventLoop{c: c, byID: map[int64]*jsTimer{}, tasks: make(chan func(), 256), settleInstalled: map[*qjs.Context]bool{}}
	el.install()
	return el
}

// pumpEntry pairs a registered context with the func that drains it, so removeContext
// can still identify the entry by context while pumpAll goes through the realm's guard.
type pumpEntry struct {
	c    *qjs.Context
	pump func()
}

// addContext registers another QuickJS context to be pumped alongside el.c, so a promise
// reaction in that realm (e.g. a guest entrypoint's settling __settle) runs as part of
// this loop. The guest realm uses native Promises only (no Go timers), so it needs no
// separate loop — just its job queue drained. pump is how that draining happens: a guest
// realm passes its budget-guarded pump; anything else passes nil for a bare Pump.
func (el *eventLoop) addContext(c *qjs.Context, pump func()) {
	if pump == nil {
		pump = func() { _ = c.Pump() }
	}
	el.extra = append(el.extra, pumpEntry{c: c, pump: pump})
}

// removeContext drops a context registered with addContext, so pumpAll stops
// touching it once its realm is closed (guestRealm.close). Safe to call with a
// context that was never added — it's a no-op. Runs on the loop goroutine.
func (el *eventLoop) removeContext(c *qjs.Context) {
	delete(el.settleInstalled, c) // its __settle dies with the realm's runtime
	for i, x := range el.extra {
		if x.c == c {
			el.extra = append(el.extra[:i], el.extra[i+1:]...)
			return
		}
	}
}

// pumpAll drains the job queue of el.c and every registered extra context. A host
// job that schedules a guest job (e.g. resolving the guest entrypoint's promise) is
// pumped first (el.c) so that guest job runs in the same round.
//
// The REVERSE direction does not fit in one round and deliberately does not try to: a
// guest job that schedules a host job — which every parked `host.call` does, since the
// settlement is a host-realm `.then` — queues it after el.c has already been drained
// here. That job waits for the NEXT round, so something has to schedule one. __host_call
// wakes the loop whenever an op parks, which is exactly the case that would otherwise
// have nothing else coming (see guest.go). Ordering the pumps the other way would only
// move the problem, and looping to a fixpoint would need a "did any queue advance"
// signal that qjs.Context.Pump does not report.
func (el *eventLoop) pumpAll() {
	el.c.Pump()
	for _, x := range el.extra {
		x.pump()
	}
}

func (el *eventLoop) install() {
	g := el.c.Global()
	g.SetPropertyStr("setTimeout", el.c.Function(func(t *qjs.This) (*qjs.Value, error) {
		args := t.Args()
		if len(args) < 1 {
			return t.Context().NewInt64(0), nil
		}
		var ms int64
		if len(args) >= 2 {
			ms = args[1].Int64()
		}
		if ms < 0 {
			ms = 0
		}
		el.nextID++
		id := el.nextID
		tm := &jsTimer{id: id, deadline: time.Now().Add(time.Duration(ms) * time.Millisecond), cb: args[0].Dup()}
		heap.Push(&el.timers, tm)
		el.byID[id] = tm
		return t.Context().NewInt64(id), nil
	}))
	g.SetPropertyStr("clearTimeout", el.c.Function(func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 1 {
			return nil, nil
		}
		if tm, ok := el.byID[t.Args()[0].Int64()]; ok {
			heap.Remove(&el.timers, tm.index)
			delete(el.byID, tm.id)
			tm.cb.Free()
		}
		return nil, nil
	}))
	// __signal flips the loop's stop flag; runUntilSignal-driven flows call it from JS.
	// Installed once (it carries no per-call state) so repeated runUntilSignal calls
	// don't register a fresh callback each time.
	g.SetPropertyStr("__signal", el.c.Function(func(t *qjs.This) (*qjs.Value, error) {
		el.stopped = true
		return nil, nil
	}))
	// queueMicrotask is not installed here: it is not loop state but a missing Web
	// global, so it lives with the rest of them in polyfill.go — one polyfill per
	// global, installed on every realm the same way.
}

// post hands a closure to the loop goroutine. Safe to call from any goroutine.
func (el *eventLoop) post(fn func()) { el.tasks <- fn }

// wake nudges the loop into another pump round.
//
// step() blocks in its select with no wait channel when there is no timer and no
// deadline, and it only pumps after a timer fires, after a task arrives, or once before
// blocking. A microtask queued *during* a pump — a host callback settling a JS promise
// after the drain loop has already passed it — therefore sits unqueued-for until
// something else happens to wake the loop, which for a caller awaiting that promise
// looks exactly like a hang. Anything that settles a promise from Go outside a
// task/timer path has to nudge the loop; markDead is the case in point.
//
// Non-blocking on purpose: it is safe to call from the loop goroutine itself, and a full
// buffer means the loop already has work and will pump regardless.
func (el *eventLoop) wake() {
	select {
	case el.tasks <- func() {}:
	default:
	}
}

// armTimer (re)arms the loop's single reusable wait timer for duration d and returns
// its channel. step() runs only on the loop goroutine and never re-entrantly, so one
// shared timer is safe; reusing it via Reset avoids a fresh time.NewTimer allocation
// every turn (per-frame GC churn in the loop's tight pump). Go 1.23+ timer
// semantics make Stop/Reset safe without the drain dance.
func (el *eventLoop) armTimer(d time.Duration) <-chan time.Time {
	if el.stepTimer == nil {
		el.stepTimer = time.NewTimer(d)
	} else {
		el.stepTimer.Reset(d)
	}
	return el.stepTimer.C
}

// callJS invokes a retained JS callback with no arguments (timer / deferred work).
func (el *eventLoop) callJS(cb *qjs.Value) {
	if _, err := el.c.Invoke(cb, el.c.NewUndefined()); err != nil {
		fmt.Println("eventLoop: callback error:", err)
	}
}

// step drives one turn of the loop and returns. It fires every timer that is due
// (pumping after each), drains ready microtasks, then — if `until` is still unmet —
// blocks until a posted task arrives, the next timer comes due, or `deadline` passes,
// whichever is first, and processes it. `pump` selects which realms advance after a
// delivered task/timer — run() passes pumpAll so both host and guest realms advance,
// which is how a net result settling on the host realm resumes a suspended guest. A zero
// `deadline` means "no deadline" — block only on tasks/timers. `until` is checked between
// sub-steps so a caller's exit condition (el.stopped) short-circuits promptly.
func (el *eventLoop) step(deadline time.Time, pump func(), until func() bool) {
	// Fire every due timer, pumping after each so its reactions run before the next.
	for len(el.timers) > 0 && !el.timers[0].deadline.After(time.Now()) {
		t := heap.Pop(&el.timers).(*jsTimer)
		delete(el.byID, t.id)
		el.callJS(t.cb)
		t.cb.Free()
		pump()
		if until() {
			return
		}
	}
	// Drain any ready microtasks before blocking on I/O — e.g. a settled __settle from a
	// fully-synchronous guest entrypoint — so we don't wait for an event that won't come.
	pump()
	if until() {
		return
	}
	// Block until a posted task, the next timer, or the deadline — whichever is first.
	var wait <-chan time.Time
	d, hasWait := time.Duration(0), false
	if !deadline.IsZero() {
		d, hasWait = time.Until(deadline), true
	}
	if len(el.timers) > 0 {
		if td := time.Until(el.timers[0].deadline); !hasWait || td < d {
			d, hasWait = td, true
		}
	}
	if hasWait {
		if d < 0 {
			d = 0
		}
		wait = el.armTimer(d)
	}
	select {
	case task := <-el.tasks:
		task()
		pump()
	case <-wait:
	}
	if hasWait {
		el.stepTimer.Stop() // disarm (Go 1.23+ needs no drain); reused next turn via Reset
	}
	// Drain whatever else is already queued before returning, pumping after each. Two
	// reasons: a burst of posted socket frames is delivered in this one turn rather than
	// one per step() (each turn otherwise re-scans timers and rebuilds the select); and a
	// result that raced <-wait (select picks at random when a task is also ready) is
	// processed now instead of sitting until the next turn, which would make a bounded run
	// (awaitIn) report a false timeout. until() short-circuits so a satisfied caller exits promptly.
	for {
		if until() {
			return
		}
		select {
		case task := <-el.tasks:
			task()
			pump()
		default:
			return
		}
	}
}

// run drives the loop on the current goroutine until stopped, one step() per turn.
// It pumps every realm (pumpAll) so a net result settling on the host realm can resume
// a guest sharing this loop. awaitIn and runUntilSignal set up an exit signal that
// flips el.stopped, then drive the loop through here.
func (el *eventLoop) run() {
	for !el.stopped {
		el.step(time.Time{}, el.pumpAll, func() bool { return el.stopped })
	}
}

// runUntilSignal evaluates kick (which starts some event-driven JS activity) and
// then drives the loop until the JS calls __signal() or the safety timeout fires.
// Used to drive event-driven flows (a PeerLink handshake, the serve loop) that
// don't reduce to a single awaitable promise.
func (el *eventLoop) runUntilSignal(kick string, timeout time.Duration) error {
	el.stopped = false
	if _, err := el.c.Eval("<kick>", qjs.Code(kick)); err != nil {
		return err
	}
	if !el.stopped && timeout > 0 {
		el.runGen++
		gen := el.runGen
		// Tag the stop with this run's gen: a late fire (Stop can't unschedule an
		// already-fired AfterFunc, so its closure may sit queued in el.tasks) is ignored
		// once a newer run has bumped runGen, instead of aborting that run.
		safety := time.AfterFunc(timeout, func() {
			el.post(func() {
				if el.runGen == gen {
					el.stopped = true
				}
			})
		})
		defer safety.Stop()
	}
	el.run()
	return nil
}

// await evaluates an async JS expression in the loop's primary context (el.c) and
// drives the loop until it settles. See awaitIn.
func (el *eventLoop) await(callExpr string, timeout time.Duration) (kind int, value []byte, msg string, err error) {
	return el.awaitIn(el.c, callExpr, timeout)
}

// ensureSettle lazily installs context c's persistent __settle resolver — the JS hook
// awaitIn's wrapped promise calls. It routes into el.onSettle (the in-flight await's
// result sink), so each await reuses one callback instead of registering a fresh one;
// a settle that fires with no await in flight (a late promise after a timeout) is
// ignored. The entry is dropped in removeContext when a guest realm closes.
func (el *eventLoop) ensureSettle(c *qjs.Context) {
	if el.settleInstalled[c] {
		return
	}
	c.Global().SetPropertyStr("__settle", c.Function(func(t *qjs.This) (*qjs.Value, error) {
		if el.onSettle == nil {
			return nil, nil
		}
		a := t.Args()
		var bytes []byte
		var msg string
		if len(a) >= 2 {
			if b, e := qjs.JsTypedArrayToGo(a[1]); e == nil {
				bytes = b
			} else {
				msg = a[1].String()
			}
		}
		el.onSettle(int(a[0].Int64()), bytes, msg)
		return nil, nil
	}))
	el.settleInstalled[c] = true
}

// awaitIn evaluates an async JS expression in context c and drives the loop (pumping
// every registered context) until it settles: kind 0 (fulfilled, with the resolved
// Uint8Array/ArrayBuffer bytes) or kind 1 (rejected, with the error string). timeout
// bounds the wait as a safety net. c may be the host realm (a serve op) or a guest realm
// (runGuest) — either way the whole loop is driven, so a guest awaiting net is resumed by
// the host realm's socket I/O.
//
// It is NOT re-entrant: el.onSettle is a single shared slot, and the defer below
// resets it to nil (not a saved previous value), so a nested awaitIn would orphan the
// outer await's result sink. The loader never nests it — only one await is in flight at a
// time. A guest's net host.call settles through its own realm's callbacks (guest.go
// settleNet), and an initiator call through that realm's __callDone/__callFail — neither
// is a second awaitIn, so neither touches onSettle. The awaited expression's own promise
// is the one __settle reports here.
func (el *eventLoop) awaitIn(c *qjs.Context, callExpr string, timeout time.Duration) (kind int, value []byte, msg string, err error) {
	kind = -1
	el.ensureSettle(c)
	el.onSettle = func(k int, bytes []byte, m string) {
		kind, value, msg = k, bytes, m
		el.stopped = true
	}
	defer func() { el.onSettle = nil }() // release the in-flight result (and its payload)

	// The kick must NOT evaluate to a promise: QJS_Eval js_std_await()s a promise
	// result, which blocks this goroutine inside the wasm call — and then the Go
	// timer that would settle a timeout can never run (deadlock). Wrapping in an
	// IIFE makes the completion value undefined, so QJS_Eval only drains the ready
	// jobs and returns control to the Go-owned loop below.
	wrap := `(function(){ Promise.resolve(` + callExpr + `).then(` +
		`(v) => __settle(0, (v instanceof Uint8Array || v instanceof ArrayBuffer) ? v : new Uint8Array(0)),` +
		`(e) => __settle(1, String(e && e.message || e))); })();`
	el.stopped = false
	if _, err = c.Eval("<await>", qjs.Code(wrap)); err != nil {
		return
	}
	if !el.stopped && timeout > 0 {
		el.runGen++
		gen := el.runGen
		// gen-guarded so a late fire (Stop can't unschedule an already-fired AfterFunc)
		// can't flag a timeout on a later await that reused this loop — see runUntilSignal.
		safety := time.AfterFunc(timeout, func() {
			el.post(func() {
				if el.runGen == gen && !el.stopped {
					kind, msg, el.stopped = 2, "await: timed out", true
				}
			})
		})
		defer safety.Stop()
	}
	el.run()
	return
}
