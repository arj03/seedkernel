// loop.go — the Go-owned JavaScript event loop.
//
// QuickJS cannot drive I/O and wazero is single-threaded, so Go owns the loop: it holds
// the timer heap, pumps the JS job queue, and re-enters JS only to deliver an event (a
// fired timer, a socket frame) before pumping so the resulting promise reactions run.
// quickjs's own os.setTimeout is overridden with Go-backed timers, so js_std_loop never
// has an os timer to block on (see qjs.Context.Pump) — which is what lets the shared host
// JS run unmodified instead of being re-implemented in Go.
//
// Threading: every QuickJS call happens on the one goroutine running the loop. Other
// goroutines (socket readers) hand work in via post(). Timers are touched only from JS
// callbacks, which already run on that goroutine, so the heap needs no lock.
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

	// extra contexts pumped alongside el.c — a confined guest realm sharing this loop, so
	// a net result settling on the host realm can resume the guest. A guest realm supplies
	// a pump that runs under its execution budget (guestRealm.pump) rather than the bare
	// Context.Pump: a continuation queued by a plain `await` is guest code like any other.
	extra []pumpEntry

	// awaitIn installs one persistent __settle per context (tracked here) routing into the
	// in-flight await's onSettle. A fresh JS function per await would leak — the callback
	// registry has no unregister — and retain its result payload.
	settleInstalled map[*qjs.Context]bool
	onSettle        func(kind int, bytes []byte, msg string)

	// runGen tags each bounded run (awaitIn / runUntilSignal). A safety timer captures the
	// gen it was armed under, so a late fire after a new run began is ignored.
	runGen int64

	// stepTimer is step()'s single reusable wait timer, Reset per turn — a fresh
	// time.NewTimer each time was per-frame GC churn in the tight pump loop.
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

// newEventLoop binds a loop to a QuickJS context and installs the setTimeout/clearTimeout
// surface the shared JS expects, which only a Go-owned loop can back.
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
// reaction in that realm runs as part of this loop. A guest realm uses native Promises
// only, so it needs no separate loop — just its job queue drained. pump nil means a bare
// Context.Pump; a guest realm passes its budget-guarded one.
func (el *eventLoop) addContext(c *qjs.Context, pump func()) {
	if pump == nil {
		pump = func() { _ = c.Pump() }
	}
	el.extra = append(el.extra, pumpEntry{c: c, pump: pump})
}

// removeContext drops a context registered with addContext, so pumpAll stops touching it
// once its realm is closed. A no-op for a context that was never added.
func (el *eventLoop) removeContext(c *qjs.Context) {
	delete(el.settleInstalled, c) // its __settle dies with the realm's runtime
	for i, x := range el.extra {
		if x.c == c {
			el.extra = append(el.extra[:i], el.extra[i+1:]...)
			return
		}
	}
}

// pumpAll drains the job queue of el.c and every registered extra context. el.c goes
// first, so a host job that schedules a guest job runs it in the same round.
//
// The REVERSE direction deliberately does not fit in one round: a guest job that schedules
// a host job — which every parked `host.call` does — queues it after el.c has drained, so
// it waits for the next round and something has to schedule one (__host_call wakes the
// loop for exactly that, see guest.go). Ordering the pumps the other way only moves the
// problem, and looping to a fixpoint would need a "did any queue advance" signal
// qjs.Context.Pump does not report.
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
	// Installed once, so repeated runUntilSignal calls register no fresh callback.
	g.SetPropertyStr("__signal", el.c.Function(func(t *qjs.This) (*qjs.Value, error) {
		el.stopped = true
		return nil, nil
	}))
	// queueMicrotask is not loop state but a missing Web global, so it lives with the rest
	// of them in host/native-polyfills.ts.
}

// post hands a closure to the loop goroutine. Safe to call from any goroutine.
func (el *eventLoop) post(fn func()) { el.tasks <- fn }

// wake nudges the loop into another pump round.
//
// With no timer and no deadline, step() blocks in its select and pumps only after a timer
// fires or a task arrives. A microtask queued *during* a pump — a host callback settling a
// JS promise after the drain loop passed it — therefore sits there until something else
// wakes the loop, which to a caller awaiting that promise looks exactly like a hang. So
// anything settling a promise from Go outside a task/timer path has to call this.
//
// Non-blocking on purpose: safe from the loop goroutine itself, and a full buffer means
// the loop already has work and will pump regardless.
func (el *eventLoop) wake() {
	select {
	case el.tasks <- func() {}:
	default:
	}
}

// armTimer (re)arms the loop's single reusable wait timer for duration d. step() runs only
// on the loop goroutine and never re-entrantly, so one shared timer is safe, and Go 1.23+
// timer semantics make Stop/Reset safe without the drain dance.
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

// step drives one turn of the loop: fire every due timer (pumping after each), drain ready
// microtasks, then — if `until` is still unmet — block until a posted task arrives, the
// next timer comes due, or `deadline` passes, and process it. `pump` selects which realms
// advance; run() passes pumpAll, which is how a net result settling on the host realm
// resumes a suspended guest. A zero `deadline` blocks only on tasks/timers, and `until` is
// checked between sub-steps so a caller's exit condition short-circuits promptly.
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
	// Drain ready microtasks before blocking on I/O — e.g. a settled __settle from a
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
	// Drain whatever else is already queued, pumping after each. Two reasons: a burst of
	// posted socket frames is delivered in this one turn rather than one per step() (each
	// turn otherwise re-scans timers and rebuilds the select); and a result that raced
	// <-wait (select picks at random when both are ready) is processed now instead of
	// sitting until the next turn, which would make awaitIn report a false timeout.
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

// run drives the loop on the current goroutine until stopped, one step() per turn, pumping
// every realm. awaitIn and runUntilSignal set up an exit signal that flips el.stopped and
// then drive the loop through here.
func (el *eventLoop) run() {
	for !el.stopped {
		el.step(time.Time{}, el.pumpAll, func() bool { return el.stopped })
	}
}

// armSafety arms a gen-guarded safety timer for the current run: onFire runs on the loop
// goroutine after timeout, but only if no newer run has bumped runGen (Stop cannot
// unschedule an already-fired AfterFunc, so its closure may still be queued in el.tasks)
// and only if this run has not already completed — so a stale timeout can neither abort
// the next run nor clobber a result a late settle just delivered.
func (el *eventLoop) armSafety(timeout time.Duration, onFire func()) (stop func() bool) {
	el.runGen++
	gen := el.runGen
	safety := time.AfterFunc(timeout, func() {
		el.post(func() {
			if el.runGen == gen && !el.stopped {
				onFire()
			}
		})
	})
	return safety.Stop
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
		defer el.armSafety(timeout, func() { el.stopped = true })()
	}
	el.run()
	return nil
}

// await evaluates an async JS expression in the loop's primary context (el.c) and
// drives the loop until it settles. See awaitIn.
func (el *eventLoop) await(callExpr string, timeout time.Duration) (kind int, value []byte, msg string, err error) {
	return el.awaitIn(el.c, callExpr, timeout)
}

// ensureSettle lazily installs context c's persistent __settle resolver — the hook
// awaitIn's wrapped promise calls — routing into el.onSettle, the in-flight await's result
// sink. A settle with no await in flight (a late promise after a timeout) is ignored.
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

// awaitIn evaluates an async JS expression in context c and drives the whole loop until it
// settles: kind 0 (fulfilled, with the resolved bytes) or kind 1 (rejected, with the error
// string), with timeout as a safety net. c may be the host realm or a guest realm — either
// way every realm is pumped, so a guest awaiting net is resumed by the host's socket I/O.
//
// NOT re-entrant: el.onSettle is a single shared slot the defer below resets to nil, so a
// nested awaitIn would orphan the outer await's result sink. The loader never nests it —
// a guest's net host.call settles through its own realm's callbacks (guest.go settleNet)
// and an initiator call through __callDone/__callFail, neither of which touches onSettle.
func (el *eventLoop) awaitIn(c *qjs.Context, callExpr string, timeout time.Duration) (kind int, value []byte, msg string, err error) {
	kind = -1
	el.ensureSettle(c)
	el.onSettle = func(k int, bytes []byte, m string) {
		kind, value, msg = k, bytes, m
		el.stopped = true
	}
	defer func() { el.onSettle = nil }() // release the in-flight result (and its payload)

	// The kick must NOT evaluate to a promise: QJS_Eval js_std_await()s a promise result,
	// blocking this goroutine inside the wasm call, and then the Go timer that would settle
	// a timeout can never run (deadlock). The IIFE makes the completion value undefined, so
	// QJS_Eval only drains ready jobs and returns control to the loop below.
	wrap := `(function(){ Promise.resolve(` + callExpr + `).then(` +
		`(v) => __settle(0, (v instanceof Uint8Array || v instanceof ArrayBuffer) ? v : new Uint8Array(0)),` +
		`(e) => __settle(1, String(e && e.message || e))); })();`
	el.stopped = false
	if _, err = c.Eval("<await>", qjs.Code(wrap)); err != nil {
		return
	}
	if !el.stopped && timeout > 0 {
		defer el.armSafety(timeout, func() {
			kind, msg, el.stopped = 2, "await: timed out", true
		})()
	}
	el.run()
	return
}
