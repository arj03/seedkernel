// loop.go — the Go-owned JavaScript event loop. QuickJS cannot drive I/O and wazero is
// single-threaded, so Go owns the loop: the timer heap, the JS job queue, and re-entry
// into JS to deliver an event. quickjs's own os.setTimeout is overridden with Go-backed
// timers, so js_std_loop has nothing to block on — which lets the shared host JS run
// unmodified. Every QuickJS call happens on the loop goroutine; socket readers hand work
// in via post(), so the timer heap needs no lock.
package main

import (
	"container/heap"
	"fmt"
	"os"
	"strconv"
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
	// a net result settling on the host realm can resume the guest. A guest realm's pump
	// runs under its execution budget (guestRealm.pump), since a plain `await` continuation
	// is guest code like any other.
	extra []pumpEntry

	// awaitIn installs one persistent __settle per context routing into the in-flight
	// await's onSettle; a fresh function per await would leak (no unregister).
	settleInstalled map[*qjs.Context]bool
	onSettle        func(kind int, bytes []byte, msg string)

	// awaitGen tags each awaitIn run and is the token its wrapped promise settles with.
	// Both of the ways a finished run can reach back into the next one read it: a safety
	// timer that already fired (Stop cannot unschedule an AfterFunc mid-flight), and the
	// abandoned promise of a timed-out await, which resolves into a __settle that is still
	// installed and would otherwise settle whichever await is now in flight.
	awaitGen int64

	// stepTimer is step()'s single reusable wait timer, Reset per turn — a fresh timer
	// per turn was per-frame GC churn in the tight pump loop.
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
// only, so it needs no separate loop — just its job queue drained. pump nil means bare
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

// pumpAll drains the job queue of el.c and every registered extra context, el.c first, so
// a host job that schedules a guest job runs it in the same round. The reverse direction
// deliberately does not fit in one round: every parked `host.call` queues a host job after
// el.c has drained, so something has to wake the loop (__host_call, see guest.go).
func (el *eventLoop) pumpAll() {
	el.c.Pump()
	for _, x := range el.extra {
		x.pump()
	}
}

func (el *eventLoop) install() {
	g := el.c.Global()
	// A monotonic clock, beside the timers that answer to it. The kernel's handoff deadlines
	// are distances between two readings (host/realm-queue.ts), which Date cannot supply:
	// a clock step backwards would fire every live deadline at once and a step forwards
	// would silently extend them. The epoch is this process, which is all a distance needs.
	// FRACTIONAL milliseconds, as Node and the browsers answer: deadlines are stated in whole
	// ones, but the seam meters host compute by the distance across one synchronous handler
	// (host/guest-seam.ts), and truncating each of those to zero would make an ed25519
	// verify — or a re-arm loop built out of them — free against the causal clock (§12.3).
	epoch := time.Now()
	perf := el.c.NewObject()
	perf.SetPropertyStr("now", el.c.Function(func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewFloat64(float64(time.Since(epoch).Nanoseconds()) / 1e6), nil
	}))
	g.SetPropertyStr("performance", perf)
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
	// queueMicrotask is not loop state but a missing Web global, so it lives with the rest
	// of them in host/native-polyfills.ts.
}

// post hands a closure to the loop goroutine. Safe to call from any goroutine.
func (el *eventLoop) post(fn func()) { el.tasks <- fn }

// wake nudges the loop into another pump round. With no timer and no deadline, step()
// blocks in its select, so a microtask queued *during* a pump sits there until something
// else wakes the loop — which to a caller awaiting that promise looks like a hang. Any
// Go-side promise settlement outside a task/timer path must call this. Non-blocking on
// purpose: safe from the loop goroutine, and a full buffer means work is already queued.
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
		fmt.Fprintln(os.Stderr, "eventLoop: callback error:", err)
	}
}

// step drives one turn of the loop: fire every due timer (pumping every realm after each),
// drain ready microtasks, then block until a posted task or the next timer — and process
// it. Every realm advances on every pump, which is how a net result settling on the host
// realm resumes a suspended guest.
func (el *eventLoop) step() {
	// Fire every due timer, pumping after each so its reactions run before the next.
	for len(el.timers) > 0 && !el.timers[0].deadline.After(time.Now()) {
		t := heap.Pop(&el.timers).(*jsTimer)
		delete(el.byID, t.id)
		el.callJS(t.cb)
		t.cb.Free()
		el.pumpAll()
		if el.stopped {
			return
		}
	}
	// Drain ready microtasks before blocking on I/O — e.g. a settled __settle from a
	// fully-synchronous guest entrypoint — so we don't wait for an event that won't come.
	el.pumpAll()
	if el.stopped {
		return
	}
	// Block until a posted task or the next timer, whichever comes first.
	var wait <-chan time.Time
	if len(el.timers) > 0 {
		d := time.Until(el.timers[0].deadline)
		if d < 0 {
			d = 0
		}
		wait = el.armTimer(d)
	}
	select {
	case task := <-el.tasks:
		task()
		el.pumpAll()
	case <-wait:
	}
	if wait != nil {
		el.stepTimer.Stop() // disarm (Go 1.23+ needs no drain); reused next turn via Reset
	}
	// Drain whatever else is already queued, pumping after each: a burst of posted socket
	// frames lands in this one turn instead of one per step(), and a result that raced
	// <-wait (select picks at random when both are ready) is processed now rather than
	// causing awaitIn to report a false timeout.
	for {
		if el.stopped {
			return
		}
		select {
		case task := <-el.tasks:
			task()
			el.pumpAll()
		default:
			return
		}
	}
}

// run drives the loop on the current goroutine until stopped, one step() per turn. Its
// callers set up an exit signal that flips el.stopped and then drive the loop through here.
func (el *eventLoop) run() {
	for !el.stopped {
		el.step()
	}
}

// armSafety arms a gen-guarded safety timer for the await now in flight: onFire runs on the
// loop goroutine only if no newer await has bumped awaitGen (Stop cannot unschedule an
// already-fired AfterFunc) and this one has not completed — so a stale timeout can neither
// abort the next await nor clobber a late settle.
func (el *eventLoop) armSafety(timeout time.Duration, onFire func()) (stop func() bool) {
	gen := el.awaitGen
	safety := time.AfterFunc(timeout, func() {
		el.post(func() {
			if el.awaitGen == gen && !el.stopped {
				onFire()
			}
		})
	})
	return safety.Stop
}

// await evaluates an async JS expression in the loop's primary context (el.c) and
// drives the loop until it settles. See awaitIn.
func (el *eventLoop) await(callExpr string, timeout time.Duration) (kind int, value []byte, msg string, err error) {
	return el.awaitIn(el.c, callExpr, timeout)
}

// ensureSettle lazily installs context c's persistent __settle resolver — the hook
// awaitIn's wrapped promise calls, carrying as its first argument the awaitGen it was
// written under — routing into el.onSettle. A settle with no await in flight is ignored,
// and so is one bearing any other token: the resolver outlives the await that wrote it, so
// a timed-out call whose promise lands during a later await must not settle that one.
func (el *eventLoop) ensureSettle(c *qjs.Context) {
	if el.settleInstalled[c] {
		return
	}
	c.Global().SetPropertyStr("__settle", c.Function(func(t *qjs.This) (*qjs.Value, error) {
		a := t.Args()
		if el.onSettle == nil || len(a) < 3 || a[0].Int64() != el.awaitGen {
			return nil, nil
		}
		var bytes []byte
		var msg string
		if b, e := qjs.JsTypedArrayToGo(a[2]); e == nil {
			bytes = b
		} else {
			msg = a[2].String()
		}
		el.onSettle(int(a[1].Int64()), bytes, msg)
		return nil, nil
	}))
	el.settleInstalled[c] = true
}

// awaitIn evaluates an async JS expression in context c and drives the whole loop until it
// settles: kind 0 (fulfilled, with the resolved bytes) or kind 1 (rejected, with the
// error string), with timeout as a safety net. c may be the host realm or a guest realm —
// either way every realm is pumped. Sequential awaits are isolated by awaitGen; nesting is
// not, since el.onSettle is a single shared slot and a nested awaitIn would orphan the
// outer await. The loader never nests it (a guest's net call settles through guest.go's own
// callbacks, which don't touch onSettle).
func (el *eventLoop) awaitIn(c *qjs.Context, callExpr string, timeout time.Duration) (kind int, value []byte, msg string, err error) {
	kind = -1
	el.ensureSettle(c)
	el.awaitGen++
	gen := strconv.FormatInt(el.awaitGen, 10)
	el.onSettle = func(k int, bytes []byte, m string) {
		kind, value, msg = k, bytes, m
		el.stopped = true
	}
	defer func() { el.onSettle = nil }() // release the in-flight result (and its payload)

	// The kick must NOT evaluate to a promise: QJS_Eval js_std_await()s it, blocking this
	// goroutine so a Go timer could never fire (deadlock). The IIFE makes the completion
	// value undefined, so QJS_Eval only drains ready jobs.
	wrap := `(function(){ Promise.resolve(` + callExpr + `).then(` +
		`(v) => __settle(` + gen + `, 0, (v instanceof Uint8Array || v instanceof ArrayBuffer) ? v : new Uint8Array(0)),` +
		`(e) => __settle(` + gen + `, 1, String(e && e.message || e))); })();`
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
