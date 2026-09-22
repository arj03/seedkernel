// loop.go — the Go-owned JavaScript event loop. QuickJS cannot drive I/O and wazero is
// single-threaded, so Go owns the loop: the timer heap, the JS job queue, and re-entry
// into JS to deliver an event. The engine has no timers of its own — setTimeout is Go's
// (install) — so draining the job queue never blocks, which lets the shared host JS run
// unmodified. Every QuickJS call happens on the loop goroutine; socket readers hand work
// in via post(), so the timer heap needs no lock.
package main

import (
	"container/heap"
	"fmt"
	"os"
	"strconv"
	"time"

	"seedkernel/qjs"
)

type eventLoop struct {
	c       *qjs.Context
	timers  timerHeap
	byID    map[int64]*jsTimer
	nextID  int64
	tasks   chan func()
	stopped bool

	// extra contexts pumped alongside el.c — a confined guest realm sharing this loop, so
	// a host-call result settling on the host realm can resume the guest. A guest realm's
	// pump runs under its execution budget (guestRealm.pump), since a plain `await`
	// continuation is guest code like any other.
	extra []pumpEntry

	// onSettle is the in-flight await's result sink, which install()'s persistent __settle
	// routes into; a fresh resolver per await would leak (no unregister).
	onSettle func(kind int, bytes []byte, msg string)

	// awaitGen tags each await run and is the token its wrapped promise settles with.
	// Both of the ways a finished run can reach back into the next one read it: a safety
	// timer that already fired (Stop cannot unschedule an AfterFunc mid-flight), and the
	// abandoned promise of a timed-out await, which resolves into a __settle that is still
	// installed and would otherwise settle whichever await is now in flight.
	awaitGen int64

	// stepTimer is step()'s single reusable wait timer, Reset per turn — a fresh timer
	// per turn was per-frame GC churn in the tight pump loop.
	stepTimer *time.Timer

	// err is a host-realm drain that failed: a job that threw, or a rejection nothing
	// handled (qjs.TrackRejections) — what ends a Node process. It stops the loop, and
	// whoever ran the loop reports it: await to its caller, main by exiting.
	err error
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
	el := &eventLoop{c: c, byID: map[int64]*jsTimer{}, tasks: make(chan func(), 256)}
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
// only, so it needs no separate loop — just its job queue drained, through the
// budget-guarded pump it hands over: a queued job is guest code (guestRealm.pump).
func (el *eventLoop) addContext(c *qjs.Context, pump func()) {
	el.extra = append(el.extra, pumpEntry{c: c, pump: pump})
}

// removeContext drops a context registered with addContext, so pumpAll stops touching it
// once its realm is closed. A no-op for a context that was never added.
func (el *eventLoop) removeContext(c *qjs.Context) {
	for i, x := range el.extra {
		if x.c == c {
			copy(el.extra[i:], el.extra[i+1:])
			el.extra[len(el.extra)-1] = pumpEntry{}
			el.extra = el.extra[:len(el.extra)-1]
			return
		}
	}
}

// pumpAll drains the job queue of el.c and every registered extra context, el.c first, so
// a host job that schedules a guest job runs it in the same round. The reverse direction
// deliberately does not fit in one round: every parked `host.call` queues a host job after
// el.c has drained, so something has to wake the loop (__host_call, see guest.go). A host
// drain that fails stops the loop (eventLoop.err); a guest realm's pump answers for its own.
func (el *eventLoop) pumpAll() {
	if err := el.c.Pump(); err != nil && el.err == nil {
		el.err = err
		el.stopped = true
	}
	for _, x := range el.extra {
		x.pump()
	}
}

func (el *eventLoop) install() {
	g := el.c.Global()
	g.SetPropertyStr("setTimeout", el.c.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
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
		return qc.NewInt64(id), nil
	}))
	g.SetPropertyStr("clearTimeout", el.c.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		if tm, ok := el.byID[args[0].Int64()]; ok {
			heap.Remove(&el.timers, tm.index)
			delete(el.byID, tm.id)
			tm.cb.Free()
		}
		return nil, nil
	}))
	// __settle is what an await's wrapped promise calls, carrying as its first argument the
	// awaitGen it was written under, and it routes into el.onSettle. A settle with no await
	// in flight is ignored, and so is one bearing any other token: the resolver outlives the
	// await that wrote it, so a timed-out call whose promise lands during a later await must
	// not settle that one.
	g.SetPropertyStr("__settle", el.c.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		if el.onSettle == nil || args[0].Int64() != el.awaitGen {
			return nil, nil
		}
		var bytes []byte
		var msg string
		if b, e := args[2].Bytes(); e == nil {
			bytes = b
		} else {
			msg = args[2].String()
		}
		el.onSettle(int(args[1].Int64()), bytes, msg)
		return nil, nil
	}))
	// The realm's other loop-adjacent globals are the engine's own: quickjs-ng defines
	// queueMicrotask, and a performance.now over the monotonic clock its WASI import answers
	// — sub-millisecond, which TestHostClockIsSubMillisecond pins and explains. Only the
	// timers need a Go-owned loop behind them.
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
	res, err := el.c.Invoke(cb, el.c.NewUndefined())
	res.Free()
	if err != nil {
		fmt.Fprintln(os.Stderr, "eventLoop: callback error:", err)
	}
}

// step drives one turn of the loop, phased as Node's is: the timers due when the turn
// began, then (after draining ready microtasks and blocking until a posted task or the
// next timer) the tasks queued by then. Each phase takes only what was ready as it began,
// so neither a timer that re-arms at zero delay nor a peer that keeps the queue full can
// hold the other phase off. Every realm advances on every pump, which is how a host-call
// result settling on the host realm resumes a suspended guest.
func (el *eventLoop) step() {
	// Fire the timers due now, pumping after each so its reactions run before the next.
	// One armed meanwhile waits for the next turn, however short its delay.
	now := time.Now()
	for len(el.timers) > 0 && !el.timers[0].deadline.After(now) {
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
	// Then the tasks already queued, pumping after each: a burst of socket frames lands in
	// this one turn, and what is posted meanwhile waits behind the next timer phase.
	for n := len(el.tasks); n > 0 && !el.stopped; n-- {
		task := <-el.tasks
		task()
		el.pumpAll()
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

// await evaluates an async JS expression in the host realm and drives the whole loop until
// it settles: kind 0 (fulfilled, with the resolved bytes) or kind 1 (rejected, with the
// error string), with timeout as a safety net. Every realm is pumped meanwhile, which is
// how a guest suspended on a host call resumes. Sequential awaits are isolated by awaitGen;
// nesting is not, since el.onSettle is a single shared slot and a nested await would orphan
// the outer one. The native host never nests it (a guest's net call settles through guest.go's
// own callbacks, which don't touch onSettle).
func (el *eventLoop) await(callExpr string, timeout time.Duration) (kind int, value []byte, msg string, err error) {
	kind = -1
	el.awaitGen++
	gen := strconv.FormatInt(el.awaitGen, 10)
	el.onSettle = func(k int, bytes []byte, m string) {
		kind, value, msg = k, bytes, m
		el.stopped = true
	}
	defer func() { el.onSettle = nil }() // release the in-flight result (and its payload)

	// The kick is an IIFE, so the eval's completion value is undefined and there is nothing
	// to free: the call's promise is reached only through the handlers it attaches, which
	// run when the loop pumps.
	wrap := `(function(){ Promise.resolve(` + callExpr + `).then(` +
		`(v) => __settle(` + gen + `, 0, (v instanceof Uint8Array || v instanceof ArrayBuffer) ? v : new Uint8Array(0)),` +
		`(e) => __settle(` + gen + `, 1, String(e && e.message || e))); })();`
	el.stopped = false
	if _, err = el.c.Eval("<await>", wrap); err != nil {
		return
	}
	if timeout > 0 {
		defer el.armSafety(timeout, func() {
			kind, msg, el.stopped = 2, "await: timed out", true
		})()
	}
	el.run()
	if el.err != nil {
		// A failed host drain stopped the loop, which fails the await whatever it was
		// waiting on (eventLoop.err).
		err, el.err = el.err, nil
	}
	return
}
