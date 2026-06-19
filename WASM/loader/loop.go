// loop.go — the Go-owned JavaScript event loop.
//
// QuickJS cannot drive I/O and wazero is single-threaded, so Go owns the loop:
// it holds the timer wheel, pumps the JS job queue, and only re-enters JS to
// deliver an event (a fired timer, a socket frame) — then pumps so the resulting
// promise reactions run. quickjs's own os.setTimeout is overridden with Go-backed
// timers, which means js_std_loop never has an os timer to block on (it just
// drains jobs and returns — see qjs.Context.Pump). This is what lets the shared
// host JS (net.ts Transport, net-link.ts PeerLink, net-node.ts NodeNetwork) run
// unmodified instead of being re-implemented in Go.
//
// Threading: all QuickJS calls happen on the one goroutine that runs the loop.
// Other goroutines (socket readers, in later phases) hand work in via post(),
// which the loop executes on its own goroutine before pumping. Timers are touched
// only from JS callbacks (setTimeout/clearTimeout), which already run on the loop
// goroutine, so the heap needs no lock.
package main

import (
	"container/heap"
	"errors"
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
	extra []*qjs.Context

	// Synchronously-blocked net calls. A guest's host.call(CAP_NET_*) blocks its wasm
	// stack at the host-import boundary (awaitNetCall) while Go pumps the host realm;
	// callSeq hands each call a unique id, and __netDone/__netFail deposit the result
	// in netBlocking[id] when the host realm's Transport promise settles.
	callSeq     int64
	netBlocking map[int64]*netOutcome
}

// netOutcome is the landing slot for a synchronously-blocked net call's result.
type netOutcome struct {
	done   bool
	bytes  []byte
	failed bool
	msg    string
}

type jsTimer struct {
	id       int64
	deadline time.Time
	cb       *qjs.Value // a retained (Dup'd) JS callback; Free()d when fired or cleared
	index    int        // heap index, maintained by timerHeap
}

// timerHeap is a min-heap of pending timers ordered by deadline.
type timerHeap []*jsTimer

func (h timerHeap) Len() int            { return len(h) }
func (h timerHeap) Less(i, j int) bool  { return h[i].deadline.Before(h[j].deadline) }
func (h timerHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *timerHeap) Push(x any)         { t := x.(*jsTimer); t.index = len(*h); *h = append(*h, t) }
func (h *timerHeap) Pop() any {
	old := *h
	n := len(old)
	t := old[n-1]
	old[n-1] = nil
	t.index = -1
	*h = old[:n-1]
	return t
}

// newEventLoop binds a loop to a QuickJS context and installs the browser-like
// async surface (setTimeout/clearTimeout/queueMicrotask) the shared JS expects.
func newEventLoop(c *qjs.Context) *eventLoop {
	el := &eventLoop{c: c, byID: map[int64]*jsTimer{}, tasks: make(chan func(), 256), netBlocking: map[int64]*netOutcome{}}
	el.install()
	return el
}

// addContext registers another QuickJS context to be pumped alongside el.c, so a
// promise reaction in that realm (e.g. a guest entrypoint's settling __settle) runs as
// part of this loop. The guest realm uses native Promises only (no Go timers), so it
// needs no separate loop — just its job queue drained.
func (el *eventLoop) addContext(c *qjs.Context) { el.extra = append(el.extra, c) }

// pumpAll drains the job queue of el.c and every registered extra context. A host
// job that schedules a guest job (e.g. resolving the guest entrypoint's promise) is
// pumped first (el.c) so that guest job runs in the same round.
func (el *eventLoop) pumpAll() {
	el.c.Pump()
	for _, c := range el.extra {
		c.Pump()
	}
}

// nextCallID hands out a unique id for an in-flight net host.call — the key both the
// host realm (via __netDone/__netFail) and the blocked caller (awaitNetCall) agree on.
func (el *eventLoop) nextCallID() int64 { el.callSeq++; return el.callSeq }

// resolveCall deposits a blocked net call's outcome (kind 0 = resolved with bytes,
// 1 = rejected with msg) into its netBlocking slot, where awaitNetCall picks it up.
// __netDone/__netFail (node.go) call this when the host realm's Transport settles.
func (el *eventLoop) resolveCall(callID int64, kind int, bytes []byte, msg string) {
	o := el.netBlocking[callID]
	if o == nil {
		return
	}
	o.done = true
	if kind == 0 {
		o.bytes = bytes
	} else {
		o.failed, o.msg = true, msg
	}
}

// awaitNetCall blocks a guest's synchronous net host.call: it drives the host realm's
// loop — socket frames (el.tasks) and host timers (the Transport request timeout) —
// until the net op for callID settles, then returns its bytes (or an error on a
// rejection/timeout). This is the non-Asyncify stand-in for Bun's Asyncify-blocking
// host.call: the guest's wasm stack is paused at the host-import boundary while Go
// pumps the host realm to completion, so an unchanged guest (tier2-guest.js, which
// calls host.call(CAP_NET_*) with no await) sees net as synchronous. Only the host
// realm is pumped — the guest realm is suspended mid-call, so running its job queue
// here would execute its microtasks out of order.
func (el *eventLoop) awaitNetCall(callID int64, timeout time.Duration) ([]byte, error) {
	o := &netOutcome{}
	el.netBlocking[callID] = o
	defer delete(el.netBlocking, callID)
	deadline := time.Now().Add(timeout)
	hostPump := func() { el.c.Pump() } // host realm only — the guest stays suspended
	for !o.done {
		el.step(deadline, hostPump, func() bool { return o.done })
		if !o.done && !time.Now().Before(deadline) {
			return nil, errors.New("net call: timed out")
		}
	}
	return el.netResult(o)
}

func (el *eventLoop) netResult(o *netOutcome) ([]byte, error) {
	if o.failed {
		return nil, errors.New(o.msg)
	}
	return o.bytes, nil
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
	// queueMicrotask isn't a quickjs-ng global; polyfill over a settled promise
	// (its reaction is a job, drained by Pump).
	if _, err := el.c.Eval("<loop-setup>", qjs.Code(`globalThis.queueMicrotask = (f) => { Promise.resolve().then(f); };`)); err != nil {
		panic(fmt.Sprintf("eventLoop install: %v", err))
	}
}

// post hands a closure to the loop goroutine. Safe to call from any goroutine.
func (el *eventLoop) post(fn func()) { el.tasks <- fn }

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
// delivered task/timer: the whole loop (pumpAll) for run(), or just the host realm
// when a guest is suspended mid-call (awaitNetCall). A zero `deadline` means "no
// deadline" — block only on tasks/timers. `until` is checked between sub-steps so a
// caller's exit condition (el.stopped, a settled net call) short-circuits promptly.
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
		tmr := time.NewTimer(d)
		defer tmr.Stop()
		wait = tmr.C
	}
	select {
	case task := <-el.tasks:
		task()
		pump()
	case <-wait:
		// The wait fired (deadline or next timer). select picks at random when a task is
		// also ready, so drain whatever is queued before returning — otherwise a result
		// that raced the deadline would sit unprocessed and awaitNetCall would report a
		// false timeout.
		for {
			select {
			case task := <-el.tasks:
				task()
				pump()
			default:
				return
			}
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
	el.c.Global().SetPropertyStr("__signal", el.c.Function(func(t *qjs.This) (*qjs.Value, error) {
		el.stopped = true
		return nil, nil
	}))
	el.stopped = false
	if _, err := el.c.Eval("<kick>", qjs.Code(kick)); err != nil {
		return err
	}
	if !el.stopped && timeout > 0 {
		safety := time.AfterFunc(timeout, func() { el.post(func() { el.stopped = true }) })
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

// awaitIn evaluates an async JS expression in context c and drives the loop (pumping
// every registered context) until it settles: kind 0 (fulfilled, with the resolved
// Uint8Array/ArrayBuffer bytes) or kind 1 (rejected, with the error string). timeout
// bounds the wait as a safety net. c may be the host realm (a serve op) or a guest
// realm (runGuest) — either way the whole loop is driven, so a guest awaiting net is
// resumed by the host realm's socket I/O.
func (el *eventLoop) awaitIn(c *qjs.Context, callExpr string, timeout time.Duration) (kind int, value []byte, msg string, err error) {
	kind = -1
	settle := c.Function(func(t *qjs.This) (*qjs.Value, error) {
		a := t.Args()
		kind = int(a[0].Int64())
		if len(a) >= 2 {
			if b, e := qjs.JsTypedArrayToGo(a[1]); e == nil {
				value = b
			} else {
				msg = a[1].String()
			}
		}
		el.stopped = true
		return nil, nil
	})
	c.Global().SetPropertyStr("__settle", settle)

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
		safety := time.AfterFunc(timeout, func() {
			el.post(func() {
				if !el.stopped {
					kind, msg, el.stopped = 2, "await: timed out", true
				}
			})
		})
		defer safety.Stop()
	}
	el.run()
	return
}
