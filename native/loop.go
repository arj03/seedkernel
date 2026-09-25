// The Go-owned JavaScript event loop: the timer heap, the JS job queue, and re-entry into
// JS to deliver an event. Every QuickJS call happens on the loop goroutine; other
// goroutines hand work in via post().
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

	// extra are the guest realms pumped alongside el.c, each through its budgeted pump.
	extra []pumpEntry

	// onSettle is the in-flight await's result sink, which __settle routes into.
	onSettle func(kind int, bytes []byte, msg string)

	// awaitGen tags each await, so a stale safety timer or a timed-out await's late
	// promise cannot settle the one now in flight.
	awaitGen int64

	// stepTimer is step()'s reusable wait timer.
	stepTimer *time.Timer

	// err is a failed host-realm drain: a job that threw, or an unhandled rejection
	// (qjs.TrackRejections). It stops the loop; await returns it, main exits on it.
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

// newEventLoop binds a loop to a QuickJS context and installs setTimeout/clearTimeout.
func newEventLoop(c *qjs.Context) *eventLoop {
	el := &eventLoop{c: c, byID: map[int64]*jsTimer{}, tasks: make(chan func(), 256)}
	el.install()
	return el
}

// pumpEntry pairs a registered context with the func that drains it.
type pumpEntry struct {
	c    *qjs.Context
	pump func()
}

// addContext registers another context to be drained by `pump` alongside el.c.
func (el *eventLoop) addContext(c *qjs.Context, pump func()) {
	el.extra = append(el.extra, pumpEntry{c: c, pump: pump})
}

// removeContext drops a context registered with addContext; a no-op otherwise.
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

// pumpAll drains el.c, then every extra context, so a host job that schedules guest work
// runs it in the same round; guest-to-host work needs a wake. A failed host drain stops
// the loop (eventLoop.err).
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
	// __settle(gen, kind, value) settles the await tagged `gen`, and is ignored otherwise.
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
	// queueMicrotask and performance.now are the engine's own.
}

// post hands a closure to the loop goroutine. Safe to call from any goroutine.
func (el *eventLoop) post(fn func()) { el.tasks <- fn }

// wake nudges the loop into another pump round, so a microtask queued during a pump is
// not stranded behind a blocking select. Any Go-side settlement outside a task or timer
// must call it. Non-blocking: a full buffer means work is already queued.
func (el *eventLoop) wake() {
	select {
	case el.tasks <- func() {}:
	default:
	}
}

// armTimer (re)arms the loop's reusable wait timer for d; step() never re-enters.
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

// step drives one turn, phased as Node's is: the timers due when the turn began, then the
// tasks queued by then. Each phase takes only what was ready as it began, so neither can
// starve the other.
func (el *eventLoop) step() {
	// Fire the timers due now, pumping after each; one armed meanwhile waits a turn.
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
	// Drain ready microtasks before blocking.
	el.pumpAll()
	if el.stopped {
		return
	}
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
		el.stepTimer.Stop()
	}
	// Then the tasks already queued, pumping after each; later posts wait a turn.
	for n := len(el.tasks); n > 0 && !el.stopped; n-- {
		task := <-el.tasks
		task()
		el.pumpAll()
	}
}

// run drives the loop on the current goroutine until stopped.
func (el *eventLoop) run() {
	for !el.stopped {
		el.step()
	}
}

// armSafety arms a timeout for the await in flight; onFire runs on the loop goroutine
// only while that await is still the current one.
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

// await evaluates an async JS expression in the host realm and drives the loop until it
// settles: kind 0 (fulfilled, bytes), 1 (rejected, message) or 2 (timed out). Awaits
// must not nest: el.onSettle is a single slot.
func (el *eventLoop) await(callExpr string, timeout time.Duration) (kind int, value []byte, msg string, err error) {
	kind = -1
	el.awaitGen++
	gen := strconv.FormatInt(el.awaitGen, 10)
	el.onSettle = func(k int, bytes []byte, m string) {
		kind, value, msg = k, bytes, m
		el.stopped = true
	}
	defer func() { el.onSettle = nil }()

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
		err, el.err = el.err, nil
	}
	return
}
