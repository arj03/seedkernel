// The Go-owned JavaScript event loop: the timer heap, the JS job queue, and re-entry into
// JS to deliver an event. Every QuickJS call happens on the loop goroutine; other
// goroutines hand work in via post().
package main

import (
	"container/heap"
	"errors"
	"fmt"
	"os"
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

	// onSettle is the in-flight await's result sink, which __settle routes into.
	onSettle func(fulfilled bool, value *qjs.Value)

	// stepTimer is step()'s reusable wait timer, stopped between turns.
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
	el := &eventLoop{c: c, byID: map[int64]*jsTimer{}, tasks: make(chan func(), 256), stepTimer: time.NewTimer(0)}
	el.stepTimer.Stop()
	el.install()
	return el
}

// pumpAll drains the host realm. A guest realm drains its own jobs inside each entry
// (host/engine-realm.ts). A failed host drain stops the loop (eventLoop.err).
func (el *eventLoop) pumpAll() {
	if err := el.c.Pump(); err != nil && el.err == nil {
		el.err = err
		el.stopped = true
	}
}

func (el *eventLoop) install() {
	g := el.c.Global()
	g.SetPropertyStr("setTimeout", el.c.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		var ms int64
		if len(args) >= 2 {
			ms = max(args[1].Int64(), 0)
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
	// __settle(fulfilled, value) settles the await in flight.
	g.SetPropertyStr("__settle", el.c.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		if el.onSettle != nil {
			el.onSettle(args[0].Int32() != 0, args[1])
		}
		return nil, nil
	}))
	// queueMicrotask and performance.now are the engine's own.
}

// post hands a closure to the loop goroutine. Safe to call from any goroutine.
func (el *eventLoop) post(fn func()) { el.tasks <- fn }

// dispatch calls a retained JS callback and frees its result and `args`. A throw is the
// callback's own failure, so it is logged under `who`, not returned.
func dispatch(c *qjs.Context, who string, cb *qjs.Value, args ...*qjs.Value) {
	res, err := c.Invoke(cb, c.NewUndefined(), args...)
	res.Free()
	for _, a := range args {
		a.Free()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, who+":", err)
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
		dispatch(el.c, "eventLoop: callback error", t.cb)
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
		el.stepTimer.Reset(max(time.Until(el.timers[0].deadline), 0))
		wait = el.stepTimer.C
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

// await evaluates an async JS expression in the host realm and drives the loop until it
// settles. read takes the fulfilled value, borrowed for the call; a rejection is the error.
// Awaits must not nest: el.onSettle is a single slot.
func (el *eventLoop) await(callExpr string, read func(*qjs.Value)) error {
	var rejected error
	el.onSettle = func(fulfilled bool, v *qjs.Value) {
		if fulfilled {
			read(v)
		} else {
			rejected = errors.New(v.String())
		}
		el.stopped = true
	}
	defer func() { el.onSettle = nil }()

	wrap := `(function(){ Promise.resolve(` + callExpr + `).then(` +
		`(v) => __settle(true, v), (e) => __settle(false, String(e && e.message || e))); })();`
	el.stopped = false
	done, err := el.c.Eval("<await>", wrap)
	if err != nil {
		return err
	}
	done.Free()
	el.run()
	if err := el.err; err != nil {
		el.err = nil
		return err
	}
	return rejected
}
