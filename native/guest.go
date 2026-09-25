// The confined guest realm (§12.3, §12.8): one QuickJS runtime per app holding only
// ECMAScript intrinsics. Its one seam is host.call(name, bytes), funnelled into the host
// realm's guest seam; every call parks a Promise that settleHostCall resolves.
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"seedkernel/qjs"
)

var (
	// realms are the live confined realms, keyed by a handle this map mints, so a caller
	// cannot reuse or forge one.
	realms   = map[int64]*guestRealm{}
	realmSeq int64
)

type guestRealm struct {
	hostQc *qjs.Context
	rt     *qjs.Runtime
	qc     *qjs.Context
	loop   *eventLoop

	hostCall *qjs.Value // retained host-realm seam — this app's whole authority
	start    *qjs.Value // guest-realm __start — the one way in

	resolveHostCall *qjs.Value // guest-realm __resolveHostCall (a host call fulfilled)
	rejectHostCall  *qjs.Value // guest-realm __rejectHostCall (a host call failed)

	// calls are initiator calls in flight, each holding the host-realm resolve/reject of
	// the Promise the shim handed the shell.
	calls map[int64]*initiatorCall

	// Execution budget (§12.3), mirroring safe-js.ts's ExecClock: the configured ceiling,
	// and the clock of the invocation whose code holds the thread, or last did.
	budget time.Duration
	*invocationClock
	// End of the running segment; a host call hands a module the caller's live remainder.
	segmentDeadline time.Time

	// Whether this realm may hold a queued job. Only guest code queues one, always through
	// `within`, so a realm not entered since its last completed drain skips the pump's four
	// wasm crossings. Cleared only by a drain that completed.
	jobsPending bool

	// Host calls parked for this realm (hostcalls.go): custody and the invocation clock
	// each resumes on.
	hostCalls hostCallLedger
}

// invocationClock is one entrypoint invocation's execution budget. Each host call keeps
// the clock it was made under, so its continuation can only fail that invocation.
type invocationClock struct {
	id                 int64 // the initiator call an overrun fails
	consumed           time.Duration
	invocationBudget   time.Duration
	invocationDeadline time.Time // zero means unbounded
}

type initiatorCall struct{ onDone, onFail *qjs.Value }

// installRealmBridge adds the confined-realm powers to the `bridge` object: create a
// realm, call into it, settle a parked op, dispose.
func installRealmBridge(qc *qjs.Context, b *qjs.Value) {
	b.SetPropertyStr("createRealm", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		mem := uint64(args[2].Int64())
		if mem == 0 {
			return nil, errors.New("createRealm: no memory limit supplied (the shim resolves the shared default)")
		}
		// Negative encodes Infinity: no budget.
		budget := time.Duration(0)
		if ms := args[3].Int64(); ms > 0 {
			budget = time.Duration(ms) * time.Millisecond
		}
		maxHostCalls := int(args[4].Int64())
		maxHostCallBytes := args[5].Int64()
		if maxHostCalls <= 0 || maxHostCallBytes <= 0 {
			return nil, errors.New("createRealm: no outstanding host-call limits supplied")
		}
		realmSeq++
		id := realmSeq
		g, err := newGuestRealm(el, args[0].String(), args[1], mem, budget,
			maxHostCalls, maxHostCallBytes)
		if err != nil {
			return nil, err
		}
		realms[id] = g
		return qc.NewInt64(id), nil
	}))
	b.SetPropertyStr("realmCall", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		g := realms[args[0].Int64()]
		if g == nil {
			return nil, fmt.Errorf("realmCall: no such realm")
		}
		callID := args[2].Int64()
		deadlineMs := args[5].Int64()
		// Borrowed last: no host-engine read may follow it (qjs.Value.View).
		payload, err := args[1].View()
		if err != nil {
			return nil, err
		}
		deferred, elapsed := g.call(callID, payload, args[3], args[4], deadlineMs)
		// elapsed<<1 | deferred: one number, no object on the dispatch path. Nanoseconds,
		// so the timer meter never rounds a short turn down to free.
		report := elapsed.Nanoseconds() << 1
		if deferred {
			report |= 1
		}
		return qc.NewInt64(report), nil
	}))
	b.SetPropertyStr("realmCancel", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		g := realms[args[0].Int64()]
		if g == nil {
			return nil, nil
		}
		if c := g.takeCall(args[1].Int64()); c != nil {
			c.free()
		}
		return nil, nil
	}))
	b.SetPropertyStr("realmSettle", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// The host-call promise outlives an uninstall, so a disposed realm is a no-op.
		g := realms[args[0].Int64()]
		if g == nil {
			return qc.NewInt64(0), nil
		}
		callID := args[1].Int64()
		// A detached call's answer is a new turn (`CallBudget.detach`).
		detached := args[4].Int64() == 1
		// Bytes resolve, a message rejects; a refusal here is the answer. The result is
		// borrowed last (qjs.Value.View).
		var bytes []byte
		var msg string
		if args[2].IsNull() || args[2].IsUndefined() {
			msg = args[3].String()
		} else if width, err := args[2].ByteLength(); err != nil {
			msg = "host call result not bytes"
		} else if err := g.hostCalls.reserve(callID, width); err != nil {
			msg = err.Error()
		} else if view, err := args[2].View(); err != nil {
			msg = "host call result not bytes"
		} else {
			bytes = view
		}
		return qc.NewInt64(g.settleHostCall(callID, bytes, msg, detached).Nanoseconds()), nil
	}))
	b.SetPropertyStr("realmDispose", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		id := args[0].Int64()
		if g := realms[id]; g != nil {
			delete(realms, id)
			g.close()
		}
		return nil, nil
	}))
}

// newGuestRealm builds a confined realm running `source` (already fronted by the shell
// with its config), with host.call funnelled into `hostCall`.
func newGuestRealm(loop *eventLoop, source string, hostCall *qjs.Value, memoryLimit uint64,
	budget time.Duration, maxHostCalls int, maxHostCallBytes int64) (*guestRealm, error) {
	hostQc := loop.c
	rt, err := qjs.New(qjs.WithMemoryLimit(memoryLimit))
	if err != nil {
		return nil, err
	}
	g := &guestRealm{
		hostQc: hostQc, rt: rt, qc: rt.Context(), loop: loop,
		hostCall: hostCall.Dup(), calls: map[int64]*initiatorCall{},
		hostCalls: newHostCallLedger(maxHostCalls, maxHostCallBytes),
		budget:    budget, invocationClock: &invocationClock{invocationBudget: budget},
	}
	fail := func(err error) (*guestRealm, error) {
		g.close()
		return nil, err
	}
	loop.addContext(g.qc, g.pump)

	// The single seam: (name, callId, payload) goes to the host-realm guest seam, the call
	// parks, and realmSettle settles the preamble's Promise under callId. The fourth host
	// argument is the segment's live module deadline; -1 means unbounded.
	g.qc.Global().SetPropertyStr("__host_call", g.qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		name := args[0].String()
		callID := args[1].Int64()
		// Admit the width before the copy; no JS runs in between (hostcalls.go).
		payloadBytes, err := args[2].ByteLength()
		if err != nil {
			return nil, err
		}
		if err := g.hostCalls.admit(callID, payloadBytes, g.invocationClock); err != nil {
			return nil, err
		}
		// Borrowed from the guest engine, copied once into the host's (qjs.Value.View).
		payload, err := args[2].View()
		if err != nil {
			g.hostCalls.release(callID)
			return nil, err
		}
		nv := hostQc.NewString(name)
		pv := hostQc.NewArrayBuffer(payload)
		deadlineMs := int64(-1)
		if !g.segmentDeadline.IsZero() {
			deadlineMs = time.Until(g.segmentDeadline).Milliseconds()
			if deadlineMs < 0 {
				deadlineMs = 0
			}
		}
		res, err := hostQc.Invoke(g.hostCall, hostQc.NewUndefined(),
			nv, pv, hostQc.NewInt64(callID), hostQc.NewInt64(deadlineMs))
		pv.Free()
		nv.Free()
		if err != nil {
			g.hostCalls.release(callID)
			return nil, err
		}
		res.Free() // always null: the call parked
		// The settlement is a host microtask queued after this round's drain, and a local
		// answer makes no I/O to wake the loop.
		g.loop.wake()
		return qc.NewNull(), nil
	}))

	// An invocation's two outcomes, from the preamble's __start into the shim's callbacks.
	g.qc.Global().SetPropertyStr("__callDone", g.qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		c := g.takeCall(args[0].Int64())
		if c == nil {
			return nil, nil
		}
		defer c.free()
		out, err := args[1].View()
		if err != nil {
			g.reportCall(c.onFail, hostQc.NewString("guest: entrypoint result is not bytes"))
			return nil, nil
		}
		g.reportCall(c.onDone, hostQc.NewArrayBuffer(out))
		return nil, nil
	}))
	g.qc.Global().SetPropertyStr("__callFail", g.qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		c := g.takeCall(args[0].Int64())
		if c == nil {
			return nil, nil
		}
		defer c.free()
		g.reportCall(c.onFail, hostQc.NewString(args[1].String()))
		return nil, nil
	}))

	// The shared preamble (host/guest-seam.ts): host.call and the __start driver.
	if _, err := g.qc.Eval("guest-preamble.js", hostFnString(hostQc, "guestPreamble")); err != nil {
		return fail(fmt.Errorf("guest preamble: %w", err))
	}
	// Top-level code runs under a fresh budget, so it cannot wedge installation; jobs it
	// queues run at the next budgeted pump.
	g.consumed = 0
	done, err := g.within(func() (*qjs.Value, error) {
		return g.qc.Eval("guest.js", source)
	})
	if err != nil {
		return fail(fmt.Errorf("guest source: %w", err))
	}
	done.Free()
	// Guest-realm values, freed by rt.Close().
	g.start = g.qc.Global().GetPropertyStr("__start")
	g.resolveHostCall = g.qc.Global().GetPropertyStr("__resolveHostCall")
	g.rejectHostCall = g.qc.Global().GetPropertyStr("__rejectHostCall")
	return g, nil
}

// hostFnString calls one zero-argument string-valued export of the shared bundle.
func hostFnString(hostQc *qjs.Context, name string) string {
	fn := hostQc.Global().GetPropertyStr(name)
	if fn.IsUndefined() {
		panic("hostFnString: " + name + " not exported by the native host bundle (build:native-host)")
	}
	v, err := hostQc.Invoke(fn, hostQc.NewUndefined())
	fn.Free()
	if err != nil {
		panic(fmt.Sprintf("%s: %v", name, err))
	}
	defer v.Free()
	return v.String()
}

// call invokes the realm's entrypoint as the initiator; onDone/onFail settle when its
// promise does. It reports whether the entrypoint deferred its answer, which frees the
// shim's queue.
func (g *guestRealm) call(id int64, payload []byte, onDone, onFail *qjs.Value, deadlineMs int64) (bool, time.Duration) {
	if !g.alive() {
		g.reportCall(onFail, g.hostQc.NewString(realmClosed))
		return false, 0
	}
	if _, duplicate := g.calls[id]; duplicate {
		g.reportCall(onFail, g.hostQc.NewString("guest: duplicate live realm invocation id"))
		return false, 0
	}
	// Copy the borrowed payload before the Dup()s re-enter the host engine.
	argV := g.qc.NewArrayBuffer(payload)
	g.calls[id] = &initiatorCall{onDone: onDone.Dup(), onFail: onFail.Dup()}
	g.invocationClock = &invocationClock{id: id, invocationBudget: g.budget}
	if deadlineMs >= 0 {
		remaining := time.Duration(deadlineMs) * time.Millisecond
		if remaining <= 0 {
			remaining = time.Nanosecond
		}
		g.invocationDeadline = time.Now().Add(remaining)
		if g.invocationBudget == 0 || remaining < g.invocationBudget {
			g.invocationBudget = remaining
		}
	}
	res, err := g.within(func() (*qjs.Value, error) {
		return g.qc.Invoke(g.start, g.qc.NewUndefined(), g.qc.NewInt64(id), argV)
	})
	argV.Free()
	deferred := false
	if res != nil {
		deferred = res.Int64() == 1
		res.Free()
	}
	// __start catches the entrypoint's throws, so this is the realm itself failing.
	if err != nil {
		if c := g.takeCall(id); c != nil {
			defer c.free()
			g.reportCall(c.onFail, g.hostQc.NewString(err.Error()))
		}
		return false, g.consumed
	}
	// Drain now, so descendant host calls are made under this invocation's clock.
	g.pump()
	return deferred, g.consumed
}

// within runs one entry into the realm under the execution budget, arming the engine's
// interrupt for the time left. An overrun is an ordinary error; the realm survives it.
func (g *guestRealm) within(fn func() (*qjs.Value, error)) (v *qjs.Value, err error) {
	remaining := time.Duration(0)
	if g.invocationBudget > 0 {
		if remaining = g.invocationBudget - g.consumed; remaining <= 0 {
			remaining = time.Nanosecond
		}
	}
	if !g.invocationDeadline.IsZero() {
		wall := time.Until(g.invocationDeadline)
		if wall <= 0 {
			wall = time.Nanosecond
		}
		if remaining == 0 || wall < remaining {
			remaining = wall
		}
	}
	g.jobsPending = true
	restore := g.rt.Budget(remaining)
	start := time.Now()
	g.segmentDeadline = time.Time{}
	if remaining > 0 {
		g.segmentDeadline = start.Add(remaining)
	}
	defer func() {
		g.consumed += time.Since(start)
		g.segmentDeadline = time.Time{}
		restore()
	}()
	v, err = fn()
	// Only an armed segment can have been interrupted; asking is an engine call.
	if remaining <= 0 || !g.rt.TookInterrupt() {
		return v, err
	}
	// Stopped mid-frame: fail the invocation here, since its own rejection would be more
	// guest work on a spent budget. `consumed` stays blown so leftover jobs stop at once.
	budgetErr := fmt.Errorf("guest realm: invocation deadline of %s exceeded", g.invocationBudget)
	g.failInvocation(budgetErr.Error())
	if err == nil {
		err = budgetErr
	}
	return v, err
}

// failInvocation rejects the initiator call whose clock is running, and only that one.
func (g *guestRealm) failInvocation(msg string) {
	if c := g.takeCall(g.invocationClock.id); c != nil {
		defer c.free()
		g.reportCall(c.onFail, g.hostQc.NewString(msg))
	}
}

// settleAll rejects every in-flight initiator call with msg (safe-js.ts failInvocations).
// The callbacks are host-realm values, so this works after the guest runtime is gone.
func (g *guestRealm) settleAll(msg string) {
	for id, c := range g.calls {
		delete(g.calls, id)
		g.reportCall(c.onFail, g.hostQc.NewString(msg))
		c.free()
	}
}

// pump drains this realm's job queue under its execution budget: a queued job is guest
// code, so a bare Pump would let one await buy an unbounded loop.
func (g *guestRealm) pump() {
	if g.rt == nil || !g.jobsPending {
		return
	}
	if _, err := g.within(func() (*qjs.Value, error) {
		return nil, g.qc.Pump()
	}); err != nil {
		// Jobs may remain, and the queued rejection needs another round.
		g.loop.wake()
		return
	}
	g.jobsPending = false
}

// realmClosed is the error a closed realm's callers get.
const realmClosed = "guest realm closed"

// alive reports whether the guest runtime is standing. Ask before allocating in it: a
// freed runtime panics.
func (g *guestRealm) alive() bool { return g.rt != nil }

// settleHostCall resolves (`bytes`) or rejects (`msg`) the guest Promise parked under
// callID, drains the continuation, and returns its execution time.
func (g *guestRealm) settleHostCall(callID int64, bytes []byte, msg string, detached bool) time.Duration {
	parked, live := g.hostCalls.at(callID)
	if !live {
		return 0
	}
	defer g.hostCalls.release(callID)
	if !g.alive() {
		return 0
	}
	// Resume on the clock the call was made under; a detached answer gets a new turn.
	if detached {
		g.invocationClock = g.turnClock()
	} else {
		g.invocationClock = parked.clock
	}
	before := g.consumed
	settler := g.resolveHostCall
	var arg *qjs.Value
	if bytes != nil {
		arg = g.qc.NewArrayBuffer(bytes)
	} else {
		settler, arg = g.rejectHostCall, g.qc.NewString(msg)
	}
	res, err := g.within(func() (*qjs.Value, error) {
		return g.qc.Invoke(settler, g.qc.NewUndefined(), g.qc.NewInt64(callID), arg)
	})
	arg.Free()
	res.Free()
	if err != nil {
		// Fail the invocation, not the realm.
		if g.alive() {
			g.failInvocation(fmt.Sprintf("guest realm failed delivering a host call result: %v", err))
		}
	}
	// Run the continuation now, so realmSettle can report its execution.
	g.pump()
	return g.consumed - before
}

// turnClock is a new turn's clock: the realm's own ceiling from now, owed to no initiator.
func (g *guestRealm) turnClock() *invocationClock {
	c := &invocationClock{invocationBudget: g.budget}
	if g.budget > 0 {
		c.invocationDeadline = time.Now().Add(g.budget)
	}
	return c
}

// takeCall consumes an in-flight initiator call, so a duplicate settlement is a no-op.
func (g *guestRealm) takeCall(id int64) *initiatorCall {
	c := g.calls[id]
	delete(g.calls, id)
	return c
}

// reportCall hands one result to a host-realm callback and frees `arg`; `cb` is borrowed.
func (g *guestRealm) reportCall(cb *qjs.Value, arg *qjs.Value) {
	res, err := g.hostQc.Invoke(cb, g.hostQc.NewUndefined(), arg)
	arg.Free()
	res.Free()
	if err != nil {
		fmt.Fprintln(os.Stderr, "guest: call settlement error:", err)
	}
	// The reaction is a host microtask queued after this round's host pump.
	g.loop.wake()
}

func (c *initiatorCall) free() {
	c.onDone.Free()
	c.onFail.Free()
}

// close disposes the realm: detach from the loop, fail outstanding calls, release its
// host-realm references, and tear the runtime down.
func (g *guestRealm) close() {
	if g.rt == nil {
		return
	}
	g.loop.removeContext(g.qc)
	g.settleAll(realmClosed)
	g.hostCalls.releaseAll()
	g.hostCall.Free() // a host-realm ref, which rt.Close does not free
	g.rt.Close()
	g.rt = nil
}

// discard tears down only the guest runtime, for a shutdown that frees the host realm too.
func (g *guestRealm) discard() {
	if g.rt != nil {
		g.rt.Close()
		g.rt = nil
	}
}
