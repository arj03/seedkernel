// guest.go — the confined guest realm (README §12.3 / §12.8): a second, zero-authority
// QuickJS runtime holding only ECMAScript intrinsics, so the guest cannot even name
// sodium / fs / net. Its single seam is host.call(name, bytes), funnelled into the host
// realm's guest seam (a JS function retained here); nothing in this file knows what a
// name means. The seam is async all the way down: __host_call always answers null, the
// preamble parks a Promise that settleNet resolves — a suspended guest is just heap
// state. Exposed to the shell as `createRealm`.
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"seedloader/qjs"
)

// The realm's resource bounds (heap cap, execution budget) are the shared host's numbers
// — core/wasm-limits.ts — sent across by the shim on every createRealm, so no Go copy can
// drift from safe-js.ts's.

var (
	// realms are the live confined realms, keyed by the opaque handle JS holds. Each has
	// its own guest seam, which is why net-settle routing is per realm rather than one
	// global hook. The map mints the handles too, so a caller has no id to reuse or forge
	// and one realm can never quietly displace another.
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

	netResolve *qjs.Value // guest-realm __netResolve (a net op fulfilled)
	netReject  *qjs.Value // guest-realm __netReject (a net op failed)

	// calls are initiator calls in flight, keyed by an id the guest carries back. Each
	// holds the host-realm resolve/reject of the Promise the shim handed the shell.
	calls map[int64]*initiatorCall

	// Execution budget (README §12.3), mirroring safe-js.ts's ExecClock. `consumed` counts
	// segments where guest code holds the thread; the separate caller-owned wall deadline
	// continues across host waits, realm queueing and deferred answers.
	budget   time.Duration
	consumed time.Duration
	// The current invocation is additionally narrowed by the caller-owned wall deadline.
	// A zero invocationDeadline is the explicit unbounded case.
	invocationBudget   time.Duration
	invocationDeadline time.Time
	// End of the currently-running segment. The host-call bridge reads this while guest
	// code is on the stack so a module inherits the caller's live remainder.
	segmentDeadline time.Time
	// dead is set when a budget kill terminated the wasm module: wazero closes the module
	// rather than unwinding one call, so the realm cannot be reused — recovery is a fresh
	// realm, and later calls are refused rather than panicking on a freed handle.
	dead bool

	// Host-side calls parked for this realm (hostcalls.go). This is the authoritative
	// native registry: it rejects before the guest-to-Go payload copy and retains custody
	// through delivery.
	hostCalls hostCallLedger
}

type initiatorCall struct{ onDone, onFail *qjs.Value }

// installRealmBridge adds the confined-realm powers to the `bridge` object: create a
// realm, call into it, settle a parked op, dispose. This is the whole of Go's involvement
// with a guest — no guest seam, no preamble assembly, no bundle facts, no dispatch.
func installRealmBridge(qc *qjs.Context, b *qjs.Value) {
	b.SetPropertyStr("createRealm", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		mem := uint64(t.Args()[2].Int64())
		if mem == 0 {
			// A 0 is a caller that forgot, and an unbounded realm is a confinement hole.
			return nil, errors.New("createRealm: no memory limit supplied (the shim resolves the shared default)")
		}
		// A negative value is the shim's encoding of Infinity — no budget, said explicitly.
		budget := time.Duration(0)
		if ms := t.Args()[3].Int64(); ms > 0 {
			budget = time.Duration(ms) * time.Millisecond
		}
		maxHostCalls := int(t.Args()[4].Int64())
		maxHostCallBytes := t.Args()[5].Int64()
		if maxHostCalls <= 0 || maxHostCallBytes <= 0 {
			return nil, errors.New("createRealm: no outstanding host-call limits supplied")
		}
		realmSeq++
		id := realmSeq
		g, err := newGuestRealm(el, t.Args()[0].String(), t.Args()[1], mem, budget,
			maxHostCalls, maxHostCallBytes)
		if err != nil {
			return nil, err
		}
		realms[id] = g
		return t.Context().NewInt64(id), nil
	}))
	b.SetPropertyStr("realmCall", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		g := realms[t.Args()[0].Int64()]
		if g == nil {
			return nil, fmt.Errorf("realmCall: no such realm")
		}
		payload, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			return nil, err
		}
		callID := t.Args()[2].Int64()
		deadlineMs := t.Args()[5].Int64()
		deferred, elapsed := g.call(callID, payload, t.Args()[3], t.Args()[4], deadlineMs)
		// Two facts, one number, because this is the dispatch path and an object would cost
		// an allocation and two interned property writes per invocation. Nanoseconds, not
		// milliseconds: the timer meter is a rate bound, so rounding every short turn down
		// to zero would make a fast re-arm loop free. A duration this wide stays exact as a
		// double for some 52 days of realm execution, well past any realm's lifetime.
		report := elapsed.Nanoseconds() << 1
		if deferred {
			report |= 1
		}
		return t.Context().NewInt64(report), nil
	}))
	b.SetPropertyStr("realmCancel", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		g := realms[t.Args()[0].Int64()]
		if g == nil {
			return nil, nil
		}
		if c := g.takeCall(t.Args()[1].Int64()); c != nil {
			c.free()
		}
		return nil, nil
	}))
	b.SetPropertyStr("realmSettle", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		// A settlement for a disposed realm is a no-op: the Transport promise behind it
		// outlives an uninstall.
		g := realms[t.Args()[0].Int64()]
		if g == nil {
			return t.Context().NewInt64(0), nil
		}
		callID := t.Args()[1].Int64()
		if !g.hostCalls.has(callID) {
			return t.Context().NewInt64(0), nil
		}
		if t.Args()[2].IsNull() || t.Args()[2].IsUndefined() {
			return t.Context().NewInt64(g.settleNet(callID, nil, t.Args()[3].String()).Nanoseconds()), nil
		}
		resultBytes, err := qjs.JsTypedArrayByteLength(t.Args()[2])
		if err != nil {
			return t.Context().NewInt64(g.settleNet(callID, nil, "net result not bytes").Nanoseconds()), nil
		}
		if err := g.hostCalls.reserve(callID, resultBytes); err != nil {
			return t.Context().NewInt64(g.settleNet(callID, nil, err.Error()).Nanoseconds()), nil
		}
		bytes, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			return t.Context().NewInt64(g.settleNet(callID, nil, "net result not bytes").Nanoseconds()), nil
		}
		return t.Context().NewInt64(g.settleNet(callID, bytes, "").Nanoseconds()), nil
	}))
	b.SetPropertyStr("realmDispose", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		id := t.Args()[0].Int64()
		if g := realms[id]; g != nil {
			delete(realms, id)
			g.close()
		}
		return nil, nil
	}))
}

// newGuestRealm builds a confined realm running `source` — already fronted by the shell
// with the guest preamble, signed APP config and per-load LOCAL config, so what arrives
// here is what a safe-js realm would be handed — with host.call funnelled into `hostCall`.
func newGuestRealm(loop *eventLoop, source string, hostCall *qjs.Value, memoryLimit uint64,
	budget time.Duration, maxHostCalls int, maxHostCallBytes int64) (*guestRealm, error) {
	hostQc := loop.c
	// The execution bound lives in the engine (qjs.Budget arms the interrupt handler), so
	// an unbounded realm costs what a bounded one does.
	rt, err := qjs.New(qjs.WithMemoryLimit(memoryLimit))
	if err != nil {
		return nil, err
	}
	g := &guestRealm{
		hostQc: hostQc, rt: rt, qc: rt.Context(), loop: loop,
		hostCall: hostCall.Dup(), calls: map[int64]*initiatorCall{},
		hostCalls: newHostCallLedger(maxHostCalls, maxHostCallBytes),
		budget:    budget, invocationBudget: budget,
	}
	fail := func(err error) (*guestRealm, error) {
		g.close()
		return nil, err
	}
	// The Web globals quickjs-ng lacks (TextEncoder/atob, the microtask queue), fetched
	// from the host realm so both realms polyfill from ONE text (host/native-polyfills.ts);
	// first, because everything after may use them.
	if _, err := g.qc.Eval("polyfills.js", qjs.Code(hostFnString(hostQc, "nativePolyfills"))); err != nil {
		return fail(fmt.Errorf("polyfills: %w", err))
	}
	// The driver's __start wrapper, fetched the same way (native-shim.ts `guestDriver`):
	// shared TS rather than a Go string TypeScript never saw.
	if _, err := g.qc.Eval("guest-driver.js", qjs.Code(hostFnString(hostQc, "guestDriver"))); err != nil {
		return fail(fmt.Errorf("guest driver: %w", err))
	}
	// The guest shares the host loop rather than owning one: it just needs its job queue
	// pumped, no Go timers of its own.
	loop.addContext(g.qc, g.pump)

	// The single seam. Read (name, callId, payload) from the guest and shuttle it to the
	// host-realm guest seam: every call parks — the shim answers null — and the preamble's
	// Promise under callId is settled by realmSettle when the seam's promise lands. The
	// fourth host argument is this segment's live module deadline; -1 means unbounded.
	g.qc.Global().SetPropertyStr("__host_call", g.qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		name := t.Args()[0].String()
		callID := t.Args()[1].Int64()
		// Asking the source its width is an engine query, not the copy; admit id, count
		// and that width together before the copy itself (hostcalls.go).
		payloadBytes, err := qjs.JsTypedArrayByteLength(t.Args()[2])
		if err != nil {
			return nil, err
		}
		if err := g.hostCalls.admit(callID, payloadBytes); err != nil {
			return nil, err
		}
		payload, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			g.hostCalls.release(callID)
			return nil, err
		}
		if int64(len(payload)) != payloadBytes {
			g.hostCalls.release(callID)
			return nil, errors.New("guest: host-call payload width changed while copying")
		}
		// The admitted custody follows the payload through the synchronous Go-to-host-realm
		// handoff. It stays charged to this call after the shuttle slice leaves scope.
		// nv and pv are the refcounted args (callID is an immediate) and Invoke only
		// borrows them, so both are freed once the call returns.
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
		res.Free() // always the JS_NULL immediate: the call parked
		// The settlement arrives as a HOST-realm microtask after pumpAll already drained
		// el.c this round, and a holder answering from local fs generates no I/O of its
		// own — so without a nudge nothing wakes the loop.
		g.loop.wake()
		return t.Context().NewNull(), nil
	}))

	// An initiator call's two outcomes, reported by __start once the entrypoint's promise
	// settles, into the host-realm callbacks the shim registered.
	g.qc.Global().SetPropertyStr("__callDone", g.qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		c := g.takeCall(t.Args()[0].Int64())
		if c == nil {
			return nil, nil
		}
		defer c.free()
		out, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			g.reportCall(c.onFail, hostQc.NewString("guest: entrypoint result is not bytes"))
			return nil, nil
		}
		g.reportCall(c.onDone, hostQc.NewArrayBuffer(out))
		return nil, nil
	}))
	g.qc.Global().SetPropertyStr("__callFail", g.qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		c := g.takeCall(t.Args()[0].Int64())
		if c == nil {
			return nil, nil
		}
		defer c.free()
		g.reportCall(c.onFail, hostQc.NewString(t.Args()[1].String()))
		return nil, nil
	}))

	if _, err := g.qc.Eval("guest-preamble.js", qjs.Code(hostFnString(hostQc, "guestPreamble"))); err != nil {
		return fail(fmt.Errorf("guest preamble: %w", err))
	}
	// Guest top-level code is execution just like an entrypoint. Run it under one fresh
	// budget so installation cannot be wedged before the shell receives a realm.
	g.consumed = 0
	if _, err := g.within(func() (*qjs.Value, error) {
		return g.qc.Eval("guest.js", qjs.Code(source))
	}); err != nil {
		return fail(fmt.Errorf("guest source: %w", err))
	}
	// Retained once — the holder path runs per inbound request, so re-resolving per call is
	// needless churn. Guest-realm values, freed by rt.Close().
	g.start = g.qc.Global().GetPropertyStr("__start")
	g.netResolve = g.qc.Global().GetPropertyStr("__netResolve")
	g.netReject = g.qc.Global().GetPropertyStr("__netReject")
	return g, nil
}

// hostFnString asks the host realm for one zero-argument string-valued export
// (host/native-shim.ts), so the plumbing a guest runs on is shared TS, never a Go string.
func hostFnString(hostQc *qjs.Context, name string) string {
	fn := hostQc.Global().GetPropertyStr(name)
	// IsUndefined, not nil — GetPropertyStr wraps a missing property as JS_UNDEFINED and
	// never returns Go nil (qjs/value.go).
	if fn.IsUndefined() {
		panic("hostFnString: " + name + " not defined (host/native-shim.ts)")
	}
	v, err := hostQc.Invoke(fn, hostQc.NewUndefined())
	fn.Free()
	if err != nil {
		panic(fmt.Sprintf("%s: %v", name, err))
	}
	defer v.Free()
	return v.String()
}

// call invokes the realm's one handle entrypoint as the *initiator*: it may await net, so
// onDone/onFail settle the shim's Promise when the entrypoint's own promise settles. It
// reports synchronously whether the entrypoint DEFERRED its answer, which tells the shim's
// queue the realm is free again even though nothing has settled.
func (g *guestRealm) call(id int64, payload []byte, onDone, onFail *qjs.Value, deadlineMs int64) (bool, time.Duration) {
	if err := g.checkAlive(); err != nil {
		// Settle in the HOST realm, which is a different runtime and still alive.
		g.reportCall(onFail.Dup(), g.hostQc.NewString(err.Error()))
		return false, 0
	}
	if _, duplicate := g.calls[id]; duplicate {
		g.reportCall(onFail.Dup(), g.hostQc.NewString("guest: duplicate live realm invocation id"))
		return false, 0
	}
	g.calls[id] = &initiatorCall{onDone: onDone.Dup(), onFail: onFail.Dup()}
	argV := g.qc.NewArrayBuffer(payload)
	g.consumed = 0 // one top-level entrypoint invocation, one budget
	g.invocationBudget = g.budget
	g.invocationDeadline = time.Time{}
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
	// __start catches everything the entrypoint throws, so an error here is the realm
	// itself failing (an OOM in the wrapper): settle rather than strand the caller.
	if err != nil {
		if c := g.takeCall(id); c != nil {
			defer c.free()
			g.reportCall(c.onFail, g.hostQc.NewString(err.Error()))
		}
		return false, g.consumed
	}
	// Drain every runnable continuation before returning to the host realm. Besides
	// advancing Promise.resolve chains in this turn, this keeps the causal clock that
	// entered through bridge.realmCall on the stack while descendant host calls are made.
	g.pump()
	return deferred, g.consumed
}

// within runs one entry into the realm under the execution budget: it opens a clock
// segment and arms the engine's deadline for the time left. An overrun is an ordinary
// error — QuickJS's interrupt handler throws and the entrypoint's promise rejects — so
// nothing here ends the realm to stop it. A segment starting with the allowance spent is
// armed at the floor, so the failure routes through the guest's own promises.
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
	// Only a segment that armed a deadline can have been interrupted by one, and asking is
	// itself an engine call — an unbounded realm must not pay for a fixed answer.
	if remaining <= 0 || !g.rt.TookInterrupt() {
		return v, err
	}
	// The engine stopped the guest mid-frame, so the invocation is OVER whatever its own
	// promises do next: delivering the rejection is more queued guest work under the
	// budget just exhausted, and the caller would wait out its timeout. Settling here
	// closes that gap. `consumed` deliberately stays blown so jobs the interrupted frame
	// left behind stop at their first check; the next entrypoint starts fresh (see call).
	budgetErr := fmt.Errorf("guest realm: invocation deadline of %s exceeded", g.invocationBudget)
	g.settleAll(budgetErr.Error())
	if err == nil {
		err = budgetErr
	}
	return v, err
}

// markDead ends the realm's life and settles every call it still owes (settleAll).
// Returns err so callers can `return nil, g.markDead(...)`.
func (g *guestRealm) markDead(err error) error {
	g.dead = true
	g.settleAll(err.Error())
	return err
}

// settleAll rejects every in-flight initiator call with msg, releasing the callbacks: a
// realm dying with continuations outstanding must not leave callers hanging forever —
// worse than an error, since they cannot retry or observe anything went wrong (safe-js
// needs no equivalent; its interrupt throws inside the guest). Callbacks are HOST-realm
// values, so reporting works once the guest runtime is gone.
func (g *guestRealm) settleAll(msg string) {
	settled := false
	for id, c := range g.calls {
		delete(g.calls, id)
		g.reportCall(c.onFail, g.hostQc.NewString(msg))
		c.free()
		settled = true
	}
	if settled {
		g.loop.wake()
	}
}

// pump drains this realm's job queue under its execution budget. The loop calls it
// instead of Context.Pump because a queued job IS guest code: the continuation after
// `await Promise.resolve()` never passes through settleNet, so a bare Pump would run it
// outside every guard — one await would buy an unbounded loop. A pump that FAILS wakes
// the loop: the rejection it queues is more work after this round drained, and a guest
// spinning on its own generates no I/O, so without the nudge the caller waits out its
// whole timeout.
func (g *guestRealm) pump() {
	if g.rt == nil || g.dead || !g.rt.Alive() {
		return
	}
	if _, err := g.within(func() (*qjs.Value, error) {
		return nil, g.qc.Pump()
	}); err != nil {
		g.loop.wake()
	}
}

// checkAlive refuses a realm a budget kill already terminated. Callers must ask BEFORE
// allocating in the guest runtime: NewString/NewArrayBuffer on a closed module panics, so
// a check inside within() would come one allocation too late.
func (g *guestRealm) checkAlive() error {
	if g.rt == nil {
		// Closed, not killed: close() already settled what it owed, so this only refuses.
		return errors.New("guest realm closed")
	}
	if g.dead || !g.rt.Alive() {
		return g.markDead(fmt.Errorf("guest realm terminated: execution budget of %s exceeded", g.budget))
	}
	return nil
}

// There is no nested-budget case: the shim's per-realm queue leaves exactly one budget
// window open at a time, so resetting `consumed` per call is the whole of the accounting.

// settleNet resolves or rejects the guest Promise parked under callID when the host
// realm's Transport promise settles (`bytes` fulfils, `msg` rejects), then drains the
// awaiting continuation before returning its execution time to the bridge.
func (g *guestRealm) settleNet(callID int64, bytes []byte, msg string) time.Duration {
	if !g.hostCalls.has(callID) {
		return 0
	}
	defer g.hostCalls.release(callID)
	if g.checkAlive() != nil {
		return 0 // the realm the continuation belonged to no longer exists
	}
	before := g.consumed
	var res *qjs.Value
	var err error
	if bytes != nil {
		// new Uint8Array(ab) inside __netResolve retains the ArrayBuffer, so freeing our
		// handle after the call leaves the guest's copy alive.
		ab := g.qc.NewArrayBuffer(bytes)
		res, err = g.within(func() (*qjs.Value, error) {
			return g.qc.Invoke(g.netResolve, g.qc.NewUndefined(), g.qc.NewInt64(callID), ab)
		})
		ab.Free()
	} else {
		msgV := g.qc.NewString(msg)
		res, err = g.within(func() (*qjs.Value, error) {
			return g.qc.Invoke(g.netReject, g.qc.NewUndefined(), g.qc.NewInt64(callID), msgV)
		})
		msgV.Free()
	}
	if res != nil {
		res.Free()
	}
	if err != nil {
		// The continuation failed: nobody may be left waiting on a reply that is not
		// coming — but the realm must NOT end. An overrun is already an ordinary error
		// (see within), and anything else is a fault contained to one guest's
		// `__netResolve`; killing the realm would brick it until the bundle reloads.
		if g.checkAlive() == nil {
			g.settleAll(fmt.Sprintf("guest realm failed delivering a net result: %v", err))
		}
	}
	// `__netResolve` queues the awaiting continuation. Run it now rather than in the
	// loop's anonymous guest pump, so bridge.realmSettle can report its execution to the
	// same causal root and any host.call it creates inherits that root synchronously.
	g.pump()
	return g.consumed - before
}

// takeCall consumes an in-flight initiator call, so a duplicate settlement is a no-op.
func (g *guestRealm) takeCall(id int64) *initiatorCall {
	c := g.calls[id]
	if c != nil {
		delete(g.calls, id)
	}
	return c
}

// reportCall hands one result to a host-realm callback and releases the argument
// (Invoke only borrows it).
func (g *guestRealm) reportCall(cb *qjs.Value, arg *qjs.Value) {
	res, err := g.hostQc.Invoke(cb, g.hostQc.NewUndefined(), arg)
	arg.Free()
	if res != nil {
		res.Free()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "guest: call settlement error:", err)
	}
	// Settling a host promise only queues a host microtask, and pumpAll pumps the host
	// realm first — so the reaction (possibly the realm's next queued entrypoint,
	// host/realm-queue.ts) lands after this round. Without a nudge the chain would
	// advance one step per round and stall to a hang.
	g.loop.wake()
}

func (c *initiatorCall) free() {
	c.onDone.Free()
	c.onFail.Free()
}

// close disposes the realm: detach from the loop, release the host-realm references it
// holds (they outlive the guest runtime, so rt.Close alone would leak them), and tear the
// runtime down. Settling comes first: an initiator's promise resolves only from inside
// this realm, so calls outstanding would be stranded.
func (g *guestRealm) close() {
	if g.rt == nil {
		return
	}
	g.loop.removeContext(g.qc) // stop pumpAll touching this realm before freeing it
	g.settleAll("guest realm closed")
	g.hostCalls.releaseAll() // the custody every parked call holds ends here (hostcalls.go)
	g.hostCall.Free() // a HOST-realm ref: rt.Close only tears down the guest realm
	g.rt.Close()
	g.rt = nil
}

// discard tears down only the guest runtime, for a shutdown about to free the host realm
// too: nothing left to detach from, and no host-realm reference worth releasing.
func (g *guestRealm) discard() {
	if g.rt != nil {
		g.rt.Close()
		g.rt = nil
	}
}
