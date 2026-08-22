// guest.go — the confined guest realm (README §12.3 / §12.8): this target's version of
// the seam safe-js.ts is on the JS targets, exposed to the shell as `createRealm`
// (host/native-shim.ts) so the shell drives either without knowing which it holds.
//
// A realm is a second, zero-authority QuickJS runtime holding only the ECMAScript
// intrinsics, so the guest cannot even *name* sodium / fs / net. Its single seam is
// host.call(name, bytes), which Go funnels into the guest seam the shell built for that
// app — a JS function in the host realm, retained here. Nothing in this file knows what a
// name means or which domains an app may reach.
//
// The seam is async: a sync name returns its bytes immediately, while a round-tripping
// one (every fs/* and every cross-realm call) returns null and the guest preamble hands
// the guest a real Promise. When the shim's promise settles it calls bridge.realmSettle,
// this file resolves the parked guest Promise, and the shared loop (loop.go) pumps the
// realm so the awaiting entrypoint resumes. No blocking and no Asyncify — a suspended
// guest is just heap state.
//
// `realmCall` is the one way in. One entrypoint still runs to completion before the next
// begins, but that serialization is the shim's per-realm queue (host/realm-queue.ts), so
// both targets get it from one implementation.
package main

import (
	"errors"
	"fmt"
	"time"

	"seedloader/qjs"
)

// The realm's resource bounds (heap cap, execution budget) are the shared host's numbers
// — core/wasm-limits.ts — sent across by the shim on every createRealm, so this file owns
// no copy that could drift from safe-js.ts's.

var (
	// realms are the live confined realms, keyed by the opaque handle JS holds. Each has
	// its own guest seam, which is why net-settle routing is per realm rather than one
	// global hook.
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
	calls   map[int64]*initiatorCall
	callSeq int64

	// Execution budget (README §12.3), mirroring safe-js.ts's ExecClock. `consumed`
	// accumulates only the segments during which guest code actually holds the thread, so
	// time the host spends awaiting the seam on the guest's behalf is nobody's budget —
	// without that split, a budget tight enough to catch a holder's infinite loop would
	// kill an initiator parked on a 2s request.
	budget   time.Duration
	consumed time.Duration
	// dead is set when a budget kill terminated the wasm module. wazero closes the module
	// rather than unwinding one call, so the realm cannot be reused: later calls are
	// refused rather than panicking on a freed handle, and recovery means a fresh realm.
	dead bool
}

type initiatorCall struct{ onDone, onFail *qjs.Value }

// installRealmBridge adds the confined-realm powers to the `bridge` object: create a
// realm, call into it, settle a parked op, dispose. This is the whole of Go's involvement
// with a guest — no guest seam, no preamble assembly, no bundle facts, no dispatch.
func installRealmBridge(qc *qjs.Context, b *qjs.Value) {
	b.SetPropertyStr("createRealm", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		mem := uint64(t.Args()[2].Int64())
		if mem == 0 {
			// A 0 is a direct caller that forgot, and an unbounded realm is a confinement
			// hole rather than a fallback.
			return nil, errors.New("createRealm: no memory limit supplied (the shim resolves the shared default)")
		}
		// A negative value is the shim's encoding of Infinity — no budget, said explicitly.
		budget := time.Duration(0)
		if ms := t.Args()[3].Int64(); ms > 0 {
			budget = time.Duration(ms) * time.Millisecond
		}
		g, err := newGuestRealm(el, t.Args()[0].String(), t.Args()[1], mem, budget)
		if err != nil {
			return nil, err
		}
		realmSeq++
		realms[realmSeq] = g
		return t.Context().NewInt64(realmSeq), nil
	}))
	b.SetPropertyStr("realmCall", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		g := realms[t.Args()[0].Int64()]
		if g == nil {
			return nil, fmt.Errorf("realmCall: no such realm")
		}
		payload, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			return nil, err
		}
		deferred := 0
		if g.call(t.Args()[1].String(), payload, t.Args()[3], t.Args()[4]) {
			deferred = 1
		}
		return t.Context().NewInt64(int64(deferred)), nil
	}))
	b.SetPropertyStr("realmSettle", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		// A settlement for a disposed realm is a no-op: the Transport promise behind it
		// outlives an uninstall, and there is nothing left to resume.
		g := realms[t.Args()[0].Int64()]
		if g == nil {
			return nil, nil
		}
		callID := t.Args()[1].Int64()
		if t.Args()[2].IsNull() || t.Args()[2].IsUndefined() {
			g.settleNet(callID, nil, t.Args()[3].String())
			return nil, nil
		}
		bytes, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			g.settleNet(callID, nil, "net result not bytes")
			return nil, nil
		}
		g.settleNet(callID, bytes, "")
		return nil, nil
	}))
	b.SetPropertyStr("realmDispose", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
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
func newGuestRealm(loop *eventLoop, source string, hostCall *qjs.Value, memoryLimit uint64, budget time.Duration) (*guestRealm, error) {
	hostQc := loop.c
	// The execution bound needs nothing at construction: it lives in the engine
	// (qjs.Budget arms QuickJS's interrupt handler), so an unbounded realm costs what a
	// bounded one does.
	rt, err := qjs.New(qjs.WithMemoryLimit(memoryLimit))
	if err != nil {
		return nil, err
	}
	g := &guestRealm{
		hostQc: hostQc, rt: rt, qc: rt.Context(), loop: loop,
		hostCall: hostCall.Dup(), calls: map[int64]*initiatorCall{},
		budget: budget,
	}
	fail := func(err error) (*guestRealm, error) {
		g.close()
		return nil, err
	}
	// The Web globals quickjs-ng does not provide (TextEncoder/TextDecoder, atob, the
	// microtask queue), fetched from the host realm so both realms polyfill from ONE text
	// (host/native-polyfills.ts). First, because everything after it may use them.
	if _, err := g.qc.Eval("polyfills.js", qjs.Code(hostFnString(hostQc, "nativePolyfills"))); err != nil {
		return fail(fmt.Errorf("polyfills: %w", err))
	}
	// The driver's __start wrapper, fetched the same way (native-shim.ts `guestDriver`):
	// shared TS rather than a Go string TypeScript never saw.
	if _, err := g.qc.Eval("guest-driver.js", qjs.Code(hostFnString(hostQc, "guestDriver"))); err != nil {
		return fail(fmt.Errorf("guest driver: %w", err))
	}
	// The guest shares the host loop rather than owning one, so it just needs its job
	// queue pumped — no Go timers of its own.
	loop.addContext(g.qc, g.pump)

	// The single seam. Read (name, callId, payload) from the guest and shuttle the call to
	// the guest seam in the host realm. A sync name returns its bytes here; an async name
	// returns null, and the guest preamble parks a Promise under callId for settleNet.
	g.qc.Global().SetPropertyStr("__host_call", g.qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		payload, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			return nil, err
		}
		// nv and pv are the refcounted args (callID is an immediate) and Invoke only
		// borrows them, so both are freed once the call returns.
		nv := hostQc.NewString(t.Args()[0].String())
		pv := hostQc.NewArrayBuffer(payload)
		res, err := hostQc.Invoke(g.hostCall, hostQc.NewUndefined(),
			nv, pv, hostQc.NewInt64(t.Args()[1].Int64()))
		pv.Free()
		nv.Free()
		if err != nil {
			return nil, err
		}
		defer res.Free() // the seam's own-ref result (sync bytes, or the JS_NULL immediate)
		// CONTRACT: null is RESERVED for an async name whose promise hasn't settled. A
		// sync name returning null/undefined would be mistaken for an async one and leave
		// a guest Promise pending forever — which is why guest-seam.ts maps an empty
		// module reply to NONE rather than null.
		if res.IsNull() {
			// The call parked, and its settlement arrives as a HOST-realm microtask
			// (native-shim.ts nativeCall attaches `.then` → bridge.realmSettle). We are
			// inside a guest pump, i.e. after pumpAll already drained el.c this round, and
			// a holder answering from local fs generates no I/O of its own — so without a
			// nudge nothing wakes the loop and the peer sees silence until its stall clock
			// fires. Same rule as reportCall and markDead (eventLoop.wake).
			g.loop.wake()
			return t.Context().NewNull(), nil
		}
		out, err := qjs.JsTypedArrayToGo(res)
		if err != nil {
			return nil, err
		}
		return t.Context().NewArrayBuffer(out), nil
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

	if _, err := g.qc.Eval("guest-preamble.js", qjs.Code(hostGuestPreamble(hostQc))); err != nil {
		return fail(fmt.Errorf("guest preamble: %w", err))
	}
	if _, err := g.qc.Eval("guest.js", qjs.Code(source)); err != nil {
		return fail(fmt.Errorf("guest source: %w", err))
	}
	// Retained once — the holder path runs per inbound request, so re-resolving them each
	// call is needless churn. Guest-realm values, freed when rt.Close() tears the realm down.
	g.start = g.qc.Global().GetPropertyStr("__start")
	g.netResolve = g.qc.Global().GetPropertyStr("__netResolve")
	g.netReject = g.qc.Global().GetPropertyStr("__netReject")
	return g, nil
}

// hostGuestPreamble asks the host realm for guestPreamble() — the guest-side ABI
// (host.call over the single seam, register/__invoke for dispatch). Fetched rather than
// restated because a bundle ships one guest.js that runs byte-identical here and on the
// node/browser host: the preamble is a contract with signed content, not a per-target
// detail. Go's side of it is the __host_call above plus settleNet.
func hostGuestPreamble(hostQc *qjs.Context) string {
	return hostFnString(hostQc, "guestPreamble")
}

// hostFnString asks the host realm for one zero-argument string-valued export
// (host/native-shim.ts), so the plumbing a guest runs on is shared TS, never a Go string.
func hostFnString(hostQc *qjs.Context, name string) string {
	fn := hostQc.Global().GetPropertyStr(name)
	// IsUndefined, not nil — GetPropertyStr wraps a missing property as JS_UNDEFINED and
	// never returns Go nil (qjs/value.go), so a nil check would never fire.
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

// call invokes an entrypoint as the *initiator*: it may await net, so there is no result
// to return — onDone/onFail (host-realm functions settling the shim's Promise) fire when
// the entrypoint's own promise settles.
//
// It reports one thing synchronously: whether the entrypoint DEFERRED its answer (the
// preamble's defer()), which tells the shim's queue the realm is free again even though
// nothing has settled. __start returns the flag; this only carries it back.
func (g *guestRealm) call(entry string, payload []byte, onDone, onFail *qjs.Value) bool {
	if err := g.checkAlive(); err != nil {
		// Settle in the HOST realm, which is a different runtime and still alive.
		g.reportCall(onFail.Dup(), g.hostQc.NewString(err.Error()))
		return false
	}
	g.callSeq++
	id := g.callSeq
	g.calls[id] = &initiatorCall{onDone: onDone.Dup(), onFail: onFail.Dup()}
	entryV, argV := g.qc.NewString(entry), g.qc.NewArrayBuffer(payload)
	g.consumed = 0 // one top-level entrypoint invocation, one budget
	res, err := g.within(func() (*qjs.Value, error) {
		return g.qc.Invoke(g.start, g.qc.NewUndefined(), g.qc.NewInt64(id), entryV, argV)
	})
	entryV.Free()
	argV.Free()
	deferred := false
	if res != nil {
		deferred = res.Int64() == 1
		res.Free()
	}
	// __start catches everything the entrypoint throws, so an error here is the realm
	// itself failing (an OOM in the wrapper). Settle rather than strand the caller.
	if err != nil {
		if c := g.takeCall(id); c != nil {
			defer c.free()
			g.reportCall(c.onFail, g.hostQc.NewString(err.Error()))
		}
		return false
	}
	return deferred
}

// within runs one entry into the realm under the execution budget: it opens a clock
// segment and arms the engine's deadline for whatever is left. An overrun comes back as
// an ordinary error — QuickJS's interrupt handler throws (qjs.Runtime.Budget) and the
// entrypoint's promise rejects — so nothing here has to end the realm to stop it, which
// is the shape safe-js.ts has on the JS target.
//
// A segment that begins with the allowance already spent is armed at the floor rather
// than refused: the engine then interrupts it at its first check, routing the failure
// through the guest's own promises instead of past them.
func (g *guestRealm) within(fn func() (*qjs.Value, error)) (v *qjs.Value, err error) {
	remaining := time.Duration(0)
	if g.budget > 0 {
		if remaining = g.budget - g.consumed; remaining <= 0 {
			remaining = time.Nanosecond
		}
	}
	restore := g.rt.Budget(remaining)
	start := time.Now()
	defer func() {
		g.consumed += time.Since(start)
		restore()
	}()
	v, err = fn()
	// Only a segment that armed a deadline can have been interrupted by one, and asking
	// is itself an engine call — an unbounded realm must not pay for an answer that is
	// fixed in advance.
	if remaining <= 0 || !g.rt.TookInterrupt() {
		return v, err
	}
	// The engine stopped the guest mid-frame, so the invocation is OVER whatever its own
	// promises do next: delivering the rejection is more queued guest work under the
	// budget just exhausted, so it would be interrupted exactly like the code that overran
	// and the caller would wait out its timeout. Settling here closes that gap.
	//
	// `consumed` is deliberately NOT reset: it stays blown for the rest of this
	// invocation, so jobs the interrupted frame left behind are interrupted at their first
	// check instead of buying a full budget each time the loop pumps. The next top-level
	// entrypoint starts a fresh clock (see call).
	budgetErr := fmt.Errorf("guest realm: execution budget of %s exceeded", g.budget)
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

// settleAll rejects every in-flight initiator call with msg, releasing the callbacks. A
// realm dying with continuations outstanding must not leave its callers hanging forever
// — worse than an error, since they cannot retry, time out, or observe anything went
// wrong. safe-js needs no equivalent: its interrupt throws inside the guest and the
// guest's own promise rejects.
//
// Callbacks are HOST-realm values, so reporting works even once the guest runtime is
// gone. Rejecting only queues a host microtask, so the loop is woken (eventLoop.wake).
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

// pump drains this realm's job queue under its execution budget.
//
// The loop calls it instead of Context.Pump because a queued job IS guest code: the
// continuation after `await Promise.resolve()` never passes through settleNet, so pumping
// the context directly would run it outside every guard the realm has — one await would
// buy an unbounded loop. A dead realm is skipped; markDead already settled its callers.
//
// A pump that FAILS wakes the loop, which is load-bearing for the budget: the interrupt
// unwinds as a throw that rejects the entrypoint's promise, and delivering that rejection
// is itself more queued work after this round has drained. A guest spinning on its own
// generates no I/O, so without the nudge the caller waits out its whole timeout for a
// call the engine already stopped. A clean pump wakes nobody.
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
// allocating anything in the guest runtime: NewString/NewArrayBuffer on a closed module
// panics, so a check inside within() would come one allocation too late.
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
// realm's Transport promise settles (`bytes` fulfils, `msg` rejects). A fresh,
// non-re-entrant call into the suspended guest runtime; the loop's next pump runs the
// awaiting entrypoint's continuation.
func (g *guestRealm) settleNet(callID int64, bytes []byte, msg string) {
	if g.checkAlive() != nil {
		return // the realm the continuation belonged to no longer exists
	}
	var res *qjs.Value
	var err error
	if bytes != nil {
		// new Uint8Array(ab) inside __netResolve retains the ArrayBuffer, so freeing our
		// handle after the call leaves the guest's copy alive (refcount stays ≥ 1).
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
		// The continuation failed. What must happen is that nobody is left waiting on a
		// reply that is not coming — NOT that the realm ends. An overrun is already an
		// ordinary error with its callers settled (see within), and anything else here is
		// an exception out of the guest's own `__netResolve`, a fault contained to one
		// guest's continuation; killing the realm would brick it until the whole bundle
		// reloads. A realm the engine genuinely ended is checkAlive's business.
		if g.checkAlive() == nil {
			g.settleAll(fmt.Sprintf("guest realm failed delivering a net result: %v", err))
		}
	}
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
		fmt.Println("guest: call settlement error:", err)
	}
	// Settling a host promise only QUEUES a host microtask, and pumpAll pumps the host
	// realm before the guest realms — so this settlement's reaction lands after the round
	// has passed it. Since a reaction can be the next entrypoint in the realm's queue
	// (host/realm-queue.ts), without a nudge the chain advances one step per round and
	// then stalls on an idle loop, which a caller cannot tell from a hang.
	g.loop.wake()
}

func (c *initiatorCall) free() {
	c.onDone.Free()
	c.onFail.Free()
}

// close disposes the realm: detach from the loop, release the host-realm references it
// holds (those outlive the guest runtime, so rt.Close alone would leak them), and tear the
// runtime down. Settling comes first because an initiator's promise can only be resolved
// from inside this realm: tearing it down with calls outstanding leaves every parked
// caller waiting on something that can no longer happen.
func (g *guestRealm) close() {
	if g.rt == nil {
		return
	}
	g.loop.removeContext(g.qc) // stop pumpAll touching this realm before freeing it
	g.settleAll("guest realm closed")
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
