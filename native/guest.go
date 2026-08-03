// guest.go — the confined guest realm (README §12.3 / §12.8) and its driver: this
// target's answer to exactly the seam safe-js.ts is on the JS targets, exposed to the
// shell as `createRealm` (host/native-shim.ts) so `createShell` drives either without
// knowing which it holds.
//
// A realm is a second, zero-authority QuickJS runtime: a fresh context holds only the
// ECMAScript intrinsics, so the guest cannot even *name* sodium / fs / net. Its single
// seam is host.call(op, bytes), which Go funnels into the cap-bridge the shell built
// for that app — a JS function in the host realm, retained here. Nothing in this file
// knows what an op means or which ops an app may reach; that is the cap-bridge's, and
// the manifest's, business.
//
// The async seam: a sync op (the primitive catalog, clock, module, the raw-link and
// transport ops) returns its bytes immediately. A round-tripping op — NET_SEND and every
// FS_* — returns null from the cap call, and the guest preamble hands the guest a real
// Promise it `await`s; when the shim's promise settles it calls bridge.realmSettle and
// this file resolves the parked guest Promise. The shared loop (loop.go) then pumps the
// guest realm so the awaiting entrypoint resumes. There is no blocking and no Asyncify —
// a suspended async guest is just heap state.
//
// There is one way in, `realmCall`, and it is asynchronous — for the initiator and the
// holder alike. A synchronous second entry is not on offer: a holder answers from local
// storage, and the fs seam is async on every target because a browser backend cannot make
// it anything else. One entrypoint still runs to completion before the next begins, but
// that comes from the shim's per-realm queue (host/realm-queue.ts) — shared TS, so both
// targets get the same guarantee from one implementation.
package main

import (
	"errors"
	"fmt"
	"time"

	"seedloader/qjs"
)

// defaultRealmMemory caps a confined realm's heap when the shell names no limit,
// matching safe-js.ts's default on the node/browser target so the same signed guest
// meets the same ceiling on either. It is a confinement property, not a tuning knob:
// the admission policy (§12.5) decides *which* guest runs, but an admitted guest that
// runs away must exhaust its own realm rather than the host — including on the request
// path, which a remote peer drives. QuickJS takes it at runtime creation only, hence
// qjs.WithMemoryLimit rather than a setter.
const defaultRealmMemory = 64 << 20 // 64 MiB

// defaultRealmBudget mirrors safe-js.ts's DEFAULT_DEADLINE_MS (README §16.1) so the two
// targets hold a guest to the same number. Like the memory cap it is a real default, not
// an absent one: a shell that configures nothing still gets a bounded guest.
const defaultRealmBudget = 5 * time.Second

var (
	// realms are the live confined realms, keyed by the opaque handle JS holds. A
	// shell with two guest apps loaded has two, each with its own cap-bridge — which
	// is why the net-settle routing is per realm rather than a single global hook.
	realms   = map[int64]*guestRealm{}
	realmSeq int64
)

type guestRealm struct {
	hostQc *qjs.Context
	rt     *qjs.Runtime
	qc     *qjs.Context
	loop   *eventLoop

	capCall *qjs.Value // retained host-realm cap call — this app's whole authority
	invoke  *qjs.Value // guest-realm __invoke (the synchronous holder hot path)
	start   *qjs.Value // guest-realm __start (an initiator call, settled by callback)
	handle  *qjs.Value // retained "handle" entry name, re-used per inbound request

	netResolve *qjs.Value // guest-realm __netResolve (a net op fulfilled)
	netReject  *qjs.Value // guest-realm __netReject (a net op failed)

	// calls are initiator calls in flight, keyed by an id the guest carries back. Each
	// holds the host-realm resolve/reject of the Promise the shim handed the shell.
	calls   map[int64]*initiatorCall
	callSeq int64

	// Execution budget (README §12.3), mirroring safe-js.ts's ExecClock. `budget` is the
	// per-entrypoint allowance; `consumed` accumulates only the segments during which
	// guest code actually holds the thread, so time the host spends awaiting a bridge on
	// the guest's behalf is nobody's budget. Without that split one number cannot serve
	// both roles: an initiator parked on a 2s request would be killed by any budget tight
	// enough to catch a holder's infinite loop.
	budget   time.Duration
	consumed time.Duration
	// dead is set when a budget kill terminated the wasm module. wazero closes the module
	// rather than unwinding one call, so the realm cannot be reused: every later call is
	// refused with an error rather than panicking on a freed handle. Recovering means
	// building a fresh realm — reloading the bundle — not retrying against this one.
	dead bool
}

type initiatorCall struct{ onDone, onFail *qjs.Value }

// guestDriverJS is the realm's own plumbing — not the guest ABI (that is the shared
// guestPreamble, which a signed guest is written against), but this driver's twin of
// what safe-js.ts does in TypeScript: a microtask queue over the shared loop, and one
// pre-compiled entry wrapper so an initiator call costs an Invoke rather than a parse.
// __start never throws: a synchronously-throwing entrypoint settles through __callFail
// like any other failure, so realmCall's contract is "always settles via a callback".
const guestDriverJS = `
"use strict";
globalThis.queueMicrotask = (f) => { Promise.resolve().then(f); };
globalThis.__start = function (id, entry, arg) {
  try {
    Promise.resolve(__invoke(entry, arg)).then(
      (v) => __callDone(id, v),
      (e) => __callFail(id, String(e && e.message || e)));
  } catch (e) {
    __callFail(id, String(e && e.message || e));
  }
};
`

// installRealmBridge adds the confined-realm powers to the `bridge` object: create a
// realm, call into it (as initiator or synchronously), settle a parked net op, dispose.
// This is the whole of Go's involvement with a guest — no cap-bridge, no preamble
// assembly, no bundle facts, no dispatch.
func installRealmBridge(qc *qjs.Context, b *qjs.Value) {
	fn := func(g func(*qjs.This) (*qjs.Value, error)) *qjs.Value { return qc.Function(g) }

	b.SetPropertyStr("createRealm", fn(func(t *qjs.This) (*qjs.Value, error) {
		mem := uint64(t.Args()[2].Int64())
		if mem == 0 {
			mem = defaultRealmMemory
		}
		// 0 from the shim means "the target's default", matching how mem is read above —
		// so a shell that configures nothing still gets a bounded realm on both targets.
		// A negative value is the shim's encoding of Infinity: no budget, said explicitly.
		budget := defaultRealmBudget
		if ms := t.Args()[3].Int64(); ms < 0 {
			budget = 0
		} else if ms > 0 {
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
	b.SetPropertyStr("realmCall", fn(func(t *qjs.This) (*qjs.Value, error) {
		g := realms[t.Args()[0].Int64()]
		if g == nil {
			return nil, fmt.Errorf("realmCall: no such realm")
		}
		payload, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			return nil, err
		}
		g.call(t.Args()[1].String(), payload, t.Args()[3], t.Args()[4])
		return nil, nil
	}))
	b.SetPropertyStr("realmSettle", fn(func(t *qjs.This) (*qjs.Value, error) {
		// A settlement for a realm that has since been disposed is a no-op: the
		// Transport promise behind it outlives an uninstall, and there is nothing
		// left to resume.
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
	b.SetPropertyStr("realmDispose", fn(func(t *qjs.This) (*qjs.Value, error) {
		id := t.Args()[0].Int64()
		if g := realms[id]; g != nil {
			delete(realms, id)
			g.close()
		}
		return nil, nil
	}))
}

// newGuestRealm builds a confined realm running `source` — which the shell has already
// fronted with the cap preamble, the bundle facts and the app config, so what arrives
// here is exactly what a safe-js realm would be handed — with host.call funnelled into
// `capCall`, a host-realm function the shell built for this app.
func newGuestRealm(loop *eventLoop, source string, capCall *qjs.Value, memoryLimit uint64, budget time.Duration) (*guestRealm, error) {
	hostQc := loop.c
	// Interruptibility is paired with the budget: armed only when there is one to
	// enforce, so a realm explicitly run unbounded (deadlineMs: Infinity) does not pay
	// wazero's per-call context check for a lever nothing will pull.
	ropts := []qjs.Option{qjs.WithMemoryLimit(memoryLimit)}
	if budget > 0 {
		ropts = append(ropts, qjs.WithInterruptible())
	}
	rt, err := qjs.New(ropts...)
	if err != nil {
		return nil, err
	}
	g := &guestRealm{
		hostQc: hostQc, rt: rt, qc: rt.Context(), loop: loop,
		capCall: capCall.Dup(), calls: map[int64]*initiatorCall{},
		budget: budget,
	}
	fail := func(err error) (*guestRealm, error) {
		g.close()
		return nil, err
	}
	installPolyfills(g.qc)
	if _, err := g.qc.Eval("guest-driver.js", qjs.Code(guestDriverJS)); err != nil {
		return fail(fmt.Errorf("guest driver: %w", err))
	}
	// The guest shares the host loop rather than owning one, so it just needs its job
	// queue pumped — no Go timers of its own.
	loop.addContext(g.qc, g.pump)

	// The single seam. Read (op, callId, payload) from the guest and shuttle the call to
	// the cap-bridge in the host realm. A sync op returns its bytes here; an async op
	// returns null (its promise isn't settled yet) and we return null too — the guest
	// preamble then parks a Promise under callId, which settleNet resolves later.
	g.qc.Global().SetPropertyStr("__host_call", g.qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		payload, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			return nil, err
		}
		// pv is the only refcounted arg (op/callID are immediates); Invoke borrows it,
		// so free it once the call returns. Without this every guest host.call leaked a
		// host-realm ArrayBuffer.
		pv := hostQc.NewArrayBuffer(payload)
		res, err := hostQc.Invoke(g.capCall, hostQc.NewUndefined(),
			hostQc.NewInt32(t.Args()[0].Int32()), pv, hostQc.NewInt64(t.Args()[1].Int64()))
		pv.Free()
		if err != nil {
			return nil, err
		}
		defer res.Free() // the cap call's own-ref result (sync bytes, or the JS_NULL immediate)
		// CONTRACT: null is RESERVED for an async op whose promise hasn't settled — NET_SEND
		// and every FS_* (core/fs.ts is async on every target, so the native shim's
		// synchronous __fs primitives are still wrapped into a resolved Promise). The
		// remaining sync ops (crypto/clock/module) return their bytes here. A sync op
		// returning null/undefined would be mistaken for an async one and leave a guest
		// Promise pending forever — which is why cap-bridge.ts maps an empty MODULE_CALL
		// reply to NONE rather than null.
		if res.IsNull() {
			// The op parked, and its settlement will arrive as a HOST-realm microtask
			// (native-shim.ts capCall attaches `.then` → bridge.realmSettle). We are running
			// inside the guest pump of some round, i.e. AFTER pumpAll already drained el.c
			// this round — so without a nudge that microtask sits unqueued-for until
			// something else happens to wake the loop, and step() blocks with no timer and
			// no task. Nothing else is coming: a holder answering from local fs generates no
			// I/O of its own, so the continuation (and the response it would produce) never
			// runs and the peer sees silence until its stall clock fires. This is the same
			// rule reportCall and markDead follow — anything that settles or parks a promise
			// outside a task/timer path has to wake the loop (see eventLoop.wake).
			//
			// Cheap and self-limiting: only an op that actually parked wakes the loop, and
			// wake() is a non-blocking send onto a buffered channel.
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
	// settles. Both hand the result to the host-realm callbacks the shim registered, which
	// settle the Promise the shell is awaiting.
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
	// Retain the entry points once: the holder path runs per inbound request, so
	// re-resolving (and freeing) them each call is needless churn. All are guest-realm
	// values, freed when rt.Close() tears the realm down.
	g.invoke = g.qc.Global().GetPropertyStr("__invoke")
	g.start = g.qc.Global().GetPropertyStr("__start")
	g.handle = g.qc.NewString("handle")
	g.netResolve = g.qc.Global().GetPropertyStr("__netResolve")
	g.netReject = g.qc.Global().GetPropertyStr("__netReject")
	return g, nil
}

// hostGuestPreamble asks the host realm for guestPreamble() — the guest-side ABI
// (host.call over the single seam, register/__invoke for dispatch). Fetched rather than
// restated for the same reason the cap preamble is: a bundle ships one guest.js that runs
// byte-identical here and on the node/browser host (safe-js.ts), so the preamble is a
// contract with signed content, not a per-target detail. Go's side of that contract is
// the __host_call installed above (null ⇒ async under callId) plus settleNet.
func hostGuestPreamble(hostQc *qjs.Context) string {
	fn := hostQc.Global().GetPropertyStr("guestPreamble")
	v, err := hostQc.Invoke(fn, hostQc.NewUndefined())
	fn.Free()
	if err != nil {
		panic(fmt.Sprintf("guestPreamble: %v", err))
	}
	defer v.Free()
	return v.String()
}

// call invokes an entrypoint as the *initiator*: it may await net, so there is no
// result to return — onDone/onFail (host-realm functions settling the shim's Promise)
// are called when the entrypoint's own promise settles, which the shared loop drives.
func (g *guestRealm) call(entry string, payload []byte, onDone, onFail *qjs.Value) {
	if err := g.checkAlive(); err != nil {
		// Settle in the HOST realm, which is a different runtime and still alive.
		g.reportCall(onFail.Dup(), g.hostQc.NewString(err.Error()))
		return
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
	if res != nil {
		res.Free()
	}
	// __start catches everything the entrypoint throws, so an error here is the realm
	// itself failing (an OOM in the wrapper). Settle rather than strand the caller.
	if err != nil {
		if c := g.takeCall(id); c != nil {
			defer c.free()
			g.reportCall(c.onFail, g.hostQc.NewString(err.Error()))
		}
	}
}

// within runs one entry into the realm under the execution budget.
//
// It opens a clock segment, arms wazero's deadline for whatever budget is left, and
// converts a budget kill into an error. The kill arrives as a panic from qjs's call
// path (wazero returns an error, which qjs.Runtime.call panics on) and is fatal to the
// module, so the realm is marked dead here rather than pretending it can be reused.
func (g *guestRealm) within(fn func() (*qjs.Value, error)) (v *qjs.Value, err error) {
	remaining := time.Duration(0)
	if g.budget > 0 {
		if remaining = g.budget - g.consumed; remaining <= 0 {
			// Cumulative exhaustion across segments: the module is still alive, but the
			// guest has spent its allowance and its in-flight work cannot be unwound
			// from here, so the realm ends. Distinct from the wazero kill below only in
			// how it was reached.
			return nil, g.markDead(errors.New("guest realm terminated: execution budget exceeded"))
		}
	}
	defer func() {
		if rec := recover(); rec != nil {
			// Distinguish a budget kill from any other engine panic by asking the module
			// rather than by matching on the message: a closed module IS the kill.
			if !g.rt.Alive() {
				err = g.markDead(fmt.Errorf("guest realm terminated: execution budget of %s exceeded", g.budget))
				return
			}
			panic(rec)
		}
	}()
	restore := g.rt.Budget(remaining)
	start := time.Now()
	defer func() {
		g.consumed += time.Since(start)
		restore()
	}()
	v, err = fn()
	// A kill reaches us two ways and both must end the realm the same way: qjs's call
	// helpers panic on a wazero error, which the recover above catches, but any path
	// that *returns* the error instead (Context.Pump does) would otherwise slip past
	// with the realm silently dead and its callers never settled. Ask the module.
	if err != nil && !g.rt.Alive() {
		return nil, g.markDead(fmt.Errorf("guest realm terminated: execution budget of %s exceeded", g.budget))
	}
	return v, err
}

// markDead ends the realm's life and settles every call it still owes.
//
// The settling is the point. A realm dies with continuations outstanding — the kill
// typically lands inside settleNet, after the initiator's promise reached the shell but
// before anything resolved it — and a dead realm cannot reject them itself. Without this
// the shell's promise never settles and the caller hangs forever, which is strictly worse
// than an error: it cannot retry, time out, or even observe that anything went wrong.
// safe-js has no equivalent path because its interrupt throws inside the guest and the
// guest's own promise rejects; on this target the host has to do it.
//
// Callbacks are HOST-realm values, so reporting works even though the guest runtime is
// gone. Returns err so callers can `return nil, g.markDead(...)`.
func (g *guestRealm) markDead(err error) error {
	g.dead = true
	settled := false
	for id, c := range g.calls {
		delete(g.calls, id)
		g.reportCall(c.onFail, g.hostQc.NewString(err.Error()))
		c.free()
		settled = true
	}
	// Rejecting those promises only queues a microtask on the host realm. If this ran
	// inside a pump that has already drained, nothing would deliver it and the caller
	// would wait out its whole timeout — a hang instead of the error we just produced.
	if settled {
		g.loop.wake()
	}
	return err
}

// pump drains this realm's job queue under its execution budget.
//
// The loop calls it instead of Context.Pump because a queued job IS guest code: the
// continuation after `await Promise.resolve()` never passes through settleNet, so
// pumping the context directly would run it outside every guard the realm has. A guest
// could then spend one await to buy an unbounded loop — the budget would cover the
// segment before the await and nothing after it.
//
// A dead realm is skipped rather than pumped; markDead has already settled its callers.
func (g *guestRealm) pump() {
	if g.rt == nil || g.dead || !g.rt.Alive() {
		return
	}
	_, _ = g.within(func() (*qjs.Value, error) {
		return nil, g.qc.Pump()
	})
}

// checkAlive refuses a realm a budget kill already terminated. Callers must ask BEFORE
// allocating anything in the guest runtime — NewString/NewArrayBuffer on a closed module
// would panic, so a late check inside within() would come one allocation too late.
func (g *guestRealm) checkAlive() error {
	if g.rt == nil {
		// Closed, not killed. close() has already settled whatever it owed, so this
		// only has to refuse — and must not touch g.rt, which is nil from here on.
		return errors.New("guest realm closed")
	}
	if g.dead || !g.rt.Alive() {
		return g.markDead(fmt.Errorf("guest realm terminated: execution budget of %s exceeded", g.budget))
	}
	return nil
}

// There is no nested-budget case: the shim's per-realm queue leaves exactly one budget
// window open at a time, so resetting `consumed` per call is the whole of the accounting
// — same as safe-js.ts.

// settleNet resolves or rejects the guest Promise parked under callID when the host
// realm's Transport promise settles (`bytes` fulfils, `msg` rejects). A fresh,
// non-re-entrant call into the suspended guest runtime; the loop's next pump then runs
// the awaiting entrypoint's continuation.
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
		// The continuation itself failed — typically the budget kill. markDead has
		// already settled the pending calls when that is why; this covers any other
		// engine failure so a caller is never left waiting on a realm that cannot reply.
		if !g.dead {
			g.markDead(fmt.Errorf("guest realm failed delivering a net result: %w", err))
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
	// Settling a host promise only QUEUES a host microtask, and one pumpAll round pumps
	// the host realm before the guest realms — so the reaction to this settlement lands
	// after this round has passed it. That matters now that a reaction can be the next
	// entrypoint in the realm's serialization queue (host/realm-queue.ts): without a
	// nudge the chain advances one step per round and then stalls on an idle loop,
	// which to a caller awaiting the result is indistinguishable from a hang. Same rule
	// markDead follows — anything settling a promise from Go outside a task/timer path
	// has to wake the loop.
	g.loop.wake()
}

func (c *initiatorCall) free() {
	c.onDone.Free()
	c.onFail.Free()
}

// close disposes the realm: detach from the loop, release the host-realm references it
// holds (those outlive the guest runtime, so rt.Close alone would leak them), and tear
// the runtime down. Any call still in flight is abandoned — its Promise never settles,
// which is the truthful outcome for a realm that no longer exists.
func (g *guestRealm) close() {
	if g.rt == nil {
		return
	}
	g.loop.removeContext(g.qc) // stop pumpAll touching this realm before freeing it
	// Settle before freeing, not instead of it. An initiator's promise can only be
	// resolved from inside this realm, so tearing it down with calls outstanding leaves
	// every parked caller waiting on something that can no longer happen — the same hang
	// markDead exists to prevent, and the one safe-js's dispose() fixes on that target.
	settled := false
	for id, c := range g.calls {
		delete(g.calls, id)
		g.reportCall(c.onFail, g.hostQc.NewString("guest realm closed"))
		c.free()
		settled = true
	}
	if settled {
		g.loop.wake() // rejecting only queues a microtask; see eventLoop.wake
	}
	g.capCall.Free() // a HOST-realm ref: rt.Close only tears down the guest realm
	g.rt.Close()
	g.rt = nil
}

// discard tears down only the guest runtime, for a shutdown that is about to free the
// host realm too — there is nothing left to detach from and no host-realm reference
// worth releasing (its context is going away in the same breath).
func (g *guestRealm) discard() {
	if g.rt != nil {
		g.rt.Close()
		g.rt = nil
	}
}
