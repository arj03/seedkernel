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
// The net seam: a sync op (crypto/fs/clock/module) returns its bytes immediately. A net
// op genuinely round-trips, so the cap call returns null and the guest preamble hands the
// guest a real Promise it `await`s; when the host realm's Transport promise settles, the
// shim calls bridge.realmSettle and this file resolves the parked guest Promise. The
// shared loop (loop.go) then pumps the guest realm so the awaiting entrypoint resumes.
// There is no blocking and no Asyncify — a suspended async guest is just heap state, so
// the same realm answers a request (callSync) while an initiator is parked mid-await.
package main

import (
	"fmt"

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
		g, err := newGuestRealm(el, t.Args()[0].String(), t.Args()[1], mem)
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
	b.SetPropertyStr("realmCallSync", fn(func(t *qjs.This) (*qjs.Value, error) {
		g := realms[t.Args()[0].Int64()]
		if g == nil {
			return nil, fmt.Errorf("realmCallSync: no such realm")
		}
		payload, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			return nil, err
		}
		out, err := g.callSync(t.Args()[1].String(), payload)
		if err != nil {
			return nil, err
		}
		return t.Context().NewArrayBuffer(out), nil
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
func newGuestRealm(loop *eventLoop, source string, capCall *qjs.Value, memoryLimit uint64) (*guestRealm, error) {
	hostQc := loop.c
	rt, err := qjs.New(qjs.WithMemoryLimit(memoryLimit))
	if err != nil {
		return nil, err
	}
	g := &guestRealm{
		hostQc: hostQc, rt: rt, qc: rt.Context(), loop: loop,
		capCall: capCall.Dup(), calls: map[int64]*initiatorCall{},
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
	loop.addContext(g.qc)

	// The single seam. Read (op, callId, payload) from the guest and shuttle the call to
	// the cap-bridge in the host realm. A sync op returns its bytes here; a net op returns
	// null (its Transport promise isn't settled yet) and we return null too — the guest
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
		// CONTRACT: null is RESERVED for an async (net) op whose Transport promise hasn't
		// settled. Every sync op (crypto/fs/clock/module) returns its bytes here. A future
		// sync op returning null/undefined would be mistaken for a net op and leave a guest
		// Promise pending forever — which is why cap-bridge.ts maps an empty MODULE_CALL
		// reply to NONE rather than null.
		if res.IsNull() {
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
	g.callSeq++
	id := g.callSeq
	g.calls[id] = &initiatorCall{onDone: onDone.Dup(), onFail: onFail.Dup()}
	entryV, argV := g.qc.NewString(entry), g.qc.NewArrayBuffer(payload)
	res, err := g.qc.Invoke(g.start, g.qc.NewUndefined(), g.qc.NewInt64(id), entryV, argV)
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

// callSync invokes an entrypoint synchronously — the request side (README §12.8). The
// arg is the raw payload from the req frame; the guest reads its own dispatch byte from
// it if it needs one. A holder answers from local fs + crypto (no net), so it returns
// bytes without yielding. Called re-entrantly from the host realm's transport.onRequest,
// which is what lets it answer while an initiator is parked mid-await in this realm.
func (g *guestRealm) callSync(entry string, payload []byte) ([]byte, error) {
	name := g.handle
	if entry != "handle" {
		name = g.qc.NewString(entry)
		defer name.Free()
	}
	argv := g.qc.NewArrayBuffer(payload)
	defer argv.Free()
	res, err := g.qc.Invoke(g.invoke, g.qc.NewUndefined(), name, argv)
	if err != nil {
		return nil, err
	}
	defer res.Free()
	return qjs.JsTypedArrayToGo(res)
}

// settleNet resolves or rejects the guest Promise parked under callID when the host
// realm's Transport promise settles (`bytes` fulfils, `msg` rejects). A fresh,
// non-re-entrant call into the suspended guest runtime; the loop's next pump then runs
// the awaiting entrypoint's continuation.
func (g *guestRealm) settleNet(callID int64, bytes []byte, msg string) {
	var res *qjs.Value
	var err error
	if bytes != nil {
		// new Uint8Array(ab) inside __netResolve retains the ArrayBuffer, so freeing our
		// handle after the call leaves the guest's copy alive (refcount stays ≥ 1).
		ab := g.qc.NewArrayBuffer(bytes)
		res, err = g.qc.Invoke(g.netResolve, g.qc.NewUndefined(), g.qc.NewInt64(callID), ab)
		ab.Free()
	} else {
		msgV := g.qc.NewString(msg)
		res, err = g.qc.Invoke(g.netReject, g.qc.NewUndefined(), g.qc.NewInt64(callID), msgV)
		msgV.Free()
	}
	if res != nil {
		res.Free()
	}
	if err != nil {
		fmt.Println("guest: net delivery error:", err)
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
	for id, c := range g.calls {
		c.free()
		delete(g.calls, id)
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
