// guest.go — the confined guest realm (README §12.3 / §12.8). A second,
// zero-authority QuickJS realm: a fresh context exposes only the ECMAScript
// intrinsics, so the guest cannot even *name* sodium / fs / net. Its single seam is
// host.call(op, bytes), which Go funnels into the host realm's cap-bridge
// (capbridge.go). This is "the shell runs the app": an arbitrary signed guest
// reaches exactly the capability domains its manifest declared — nothing else.
//
// The net seam: a sync op (crypto/fs/clock/module) returns its bytes immediately. A net
// op genuinely round-trips, so __host_call returns null and the guest preamble hands the
// guest a real Promise it `await`s: the host realm's cap-bridge kicks off the Transport
// request under a callId, and when that promise settles __netDone/__netFail (node.go)
// route through el.resolveGuestNet → deliverNet, which resolves the guest Promise. The
// shared loop (loop.go) then pumps the guest realm so the awaiting entrypoint resumes.
// There is no blocking and no Asyncify — a suspended async guest is just heap state, so
// the same realm answers a request (serveHandle) while an initiator is parked mid-await.
package main

import (
	"fmt"
	"time"

	"seedloader/qjs"
)

type guestRealm struct {
	hostQc         *qjs.Context
	rt             *qjs.Runtime
	qc             *qjs.Context
	host           *eventLoop // the shared host loop (drives both realms)
	hostBridgeCall *qjs.Value // retained host-realm __hostBridgeCall
	invoke         *qjs.Value // retained guest-realm __invoke (holder hot path)
	handleName     *qjs.Value // retained "handle" entry name for serveHandle
	netResolve     *qjs.Value // retained guest-realm __netResolve (net op fulfilled)
	netReject      *qjs.Value // retained guest-realm __netReject (net op failed)
}

// newGuestRealm builds a confined realm running guestSource, fronted by the cap op
// preamble (capPreamble) and the app config (`const APP = …`), with host.call wired
// to the host realm's cap-bridge over the shared loop. The host realm (host.c) must
// already have the cap-bridge installed (exposeCapBridge + a __buildCapBridge call).
func newGuestRealm(host *eventLoop, appJSON, guestSource string) (*guestRealm, error) {
	hostQc := host.c
	rt, err := qjs.New()
	if err != nil {
		return nil, err
	}
	g := &guestRealm{hostQc: hostQc, rt: rt, qc: rt.Context(), host: host}
	installPolyfills(g.qc)
	// The guest shares the host loop rather than owning one, so it just needs its job
	// queue pumped (host.addContext) and a queueMicrotask polyfill — no Go timers.
	if _, err := g.qc.Eval("guest-setup.js", qjs.Code(`globalThis.queueMicrotask = (f) => { Promise.resolve().then(f); };`)); err != nil {
		rt.Close()
		return nil, err
	}
	host.addContext(g.qc)
	host.resolveGuestNet = g.deliverNet
	g.hostBridgeCall = hostQc.Global().GetPropertyStr("__hostBridgeCall")

	// The single seam: read (op, callId, payload) from the guest, shuttle the call to the
	// host realm's cap-bridge. A sync op returns its bytes here; a net op returns null from
	// the bridge (its Transport promise isn't settled yet), and we return null too — the
	// guest preamble then hands the guest a Promise registered under callId, which
	// deliverNet resolves when the host realm's Transport settles.
	g.qc.Global().SetPropertyStr("__host_call", g.qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		op := t.Args()[0].Int32()
		callID := t.Args()[1].Int64()
		payload, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			return nil, err
		}
		// pv is the only refcounted arg (op/callID are immediates); Invoke borrows it,
		// so free it once the call returns. Without this every guest host.call leaked a
		// host-realm ArrayBuffer.
		pv := hostQc.NewArrayBuffer(payload)
		res, err := hostQc.Invoke(g.hostBridgeCall, hostQc.NewUndefined(),
			hostQc.NewInt32(op), pv, hostQc.NewInt64(callID))
		pv.Free()
		if err != nil {
			return nil, err
		}
		defer res.Free() // the bridge's own-ref result (sync bytes, or the JS_NULL immediate)
		// CONTRACT: null from __hostBridgeCall is RESERVED for an async (net) op whose
		// Transport promise hasn't settled. Every sync op (crypto/fs/clock/module) returns
		// its bytes here. A future sync op that returned null/undefined would be mistaken
		// for a net op and leave a guest Promise pending forever — so such ops must always
		// return bytes (capbridge.go's MODULE_CALL maps an empty handler reply to NONE,
		// never null, precisely to keep this invariant).
		if res.IsNull() {
			// A net op: return null to the guest preamble, which creates the pending
			// Promise for this callID. __netDone/__netFail → deliverNet settle it later.
			return t.Context().NewNull(), nil
		}
		out, err := qjs.JsTypedArrayToGo(res)
		if err != nil {
			return nil, err
		}
		return t.Context().NewArrayBuffer(out), nil
	}))

	if _, err := g.qc.Eval("guest-preamble.js", qjs.Code(guestPreambleJS)); err != nil {
		rt.Close()
		return nil, fmt.Errorf("guest preamble: %w", err)
	}
	full := hostCapPreamble(hostQc) + "const APP = " + appJSON + ";\n" + guestSource
	if _, err := g.qc.Eval("guest.js", qjs.Code(full)); err != nil {
		rt.Close()
		return nil, fmt.Errorf("guest source: %w", err)
	}
	// Retain the entrypoint dispatcher + its "handle" name once: serveHandle runs per
	// inbound request, so re-resolving (and freeing) them each call is needless churn.
	// Also retain the net completion callbacks deliverNet drives. All are guest-realm
	// values, freed when rt.Close() tears down the realm.
	g.invoke = g.qc.Global().GetPropertyStr("__invoke")
	g.handleName = g.qc.NewString("handle")
	g.netResolve = g.qc.Global().GetPropertyStr("__netResolve")
	g.netReject = g.qc.Global().GetPropertyStr("__netReject")
	return g, nil
}

// deliverNet settles the guest Promise for a net host.call whose host-realm Transport
// request just resolved (kind 0, with bytes) or failed (kind 1, with msg). It is the
// loop's el.resolveGuestNet hook: __netDone/__netFail (node.go) call it when the host
// realm's Transport promise settles. It invokes the guest realm's __netResolve/__netReject
// — a fresh, non-re-entrant call into the (suspended) guest runtime — which resolves the
// pending Promise; the loop's next pumpAll then runs the awaiting entrypoint's continuation.
func (g *guestRealm) deliverNet(callID int64, kind int, bytes []byte, msg string) {
	var res *qjs.Value
	var err error
	if kind == 0 {
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

// hostCapPreamble asks the host realm for capPreamble() — the `const CAP_X = n;`
// block the guest is written against, so guest and bridge can never drift.
func hostCapPreamble(hostQc *qjs.Context) string {
	fn := hostQc.Global().GetPropertyStr("capPreamble")
	v, err := hostQc.Invoke(fn, hostQc.NewUndefined())
	fn.Free()
	if err != nil {
		panic(fmt.Sprintf("capPreamble: %v", err))
	}
	defer v.Free()
	return v.String()
}

// runGuest invokes a registered guest entrypoint (put/get/…) as the *initiator*. The
// arg and result cross as raw bytes; the shared loop is driven (pumping both realms)
// until the entrypoint settles — including any net round-trips it awaits.
func (g *guestRealm) runGuest(entry string, payload []byte) ([]byte, error) {
	g.qc.Global().SetPropertyStr("__arg", g.qc.NewArrayBuffer(payload))
	kind, value, msg, err := g.host.awaitIn(g.qc, fmt.Sprintf("__invoke(%q, __arg)", entry), 30*time.Second)
	if err != nil {
		return nil, err
	}
	if kind != 0 {
		return nil, fmt.Errorf("guest %s: %s", entry, msg)
	}
	return value, nil
}

// serveHandle invokes the guest's `handle` entrypoint synchronously — the request
// side (README §12.8). The arg is [type u8][payload]; the guest answers from local
// fs + crypto (no net), so it returns bytes without yielding. Called re-entrantly
// from the host realm's transport.onRequest (wireServe).
func (g *guestRealm) serveHandle(typ byte, payload []byte) ([]byte, error) {
	// Stage [type][payload] straight into one wasm buffer instead of building a
	// concatenated Go slice first and copying it in again (two passes over payload).
	argv := g.qc.NewArrayBufferParts([]byte{typ}, payload)
	defer argv.Free() // Invoke borrows its args; free the per-request ArrayBuffer
	res, err := g.qc.Invoke(g.invoke, g.qc.NewUndefined(), g.handleName, argv)
	if err != nil {
		return nil, err
	}
	defer res.Free()                 // own-ref result; the copy below happens before this runs
	return qjs.JsTypedArrayToGo(res) // sync handle → ArrayBuffer (not a Promise)
}

func (g *guestRealm) close() {
	if g.rt == nil {
		return
	}
	g.host.removeContext(g.qc)      // stop pumpAll touching this realm before freeing it
	g.host.resolveGuestNet = nil    // stop __netDone/__netFail routing into a freed realm
	// hostBridgeCall is a HOST-realm ref; it outlives the guest runtime, so rt.Close()
	// (which only tears down the guest realm) won't reclaim it — free it explicitly. The
	// cached guest-realm values (invoke/handleName/netResolve/netReject) die with
	// rt.Close(), so leave those.
	g.hostBridgeCall.Free()
	g.rt.Close()
	g.rt = nil
}

// guestPreambleJS is the guest-side ABI (safe-js.ts PREAMBLE): host.call over the
// single seam, plus register/__invoke for entrypoint dispatch. Pure JS, no authority.
// A sync op returns its bytes directly; a net op returns null from __host_call (Go kicked
// off the Transport request under callId) and host.call hands back a Promise registered in
// __pending, which deliverNet resolves via __netResolve/__netReject when the round-trip
// settles. So a guest `await host.call(CAP_NET_*)` suspends and resumes on real promises,
// and a fan-out is just Promise.all. __host_call reads the payload via JsTypedArrayToGo
// (view-aware, copies on read), so the buffer is handed across as-is.
const guestPreambleJS = `
"use strict";
let __callSeq = 0;
const __pending = Object.create(null);
globalThis.__netResolve = (callId, bytes) => {
  const p = __pending[callId];
  if (!p) return;
  delete __pending[callId];
  p.resolve(new Uint8Array(bytes));
};
globalThis.__netReject = (callId, msg) => {
  const p = __pending[callId];
  if (!p) return;
  delete __pending[callId];
  p.reject(new Error(msg));
};
globalThis.host = {
  call(op, bytes) {
    const callId = ++__callSeq;
    const r = __host_call(op, callId, bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes);
    if (r !== null) return new Uint8Array(r);          // sync op — bytes directly
    return new Promise((resolve, reject) => { __pending[callId] = { resolve, reject }; }); // net op
  },
};
globalThis.__entries = Object.create(null);
globalThis.register = (name, fn) => { globalThis.__entries[name] = fn; };
function __norm(out) {
  if (out instanceof ArrayBuffer) return out;
  if (out instanceof Uint8Array) {
    return (out.byteOffset === 0 && out.byteLength === out.buffer.byteLength) ? out.buffer : out.slice().buffer;
  }
  throw new Error("safe-js: entrypoint must return Uint8Array | ArrayBuffer");
}
globalThis.__invoke = (name, argBuf) => {
  const fn = globalThis.__entries[name];
  if (typeof fn !== "function") throw new Error("safe-js: no entrypoint '" + name + "'");
  const out = fn(new Uint8Array(argBuf));
  return out && typeof out.then === "function" ? out.then(__norm) : __norm(out);
};
`
