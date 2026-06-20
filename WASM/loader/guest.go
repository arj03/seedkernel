// guest.go — the confined guest realm (README §13.3 / §13.7). A second,
// zero-authority QuickJS realm: a fresh context exposes only the ECMAScript
// intrinsics, so the guest cannot even *name* sodium / fs / net. Its single seam is
// host.call(op, bytes), which Go funnels into the host realm's cap-bridge
// (capbridge.go). This is "the shell runs the app": an arbitrary signed guest
// reaches exactly the capability domains its manifest declared — nothing else.
//
// Blocking net: Bun's safe-js uses an Asyncify QuickJS build so host.call can block
// the guest while a net round-trip resolves; the shared guest (tier2-guest.js) relies
// on that — it calls host.call(CAP_NET_*) with no await. The engine's qjs.wasm is
// non-asyncify, but Go (not a JS host) drives the guest's wasm, so a net host.call can
// block at the host-import boundary just as well: __host_call hands the op to the host
// realm's cap-bridge, then pumps the host realm's loop (loop.awaitNetCall) until that
// Transport promise settles and returns the bytes — synchronous to the guest. Sync ops
// (crypto/fs/clock/module) return bytes immediately and never enter the pump.
package main

import (
	"fmt"
	"time"

	"seedloader/qjs"
)

// netCallTimeout is a safety bound on a synchronously-blocked net host.call: the
// host-realm Transport settles every request via its own (shorter) per-request
// timeout, so this only fires if that machinery wedges. Generous so it never clips a
// legitimately slow cohort round-trip.
const netCallTimeout = 120 * time.Second

type guestRealm struct {
	hostQc         *qjs.Context
	rt             *qjs.Runtime
	qc             *qjs.Context
	host           *eventLoop  // the shared host loop (drives both realms)
	hostBridgeCall *qjs.Value  // retained host-realm __hostBridgeCall
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
	g.hostBridgeCall = hostQc.Global().GetPropertyStr("__hostBridgeCall")

	// The single seam: read (op, payload) from the guest, shuttle the call to the host
	// realm's cap-bridge. A sync op returns its bytes; a net op returns null from the
	// bridge (its Transport promise isn't settled yet) and we block on it (awaitNetCall)
	// so the guest sees bytes either way.
	g.qc.Global().SetPropertyStr("__host_call", g.qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		op := t.Args()[0].Int32()
		payload, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			return nil, err
		}
		callID := host.nextCallID()
		res, err := hostQc.Invoke(g.hostBridgeCall, hostQc.NewUndefined(),
			hostQc.NewInt32(op), hostQc.NewArrayBuffer(payload), hostQc.NewInt64(callID))
		if err != nil {
			return nil, err
		}
		if res.IsNull() {
			// A net op: the host realm's Transport returned a Promise, so the bytes
			// aren't ready yet. Block here, pumping the host realm until it settles, and
			// return the bytes synchronously — the guest (tier2-guest.js) calls net
			// host.call without await, expecting Bun's Asyncify-blocking semantics. Go
			// driving the wasm means we can block at the host import instead of Asyncify.
			resp, err := host.awaitNetCall(callID, netCallTimeout)
			if err != nil {
				return nil, err
			}
			return t.Context().NewArrayBuffer(resp), nil
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
	return g, nil
}

// hostCapPreamble asks the host realm for capPreamble() — the `const CAP_X = n;`
// block the guest is written against, so guest and bridge can never drift.
func hostCapPreamble(hostQc *qjs.Context) string {
	v, err := hostQc.Invoke(hostQc.Global().GetPropertyStr("capPreamble"), hostQc.NewUndefined())
	if err != nil {
		panic(fmt.Sprintf("capPreamble: %v", err))
	}
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

// serveHandle invokes the guest's `handle` entrypoint synchronously — the holder
// side (README §13.7). The arg is [type u8][payload]; the guest answers from local
// fs + crypto (no net), so it returns bytes without yielding. Called re-entrantly
// from the host realm's transport.onRequest (wireHolder).
func (g *guestRealm) serveHandle(typ byte, payload []byte) ([]byte, error) {
	arg := make([]byte, 1+len(payload))
	arg[0] = typ
	copy(arg[1:], payload)
	res, err := g.qc.Invoke(
		g.qc.Global().GetPropertyStr("__invoke"),
		g.qc.NewUndefined(), g.qc.NewString("handle"), g.qc.NewArrayBuffer(arg),
	)
	if err != nil {
		return nil, err
	}
	return qjs.JsTypedArrayToGo(res) // sync handle → ArrayBuffer (not a Promise)
}

func (g *guestRealm) close() {
	if g.rt != nil {
		g.host.removeContext(g.qc) // stop pumpAll touching this realm before freeing it
		g.rt.Close()
	}
}

// guestPreambleJS is the guest-side ABI (safe-js.ts PREAMBLE): host.call over the
// single seam, plus register/__invoke for entrypoint dispatch. Pure JS, no authority.
// host.call is synchronous for every op — sync ops return their bytes directly, and a
// net op blocks in Go (__host_call → loop.awaitNetCall) until its round-trip settles,
// so the guest never has to await net. __host_call reads the payload via
// JsTypedArrayToGo (view-aware, copies on read), so the buffer is handed across as-is.
const guestPreambleJS = `
"use strict";
globalThis.host = {
  call(op, bytes) {
    return new Uint8Array(__host_call(op, bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes));
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
