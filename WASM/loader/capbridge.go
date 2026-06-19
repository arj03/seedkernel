// capbridge.go — wires the shared cap-bridge (host/cap-bridge.ts, README §13.2)
// into the host realm. cap-bridge.ts is reused verbatim: it is the single
// capability funnel the confined guest reaches through `host.call(op, bytes)`. It
// runs in the HOST realm (where sodium/fs/transport live) so the guest realm
// (guest.go) can stay zero-authority — the guest's __host_call is byte-shuttled
// here by Go. Every op is application-neutral; structure is the guest's business.
package main

import (
	_ "embed"
	"fmt"

	"seedloader/qjs"
)

// hostCapBridgeJS is build/host/{util,cap-bridge}.js bundled by bundle-loader.mjs:
// createCapBridge + capPreamble + opsForCaps + the CAP op catalog.
//
//go:embed host-capbridge.gen.js
var hostCapBridgeJS string

// exposeCapBridge evals the cap-bridge bundle and the glue that constructs the
// bridge from host-realm primitives. After this, JS can call
// `__buildCapBridge(caps, identity, transport, peers, moduleCall)` to install
// `globalThis.__capBridge` for a loaded bundle's declared cap domains. Requires
// polyfills + sodium + fs already installed in the realm.
func exposeCapBridge(qc *qjs.Context) {
	if _, err := qc.Eval("host-capbridge.gen.js", qjs.Code(hostCapBridgeJS)); err != nil {
		panic(fmt.Sprintf("cap-bridge bundle: %v", err))
	}
	if _, err := qc.Eval("capbridge-glue.js", qjs.Code(capBridgeGlueJS)); err != nil {
		panic(fmt.Sprintf("cap-bridge glue: %v", err))
	}
}

const capBridgeGlueJS = `
"use strict";
(function () {
  // Build the single capability funnel for a loaded bundle. caps = the manifest's
  // declared domains (e.g. ["crypto","fs","net"]); only their ops resolve. identity
  // is the node keypair ({publicKey,privateKey} Uint8Arrays — sodium.crypto_sign_keypair
  // shape). transport/peers/moduleCall may be omitted for a local-only node.
  globalThis.__buildCapBridge = function (caps, identity, transport, peers, moduleCall) {
    globalThis.__capBridge = createCapBridge({
      sodium,
      identity,
      callHandler: (name, payload) => {
        const r = (moduleCall || (() => null))(name, payload);
        return (r === null || r === undefined) ? null : new Uint8Array(r);
      },
      transport: transport || {
        request: () => Promise.reject(new Error("cap-bridge: net not wired")),
        requestMany: () => Promise.resolve([]),
      },
      peers: () => peers || [],
      fs,
      now: () => Date.now(),
      allowedOps: opsForCaps(new Set(caps)),
    });
  };

  // Direct synchronous invocation helper (Go passes an ArrayBuffer; the bridge wants
  // a Uint8Array). Returns the bytes for a sync op, or the Promise for an async (net)
  // op — the guest realm's __host_call handles the async case. The sync result is
  // returned as-is: JsTypedArrayToGo copies on read and leaves the source intact, so
  // shared singletons (ONE/ZERO/NONE) survive without a defensive .slice() here.
  globalThis.__callBridge = (op, ab) => __capBridge(op, new Uint8Array(ab));

  // The guest realm's seam target. A sync op returns its bytes; a net op returns null
  // and later calls __netDone(callId)/__netFail(callId) (Go fns wired by
  // installEngineNet) when the Transport promise settles — which loop.resolveCall hands
  // to the guest's blocked host.call (awaitNetCall). __netDone reads via
  // JsTypedArrayToGo (view-aware, copies), so the settled value passes straight through.
  globalThis.__hostBridgeCall = (op, ab, callId) => {
    const r = __capBridge(op, new Uint8Array(ab));
    if (r && typeof r.then === "function") {
      r.then(
        (b) => __netDone(callId, b instanceof Uint8Array ? b : new Uint8Array(b)),
        (e) => __netFail(callId, String(e && e.message || e)),
      );
      return null;
    }
    return r;
  };
})();
`
