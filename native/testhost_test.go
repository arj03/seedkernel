package main

// The one way a test stands the loader up. There is a single assembly path in
// production — boot() installs the platform primitives and evaluates the shared
// bundle, bootNode() builds the node and the shell inside it — so the tests drive
// that path rather than a parallel wiring of their own. A harness that assembles the
// realm differently is exactly the second implementation this target exists not to
// have (README §12.9).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"seedloader/qjs"
)

// bootRealm stands up a fresh realm on a temp data dir: the engines, the platform
// primitives, and the one shared bundle — but no node. For tests that exercise a
// primitive (fs, the byte seam) or the shared JS directly.
func bootRealm(tb testing.TB) { bootRealmIn(tb, tb.TempDir()) }

func bootRealmIn(tb testing.TB, dir string) {
	tb.Helper()
	if err := boot(dir); err != nil {
		tb.Fatal("boot:", err)
	}
}

// bootShell stands a whole node up exactly as the binary does — bootRealm, then
// bootNode inside the realm (identity, network, createShell over this platform).
// `listen` is nil for a node that only initiates; policyJSON "" is the deny-all
// default (README §14). Returns what the realm reported: the peer id and the ports
// actually bound.
func bootShell(tb testing.TB, dir, policyJSON string, listen *hostPort) nodeStatus {
	tb.Helper()
	bootRealmIn(tb, dir)
	cfg := nodeConfig{KeyHex: testKeyHex(tb), Listen: listen, TimeoutMs: 2000}
	if policyJSON != "" {
		cfg.PolicyJSON = &policyJSON
	}
	st, err := startNode(cfg)
	if err != nil {
		tb.Fatal("bootNode:", err)
	}
	return st
}

// testKeyHex mints a node identity. Go's ed25519 private key is seed‖public, which is
// byte-for-byte what libsodium calls a secret key — the same 128 hex chars --key holds.
func testKeyHex(tb testing.TB) string {
	tb.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return hex.EncodeToString(priv)
}

// applyPolicy narrows (or widens) the running node's admission predicate — the
// operator's --policy, after the fact. "" is the deny-all default, not "no policy".
func applyPolicy(policyJSON string) error {
	arg := qc.NewString(policyJSON)
	if policyJSON == "" {
		arg.Free()
		arg = qc.NewNull()
	}
	_, err := callRealm("setPolicy", 5*time.Second, arg)
	return err
}

// testCapBridgeJS installs __buildCapBridge / __callBridge: a TEST-ONLY convenience
// over the shared createCapBridge, so a test can hand a realm a capability funnel with
// no signed bundle behind it. Production never takes this path — createShell builds
// the bridge from the admitted manifest's declared domains (§12.2) — which is why this
// lives in a _test file and not in the shipped glue.
const testCapBridgeJS = `
"use strict";
globalThis.__buildCapBridge = function (caps, identity, transport, peers, scope) {
  globalThis.__capBridge = createCapBridge({
    sodium, identity, fs,
    callHandler: () => null,
    transport: transport || { request: () => Promise.reject(new Error("test: net not wired")) },
    peers: () => peers || [],
    now: () => Date.now(),
    allowedOps: opsForCaps(new Set(caps)),
    // No signed manifest behind this harness, so there is no logical->kernel map to
    // scope MODULE_CALL against. The sentinel says so explicitly; omitting the field
    // is refused (§12.2), which is the point — production reaches this call through
    // createShell, which always has a manifest.
    modules: UNSCOPED_MODULES,
    signScope: scope || undefined,
  });
  return __capBridge;
};
globalThis.__callBridge = (op, ab) => __capBridge(op, new Uint8Array(ab));
`

// capBridgeRealm boots a realm and adds the test-only cap-bridge builder above.
func capBridgeRealm(tb testing.TB) {
	tb.Helper()
	bootRealm(tb)
	if _, err := qc.Eval("test-capbridge.js", qjs.Code(testCapBridgeJS)); err != nil {
		tb.Fatal("test cap-bridge:", err)
	}
}

// newTestRealm creates a confined realm through the SAME factory production uses
// (createRealm, host/native-shim.ts) over a bridge the caller has already installed at
// `__capBridge`, and parks it at `__realm`. `source` is fronted with the shared cap
// preamble and the given APP config, mirroring what createShell composes for a real
// bundle's guest.
func newTestRealm(tb testing.TB, appJSON, source string) {
	tb.Helper()
	newTestRealmBudget(tb, appJSON, source, 0)
}

// newTestRealmBudget is newTestRealm with an explicit execution budget in ms (0 = the
// target default, §16.1). Separate so the budget test can use a short one without every
// other test paying for a non-default path.
func newTestRealmBudget(tb testing.TB, appJSON, source string, deadlineMs int) {
	tb.Helper()
	qc.Global().SetPropertyStr("__src", qc.NewString("const APP = "+appJSON+";\n"+source))
	qc.Global().SetPropertyStr("__deadlineMs", qc.NewInt64(int64(deadlineMs)))
	if _, err := callRealm(
		`(async () => {
			globalThis.__realm = await createRealm({ source: capPreamble() + __src, bridge: __capBridge,
				deadlineMs: __deadlineMs || undefined });
			globalThis.__realmCall = (entry, arg) => __realm.call(entry, new Uint8Array(arg));
			return new Uint8Array(0);
		})`,
		10*time.Second,
	); err != nil {
		tb.Fatal("createRealm:", err)
	}
}

// realmCall invokes an entrypoint on the realm newTestRealm parked, as the initiator,
// driving the loop until it settles — the guest may await net on the way. Go stages the
// payload as an ArrayBuffer, so the view SafeRealm.call is declared to take is made in
// the expression rather than by widening the shared signature.
func realmCall(entry string, payload []byte) ([]byte, error) {
	return callRealm("__realmCall", 30*time.Second, qc.NewString(entry), qc.NewArrayBuffer(payload))
}
