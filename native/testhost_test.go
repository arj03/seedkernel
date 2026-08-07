package main

// The one way a test stands the loader up. There is a single assembly path in
// production — boot() installs the platform primitives and evaluates the shared
// bundle, bootNode() builds the node and the shell inside it — so the tests drive
// that path rather than a parallel wiring of their own. A harness that assembles the
// realm differently is exactly the second implementation this target exists not to
// have (README §12.9).

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
// withTransportAuthor adds the artifact's own transport author to a policy's
// transportAuthors. A node whose policy does not admit a transport bundle has no
// network at all — which is also what a deliberate deny-all looks like, so the two
// must not be confused by accident in a test.
func withTransportAuthor(tb testing.TB, policyJSON string) string {
	tb.Helper()
	author := evalString(tb, "embeddedTransportAuthor")
	if author == "" {
		return policyJSON
	}
	var p map[string]any
	if policyJSON == "" {
		p = map[string]any{}
	} else if err := json.Unmarshal([]byte(policyJSON), &p); err != nil {
		tb.Fatal("policy json:", err)
	}
	authors, _ := p["authors"].([]any)
	p["authors"] = append(authors, author)
	p["transportAuthors"] = []string{author}
	out, err := json.Marshal(p)
	if err != nil {
		tb.Fatal("policy json:", err)
	}
	return string(out)
}

// evalString evaluates a JS expression in the host realm and returns it as a string.
func evalString(tb testing.TB, expr string) string {
	tb.Helper()
	v, err := qc.Eval("<evalString>", qjs.Code(expr))
	if err != nil {
		tb.Fatal("eval:", err)
	}
	return v.String()
}

func bootShell(tb testing.TB, dir, policyJSON string, listen *hostPort) nodeStatus {
	tb.Helper()
	bootRealmIn(tb, dir)
	policyJSON = withTransportAuthor(tb, policyJSON)
	cfg := nodeConfig{KeyHex: testKeyHex(tb), ContactSecretHex: testContactSecretHex, Listen: listen, RequestDeadline: 2000}
	if policyJSON != "" {
		cfg.PolicyJSON = &policyJSON
	}
	st, err := startNode(cfg)
	if err != nil {
		tb.Fatal("bootNode:", err)
	}
	return st
}

// testContactSecretHex is the deployment secret every test node shares: it gates who may
// draw any response at all from a node, so two nodes on different values are mutually
// invisible. One value here means one deployment.
const testContactSecretHex = "0303030303030303030303030303030303030303030303030303030303030303"

// testKeyHex mints a node identity master seed: 32 bytes of entropy, hex — the same
// 64 hex chars --key holds. bootNode derives the channel and guest subkeys from it
// inside the shared realm (deriveNodeKeys, core/subkeys.ts).
func testKeyHex(tb testing.TB) string {
	tb.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		tb.Fatal(err)
	}
	return hex.EncodeToString(seed)
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
// the bridge from the admitted manifest's declared requires (§12.2) — which is why this
// lives in a _test file and not in the shipped glue.
const testCapBridgeJS = `
"use strict";
globalThis.__buildCapBridge = function (names, identity, transport, peers, scope) {
  globalThis.__capBridge = createCapBridge({
    sodium, identity, fs,
    // No app behind this harness, so module/call reaches nothing. Nothing to scope
    // either: the bridge is built against ONE app's module map, so "a guest reaches
    // only its own modules" needs no argument here to stay true.
    callModule: () => null,
    transport: transport || { request: () => Promise.reject(new Error("test: net not wired")) },
    peers: () => peers || [],
    now: () => Date.now(),
    // The granted names, straight through: a call resolves iff the name itself is
    // one of these (or crypto/module, which are never grants).
    allowedNames: names,
    signScope: scope || undefined,
  });
  return __capBridge;
};
globalThis.__callBridge = (name, ab) => __capBridge(name, new Uint8Array(ab));
// The round-tripping names — net/send and every fs/* — hand back a Promise (§12.2),
// so a caller that wants their bytes has to settle it. Driven through callRealm,
// which already knows how to pump the loop until a realm promise settles.
globalThis.__callBridgeAwait = async (name, ab) => __capBridge(name, new Uint8Array(ab));
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
			globalThis.__realm = await createRealm({ source: __src, bridge: __capBridge,
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

// TestCallRealmReleasesStagedArgs covers the argument staging: callRealm lands each
// argument on a __aN global for the duration of the call and must release it when the
// call returns — otherwise a one-shot op (a --put of a large file, an uninstall after
// which nothing else runs) leaves its payload rooted on the global object for the
// process's life.
func TestCallRealmReleasesStagedArgs(t *testing.T) {
	bootRealm(t)
	if _, err := qc.Eval("probe.js", qjs.Code(`
		globalThis.__probe = function () { return new Uint8Array(0); };
	`)); err != nil {
		t.Fatal("probe:", err)
	}
	if _, err := callRealm("__probe", 5*time.Second, qc.NewString("a"), qc.NewString("b")); err != nil {
		t.Fatal("callRealm:", err)
	}
	for _, slot := range []string{"__a0", "__a1"} {
		v := qc.Global().GetPropertyStr(slot)
		if !v.IsUndefined() {
			t.Fatalf("%s must be released after the call, got %q", slot, v.String())
		}
		v.Free()
	}
}
