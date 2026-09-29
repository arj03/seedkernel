package main

// How tests boot the native host. Production has a single assembly path (boot() installs
// the platform primitives and evaluates the shared bundle, standUp() builds the node and
// shell inside it), and the tests use that path instead of a second assembly (§12.9).

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// A test-only adapter that invokes installed bundles by label, for Go assertions that pick
// among several bundles. Production returns AppHandles and keeps none.
const nativeHandleHarness = `
(() => {
  const apps = new Map();
  // The node startNode booted: the one a test's bundles install into and its invocations reach.
  let node = null;
  // The operator's choices as one JSON object, booted through the same standUp the shared
  // CLI uses, on this realm's data directory. The key is derived here by the shared subkey
  // code the CLI runs, so the peer id is the one --key would give.
  globalThis.startNode = async (json) => {
    const cfg = JSON.parse(json);
    const identity = deriveNodeKey(sodium, fromHex(cfg.keyHex));
    node = await standUp({
      dir: __dir,
      policyJson: cfg.policyJson ?? undefined,
      identity,
      transport: {
        // This harness's two listener slots, under the labels the shipped transport reads.
        listen: [
          ...(cfg.listen ? [{ label: "tcp", ...cfg.listen }] : []),
          ...(cfg.wsListen ? [{ label: "ws", ...cfg.wsListen }] : []),
        ],
        // Contact policy is transport config (§12.6.3).
        config: cfg.contactSecretHex ? { contactSecret: cfg.contactSecretHex } : undefined,
      },
    });
    return new TextEncoder().encode(JSON.stringify({
      peerId: toHex(identity.publicKey),
      port: node.transport?.portOf("tcp") ?? 0,
      wsPort: node.transport?.portOf("ws") ?? 0,
    }));
  };
  globalThis.cliLoadBundle = async (path) => {
    const raw = bridge.readFile(path);
    if (raw === null) throw new Error("native test: cannot read " + path);
    const app = await node.shell.install(new Uint8Array(raw));
    apps.set(app.manifest.app, app);
    return new TextEncoder().encode(loadedLine(app));
  };
  globalThis.invokeApp = (key, payload) => {
    const app = apps.get(key);
    if (!app) throw new Error("native test: no loaded handle for '" + key + "'");
    // This adapter only invokes the test fixture's literal "test" op. The frame is built
    // here instead of exposing the client codec as a production QuickJS global just for
    // Go assertions.
    const args = new Uint8Array(payload);
    const body = new Uint8Array(5 + args.length);
    body.set([4, 0x74, 0x65, 0x73, 0x74]);
    body.set(args, 5);
    return app.invoke(body);
  };
  // Adding a peer is a call to the id the transport bundle claims, the host's own way into
  // the network. The op frame is written out here, as invokeApp does for its own frame,
  // instead of exposing the client codec as a production QuickJS global.
  const opFrame = (op, args) => {
    const out = new Uint8Array(1 + op.length + args.length);
    out[0] = op.length;
    for (let i = 0; i < op.length; i++) out[1 + i] = op.charCodeAt(i);
    out.set(args, 1 + op.length);
    return out;
  };
  const blob = (b) => {
    const out = new Uint8Array(4 + b.length);
    out[0] = b.length >>> 24; out[1] = (b.length >>> 16) & 255;
    out[2] = (b.length >>> 8) & 255; out[3] = b.length & 255;
    out.set(b, 4);
    return out;
  };
  globalThis.teachAddr = (shell, peerHex, dest, contactSecret) => {
    const parts = [
      blob(fromHex(peerHex)),
      blob(contactSecret || new Uint8Array(32)),
      blob(new TextEncoder().encode(dest)),
    ];
    let n = 0;
    for (const p of parts) n += p.length;
    const args = new Uint8Array(n);
    let off = 0;
    for (const p of parts) { args.set(p, off); off += p.length; }
    const answer = shell.call("_net", opFrame("addr", args));
    if (!answer) throw new Error("native test: nothing claims _net on this node");
    return answer;
  };
})();
`

// The data directory of the current realm, while the harness owns it.
//
// A realm outlives the caller that booted it: boot() keeps it until the next boot, so a
// data directory removed when that test ends would leave whatever runs next writing into
// a deleted path, and `tb.TempDir()` has exactly that lifetime. Benchmarks run after the
// tests in the same process, so a reused realm would hand them a deleted directory, which
// shows up as a freshness-store write failure far from its cause. So the realm gets a
// directory owned by the harness, removed when that realm is torn down, which leaves at
// most a stale directory or two per run instead of one per boot.
var ownedRealmDir string

// bootRealm starts a fresh realm on a temp data dir: the engines, the platform
// primitives, and the shared bundle, but no node. For tests of a primitive (fs, the byte
// seam) or the shared JS directly.
func bootRealm(tb testing.TB) {
	tb.Helper()
	dir, err := os.MkdirTemp("", "seedkernel-realm-")
	if err != nil {
		tb.Fatal("realm data dir:", err)
	}
	bootRealmIn(tb, dir)
	// Recorded only once the boot succeeded: bootRealmIn has just released the previous
	// one, and this is the directory the new realm reads and writes.
	ownedRealmDir = dir
}

func bootRealmIn(tb testing.TB, dir string) {
	tb.Helper()
	// Nothing below is worth running against an artifact older than its sources
	// (shell_stamp_test.go). Checked here, not per suite, because every suite evaluates
	// that artifact and none can tell.
	requireFreshShell(tb)
	if err := boot(); err != nil {
		tb.Fatal("boot:", err)
	}
	// boot() tore the previous realm down, so nothing reads its directory now. A
	// caller-supplied `dir` is the caller's to keep. The freshness marks sit beside the
	// data directory, not inside it (bundle.ts `freshnessPathFor`), so removing a realm's
	// directory means removing both.
	if ownedRealmDir != "" {
		_ = os.RemoveAll(ownedRealmDir)
		_ = os.Remove(ownedRealmDir + ".freshness.json")
		ownedRealmDir = ""
	}
	if _, err := qc.Eval("native-handle-harness.js", nativeHandleHarness); err != nil {
		tb.Fatal("native handle harness:", err)
	}
	// This realm's data directory, which Go's boot knows nothing about. Opened through the
	// platform's own `fs.open` for tests that use `fs` with no node running, and kept as
	// `__dir` for every `standUp` a test calls: the Go primitive serves one directory, so
	// all nodes in a realm share it (host/native-shim.ts).
	evalString(tb, "__fs.open("+jsonString(dir)+"), globalThis.__dir = "+jsonString(dir))
}

// jsonString quotes a Go string as a JS string literal, for the few test helpers that
// reach the realm by evaluating an expression.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// ── the realm entry points a test drives ─────────────────────────────────────
//
// Test drivers, not production code: the binary calls into the realm once, at `runMain`,
// and everything below that is the shared CLI. A test needs finer control than one call,
// so it uses the same realm exports `runCli` does, never a separate assembly.

// nodeConfig is what the harness's `startNode` takes: the operator's choices as one JSON
// object. In production the shared CLI builds a node's setup from the flags; here a test
// builds it directly to boot a node without a command line.
type nodeConfig struct {
	PolicyJSON       *string   `json:"policyJson"`
	KeyHex           string    `json:"keyHex"`
	ContactSecretHex string    `json:"contactSecretHex"`
	Listen           *hostPort `json:"listen,omitempty"`
	WsListen         *hostPort `json:"wsListen,omitempty"`
}

type hostPort struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// nodeStatus is what the realm reports once the node is up: its peer id, and the ports
// actually bound (0 where not listening).
type nodeStatus struct {
	PeerID string `json:"peerId"`
	Port   int    `json:"port"`
	WsPort int    `json:"wsPort"`
}

// startNode builds the node inside the realm and waits for its listeners to bind, using
// the same `standUp` as the shared CLI, without the command line.
func startNode(cfg nodeConfig) (nodeStatus, error) {
	var st nodeStatus
	j, err := json.Marshal(cfg)
	if err != nil {
		return st, err
	}
	out, err := callRealm("startNode", 30*time.Second, qc.NewString(string(j)))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(out, &st)
}

// loadBundle installs a signed bundle file and returns the operator's console line for it,
// or an `ERROR: ...` string. The line comes from `loadedLine` in the shared CLI, the same
// line the binary prints, so a test checks exactly what an operator sees.
func loadBundle(path string) string {
	out, err := callRealm("cliLoadBundle", 30*time.Second, qc.NewString(path))
	if err != nil {
		return "ERROR: " + err.Error()
	}
	return string(out)
}

// invokeBundle calls an installed slot through its guest; pure modules are only reachable
// from tests this way.
func invokeBundle(app string, payload []byte) ([]byte, error) {
	return callRealm("invokeApp", 30*time.Second, qc.NewString(app), qc.NewArrayBuffer(payload))
}

// evalString evaluates a JS expression in the host realm and returns it as a string.
func evalString(tb testing.TB, expr string) string {
	tb.Helper()
	v, err := qc.Eval("<evalString>", expr)
	if err != nil {
		tb.Fatal("eval:", err)
	}
	return v.String()
}

// awaitOK drives the loop until expr settles and fails the test unless it fulfilled. Prefer
// it to el.await, which reports a rejection as kind 1 with a nil error, so an `err != nil`
// check silently passes on the failure it was meant to catch. A test about a rejection or
// timeout reads the kind instead (loop_probe_test.go).
func awaitOK(tb testing.TB, what, expr string, timeout time.Duration) []byte {
	tb.Helper()
	kind, value, msg, err := el.await(expr, timeout)
	if err != nil {
		tb.Fatalf("%s: %v", what, err)
	}
	if kind != 0 {
		tb.Fatalf("%s: kind=%d msg=%q", what, kind, msg)
	}
	return value
}

// bootShell boots a whole node as the binary does: a fresh realm on `dir`, then
// startShell. Returns what the realm reported: the peer id and the ports actually bound.
func bootShell(tb testing.TB, dir, policyJSON string, listen *hostPort) nodeStatus {
	tb.Helper()
	bootRealmIn(tb, dir)
	return startShell(tb, policyJSON, listen)
}

// startShell boots a node in the already booted realm (standUp inside it: identity,
// network, bootShell over this platform), for a test whose policy names an author it has
// to create in that realm first. `listen` is nil for a node that only initiates;
// policyJSON "" is the deny-all default (§14).
func startShell(tb testing.TB, policyJSON string, listen *hostPort) nodeStatus {
	tb.Helper()
	cfg := nodeConfig{KeyHex: testKeyHex(tb), ContactSecretHex: testContactSecretHex, Listen: listen}
	if policyJSON != "" {
		cfg.PolicyJSON = &policyJSON
	}
	st, err := startNode(cfg)
	if err != nil {
		tb.Fatal("startNode:", err)
	}
	return st
}

// testContactSecretHex is the contact secret every test node uses. A node answers only
// callers presenting its secret, so one shared value lets every test node reach every
// other.
const testContactSecretHex = "0303030303030303030303030303030303030303030303030303030303030303"

// testKeyHex creates a node master seed: 32 bytes of entropy as hex, the same 64 hex chars
// --key holds. startNode derives the node's keypair from it inside the shared realm
// (deriveNodeKey, services/subkeys.ts).
func testKeyHex(tb testing.TB) string {
	tb.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		tb.Fatal(err)
	}
	return hex.EncodeToString(seed)
}

// authorsPolicy is a --policy file admitting exactly these app authors (§12.5).
func authorsPolicy(ids ...[]byte) string {
	authors := make([]string, len(ids))
	for i, id := range ids {
		authors[i] = hex.EncodeToString(id)
	}
	j, err := json.Marshal(map[string][]string{"authors": authors})
	if err != nil {
		panic(err)
	}
	return string(j)
}

// testGuestSeamJS installs __buildGuestSeam / __callSeam: a test-only helper over the
// shared createGuestSeam, so a test can give a realm a seam with no signed bundle behind
// it. Production wires the seam from the admitted manifest's guest.requires (§12.2,
// §12.10).
const testGuestSeamJS = `
"use strict";
globalThis.__buildGuestSeam = function (names, callLocal, scope) {
  globalThis.__guestSeam = createGuestSeam({
    sodium,
    // The declared names as given: a host service's methods are wired only if it is one
    // of these, and every other name here is a local service id (§12.10).
    requires: names,
    // What this node provides; only the declared ones are wired.
    backends: { node: scope || undefined, fs },
    // Local service id routing, done by the shell in production. Absent here means
    // nothing claims any id, which the seam reports by name instead of leaving the caller
    // waiting.
    callLocal: callLocal || (() => null),
    // Per app: there is no app behind this harness, so a bare name reaches nothing.
    modules: { names: new Set(), call: () => null },
  });
  return __guestSeam;
};
// With the budget a realm would pass: an unbounded segment, no causal root, no spend.
const __testBudget = { remainingMs: Infinity, causalClock: undefined, charge() {}, detach() {} };
globalThis.__callSeam = async (name, ab) => __guestSeam(name, new Uint8Array(ab), __testBudget);
// Every name, crypto included, answers a Promise, so this is the only calling convention.
// Used through callRealm, which pumps the loop until a realm promise settles.
globalThis.__callSeamAwait = __callSeam;
`

// guestSeamRealm boots a realm and adds the test-only guest-seam builder above.
func guestSeamRealm(tb testing.TB) {
	tb.Helper()
	bootRealm(tb)
	if _, err := qc.Eval("test-guest-seam.js", testGuestSeamJS); err != nil {
		tb.Fatal("test guest-seam:", err)
	}
}

// newTestRealm creates a confined realm through the same factory production uses
// (createRealm, host/native-shim.ts) over a seam the caller has already installed at
// `__guestSeam`, and stores it at `__realm`. `source` is prefixed with the given APP
// fixture and an empty LOCAL value, as the shell does for a real bundle's guest (no HOST).
func newTestRealm(tb testing.TB, appJSON, source string) {
	tb.Helper()
	newTestRealmBudget(tb, appJSON, source, 0)
}

// newTestRealmBudget is newTestRealm with an explicit execution budget in ms (0 = the
// target default, §16.1). Separate so the budget test can use a short one without every
// other test paying for a non-default path.
func newTestRealmBudget(tb testing.TB, appJSON, source string, deadlineMs int) {
	tb.Helper()
	qc.Global().SetPropertyStr("__src", qc.NewString(
		"const APP = JSON.parse("+jsonString(appJSON)+");\nconst LOCAL = {};\n"+source))
	qc.Global().SetPropertyStr("__deadlineMs", qc.NewInt64(int64(deadlineMs)))
	if _, err := callRealm(
		`(async () => {
			globalThis.__realm = await createRealm({ source: __src, hostCall: __guestSeam,
				deadlineMs: __deadlineMs || undefined });
			// The test driver's version of the shell's enter: the host's 32 zero-byte
			// caller id in front of the guest's own op framing (built here, since the host
			// never knows a guest's op names).
			globalThis.__realmCall = (op, arg, causalClock) => {
			  const body = new Uint8Array(arg);
			  const framed = new Uint8Array(1 + op.length + body.length);
			  framed[0] = op.length;
			  for (let i = 0; i < op.length; i++) framed[1 + i] = op.charCodeAt(i);
			  framed.set(body, 1 + op.length);
			  const input = new Uint8Array(32 + framed.length);
			  input.set(framed, 32);
			  return __realm.call(input, undefined, causalClock);
			};
			return new Uint8Array(0);
		})`,
		10*time.Second,
	); err != nil {
		tb.Fatal("createRealm:", err)
	}
}

// realmCall invokes the realm newTestRealm stored, as the initiator, the same way the
// shell does (the 32 zero-byte caller id plus the guest's own op framing, built by
// __realmCall), driving the loop until it settles; the guest may await the network on the
// way. Go passes the payload as an ArrayBuffer, so the Uint8Array Realm.call takes is
// made in the expression instead of loosening the shared signature.
func realmCall(entry string, payload []byte) ([]byte, error) {
	return callRealm("__realmCall", 30*time.Second, qc.NewString(entry), qc.NewArrayBuffer(payload))
}

// TestCallRealmReleasesStagedArgs covers argument staging: callRealm puts each argument on
// an __aN global and must release it when the call returns, or a one-shot op (an --op put
// of a large file) would keep its payload alive on the global object for the life of the
// process.
func TestCallRealmReleasesStagedArgs(t *testing.T) {
	bootRealm(t)
	if _, err := qc.Eval("probe.js", `
		globalThis.__probe = function () { return new Uint8Array(0); };
	`); err != nil {
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
