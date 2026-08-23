package main

// The one way a test stands the loader up. Production has a single assembly path — boot()
// installs the platform primitives and evaluates the shared bundle, bootNode() builds the
// node and shell inside it — so the tests drive that path. A harness that assembled the
// realm differently would be the second implementation this target exists not to have
// (README §12.9).

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
	if err := boot(); err != nil {
		tb.Fatal("boot:", err)
	}
	// Where this node's disk is, through the same `openStore` the operator flow calls
	// once it has read --dir (host/native-shim.ts). Go's boot no longer knows about a
	// data directory at all, so a harness that opened the store some other way would be
	// testing a store production never opens.
	evalString(tb, "openStore("+jsonString(dir)+")")
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
// TEST drivers, not production code: the binary reaches the realm once, at `runMain`, and
// everything below that is the shared CLI's. A test needs finer joints than one call, so
// it uses the same realm exports `runCli` does — never a second assembly of its own.

// nodeConfig is what `bootNode` takes: the operator's choices as one JSON object. In
// production the shared CLI builds this from the flags; here a test builds it directly
// to stand a node up without a command line.
type nodeConfig struct {
	PolicyJSON       *string        `json:"policyJson"`
	KeyHex           string         `json:"keyHex"`
	ContactSecretHex string         `json:"contactSecretHex"`
	Listen           *hostPort      `json:"listen,omitempty"`
	WsListen         *hostPort      `json:"wsListen,omitempty"`
	Peers            []string       `json:"peers,omitempty"`
	RequestDeadline  int            `json:"requestDeadlineMs,omitempty"`
}

type hostPort struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// nodeStatus is what the realm reports once the node is up: who we are, and the ports
// actually bound (0 where not listening).
type nodeStatus struct {
	PeerID string `json:"peerId"`
	Port   int    `json:"port"`
	WsPort int    `json:"wsPort"`
}

// startNode builds the node inside the realm and waits for its listeners to bind — the
// same `bootNode` the shared CLI's `standUp` reaches, minus the command line.
func startNode(cfg nodeConfig) (nodeStatus, error) {
	var st nodeStatus
	j, err := json.Marshal(cfg)
	if err != nil {
		return st, err
	}
	out, err := callRealm("bootNode", 30*time.Second, qc.NewString(string(j)))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(out, &st)
}

// loadBundle loads a signed bundle file and returns the operator's console line for it,
// or an `ERROR: …` string. The line is produced by `loadedLine` in the shared CLI — the
// very line the binary prints — so a test asserting on it is asserting on what an
// operator sees, and there is no second formatting here to drift from it.
func loadBundle(path string) string {
	out, err := callRealm("cliLoadBundle", 30*time.Second, qc.NewString(path))
	if err != nil {
		return "ERROR: " + err.Error()
	}
	return string(out)
}

// invokeBundle drives a loaded slot through its guest; pure modules are intentionally
// unreachable from the host test seam except through this path.
func invokeBundle(appKey string, payload []byte) ([]byte, error) {
	return callRealm("invokeApp", 30*time.Second, qc.NewString(appKey), qc.NewArrayBuffer(payload))
}

// bootShell stands a whole node up exactly as the binary does — bootRealm, then
// bootNode inside the realm (identity, network, bootShell over this platform).
// `listen` is nil for a node that only initiates; policyJSON "" is the deny-all
// default (README §14). Returns what the realm reported: the peer id and the ports
// actually bound.
// withTransportAuthor adds the artifact's own transport author to a policy's authors and
// grants it `link`. A node whose policy does not admit a transport bundle has no
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
	p["grants"] = map[string]any{"link": []string{author}}
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
// 64 hex chars --key holds. bootNode derives the node's keypair from it inside the
// shared realm (deriveNodeKeys, core/subkeys.ts).
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

// testGuestSeamJS installs __buildGuestSeam / __callSeam: a TEST-ONLY convenience over the
// shared createGuestSeam, so a test can hand a realm a seam with no signed bundle behind
// it. Production wires the seam from the admitted manifest's requires (§12.2), which is
// why this lives in a _test file.
const testGuestSeamJS = `
"use strict";
globalThis.__buildGuestSeam = function (names, identity, calls, scope) {
  globalThis.__guestSeam = createGuestSeam({
    // Per NODE.
    platform: { sodium, identity, now: () => Date.now() },
    // Per REALM: the granted names straight through — a call resolves iff the name
    // itself is one of these (or crypto/*, or one of the bundle's own modules — never
    // grants) — plus the backends behind them.
    grants: {
      names,
      signScope: scope || undefined,
      fs,
      // The routing a reserved (_-led) name resolves through: the shell's, in
      // production. Absent here means nothing claims any id, which the seam reports
      // by name rather than leaving the caller pending.
      calls: calls || { call: () => null },
    },
    // Per APP: no app behind this harness, so a bare name reaches nothing. Nothing to
    // scope either — the seam is wired against ONE app's module map, so "a guest
    // reaches only its own modules" needs no argument here to stay true.
    modules: { call: () => null, has: () => false },
  });
  return __guestSeam;
};
globalThis.__callSeam = (name, ab) => __guestSeam(name, new Uint8Array(ab));
// The round-tripping names — net/send and every fs/* — hand back a Promise (§12.2),
// so a caller that wants their bytes has to settle it. Driven through callRealm,
// which already knows how to pump the loop until a realm promise settles.
globalThis.__callSeamAwait = async (name, ab) => __guestSeam(name, new Uint8Array(ab));
`

// guestSeamRealm boots a realm and adds the test-only guest-seam builder above.
func guestSeamRealm(tb testing.TB) {
	tb.Helper()
	bootRealm(tb)
	if _, err := qc.Eval("test-guest-seam.js", qjs.Code(testGuestSeamJS)); err != nil {
		tb.Fatal("test guest-seam:", err)
	}
}

// newTestRealm creates a confined realm through the SAME factory production uses
// (createRealm, host/native-shim.ts) over a seam the caller has already installed at
// `__guestSeam`, and parks it at `__realm`. `source` is fronted with the shared guest
// preamble, the given signed APP fixture and an empty LOCAL value, mirroring what
// the shell composes for a real bundle's guest.
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
			// The test driver's twin of the shell's callSlot: the host's 32 zero-byte
			// caller id in front of the guest's own op framing (composed here, since the
			// kernel writing it would learn the guest's vocabulary).
			globalThis.__realmCall = (op, arg) => {
			  const body = new Uint8Array(arg);
			  const framed = new Uint8Array(1 + op.length + body.length);
			  framed[0] = op.length;
			  for (let i = 0; i < op.length; i++) framed[1 + i] = op.charCodeAt(i);
			  framed.set(body, 1 + op.length);
			  const input = new Uint8Array(32 + framed.length);
			  input.set(framed, 32);
			  return __realm.call(input);
			};
			return new Uint8Array(0);
		})`,
		10*time.Second,
	); err != nil {
		tb.Fatal("createRealm:", err)
	}
}

// realmCall invokes the realm newTestRealm parked, as the initiator — the same shape
// the shell uses, with the 32 zero-byte caller id + the guest's own op framing composed
// by __realmCall — driving the loop until it settles; the guest may await net on the way.
// Go stages the payload as an ArrayBuffer, so the view SafeRealm.call is declared to
// take is made in the expression rather than by widening the shared signature.
func realmCall(entry string, payload []byte) ([]byte, error) {
	return callRealm("__realmCall", 30*time.Second, qc.NewString(entry), qc.NewArrayBuffer(payload))
}

// TestCallRealmReleasesStagedArgs covers the argument staging: callRealm lands each
// argument on a __aN global and must release it when the call returns — otherwise a
// one-shot op (an --op put of a large file) leaves its payload rooted on the global object
// for the process's life.
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
