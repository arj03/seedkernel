package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"seedloader/qjs"
)

// Initialization regressions run in a child process: without the source-evaluation guard,
// QuickJS holds the test thread forever and no in-process timeout can make progress.
func TestGuestRealmInitializationBudget(t *testing.T) {
	const marker = "SEEDKERNEL_TEST_GUEST_INIT_BUDGET"
	if os.Getenv(marker) == "1" {
		guestSeamRealm(t)
		if _, err := qc.Eval("build.js", qjs.Code(`
			globalThis.__id = sodium.crypto_sign_keypair();
			__buildGuestSeam([], __id, null);
			globalThis.__src = "for (;;) {}";
		`)); err != nil {
			t.Fatal("build seam:", err)
		}
		if _, err := callRealm(`createRealm({ source: __src, hostCall: __guestSeam, deadlineMs: 100 })`, 3*time.Second); err == nil {
			t.Fatal("top-level guest loop unexpectedly completed")
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGuestRealmInitializationBudget$", "-test.v")
	cmd.Env = append(os.Environ(), marker+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("guest source evaluation wedged its host process: %v\n%s", ctx.Err(), out)
	}
	if err != nil {
		t.Fatalf("initialization budget probe failed: %v\n%s", err, out)
	}
}

func TestGuestRealmOutstandingHostCallsCapped(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("build.js", qjs.Code(`
		// A host operation that never settles retains every copied request unless the realm
		// refuses new calls at its shared per-realm limit.
		globalThis.__guestSeam = () => new Promise(() => {});
	`)); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealmBudget(t, "{}", `
		function handle() {
		  for (let i = 0; i < 10000; i++) host.call("hold", new Uint8Array([i & 255]));
		  return new Uint8Array();
		}
	`, 1000)
	defer func() { _, _ = callRealm(`__realm.dispose()`, 2*time.Second) }()
	if _, err := realmCall("flood", nil); err == nil {
		t.Fatal("a guest accumulated unbounded unresolved host calls")
	}
}

func TestGuestRealmOutstandingHostCallBytesCapped(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__heldHostCalls = 0;
		globalThis.__guestSeam = () => {
		  __heldHostCalls++;
		  return new Promise(() => {});
		};
	`)); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealmBudget(t, "{}", `
		function handle() {
		  const payload = new Uint8Array(2 * 1024 * 1024);
		  for (let i = 0; i < 9; i++) host.call("link/deliver", payload);
		  return new Uint8Array();
		}
	`, 1000)
	defer func() { _, _ = callRealm(`__realm.dispose()`, 2*time.Second) }()
	if _, err := realmCall("byte flood", nil); err == nil {
		t.Fatal("a guest accumulated unbounded unresolved host-call payload bytes")
	}
	if got := evalString(t, "String(__heldHostCalls)"); got != "8" {
		t.Fatalf("host received %s payloads, want exactly 8 before the 16 MiB byte cap", got)
	}
}

func TestGuestRealmHostCallBytesAreNameBlind(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__heldHostCalls = 0;
		globalThis.__guestSeam = () => {
		  __heldHostCalls++;
		  return new Promise(() => {});
		};
	`)); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealmBudget(t, "{}", `
		function handle() {
		  const payload = new Uint8Array(2 * 1024 * 1024);
		  for (let i = 0; i < 9; i++) host.call("send", payload);
		  return new Uint8Array();
		}
	`, 1000)
	defer func() { _, _ = callRealm(`__realm.dispose()`, 2*time.Second) }()
	if _, err := realmCall("ordinary flood", nil); err == nil {
		t.Fatal("an ordinary call name bypassed the universal host-call byte cap")
	}
	if got := evalString(t, "String(__heldHostCalls)"); got != "8" {
		t.Fatalf("host received %s payloads, want exactly 8 before name-blind admission refused the ninth", got)
	}
}

func TestGuestRealmRejectsDuplicateLiveHostCallID(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__heldHostCalls = 0;
		globalThis.__guestSeam = () => {
		  __heldHostCalls++;
		  return new Promise(() => {});
		};
	`)); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealmBudget(t, "{}", `
		function handle() {
		  __host_call("first", 7, new ArrayBuffer(1));
		  __host_call("second", 7, new ArrayBuffer(1));
		  return new Uint8Array();
		}
	`, 1000)
	defer func() { _, _ = callRealm(`__realm.dispose()`, 2*time.Second) }()
	if _, err := realmCall("duplicate", nil); err == nil {
		t.Fatal("a duplicate live host-call id was accepted")
	}
	if got := evalString(t, "String(__heldHostCalls)"); got != "1" {
		t.Fatalf("host received %s payloads, want one before duplicate-id rejection", got)
	}
}

// TestGuestRealmNodeAllowanceIsProcessScoped drives bridge.createRealm directly (not
// through native-shim.ts's RealmFactory, which always restates the same shared defaults —
// so a mismatch never arises through the production call path) with two DIFFERENT declared
// node-host-call ceilings, standing in for two legitimate shells sharing one process.
// Before the fix this errored on the second call ("node host-call limits changed after
// initialization"); the ceiling is process-scoped by design (see the var block above
// guestRealm), so a later caller's numbers must simply replace the earlier ones, never be
// refused for disagreeing with them.
func TestGuestRealmNodeAllowanceIsProcessScoped(t *testing.T) {
	bootRealm(t)
	mk := func(id, nodeCalls, nodeBytes int64) error {
		src := fmt.Sprintf(
			`bridge.createRealm(%d, "function handle(){ return new Uint8Array(); }", () => {}, %d, 1000, 10, 1048576, %d, %d)`,
			id, 64<<20, nodeCalls, nodeBytes)
		_, err := qc.Eval("mk.js", qjs.Code(src))
		return err
	}
	if err := mk(1, 5, 4096); err != nil {
		t.Fatalf("first realm declaring its own node ceiling: %v", err)
	}
	if err := mk(2, 9, 8192); err != nil {
		t.Fatalf("a second realm declaring a DIFFERENT node ceiling must not be refused: %v", err)
	}
	if maxNodeHostCalls != 9 || maxNodeHostBytes != 8192 {
		t.Fatalf("the process-scoped ceiling should track the latest caller, got %d/%d", maxNodeHostCalls, maxNodeHostBytes)
	}
}

// TestGuestRealmCarriesModuleDeadline pins the native-only half of CallBudget: guest.go
// owns the live execution segment, so it must carry that remainder into the shared seam.
// The seam then hands exactly that value to this slot's private module call.
func TestGuestRealmCarriesModuleDeadline(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("module-budget-seam.js", qjs.Code(`
		globalThis.__seenModuleDeadline = -1;
		const __budgetIdentity = sodium.crypto_sign_keypair();
		globalThis.__guestSeam = createGuestSeam({
		  platform: { sodium, identity: __budgetIdentity, now: () => Date.now() },
		  grants: { names: [], localServices: new Set(), calls: { call: () => null } },
		  modules: {
		    names: new Set(["probe"]),
		    call: (_name, _payload, deadlineMs) => {
		      globalThis.__seenModuleDeadline = deadlineMs;
		      return Promise.resolve({ bytes: new Uint8Array([9]), ms: 0 });
		    },
		  },
		});
	`)); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealmBudget(t, "{}", `
		function handle() { return host.call("probe", new Uint8Array()); }
	`, 250)
	defer func() { _, _ = callRealm(`__realm.dispose()`, 2*time.Second) }()
	if got, err := realmCall("probe", nil); err != nil || !bytes.Equal(got, []byte{9}) {
		t.Fatalf("module probe = %v, err = %v", got, err)
	}
	deadline := evalString(t, "String(__seenModuleDeadline)")
	ms, err := strconv.Atoi(deadline)
	if err != nil || ms <= 0 || ms > 250 {
		t.Fatalf("module deadline = %q ms, want the live remainder of a 250 ms segment", deadline)
	}
}

func TestGuestRealmStraySettleDoesNotConsumeParkedCall(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("build-seam.js", qjs.Code(`
		globalThis.__guestSeam = () => new Promise(() => {});
	`)); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealm(t, "{}", `
		function handle() {
		  host.call("hold", new Uint8Array([1]));
		  return new Uint8Array();
		}
	`)
	defer func() { _, _ = callRealm(`__realm.dispose()`, 2*time.Second) }()

	// realm id 1: guestSeamRealm's bootRealm() calls boot(), which stands the host realm up
	// fresh (host-shell.gen.js re-evaluates, resetting native-shim.ts's own realm-id
	// counter), and newTestRealm above is the first createRealm this test makes.
	g := realms[1]
	if _, err := realmCall("park", nil); err != nil {
		t.Fatal("park host call:", err)
	}
	if len(g.hostCalls) != 1 {
		t.Fatalf("parked call count = %d, want 1", len(g.hostCalls))
	}
	var liveID int64
	for id := range g.hostCalls {
		liveID = id
	}

	g.settleNet(liveID+1000, []byte{}, "")
	if len(g.hostCalls) != 1 {
		t.Fatalf("stray settlement changed parked call count to %d", len(g.hostCalls))
	}
	g.settleNet(liveID, []byte{}, "")
	if len(g.hostCalls) != 0 {
		t.Fatalf("live settlement left parked call count at %d", len(g.hostCalls))
	}
}

// A confined guest realm runs an app's entrypoints over the single
// host.call seam, reaching only its declared requires. This exercises a
// content-addressed put/get guest (local, synchronous ops) end-to-end, and asserts
// the realm is zero-authority — the host capabilities are not reachable by name.

// A minimal content-addressed store guest, the essence of seedstore's local path:
// put hashes the data (crypto/blake2b-256, by name) and stores it under that id
// (fs/put); get fetches by id (fs/get). `probe` reports any leaked host globals. One
// entrypoint, and the ops are the guest's own framing after the caller id.
const storeGuestSource = `
function hex(u8) { let s = ""; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, "0"); return s; }
function fsPutArg(key, bytes) {
  const k = new TextEncoder().encode(key);
  const out = new Uint8Array(4 + k.length + bytes.length);
  out[0] = (k.length >>> 24) & 255; out[1] = (k.length >>> 16) & 255;
  out[2] = (k.length >>> 8) & 255;  out[3] = k.length & 255;
  out.set(k, 4); out.set(bytes, 4 + k.length);
  return out;
}
function handle(arg) {
  const n = arg[32];
  let op = "";
  for (let i = 0; i < n; i++) op += String.fromCharCode(arg[33 + i]);
  const data = arg.subarray(33 + n);
  if (op === "put") {
    // A primitive is reached BY NAME through the crypto/ prefix — the name is the
    // seam, not an op number — and it answers a Promise like every name now.
    return host.call("crypto/blake2b-256", data).then((id) =>
      host.call("fs/put", fsPutArg(hex(id), data)).then(() => id));
  }
  if (op === "get") {
    return host.call("fs/get", new TextEncoder().encode(hex(data))).then((r) => {
      if (r.length < 1 || r[0] !== 1) throw new Error("not found");
      return r.slice(1);
    });
  }
  if (op === "probe") {
    const names = ["sodium", "fs", "__net", "__guestSeam", "__callSeam", "bridge", "bootShell", "process", "Bun"];
    const leaked = names.filter((n) => typeof globalThis[n] !== "undefined");
    return new TextEncoder().encode(leaked.join(","));
  }
  return new Uint8Array(0);
}
`

func TestGuestPutGetAndConfinement(t *testing.T) {
	guestSeamRealm(t)

	// Host realm: build the guest seam granting fs/put + fs/get (no net).
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildGuestSeam(["fs"], __id, null);
	`)); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealm(t, "{}", storeGuestSource)

	// put → returns the content id (32-byte hash).
	data := []byte("hello, confined world — stored by content id")
	id, err := realmCall("put", data)
	if err != nil {
		t.Fatal("put:", err)
	}
	if len(id) != 32 {
		t.Fatalf("put returned id of %d bytes, want a 32-byte hash", len(id))
	}

	// get(id) → the original bytes (proves it stored under the content id).
	got, err := realmCall("get", id)
	if err != nil {
		t.Fatal("get:", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("get = %q, want %q", got, data)
	}

	// get of an unknown id rejects (the guest throws "not found").
	if _, err := realmCall("get", make([]byte, 32)); err == nil {
		t.Fatal("get of an absent id should have failed")
	}

	// Confinement: none of the host capabilities are reachable by name in the realm.
	leaked, err := realmCall("probe", nil)
	if err != nil {
		t.Fatal("probe:", err)
	}
	if len(leaked) != 0 {
		t.Fatalf("guest realm leaked host globals: %s", leaked)
	}
}

// The realm's heap cap is a confinement property, not a tuning knob: an admitted guest
// that runs away must exhaust its own realm rather than the host, including on the request
// path a remote peer drives. Asserted on the real createRealm path, since the cap can only
// be set at runtime creation and is easy to drop there silently. The modest allocation is
// the control.
func TestGuestRealmHeapCapped(t *testing.T) {
	guestSeamRealm(t)

	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildGuestSeam([], __id, null);
	`)); err != nil {
		t.Fatal("build seam:", err)
	}
	// Twice the shared 64 MiB default (core/wasm-limits.ts DEFAULT_REALM_MEMORY_BYTES,
	// resolved by the shim) — mirrored here because the runtime no longer owns a copy.
	src := fmt.Sprintf(`
		function handle(arg) {
		  const n = arg[32];
		  let op = "";
		  for (let i = 0; i < n; i++) op += String.fromCharCode(arg[33 + i]);
		  if (op === "ok") return new Uint8Array(1 << 20);   // well under the cap
		  return new Uint8Array(%d);                        // twice the cap
		}
	`, 2*(64<<20))
	newTestRealm(t, "{}", src)

	out, err := realmCall("ok", nil)
	if err != nil {
		t.Fatal("guest refused a 1 MiB allocation under its cap:", err)
	}
	if len(out) != 1<<20 {
		t.Fatalf("guest returned %d bytes, want %d", len(out), 1<<20)
	}

	if _, err := realmCall("hog", nil); err == nil {
		t.Fatal("guest allocated past its heap cap — the realm is not confined")
	}
}

// A guest that never yields is stopped by its execution budget (README §12.3, §16.1).
//
// The native half of safe-js.ts's interrupt handler, and the SAME lever: QuickJS's own,
// armed through qjs.Runtime.Budget. So the consequence asserted below is safe-js's — the
// overrun is a throw, the caller gets an error, and the realm is still usable. A guest
// that spends its allowance has failed one invocation, not destroyed the app.
//
// The trivial call first is the control; the trivial call AFTER is the point.
func TestGuestRealmExecutionBudget(t *testing.T) {
	guestSeamRealm(t)

	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildGuestSeam([], __id, null);
	`)); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealmBudget(t, "{}", `
		function handle(arg) {
		  const n = arg[32];
		  let op = "";
		  for (let i = 0; i < n; i++) op += String.fromCharCode(arg[33 + i]);
		  if (op === "ok") return new Uint8Array([7]);
		  for (;;) {}
		}
	`, 300)

	out, err := realmCall("ok", nil)
	if err != nil || len(out) != 1 || out[0] != 7 {
		t.Fatalf("a bounded realm refused a trivial call: %v %v", out, err)
	}

	start := time.Now()
	if _, err := realmCall("spin", nil); err == nil {
		t.Fatal("a spinning guest was not interrupted")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("interrupted after %s, want near the 300ms budget", d)
	}

	out, err = realmCall("ok", nil)
	if err != nil || len(out) != 1 || out[0] != 7 {
		t.Fatalf("a realm that overran its budget must survive it: %v %v", out, err)
	}
}

// A realm killed mid-flight must SETTLE the calls it still owes, not strand them.
//
// The dangerous shape is an entrypoint that parks on net and then burns its budget in the
// continuation: the kill lands inside settleNet, after the initiator's promise reached the
// shell but before anything settled it. safe-js has no equivalent problem (its interrupt
// throws and the guest's promise rejects), so a native realm that merely stopped answering
// would hang the node rather than fail it — strictly worse, since the caller cannot retry,
// time out, or tell anything went wrong.
func TestGuestRealmBudgetSettlesInflightCall(t *testing.T) {
	guestSeamRealm(t)

	// A stub claimant is enough: a cross-realm call only needs a promise that settles on
	// the loop, and using one keeps the kill (not a socket) as the only variable.
	if _, err := qc.Eval("setup.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		globalThis.__peer = toHex(sodium.crypto_sign_keypair().publicKey);
		__buildGuestSeam([], __id,
			{ call: async () => new Uint8Array([9]) }, undefined, ["_net"]);
	`)); err != nil {
		t.Fatal("setup:", err)
	}

	newTestRealmBudget(t, fmt.Sprintf(`{"peer":%q}`, mustEvalString(t, qc, `__peer`)), `
		async function handle() {
		  // the mock composes this guest's op framing; the local op is "park"
		  await host.call("_net", new Uint8Array(0));
		  for (;;) {}                 // burn the budget in the CONTINUATION
		}
	`, 300)

	start := time.Now()
	if _, err := realmCall("park", nil); err == nil {
		t.Fatal("a guest that spun in its continuation was not stopped")
	}
	// The harness gives up at 30s. Anything near that means the call was stranded
	// rather than settled — the bug this test exists for.
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("in-flight call was stranded for %s, not settled with an error", d)
	}
}

// The budget also covers continuations the loop pumps directly. A plain `await` (no
// host.call) resumes through eventLoop.pumpAll rather than settleNet, which was once
// outside every guard the realm had: one `await Promise.resolve()` bought an unbounded
// loop, since only the segment before the await was budgeted.
//
// Runs on the test goroutine, not a helper one: qjs contexts are not goroutine-safe, and
// the loop must be driven by whoever is waiting on it.
func TestGuestRealmBudgetCoversPumpedContinuations(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildGuestSeam([], __id, null);
	`)); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealmBudget(t, "{}", `
		async function handle() {
			await Promise.resolve();   // resumes via pumpAll, not settleNet
			for (;;) {}
		}
	`, 300)

	start := time.Now()
	if _, err := realmCall("park", nil); err == nil {
		t.Fatal("a guest spinning in a pumped continuation was not stopped")
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("caller stranded for %s rather than settled with an error", d)
	}
}

// Closing a realm settles the calls it still owes, rather than stranding them.
//
// Same failure mode as a budget kill and the same fix: an initiator's promise lives
// inside the realm, so a close with calls outstanding leaves the caller waiting on
// something that can no longer be resolved. safe-js's dispose() fails its pending
// callers for this reason; close() has to as well.
func TestGuestRealmCloseSettlesInflightCall(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("setup.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		globalThis.__peer = toHex(sodium.crypto_sign_keypair().publicKey);
		__buildGuestSeam([], __id,
			{ call: () => new Promise(() => {}) }, undefined, ["_net"]);
	`)); err != nil {
		t.Fatal("setup:", err)
	}
	// The transport never settles, so the guest parks forever and the realm is closed
	// out from under a live call — the shape that used to hang.
	newTestRealmBudget(t, fmt.Sprintf(`{"peer":%q}`, mustEvalString(t, qc, `__peer`)), `
		function fromHex(h) {
		  const out = new Uint8Array(h.length / 2);
		  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
		  return out;
		}
		async function handle() {
		  const peer = fromHex(APP.peer);
		  const proto = [0x74, 0x65, 0x73, 0x74];
		  const req = new Uint8Array(32 + 1 + proto.length);
		  req.set(peer, 0);
		  req[32] = proto.length;
		  req.set(proto, 33);
		  await host.call("_net", req);
		  return new Uint8Array([1]);
		}
	`, 0)

	if _, err := qc.Eval("close.js", qjs.Code(`
		__realm.call(new Uint8Array(0)).then(
			() => { globalThis.__outcome = "resolved"; },
			(e) => { globalThis.__outcome = "rejected: " + (e && e.message || e); });
		__realm.dispose();
	`)); err != nil {
		t.Fatal("close:", err)
	}
	// One bounded await is enough to drive the loop; the rejection must arrive in it.
	_, _ = callRealm("(() => new Promise(r => setTimeout(() => r(new Uint8Array(0)), 50)))", 5*time.Second)
	got := mustEvalString(t, qc, `String(globalThis.__outcome)`)
	if got == "undefined" {
		t.Fatal("call was stranded: closing the realm left its caller unsettled")
	}
	t.Logf("caller settled with: %s", got)
}
