package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"seedloader/qjs"
)

// A confined guest realm runs an app's entrypoints over the single
// host.call seam, reaching only its declared cap domains. This exercises a
// content-addressed put/get guest (local, synchronous ops) end-to-end, and asserts
// the realm is zero-authority — the host capabilities are not reachable by name.

// A minimal content-addressed store guest, the essence of seedstore's local path:
// put hashes the data (crypto/blake2b-256, by name) and stores it under that id
// (fs/put); get fetches by id (fs/get). `probe` reports any leaked host globals.
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
register("put", async (data) => {
  // A primitive is reached BY NAME through the crypto/ prefix — the name is the
  // seam, not an op number — and it resolves synchronously like every primitive.
  const id = host.call("crypto/blake2b-256", data);
  await host.call("fs/put", fsPutArg(hex(id), data));
  return id;
});
register("get", async (id) => {
  const r = await host.call("fs/get", new TextEncoder().encode(hex(id)));
  if (r.length < 1 || r[0] !== 1) throw new Error("not found");
  return r.slice(1);
});
register("probe", () => {
  const names = ["sodium", "fs", "__net", "__capBridge", "__callBridge", "bridge", "createShell", "process", "Bun"];
  const leaked = names.filter((n) => typeof globalThis[n] !== "undefined");
  return new TextEncoder().encode(leaked.join(","));
});
`

func TestGuestPutGetAndConfinement(t *testing.T) {
	capBridgeRealm(t)

	// Host realm: build the cap-bridge granting crypto + fs (no net).
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildCapBridge(["fs"], __id, null, []);
	`)); err != nil {
		t.Fatal("build bridge:", err)
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

// The realm's heap cap is a confinement property, not a tuning knob: the admission
// policy decides WHICH guest runs, but an admitted guest that runs away must exhaust
// its own realm rather than the host — including on the request path, which a remote
// peer drives. Asserted on the real createRealm path, since the cap can only be set at
// runtime creation and is easy to drop there silently. The modest allocation is the
// control: without it a realm that was simply broken would pass the same test.
func TestGuestRealmHeapCapped(t *testing.T) {
	capBridgeRealm(t)

	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildCapBridge(["crypto"], __id, null, []);
	`)); err != nil {
		t.Fatal("build bridge:", err)
	}
	// Twice the shared 64 MiB default (core/wasm-limits.ts DEFAULT_REALM_MEMORY_BYTES,
	// resolved by the shim) — mirrored here because the runtime no longer owns a copy.
	src := fmt.Sprintf(`
		register("ok",  () => new Uint8Array(1 << 20));  // well under the cap
		register("hog", () => new Uint8Array(%d));       // twice the cap
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

// A guest that never yields is terminated by its execution budget (README §12.3, §16.1).
//
// This is the native half of safe-js.ts's interrupt handler, and it does NOT go through
// QuickJS: New_QJS's maxExecutionTime argument is inert in the vendored qjs.wasm (a 1 ms
// limit does not stop `for(;;){f()}`), so guest.go arms a wazero deadline instead. The
// consequence asserted below is that the kill is fatal to the realm rather than a
// catchable JS error — wazero closes the module, so the realm must refuse later calls
// cleanly instead of panicking on a freed handle.
//
// The trivial call first is the control: without it a realm that was simply broken would
// pass the same test.
func TestGuestRealmExecutionBudget(t *testing.T) {
	capBridgeRealm(t)

	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildCapBridge(["crypto"], __id, null, []);
	`)); err != nil {
		t.Fatal("build bridge:", err)
	}
	newTestRealmBudget(t, "{}", `
		register("ok",   () => new Uint8Array([7]));
		register("spin", () => { for (;;) {} });
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

	if _, err := realmCall("ok", nil); err == nil {
		t.Fatal("a realm terminated by its budget should refuse further calls")
	}
}

// A realm killed mid-flight must SETTLE the calls it still owes, not strand them.
//
// The dangerous shape is an entrypoint that parks on net and then burns its budget in
// the continuation: the kill lands inside settleNet, i.e. after the initiator's promise
// was handed to the shell but before anything settled it. safe-js has no equivalent
// problem — its interrupt throws, the guest's promise rejects, the caller sees an error —
// so a native realm that merely stopped answering would be a divergence that hangs the
// node rather than failing it. A hang is strictly worse than an error: the caller cannot
// retry, time out on its own, or even tell that anything went wrong.
func TestGuestRealmBudgetSettlesInflightCall(t *testing.T) {
	capBridgeRealm(t)

	// A stub transport is enough: net/send only needs a promise that settles on the
	// loop, and using one keeps the kill (not a socket) as the only variable.
	if _, err := qc.Eval("setup.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		globalThis.__peer = toHex(sodium.crypto_sign_keypair().publicKey);
		__buildCapBridge(["crypto", "net"], __id,
			{ request: async () => new Uint8Array([9]) }, [__peer]);
	`)); err != nil {
		t.Fatal("setup:", err)
	}

	newTestRealmBudget(t, fmt.Sprintf(`{"peer":%q}`, mustEvalString(t, qc, `__peer`)), `
		function fromHex(h) {
		  const out = new Uint8Array(h.length / 2);
		  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
		  return out;
		}
		register("park", async () => {
		  const peer = fromHex(APP.peer);
		  const proto = [0x74, 0x65, 0x73, 0x74];
		  const req = new Uint8Array(32 + 1 + proto.length);
		  req.set(peer, 0);
		  req[32] = proto.length;
		  req.set(proto, 33);
		  await host.call("net/send", req);
		  for (;;) {}                 // burn the budget in the CONTINUATION
		});
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

// The budget also covers continuations the loop pumps directly.
//
// A plain `await` (no host.call) resumes through eventLoop.pumpAll rather than settleNet,
// which for a while was outside every guard the realm had: one `await Promise.resolve()`
// bought an unbounded loop, since only the segment before the await was budgeted. The
// loop now drains a guest realm through guestRealm.pump, so a queued job is guest code
// like any other.
//
// Runs on the test goroutine, not a helper one: qjs contexts are not goroutine-safe, and
// the loop must be driven by whoever is waiting on it.
func TestGuestRealmBudgetCoversPumpedContinuations(t *testing.T) {
	capBridgeRealm(t)
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildCapBridge(["crypto"], __id, null, []);
	`)); err != nil {
		t.Fatal("build bridge:", err)
	}
	newTestRealmBudget(t, "{}", `
		register("park", async () => {
			await Promise.resolve();   // resumes via pumpAll, not settleNet
			for (;;) {}
		});
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
	capBridgeRealm(t)
	if _, err := qc.Eval("setup.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		globalThis.__peer = toHex(sodium.crypto_sign_keypair().publicKey);
		__buildCapBridge(["crypto", "net"], __id,
			{ request: () => new Promise(() => {}) }, [__peer]);
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
		register("park", async () => {
		  const peer = fromHex(APP.peer);
		  const proto = [0x74, 0x65, 0x73, 0x74];
		  const req = new Uint8Array(32 + 1 + proto.length);
		  req.set(peer, 0);
		  req[32] = proto.length;
		  req.set(proto, 33);
		  await host.call("net/send", req);
		  return new Uint8Array([1]);
		});
	`, 0)

	if _, err := qc.Eval("close.js", qjs.Code(`
		__realm.call("park", new Uint8Array(0)).then(
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
