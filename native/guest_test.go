package main

import (
	"bytes"
	"fmt"
	"testing"

	"seedloader/qjs"
)

// A confined guest realm runs an app's entrypoints over the single
// host.call seam, reaching only its declared cap domains. This exercises a
// content-addressed put/get guest (local, synchronous ops) end-to-end, and asserts
// the realm is zero-authority — the host capabilities are not reachable by name.

// A minimal content-addressed store guest, the essence of seedstore's local path:
// put hashes the data (CAP_HASH) and stores it under that id (CAP_FS_PUT); get
// fetches by id (CAP_FS_GET). `probe` reports any leaked host globals.
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
register("put", (data) => {
  const id = host.call(CAP_HASH, data);
  host.call(CAP_FS_PUT, fsPutArg(hex(id), data));
  return id;
});
register("get", (id) => {
  const r = host.call(CAP_FS_GET, new TextEncoder().encode(hex(id)));
  if (r.length < 1 || r[0] !== 1) throw new Error("not found");
  return r.slice(1);
});
register("probe", () => {
  const names = ["sodium", "fs", "__net", "__capBridge", "__callBridge", "bridge", "process", "Bun"];
  const leaked = names.filter((n) => typeof globalThis[n] !== "undefined");
  return new TextEncoder().encode(leaked.join(","));
});
`

func TestGuestPutGetAndConfinement(t *testing.T) {
	hostQc, el, done := capBridgeRealm(t)
	defer done()

	// Host realm: build the cap-bridge granting crypto + fs (no net/module).
	if _, err := hostQc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildCapBridge(["crypto", "fs"], __id, null, []);
	`)); err != nil {
		t.Fatal("build bridge:", err)
	}

	g, err := newGuestRealm(el, "", "{}", storeGuestSource)
	if err != nil {
		t.Fatal("guest realm:", err)
	}
	defer g.close()

	// put → returns the content id (32-byte hash).
	data := []byte("hello, confined world — stored by content id")
	id, err := g.runGuest("put", data)
	if err != nil {
		t.Fatal("put:", err)
	}
	if len(id) != 32 {
		t.Fatalf("put returned id of %d bytes, want a 32-byte hash", len(id))
	}

	// get(id) → the original bytes (proves it stored under the content id).
	got, err := g.runGuest("get", id)
	if err != nil {
		t.Fatal("get:", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("get = %q, want %q", got, data)
	}

	// get of an unknown id rejects (the guest throws "not found").
	if _, err := g.runGuest("get", make([]byte, 32)); err == nil {
		t.Fatal("get of an absent id should have failed")
	}

	// Confinement: none of the host capabilities are reachable by name in the realm.
	leaked, err := g.runGuest("probe", nil)
	if err != nil {
		t.Fatal("probe:", err)
	}
	if len(leaked) != 0 {
		t.Fatalf("guest realm leaked host globals: %s", leaked)
	}
}

// The realm's heap cap (guestMemoryLimit) is a confinement property, not a tuning knob:
// the admission policy decides WHICH guest runs, but an admitted guest that runs away must
// exhaust its own realm rather than the host — including on the serveHandle path, which a
// remote peer drives. Asserted on the real newGuestRealm path, since the cap can only be
// set at runtime creation and is easy to drop there silently. The modest allocation is the
// control: without it a realm that was simply broken would pass the same test.
func TestGuestRealmHeapCapped(t *testing.T) {
	hostQc, el, done := capBridgeRealm(t)
	defer done()

	if _, err := hostQc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildCapBridge(["crypto"], __id, null, []);
	`)); err != nil {
		t.Fatal("build bridge:", err)
	}

	src := fmt.Sprintf(`
		register("ok",  () => new Uint8Array(1 << 20));  // well under the cap
		register("hog", () => new Uint8Array(%d));       // twice the cap
	`, 2*guestMemoryLimit)
	g, err := newGuestRealm(el, "", "{}", src)
	if err != nil {
		t.Fatal("guest realm:", err)
	}
	defer g.close()

	out, err := g.runGuest("ok", nil)
	if err != nil {
		t.Fatal("guest refused a 1 MiB allocation under its cap:", err)
	}
	if len(out) != 1<<20 {
		t.Fatalf("guest returned %d bytes, want %d", len(out), 1<<20)
	}

	if _, err := g.runGuest("hog", nil); err == nil {
		t.Fatal("guest allocated past its heap cap — the realm is not confined")
	}
}
