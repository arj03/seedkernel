package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"seedloader/qjs"
)

// The shared cap-bridge.ts runs in the host realm over the Go
// primitives (sodium + fs), reused verbatim. Each op is exercised through the
// single `__capBridge(op, bytes)` funnel and checked against the underlying
// primitive, plus the cap-domain gate (an undeclared op is refused).

// The op numbers of cap-bridge.ts's CAP catalog, named here so a renumbering shows up as
// one edit rather than as bare integers scattered through the assertions.
const (
	capCrypto      = 1
	capSign        = 2
	capIdentity    = 3
	capNetSend     = 5
	capNetPeers    = 6
	capFsGet       = 7
	capFsPut       = 8
	capClock       = 14
	capNetLinkSend = 16
)

func TestCapBridgeOps(t *testing.T) {
	capBridgeRealm(t)

	// Grant crypto + fs + clock (not net/module) and an identity from sodium. The
	// guest-signing scope binds SIGN to a bundle namespace (README §12.2); a real node
	// derives it from the manifest's (author, app), here a throwaway pair.
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		// What SIGN signs under is a SLOT-derived scope — domain, scope bytes and the key
		// that signs, all three. __scopeBytes is the middle third, which this test
		// reconstructs the preimage from.
		globalThis.__scope = appSignScope(__id, __id.publicKey, "testapp");
		globalThis.__scopeBytes = guestSignScope(__id.publicKey, "testapp");
		__buildCapBridge(["crypto", "fs", "clock"], __id, null, [], __scope);
	`)); err != nil {
		t.Fatal("build bridge:", err)
	}

	call := func(op int, payload []byte) (*qjs.Value, error) {
		fn := qc.Global().GetPropertyStr("__callBridge")
		return qc.Invoke(fn, qc.NewUndefined(), qc.NewInt32(int32(op)), qc.NewArrayBuffer(payload))
	}
	callBytes := func(op int, payload []byte) []byte {
		t.Helper()
		v, err := call(op, payload)
		if err != nil {
			t.Fatalf("op %d: %v", op, err)
		}
		b, err := qjs.JsTypedArrayToGo(v)
		if err != nil {
			t.Fatalf("op %d result: %v", op, err)
		}
		return b
	}

	// The node pubkey. JsTypedArrayToGo copies on read and leaves __id.publicKey intact
	// for the bridge's own use, so it can be read directly.
	pk := jsBytes(t, qc, `__id.publicKey`)

	// A primitive is reached BY NAME through the one CAP_CRYPTO op, so there is no op
	// number per algorithm and no ABI rev to add one.
	prim := func(name string, args []byte) []byte {
		t.Helper()
		out := append([]byte{byte(len(name))}, name...)
		return callBytes(capCrypto, append(out, args...))
	}

	// blake2b-256: must equal sodium.crypto_generichash.
	h := prim("blake2b-256", []byte("hello seedkernel"))
	if len(h) != 32 {
		t.Fatalf("blake2b-256 len = %d, want 32", len(h))
	}
	want := jsBytes(t, qc, `sodium.crypto_generichash(32, new TextEncoder().encode("hello seedkernel"))`)
	if !bytes.Equal(h, want) {
		t.Fatalf("blake2b-256 = %x, want %x", h, want)
	}

	// IDENTITY: this node's public key.
	if id := callBytes(capIdentity, nil); !bytes.Equal(id, pk) {
		t.Fatalf("IDENTITY = %x, want node pubkey %x", id, pk)
	}

	// SIGN is scoped, so it signs DOMAIN_guest ‖ scope ‖ msg, not raw msg. The verify
	// primitive stays raw, so we reconstruct the prefixed preimage.
	msg := []byte("a message to sign")
	sig := callBytes(capSign, msg)
	if len(sig) != 64 {
		t.Fatalf("SIGN len = %d, want 64", len(sig))
	}
	scope := jsBytes(t, qc, `__scopeBytes`)
	preimage := append(append(append([]byte{}, []byte("seedkernel-guest-sig-v1\x00")...), scope...), msg...)
	verifyGood := append(append(append([]byte{}, pk...), sig...), preimage...) // [pk 32][sig 64][preimage]
	if v := prim("ed25519/verify", verifyGood); len(v) != 1 || v[0] != 1 {
		t.Fatalf("ed25519/verify(scoped preimage) = %v, want [1]", v)
	}
	// The raw message must NOT verify — proof the signature is bound to the scope.
	verifyRaw := append(append(append([]byte{}, pk...), sig...), msg...)
	if v := prim("ed25519/verify", verifyRaw); len(v) != 1 || v[0] != 0 {
		t.Fatalf("ed25519/verify(raw msg) = %v, want [0] (SIGN is scoped, never raw)", v)
	}

	// FS_PUT then FS_GET: content-addressed round trip.
	key := []byte("blk")
	value := []byte("a content-addressed block")
	put := make([]byte, 4+len(key)+len(value)) // [klen u32][key][bytes]
	binary.BigEndian.PutUint32(put, uint32(len(key)))
	copy(put[4:], key)
	copy(put[4+len(key):], value)
	callBytes(capFsPut, put)
	got := callBytes(capFsGet, key) // [1][bytes] on hit
	if len(got) == 0 || got[0] != 1 || !bytes.Equal(got[1:], value) {
		t.Fatalf("FS_GET = %v, want [1] ++ %q", got, value)
	}

	// CLOCK: 8-byte big-endian millis, nonzero.
	if clk := callBytes(capClock, nil); len(clk) != 8 || (clk[0]|clk[1]|clk[2]|clk[3]|clk[4]|clk[5]|clk[6]|clk[7]) == 0 {
		t.Fatalf("CLOCK = %v, want nonzero u64", clk)
	}

	// Gate: an undeclared op is refused. NET_PEERS rather than NET_SEND because the
	// gate has to be observed SYNCHRONOUSLY here — NET_SEND is a real round trip, so a
	// refusal comes back as a rejected promise rather than a thrown error.
	if _, err := call(capNetPeers, nil); err == nil {
		t.Fatal("NET_PEERS resolved despite not being a declared cap")
	}
	// And RAW net is not merely undeclared here — it is the transport slot's, so no app
	// bridge is ever wired one.
	if _, err := call(capNetLinkSend, make([]byte, 8)); err == nil {
		t.Fatal("a raw-link op resolved on an app bridge")
	}
}

// jsBytes evaluates a JS expression that yields a Uint8Array and returns its bytes.
func jsBytes(t *testing.T, qc *qjs.Context, expr string) []byte {
	t.Helper()
	v, err := qc.Eval("<jsBytes>", qjs.Code(expr))
	if err != nil {
		t.Fatalf("eval %q: %v", expr, err)
	}
	b, err := qjs.JsTypedArrayToGo(v)
	if err != nil {
		t.Fatalf("bytes of %q: %v", expr, err)
	}
	return b
}
