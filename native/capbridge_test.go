package main

import (
	"bytes"
	"encoding/binary"
	"time"
	"testing"

	"seedloader/qjs"
)

// The shared cap-bridge.ts runs in the host realm over the Go
// primitives (sodium + fs), reused verbatim. Each name is exercised through the
// single `__capBridge(name, bytes)` funnel and checked against the underlying
// primitive, plus the cap-domain gate (a name under an undeclared prefix is refused).

// The names of cap-bridge.ts's cap catalog, written here so a rename shows up as
// one edit rather than as bare strings scattered through the assertions.
const (
	nameSign     = "node/sign"
	nameIdentity = "node/identity"
	nameNetPeers = "net/peers"
	nameFsGet    = "fs/get"
	nameFsPut    = "fs/put"
	nameClockNow = "clock/now"
	nameLinkSend = "link/send"
)

func TestCapBridgeOps(t *testing.T) {
	capBridgeRealm(t)

	// Grant node/sign, node/identity, fs/put, fs/get and clock/now (not net, not
	// link) and an identity from sodium. The
	// guest-signing scope binds node/sign to a bundle namespace (README §12.2); a real
	// node derives it from the manifest's (author, app), here a throwaway pair.
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		// What node/sign signs under is a SLOT-derived scope — domain, scope bytes and
		// the key that signs, all three. __scopeBytes is the middle third, which this
		// test reconstructs the preimage from.
		globalThis.__scope = appSignScope(__id, __id.publicKey, "testapp");
		globalThis.__scopeBytes = guestSignScope(__id.publicKey, "testapp");
		__buildCapBridge(["node/sign", "node/identity", "fs/put", "fs/get", "clock/now"], __id, null, [], __scope);
	`)); err != nil {
		t.Fatal("build bridge:", err)
	}

	call := func(name string, payload []byte) (*qjs.Value, error) {
		fn := qc.Global().GetPropertyStr("__callBridge")
		return qc.Invoke(fn, qc.NewUndefined(), qc.NewString(name), qc.NewArrayBuffer(payload))
	}
	callBytes := func(name string, payload []byte) []byte {
		t.Helper()
		v, err := call(name, payload)
		if err != nil {
			t.Fatalf("call %s: %v", name, err)
		}
		b, err := qjs.JsTypedArrayToGo(v)
		if err != nil {
			t.Fatalf("call %s result: %v", name, err)
		}
		return b
	}

	// The node pubkey. JsTypedArrayToGo copies on read and leaves __id.publicKey intact
	// for the bridge's own use, so it can be read directly.
	pk := jsBytes(t, qc, `__id.publicKey`)

	// A primitive is reached BY NAME through the `crypto/` prefix, so there is no op
	// number per algorithm and no ABI rev to add one.

	// blake2b-256: must equal sodium.crypto_generichash.
	h := callBytes("crypto/blake2b-256", []byte("hello seedkernel"))
	if len(h) != 32 {
		t.Fatalf("crypto/blake2b-256 len = %d, want 32", len(h))
	}
	want := jsBytes(t, qc, `sodium.crypto_generichash(32, new TextEncoder().encode("hello seedkernel"))`)
	if !bytes.Equal(h, want) {
		t.Fatalf("crypto/blake2b-256 = %x, want %x", h, want)
	}

	// node/identity: this node's public key.
	if id := callBytes(nameIdentity, nil); !bytes.Equal(id, pk) {
		t.Fatalf("node/identity = %x, want node pubkey %x", id, pk)
	}

	// node/sign is scoped, so it signs DOMAIN_guest ‖ scope ‖ msg, not raw msg. The
	// verify primitive stays raw, so we reconstruct the prefixed preimage.
	msg := []byte("a message to sign")
	sig := callBytes(nameSign, msg)
	if len(sig) != 64 {
		t.Fatalf("node/sign len = %d, want 64", len(sig))
	}
	scope := jsBytes(t, qc, `__scopeBytes`)
	preimage := append(append(append([]byte{}, []byte("seedkernel-guest-sig-v1\x00")...), scope...), msg...)
	verifyGood := append(append(append([]byte{}, pk...), sig...), preimage...) // [pk 32][sig 64][preimage]
	if v := callBytes("crypto/ed25519/verify", verifyGood); len(v) != 1 || v[0] != 1 {
		t.Fatalf("crypto/ed25519/verify(scoped preimage) = %v, want [1]", v)
	}
	// The raw message must NOT verify — proof the signature is bound to the scope.
	verifyRaw := append(append(append([]byte{}, pk...), sig...), msg...)
	if v := callBytes("crypto/ed25519/verify", verifyRaw); len(v) != 1 || v[0] != 0 {
		t.Fatalf("crypto/ed25519/verify(raw msg) = %v, want [0] (node/sign is scoped, never raw)", v)
	}

	// fs/put then fs/get: content-addressed round trip. Both AWAIT — fs round-trips at
	// the seam, because a synchronous `get` is a shape no browser backend can implement
	// and the seam is one shape on every target (core/fs.ts).
	awaitBytes := func(name string, payload []byte) []byte {
		t.Helper()
		b, err := callRealm("__callBridgeAwait", 5*time.Second,
			qc.NewString(name), qc.NewArrayBuffer(payload))
		if err != nil {
			t.Fatalf("call %s: %v", name, err)
		}
		return b
	}
	key := []byte("blk")
	value := []byte("a content-addressed block")
	put := make([]byte, 4+len(key)+len(value)) // [klen u32][key][bytes]
	binary.BigEndian.PutUint32(put, uint32(len(key)))
	copy(put[4:], key)
	copy(put[4+len(key):], value)
	awaitBytes(nameFsPut, put)
	got := awaitBytes(nameFsGet, key) // [1][bytes] on hit
	if len(got) == 0 || got[0] != 1 || !bytes.Equal(got[1:], value) {
		t.Fatalf("fs/get = %v, want [1] ++ %q", got, value)
	}

	// clock/now: 8-byte big-endian millis, nonzero.
	if clk := callBytes(nameClockNow, nil); len(clk) != 8 || (clk[0]|clk[1]|clk[2]|clk[3]|clk[4]|clk[5]|clk[6]|clk[7]) == 0 {
		t.Fatalf("clock/now = %v, want nonzero u64", clk)
	}

	// Gate: a name outside the granted set is refused. net/peers rather than
	// net/send because the gate has to be observed SYNCHRONOUSLY here — net/send is a
	// real round trip, so a refusal comes back as a rejected promise rather than a
	// thrown error.
	if _, err := call(nameNetPeers, nil); err == nil {
		t.Fatal("net/peers resolved despite not being a declared name")
	}
	// And raw net is not merely undeclared here — it is the transport slot's, so no app
	// bridge is ever wired one.
	if _, err := call(nameLinkSend, make([]byte, 8)); err == nil {
		t.Fatal("a link/* name resolved on an app bridge")
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
