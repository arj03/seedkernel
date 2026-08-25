package main

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"seedloader/qjs"
)

// The shared guest-seam.ts runs in the host realm over the Go
// primitives (sodium + fs), reused verbatim. Each name is exercised through the
// single `__guestSeam(name, bytes)` seam and checked against the underlying
// primitive, plus the name gate (an undeclared authority is refused).

// The names of guest-seam.ts's catalog, written here so a rename shows up as
// one edit rather than as bare strings scattered through the assertions.
const (
	nameSign       = "node/sign"
	nameVerify     = "node/verify"
	nameIdentity   = "node/identity"
	nameNodeRandom = "node/random"
	nameFsGet      = "fs/get"
	nameFsPut      = "fs/put"
	nameClockNow   = "clock/now"
	nameLinkSend   = "link/send"
)

func TestGuestSeamOps(t *testing.T) {
	guestSeamRealm(t)

	// Grant node/sign, node/verify, node/identity, fs/put, fs/get and clock/now (not net,
	// not link), plus an identity from sodium. The signing scope binds node/sign and
	// node/verify to a bundle namespace (README §12.2) — a real node derives it from the
	// manifest's (author, app); here it is a throwaway pair.
	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		globalThis.__other = sodium.crypto_sign_keypair();
		// What node/sign signs under is a SLOT-derived scope — domain, scope bytes and
		// the key that signs, all three.
		globalThis.__scope = appSignScope(__id, __id.publicKey, "testapp");
		__buildGuestSeam(["node", "fs", "clock"], __id, null, __scope);
	`)); err != nil {
		t.Fatal("build seam:", err)
	}

	// Every seam name — crypto included — answers a Promise now, so every probe goes
	// through callRealm, which pumps the loop until it settles. A gate refusal is a
	// rejected promise here and surfaces as callRealm's error.
	callBytes := func(name string, payload []byte) []byte {
		t.Helper()
		b, err := callRealm("__callSeam", 5*time.Second,
			qc.NewString(name), qc.NewArrayBuffer(payload))
		if err != nil {
			t.Fatalf("call %s: %v", name, err)
		}
		return b
	}
	refused := func(name string, payload []byte) error {
		t.Helper()
		_, err := callRealm("__callSeam", 5*time.Second,
			qc.NewString(name), qc.NewArrayBuffer(payload))
		return err
	}

	// The node pubkey. JsTypedArrayToGo copies on read and leaves __id.publicKey intact
	// for the seam's own use, so it can be read directly.
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

	// node/sign and node/verify are scoped (README §12.2): the host applies
	// DOMAIN_guest ‖ scope to the message on BOTH sides, so the guest checks a
	// signature by naming the key, never by reconstructing host-owned prefix bytes.
	msg := []byte("a message to sign")
	sig := callBytes(nameSign, msg)
	if len(sig) != 64 {
		t.Fatalf("node/sign len = %d, want 64", len(sig))
	}
	// node/verify — [pk 32][sig 64][msg] — the scope rides on the host side of the seam.
	verifyScoped := append(append(append([]byte{}, pk...), sig...), msg...)
	if v := callBytes(nameVerify, verifyScoped); len(v) != 1 || v[0] != 1 {
		t.Fatalf("node/verify(scoped msg) = %v, want [1]", v)
	}
	// The same signature must NOT verify under a different key: the key is caller-named,
	// the scope is not — this is a check of this bundle's namespace, not of "some key".
	otherPk := jsBytes(t, qc, `__other.publicKey`)
	verifyOther := append(append(append([]byte{}, otherPk...), sig...), msg...)
	if v := callBytes(nameVerify, verifyOther); len(v) != 1 || v[0] != 0 {
		t.Fatalf("node/verify(another key) = %v, want [0]", v)
	}
	// A mis-framed call is not a failed verification: a payload too short to hold
	// [pk 32][sig 64] errors, where [0] would have been a verdict about bytes nothing
	// checked. The bound is exactly that prefix, so an empty message still answers.
	if err := refused(nameVerify, verifyScoped[:95]); err == nil {
		t.Fatal("node/verify(short payload) returned a verdict, want an error (mis-framed is not invalid)")
	}
	emptySig := callBytes(nameSign, nil)
	verifyEmpty := append(append([]byte{}, pk...), emptySig...)
	if v := callBytes(nameVerify, verifyEmpty); len(v) != 1 || v[0] != 1 {
		t.Fatalf("node/verify(empty msg) = %v, want [1]", v)
	}
	// Raw Ed25519 verification is host-internal. Guests get only node/verify, whose
	// scope is supplied by the host rather than reconstructed in guest bytes.
	if err := refused("crypto/ed25519/verify", nil); err == nil {
		t.Fatal("crypto/ed25519/verify was exposed, want unknown host transform")
	}

	// fs/put then fs/get: content-addressed round trip. Both AWAIT — fs round-trips at
	// the seam, because a synchronous `get` is a shape no browser backend can implement
	// and the seam is one shape on every target (core/fs.ts).
	awaitBytes := func(name string, payload []byte) []byte {
		t.Helper()
		b, err := callRealm("__callSeamAwait", 5*time.Second,
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

	// The unit a manifest declares is the SERVICE, so node/random resolves beside
	// node/sign: one service under two calls, never a boundary a guest could hold half of.
	if r := callBytes(nameNodeRandom, []byte{0, 0, 0, 4}); len(r) != 4 {
		t.Fatalf("node/random = %d bytes, want 4", len(r))
	}
	// And raw net is not merely undeclared here — it is capability-wired, so no app
	// seam is ever wired one.
	if err := refused(nameLinkSend, make([]byte, 8)); err == nil {
		t.Fatal("a link/* name resolved on an app seam")
	}

	// THE gate, on a service this harness wires a real backend for, so nothing but the
	// gate can be what refuses it: the same seam narrowed to `clock` alone answers no
	// fs name. A refusal at the GATE — an undeclared service, still a throw at the call
	// site (guest-seam.ts) — reaches the test as callRealm's error.
	if _, err := qc.Eval("narrow.js", qjs.Code(`__buildGuestSeam(["clock"], __id, null, __scope);`)); err != nil {
		t.Fatal("narrow seam:", err)
	}
	if err := refused(nameFsPut, make([]byte, 8)); err == nil {
		t.Fatal("fs/put resolved on a seam declaring no fs service")
	}
	if clk := callBytes(nameClockNow, nil); len(clk) != 8 {
		t.Fatalf("clock/now = %v on the narrowed seam, want the one service it declares", clk)
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
