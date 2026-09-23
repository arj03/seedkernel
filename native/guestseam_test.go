package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"seedkernel/qjs"
)

// The shared guest-seam.ts runs in the host realm over the Go
// primitives (sodium + fs), reused verbatim. Each name is exercised through the
// single `__guestSeam(name, bytes)` seam and checked against the underlying
// primitive, plus the name gate (an undeclared authority is refused).

// The names of guest-seam.ts's catalog, written here so a rename shows up as
// one edit rather than as bare strings scattered through the assertions.
const (
	nameSign     = "node/sign"
	nameVerify   = "node/verify"
	nameRandom   = "crypto/random"
	nameFsGet    = "fs/get"
	nameFsPut    = "fs/put"
	nameLinkSend = "link/send"
)

func TestGuestSeamOps(t *testing.T) {
	guestSeamRealm(t)

	// Grant node/sign, node/verify, fs/put and fs/get (not link),
	// plus an identity from sodium. The signing scope binds node/sign and
	// node/verify to a bundle namespace (README §12.2) — a real node derives it from the
	// manifest's (author, app); here it is a throwaway pair.
	if _, err := qc.Eval("build.js", `
		globalThis.__id = sodium.crypto_sign_keypair();
		globalThis.__other = sodium.crypto_sign_keypair();
		// What node/sign signs under is a SLOT-derived scope — domain, scope bytes and
		// the key that signs, all three.
		globalThis.__scope = appSignScope(__id, "testapp");
		__buildGuestSeam(["node", "fs"], null, __scope);
	`); err != nil {
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

	// The node pubkey. Value.Bytes copies on read and leaves __id.publicKey intact
	// for the seam's own use, so it can be read directly.
	pk := jsBytes(t, qc, `__id.publicKey`)

	// A primitive is reached BY NAME through the `crypto/` prefix, so there is no op
	// number per algorithm and no ABI rev to add one.

	// crypto/blake2b — [outLen][keyLen][key][msg] — over RFC 7693's whole interface: the
	// system hash's 32 bytes, and the published 64-byte unkeyed and keyed answers.
	h := callBytes("crypto/blake2b", append([]byte{32, 0}, "hello seedkernel"...))
	want := jsBytes(t, qc, `sodium.crypto_generichash(32, new TextEncoder().encode("hello seedkernel"), null)`)
	if !bytes.Equal(h, want) {
		t.Fatalf("crypto/blake2b(32) = %x, want %x", h, want)
	}
	blake2bKat := func(arg []byte, wantHex string) {
		t.Helper()
		if got := hex.EncodeToString(callBytes("crypto/blake2b", arg)); got != wantHex {
			t.Fatalf("crypto/blake2b(%x) = %s, want %s", arg[:2], got, wantHex)
		}
	}
	// RFC 7693 Appendix A: BLAKE2b-512("abc").
	blake2bKat(append([]byte{64, 0}, "abc"...),
		"ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
	// BLAKE2's keyed KAT, first entry: key 00..3f, empty message.
	katKey := make([]byte, 64)
	for i := range katKey {
		katKey[i] = byte(i)
	}
	blake2bKat(append([]byte{64, 64}, katKey...),
		"10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568")
	for _, bad := range [][]byte{{}, {0, 0}, {65, 0}, {32, 65}, {32, 8, 1, 2}} {
		if err := refused("crypto/blake2b", bad); err == nil {
			t.Fatalf("crypto/blake2b(%x) answered, want a mis-framing error", bad)
		}
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
	// and the seam is one shape on every target (services/fs.ts).
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

	// Entropy is an ungated host transform: random bytes reach nothing.
	if r := callBytes(nameRandom, []byte{0, 0, 0, 4}); len(r) != 4 {
		t.Fatalf("crypto/random = %d bytes, want 4", len(r))
	}
	// And raw net is not merely undeclared here — it is wired only for the link occupant, so no app
	// seam is ever wired one.
	if err := refused(nameLinkSend, make([]byte, 8)); err == nil {
		t.Fatal("a link/* name resolved on an app seam")
	}

	// THE gate, on a service this harness wires a real backend for, so nothing but the
	// gate can be what refuses it: the same seam narrowed to `node` alone answers no
	// fs name. A refusal at the GATE — an undeclared service, still a throw at the call
	// site (guest-seam.ts) — reaches the test as callRealm's error.
	if _, err := qc.Eval("narrow.js", `__buildGuestSeam(["node"], null, __scope);`); err != nil {
		t.Fatal("narrow seam:", err)
	}
	if err := refused(nameFsPut, make([]byte, 8)); err == nil {
		t.Fatal("fs/put resolved on a seam declaring no fs service")
	}
	if sig := callBytes(nameSign, []byte{1}); len(sig) != 64 {
		t.Fatalf("node/sign = %d bytes on the narrowed seam, want the one service it declares", len(sig))
	}
	if r := callBytes(nameRandom, []byte{0, 0, 0, 4}); len(r) != 4 {
		t.Fatalf("crypto/random = %d bytes on the narrowed seam, want 4 — it is not a grant", len(r))
	}
}

// jsBytes evaluates a JS expression that yields a Uint8Array and returns its bytes.
func jsBytes(t *testing.T, qc *qjs.Context, expr string) []byte {
	t.Helper()
	v, err := qc.Eval("<jsBytes>", expr)
	if err != nil {
		t.Fatalf("eval %q: %v", expr, err)
	}
	b, err := v.Bytes()
	if err != nil {
		t.Fatalf("bytes of %q: %v", expr, err)
	}
	return b
}

// TestGuestSeamNoiseVectors replays the published Noise XX vectors through the Go
// primitives by way of the shared seam — the same script tests/realm-guest.test.mjs runs
// on the JS target. The crypto/ names must carry their algorithms' whole interface, or a
// replacement transport stops being a bundle update (services/domains.ts).
func TestGuestSeamNoiseVectors(t *testing.T) {
	guestSeamRealm(t)
	script, err := os.ReadFile("../WASM/tests/noise-vectors.js")
	if err != nil {
		t.Fatal(err)
	}
	vectors, err := os.ReadFile("../WASM/tests/fixtures/noise-xx-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qc.Eval("noise-vectors.js", string(script)); err != nil {
		t.Fatal("noise-vectors.js:", err)
	}
	// A seam granting nothing: every name the handshake needs is an ungated transform.
	if _, err := qc.Eval("build.js", `__buildGuestSeam([], null);`); err != nil {
		t.Fatal("build seam:", err)
	}
	qc.Global().SetPropertyStr("__noiseVectors", qc.NewString(string(vectors)))
	out, err := callRealm(`(async () => {
		const r = await runNoiseVectors(__callSeam, JSON.parse(__noiseVectors).vectors);
		return new TextEncoder().encode(JSON.stringify(r));
	})`, 30*time.Second)
	if err != nil {
		t.Fatal("run:", err)
	}
	var r struct {
		Ran      int      `json:"ran"`
		Failures []string `json:"failures"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("result %q: %v", out, err)
	}
	if r.Ran != 2 || len(r.Failures) != 0 {
		t.Fatalf("ran %d vector(s), failures: %v", r.Ran, r.Failures)
	}
}
