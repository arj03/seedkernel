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

// The shared guest-seam.ts runs in the host realm over the Go primitives (sodium and fs),
// unchanged. Each name is called through the single `__guestSeam(name, bytes)` seam and
// checked against the underlying primitive, plus the name gate (an undeclared service is
// refused).

// The guest-seam.ts names used below, defined once so a rename is one edit.
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

	// Declare `node` and `fs` (not link), plus an identity from sodium. The signing scope
	// ties node/sign and node/verify to an app namespace (§12.2); a real node derives it
	// from the manifest's `app` label, here it is a throwaway one.
	if _, err := qc.Eval("build.js", `
		globalThis.__id = sodium.crypto_sign_keypair();
		globalThis.__other = sodium.crypto_sign_keypair();
		// node/sign signs under a slot-derived scope: domain, scope bytes and the signing
		// key.
		globalThis.__scope = appSignScope(__id, "testapp");
		__buildGuestSeam(["node", "fs"], null, __scope);
	`); err != nil {
		t.Fatal("build seam:", err)
	}

	// Every seam name, crypto included, answers a Promise, so every probe goes through
	// callRealm, which pumps the loop until it settles. A gate refusal surfaces as
	// callRealm's error.
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

	// A primitive is reached by name under `crypto/`; there is no op number per algorithm.

	// crypto/sha256 and crypto/aes256gcm, the platform's own (here Go's): FIPS 180-4's
	// "abc", and the GCM specification's AES-256 test cases 13 and 14 (zero key and nonce).
	if got := hex.EncodeToString(callBytes("crypto/sha256", []byte("abc"))); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("crypto/sha256(abc) = %s", got)
	}
	gcm := func(name string, body []byte) []byte {
		t.Helper()
		// [npub 12][key 32][adLen u32], all zero, then the body.
		return callBytes(name, append(make([]byte, 12+32+4), body...))
	}
	if got := hex.EncodeToString(gcm("crypto/aes256gcm/seal", nil)); got != "530f8afbc74536b9a963b4f1c4cb738b" {
		t.Fatalf("crypto/aes256gcm/seal(empty) = %s", got)
	}
	ct := gcm("crypto/aes256gcm/seal", make([]byte, 16))
	if got := hex.EncodeToString(ct); got != "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919" {
		t.Fatalf("crypto/aes256gcm/seal(0^16) = %s", got)
	}
	if got := gcm("crypto/aes256gcm/open", ct); !bytes.Equal(got, append([]byte{1}, make([]byte, 16)...)) {
		t.Fatalf("crypto/aes256gcm/open = %x", got)
	}
	ct[0] ^= 1
	if got := gcm("crypto/aes256gcm/open", ct); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("crypto/aes256gcm/open of a flipped bit = %x, want [0]", got)
	}

	// node/sign and node/verify are scoped (§12.2): the host applies DOMAIN_guest ‖ scope
	// to the message on both sides, so the guest checks a signature by naming the key,
	// never by rebuilding the host's prefix bytes.
	msg := []byte("a message to sign")
	sig := callBytes(nameSign, msg)
	if len(sig) != 64 {
		t.Fatalf("node/sign len = %d, want 64", len(sig))
	}
	// node/verify, [pk 32][sig 64][msg]; the host adds the scope.
	verifyScoped := append(append(append([]byte{}, pk...), sig...), msg...)
	if v := callBytes(nameVerify, verifyScoped); len(v) != 1 || v[0] != 1 {
		t.Fatalf("node/verify(scoped msg) = %v, want [1]", v)
	}
	// The same signature must not verify under a different key: the caller names the key,
	// not the scope, so this checks this app's namespace, not just any key.
	otherPk := jsBytes(t, qc, `__other.publicKey`)
	verifyOther := append(append(append([]byte{}, otherPk...), sig...), msg...)
	if v := callBytes(nameVerify, verifyOther); len(v) != 1 || v[0] != 0 {
		t.Fatalf("node/verify(another key) = %v, want [0]", v)
	}
	// A mis-framed call is not a failed verification: a payload too short for
	// [pk 32][sig 64] errors, since [0] would be a verdict on bytes nothing checked. The
	// bound is exactly that prefix, so an empty message still gets an answer.
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

	// fs/put then fs/get round trip. Both are awaited: fs is async at the seam, since no
	// browser backend could implement a synchronous `get` and the seam is the same on
	// every target (services/fs.ts).
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

	// Entropy needs no declaration: random bytes reach nothing.
	if r := callBytes(nameRandom, []byte{0, 0, 0, 4}); len(r) != 4 {
		t.Fatalf("crypto/random = %d bytes, want 4", len(r))
	}
	// Raw links are not declared here, and `link` is only ever wired for the link
	// occupant.
	if err := refused(nameLinkSend, make([]byte, 8)); err == nil {
		t.Fatal("a link/* name resolved on an app seam")
	}

	// The gate itself, on a service this harness has a real backend for, so only the gate
	// can refuse it: the same seam narrowed to `node` answers no fs name. The refusal (a
	// throw at the call site, guest-seam.ts) reaches the test as callRealm's error.
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
// primitives via the shared seam, the same script tests/realm-guest.test.mjs runs on the
// JS target. The crypto/ names must expose their algorithms' whole interface, or a
// replacement transport could not ship as a bundle (host/domains.ts).
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
	// A seam declaring nothing: every name the handshake needs is a crypto transform.
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
