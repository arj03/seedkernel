package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/tetratelabs/wazero"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// newSodium stands up an isolated libsodium instance (its own runtime) so the
// crypto FFI can be exercised without the full shell boot.
func newSodium(t *testing.T) *libsodium {
	t.Helper()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	t.Cleanup(func() { rt.Close(ctx) })
	return bootSodium(rt)
}

// SHA3-256 must be FIPS-202 (so a Go node's names/hashes match a Bun node's) — the
// known-answer for "" guards against a legacy-Keccak padding build, and the
// per-input cross-check pins it to an independent oracle (golang.org/x/crypto/sha3).
// This is the only crypto the build keeps outside libsodium — and only in tests, as
// an oracle; the shipped binary's hashing (incl. name()) goes through libsodium.
func TestSodiumSha3256(t *testing.T) {
	s := newSodium(t)
	for _, msg := range [][]byte{nil, []byte("abc"), bytes.Repeat([]byte{0x5a}, 1000)} {
		got, want := s.hashSha3256(msg), sha3.Sum256(msg)
		if !bytes.Equal(got, want[:]) {
			t.Fatalf("sha3256(%q): got %x want %x", msg, got, want)
		}
	}
	const wantEmpty = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
	if g := hex.EncodeToString(s.hashSha3256(nil)); g != wantEmpty {
		t.Fatalf("sha3256(\"\") = %s, want %s (Keccak vs FIPS-202?)", g, wantEmpty)
	}
}

// genericHash (no key, 32-byte out) is plain BLAKE2b-256, and runs on native Go rather
// than libsodium (sodium.go header). Since it's the content-address block-id hash, a Go
// node and a Bun node MUST agree on it — so beyond the x/crypto cross-check, pin it to
// known-answer vectors captured from the libsodium.wasm this build embeds. If native Go
// ever diverged from that exact binary, these fail rather than silently forking storage.
func TestSodiumGenericHash(t *testing.T) {
	s := newSodium(t)
	for _, msg := range [][]byte{nil, []byte("hello"), bytes.Repeat([]byte{1}, 333)} {
		got, want := s.genericHash(32, msg), blake2b.Sum256(msg)
		if !bytes.Equal(got, want[:]) {
			t.Fatalf("generichash(%q): got %x want %x", msg, got, want)
		}
	}
	// KAT: libsodium crypto_generichash(32, msg) for "" and "abc" (also the standard
	// BLAKE2b-256 vectors). Locks native Go to the embedded binary's output.
	for _, kat := range []struct{ msg, hex string }{
		{"", "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
		{"abc", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
	} {
		if g := hex.EncodeToString(s.genericHash(32, []byte(kat.msg))); g != kat.hex {
			t.Fatalf("blake2b256(%q) = %s, want %s (native vs libsodium drift?)", kat.msg, g, kat.hex)
		}
	}
}

// The ChaCha20-Poly1305-IETF record layer (§13.6) runs on native Go, not libsodium
// (sodium.go header). Every node's frames must open on every peer's link, so native
// ciphertext MUST be byte-identical to libsodium's. RFC 8439 is byte-exact, so it is —
// pinned three ways: a round-trip + tamper/wrong-key check of the no-AAD wrapper, KATs
// captured from the libsodium.wasm this build embeds (native/binary drift fails here
// rather than silently forking the wire), and the independent RFC 8439 §2.8.2 vector
// (with AAD, exercising the primitive against the published standard).
func TestSodiumAead(t *testing.T) {
	s := newSodium(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	npub := bytes.Repeat([]byte{0x24}, 12)

	// The wrapper is its own inverse; any bit flip in the tag, or a wrong key, fails
	// the open (ok=false) rather than returning garbage.
	for _, msg := range [][]byte{nil, []byte("abc"), bytes.Repeat([]byte{0x5a}, 4096)} {
		ct := s.aeadEncrypt(msg, npub, key)
		if len(ct) != len(msg)+16 {
			t.Fatalf("seal length = %d, want %d", len(ct), len(msg)+16)
		}
		pt, ok := s.aeadDecrypt(ct, npub, key)
		if !ok || !bytes.Equal(pt, msg) {
			t.Fatalf("aead round trip: ok=%v pt=%x want %x", ok, pt, msg)
		}
		bad := append([]byte(nil), ct...)
		bad[len(bad)-1] ^= 1 // flip a tag bit
		if _, ok := s.aeadDecrypt(bad, npub, key); ok {
			t.Fatal("aead opened a tampered tag")
		}
		if _, ok := s.aeadDecrypt(ct, npub, bytes.Repeat([]byte{0x43}, 32)); ok {
			t.Fatal("aead opened under the wrong key")
		}
	}

	// KAT: crypto_aead_chacha20poly1305_ietf_encrypt(msg, npub=0x24×12, key=0x42×32),
	// no AAD, captured from the embedded libsodium.wasm. Locks native Go to that exact
	// binary — divergence fails here instead of forking the wire.
	for _, kat := range []struct{ msg, hex string }{
		{"", "3f51eace5bd1df2f4656bf812c77a1df"},
		{"abc", "8565e611f66e1a31314e67413c37a2b2ef7474"},
		{"the quick brown fox", "906fe02e9aab31cbee4beaf98b6073b899a63132dc8f227697aa57eb0d9c797f19636c"},
	} {
		if g := hex.EncodeToString(s.aeadEncrypt([]byte(kat.msg), npub, key)); g != kat.hex {
			t.Fatalf("aead(%q) = %s, want %s (native vs libsodium drift?)", kat.msg, g, kat.hex)
		}
	}

	// Independent standard vector: RFC 8439 §2.8.2 (with AAD). The wrapper uses no AAD,
	// so this drives the primitive directly — proves it's RFC-correct, not merely
	// self-consistent with the libsodium build.
	rfcKey, _ := hex.DecodeString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	rfcNonce, _ := hex.DecodeString("070000004041424344454647")
	rfcAad, _ := hex.DecodeString("50515253c0c1c2c3c4c5c6c7")
	rfcPlain := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	const rfcWant = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
	aead, err := chacha20poly1305.New(rfcKey)
	if err != nil {
		t.Fatal(err)
	}
	if g := hex.EncodeToString(aead.Seal(nil, rfcNonce, rfcPlain, rfcAad)); g != rfcWant {
		t.Fatalf("RFC 8439 §2.8.2 vector: got %s want %s", g, rfcWant)
	}
}

// Ed25519 sign/verify, plus byte-for-byte parity with crypto/ed25519 (libsodium and
// Go must derive the same keypair from a seed and accept each other's signatures).
func TestSodiumSign(t *testing.T) {
	s := newSodium(t)
	seed := bytes.Repeat([]byte{7}, 32)
	pk, sk := s.signSeedKeypair(seed)
	goPriv := ed25519.NewKeyFromSeed(seed)
	goPub := goPriv.Public().(ed25519.PublicKey)
	if !bytes.Equal(pk, goPub) {
		t.Fatalf("seed_keypair pk: %x vs %x", pk, goPub)
	}
	if !bytes.Equal(sk, goPriv) { // both 64B = seed‖pubkey
		t.Fatalf("seed_keypair sk: %x vs %x", sk, []byte(goPriv))
	}

	msg := []byte("sign me")
	sig := s.signDetached(msg, sk)
	if !ed25519.Verify(goPub, msg, sig) {
		t.Fatal("Go rejected a libsodium signature")
	}
	if !s.verifyDetached(sig, msg, pk) {
		t.Fatal("libsodium rejected its own signature")
	}
	if !s.verifyDetached(ed25519.Sign(goPriv, msg), msg, pk) {
		t.Fatal("libsodium rejected a Go signature")
	}
	if s.verifyDetached(sig, []byte("tampered"), pk) {
		t.Fatal("verify accepted a tampered message")
	}
}

// xchacha20 keystream XOR is its own inverse.
func TestSodiumStreamXor(t *testing.T) {
	s := newSodium(t)
	key, nonce := bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x24}, 24)
	msg := []byte("the quick brown fox jumps over the lazy dog")
	ct := s.streamXor(msg, nonce, key)
	if bytes.Equal(ct, msg) {
		t.Fatal("xchacha20 left the plaintext unchanged")
	}
	if pt := s.streamXor(ct, nonce, key); !bytes.Equal(pt, msg) {
		t.Fatalf("xchacha20 round trip: %q", pt)
	}
}

// Random keypair → ed25519→curve25519 → sealed-box round trip. This is the path
// that exercises the wasm RNG (crypto_sign_keypair and crypto_box_seal both draw
// from randombytes, routed through the asm-const entropy import).
func TestSodiumSealedBox(t *testing.T) {
	s := newSodium(t)
	pk, sk := s.signKeypair()
	if len(pk) != 32 || len(sk) != 64 {
		t.Fatalf("keypair sizes: pk=%d sk=%d", len(pk), len(sk))
	}
	cpk, csk := s.edPkToCurve(pk), s.edSkToCurve(sk)

	msg := []byte("a sealed secret for the holder")
	ct := s.boxSeal(msg, cpk)
	if len(ct) != len(msg)+sealBytes {
		t.Fatalf("seal length = %d, want %d", len(ct), len(msg)+sealBytes)
	}
	if bytes.Contains(ct, msg) {
		t.Fatal("ciphertext leaks plaintext")
	}
	pt, ok := s.boxSealOpen(ct, cpk, csk)
	if !ok || !bytes.Equal(pt, msg) {
		t.Fatalf("seal_open: ok=%v pt=%q", ok, pt)
	}
	pk2, sk2 := s.signKeypair()
	if _, ok := s.boxSealOpen(ct, s.edPkToCurve(pk2), s.edSkToCurve(sk2)); ok {
		t.Fatal("seal_open succeeded under the wrong keypair")
	}
}
