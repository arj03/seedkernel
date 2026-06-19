package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/tetratelabs/wazero"
	"golang.org/x/crypto/blake2b"
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

// crypto_generichash (no key, 32-byte out) is plain BLAKE2b-256.
func TestSodiumGenericHash(t *testing.T) {
	s := newSodium(t)
	for _, msg := range [][]byte{nil, []byte("hello"), bytes.Repeat([]byte{1}, 333)} {
		got, want := s.genericHash(32, msg), blake2b.Sum256(msg)
		if !bytes.Equal(got, want[:]) {
			t.Fatalf("generichash(%q): got %x want %x", msg, got, want)
		}
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
