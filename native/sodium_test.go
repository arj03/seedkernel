package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/tetratelabs/wazero"
	"golang.org/x/crypto/blake2b"
)

// newSodium creates an isolated libsodium instance (its own runtime) so the crypto FFI
// can be tested without the full shell boot.
func newSodium(t *testing.T) *libsodium {
	t.Helper()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	t.Cleanup(func() { rt.Close(ctx) })
	return bootSodium(rt)
}

// genericHash runs on native Go instead of libsodium (sodium.go header) and is the system
// hash, so a Go node and a Node node must agree on it. Besides the x/crypto cross-check it
// is checked against vectors captured from the libsodium.wasm this build embeds, so a
// difference fails here instead of silently splitting storage.
func TestSodiumGenericHash(t *testing.T) {
	for _, msg := range [][]byte{nil, []byte("hello"), bytes.Repeat([]byte{1}, 333)} {
		got, want := genericHash(32, msg, nil), blake2b.Sum256(msg)
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
		if g := hex.EncodeToString(genericHash(32, []byte(kat.msg), nil)); g != kat.hex {
			t.Fatalf("blake2b256(%q) = %s, want %s (native vs libsodium drift?)", kat.msg, g, kat.hex)
		}
	}
}

// The host's ChaCha20-Poly1305-IETF (§12.6) runs on libsodium.wasm through the engine
// table (host/sodium-engine.ts), and every node's frames must open on every peer's link.
// Checked against KATs captured from that libsodium and the independent RFC 8439 §2.8.2
// vector, with a round trip that a flipped tag bit fails.
func TestHostSodiumAead(t *testing.T) {
	bootRealm(t)
	got := evalString(t, `(() => {
	  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
	  const unhex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
	  const key = new Uint8Array(32).fill(0x42), npub = new Uint8Array(12).fill(0x24);
	  const seal = (m, ad, n, k) => sodium.crypto_aead_chacha20poly1305_ietf_encrypt(m, ad, null, n, k);
	  const out = ["", "abc", "the quick brown fox"].map((m) => hex(seal(new TextEncoder().encode(m), null, npub, key)));
	  const rfc = seal(new TextEncoder().encode("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
	    unhex("50515253c0c1c2c3c4c5c6c7"), unhex("070000004041424344454647"),
	    unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));
	  out.push(hex(rfc));
	  const ct = seal(new Uint8Array(4096).fill(0x5a), null, npub, key);
	  const pt = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ct, null, npub, key);
	  ct[ct.length - 1] ^= 1;
	  let tampered = "opened";
	  try { sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ct, null, npub, key); } catch { tampered = "refused"; }
	  out.push(String(pt.length === 4096 && pt.every((x) => x === 0x5a)), tampered);
	  return out.join(",");
	})()`)
	want := "3f51eace5bd1df2f4656bf812c77a1df,8565e611f66e1a31314e67413c37a2b2ef7474," +
		"906fe02e9aab31cbee4beaf98b6073b899a63132dc8f227697aa57eb0d9c797f19636c," +
		"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691," +
		"true,refused"
	if got != want {
		t.Fatalf("host AEAD = %s\nwant %s", got, want)
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
