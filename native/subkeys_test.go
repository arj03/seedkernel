package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The native node's identity IS the master seed's CHANNEL subkey (§12.6.2b): bootNode
// derives both purpose-bound keypairs from the one 32-byte seed in the shared code
// (deriveNodeKeys, core/subkeys.ts) — the exact derivation the JS CLI runs — so the
// peer id it reports must be the channel subkey's public half, and the channel and
// guest halves must differ, which is the whole point of separate keys. This pins the
// native target to the same subkey practice rather than one raw keypair signing for
// both roles.
func TestBootNodeDerivesSubkeys(t *testing.T) {
	bootRealm(t)
	seedHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	st, err := startNode(nodeConfig{KeyHex: seedHex, ContactSecretHex: testContactSecretHex, RequestDeadline: 2000})
	if err != nil {
		t.Fatal("bootNode:", err)
	}
	derive := `deriveNodeKeys(sodium, fromHex("` + seedHex + `"))`
	channel := evalString(t, `toHex(`+derive+`.channel.publicKey)`)
	if st.PeerID != channel {
		t.Fatalf("peer id = %s, want the channel subkey %s", st.PeerID, channel)
	}
	if guest := evalString(t, `toHex(`+derive+`.guest.publicKey)`); guest == channel {
		t.Fatal("channel and guest subkeys are the same key — purpose separation lost")
	}
}

// The --key file holds the node's 32-byte master seed (64 hex chars) — the format the
// JS shell writes and the one input to deriveNodeKeys — not the 64-byte ed25519 secret
// key the native target used to store. Absent ⇒ minted from crypto/rand and persisted;
// present ⇒ read back verbatim; anything else is refused loudly.
func TestLoadOrMintKeyFormat(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "node.key")

	// Absent → mint a 32-byte seed and persist it.
	skHex, err := loadOrMintKey(keyPath)
	if err != nil {
		t.Fatal("mint:", err)
	}
	b, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != skHex {
		t.Fatalf("minted key not persisted: file %q vs %q", b, skHex)
	}
	if len(skHex) != 64 {
		t.Fatalf("minted seed = %d hex chars, want 64 (32 bytes)", len(skHex))
	}
	if _, err := hex.DecodeString(skHex); err != nil {
		t.Fatalf("minted seed is not hex: %v", err)
	}

	// Present → read back verbatim.
	got, err := loadOrMintKey(keyPath)
	if err != nil {
		t.Fatal("re-read:", err)
	}
	if got != skHex {
		t.Fatalf("re-read = %q, want %q", got, skHex)
	}

	// A 128-char file — the old 64-byte secret-key format — is refused loudly.
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("ab", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrMintKey(keyPath); err == nil {
		t.Fatal("a 64-byte secret-key file was accepted — the format is now a 32-byte master seed")
	}

	// Non-hex 64-char content is refused loudly: the shared fromHex maps non-hex pairs
	// to 0, so a corrupt file must not silently boot the node under a different identity.
	if err := os.WriteFile(keyPath, []byte("zzzz"+strings.Repeat("0", 60)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrMintKey(keyPath); err == nil {
		t.Fatal("non-hex seed accepted")
	}
}
