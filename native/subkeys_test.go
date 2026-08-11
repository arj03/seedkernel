package main

import "testing"

// The native node's identity IS the key derived from the master seed (§12.6.2b): bootNode
// derives it from the one 32-byte seed in the shared code (deriveNodeKeys,
// core/subkeys.ts) — the exact derivation the JS CLI runs — so the peer id it reports must
// be that key's public half. This pins the native target to the shared derivation rather
// than a raw keypair of its own, and to ONE identity: the same key answers node/identity,
// signs guest records and signs the handshake, so a record authored here names an author
// every peer in the cohort already knows.
func TestBootNodeDerivesIdentity(t *testing.T) {
	bootRealm(t)
	seedHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	st, err := startNode(nodeConfig{KeyHex: seedHex, ContactSecretHex: testContactSecretHex, RequestDeadline: 2000})
	if err != nil {
		t.Fatal("bootNode:", err)
	}
	derive := `deriveNodeKeys(sodium, fromHex("` + seedHex + `"))`
	channel := evalString(t, `toHex(`+derive+`.channel.publicKey)`)
	if st.PeerID != channel {
		t.Fatalf("peer id = %s, want the derived key %s", st.PeerID, channel)
	}
}

// The --key file format (a 32-byte master seed as 64 hex characters), the mint-on-absent
// behaviour, and the loud refusal of a corrupt or wrong-length file are the shared CLI's
// now (host/cli.ts `loadNodeKeys`/`parseHex32`), so they are covered once in the JS suite
// (WASM/tests/cli.test.mjs) rather than again here against a Go copy of the same rules.
