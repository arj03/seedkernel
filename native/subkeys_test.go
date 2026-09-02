package main

import "testing"

// The native node's identity IS the key the shared code derives from the master seed
// (deriveNodeKey, core/subkeys.ts, §12.6.2b), so the peer id it reports must be that
// key's public half. Pins this target to the shared derivation rather than a raw keypair
// of its own, and to ONE identity: the same key answers node/identity, signs guest records
// and signs the handshake.
func TestBootNodeDerivesIdentity(t *testing.T) {
	bootRealm(t)
	seedHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	st, err := startNode(nodeConfig{KeyHex: seedHex, ContactSecretHex: testContactSecretHex})
	if err != nil {
		t.Fatal("bootNode:", err)
	}
	derive := `deriveNodeKey(sodium, fromHex("` + seedHex + `"))`
	channel := evalString(t, `toHex(`+derive+`.publicKey)`)
	if st.PeerID != channel {
		t.Fatalf("peer id = %s, want the derived key %s", st.PeerID, channel)
	}
}

// The --key file format (a 32-byte master seed as 64 hex characters), the mint-on-absent
// behaviour, and the loud refusal of a corrupt or wrong-length file are the shared CLI's
// now (host/cli.ts `loadNodeKeys`/`parseHex32`), so they are covered once in the JS suite
// (WASM/tests/cli.test.mjs) rather than again here against a Go copy of the same rules.
