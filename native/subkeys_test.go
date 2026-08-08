package main

import "testing"

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

// The --key file format (a 32-byte master seed as 64 hex characters), the mint-on-absent
// behaviour, and the loud refusal of a corrupt or wrong-length file are the shared CLI's
// now (host/cli.ts `loadNodeKeys`/`parseHex32`), so they are covered once in the JS suite
// (WASM/tests/cli.test.mjs) rather than again here against a Go copy of the same rules.
