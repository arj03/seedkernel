package main

import "testing"

// The native node's identity is the key the shared code derives from the master seed
// (deriveNodeKey, core/subkeys.ts, §12.6.2b), computed over THIS target's crypto — whose
// BLAKE2b is native. The expected peer id is the JS target's answer for the same seed, so
// a native derivation that drifted would stand up a node every other target names
// differently.
func TestNodeDerivesSharedIdentity(t *testing.T) {
	bootRealm(t)
	seedHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	st, err := startNode(nodeConfig{KeyHex: seedHex, ContactSecretHex: testContactSecretHex})
	if err != nil {
		t.Fatal("startNode:", err)
	}
	// deriveNodeKey over libsodium-wrappers (the Node target) for the seed above.
	const want = "7167b875c908982c267a60468df52921a01a13c184f5b98368c0f5bdd1587b03"
	if st.PeerID != want {
		t.Fatalf("peer id = %s, want the shared derivation %s", st.PeerID, want)
	}
}

// The --key file format (a 32-byte master seed as 64 hex characters), the mint-on-absent
// behaviour, and the loud refusal of a corrupt or wrong-length file are the shared CLI's
// now (host/cli.ts `loadNodeKeys`/`parseHex32`), so they are covered once in the JS suite
// (WASM/tests/cli.test.mjs) rather than again here against a Go copy of the same rules.
