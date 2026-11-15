package main

import "testing"

// The native node's identity is the key the shared code derives from the master seed
// (deriveNodeKey, host/subkeys.ts, §12.6.2b), computed with this target's crypto, whose
// SHA-256 is native Go. The expected peer id is the JS target's answer for the same seed,
// so a native derivation that differed would give the node a different identity.
func TestNodeDerivesSharedIdentity(t *testing.T) {
	bootRealm(t)
	seedHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	st, err := startNode(nodeConfig{KeyHex: seedHex, ContactSecretHex: testContactSecretHex})
	if err != nil {
		t.Fatal("startNode:", err)
	}
	// deriveNodeKey on the Node target for the seed above.
	const want = "c5536ae5e33f89e175c07b178fe48604bed6effcd4d881e4e6c71effcc4798ff"
	if st.PeerID != want {
		t.Fatalf("peer id = %s, want the shared derivation %s", st.PeerID, want)
	}
}

// The --key file format (a 32-byte master seed as 64 hex characters), creating it when
// absent, and refusing a corrupt or wrong-length file are handled by the shared CLI
// (host/cli.ts `loadNodeKeys`/`parseHex32`) and tested in WASM/tests/cli.test.mjs.
