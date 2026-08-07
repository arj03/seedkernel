package main

// The native half of "one implementation, three targets" for the catalog's KEM
// (§12.9, §14.1) — the sibling of mldsa_test.go, and the same argument: the JS suite
// checks mlkem768.wasm from Node, and without this the target that embeds its own
// copy of the artifact would be the one nobody checked.
//
// It reads the fixture the JS suite reads rather than keeping a second copy. The
// whole value of the test is that both targets are judged by the same vectors, so a
// local copy could quietly drift into agreeing only with itself.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"seedloader/qjs"
)

// mlkemKat is the ML-KEM-768 ACVP fixture. Each group carries only the fields it
// needs; the JSON decoder leaves the rest zero.
type mlkemKat struct {
	KeyGen []struct {
		TcID int    `json:"tcId"`
		D string `json:"d"`
		Z string `json:"z"`
		Ek string `json:"ek"`
		Dk string `json:"dk"`
	} `json:"keyGen"`
	Encaps []struct {
		TcID int    `json:"tcId"`
		Ek string `json:"ek"`
		M string `json:"m"`
		C string `json:"c"`
		K string `json:"k"`
	} `json:"encaps"`
	Decaps []struct {
		TcID int    `json:"tcId"`
		Dk string `json:"dk"`
		C string `json:"c"`
		K string `json:"k"`
		Reason string `json:"reason"`
	} `json:"decaps"`
	EncapsKeyCheck []struct {
		TcID int    `json:"tcId"`
		Ek string `json:"ek"`
		Pass bool   `json:"pass"`
		Reason string `json:"reason"`
	} `json:"encapsKeyCheck"`
	DecapsKeyCheck []struct {
		TcID int    `json:"tcId"`
		Dk string `json:"dk"`
		Pass bool   `json:"pass"`
		Reason string `json:"reason"`
	} `json:"decapsKeyCheck"`
}

func TestMlKemAcvpVectors(t *testing.T) {
	bootRealm(t)
	raw, err := os.ReadFile("../WASM/tests/fixtures/mlkem768-acvp.json")
	if err != nil {
		t.Fatal("ACVP fixture:", err)
	}
	var kat mlkemKat
	if err := json.Unmarshal(raw, &kat); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	n := 0
	for _, v := range kat.KeyGen {
		pk, sk := mk.keypairFromSeed(append(unhex(v.D), unhex(v.Z)...))
		if hex.EncodeToString(pk) != v.Ek || hex.EncodeToString(sk) != v.Dk {
			t.Fatalf("ACVP keyGen tc%d: key set is not byte-exact", v.TcID)
		}
		n++
	}
	for _, v := range kat.Encaps {
		ct, ss, ok := mk.encapsulate(unhex(v.Ek), unhex(v.M))
		if !ok {
			t.Fatalf("ACVP encaps tc%d: the vector's key was refused", v.TcID)
		}
		if hex.EncodeToString(ct) != v.C || hex.EncodeToString(ss) != v.K {
			t.Fatalf("ACVP encaps tc%d: ciphertext or shared secret is not byte-exact", v.TcID)
		}
		n++
	}
	// Both the valid and the MODIFIED-ciphertext cases run here and both must match:
	// a modified ciphertext is implicit rejection, which has one right answer rather
	// than an error. Reporting it apart from success would be the oracle implicit
	// rejection exists to deny.
	for _, v := range kat.Decaps {
		ss, ok := mk.decapsulate(unhex(v.Dk), unhex(v.C))
		if !ok {
			t.Fatalf("ACVP decaps tc%d: the vector's key was refused", v.TcID)
		}
		if hex.EncodeToString(ss) != v.K {
			t.Fatalf("ACVP decaps tc%d (%s): shared secret is not byte-exact", v.TcID, v.Reason)
		}
		n++
	}
	// The two key checks are the edges where two implementations of a lattice scheme
	// disagree while both pass their own round trips: FIPS 203 §7.2's modulus check on
	// an encapsulation key, §7.3's hash check on a decapsulation key.
	for _, v := range kat.EncapsKeyCheck {
		if _, _, ok := mk.encapsulate(unhex(v.Ek), make([]byte, mlkemCoinsBytes)); ok != v.Pass {
			t.Fatalf("ACVP encapsulationKeyCheck tc%d (%s): got %v, want %v", v.TcID, v.Reason, ok, v.Pass)
		}
		n++
	}
	for _, v := range kat.DecapsKeyCheck {
		if _, ok := mk.decapsulate(unhex(v.Dk), make([]byte, mlkemCtBytes)); ok != v.Pass {
			t.Fatalf("ACVP decapsulationKeyCheck tc%d (%s): got %v, want %v", v.TcID, v.Reason, ok, v.Pass)
		}
		n++
	}

	// Wrong-width arguments are the same rejection as a malformed key, never a panic:
	// the cap-bridge turns them into a leading zero byte, and there is no second
	// channel for a structural failure to come back through.
	if _, _, ok := mk.encapsulate(make([]byte, 10), make([]byte, mlkemCoinsBytes)); ok {
		t.Fatal("a wrong-width encapsulation key must be refused")
	}
	if _, ok := mk.decapsulate(make([]byte, 10), make([]byte, mlkemCtBytes)); ok {
		t.Fatal("a wrong-width decapsulation key must be refused")
	}
	t.Logf("%d NIST vectors", n)
}

// TestMlKemThroughCatalog drives the KEM the way a guest does — by name, through the
// `crypto/` prefix — rather than through the Go wrapper. That is the path that has
// to work end to end on this target: the `crypto/*` entries of `HOST_CALL_NAMES` are
// what a manifest's `guest.requires` is checked against in `verifyManifest` (bundle.ts),
// so a host whose `__sodium` lacked these methods would admit a bundle by name and then
// fail it at first use — the legibility failure the check exists to prevent.
//
// It also pins the thing the Go wrapper alone cannot: that the shared cap-bridge, the
// sodium shim's ArrayBuffer→Uint8Array wrapping and the null-is-a-rejection contract
// line up. A bundle declaring NO requires runs it, because a pure transform is
// not a capability.
func TestMlKemThroughCatalog(t *testing.T) {
	capBridgeRealm(t)

	if _, err := qc.Eval("build.js", qjs.Code(`
		globalThis.__id = sodium.crypto_sign_keypair();
		__buildCapBridge([], __id, null, [], appSignScope(__id, __id.publicKey, "testapp"));
	`)); err != nil {
		t.Fatal("build bridge:", err)
	}
	prim := func(name string, args []byte) []byte {
		t.Helper()
		fn := qc.Global().GetPropertyStr("__callBridge")
		v, err := qc.Invoke(fn, qc.NewUndefined(), qc.NewString("crypto/"+name), qc.NewArrayBuffer(args))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, err := qjs.JsTypedArrayToGo(v)
		if err != nil {
			t.Fatalf("%s result: %v", name, err)
		}
		return b
	}

	seed := bytes.Repeat([]byte{5}, mlkemSeedBytes)
	kp := prim("ml-kem-768/keypair", seed)
	if len(kp) != mlkemPkBytes+mlkemSkBytes {
		t.Fatalf("keypair returned %d bytes, want [pk %d][sk %d]", len(kp), mlkemPkBytes, mlkemSkBytes)
	}
	pk, sk := kp[:mlkemPkBytes], kp[mlkemPkBytes:]

	coins := bytes.Repeat([]byte{9}, mlkemCoinsBytes)
	enc := prim("ml-kem-768/encaps", append(append([]byte{}, pk...), coins...))
	if len(enc) != 1+mlkemCtBytes+mlkemSsBytes || enc[0] != 1 {
		t.Fatalf("encaps returned %d bytes starting %v, want [1][ct][ss]", len(enc), enc[0])
	}
	ct, ss := enc[1:1+mlkemCtBytes], enc[1+mlkemCtBytes:]

	dec := prim("ml-kem-768/decaps", append(append([]byte{}, sk...), ct...))
	if len(dec) != 1+mlkemSsBytes || dec[0] != 1 || !bytes.Equal(dec[1:], ss) {
		t.Fatal("the two ends did not derive the same shared secret through the catalog")
	}

	// The whole point of taking coins as an argument: the entry is a pure function,
	// so it grants nothing and needs no capability to reach.
	if again := prim("ml-kem-768/encaps", append(append([]byte{}, pk...), coins...)); !bytes.Equal(again, enc) {
		t.Fatal("encaps is not a pure function of (key, coins)")
	}

	// A malformed peer key is an answer, not an exception. 12-bit little-endian
	// packing: 0xff,0xff decodes to 4095, outside [0, q-1].
	badPk := append([]byte{}, pk...)
	badPk[0], badPk[1] = 0xff, 0xff
	if bad := prim("ml-kem-768/encaps", append(badPk, coins...)); len(bad) != 1 || bad[0] != 0 {
		t.Fatalf("a key failing the modulus check returned %d bytes, want [0]", len(bad))
	}
}
