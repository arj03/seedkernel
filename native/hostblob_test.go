package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// hostEnvelope independently frames and signs a host blob (WASM/host/host-blob.ts) under
// DOMAIN_host as the realm spells it, so a disagreement with either reader shows up.
func hostEnvelope(t testing.TB, a authorKeys, version, abi int, h *hostBlob) []byte {
	t.Helper()
	manifest, err := json.Marshal(map[string]int{"version": version, "abi": abi})
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	for _, part := range [][]byte{manifest, []byte(h.script), h.qjs, h.sodium, h.mldsa} {
		body = binary.BigEndian.AppendUint32(body, uint32(len(part)))
		body = append(body, part...)
	}
	pre := append(hexBytes(realmString(`toHex(DOMAIN_HOST)`)), manifestSuite())
	pre = append(append(append(pre, a.edPub...), a.mlPk...), genericHash(32, body, nil)...)
	env := append([]byte{manifestSuite()}, a.edPub...)
	env = append(append(env, a.mlPk...), ed25519.Sign(a.edPriv, pre)...)
	return append(append(env, testSigner(t).signDetached(t, pre, a.mlSk)...), body...)
}

// The binary boots the blob it was built with, signed under the prefix the host script
// names, by the author of its own record.
func TestGenesisHostVerifies(t *testing.T) {
	bootRealm(t)
	if got := realmString(`toHex(DOMAIN_HOST)`); got != hex.EncodeToString(domainHost) {
		t.Fatalf("DOMAIN_HOST is %s in the host script and %x here", got, domainHost)
	}
	h, err := verifyHostBlob(genesisHost)
	if err != nil {
		t.Fatal("genesis:", err)
	}
	if h.abi != platformABI || h.version < 1 || len(h.author) != 32 {
		t.Fatalf("genesis manifest: abi %d, version %d, author %x", h.abi, h.version, h.author)
	}
	if !reflect.DeepEqual(h.author, host.author) {
		t.Fatal("the running host is not the genesis blob")
	}
}

// Any change to a signed byte refuses the blob, and an app bundle is not a host blob: the
// two are signed under different prefixes, so neither passes as the other.
func TestHostBlobRefusesWhatIsNotItsAuthorsHost(t *testing.T) {
	bootRealm(t)
	tampered := append([]byte(nil), genesisHost...)
	tampered[len(tampered)-1] ^= 1
	if _, err := verifyHostBlob(tampered); !errors.Is(err, errHostSignature) {
		t.Fatalf("a tampered body: %v", err)
	}
	tampered = append([]byte(nil), genesisHost...)
	tampered[offEdSig] ^= 1
	if _, err := verifyHostBlob(tampered); !errors.Is(err, errHostSignature) {
		t.Fatalf("a tampered signature: %v", err)
	}
	tampered[0] = 0x01
	if _, err := verifyHostBlob(tampered); err == nil || !strings.Contains(err.Error(), "unsupported manifest suite 0x01") {
		t.Fatalf("another suite: %v", err)
	}
	app := bundleEnvelope(t, testAuthor(t), manifestJSON(t, "probe", 1, stubGuestSrc, nil), stubGuestSrc, forwarderWasm)
	if _, err := verifyHostBlob(app); !errors.Is(err, errHostSignature) {
		t.Fatalf("an app bundle read as a host: %v", err)
	}
	if _, err := startNode(nodeConfig{KeyHex: testKeyHex(t)}); err != nil {
		t.Fatal("startNode:", err)
	}
	path := filepath.Join(t.TempDir(), "host.skb")
	if err := os.WriteFile(path, genesisHost, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := callRealm("cliLoadBundle", 5*time.Second, qc.NewString(path)); err == nil ||
		!strings.Contains(err.Error(), "bundle: signature invalid") {
		t.Fatalf("a host blob installed as an app: %v", err)
	}
}

// A blob for another platform ABI is refused before any of it runs.
func TestBootRefusesAnotherABI(t *testing.T) {
	bootRealm(t)
	other := hostEnvelope(t, testAuthor(t), 2, platformABI+1, host)
	defer func() {
		bootBlob = genesisHost
		bootRealm(t)
	}()
	bootBlob = other
	err := boot()
	if err == nil || !strings.Contains(err.Error(), "platform ABI") {
		t.Fatalf("boot of an ABI %d blob: %v", platformABI+1, err)
	}
}

// --host and --host-updates are the loader's: they come out of what the host sees, in
// either spelling.
func TestLoaderFlags(t *testing.T) {
	for _, tc := range []struct {
		argv     []string
		rest     []string
		hostFile string
		updates  string
	}{
		{[]string{"--dir", "d"}, []string{"--dir", "d"}, "", "off"},
		{[]string{"--host", "h.skb", "--dir", "d"}, []string{"--dir", "d"}, "h.skb", "off"},
		{[]string{"--dir=d", "--host=h.skb", "--host-updates", "now"}, []string{"--dir=d"}, "h.skb", "now"},
		{[]string{"--host-updates=next", "--hostile", "x"}, []string{"--hostile", "x"}, "", "next"},
		{nil, []string{}, "", "off"},
	} {
		o, err := loaderFlags(tc.argv)
		if err != nil || !reflect.DeepEqual(o.rest, tc.rest) || o.hostFile != tc.hostFile || o.updates != tc.updates {
			t.Fatalf("loaderFlags(%q) = %+v, %v", tc.argv, o, err)
		}
	}
	if _, err := loaderFlags([]string{"--host"}); err == nil {
		t.Fatal("--host with no value was accepted")
	}
	if dataDirOf([]string{"--policy", "p", "--dir=x/"}) != "x/" || dataDirOf(nil) != "./data" {
		t.Fatal("dataDirOf")
	}
}
