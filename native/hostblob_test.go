package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The parts of a host blob's body, in order (WASM/host/host-blob.ts).
const (
	partManifest = iota
	partScript
	partQjs
	partSodium
	partMldsa
)

// hostPart is one part of env's body, read independently of readHostBlob.
func hostPart(t testing.TB, env []byte, part int) []byte {
	t.Helper()
	body := env[offBody:]
	for i := 0; ; i++ {
		n := binary.BigEndian.Uint32(body)
		if i == part {
			return body[4 : 4+n]
		}
		body = body[4+n:]
	}
}

// hostEnvelope independently frames and signs a host blob (WASM/host/host-blob.ts) under
// DOMAIN_host as the realm spells it, with the genesis blob's engine and crypto and this
// script, so a disagreement with either reader shows up.
func hostEnvelope(t testing.TB, a authorKeys, version, abi int, script string) []byte {
	t.Helper()
	manifest, err := json.Marshal(map[string]int{"version": version, "abi": abi})
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	for _, part := range [][]byte{manifest, []byte(script), hostPart(t, genesisHost, partQjs),
		hostPart(t, genesisHost, partSodium), hostPart(t, genesisHost, partMldsa)} {
		body = binary.BigEndian.AppendUint32(body, uint32(len(part)))
		body = append(body, part...)
	}
	pre := append(hexBytes(realmString(`toHex(DOMAIN_HOST)`)), manifestSuite())
	pre = append(append(append(pre, a.edPub...), a.mlPk...), blake2b256(body)...)
	env := append([]byte{manifestSuite()}, a.edPub...)
	env = append(append(env, a.mlPk...), ed25519.Sign(a.edPriv, pre)...)
	return append(append(env, testSigner(t).signDetached(t, pre, a.mlSk)...), body...)
}

// The binary boots the blob it was built with, and reads the layout the realm writes.
func TestGenesisHostReads(t *testing.T) {
	bootRealm(t)
	h, err := readHostBlob(genesisHost)
	if err != nil {
		t.Fatal("genesis:", err)
	}
	if h.version < 1 || h.script == "" || len(h.qjs) == 0 {
		t.Fatalf("genesis: version %d, script %d B, qjs %d B", h.version, len(h.script), len(h.qjs))
	}
	if &host.env[0] != &genesisHost[0] {
		t.Fatal("the running host is not the genesis blob")
	}
	again, err := readHostBlob(hostEnvelope(t, testAuthor(t), 7, platformABI, h.script))
	if err != nil || again.version != 7 || again.script != h.script || !reflect.DeepEqual(again.qjs, h.qjs) {
		t.Fatalf("a blob framed here reads back as %+v, %v", again, err)
	}
}

// What is not a host blob is refused before any of it runs, and a host blob is not an
// app: the two are signed under different prefixes, so the host refuses one as the other.
func TestHostBlobRefusesWhatIsNotAHost(t *testing.T) {
	bootRealm(t)
	for _, tc := range []struct {
		what string
		env  []byte
		want string
	}{
		{"another suite", append([]byte{0x01}, genesisHost[1:]...), "not a suite 0x02 envelope"},
		{"a truncated body", genesisHost[:len(genesisHost)-1], "truncated body"},
		{"trailing bytes", append(append([]byte(nil), genesisHost...), 0), "trailing bytes"},
	} {
		if _, err := readHostBlob(tc.env); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.what, err)
		}
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
	other := hostEnvelope(t, testAuthor(t), 2, platformABI+1, host.script)
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
