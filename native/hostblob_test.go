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

// The binary boots the blob it was built with, and finds the parts of a blob framed here
// as the realm frames them.
func TestGenesisHostReads(t *testing.T) {
	bootRealm(t)
	script, engine, err := hostParts(genesisHost)
	if err != nil || script == "" || len(engine) == 0 {
		t.Fatalf("genesis: script %d B, qjs %d B, %v", len(script), len(engine), err)
	}
	if &host.env[0] != &genesisHost[0] {
		t.Fatal("the running host is not the genesis blob")
	}
	s, q, err := hostParts(hostEnvelope(t, testAuthor(t), 7, ldr.abi, script))
	if err != nil || s != script || !reflect.DeepEqual(q, engine) {
		t.Fatalf("a blob framed here reads back differently: %v", err)
	}
	for _, short := range [][]byte{genesisHost[:offBody-1], genesisHost[:offBody+10]} {
		if _, _, err := hostParts(short); err == nil {
			t.Fatalf("a %d-byte blob was read", len(short))
		}
	}
}

// testLoader is the loader script's realm with its slots open in a fresh directory.
func testLoader(t *testing.T) (*loader, string) {
	t.Helper()
	bootRealm(t)
	data := filepath.Join(t.TempDir(), "data")
	l, err := newLoader(host.qjs, []string{"--dir", data, "--host-updates", "next"}, genesisHost)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.rt.Close)
	return l, data + ".host"
}

// A slot whose blob is not one for this loader is passed over for the host below it: not
// a suite 0x02 envelope, a body that does not frame, or a manifest for another ABI.
func TestSlotsPassOverWhatIsNotAHost(t *testing.T) {
	l, dir := testLoader(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	a := testAuthor(t)
	for what, env := range map[string][]byte{
		"another suite":   append([]byte{0x01}, hostEnvelope(t, a, 5, ldr.abi, host.script)[1:]...),
		"trailing bytes":  append(hostEnvelope(t, a, 5, ldr.abi, host.script), 0),
		"another ABI":     hostEnvelope(t, a, 5, ldr.abi+1, host.script),
		"a truncated one": genesisHost[:offBody+10],
	} {
		if err := os.WriteFile(filepath.Join(dir, "pending.skb"), env, 0o600); err != nil {
			t.Fatal(err)
		}
		_, got, err := l.call(`__loader.choose()`)
		if err != nil || string(got) != string(genesisHost) {
			t.Fatalf("%s: the slots did not fall back on the genesis blob (%v)", what, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "pending.skb")); err == nil {
			t.Fatalf("%s: the pending blob was kept", what)
		}
	}
}

// A host blob is not an app: the two are signed under different prefixes, so the host
// refuses one as the other.
func TestHostBlobIsNotAnApp(t *testing.T) {
	bootRealm(t)
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

// --host and --host-updates are the loader's: they come out of what the host sees, in
// either spelling. The rules are the shared script's; this checks this binary runs it.
func TestLoaderFlags(t *testing.T) {
	l, _ := testLoader(t)
	// call runs fn over argv as JSON, and reads its answer back into out.
	call := func(fn string, argv []string, out any) error {
		j, _ := json.Marshal(argv)
		s, _, err := l.call(`JSON.stringify(`+fn+`(JSON.parse(__a0)))`, string(j))
		if err == nil {
			err = json.Unmarshal([]byte(s), out)
		}
		return err
	}
	type loaderOptions struct {
		Rest              []string
		HostFile, Updates string
	}
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
		{[]string{}, []string{}, "", "off"},
	} {
		var o loaderOptions
		if err := call("loaderFlags", tc.argv, &o); err != nil || !reflect.DeepEqual(o.Rest, tc.rest) || o.HostFile != tc.hostFile || o.Updates != tc.updates {
			t.Fatalf("loaderFlags(%q) = %+v, %v", tc.argv, o, err)
		}
	}
	if err := call("loaderFlags", []string{"--host"}, &loaderOptions{}); err == nil {
		t.Fatal("--host with no value was accepted")
	}
	var rest []string
	if err := call("withoutOp", []string{"--op", "x", "--dir", "d", "--op=y"}, &rest); err != nil || !reflect.DeepEqual(rest, []string{"--dir", "d"}) {
		t.Fatalf("withoutOp: %q, %v", rest, err)
	}
}
