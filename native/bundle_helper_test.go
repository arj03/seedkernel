package main

import (
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// forwarderWasm is a minimal, valid pure-transform handler module
// (WASM/tests/fixtures/forwarder: exports scratch + handle, imports only env.abort,
// echoes its input). Embedded so the native tests build a self-contained signed bundle
// right here — no dependency on the seedstore app or any other sibling repo. Refresh it
// with `cp ../WASM/build/forwarder.wasm testdata/`.
//
//go:embed testdata/forwarder.wasm
var forwarderWasm []byte

// testAuthor mints a fresh Ed25519 author identity (32-byte public, seed‖pub private).
// Fresh per test so bundle-freshness marks (keyed by author+app) never collide.
func testAuthor(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// packBundle serializes named files into the one bundle container (README §12.4):
//
//	"SKB1" (4) │ count u16 │ count× ( nameLen u16 │ name utf8 │ dataLen u32 │ data )
//
// A deliberate second implementation of the writer, in another language: the tests
// below feed it to the shared JS reader, so a drift between the two shows up here
// rather than in a deployment.
func packBundle(files [][2]any) []byte {
	out := append([]byte("SKB1"), 0, 0)
	binary.BigEndian.PutUint16(out[4:], uint16(len(files)))
	for _, f := range files {
		n, d := []byte(f[0].(string)), f[1].([]byte)
		out = binary.BigEndian.AppendUint16(out, uint16(len(n)))
		out = append(out, n...)
		out = binary.BigEndian.AppendUint32(out, uint32(len(d)))
		out = append(out, d...)
	}
	return out
}

// writeTestBundle assembles a minimal signed bundle FILE (README §12.4) in a fresh temp
// dir: one forwarder module + a stub guest, under an author-signed manifest at the given
// (app, version). Returns the bundle's path and the module's kernel name. Requires boot()
// first (it hashes content with the booted sodium). Mirrors the TS run.mjs testBundle. The
// module binds at name("fwd") unless a `kernelOverride` is passed — a test uses that to
// aim a module at a seeded slot and prove the §12.5 overlay refusal.
func writeTestBundle(t *testing.T, priv ed25519.PrivateKey, pub []byte, app string, version int, kernelOverride ...string) (string, string) {
	t.Helper()
	kernelName := name("fwd")
	if len(kernelOverride) > 0 {
		kernelName = kernelOverride[0]
	}
	guestSrc := "register('ping', () => new Uint8Array([1]));"

	type mod struct {
		Name       string `json:"name"`
		Hash       string `json:"hash"`
		KernelName string `json:"kernelName"`
	}
	// caps + config live inside `guest` (§12.4): a bundle's authority is its guest's.
	type guest struct {
		Hash string   `json:"hash"`
		Caps []string `json:"caps"`
	}
	manifest := struct {
		App     string `json:"app"`
		Version int    `json:"version"`
		Modules []mod  `json:"modules"`
		Guest   guest  `json:"guest"`
	}{
		App:     app,
		Version: version,
		Modules: []mod{{
			Name: "fwd", Hash: hex.EncodeToString(sd.genericHash(32, forwarderWasm)),
			KernelName: kernelName,
		}},
		Guest: guest{Hash: hex.EncodeToString(sd.genericHash(32, []byte(guestSrc))), Caps: []string{}},
	}
	mjson, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	// Manifest envelope: [author_pk 32][sig 64][json]. The Ed25519 detached sig is over
	// DOMAIN_manifest ‖ json (§12.4) — the prefix is signed but not stored in the envelope.
	sig := ed25519.Sign(priv, append([]byte("seedkernel-manifest-sig-v1\x00"), mjson...))
	menv := append(append(append([]byte{}, pub...), sig...), mjson...)

	// Module and guest name no file: they are `<name>.wasm` and `guest.js` (§12.4).
	blob := packBundle([][2]any{
		{"manifest.bundle", menv},
		{"fwd.wasm", forwarderWasm},
		{"guest.js", []byte(guestSrc)},
	})
	path := filepath.Join(t.TempDir(), app+".skb")
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, kernelName
}
