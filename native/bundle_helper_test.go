package main

import (
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
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

// writeTestBundle assembles a minimal signed bundle directory (README §12.4) in a fresh
// temp dir: one forwarder module + a stub guest, under an author-signed manifest at the
// given (app, version). Returns the dir and the module's kernel name. Requires boot()
// first (it hashes content with the booted sodium). Mirrors the TS run.mjs testBundle. The
// module binds at name("fwd") unless a `kernelOverride` is passed — a test uses that to
// aim a module at a seeded slot and prove the §12.5 overlay refusal.
func writeTestBundle(t *testing.T, priv ed25519.PrivateKey, pub []byte, app string, version int, kernelOverride ...string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	kernelName := name("fwd")
	if len(kernelOverride) > 0 {
		kernelName = kernelOverride[0]
	}
	guestSrc := "register('ping', () => new Uint8Array([1]));"

	type mod struct {
		Name       string `json:"name"`
		File       string `json:"file"`
		Hash       string `json:"hash"`
		KernelName string `json:"kernelName"`
	}
	manifest := struct {
		App     string            `json:"app"`
		Version int               `json:"version"`
		Modules []mod             `json:"modules"`
		Guest   map[string]string `json:"guest"`
		Caps    []string          `json:"caps"`
	}{
		App:     app,
		Version: version,
		Modules: []mod{{
			Name: "fwd", File: "fwd.wasm", Hash: hex.EncodeToString(sd.genericHash(32, forwarderWasm)),
			KernelName: kernelName,
		}},
		Guest: map[string]string{"file": "guest.js", "hash": hex.EncodeToString(sd.genericHash(32, []byte(guestSrc)))},
		Caps:  []string{},
	}
	mjson, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	// Manifest envelope: [author_pk 32][sig 64][json]. The Ed25519 detached sig is over
	// DOMAIN_manifest ‖ json (§12.4) — the prefix is signed but not stored in the envelope.
	sig := ed25519.Sign(priv, append([]byte("seedkernel-manifest-sig-v1\x00"), mjson...))
	menv := append(append(append([]byte{}, pub...), sig...), mjson...)

	write := func(fn string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, fn), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("fwd.wasm", forwarderWasm)
	write("guest.js", []byte(guestSrc))
	write("manifest.bundle", menv)
	return dir, kernelName
}
