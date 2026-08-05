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
// (WASM/tests/fixtures/forwarder: exports scratch + handle, echoes its input). Embedded
// so the native tests build a self-contained signed bundle right here — no dependency on
// the seedstore app or any other sibling repo. Refresh it with
// `cp ../WASM/build/forwarder.wasm testdata/`.
//
// It carries the full AssemblyScript shim set — `env.abort`, `env.seed`, `env.trace` —
// so every test that installs it proves this target resolves all three, the same set the
// JS host resolves (WASM/core/kernel-host.ts). A target resolving a subset would refuse
// real AS handlers that a browser accepts, and would do it at instantiation, far from
// anything that reads like an import problem.
//
//go:embed testdata/forwarder.wasm
var forwarderWasm []byte

// Manifest signing constants, mirroring domains.ts. The domain prefixes are disjoint from
// every other prefix in the family (§16.1), which is what stops one signature from being
// replayed as another over the same bytes — and, for the author prefix, what stops a
// derived id from ever also being something someone signed.
const (
	domainManifest       = "seedkernel-manifest-sig-v1\x00"
	domainManifestAuthor = "seedkernel-manifest-author-v1\x00"
	suiteManifestGenesis = 0x01
	suiteManifestHybrid  = 0x02
	// The guest seam version these test bundles are written against, mirroring
	// GUEST_ABI_VERSION in core/domains.ts. A manifest declaring anything else is refused
	// by the shared loader, which is the point of the field (§12.2) — so a bump lands
	// here too, and a stale native test fails loudly rather than running a guest against
	// a seam that moved.
	guestABIVersion = 2
)

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

// appKeyFor is the §5.1 app-key derivation, mirroring bundle.ts, so a test can predict
// which table entry a bundle's modules land under. Test-side only: the native host
// derives no key in production — the shared JS loader hands it the finished one.
// The author leads the key, which is what makes ownership structural: two authors
// shipping the same app name never collide, so nothing has to arbitrate between them.
// A module is then addressed by the LOGICAL name from its manifest, inside that app's
// map — there is no third component encoded into anything.
func appKeyFor(author []byte, app string) string {
	return hex.EncodeToString(author) + ":" + app
}

// writeTestBundle assembles a minimal signed bundle FILE (README §12.4) in a fresh temp
// dir: one forwarder module + a stub guest with no caps, under an author-signed manifest
// at the given (app, version). See writeBundle for the general form.
func writeTestBundle(t *testing.T, priv ed25519.PrivateKey, pub []byte, app string, version int) (string, string) {
	t.Helper()
	return writeBundle(t, priv, pub, app, version, "register('ping', () => new Uint8Array([1]));", nil)
}

// writeBundle assembles a signed bundle FILE: one forwarder module plus the given guest,
// under an author-signed manifest. An empty guestSrc makes it HANDLER-ONLY — the manifest
// declares no `guest` at all, which is the shape a chat-style app ships (§12.4) and the
// only way to exercise the shell's handler dispatch arm. Returns the bundle's path and
// the app key its modules will bind under; the module itself is "fwd", the logical name
// from the manifest. Requires a booted realm (it hashes content with the booted
// sodium). Mirrors the TS run.mjs testBundle.
func writeBundle(t *testing.T, priv ed25519.PrivateKey, pub []byte, app string, version int, guestSrc string, caps []string) (string, string) {
	t.Helper()
	return signBundleJSON(t, priv, pub, app, manifestJSON(t, app, version, guestSrc, caps), guestSrc)
}

// writeSlotBundle is writeBundle for a bundle that CLAIMS A SLOT (§12.4): a handler-only
// manifest carrying `role`. Deliberately NOT the shape of the real transport bundle,
// which ships a guest — nothing here is ever run, because the point is admission: a slot
// occupant is an authority grant with its own class (§12.5), so the native tests need a
// bundle the ordinary author allowlist must refuse. `role` is inside the signed JSON,
// which is why this signs its own body rather than post-editing one.
func writeSlotBundle(t *testing.T, priv ed25519.PrivateKey, pub []byte, app string, version int, role string) string {
	t.Helper()
	type mod struct {
		Name string `json:"name"`
		Hash string `json:"hash"`
	}
	// One module: a handler-only bundle is one module by construction (§12.4).
	mjson, err := json.Marshal(struct {
		App     string `json:"app"`
		Version int    `json:"version"`
		Role    string `json:"role"`
		Modules []mod  `json:"modules"`
	}{App: app, Version: version, Role: role, Modules: []mod{{
		Name: "fwd", Hash: hex.EncodeToString(sd.genericHash(32, forwarderWasm)),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	path, _ := signBundleJSON(t, priv, pub, app, mjson, "")
	return path
}

// signBundleJSON wraps a finished manifest body in the suite-0x01 envelope and packs it.
func signBundleJSON(t *testing.T, priv ed25519.PrivateKey, pub []byte, app string, mjson []byte, guestSrc string) (string, string) {
	t.Helper()
	// Manifest envelope: [suite 1][author_pk 32][sig 64][json]. The Ed25519 detached sig is
	// over DOMAIN_manifest ‖ suite ‖ json (§12.4): the domain prefix is signed but not
	// stored, while the suite byte is signed *and* stored, so a verifier reads the byte
	// that tells it the field widths and then checks a signature committing to that same
	// byte (§14.1). suiteManifestGenesis mirrors SUITE_MANIFEST_GENESIS in domains.ts.
	preimage := append(append([]byte(domainManifest), suiteManifestGenesis), mjson...)
	sig := ed25519.Sign(priv, preimage)
	menv := append(append(append([]byte{suiteManifestGenesis}, pub...), sig...), mjson...)

	return writeBundleFile(t, app, menv, guestSrc), appKeyFor(pub, app)
}

// manifestJSON builds the manifest body both suites sign: one forwarder module plus the
// given guest. An empty guestSrc makes it HANDLER-ONLY — the manifest declares no `guest`
// at all. The bytes are the signed bytes; there is no canonicalisation step, so the
// verifier parses exactly what it checked (§12.4).
func manifestJSON(t *testing.T, app string, version int, guestSrc string, caps []string) []byte {
	t.Helper()

	type mod struct {
		Name string `json:"name"`
		Hash string `json:"hash"`
	}
	// caps + config live inside `guest` (§12.4): a bundle's authority is its guest's,
	// so a bundle with no guest has no authority to declare and omits the object.
	// `abi` names the host seam the guest was written against (§12.2) and is required
	// wherever a guest is — the loader refuses one it does not implement.
	type guest struct {
		Hash string   `json:"hash"`
		Abi  int      `json:"abi"`
		Caps []string `json:"caps"`
	}
	manifest := struct {
		App     string `json:"app"`
		Version int    `json:"version"`
		Modules []mod  `json:"modules"`
		Guest   *guest `json:"guest,omitempty"`
	}{
		App:     app,
		Version: version,
		Modules: []mod{{
			Name: "fwd", Hash: hex.EncodeToString(sd.genericHash(32, forwarderWasm)),
		}},
	}
	if caps == nil {
		caps = []string{}
	}
	if guestSrc != "" {
		manifest.Guest = &guest{
			Hash: hex.EncodeToString(sd.genericHash(32, []byte(guestSrc))),
			Abi:  guestABIVersion,
			Caps: caps,
		}
	}
	mjson, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return mjson
}

// writeBundleFile packs a finished manifest envelope, the forwarder module and the guest
// (if any) into the container and writes it to a fresh temp dir. Suite-agnostic on
// purpose: the envelope is opaque bytes to the container, which is the property that lets
// a new signature suite land without the packing format moving (§12.4).
func writeBundleFile(t *testing.T, app string, menv []byte, guestSrc string) string {
	t.Helper()
	// Module and guest name no file: they are `<name>.wasm` and `guest.js` (§12.4).
	files := [][2]any{
		{"manifest.bundle", menv},
		{"fwd.wasm", forwarderWasm},
	}
	if guestSrc != "" {
		files = append(files, [2]any{"guest.js", []byte(guestSrc)})
	}
	path := filepath.Join(t.TempDir(), app+".skb")
	if err := os.WriteFile(path, packBundle(files), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
