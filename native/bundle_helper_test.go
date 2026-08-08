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

	"seedloader/qjs"
)

// forwarderWasm is a minimal, valid pure-transform WASM module
// (WASM/tests/fixtures/forwarder: exports scratch + handle, echoes its input). Embedded
// so the native tests build a self-contained signed bundle right here — no dependency on
// the seedstore app or any other sibling repo. Refresh it with
// `cp ../WASM/build/forwarder.wasm testdata/`.
//
// It carries the full AssemblyScript shim set — `env.abort`, `env.seed`, `env.trace` —
// so every test that installs it proves this target resolves all three, the same set the
// JS host resolves (WASM/host/module-table.ts). A target resolving a subset would refuse
// real AS modules that a browser accepts, and would do it at instantiation, far from
// anything that reads like an import problem.
//
//go:embed testdata/forwarder.wasm
var forwarderWasm []byte

// The manifest signing vocabulary — the domain prefixes, the suite bytes and the guest
// ABI version these test bundles are written against. READ OUT OF THE SHARED BUNDLE
// (core/domains.ts, published on the realm's global by build:loader-bundles), not
// restated here.
//
// This is the line between the two kinds of test-side duplication in this file.
// `packBundle` below is a deliberate second *implementation* of the container writer, in
// another language, fed to the shared reader: a drift between them is what it is there
// to catch. A constant has no such second implementation to disagree with — a copy of
// one is a value that can only ever be right or stale, and a stale one silently stops
// testing what it names. The domain prefixes are disjoint from every other prefix in the
// family (§16.1), which is what stops one signature from being replayed as another over
// the same bytes; the ABI version is the field the shared loader refuses a mismatch on
// (§12.2). Both are the shell's to define, so both are asked of it.
type manifestVocab struct {
	Manifest string `json:"manifest"` // DOMAIN_MANIFEST, hex
	Author   string `json:"author"`   // DOMAIN_MANIFEST_AUTHOR, hex
	Genesis  int    `json:"genesis"`  // SUITE_MANIFEST_GENESIS
	Hybrid   int    `json:"hybrid"`   // SUITE_MANIFEST_HYBRID_PQ
	ABI      int    `json:"abi"`      // GUEST_ABI_VERSION
}

// vocab reads that vocabulary from the booted realm. Cached: the values are the shared
// bundle's constants, so they cannot differ between two boots in one process.
var vocabCache *manifestVocab

func vocab() manifestVocab {
	if vocabCache == nil {
		var v manifestVocab
		out := realmString(`JSON.stringify({
			manifest: toHex(DOMAIN_MANIFEST), author: toHex(DOMAIN_MANIFEST_AUTHOR),
			genesis: SUITE_MANIFEST_GENESIS, hybrid: SUITE_MANIFEST_HYBRID_PQ,
			abi: GUEST_ABI_VERSION })`)
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			panic("vocab: " + err.Error())
		}
		vocabCache = &v
	}
	return *vocabCache
}

// domainManifest and domainManifestAuthor are those two prefixes as the bytes a signer
// prepends. Byte slices rather than strings because that is what the realm hands back.
func domainManifest() []byte       { return hexBytes(vocab().Manifest) }
func domainManifestAuthor() []byte { return hexBytes(vocab().Author) }
func suiteManifestGenesis() byte   { return byte(vocab().Genesis) }
func suiteManifestHybrid() byte    { return byte(vocab().Hybrid) }
func guestABIVersion() int         { return vocab().ABI }

func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("hexBytes: " + err.Error())
	}
	return b
}

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

// appKeyFor asks the realm for the §5.1 app key, so a test can predict which table entry
// a bundle's modules land under. The shared `appKeyFor` (bundle.ts) itself, not a Go
// restatement of it: the derivation is the loader's, and a test that computed its own
// would agree with the table by coincidence and keep agreeing after the derivation moved.
// The author leads the key, which is what makes ownership structural: two authors
// shipping the same app name never collide, so nothing has to arbitrate between them.
// A module is then addressed by the LOGICAL name from its manifest, inside that app's
// map — there is no third component encoded into anything.
func appKeyFor(author []byte, app string) string {
	return realmString("appKeyFor(fromHex(" + jsonString(hex.EncodeToString(author)) + "), " +
		jsonString(app) + ")")
}

// realmString evaluates an expression in the booted host realm and returns it as a
// string — `evalString`'s twin for the helpers below, which have no `testing.TB` in hand
// and are called from too many places to thread one through. A failure here is a broken
// harness rather than a failed assertion, so it panics: the realm is up (every caller
// runs after a boot) and the expression is a constant.
func realmString(expr string) string {
	if qc == nil {
		panic("realmString: the realm has not booted")
	}
	v, err := qc.Eval("<realmString>", qjs.Code(expr))
	if err != nil {
		panic("realmString(" + expr + "): " + err.Error())
	}
	defer v.Free()
	return v.String()
}

// The stub guest every test bundle that does not exercise the guest declares: every
// app is a guest (§12.4), so the one app shape ships a guest program even when the
// test's point is elsewhere (policy, freshness, suite admission…).
const stubGuestSrc = "register('ping', () => new Uint8Array([1]));"

// writeTestBundle assembles a minimal signed bundle FILE (README §12.4) in a fresh temp
// dir: one forwarder module + a stub guest with no requires, under an author-signed manifest
// at the given (app, version). See writeBundle for the general form.
func writeTestBundle(t *testing.T, priv ed25519.PrivateKey, pub []byte, app string, version int) (string, string) {
	t.Helper()
	return writeBundle(t, priv, pub, app, version, "", nil)
}

// writeBundle assembles a signed bundle FILE: one forwarder module plus the given guest,
// under an author-signed manifest. A zero guestSrc falls back to the stub — every app is
// a guest (§12.4), so there is no guest-less shape to write. Returns the bundle's path
// and the app key its modules will bind under; the module itself is "fwd", the logical
// name from the manifest. Requires a booted realm (it hashes content with the booted
// sodium). Mirrors the TS run.mjs testBundle.
func writeBundle(t *testing.T, priv ed25519.PrivateKey, pub []byte, app string, version int, guestSrc string, requires []string) (string, string) {
	t.Helper()
	if guestSrc == "" {
		guestSrc = stubGuestSrc
	}
	return signBundleJSON(t, priv, pub, app, manifestJSON(t, app, version, guestSrc, requires), guestSrc)
}

// signBundleJSON wraps a finished manifest body in the suite-0x01 envelope and packs it.
func signBundleJSON(t *testing.T, priv ed25519.PrivateKey, pub []byte, app string, mjson []byte, guestSrc string) (string, string) {
	t.Helper()
	// Manifest envelope: [suite 1][author_pk 32][sig 64][json]. The Ed25519 detached sig is
	// over DOMAIN_manifest ‖ suite ‖ json (§12.4): the domain prefix is signed but not
	// stored, while the suite byte is signed *and* stored, so a verifier reads the byte
	// that tells it the field widths and then checks a signature committing to that same
	// byte (§14.1). The suite byte is the shell's SUITE_MANIFEST_GENESIS, asked of it.
	preimage := append(append(domainManifest(), suiteManifestGenesis()), mjson...)
	sig := ed25519.Sign(priv, preimage)
	menv := append(append(append([]byte{suiteManifestGenesis()}, pub...), sig...), mjson...)

	return writeBundleFile(t, app, menv, guestSrc), appKeyFor(pub, app)
}

// claimManifest builds a manifest body claiming exactly the given protocol ids — the one
// field the ordinary fixture derives, spelled out, so a test can feed the loader an id the
// format refuses (§12.10). Everything else matches manifestJSON.
func claimManifest(t *testing.T, app string, protocols ...string) []byte {
	t.Helper()
	mjson, err := json.Marshal(map[string]any{
		"app":       app,
		"version":   1,
		"protocols": protocols,
		"modules": []map[string]string{{
			"name": "fwd", "hash": hex.EncodeToString(sd.genericHash(32, forwarderWasm)),
		}},
		"guest": map[string]any{
			"hash":     hex.EncodeToString(sd.genericHash(32, []byte(stubGuestSrc))),
			"abi":      guestABIVersion(),
			"requires": []string{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return mjson
}

// appProtocols is the fixture's claim: the app's own name, or nothing at all when the
// requires name a mount half (§12.5) — those bundles are transports, and a transport
// claiming a protocol id is refused at the load (§12.10).
func appProtocols(app string, requires []string) []string {
	for _, r := range requires {
		if r == "link/open" || r == "transport/deliver" {
			return nil
		}
	}
	return []string{app}
}

// manifestJSON builds the manifest body both suites sign: one forwarder module plus the
// given guest. Every app is a guest (§12.4), so the manifest always declares one — the
// guest's authority is the `requires` list, which may be empty. The bytes are the signed
// bytes; there is no canonicalisation step, so the verifier parses exactly what it
// checked (§12.4).
func manifestJSON(t *testing.T, app string, version int, guestSrc string, requires []string) []byte {
	t.Helper()

	type mod struct {
		Name string `json:"name"`
		Hash string `json:"hash"`
	}
	// requires + config live inside `guest` (§12.4): a bundle's authority is its guest's,
	// so "no authority" is an empty `requires` list, not an absent object. `abi` names the
	// host seam the guest was written against (§12.2) and is required — the loader
	// refuses one it does not implement.
	type guest struct {
		Hash     string   `json:"hash"`
		Abi      int      `json:"abi"`
		Requires []string `json:"requires"`
	}
	manifest := struct {
		App       string   `json:"app"`
		Version   int      `json:"version"`
		Protocols []string `json:"protocols,omitempty"`
		Modules   []mod    `json:"modules"`
		Guest     guest    `json:"guest"`
	}{
		App: app,
		// The protocol this fixture claims (§12.10), which is its app name: the load
		// itself is what routes, so a test that wants a protocol answered says so in the
		// manifest and never through a second call. A MOUNT-shaped fixture claims none —
		// a transport receives no dispatch, and the shell refuses a claim from one — so
		// the field is derived from the same `requires` that decide the admission class,
		// keeping the two facts one fact here as they are in the loader.
		Protocols: appProtocols(app, requires),
		Version:   version,
		Modules: []mod{{
			Name: "fwd", Hash: hex.EncodeToString(sd.genericHash(32, forwarderWasm)),
		}},
		Guest: guest{
			Hash:     hex.EncodeToString(sd.genericHash(32, []byte(guestSrc))),
			Abi:      guestABIVersion(),
			Requires: requires,
		},
	}
	if manifest.Guest.Requires == nil {
		manifest.Guest.Requires = []string{}
	}
	mjson, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return mjson
}

// writeBundleFile packs a finished manifest envelope, the forwarder module and the guest
// into the container and writes it to a fresh temp dir. Suite-agnostic on purpose: the
// envelope is opaque bytes to the container, which is the property that lets a new
// signature suite land without the packing format moving (§12.4).
func writeBundleFile(t *testing.T, app string, menv []byte, guestSrc string) string {
	t.Helper()
	// Module and guest name no file: they are `<name>.wasm` and `guest.js` (§12.4).
	files := [][2]any{
		{"manifest.bundle", menv},
		{"fwd.wasm", forwarderWasm},
		{"guest.js", []byte(guestSrc)},
	}
	path := filepath.Join(t.TempDir(), app+".skb")
	if err := os.WriteFile(path, packBundle(files), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
