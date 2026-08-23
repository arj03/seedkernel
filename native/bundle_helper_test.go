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

	"github.com/tetratelabs/wazero"

	"seedloader/qjs"
)

// forwarderWasm is a minimal pure-transform module (WASM/tests/fixtures/forwarder: exports
// scratch + handle, echoes its input), embedded so these tests build a self-contained
// signed bundle with no sibling-repo dependency. Refresh with
// `cp ../WASM/build/forwarder.wasm testdata/`.
//
// It carries the full AssemblyScript shim set — `env.abort`, `env.seed`, `env.trace` — so
// every test that installs it proves this target resolves all three. A target resolving a
// subset would refuse real AS modules a browser accepts, and would do it at instantiation,
// far from anything that reads like an import problem.
//
//go:embed testdata/forwarder.wasm
var forwarderWasm []byte

// The manifest signing vocabulary these test bundles are written against, READ OUT OF THE
// SHARED BUNDLE (core/domains.ts) rather than restated here.
//
// That is the line between the two kinds of duplication in this file: `packBundle` and
// `manifestEnvelope` are deliberate second *implementations* fed to the shared reader, so
// a drift between them is the point. A constant has nothing to disagree with — a copy can
// only be right or stale, and a stale one silently stops testing what it names.
type manifestVocab struct {
	Manifest string `json:"manifest"` // DOMAIN_MANIFEST, hex
	Author   string `json:"author"`   // DOMAIN_MANIFEST_AUTHOR, hex
	Suite    int    `json:"suite"`    // SUITE_MANIFEST_HYBRID_PQ, the one manifest suite
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
			suite: SUITE_MANIFEST_HYBRID_PQ, abi: GUEST_ABI_VERSION })`)
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
func manifestSuite() byte          { return byte(vocab().Suite) }
func guestABIVersion() int         { return vocab().ABI }

func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("hexBytes: " + err.Error())
	}
	return b
}

// authorKeys is a whole author identity (§12.4): an Ed25519 half and an ML-DSA-65 half,
// neither of which is the identity on its own. There is one manifest suite and it signs
// with both, so there is no half-identity shape for a test to hold by mistake.
type authorKeys struct {
	edPriv ed25519.PrivateKey
	edPub  []byte
	mlPk   []byte
	mlSk   []byte
}

// id is the 32-byte author id everything downstream is keyed by: policy entries, app keys,
// freshness marks. A second implementation of bundle.ts `hybridAuthorId`, since a test
// that asked the loader for the id would agree with it by construction.
func (a authorKeys) id() []byte {
	pre := append(domainManifestAuthor(), manifestSuite())
	pre = append(append(pre, a.edPub...), a.mlPk...)
	return sd.genericHash(32, pre)
}

// testAuthor mints a fresh author identity. Fresh per test so bundle-freshness marks
// (keyed by author+app) never collide. Requires a booted realm — the id is hashed with
// the booted sodium — which every caller has.
func testAuthor(t testing.TB) authorKeys {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	mlPk, mlSk := testSigner(t).keypair(t, seed)
	return authorKeys{edPriv: edPriv, edPub: edPub, mlPk: mlPk, mlSk: mlSk}
}

// testSigner is the ML-DSA-65 signing half the tests need and the shipped loader
// deliberately does not have (mldsa.go binds verify only, §12.4).
//
// One instance per RUNTIME, not per author: compiling it for every author would cost
// seconds across the suite, but a boot tears its runtime down and a module cached past
// that closes under the next test with `exit_code(0)`.
var (
	signerCache   *mldsaSigner
	signerCacheRt wazero.Runtime
)

func testSigner(t testing.TB) *mldsaSigner {
	t.Helper()
	if signerCache == nil || signerCacheRt != rt {
		signerCache, signerCacheRt = newMlDsaSigner(t), rt
	}
	return signerCache
}

// packBundle serializes named files into the one bundle container (README §12.4):
//
//	"SKB1" (4) │ count u16 │ count× ( nameLen u16 │ name utf8 │ dataLen u32 │ data )
//
// A deliberate second implementation of the writer, fed to the shared JS reader.
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

// appKeyFor asks the realm for the §5.1 app key, so a test can predict which table entry a
// bundle's modules land under. The shared `appKeyFor` (bundle.ts) itself, not a Go
// restatement: one computed here would agree with the table by coincidence and keep
// agreeing after the derivation moved.
func appKeyFor(author []byte, app string) string {
	return realmString("appKeyFor(fromHex(" + jsonString(hex.EncodeToString(author)) + "), " +
		jsonString(app) + ")")
}

// realmString evaluates an expression in the booted host realm — `evalString`'s twin for
// the helpers below, which have no `testing.TB` in hand. A failure here is a broken harness
// rather than a failed assertion, so it panics.
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
// test's point is elsewhere (policy, freshness, suite admission…). It reads the payload
// after the kernel's 32-byte caller with ITS OWN framing (the op-lead shape the test
// harness composes around invokeApp) and forwards the arguments to its one module.
const stubGuestSrc = `function handle(arg) {
	const n = arg.length > 32 ? arg[32] : -1;
	let op = "";
	for (let i = 0; i < n; i++) op += String.fromCharCode(arg[33 + i]);
	return host.call("fwd", arg.subarray(33 + n));
}`

// writeTestBundle assembles a minimal signed bundle FILE (README §12.4) in a fresh temp
// dir: one forwarder module + a stub guest with no requires, under an author-signed manifest
// at the given (app, version). See writeBundle for the general form.
func writeTestBundle(t testing.TB, a authorKeys, app string, version int) (string, string) {
	t.Helper()
	return writeBundle(t, a, app, version, "", nil)
}

// writeBundle assembles a signed bundle FILE: one forwarder module ("fwd") plus the given
// guest, under an author-signed manifest. A zero guestSrc falls back to the stub — every
// app is a guest (§12.4). Returns the bundle's path and host audit identity.
func writeBundle(t testing.TB, a authorKeys, app string, version int, guestSrc string, requires []string) (string, string) {
	t.Helper()
	if guestSrc == "" {
		guestSrc = stubGuestSrc
	}
	return signBundleJSON(t, a, app, manifestJSON(t, app, version, guestSrc, requires), guestSrc)
}

// signBundleJSON wraps a finished manifest body in the manifest envelope and packs it.
func signBundleJSON(t testing.TB, a authorKeys, app string, mjson []byte, guestSrc string) (string, string) {
	t.Helper()
	return writeBundleFile(t, app, manifestEnvelope(t, a, mjson), guestSrc), appKeyFor(a.id(), app)
}

// manifestEnvelope signs a manifest body under the one manifest suite:
//
//	[suite 1][ed_pk 32][ml_dsa_pk 1952][ed_sig 64][ml_dsa_sig 3309][json]
//
// Both signatures are over DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ json, so each
// commits to the other's key and the pair cannot be taken apart. The domain prefix is
// signed but not stored, the suite byte both, so a verifier reads the byte giving it the
// field widths and then checks a signature committing to that byte (§14.1).
//
// A deliberate second implementation of the writer, fed to the shared JS reader.
func manifestEnvelope(t testing.TB, a authorKeys, mjson []byte) []byte {
	t.Helper()
	pre := append(domainManifest(), manifestSuite())
	pre = append(append(append(pre, a.edPub...), a.mlPk...), mjson...)

	menv := append([]byte{manifestSuite()}, a.edPub...)
	menv = append(append(menv, a.mlPk...), ed25519.Sign(a.edPriv, pre)...)
	return append(append(menv, testSigner(t).signDetached(t, pre, a.mlSk)...), mjson...)
}

// claimManifest builds a manifest body claiming exactly the given protocol ids — the one
// field the ordinary fixture derives, spelled out, so a test can feed the loader an id the
// format refuses (§12.10). Everything else matches manifestJSON.
func claimManifest(t testing.TB, app string, protocols ...string) []byte {
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

// appProtocols is the fixture's claim: the app's own name, whatever it requires. Claim
// spellings carry no authority (§12.10) and the loader ties nothing to one, so a fixture
// deriving `_net` from a `link/*` requires would only be borrowing the transport's claim
// and testing the CLAIM contest wherever it meant to test the privilege. A claim has one
// active owner, so two fixtures must not derive the same id.
func appProtocols(app string, _ []string) []string {
	return []string{app}
}

// manifestJSON builds the manifest body both suites sign: one forwarder module plus the
// given guest, whose authority is its `requires` list. These bytes ARE the signed bytes —
// there is no canonicalisation step, so the verifier parses exactly what it checked (§12.4).
func manifestJSON(t testing.TB, app string, version int, guestSrc string, requires []string) []byte {
	t.Helper()

	type mod struct {
		Name string `json:"name"`
		Hash string `json:"hash"`
	}
	// requires + config live inside `guest` (§12.4), so "no authority" is an empty
	// `requires` list rather than an absent object. `abi` names the host seam the guest was
	// written against (§12.2) and is required — the loader refuses one it cannot implement.
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
		// The protocol this fixture claims (§12.10): the load itself is what routes, so a
		// test wanting a protocol answered says so in the manifest, never through a second
		// call. Derived from the same `requires` that decide the privileges, so the two
		// stay one fact here as they are in the loader.
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

// bundleBytes packs a finished manifest envelope, the forwarder module and the guest into
// the container. Suite-agnostic on purpose: the envelope is opaque bytes to the container,
// which is the property that lets a new signature suite land without the packing format
// moving (§12.4).
func bundleBytes(menv []byte, guestSrc string) []byte {
	// Module and guest name no file: they are `<name>.wasm` and `guest.js` (§12.4).
	return packBundle([][2]any{
		{"manifest.bundle", menv},
		{"fwd.wasm", forwarderWasm},
		{"guest.js", []byte(guestSrc)},
	})
}

// writeBundleFile is bundleBytes on disk, in a fresh temp dir — what the tests that go in
// through `cliLoadBundle` (a path) need. The benches take the bytes instead: they hand the
// blob to a shell they already hold, so a file would only be a detour.
func writeBundleFile(t testing.TB, app string, menv []byte, guestSrc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), app+".skb")
	if err := os.WriteFile(path, bundleBytes(menv, guestSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// signedBundleBytes is writeBundle's twin for a caller that wants the blob rather than a
// path: the same manifest, the same envelope, packed and handed back.
func signedBundleBytes(t testing.TB, a authorKeys, app string, version int, guestSrc string, requires []string) []byte {
	t.Helper()
	return bundleBytes(manifestEnvelope(t, a, manifestJSON(t, app, version, guestSrc, requires)), guestSrc)
}

// ── the probe app: how a native test puts a request on the wire ───────────────
//
// There is no host-side request facade: an app reaches the network by calling the id the
// transport claims (`_net`, §12.10) and is reached by the id it claims itself, so a test
// that sends a request has to BE an app — which means these tests drive the path a
// deployment uses, end to end.
//
// One guest serves both ends. `handle` echoes what it was given, and for a local loopback
// the `send` op is one request out. The envelope after the kernel's 32-byte caller is
// read and written with THIS probe's own copies, so the probe carries the call shape a
// real app does — content, not a kernel ABI.
const probeGuestSource = `
  function readOp(b) {
    const n = b.length > 0 ? b[0] : -1;
    if (n < 0 || b.length < 1 + n) throw new Error("probe: malformed op");
    let op = "";
    for (let i = 0; i < n; i++) op += String.fromCharCode(b[1 + i]);
    return { op, args: b.subarray(1 + n) };
  }
  function writeOp(op, args) {
    const out = new Uint8Array(1 + op.length + args.length);
    out[0] = op.length;
    for (let i = 0; i < op.length; i++) out[1 + i] = op.charCodeAt(i) & 255;
    out.set(args, 1 + op.length);
    return out;
  }
  function handle(arg) {
    let fromHost = true;
    for (let i = 0; i < 32; i++) { if (arg[i] !== 0) { fromHost = false; break; } }
    const body = arg.subarray(32);
    if (fromHost) {
      const { op, args } = readOp(body);
      if (op === "send") return host.call("_net", writeOp("send", args));
      return new Uint8Array(0);
    }
    return body;
  }
`

// probeSendArgs encodes the `send` op's arguments:
// [noReply u8][deadline u32][to blob][proto blob][payload blob].
func probeSendArgs(toHexID, proto string, payload []byte) []byte {
	to, err := hex.DecodeString(toHexID)
	if err != nil {
		panic("probeSendArgs: " + err.Error())
	}
	out := []byte{0}
	out = binary.BigEndian.AppendUint32(out, 0) // deadline: the node's default
	out = binary.BigEndian.AppendUint32(out, uint32(len(to)))
	out = append(out, to...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(proto)))
	out = append(out, proto...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(payload)))
	return append(out, payload...)
}

// writeProbeBundle signs the probe app under `author`, claiming `app` as its protocol id
// and declaring the one grant it needs: the transport's id.
func writeProbeBundle(t testing.TB, author authorKeys, app string) string {
	t.Helper()
	path, _ := writeBundle(t, author, app, 1, probeGuestSource, []string{"_net"})
	return path
}
