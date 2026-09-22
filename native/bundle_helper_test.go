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
// SHARED BUNDLE (services/domains.ts) rather than restated here.
//
// That is the line between the two kinds of duplication in this file: `bundleEnvelope` is a deliberate second *implementation* fed to the shared reader, so
// a drift between them is the point. A constant has nothing to disagree with — a copy can
// only be right or stale, and a stale one silently stops testing what it names.
type manifestVocab struct {
	Manifest string `json:"manifest"` // DOMAIN_MANIFEST, hex
	Author   string `json:"author"`   // DOMAIN_MANIFEST_AUTHOR, hex
	Suite    int    `json:"suite"`    // SUITE_MANIFEST_HYBRID_PQ, the one manifest suite
}

// vocab reads that vocabulary from the booted realm. Cached: the values are the shared
// bundle's constants, so they cannot differ between two boots in one process.
var vocabCache *manifestVocab

func vocab() manifestVocab {
	if vocabCache == nil {
		var v manifestVocab
		out := realmString(`JSON.stringify({
			manifest: toHex(DOMAIN_MANIFEST), author: toHex(DOMAIN_MANIFEST_AUTHOR),
			suite: SUITE_MANIFEST_HYBRID_PQ })`)
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

// id is the 32-byte author id everything downstream is keyed by: policy entries,
// freshness marks, revocation. A second implementation of bundle.ts `hybridAuthorId`,
// since a test that asked the host for the id would agree with it by construction.
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

// testSigner is the ML-DSA-65 signing half the tests need and the shipped native binary
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


// realmString evaluates an expression in the booted host realm — `evalString`'s twin for
// the helpers below, which have no `testing.TB` in hand. A failure here is a broken harness
// rather than a failed assertion, so it panics.
func realmString(expr string) string {
	if qc == nil {
		panic("realmString: the realm has not booted")
	}
	v, err := qc.Eval("<realmString>", expr)
	if err != nil {
		panic("realmString(" + expr + "): " + err.Error())
	}
	defer v.Free()
	return v.String()
}

// The stub guest every test bundle that does not exercise the guest declares: every
// app is a guest (§12.4), so the one app shape ships a guest program even when the
// test's point is elsewhere (policy, freshness, suite admission…). It reads the payload
// after the host's 32-byte caller with ITS OWN framing (the op-lead shape the test
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
// app is a guest (§12.4). Returns the bundle's path and the app label it installs under.
func writeBundle(t testing.TB, a authorKeys, app string, version int, guestSrc string, requires []string) (string, string) {
	t.Helper()
	if guestSrc == "" {
		guestSrc = stubGuestSrc
	}
	return signBundleJSON(t, a, app, manifestJSON(t, app, version, guestSrc, requires), guestSrc)
}

// signBundleJSON signs a complete body and writes the bundle.
func signBundleJSON(t testing.TB, a authorKeys, app string, mjson []byte, guestSrc string) (string, string) {
	t.Helper()
	return writeBundleFile(t, app, bundleEnvelope(t, a, mjson, guestSrc, forwarderWasm)), app
}

// bundleEnvelope independently frames and signs the whole bundle, for the shared JS reader.
// Both keys sign DOMAIN_manifest || suite || keys || BLAKE2b-256(body).
func bundleEnvelope(t testing.TB, a authorKeys, mjson []byte, guestSrc string, modules ...[]byte) []byte {
	t.Helper()
	var body []byte
	parts := append([][]byte{mjson, []byte(guestSrc)}, modules...)
	for _, part := range parts {
		body = binary.BigEndian.AppendUint32(body, uint32(len(part)))
		body = append(body, part...)
	}
	pre := append(domainManifest(), manifestSuite())
	pre = append(append(append(pre, a.edPub...), a.mlPk...), sd.genericHash(32, body)...)
	env := append([]byte{manifestSuite()}, a.edPub...)
	env = append(append(env, a.mlPk...), ed25519.Sign(a.edPriv, pre)...)
	return append(append(env, testSigner(t).signDetached(t, pre, a.mlSk)...), body...)
}

// claimManifest builds a manifest body claiming exactly the given protocol ids — the one
// field the ordinary fixture derives, spelled out, so a test can feed the host an id the
// format refuses (§12.10). Everything else matches manifestJSON.
func claimManifest(t testing.TB, app string, protocols ...string) []byte {
	t.Helper()
	mjson, err := json.Marshal(map[string]any{
		"app":       app,
		"version":   1,
		"protocols": protocols,
		"modules": []map[string]string{{
			"name": "fwd",
		}},
		"guest": map[string]any{
			"requires": []string{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return mjson
}

// appProtocols is the fixture's claim: the app's own name, whatever it requires. Claim
// spellings carry no authority (§12.10) and the host ties nothing to one, so a fixture
// deriving `_net` from a `link` requires would only be borrowing the transport's claim
// and testing the CLAIM contest wherever it meant to test `link`. A claim has one
// active owner, so two fixtures must not derive the same id.
func appProtocols(app string, _ []string) []string {
	return []string{app}
}

// manifestJSON builds the ordinary fixture manifest: one forwarder module plus the guest.
func manifestJSON(t testing.TB, app string, version int, guestSrc string, requires []string) []byte {
	t.Helper()
	return manifestJSONForModule(t, app, version, guestSrc, requires, "fwd", forwarderWasm)
}

// manifestJSONForModule is the same fixture shape with an explicitly supplied private
// module. The RS benchmark uses it to exercise a loaded module through its guest instead
// of reaching into the native module table (loaded modules have opaque slot ids). These
// bytes ARE the signed bytes: there is no canonicalisation step.
func manifestJSONForModule(t testing.TB, app string, version int, guestSrc string, requires []string, moduleName string, moduleBytes []byte) []byte {
	t.Helper()

	type mod struct {
		Name string `json:"name"`
	}
	// requires + config live inside `guest` (§12.4), so "no authority" is an empty
	// `requires` list rather than an absent object.
	type guest struct {
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
		// call.
		Protocols: appProtocols(app, requires),
		Version:   version,
		Modules: []mod{{
			Name: moduleName,
		}},
		Guest: guest{Requires: append([]string{}, requires...)},
	}
	mjson, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return mjson
}

// writeBundleFile writes the signed blob to a fresh temporary directory.
func writeBundleFile(t testing.TB, app string, blob []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), app+".skb")
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// signedBundleBytes is writeBundle's twin for a caller that wants the blob rather than a
// path: the same manifest, the same envelope, packed and handed back.
func signedBundleBytes(t testing.TB, a authorKeys, app string, version int, guestSrc string, requires []string) []byte {
	t.Helper()
	return bundleEnvelope(t, a, manifestJSON(t, app, version, guestSrc, requires), guestSrc, forwarderWasm)
}

// signedModuleBundleBytes is the custom-module twin used by benchmarks whose real module
// bytes are supplied out of tree.
func signedModuleBundleBytes(t testing.TB, a authorKeys, app string, version int, guestSrc string, requires []string, moduleName string, moduleBytes []byte) []byte {
	t.Helper()
	mjson := manifestJSONForModule(t, app, version, guestSrc, requires, moduleName, moduleBytes)
	return bundleEnvelope(t, a, mjson, guestSrc, moduleBytes)
}

// ── the probe app: how a native test puts a request on the wire ───────────────
//
// There is no host-side request facade: an app reaches the network by calling the id the
// transport claims (`_net`, §12.10) and is reached by the id it claims itself, so a test
// that sends a request has to BE an app — which means these tests drive the path a
// deployment uses, end to end.
//
// One guest serves both ends. `handle` echoes what it was given, and for a local loopback
// the `send` op is one request out. The envelope after the host's 32-byte caller is
// read and written with THIS probe's own copies, so the probe carries the call shape a
// real app does — content, not a host ABI.
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
// [noReply u8][to blob][proto blob][payload blob].
func probeSendArgs(toHexID, proto string, payload []byte) []byte {
	to, err := hex.DecodeString(toHexID)
	if err != nil {
		panic("probeSendArgs: " + err.Error())
	}
	out := []byte{0}
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
