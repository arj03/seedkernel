package main

// The native half of "one implementation, three targets" (§12.9, §14.1). The JS suite
// checks mldsa65.wasm from Node; these tests check that THIS target — the embedded copy,
// instantiated under wazero — reaches the same verdicts, both on NIST's own vectors and
// on a whole hybrid-signed bundle driven through the production loader.
//
// Without them the claim would rest on the targets that run the JS suite, and the one
// that embeds its own copy of the artifact would be the one nobody checked. A verifier's
// accept/reject boundary is consensus: a bundle one node admits, every node must admit.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// ─── a test-only signer ──────────────────────────────────────────────────────────
//
// The shipped loader binds mldsa65_verify and nothing else (mldsa.go), which is what
// keeps it from being turned into a signing oracle (§12.4). A test still has to produce
// a hybrid bundle for it to admit, so it instantiates its OWN module — a second instance
// of the same artifact, under a different name — and binds the signing exports there.
// The signing half therefore exists only in _test files, which is the property the
// production header claims.

type mldsaSigner struct {
	mldsa

	sign api.Function
	keys api.Function
}

// ML-DSA-65 secret key width (FIPS 204). Only the signing side needs it, so it lives
// here rather than beside the envelope's format constants in mldsa.go.
const mldsaSkBytes = 4032

func newMlDsaSigner(t *testing.T) *mldsaSigner {
	t.Helper()
	cm, err := rt.CompileModule(ctx, mldsaWasm)
	if err != nil {
		t.Fatal("mldsa65 test signer: compile:", err)
	}
	mod, err := rt.InstantiateModule(ctx, cm,
		wazero.NewModuleConfig().WithName("mldsa65-test-signer").WithStartFunctions())
	if err != nil {
		t.Fatal("mldsa65 test signer: instantiate:", err)
	}
	s := &mldsaSigner{
		sign: mod.ExportedFunction("mldsa65_sign"),
		keys: mod.ExportedFunction("mldsa65_keypair"),
	}
	s.mem, s.verify = mod.Memory(), mod.ExportedFunction("mldsa65_verify")
	hb := mod.ExportedGlobal("__heap_base")
	if s.sign == nil || s.keys == nil || s.verify == nil || hb == nil {
		t.Fatal("mldsa65 test signer: missing an export")
	}
	s.heapBase = uint32(hb.Get())
	return s
}

// keypair derives an ML-DSA-65 key set from a 32-byte seed.
func (s *mldsaSigner) keypair(t *testing.T, seed []byte) (pk, sk []byte) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reset()
	pkP, skP, seedP := s.alloc(mldsaPkBytes), s.alloc(mldsaSkBytes), s.put(seed)
	r, err := s.keys.Call(ctx, uint64(pkP), uint64(skP), uint64(seedP))
	if err != nil || r[0] != 1 {
		t.Fatalf("mldsa65 keypair: %v %v", r, err)
	}
	return s.read(t, pkP, mldsaPkBytes), s.read(t, skP, mldsaSkBytes)
}

// signDetached signs with an empty FIPS 204 context — the runtime's only mode, since its
// domain separation is the DOMAIN_manifest prefix inside the preimage (§16.1).
func (s *mldsaSigner) signDetached(t *testing.T, msg, sk []byte) []byte {
	t.Helper()
	// Hedging randomness: a fixed value is acceptable here and nowhere else — these
	// signatures never leave the test binary, and a deterministic one makes a failure
	// reproducible.
	return s.signCtx(t, msg, nil, make([]byte, 32), sk)
}

// signCtx is the full FIPS 204 external interface, context and hedging randomness
// included. The ACVP vectors carry both, and a wrapper that can only be tested on the
// subset matching one call site is a wrapper that has barely been tested.
func (s *mldsaSigner) signCtx(t *testing.T, msg, sctx, rnd, sk []byte) []byte {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reset()
	sigP, msgP := s.alloc(mldsaSigBytes), s.put(msg)
	ctxP, rndP, skP := s.put(sctx), s.put(rnd), s.put(sk)
	r, err := s.sign.Call(ctx, uint64(sigP), uint64(msgP), uint64(len(msg)),
		uint64(ctxP), uint64(len(sctx)), uint64(rndP), uint64(skP))
	if err != nil || r[0] != 1 {
		t.Fatalf("mldsa65 sign: %v %v", r, err)
	}
	return s.read(t, sigP, mldsaSigBytes)
}

// verifyCtx is the same for the verify side. The production wrapper fixes the context to
// empty, so the vectors that carry one are driven at the export directly — the same
// instance of the same module, exercised through a wider door.
func (s *mldsaSigner) verifyCtx(t *testing.T, sig, msg, sctx, pk []byte) bool {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reset()
	sigP, msgP := s.put(sig), s.put(msg)
	ctxP, pkP := s.put(sctx), s.put(pk)
	r, err := s.verify.Call(ctx, uint64(sigP), uint64(msgP), uint64(len(msg)),
		uint64(ctxP), uint64(len(sctx)), uint64(pkP))
	if err != nil {
		t.Fatalf("mldsa65 verify: %v", err)
	}
	return r[0] == 1
}

func (s *mldsaSigner) read(t *testing.T, off uint32, n int) []byte {
	t.Helper()
	b, ok := s.mem.Read(off, uint32(n))
	if !ok {
		t.Fatal("mldsa65: read out of range")
	}
	return append([]byte(nil), b...)
}

// ─── the vectors ─────────────────────────────────────────────────────────────────

// acvpCase is one NIST vector. sigVer carries a verdict to match; sigGen a secret key,
// hedging randomness and a signature that must come out byte for byte.
type acvpCase struct {
	TcID   int    `json:"tcId"`
	Reason string `json:"reason"`
	Pass   bool   `json:"pass"`
	Pk     string `json:"pk"`
	Sk     string `json:"sk"`
	Msg    string `json:"msg"`
	Ctx    string `json:"ctx"`
	Rnd    string `json:"rnd"`
	Sig    string `json:"sig"`
}

// TestMlDsaAcvpVectors runs NIST's published ACVP vectors against the wasm THIS binary
// embeds. It reads the fixture the JS suite reads rather than keeping a second copy: the
// whole value of the test is that both targets are judged by the same vectors, so a
// local copy could quietly drift into agreeing only with itself.
func TestMlDsaAcvpVectors(t *testing.T) {
	bootRealm(t)
	raw, err := os.ReadFile("../WASM/tests/fixtures/mldsa65-acvp.json")
	if err != nil {
		t.Fatal("ACVP fixture:", err)
	}
	var kat struct {
		SigVer []acvpCase
		SigGen []acvpCase
	}
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

	s := newMlDsaSigner(t)
	for _, v := range kat.SigVer {
		got := s.verifyCtx(t, unhex(v.Sig), unhex(v.Msg), unhex(v.Ctx), unhex(v.Pk))
		if got != v.Pass {
			t.Fatalf("ACVP sigVer tc%d (%s): got %v, want %v", v.TcID, v.Reason, got, v.Pass)
		}
	}
	// sigGen must match byte for byte, which is what catches a build against the wrong
	// parameter set or a toolchain that reordered something inside.
	for _, v := range kat.SigGen {
		out := s.signCtx(t, unhex(v.Msg), unhex(v.Ctx), unhex(v.Rnd), unhex(v.Sk))
		if hex.EncodeToString(out) != v.Sig {
			t.Fatalf("ACVP sigGen tc%d: signature is not byte-exact", v.TcID)
		}
	}

	// And the production wrapper's own path (mldsa.go): it agrees with the artifact, and
	// a wrong-width input is `false` rather than an error — the verdict
	// crypto_sign_verify_detached gives for the same input, so one suite cannot report a
	// structural failure through a different channel than the other.
	pk, sk := s.keypair(t, make([]byte, 32))
	msg := []byte("native adapter path")
	sig := s.signDetached(t, msg, sk)
	if !md.verifyDetached(sig, msg, pk) {
		t.Fatal("the loader's verifier rejects a signature made by the same artifact")
	}
	flipped := append([]byte(nil), sig...)
	flipped[0] ^= 1
	if md.verifyDetached(flipped, msg, pk) {
		t.Fatal("a flipped bit verified")
	}
	if md.verifyDetached(sig[:10], msg, pk) || md.verifyDetached(sig, msg, pk[:10]) {
		t.Fatal("a wrong-width input must be false, not a pass")
	}
	t.Logf("%d NIST vectors", len(kat.SigVer)+len(kat.SigGen))
}

// ─── a hybrid bundle, end to end, through the production loader ──────────────────

// Suite 0x02 envelope offsets:
// [suite 1][ed_pk 32][ml_dsa_pk 1952][ed_sig 64][ml_dsa_sig 3309][json].
const (
	offHybridMlPk  = 1 + ed25519.PublicKeySize
	offHybridEdSig = offHybridMlPk + mldsaPkBytes
	offHybridMlSig = offHybridEdSig + ed25519.SignatureSize
)

// hybridAuthorID mirrors bundle.ts: genesisHash(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖
// ml_dsa_pk). Derived here rather than read back from the loader — a test that asked the
// loader for the id would agree with the loader by construction.
func hybridAuthorID(edPub, mlPk []byte) []byte {
	pre := append([]byte(domainManifestAuthor), suiteManifestHybrid)
	pre = append(append(pre, edPub...), mlPk...)
	return sd.genericHash(32, pre)
}

// hybridEnvelope signs a manifest body under suite 0x02: both signatures over
// DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ json, so each commits to the other's key
// and the pair cannot be taken apart. A deliberate second implementation of the writer,
// in another language, fed to the shared JS reader — a drift between the two shows up
// here rather than in a deployment.
func hybridEnvelope(t *testing.T, s *mldsaSigner, a hybridKeys, mjson []byte) []byte {
	t.Helper()
	pre := append([]byte(domainManifest), suiteManifestHybrid)
	pre = append(append(append(pre, a.edPub...), a.mlPk...), mjson...)

	menv := append([]byte{suiteManifestHybrid}, a.edPub...)
	menv = append(append(menv, a.mlPk...), ed25519.Sign(a.edPriv, pre)...)
	return append(append(menv, s.signDetached(t, pre, a.mlSk)...), mjson...)
}

// hybridKeys is a whole hybrid author identity: an Ed25519 half and an ML-DSA-65 half,
// neither of which is the identity on its own (§12.4).
type hybridKeys struct {
	edPriv ed25519.PrivateKey
	edPub  []byte
	mlPk   []byte
	mlSk   []byte
}

func (a hybridKeys) id() []byte { return hybridAuthorID(a.edPub, a.mlPk) }

func hybridAuthor(t *testing.T, s *mldsaSigner, seed byte) hybridKeys {
	t.Helper()
	edPriv, edPub := testAuthor(t)
	mlSeed := make([]byte, 32)
	for i := range mlSeed {
		mlSeed[i] = seed
	}
	mlPk, mlSk := s.keypair(t, mlSeed)
	return hybridKeys{edPriv: edPriv, edPub: edPub, mlPk: mlPk, mlSk: mlSk}
}

// writeHybridBundle is writeBundle under manifest suite 0x02.
func writeHybridBundle(t *testing.T, s *mldsaSigner, a hybridKeys, app string, version int) (string, string) {
	t.Helper()
	menv := hybridEnvelope(t, s, a, manifestJSON(t, app, version, "", nil))
	return writeBundleFile(t, app, menv, ""), kernelNameFor(a.id(), app, "fwd")
}

// The whole point of the suite on this target: a hybrid-signed bundle loads, and its
// module binds under the DERIVED author id — so nothing downstream of the verifier
// (names, policy, freshness) knows or cares which suite signed.
func TestHybridManifestBundleLoads(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	s := newMlDsaSigner(t)
	a := hybridAuthor(t, s, 1)

	path, name := writeHybridBundle(t, s, a, "pqapp", 1)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(a.id()) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	if status := loadBundle(path); !strings.HasPrefix(status, "pqapp v1") {
		t.Fatalf("hybrid bundle should load: %s", status)
	}
	if !boundToWasm(name) {
		t.Fatalf("hybrid bundle's module is not bound at `%s`", name)
	}
	// The id is the key-set hash, not the Ed25519 key — the property hybrid signing
	// actually rests on (§12.4), since otherwise an attacker who breaks Ed25519 brings
	// an ML-DSA key of their own and lands on the author's names under an unchanged id.
	if hex.EncodeToString(a.id()) == hex.EncodeToString(a.edPub) {
		t.Fatal("the hybrid author id must not be the Ed25519 public key")
	}
	if boundToWasm(kernelNameFor(a.edPub, "pqapp", "fwd")) {
		t.Fatal("a hybrid bundle bound under its Ed25519 key rather than its derived id")
	}
}

// Both halves are load-bearing on this target too. "Either verifies" would be exactly as
// strong as the weaker algorithm; a break in one half must reject valid bundles (an
// operator's problem, recoverable) rather than admit forged ones.
func TestHybridManifestBothSignaturesRequired(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	s := newMlDsaSigner(t)
	a := hybridAuthor(t, s, 2)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(a.id()) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	mjson := manifestJSON(t, "pqtamper", 1, "", nil)

	for _, tc := range []struct {
		what string
		at   int
	}{
		{"the Ed25519 signature", offHybridEdSig},
		{"the ML-DSA signature", offHybridMlSig},
		// Not a signature, but the splice the format has to survive: both preimages
		// commit to both keys, so touching one key invalidates BOTH signatures rather
		// than only the one made under it.
		{"the ML-DSA public key", offHybridMlPk},
	} {
		menv := hybridEnvelope(t, s, a, mjson)
		menv[tc.at] ^= 0x01
		path := writeBundleFile(t, "pqtamper", menv, "")
		if status := loadBundle(path); !strings.Contains(status, "manifest signature invalid") {
			t.Fatalf("tampering with %s must fail the manifest, got: %s", tc.what, status)
		}
	}
}

// Which suites a deployment ACCEPTS is separate from which it can CHECK, and it is
// operator policy (§12.5). Without the dial there is no way to finish a migration — the
// classical suite would stay acceptable forever on every host still able to verify it.
func TestPolicyManifestSuitesOnNative(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	s := newMlDsaSigner(t)
	a := hybridAuthor(t, s, 3)

	hybridPath, _ := writeHybridBundle(t, s, a, "pqonly", 1)
	classicalPath, _ := writeBundle(t, a.edPriv, a.edPub, "pqonly", 1, "", nil)

	// Both identities are trusted, so the only thing left that can refuse the second
	// bundle is the suite dial.
	policy := `{"authors":["` + hex.EncodeToString(a.id()) + `","` + hex.EncodeToString(a.edPub) + `"],` +
		`"manifestSuites":[2]}`
	if err := applyPolicy(policy); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	if status := loadBundle(hybridPath); !strings.HasPrefix(status, "pqonly v1") {
		t.Fatalf("manifestSuites=[2] must admit a hybrid bundle: %s", status)
	}
	if status := loadBundle(classicalPath); !strings.Contains(status, "rejected by admission") {
		t.Fatalf("manifestSuites=[2] must refuse an Ed25519-only bundle: %s", status)
	}
}
