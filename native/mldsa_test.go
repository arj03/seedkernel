package main

// The native half of "one implementation, three targets" (§12.9, §14.1). The JS suite
// checks mldsa65.wasm from Node; these check that this target's embedded copy, under
// wazero, reaches the same verdicts, on NIST's vectors and on a whole hybrid-signed bundle
// through the production install path. A verifier's accept/reject boundary is consensus,
// so the embedded copy needs its own check.

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
// The shipped native binary binds mldsa65_verify and nothing else, so it cannot be used as
// a signing oracle (§12.4). A test still has to produce a hybrid bundle for it to accept,
// so it instantiates its own copy of the same artifact and binds the signing exports
// there, keeping signing in _test files.

type mldsaSigner struct {
	mldsa

	sign api.Function
	keys api.Function
}

// ML-DSA-65 secret key width (FIPS 204). Only signing needs it, so it is here, not with
// the envelope's format constants in mldsa.go.
const mldsaSkBytes = 4032

func newMlDsaSigner(t testing.TB) *mldsaSigner {
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
		mldsa: mldsa{wasmModule: &wasmModule{mod: mod, mem: mod.Memory(), name: "mldsa65-test-signer"}},
		sign:  mod.ExportedFunction("mldsa65_sign"),
		keys:  mod.ExportedFunction("mldsa65_keypair"),
	}
	s.verify = mod.ExportedFunction("mldsa65_verify")
	hb := mod.ExportedGlobal("__heap_base")
	if s.sign == nil || s.keys == nil || s.verify == nil || hb == nil {
		t.Fatal("mldsa65 test signer: missing an export")
	}
	s.heapBase = uint32(hb.Get())
	return s
}

// keypair derives an ML-DSA-65 key set from a 32-byte seed.
func (s *mldsaSigner) keypair(t testing.TB, seed []byte) (pk, sk []byte) {
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

// signDetached signs with an empty FIPS 204 context, the runtime's only mode, since its
// domain separation is the DOMAIN_manifest prefix inside the preimage (§16.1).
func (s *mldsaSigner) signDetached(t testing.TB, msg, sk []byte) []byte {
	t.Helper()
	// Hedging randomness: a fixed value is acceptable only here, since these signatures
	// never leave the test binary, and a deterministic one makes a failure reproducible.
	return s.signCtx(t, msg, nil, make([]byte, 32), sk)
}

// signCtx is the full FIPS 204 external interface, context and hedging randomness
// included, since the ACVP vectors use both.
func (s *mldsaSigner) signCtx(t testing.TB, msg, sctx, rnd, sk []byte) []byte {
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

// verifyCtx is the same for verification. The production wrapper fixes the context to
// empty, so vectors with a context call the export directly, on the same module.
func (s *mldsaSigner) verifyCtx(t testing.TB, sig, msg, sctx, pk []byte) bool {
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

func (s *mldsaSigner) read(t testing.TB, off uint32, n int) []byte {
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

// TestMlDsaAcvpVectors runs NIST's published ACVP vectors against the wasm this binary
// embeds. It reads the same fixture as the JS suite, so both targets are checked against
// the same vectors.
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
	// sigGen must match byte for byte, which catches a build against the wrong parameter
	// set or a toolchain that changed something inside.
	for _, v := range kat.SigGen {
		out := s.signCtx(t, unhex(v.Msg), unhex(v.Ctx), unhex(v.Rnd), unhex(v.Sk))
		if hex.EncodeToString(out) != v.Sig {
			t.Fatalf("ACVP sigGen tc%d: signature is not byte-exact", v.TcID)
		}
	}

	// The production wrapper's path (mldsa.go): it agrees with the artifact, and a
	// wrong-width input is `false`, not an error, as crypto_sign_verify_detached gives, so
	// both halves of the suite fail the same way.
	pk, sk := s.keypair(t, make([]byte, 32))
	msg := []byte("native adapter path")
	sig := s.signDetached(t, msg, sk)
	if !md.verifyDetached(sig, msg, pk) {
		t.Fatal("the binary's verifier rejects a signature made by the same artifact")
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

// ─── a hybrid bundle, end to end, through the production install path ──────────────────

// Suite 0x02 envelope offsets:
// [suite 1][ed_pk 32][ml_dsa_pk 1952][ed_sig 64][ml_dsa_sig 3309][body].
const (
	offHybridMlPk  = 1 + ed25519.PublicKeySize
	offHybridEdSig = offHybridMlPk + mldsaPkBytes
	offHybridMlSig = offHybridEdSig + ed25519.SignatureSize
)

// The author identity, the envelope writer and the bundle fixtures come from the shared
// harness (bundle_helper_test.go): there is one manifest suite, so every bundle any test
// writes is hybrid-signed. What is here is specific to the PQ half.

// The suite on this target: a hybrid-signed bundle installs, and its module is bound under
// the derived author id (the key-set hash), never either key alone.
func TestHybridManifestBundleLoads(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	a := testAuthor(t)
	startShell(t, authorsPolicy(a.id()), nil)

	path, key := writeTestBundle(t, a, "pqapp", 1)
	// The load line names the author by the key-set hash the host derived (§12.4).
	if status := loadBundle(path); status != loadedLine("pqapp", 1, a.id(), "pqapp") {
		t.Fatalf("hybrid bundle should load under its derived author id: %s", status)
	}
	if out, err := invokeBundle(key, []byte("hybrid")); err != nil || string(out) != "hybrid" {
		t.Fatalf("hybrid bundle's private module did not run through `%s`: %q, %v", key, out, err)
	}
	// The id is the key-set hash, not the Ed25519 key. Hybrid signing depends on this
	// (§12.4): otherwise an attacker who breaks Ed25519 could bring their own ML-DSA key
	// and install under the author's unchanged id.
	if hex.EncodeToString(a.id()) == hex.EncodeToString(a.edPub) {
		t.Fatal("the hybrid author id must not be the Ed25519 public key")
	}
}

// Both halves matter on this target too. "Either verifies" would only be as strong as the
// weaker algorithm; a break in one half must reject valid bundles (a recoverable
// operator problem) instead of admitting forged ones.
func TestHybridManifestBothSignaturesRequired(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	a := testAuthor(t)
	startShell(t, authorsPolicy(a.id()), nil)
	mjson := manifestJSON(t, "pqtamper", 1, stubGuestSrc, nil)

	for _, tc := range []struct {
		what string
		at   int
	}{
		{"the Ed25519 signature", offHybridEdSig},
		{"the ML-DSA signature", offHybridMlSig},
		// Not a signature, but the splice the format must resist: both preimages cover both
		// keys, so changing one key invalidates both signatures, not just the one made
		// with it.
		{"the ML-DSA public key", offHybridMlPk},
	} {
		menv := bundleEnvelope(t, a, mjson, stubGuestSrc, forwarderWasm)
		menv[tc.at] ^= 0x01
		path := writeBundleFile(t, "pqtamper", menv)
		if status := loadBundle(path); !strings.Contains(status, "signature invalid") {
			t.Fatalf("tampering with %s must fail the manifest, got: %s", tc.what, status)
		}
	}
}

// The Ed25519-only suite `0x01` is refused on this target too (§14.1). A host that accepted
// it would allow a downgrade by changing one byte, so the host reports "a suite I do not
// implement", not a signature verdict.
func TestGenesisManifestSuiteRefused(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	a := testAuthor(t)
	startShell(t, authorsPolicy(a.id(), a.edPub), nil)

	// A well-formed 0x01 envelope: [0x01][ed_pk 32][ed_sig 64][json], signed over
	// DOMAIN_manifest ‖ 0x01 ‖ json as that suite specified.
	mjson := manifestJSON(t, "genesis", 1, stubGuestSrc, nil)
	pre := append(append(domainManifest(), 0x01), mjson...)
	menv := append(append(append([]byte{0x01}, a.edPub...), ed25519.Sign(a.edPriv, pre)...), mjson...)
	path := writeBundleFile(t, "genesis", menv)

	if status := loadBundle(path); !strings.Contains(status, "unsupported manifest suite") {
		t.Fatalf("a genesis-suite bundle must be refused by suite, got: %s", status)
	}
}
