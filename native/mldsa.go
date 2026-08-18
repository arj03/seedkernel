// mldsa.go — ML-DSA-65 (FIPS 204) for the native loader: the PQ half of manifest suite
// 0x02 (§12.4, §14.1).
//
// Deliberately NOT a Go implementation. It drives wasm/mldsa65.wasm — the same artifact
// the browser fetches and Node reads — through wazero, for the reason sodium.go's header
// gives for keeping Ed25519 on wasm: a verifier's accept/reject boundary is consensus, and
// two independent implementations of a lattice scheme can disagree at the edges (malformed
// encodings, hint bounds, out-of-range z) while both pass their own test suites.
//
// Unlike libsodium.wasm this module has NO imports — randomness is an argument and there
// is no libc — so instantiation is the whole wiring.

package main

import (
	_ "embed"
	"fmt"

	"seedloader/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed wasm/mldsa65.wasm
var mldsaWasm []byte

// FIPS 204 ML-DSA-65 field widths — format constants of the manifest envelope
// (§12.4), cross-checked against the module's own exports at boot.
const (
	mldsaPkBytes  = 1952
	mldsaSigBytes = 3309
)

type mldsa struct {
	*wasmModule
	verify api.Function
}

var md *mldsa // the process-wide ML-DSA-65 instance (manifest suite 0x02)

// bootMlDsa instantiates mldsa65.wasm and binds the exports the loader uses. Verification
// is all it needs: signing manifests is a build-side job, and a loader that cannot sign
// cannot be turned into a signing oracle (§12.4).
func bootMlDsa(rt wazero.Runtime) *mldsa {
	m := newWasmModule(rt, "mldsa65", mldsaWasm, map[string]uint64{
		"mldsa65_publickeybytes": mldsaPkBytes,
		"mldsa65_signaturebytes": mldsaSigBytes,
	})
	verify := m.mod.ExportedFunction("mldsa65_verify")
	if verify == nil {
		panic("mldsa65: missing export mldsa65_verify")
	}
	return &mldsa{wasmModule: m, verify: verify}
}

// verifyDetached reports whether sig is a valid ML-DSA-65 signature over msg under pk,
// with an empty FIPS 204 context — the runtime's only mode, since domain separation is the
// DOMAIN_manifest prefix inside the preimage (§16.1).
//
// Wrong-width inputs are `false`, not an error: that is what crypto_sign_verify_detached
// answers, and one suite must not report a structural failure through a different channel
// than the other.
func (m *mldsa) verifyDetached(sig, msg, pk []byte) bool {
	if len(sig) != mldsaSigBytes || len(pk) != mldsaPkBytes {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.reset()
	sigP, msgP, pkP := m.put(sig), m.put(msg), m.put(pk)
	r, err := m.verify.Call(ctx, uint64(sigP), uint64(msgP), uint64(len(msg)), 0, 0, uint64(pkP))
	if err != nil {
		panic(fmt.Sprintf("mldsa65: verify trapped: %v", err))
	}
	return r[0] == 1
}

// exposeMlDsa adds ml_dsa65_verify_detached to the realm's `__sodium` object. bundle.ts
// feature-detects on exactly this method: absent, it refuses suite 0x02 bundles rather
// than falling back to the Ed25519 half alone.
func exposeMlDsa(qc *qjs.Context, o *qjs.Value, m *mldsa) {
	o.SetPropertyStr("ml_dsa65_verify_detached", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewBool(m.verifyDetached(argBytes(t, 0), argBytes(t, 1), argBytes(t, 2))), nil
	}))
}
