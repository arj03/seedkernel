// ML-DSA-65 (FIPS 204) verification, the PQ half of manifest suite 0x02 (§12.4, §14.1).
// It runs the same wasm/mldsa65.wasm the JS target does: the accept/reject boundary is
// consensus, so it must not be a second implementation.
package main

import (
	_ "embed"
	"fmt"

	"seedkernel/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed wasm/mldsa65.wasm
var mldsaWasm []byte

// ML-DSA-65 widths (§12.4), cross-checked against the module's exports at boot.
const (
	mldsaPkBytes  = 1952
	mldsaSigBytes = 3309
)

type mldsa struct {
	*wasmModule
	verify api.Function
}

var md *mldsa

// bootMlDsa instantiates mldsa65.wasm. The binary only verifies; signing is build-side
// (§12.4).
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
// with an empty context: domain separation is in the preimage (§16.1). Wrong widths are
// false, as in crypto_sign_verify_detached.
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

// exposeMlDsa adds ml_dsa65_verify_detached to the realm's `__sodium` object.
func exposeMlDsa(qc *qjs.Context, o *qjs.Value, m *mldsa) {
	o.SetPropertyStr("ml_dsa65_verify_detached", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return qc.NewBool(m.verifyDetached(argView(args, 0), argView(args, 1), argView(args, 2))), nil
	}))
}
