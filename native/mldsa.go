// mldsa.go — ML-DSA-65 (FIPS 204) for the native loader: the PQ half of manifest
// suite 0x02 (§12.4, §14.1).
//
// This is deliberately NOT a Go implementation of ML-DSA. It drives
// wasm/mldsa65.wasm — the same artifact the browser fetches and Node reads,
// compiled from the pinned mldsa-native submodule by WASM/scripts/build-mldsa.mjs
// — through wazero, exactly as sodium.go drives libsodium.wasm. The reason is the
// one stated in sodium.go's header for keeping Ed25519 on wasm: a signature this
// node accepts, every node must accept. A verifier's accept/reject boundary is
// consensus, and two independent implementations of a lattice scheme can disagree
// at the edges (malformed encodings, hint bounds, out-of-range z) while both pass
// their own test suites. There is exactly one ML-DSA implementation in this
// system, and this file is a way of calling it rather than a second one.
//
// Unlike libsodium.wasm, this module has NO imports: randomness is an argument and
// there is no libc, so there is no host module to build and nothing a Go host
// could satisfy differently from a browser. Instantiation is the whole wiring.

package main

import (
	_ "embed"
	"fmt"
	"sync"

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
	mem      api.Memory
	verify   api.Function
	heapBase uint32
	// Bump pointer over the module's own heap, valid only while mu is held. The
	// module never allocates and never retains anything across a call — the host
	// writes arguments in, it runs to completion, the host reads a number back — so
	// a rewind at the start of each call is the whole memory manager and there is no
	// free list to corrupt.
	top uint32

	// One shared linear memory and a bump allocator over it, so an op must not
	// interleave with another. Verification is driven from the realm (bundle loads)
	// and, like the libsodium ops next door, is serialized by this lock. Held only
	// for the duration of one call — never across a callback into JS or Go.
	mu sync.Mutex
}

// reset rewinds the arena. Call once at the top of every op, under mu.
func (m *mldsa) reset() { m.top = m.heapBase }

func (m *mldsa) alloc(n int) uint32 {
	p := (m.top + 15) &^ 15
	m.top = p + uint32(n)
	if need := int64(m.top) - int64(m.mem.Size()); need > 0 {
		if _, ok := m.mem.Grow(uint32(need/0x10000) + 1); !ok {
			panic("mldsa65: out of memory")
		}
	}
	return p
}

func (m *mldsa) put(b []byte) uint32 {
	p := m.alloc(len(b))
	if !m.mem.Write(p, b) {
		panic("mldsa65: memory write out of range")
	}
	return p
}

var md *mldsa // the process-wide ML-DSA-65 instance (manifest suite 0x02)

// bootMlDsa instantiates mldsa65.wasm and binds the exports the loader uses.
// Verification is all the native target needs: signing manifests is a build-side
// job, and a loader that cannot sign is a loader that cannot be turned into a
// signing oracle (§12.4).
func bootMlDsa(rt wazero.Runtime) *mldsa {
	cm, err := rt.CompileModule(ctx, mldsaWasm)
	if err != nil {
		panic(fmt.Sprintf("mldsa65: compile: %v", err))
	}
	mod, err := rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName("mldsa65").WithStartFunctions())
	if err != nil {
		panic(fmt.Sprintf("mldsa65: instantiate: %v", err))
	}
	m := &mldsa{mem: mod.Memory(), verify: mod.ExportedFunction("mldsa65_verify")}
	if m.verify == nil {
		panic("mldsa65: missing export mldsa65_verify")
	}
	// A module built for another parameter set would otherwise look like a working
	// ML-DSA-65 verifier right up until a real bundle arrived, and then report it as
	// a bad signature. Fail at boot instead.
	for _, w := range []struct {
		export string
		want   uint64
	}{
		{"mldsa65_publickeybytes", mldsaPkBytes},
		{"mldsa65_signaturebytes", mldsaSigBytes},
	} {
		f := mod.ExportedFunction(w.export)
		if f == nil {
			panic(fmt.Sprintf("mldsa65: missing export %q", w.export))
		}
		r, err := f.Call(ctx)
		if err != nil || r[0] != w.want {
			panic(fmt.Sprintf("mldsa65: %s reported %v, expected %d", w.export, r, w.want))
		}
	}
	hb := mod.ExportedGlobal("__heap_base")
	if hb == nil {
		panic("mldsa65: missing __heap_base")
	}
	m.heapBase = uint32(hb.Get())
	return m
}

// verifyDetached reports whether sig is a valid ML-DSA-65 signature over msg under
// pk, with an empty FIPS 204 context — the runtime's only mode, since its domain
// separation is the DOMAIN_manifest prefix inside the preimage (§16.1).
//
// Wrong-width inputs are `false`, not an error: that is the verdict
// crypto_sign_verify_detached gives for the same input, and one suite must not
// report a structural failure through a different channel than the other.
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

// exposeMlDsa adds ml_dsa65_verify_detached to the realm's `__sodium` object. The
// shared loader (bundle.ts) feature-detects on exactly this method: present, the
// host verifies manifest suite 0x02; absent, it refuses those bundles rather than
// falling back to the Ed25519 half alone.
func exposeMlDsa(qc *qjs.Context, o *qjs.Value, m *mldsa) {
	arg := func(t *qjs.This, i int) []byte { b, _ := qjs.JsTypedArrayToGo(t.Args()[i]); return b }
	o.SetPropertyStr("ml_dsa65_verify_detached", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewBool(m.verifyDetached(arg(t, 0), arg(t, 1), arg(t, 2))), nil
	}))
}
