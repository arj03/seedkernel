// mlkem.go — ML-KEM-768 (FIPS 203) for the native loader: the KEM in the primitive
// catalog (§12.2, §14.1), reachable from a guest as `ml-kem-768/{keypair,encaps,decaps}`.
//
// Like mldsa.go, this is deliberately NOT a Go implementation. It drives
// wasm/mlkem768.wasm — the same artifact the browser fetches and Node reads,
// compiled from the pinned mlkem-native submodule by WASM/scripts/build-mlkem.mjs —
// through wazero. The argument is weaker than ML-DSA's, and worth stating so it is
// not mistaken for the same one: a KEM is not a verifier, so its accept/reject
// boundary is not consensus. Two implementations that disagree at the edges do not
// split the network over a bundle; they just fail to agree on a key. That is still
// a bug found in production rather than at build time, and there is no capability
// to be gained by having a second implementation, so there is one.
//
// It is here before anything calls it. A bundle is replaceable and the vocabulary
// it draws on is not, so a core primitive is provisioned ahead of need or not at
// all (§14.1) — a post-quantum channel suite is a bundle rollout only if the name
// it reaches for already exists on every target.
//
// Like mldsa65.wasm, the module has NO imports: the coins are an argument (which is
// also what keeps the catalog entries pure functions) and there is no libc, so
// instantiation is the whole wiring.

package main

import (
	_ "embed"
	"fmt"
	"sync"

	"seedloader/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed wasm/mlkem768.wasm
var mlkemWasm []byte

// FIPS 203 ML-KEM-768 field widths, cross-checked against the module's own exports
// at boot.
const (
	mlkemPkBytes    = 1184
	mlkemSkBytes    = 2400
	mlkemCtBytes    = 1088
	mlkemSsBytes    = 32
	mlkemCoinsBytes = 32
	mlkemSeedBytes  = 64 // d ‖ z
)

type mlkem struct {
	mem api.Memory
	keypair api.Function
	encaps api.Function
	decaps api.Function

	heapBase uint32
	// Bump pointer over the module's own heap, valid only while mu is held. The
	// module never allocates and never retains anything across a call, so a rewind at
	// the top of each op is the whole memory manager.
	top uint32

	// One shared linear memory and a bump allocator over it, so an op must not
	// interleave with another. Held only for the duration of one call.
	mu sync.Mutex
}

func (m *mlkem) reset() { m.top = m.heapBase }

func (m *mlkem) alloc(n int) uint32 {
	p := (m.top + 15) &^ 15
	m.top = p + uint32(n)
	if need := int64(m.top) - int64(m.mem.Size()); need > 0 {
		if _, ok := m.mem.Grow(uint32(need/0x10000) + 1); !ok {
			panic("mlkem768: out of memory")
		}
	}
	return p
}

func (m *mlkem) put(b []byte) uint32 {
	p := m.alloc(len(b))
	if !m.mem.Write(p, b) {
		panic("mlkem768: memory write out of range")
	}
	return p
}

func (m *mlkem) read(p uint32, n int) []byte {
	b, ok := m.mem.Read(p, uint32(n))
	if !ok {
		panic("mlkem768: memory read out of range")
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}

var mk *mlkem // the process-wide ML-KEM-768 instance

// bootMlKem instantiates mlkem768.wasm and binds the three ops the catalog serves.
func bootMlKem(rt wazero.Runtime) *mlkem {
	cm, err := rt.CompileModule(ctx, mlkemWasm)
	if err != nil {
		panic(fmt.Sprintf("mlkem768: compile: %v", err))
	}
	mod, err := rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName("mlkem768").WithStartFunctions())
	if err != nil {
		panic(fmt.Sprintf("mlkem768: instantiate: %v", err))
	}
	m := &mlkem{
		mem:     mod.Memory(),
		keypair: mod.ExportedFunction("mlkem768_keypair"),
		encaps:  mod.ExportedFunction("mlkem768_encaps"),
		decaps:  mod.ExportedFunction("mlkem768_decaps"),
	}
	for name, f := range map[string]api.Function{
		"mlkem768_keypair": m.keypair, "mlkem768_encaps": m.encaps, "mlkem768_decaps": m.decaps,
	} {
		if f == nil {
			panic(fmt.Sprintf("mlkem768: missing export %q", name))
		}
	}
	// A module built for another parameter set would otherwise look like a working
	// ML-KEM-768 right up until two nodes tried to agree on a key and silently did
	// not. Fail at boot instead.
	for _, w := range []struct {
		export string
		want uint64
	}{
		{"mlkem768_publickeybytes", mlkemPkBytes},
		{"mlkem768_secretkeybytes", mlkemSkBytes},
		{"mlkem768_ciphertextbytes", mlkemCtBytes},
		{"mlkem768_bytes", mlkemSsBytes},
	} {
		f := mod.ExportedFunction(w.export)
		if f == nil {
			panic(fmt.Sprintf("mlkem768: missing export %q", w.export))
		}
		r, err := f.Call(ctx)
		if err != nil || r[0] != w.want {
			panic(fmt.Sprintf("mlkem768: %s reported %v, expected %d", w.export, r, w.want))
		}
	}
	hb := mod.ExportedGlobal("__heap_base")
	if hb == nil {
		panic("mlkem768: missing __heap_base")
	}
	m.heapBase = uint32(hb.Get())
	return m
}

// keypairFromSeed is FIPS 203 KeyGen_Internal over caller-supplied coins (d ‖ z).
func (m *mlkem) keypairFromSeed(seed []byte) (pk, sk []byte) {
	if len(seed) != mlkemSeedBytes {
		panic(fmt.Sprintf("mlkem768: seed must be %d bytes (d ‖ z), got %d", mlkemSeedBytes, len(seed)))
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.reset()
	pkP, skP, seedP := m.alloc(mlkemPkBytes), m.alloc(mlkemSkBytes), m.put(seed)
	r, err := m.keypair.Call(ctx, uint64(pkP), uint64(skP), uint64(seedP))
	if err != nil {
		panic(fmt.Sprintf("mlkem768: keypair trapped: %v", err))
	}
	if r[0] != 1 {
		panic("mlkem768: keygen failed")
	}
	return m.read(pkP, mlkemPkBytes), m.read(skP, mlkemSkBytes)
}

// encapsulate returns ok=false for a public key that fails the modulus check of
// FIPS 203 §7.2, and for a wrong-width argument — the caller holds a peer's key it
// did not choose, and "unusable" is the only distinction it can act on.
func (m *mlkem) encapsulate(pk, coins []byte) (ct, ss []byte, ok bool) {
	if len(pk) != mlkemPkBytes || len(coins) != mlkemCoinsBytes {
		return nil, nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.reset()
	ctP, ssP := m.alloc(mlkemCtBytes), m.alloc(mlkemSsBytes)
	pkP, coinsP := m.put(pk), m.put(coins)
	r, err := m.encaps.Call(ctx, uint64(ctP), uint64(ssP), uint64(pkP), uint64(coinsP))
	if err != nil {
		panic(fmt.Sprintf("mlkem768: encaps trapped: %v", err))
	}
	if r[0] != 1 {
		return nil, nil, false
	}
	return m.read(ctP, mlkemCtBytes), m.read(ssP, mlkemSsBytes), true
}

// decapsulate returns ok=false only when the SECRET KEY fails the hash check of
// FIPS 203 §7.3 — never for a bad ciphertext. ML-KEM answers those with a shared
// secret derived from the key's own z, in constant time, and reporting that apart
// from success is exactly the oracle implicit rejection exists to deny.
func (m *mlkem) decapsulate(sk, ct []byte) (ss []byte, ok bool) {
	if len(sk) != mlkemSkBytes || len(ct) != mlkemCtBytes {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.reset()
	ssP := m.alloc(mlkemSsBytes)
	ctP, skP := m.put(ct), m.put(sk)
	r, err := m.decaps.Call(ctx, uint64(ssP), uint64(ctP), uint64(skP))
	if err != nil {
		panic(fmt.Sprintf("mlkem768: decaps trapped: %v", err))
	}
	if r[0] != 1 {
		return nil, false
	}
	return m.read(ssP, mlkemSsBytes), true
}

// exposeMlKem adds the three ml_kem768_* methods to the realm's `__sodium` object,
// in the shape kem.ts gives the JS targets — the cap-bridge's catalog calls them by
// those names, so the shared TS runs unchanged here.
func exposeMlKem(qc *qjs.Context, o *qjs.Value, m *mlkem) {
	arg := func(t *qjs.This, i int) []byte { b, _ := qjs.JsTypedArrayToGo(t.Args()[i]); return b }
	o.SetPropertyStr("ml_kem768_keypair_from_seed", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		pk, sk := m.keypairFromSeed(arg(t, 0))
		return keypairObj(t.Context(), pk, sk), nil
	}))
	o.SetPropertyStr("ml_kem768_encaps", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		ct, ss, ok := m.encapsulate(arg(t, 0), arg(t, 1))
		if !ok {
			return t.Context().NewNull(), nil
		}
		obj := t.Context().NewObject()
		obj.SetPropertyStr("ciphertext", t.Context().NewArrayBuffer(ct))
		obj.SetPropertyStr("sharedSecret", t.Context().NewArrayBuffer(ss))
		return obj, nil
	}))
	o.SetPropertyStr("ml_kem768_decaps", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		ss, ok := m.decapsulate(arg(t, 0), arg(t, 1))
		if !ok {
			return t.Context().NewNull(), nil
		}
		return t.Context().NewArrayBuffer(ss), nil
	}))
}
