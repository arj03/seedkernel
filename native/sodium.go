// The loader's own crypto, for checking a host blob before anything in it runs: BLAKE2b
// on native Go, and Ed25519 verification on the shared browser/libsodium.wasm over wazero,
// since Ed25519's accept/reject boundary is consensus. The host runs its own copy of the
// same libsodium on the engine table (host/sodium-engine.ts).
package main

import (
	"context"
	crand "crypto/rand"
	_ "embed"
	"encoding/binary"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"golang.org/x/crypto/blake2b"
)

//go:embed wasm/libsodium.wasm
var sodiumWasm []byte

// libsodium drives the embedded emscripten build. The minified export names and the
// EM_JS entropy addresses below come from browser/libsodium-core.mjs; re-derive both if
// libsodium.wasm is rebuilt.
type libsodium struct {
	mem api.Memory
	fns map[string]api.Function

	// A grow-on-demand scratch block, bump-allocated per op.
	arena    uint32 // wasm ptr to the scratch block (0 until first grown)
	arenaCap int    // its size in bytes; grows to the high-water op need, never shrinks
	bump     int    // next free offset within the arena, rewound to 0 per op
}

// scratchAlign matches the wasm allocator's alignment.
const scratchAlign = 16

func alignUp(n int) int {
	if n < 1 {
		n = 1
	}
	return (n + scratchAlign - 1) &^ (scratchAlign - 1)
}

var sd *libsodium

// real libsodium name → minified wasm export, for the pinned browser/libsodium.wasm.
var sodiumExports = map[string]string{
	"malloc":                      "Ee",
	"free":                        "Fe",
	"sodium_init":                 "xe",
	"crypto_sign_detached":        "wd",
	"crypto_sign_verify_detached": "xd",
	"crypto_sign_keypair":         "td",
	"crypto_sign_seed_keypair":    "sd",
}

// The EM_JS entropy snippets randombytes reaches through import `a.b`, served from
// crypto/rand.
const (
	sodiumRandU32  = 40216 // ()->u32: one random word
	sodiumRandInit = 40252 // ()->void: lazy RNG init (a no-op here)
)

// bootSodium wires the emscripten imports, instantiates libsodium.wasm and runs
// sodium_init.
func bootSodium(rt wazero.Runtime) *libsodium {
	a := rt.NewHostModuleBuilder("a")
	// a.a: __assert_fail(cond,file,line,func), only reached on a libsodium bug.
	a.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _, _, _ uint32) {
		panic("libsodium: assertion failed")
	}).Export("a")
	// a.b: _emscripten_asm_const_int, only the two entropy snippets.
	a.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, code, _, _ uint32) uint32 {
		switch code {
		case sodiumRandU32:
			var b [4]byte
			crand.Read(b[:])
			return binary.LittleEndian.Uint32(b[:])
		case sodiumRandInit:
			return 0
		default:
			panic(fmt.Sprintf("libsodium: unexpected asm-const code %d", code))
		}
	}).Export("b")
	// a.c: abort().
	a.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module) {
		panic("libsodium: abort")
	}).Export("c")
	// a.d: emscripten_resize_heap(requestedBytes), grow linear memory to fit.
	a.NewFunctionBuilder().WithFunc(func(_ context.Context, m api.Module, requested uint32) uint32 {
		mem := m.Memory()
		if cur := mem.Size(); requested > cur {
			if _, ok := mem.Grow((requested - cur + 0xffff) / 0x10000); !ok {
				return 0
			}
		}
		return 1
	}).Export("d")
	if _, err := a.Instantiate(ctx); err != nil {
		panic(fmt.Sprintf("libsodium imports: %v", err))
	}

	cm, err := rt.CompileModule(ctx, sodiumWasm)
	if err != nil {
		panic(fmt.Sprintf("libsodium compile: %v", err))
	}
	mod, err := rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName("libsodium").WithStartFunctions())
	if err != nil {
		panic(fmt.Sprintf("libsodium instantiate: %v", err))
	}
	s := &libsodium{mem: mod.Memory(), fns: map[string]api.Function{}}
	for nm, min := range sodiumExports {
		f := mod.ExportedFunction(min)
		if f == nil {
			panic(fmt.Sprintf("libsodium: missing export %q (%s)", min, nm))
		}
		s.fns[nm] = f
	}
	if r := s.call("sodium_init"); r < 0 {
		panic(fmt.Sprintf("libsodium: sodium_init returned %d", r))
	}
	return s
}

// ───────────────────────── emscripten FFI helpers ─────────────────────────

func (s *libsodium) malloc(n int) uint32 {
	r, err := s.fns["malloc"].Call(ctx, uint64(n))
	if err != nil || r[0] == 0 {
		panic(fmt.Sprintf("libsodium: malloc(%d): %v", n, err))
	}
	return uint32(r[0])
}

func (s *libsodium) free(p uint32) { s.fns["free"].Call(ctx, uint64(p)) }

// arenaReset sizes the arena for total bytes (Σ alignUp of each buffer) and rewinds it.
// Call once at the top of an op; growth happens only here, so pointers cannot dangle.
func (s *libsodium) arenaReset(total int) {
	if total > s.arenaCap {
		if s.arena != 0 {
			s.free(s.arena)
		}
		s.arena = s.malloc(total)
		s.arenaCap = total
	}
	s.bump = 0
}

// take sub-allocates n bytes (min 1, aligned) from room reserved by arenaReset.
func (s *libsodium) take(n int) uint32 {
	if n < 1 {
		n = 1
	}
	off := (s.bump + scratchAlign - 1) &^ (scratchAlign - 1)
	s.bump = off + n
	return s.arena + uint32(off)
}

// takeIn is take plus a copy of b.
func (s *libsodium) takeIn(b []byte) uint32 {
	p := s.take(len(b))
	if len(b) > 0 {
		s.mem.Write(p, b)
	}
	return p
}

func (s *libsodium) read(p uint32, n int) []byte {
	b, _ := s.mem.Read(p, uint32(n))
	return append([]byte(nil), b...)
}

// call invokes a bound export and returns its i32 result (0 ok, -1 failure; 0 for void).
func (s *libsodium) call(name string, args ...uint64) int32 {
	r, err := s.fns[name].Call(ctx, args...)
	if err != nil {
		panic("libsodium: " + name + ": " + err.Error())
	}
	if len(r) == 0 {
		return 0
	}
	return int32(uint32(r[0]))
}

// mustCall is call for a producing op whose failure is an invariant violation. It panics:
// a failed op leaves the reused arena holding the previous op's output.
func (s *libsodium) mustCall(name string, args ...uint64) {
	if r := s.call(name, args...); r != 0 {
		panic(fmt.Sprintf("libsodium: %s returned %d (output not written)", name, r))
	}
}

// lenArgs splits a 64-bit length into this build's (lo, hi) i32 pair.
func lenArgs(n int) (lo, hi uint64) { return uint64(uint32(n)), 0 }

// ───────────────────────── the crypto ops ─────────────────────────

// genericHash is BLAKE2b, the system hash (§12.4): 1..64 output bytes, keyed or not.
// Callers check the ranges first.
func genericHash(outLen int, msg, key []byte) []byte {
	if outLen == 32 && len(key) == 0 {
		sum := blake2b.Sum256(msg)
		return sum[:]
	}
	h, err := blake2b.New(outLen, key)
	if err != nil {
		panic(fmt.Sprintf("genericHash: %v", err))
	}
	h.Write(msg)
	return h.Sum(nil)
}

func (s *libsodium) verifyDetached(sig, msg, pk []byte) bool {
	// Fixed widths are passed without lengths, so check them before staging.
	if len(sig) != 64 || len(pk) != 32 {
		return false
	}
	s.arenaReset(alignUp(len(sig)) + alignUp(len(msg)) + alignUp(len(pk)))
	sp, in, pkp := s.takeIn(sig), s.takeIn(msg), s.takeIn(pk)
	lo, hi := lenArgs(len(msg))
	return s.call("crypto_sign_verify_detached", uint64(sp), uint64(in), lo, hi, uint64(pkp)) == 0
}

