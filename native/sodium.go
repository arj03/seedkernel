// The crypto primitive: the shared browser/libsodium.wasm driven over wazero, exposed with
// libsodium-wrappers method names. BLAKE2b and ChaCha20-Poly1305-IETF run on native Go
// (§12.9); Ed25519 stays on the shared wasm, since its accept/reject boundary is consensus.
package main

import (
	"context"
	crand "crypto/rand"
	_ "embed"
	"encoding/binary"
	"fmt"
	"sync"

	"seedkernel/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

//go:embed wasm/libsodium.wasm
var sodiumWasm []byte

// libsodium drives the embedded emscripten build. The minified export names and the
// EM_JS entropy addresses below come from browser/libsodium-core.mjs; re-derive both if
// libsodium.wasm is rebuilt.
type libsodium struct {
	mem api.Memory
	fns map[string]api.Function
	// Serializes ops over the shared scratch arena; held for one op only.
	mu sync.Mutex

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
	// X25519 for the §12.6 AKE; against the base point it also derives public keys.
	"crypto_scalarmult": "Jc",
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
	// a.a — __assert_fail(cond,file,line,func): only reached on a libsodium bug.
	a.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _, _, _ uint32) {
		panic("libsodium: assertion failed")
	}).Export("a")
	// a.b — _emscripten_asm_const_int: only the two entropy snippets.
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
	// a.c — abort().
	a.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module) {
		panic("libsodium: abort")
	}).Export("c")
	// a.d — emscripten_resize_heap(requestedBytes): grow linear memory to fit.
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
func (s *libsodium) genericHash(outLen int, msg, key []byte) []byte {
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

func (s *libsodium) signDetached(msg, sk []byte) []byte {
	if len(sk) != 64 {
		panic("crypto_sign_detached: secret key must be 64 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(len(msg)) + alignUp(len(sk)) + alignUp(64))
	in, skp, sig := s.takeIn(msg), s.takeIn(sk), s.take(64)
	lo, hi := lenArgs(len(msg))
	s.mustCall("crypto_sign_detached", uint64(sig), 0 /*siglen_p=NULL*/, uint64(in), lo, hi, uint64(skp))
	return s.read(sig, 64)
}

func (s *libsodium) verifyDetached(sig, msg, pk []byte) bool {
	// Fixed widths are passed without lengths, so check them before staging.
	if len(sig) != 64 || len(pk) != 32 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(len(sig)) + alignUp(len(msg)) + alignUp(len(pk)))
	sp, in, pkp := s.takeIn(sig), s.takeIn(msg), s.takeIn(pk)
	lo, hi := lenArgs(len(msg))
	return s.call("crypto_sign_verify_detached", uint64(sp), uint64(in), lo, hi, uint64(pkp)) == 0
}

func (s *libsodium) signKeypair() (pk, sk []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(32) + alignUp(64))
	pkp, skp := s.take(32), s.take(64)
	s.mustCall("crypto_sign_keypair", uint64(pkp), uint64(skp))
	return s.read(pkp, 32), s.read(skp, 64)
}

func (s *libsodium) signSeedKeypair(seed []byte) (pk, sk []byte) {
	if len(seed) != 32 {
		panic("crypto_sign_seed_keypair: seed must be 32 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(32) + alignUp(64) + alignUp(len(seed)))
	pkp, skp, sp := s.take(32), s.take(64), s.takeIn(seed)
	s.mustCall("crypto_sign_seed_keypair", uint64(pkp), uint64(skp), uint64(sp))
	return s.read(pkp, 32), s.read(skp, 64)
}

// ── §12.6 transport AKE primitives ──

// scalarmult computes the X25519 point q = n·p, or ok=false on a low-order result.
func (s *libsodium) scalarmult(n, p []byte) ([]byte, bool) {
	if len(n) != 32 || len(p) != 32 {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(32) + alignUp(len(n)) + alignUp(len(p)))
	q, np, pp := s.take(32), s.takeIn(n), s.takeIn(p)
	if s.call("crypto_scalarmult", uint64(q), uint64(np), uint64(pp)) != 0 {
		return nil, false
	}
	return s.read(q, 32), true
}

// aeadEncrypt seals msg under (npub, key) with ChaCha20-Poly1305-IETF, binding ad; the
// result is ciphertext ‖ tag. A wrong key width is an invariant violation.
func (s *libsodium) aeadEncrypt(msg, ad, npub, key []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(fmt.Sprintf("chacha20poly1305.New: %v", err))
	}
	return aead.Seal(nil, npub, msg, ad)
}

// aeadDecrypt opens a ChaCha20-Poly1305-IETF record; a bad tag or short ct is ok=false.
func (s *libsodium) aeadDecrypt(ct, ad, npub, key []byte) ([]byte, bool) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(fmt.Sprintf("chacha20poly1305.New: %v", err))
	}
	pt, err := aead.Open(nil, npub, ct, ad)
	if err != nil {
		return nil, false
	}
	return pt, true
}

// ───────────────────────── QuickJS exposure ─────────────────────────

// argView borrows the i-th argument's bytes, or nil if it is not bytes. Every primitive
// below is done with them before the engine runs again (qjs.Value.View).
func argView(args []*qjs.Value, i int) []byte {
	b, _ := args[i].View()
	return b
}

// optView is argView for an optional argument: absent, null or undefined reads as nil.
func optView(args []*qjs.Value, i int) []byte {
	if i >= len(args) || args[i].IsNull() || args[i].IsUndefined() {
		return nil
	}
	return argView(args, i)
}

// exposeSodium installs `__sodium`, shaped by `wrapNativeSodium` (host/native-shim.ts).
func exposeSodium(qc *qjs.Context, s *libsodium) {
	o := qc.NewObject()

	o.SetPropertyStr("crypto_generichash", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// crypto_generichash(hashLength, message, key), with libsodium's ranges.
		outLen, key := int(args[0].Int32()), optView(args, 2)
		if outLen < 1 || outLen > 64 || len(key) > 64 {
			return nil, fmt.Errorf("crypto_generichash: output 1..64 and key 0..64 bytes, got %d and %d", outLen, len(key))
		}
		return qc.NewArrayBuffer(s.genericHash(outLen, argView(args, 1), key)), nil
	}))
	o.SetPropertyStr("crypto_sign_detached", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return qc.NewArrayBuffer(s.signDetached(argView(args, 0), argView(args, 1))), nil
	}))
	o.SetPropertyStr("crypto_sign_verify_detached", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return qc.NewBool(s.verifyDetached(argView(args, 0), argView(args, 1), argView(args, 2))), nil
	}))
	o.SetPropertyStr("crypto_scalarmult", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		q, ok := s.scalarmult(argView(args, 0), argView(args, 1))
		if !ok {
			return qc.NewNull(), nil
		}
		return qc.NewArrayBuffer(q), nil
	}))
	o.SetPropertyStr("crypto_aead_chacha20poly1305_ietf_encrypt", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return qc.NewArrayBuffer(s.aeadEncrypt(argView(args, 0), optView(args, 1), argView(args, 2), argView(args, 3))), nil
	}))
	o.SetPropertyStr("crypto_aead_chacha20poly1305_ietf_decrypt", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		pt, ok := s.aeadDecrypt(argView(args, 0), optView(args, 1), argView(args, 2), argView(args, 3))
		if !ok {
			return qc.NewNull(), nil
		}
		return qc.NewArrayBuffer(pt), nil
	}))
	o.SetPropertyStr("crypto_sign_keypair", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		pk, skv := s.signKeypair()
		return keypairObj(qc, pk, skv), nil
	}))
	o.SetPropertyStr("crypto_sign_seed_keypair", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		pk, skv := s.signSeedKeypair(argView(args, 0))
		return keypairObj(qc, pk, skv), nil
	}))
	o.SetPropertyStr("randombytes_buf", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		b := make([]byte, args[0].Int32())
		crand.Read(b)
		return qc.NewArrayBuffer(b), nil
	}))
	exposeMlDsa(qc, o, md)
	qc.Global().SetPropertyStr("__sodium", o)
}

func keypairObj(qc *qjs.Context, pk, sk []byte) *qjs.Value {
	o := qc.NewObject()
	o.SetPropertyStr("publicKey", qc.NewArrayBuffer(pk))
	o.SetPropertyStr("privateKey", qc.NewArrayBuffer(sk))
	return o
}
