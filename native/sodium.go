// sodium.go — the Go target's crypto *primitive*: the same browser/libsodium.wasm, driven
// over wazero, so this file is the FFI seam over the emscripten ABI plus a `sodium` object
// carrying libsodium-wrappers method names — the shared host JS calls `sodium.*` unchanged
// and a Go node's output is byte-identical to a Bun node's. Under the native fast-path
// rule (§12.9), genericHash (BLAKE2b-256, pinned by TestSodiumGenericHash — the one hash
// wazero runs slower than V8) and the ChaCha20-Poly1305-IETF record layer (RFC 8439,
// pinned by TestSodiumAead from this build's own binary; ~8× faster, no scratch lock) run
// on native Go. Ed25519 and ML-DSA-65 (mldsa.go) stay on the shared wasm: a verifier's
// accept/reject boundary is consensus, and X25519 is handshake-only, amortized over the
// link.
package main

import (
	"context"
	crand "crypto/rand"
	_ "embed"
	"encoding/binary"
	"fmt"
	"sync"

	"seedloader/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

//go:embed wasm/libsodium.wasm
var sodiumWasm []byte

// libsodium drives the embedded emscripten build. Its exports are minified; the
// real-name → minified-export map (and the two EM_JS entropy code addresses below) are
// read from browser/libsodium-core.mjs — re-derive both if libsodium.wasm is rebuilt.
type libsodium struct {
	mod api.Module
	mem api.Memory
	fns map[string]api.Function
	// One shared scratch heap and allocator, so an op is a malloc/call/read sequence that
	// must not interleave with another (sign/verify run on per-connection goroutines).
	// Held for one op only, never across a callback into JS or Go.
	mu sync.Mutex

	// Scratch arena reused across ops, replacing the 2–4 malloc/free pairs each one made:
	// ops are serialized by mu, so one grow-on-demand block with a per-op bump allocator
	// suffices.
	arena    uint32 // wasm ptr to the scratch block (0 until first grown)
	arenaCap int    // its size in bytes; grows to the high-water op need, never shrinks
	bump     int    // next free offset within the arena, rewound to 0 per op
}

// scratchAlign matches the wasm allocator's alignment, so a bump-allocated buffer sits
// exactly where a malloc'd one would — keeping libsodium's memory layout identical.
const scratchAlign = 16

func alignUp(n int) int {
	if n < 1 {
		n = 1
	}
	return (n + scratchAlign - 1) &^ (scratchAlign - 1)
}

var sd *libsodium // the process-wide libsodium instance (genesis verify + sodium.*)

// real libsodium name → minified wasm export, for the pinned browser/libsodium.wasm.
var sodiumExports = map[string]string{
	"malloc":                               "Ee",
	"free":                                 "Fe",
	"sodium_init":                          "xe",
	"crypto_generichash":                   "Ja",
	"crypto_sign_detached":                 "wd",
	"crypto_sign_verify_detached":          "xd",
	"crypto_sign_keypair":                  "td",
	"crypto_sign_seed_keypair":             "sd",
	"crypto_sign_ed25519_pk_to_curve25519": "Cd",
	"crypto_sign_ed25519_sk_to_curve25519": "Dd",
	"crypto_box_seal":                      "za",
	"crypto_box_seal_open":                 "Aa",
	// One export covers the §12.6 AKE's X25519: the transport bundle reaches scalarmult
	// through the guest seam's `x25519/dh` and derives its ephemeral PUBLIC key with the
	// same entry against the base point — no keypair primitive to export.
	"crypto_scalarmult": "Jc",
}

// EM_JS entropy snippet code addresses (libsodium-core.mjs `d={…}`): randombytes routes
// through the asm-const import `a.b`, and these are the only two snippets in this build,
// satisfied from crypto/rand (the source need not match across nodes).
const (
	sodiumRandU32  = 40216 // ()->u32: one random word
	sodiumRandInit = 40252 // ()->void: lazy RNG init (a no-op here)
)

const sealBytes = 48 // crypto_box_SEALBYTES (ephemeral pk 32 + MAC 16)

// bootSodium wires the four emscripten host imports (module "a"), instantiates
// libsodium.wasm, binds the exports used, and runs sodium_init — what libsodium-wrappers
// does after load.
func bootSodium(rt wazero.Runtime) *libsodium {
	a := rt.NewHostModuleBuilder("a")
	// a.a — __assert_fail(cond,file,line,func): only reached on a libsodium bug.
	a.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _, _, _ uint32) {
		panic("libsodium: assertion failed")
	}).Export("a")
	// a.b — _emscripten_asm_const_int: the EM_JS dispatcher, which in this build only
	// ever runs the two argument-free entropy snippets.
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
	s := &libsodium{mod: mod, mem: mod.Memory(), fns: map[string]api.Function{}}
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

// arenaReset ensures the arena can hold total bytes and rewinds the bump allocator: call
// once at the top of an op with Σ alignUp(each buffer), then take/takeIn the buffers —
// growing happens only here, never mid-op, so pointers cannot dangle.
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

// take sub-allocates n bytes (min 1, scratchAlign-aligned) from the arena at the current
// bump. The op must have reserved room via arenaReset; take never grows.
func (s *libsodium) take(n int) uint32 {
	if n < 1 {
		n = 1
	}
	off := (s.bump + scratchAlign - 1) &^ (scratchAlign - 1)
	s.bump = off + n
	return s.arena + uint32(off)
}

// takeIn is take plus a copy of b into the sub-allocation (min 1 byte, so an empty input
// still yields a valid non-null pointer).
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

// call invokes a bound export; the single i32 result (0 for void exports) is
// returned as int32, since libsodium's convention is 0 = ok / -1 = failure.
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

// mustCall is call for a PRODUCING op whose failure is an invariant violation — a key or
// nonce of the wrong length, an arena too small for the output. libsodium signals that
// with -1 and leaves the output buffer UNTOUCHED, and the arena is reused across ops, so
// reading it anyway would hand the caller whatever the previous op left there (a secret
// key, a plaintext). Panic rather than an error return, because these callers pass lengths
// this process derived itself; an op that can fail on its INPUTS (crypto_scalarmult, the
// ed→curve conversions) checks the code itself and answers ok=false.
func (s *libsodium) mustCall(name string, args ...uint64) {
	if r := s.call(name, args...); r != 0 {
		panic(fmt.Sprintf("libsodium: %s returned %d (output not written)", name, r))
	}
}

// 64-bit length args are legalized to (lo, hi) i32 pairs in this build; our buffers
// are far under 4 GiB, so hi is always 0.
func lenArgs(n int) (lo, hi uint64) { return uint64(uint32(n)), 0 }

// ───────────────────────── the crypto ops ─────────────────────────

// genericHash is native Go BLAKE2b (see the file header) and the one system hash: the
// content-address block-id, the guest `HASH` op and the loader's genesis hash (§12.4) all
// route here. This build computes only the UNKEYED 32-byte digest; any other length is
// rejected loudly, because a quietly-wrong consensus-affecting hash is worse than a hard
// failure. (Keyed hashing is rejected at the JS seam, where the key would be dropped.)
func (s *libsodium) genericHash(outLen int, msg []byte) []byte {
	if outLen != 32 {
		panic(fmt.Sprintf("genericHash: native blake2b is 32-byte-only in this build, got %d", outLen))
	}
	h, err := blake2b.New(outLen, nil)
	if err != nil {
		panic(fmt.Sprintf("blake2b.New(%d): %v", outLen, err))
	}
	h.Write(msg)
	return h.Sum(nil)
}

func (s *libsodium) signDetached(msg, sk []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(len(msg)) + alignUp(len(sk)) + alignUp(64))
	in, skp, sig := s.takeIn(msg), s.takeIn(sk), s.take(64)
	lo, hi := lenArgs(len(msg))
	s.mustCall("crypto_sign_detached", uint64(sig), 0 /*siglen_p=NULL*/, uint64(in), lo, hi, uint64(skp))
	return s.read(sig, 64)
}

func (s *libsodium) verifyDetached(sig, msg, pk []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(len(sig)) + alignUp(len(msg)) + alignUp(len(pk)))
	sp, in, pkp := s.takeIn(sig), s.takeIn(msg), s.takeIn(pk)
	lo, hi := lenArgs(len(msg))
	return s.call("crypto_sign_verify_detached", uint64(sp), uint64(in), lo, hi, uint64(pkp)) == 0
}

// There is no separate public-key point check: Ed25519 verification is the one gate on
// every target, and a second one here alone would be the exact disagreement such a check
// exists to prevent (§12.6).

func (s *libsodium) signKeypair() (pk, sk []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(32) + alignUp(64))
	pkp, skp := s.take(32), s.take(64)
	s.mustCall("crypto_sign_keypair", uint64(pkp), uint64(skp))
	return s.read(pkp, 32), s.read(skp, 64)
}

func (s *libsodium) signSeedKeypair(seed []byte) (pk, sk []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(32) + alignUp(64) + alignUp(len(seed)))
	pkp, skp, sp := s.take(32), s.take(64), s.takeIn(seed)
	s.mustCall("crypto_sign_seed_keypair", uint64(pkp), uint64(skp), uint64(sp))
	return s.read(pkp, 32), s.read(skp, 64)
}

// edPkToCurve converts an Ed25519 public key to its X25519 counterpart. ok=false rather
// than a panic on -1: the input is somebody ELSE's key and libsodium refuses one that is
// not a canonical point — a data-dependent failure, not an invariant of ours. The output
// is read only on success (the arena otherwise still holds the previous op's bytes).
func (s *libsodium) edPkToCurve(edPk []byte) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(len(edPk)) + alignUp(32))
	in, out := s.takeIn(edPk), s.take(32)
	if s.call("crypto_sign_ed25519_pk_to_curve25519", uint64(out), uint64(in)) != 0 {
		return nil, false
	}
	return s.read(out, 32), true
}

// edSkToCurve is the secret-key half; same contract (see edPkToCurve).
func (s *libsodium) edSkToCurve(edSk []byte) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(len(edSk)) + alignUp(32))
	in, out := s.takeIn(edSk), s.take(32)
	if s.call("crypto_sign_ed25519_sk_to_curve25519", uint64(out), uint64(in)) != 0 {
		return nil, false
	}
	return s.read(out, 32), true
}

func (s *libsodium) boxSeal(msg, curvePk []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(len(msg)) + alignUp(len(curvePk)) + alignUp(len(msg)+sealBytes))
	in, pkp, out := s.takeIn(msg), s.takeIn(curvePk), s.take(len(msg)+sealBytes)
	lo, hi := lenArgs(len(msg))
	s.mustCall("crypto_box_seal", uint64(out), uint64(in), lo, hi, uint64(pkp))
	return s.read(out, len(msg)+sealBytes)
}

func (s *libsodium) boxSealOpen(ct, curvePk, curveSk []byte) ([]byte, bool) {
	if len(ct) < sealBytes {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(len(ct)) + alignUp(len(curvePk)) + alignUp(len(curveSk)) + alignUp(len(ct)-sealBytes))
	cp, pkp, skp := s.takeIn(ct), s.takeIn(curvePk), s.takeIn(curveSk)
	out := s.take(len(ct) - sealBytes)
	lo, hi := lenArgs(len(ct))
	if s.call("crypto_box_seal_open", uint64(out), uint64(cp), lo, hi, uint64(pkp), uint64(skp)) != 0 {
		return nil, false
	}
	return s.read(out, len(ct)-sealBytes), true
}

// ── §12.6 transport AKE primitives ──

// scalarmult computes the X25519 shared point q = n·p. Against the base point it is also
// the ephemeral public-key derivation, which is why the AKE needs no keypair primitive.
// ok=false on a low-order / all-zero result, which the handshake treats as failed —
// mirroring libsodium-wrappers throwing there.
func (s *libsodium) scalarmult(n, p []byte) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.arenaReset(alignUp(32) + alignUp(len(n)) + alignUp(len(p)))
	q, np, pp := s.take(32), s.takeIn(n), s.takeIn(p)
	if s.call("crypto_scalarmult", uint64(q), uint64(np), uint64(pp)) != 0 {
		return nil, false
	}
	return s.read(q, 32), true
}

// aeadEncrypt seals msg under (npub, key) with ChaCha20-Poly1305-IETF, no AAD; the result
// is msg ‖ 16-byte Poly1305 tag. Native Go, not libsodium (file header). npub/key are
// locally derived, so New/Seal can only fail on an invariant violation — panic, like the
// other primitives. No wasm scratch means no lock: per-connection goroutines seal
// concurrently.
func (s *libsodium) aeadEncrypt(msg, npub, key []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(fmt.Sprintf("chacha20poly1305.New: %v", err))
	}
	return aead.Seal(nil, npub, msg, nil)
}

// aeadDecrypt opens a ChaCha20-Poly1305-IETF record (native Go, see aeadEncrypt).
// ct is attacker-controlled, so a bad tag or a short ct is an ordinary open failure
// (ok=false, and PeerLink tears the link down); npub/key are ours, so a wrong length there
// is an invariant violation and panics.
func (s *libsodium) aeadDecrypt(ct, npub, key []byte) ([]byte, bool) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(fmt.Sprintf("chacha20poly1305.New: %v", err))
	}
	pt, err := aead.Open(nil, npub, ct, nil)
	if err != nil {
		return nil, false
	}
	return pt, true
}

// ───────────────────────── QuickJS exposure ─────────────────────────

// exposeSodium installs `__sodium` — the ArrayBuffer-returning byte primitives, and the
// whole of Go's crypto surface. Shaping them into the libsodium-wrappers API the shared
// code consumes is `wrapNativeSodium` in host/native-shim.ts, where it is typechecked
// against `ShellSodium`.
//
// Only what JS actually reaches is registered. The curve25519 conversions and
// crypto_box_seal have no caller above this seam (sodium_test.go exercises them directly),
// so they are not published into the realm.
func exposeSodium(qc *qjs.Context, s *libsodium) {
	o := qc.NewObject()

	o.SetPropertyStr("crypto_generichash", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		// crypto_generichash(hashLength, message, key?): the native blake2b shim computes
		// only the UNKEYED hash, so a key arg would be silently dropped — a plain hash
		// where libsodium computes a MAC.
		if len(t.Args()) > 2 && !t.Args()[2].IsNull() && !t.Args()[2].IsUndefined() {
			if k, _ := qjs.JsTypedArrayToGo(t.Args()[2]); len(k) > 0 {
				return nil, fmt.Errorf("crypto_generichash: keyed hashing not supported by the native blake2b shim")
			}
		}
		return bytesAB(t, s.genericHash(int(t.Args()[0].Int32()), argBytes(t, 1))), nil
	}))
	o.SetPropertyStr("crypto_sign_detached", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		return bytesAB(t, s.signDetached(argBytes(t, 0), argBytes(t, 1))), nil
	}))
	o.SetPropertyStr("crypto_sign_verify_detached", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewBool(s.verifyDetached(argBytes(t, 0), argBytes(t, 1), argBytes(t, 2))), nil
	}))
	o.SetPropertyStr("crypto_scalarmult", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		q, ok := s.scalarmult(argBytes(t, 0), argBytes(t, 1))
		if !ok {
			return t.Context().NewNull(), nil
		}
		return bytesAB(t, q), nil
	}))
	o.SetPropertyStr("crypto_aead_chacha20poly1305_ietf_encrypt", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		return bytesAB(t, s.aeadEncrypt(argBytes(t, 0), argBytes(t, 1), argBytes(t, 2))), nil
	}))
	o.SetPropertyStr("crypto_aead_chacha20poly1305_ietf_decrypt", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		pt, ok := s.aeadDecrypt(argBytes(t, 0), argBytes(t, 1), argBytes(t, 2))
		if !ok {
			return t.Context().NewNull(), nil
		}
		return bytesAB(t, pt), nil
	}))
	o.SetPropertyStr("crypto_sign_keypair", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		pk, skv := s.signKeypair()
		return keypairObj(t.Context(), pk, skv), nil
	}))
	o.SetPropertyStr("crypto_sign_seed_keypair", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		pk, skv := s.signSeedKeypair(argBytes(t, 0))
		return keypairObj(t.Context(), pk, skv), nil
	}))
	o.SetPropertyStr("randombytes_buf", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		b := make([]byte, t.Args()[0].Int32())
		crand.Read(b)
		return bytesAB(t, b), nil
	}))
	// The PQ half of the manifest suite hangs off the same object. It is part of the host
	// trust root because it verifies the bundles that deliver everything else.
	exposeMlDsa(qc, o, md)
	qc.Global().SetPropertyStr("__sodium", o)
}

func keypairObj(qc *qjs.Context, pk, sk []byte) *qjs.Value {
	o := qc.NewObject()
	o.SetPropertyStr("publicKey", qc.NewArrayBuffer(pk))
	o.SetPropertyStr("privateKey", qc.NewArrayBuffer(sk))
	return o
}
