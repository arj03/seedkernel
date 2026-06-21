// sodium.go — the Go target's crypto *primitive*: the same browser/libsodium.wasm,
// driven over wazero. Mostly not Go-native crypto. The point is interop: a Go node's
// sealed boxes / ed25519→curve25519 conversions / xchacha20 blocks must be
// byte-identical to a Bun node's, which only the exact same libsodium binary
// guarantees. This file is the FFI seam over the emscripten ABI (malloc / copy-in /
// call / copy-out) plus a `sodium` object into the QuickJS realm carrying
// libsodium-wrappers method names — so the shared host JS (and, later, cap-bridge.ts)
// calls `sodium.*` unchanged.
//
// The one exception is genericHash (BLAKE2b-256, the content-address block-id hash):
// it runs on native Go (golang.org/x/crypto/blake2b). Unkeyed BLAKE2b-256 is fully
// standardized, so native output is byte-identical to libsodium's (pinned by a KAT in
// TestSodiumGenericHash) — but it's on the storage data path (every block hashed on
// PUT, verified on bulk receive, §13.6) and it's the one primitive wazero runs the
// wasm materially slower than V8, so native (~600 vs ~390 MB/s) is the clear win.
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
)

//go:embed wasm/libsodium.wasm
var sodiumWasm []byte

// libsodium drives the embedded emscripten build. Its exports are minified; the
// real-name → minified-export map (and the two EM_JS entropy code addresses below)
// are read from browser/libsodium-core.mjs. Re-derive both if libsodium.wasm is
// ever rebuilt (`<name>=A.<minified>` for the funcs; `d={<addr>:…}` for entropy).
type libsodium struct {
	mod api.Module
	mem api.Memory
	fns map[string]api.Function
	// One shared scratch heap + allocator means an op is a malloc/call/read/free
	// sequence that must not interleave with another. The net stack (net.go) now
	// drives sign/verify from per-connection goroutines and the kernel's
	// env.ed25519_verify from the main thread, so every op takes this lock. Held
	// only for the duration of one op — never across a callback into JS or Go.
	mu sync.Mutex
}

var sd *libsodium // the process-wide libsodium instance (genesis verify + sodium.*)

// real libsodium name → minified wasm export, for the pinned browser/libsodium.wasm.
var sodiumExports = map[string]string{
	"malloc":                               "lm",
	"free":                                 "mm",
	"sodium_init":                          "Uj",
	"crypto_hash_sha3256":                  "Zc",
	"crypto_generichash":                   "kc",
	"crypto_stream_xchacha20_xor":          "jm",
	"crypto_sign_detached":                 "Nh",
	"crypto_sign_verify_detached":          "Oh",
	"crypto_sign_keypair":                  "Kh",
	"crypto_sign_seed_keypair":             "Jh",
	"crypto_sign_ed25519_pk_to_curve25519": "fi",
	"crypto_sign_ed25519_sk_to_curve25519": "gi",
	"crypto_box_seal":                      "gb",
	"crypto_box_seal_open":                 "hb",
}

// EM_JS entropy snippet code addresses (libsodium-core.mjs `d={…}`): randombytes
// routes through the asm-const import `a.b`; the only snippets in this build are
// these two. We satisfy them from crypto/rand (the entropy source need not match
// across nodes — only its consumers' deterministic structure does).
const (
	sodiumRandU32  = 40712 // ()->u32: one random word
	sodiumRandInit = 40748 // ()->void: lazy RNG init (a no-op here)
)

const sealBytes = 48 // crypto_box_SEALBYTES (ephemeral pk 32 + MAC 16)

// bootSodium wires the four emscripten host imports (module "a"), instantiates
// libsodium.wasm, binds the exports we use, and runs sodium_init — mirroring what
// libsodium-wrappers does after load.
func bootSodium(rt wazero.Runtime) *libsodium {
	a := rt.NewHostModuleBuilder("a")
	// a.a — __assert_fail(cond,file,line,func): only reached on a libsodium bug.
	a.NewFunctionBuilder().WithFunc(func(_ context.Context, _ api.Module, _, _, _, _ uint32) {
		panic("libsodium: assertion failed")
	}).Export("a")
	// a.b — _emscripten_asm_const_int(code,sig,args): the EM_JS dispatcher. In this
	// build it only ever runs the two entropy snippets, both argument-free.
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

// copyIn allocates a buffer holding b (min 1 byte so the pointer is non-null even
// for an empty input) and returns its pointer. Free it with free.
func (s *libsodium) copyIn(b []byte) uint32 {
	n := len(b)
	if n == 0 {
		n = 1
	}
	p := s.malloc(n)
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

// 64-bit length args are legalized to (lo, hi) i32 pairs in this build; our buffers
// are far under 4 GiB, so hi is always 0.
func lenArgs(n int) (lo, hi uint64) { return uint64(uint32(n)), 0 }

// ───────────────────────── the crypto ops ─────────────────────────

func (s *libsodium) hashSha3256(msg []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, out := s.copyIn(msg), s.malloc(32)
	defer s.free(in)
	defer s.free(out)
	lo, hi := lenArgs(len(msg))
	s.call("crypto_hash_sha3256", uint64(out), uint64(in), lo, hi)
	return s.read(out, 32)
}

// genericHash is native Go BLAKE2b (not libsodium) — see the file header. This build
// only ever computes the UNKEYED, 32-byte digest (the content-address block-id), which
// is KAT-pinned byte-identical to libsodium. Reject any other length loudly: 1–15
// diverges from libsodium's BYTES_MIN, and 0/>64 would panic inside blake2b.New — a
// quietly-wrong, consensus-affecting hash is worse than a hard failure. (Keyed hashing
// is rejected at the JS seam, where the key would otherwise be silently dropped.)
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

func (s *libsodium) streamXor(msg, nonce, key []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, np, kp := s.copyIn(msg), s.copyIn(nonce), s.copyIn(key)
	out := s.malloc(max(len(msg), 1))
	defer s.free(in)
	defer s.free(np)
	defer s.free(kp)
	defer s.free(out)
	lo, hi := lenArgs(len(msg))
	s.call("crypto_stream_xchacha20_xor", uint64(out), uint64(in), lo, hi, uint64(np), uint64(kp))
	return s.read(out, len(msg))
}

func (s *libsodium) signDetached(msg, sk []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, skp, sig := s.copyIn(msg), s.copyIn(sk), s.malloc(64)
	defer s.free(in)
	defer s.free(skp)
	defer s.free(sig)
	lo, hi := lenArgs(len(msg))
	s.call("crypto_sign_detached", uint64(sig), 0 /*siglen_p=NULL*/, uint64(in), lo, hi, uint64(skp))
	return s.read(sig, 64)
}

func (s *libsodium) verifyDetached(sig, msg, pk []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sp, in, pkp := s.copyIn(sig), s.copyIn(msg), s.copyIn(pk)
	defer s.free(sp)
	defer s.free(in)
	defer s.free(pkp)
	lo, hi := lenArgs(len(msg))
	return s.call("crypto_sign_verify_detached", uint64(sp), uint64(in), lo, hi, uint64(pkp)) == 0
}

func (s *libsodium) signKeypair() (pk, sk []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pkp, skp := s.malloc(32), s.malloc(64)
	defer s.free(pkp)
	defer s.free(skp)
	s.call("crypto_sign_keypair", uint64(pkp), uint64(skp))
	return s.read(pkp, 32), s.read(skp, 64)
}

func (s *libsodium) signSeedKeypair(seed []byte) (pk, sk []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pkp, skp, sp := s.malloc(32), s.malloc(64), s.copyIn(seed)
	defer s.free(pkp)
	defer s.free(skp)
	defer s.free(sp)
	s.call("crypto_sign_seed_keypair", uint64(pkp), uint64(skp), uint64(sp))
	return s.read(pkp, 32), s.read(skp, 64)
}

func (s *libsodium) edPkToCurve(edPk []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, out := s.copyIn(edPk), s.malloc(32)
	defer s.free(in)
	defer s.free(out)
	s.call("crypto_sign_ed25519_pk_to_curve25519", uint64(out), uint64(in))
	return s.read(out, 32)
}

func (s *libsodium) edSkToCurve(edSk []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, out := s.copyIn(edSk), s.malloc(32)
	defer s.free(in)
	defer s.free(out)
	s.call("crypto_sign_ed25519_sk_to_curve25519", uint64(out), uint64(in))
	return s.read(out, 32)
}

func (s *libsodium) boxSeal(msg, curvePk []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, pkp, out := s.copyIn(msg), s.copyIn(curvePk), s.malloc(len(msg)+sealBytes)
	defer s.free(in)
	defer s.free(pkp)
	defer s.free(out)
	lo, hi := lenArgs(len(msg))
	s.call("crypto_box_seal", uint64(out), uint64(in), lo, hi, uint64(pkp))
	return s.read(out, len(msg)+sealBytes)
}

func (s *libsodium) boxSealOpen(ct, curvePk, curveSk []byte) ([]byte, bool) {
	if len(ct) < sealBytes {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp, pkp, skp := s.copyIn(ct), s.copyIn(curvePk), s.copyIn(curveSk)
	out := s.malloc(max(len(ct)-sealBytes, 1))
	defer s.free(cp)
	defer s.free(pkp)
	defer s.free(skp)
	defer s.free(out)
	lo, hi := lenArgs(len(ct))
	if s.call("crypto_box_seal_open", uint64(out), uint64(cp), lo, hi, uint64(pkp), uint64(skp)) != 0 {
		return nil, false
	}
	return s.read(out, len(ct)-sealBytes), true
}

// ───────────────────────── QuickJS exposure ─────────────────────────

// exposeSodium installs `__sodium` (ArrayBuffer-returning primitives) into the
// realm; sodiumShimJS then wraps it as `sodium` with libsodium-wrappers semantics
// (Uint8Array results, the {publicKey,privateKey,keyType} keypair shape). Keeping
// the byte primitives in Go and the API shaping in JS follows the project rule:
// Go grows with primitives, the reusable shape lives in JS.
func exposeSodium(qc *qjs.Context, s *libsodium) {
	o := qc.NewObject()
	fn := func(g func(*qjs.This) (*qjs.Value, error)) *qjs.Value { return qc.Function(g) }
	arg := func(t *qjs.This, i int) []byte { b, _ := qjs.JsTypedArrayToGo(t.Args()[i]); return b }
	ab := func(t *qjs.This, b []byte) *qjs.Value { return t.Context().NewArrayBuffer(b) }

	o.SetPropertyStr("crypto_hash_sha3256", fn(func(t *qjs.This) (*qjs.Value, error) {
		return ab(t, s.hashSha3256(arg(t, 0))), nil
	}))
	o.SetPropertyStr("crypto_generichash", fn(func(t *qjs.This) (*qjs.Value, error) {
		// libsodium-wrappers is crypto_generichash(hashLength, message, key?). The native
		// blake2b shim computes only the UNKEYED hash, so a key arg would be SILENTLY
		// dropped — a plain hash where libsodium computes a MAC. Reject it loudly instead.
		if len(t.Args()) > 2 && !t.Args()[2].IsNull() && !t.Args()[2].IsUndefined() {
			if k, _ := qjs.JsTypedArrayToGo(t.Args()[2]); len(k) > 0 {
				return nil, fmt.Errorf("crypto_generichash: keyed hashing not supported by the native blake2b shim")
			}
		}
		return ab(t, s.genericHash(int(t.Args()[0].Int32()), arg(t, 1))), nil
	}))
	o.SetPropertyStr("crypto_stream_xchacha20_xor", fn(func(t *qjs.This) (*qjs.Value, error) {
		return ab(t, s.streamXor(arg(t, 0), arg(t, 1), arg(t, 2))), nil
	}))
	o.SetPropertyStr("crypto_sign_detached", fn(func(t *qjs.This) (*qjs.Value, error) {
		return ab(t, s.signDetached(arg(t, 0), arg(t, 1))), nil
	}))
	o.SetPropertyStr("crypto_sign_verify_detached", fn(func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewBool(s.verifyDetached(arg(t, 0), arg(t, 1), arg(t, 2))), nil
	}))
	o.SetPropertyStr("crypto_sign_ed25519_pk_to_curve25519", fn(func(t *qjs.This) (*qjs.Value, error) {
		return ab(t, s.edPkToCurve(arg(t, 0))), nil
	}))
	o.SetPropertyStr("crypto_sign_ed25519_sk_to_curve25519", fn(func(t *qjs.This) (*qjs.Value, error) {
		return ab(t, s.edSkToCurve(arg(t, 0))), nil
	}))
	o.SetPropertyStr("crypto_box_seal", fn(func(t *qjs.This) (*qjs.Value, error) {
		return ab(t, s.boxSeal(arg(t, 0), arg(t, 1))), nil
	}))
	o.SetPropertyStr("crypto_box_seal_open", fn(func(t *qjs.This) (*qjs.Value, error) {
		pt, ok := s.boxSealOpen(arg(t, 0), arg(t, 1), arg(t, 2))
		if !ok {
			return t.Context().NewNull(), nil
		}
		return ab(t, pt), nil
	}))
	o.SetPropertyStr("crypto_sign_keypair", fn(func(t *qjs.This) (*qjs.Value, error) {
		pk, skv := s.signKeypair()
		return keypairObj(t.Context(), pk, skv), nil
	}))
	o.SetPropertyStr("crypto_sign_seed_keypair", fn(func(t *qjs.This) (*qjs.Value, error) {
		pk, skv := s.signSeedKeypair(arg(t, 0))
		return keypairObj(t.Context(), pk, skv), nil
	}))
	o.SetPropertyStr("randombytes_buf", fn(func(t *qjs.This) (*qjs.Value, error) {
		b := make([]byte, t.Args()[0].Int32())
		crand.Read(b)
		return ab(t, b), nil
	}))
	qc.Global().SetPropertyStr("__sodium", o)
	if _, err := qc.Eval("sodium-shim.js", qjs.Code(sodiumShimJS)); err != nil {
		panic(fmt.Sprintf("sodium shim: %v", err))
	}
}

func keypairObj(qc *qjs.Context, pk, sk []byte) *qjs.Value {
	o := qc.NewObject()
	o.SetPropertyStr("publicKey", qc.NewArrayBuffer(pk))
	o.SetPropertyStr("privateKey", qc.NewArrayBuffer(sk))
	return o
}

// sodiumShimJS shapes the Go primitives into the libsodium-wrappers surface the
// shared host JS expects: byte results as Uint8Array, keypairs as
// {publicKey,privateKey,keyType}, and crypto_box_seal_open throwing on failure.
const sodiumShimJS = `
"use strict";
(function () {
  const N = __sodium;
  const u8 = (b) => new Uint8Array(b);
  globalThis.sodium = {
    crypto_hash_sha3256: (m) => u8(N.crypto_hash_sha3256(m)),
    crypto_generichash: (len, m) => u8(N.crypto_generichash(len, m)),
    crypto_stream_xchacha20_xor: (m, nonce, key) => u8(N.crypto_stream_xchacha20_xor(m, nonce, key)),
    crypto_sign_detached: (m, sk) => u8(N.crypto_sign_detached(m, sk)),
    crypto_sign_verify_detached: (sig, m, pk) => N.crypto_sign_verify_detached(sig, m, pk),
    crypto_sign_ed25519_pk_to_curve25519: (pk) => u8(N.crypto_sign_ed25519_pk_to_curve25519(pk)),
    crypto_sign_ed25519_sk_to_curve25519: (sk) => u8(N.crypto_sign_ed25519_sk_to_curve25519(sk)),
    crypto_box_seal: (m, pk) => u8(N.crypto_box_seal(m, pk)),
    crypto_box_seal_open: (c, pk, sk) => {
      const r = N.crypto_box_seal_open(c, pk, sk);
      if (r === null) throw new Error("crypto_box_seal_open: incorrect key pair for the given ciphertext");
      return u8(r);
    },
    crypto_sign_keypair: () => {
      const k = N.crypto_sign_keypair();
      return { publicKey: u8(k.publicKey), privateKey: u8(k.privateKey), keyType: "ed25519" };
    },
    crypto_sign_seed_keypair: (seed) => {
      const k = N.crypto_sign_seed_keypair(seed);
      return { publicKey: u8(k.publicKey), privateKey: u8(k.privateKey), keyType: "ed25519" };
    },
    randombytes_buf: (n) => u8(N.randombytes_buf(n)),
  };
})();
`
