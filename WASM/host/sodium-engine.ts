// The host's crypto (§12.9): the shared libsodium.wasm and mldsa65.wasm, run on the
// platform's engine table, under libsodium-wrappers' method names. The host carries its
// own crypto, so a fix to it ships with the host script; the loader only supplies
// entropy and the engine.
//
// Each operation writes its inputs at offsets it computes in a scratch block, makes one
// call and reads its output with one read. On the native target this side is interpreted
// while a crossing is a fraction of a microsecond, so the work saved is JS work: no
// arrays, closures or copies to lay an operation out.

import type { EngineExport, EngineInstance, EngineImports } from "./engine-realm.js";
import type { Keypair } from "../services/subkeys.js";
import type { ShellSodium } from "./shell-core.js";
import { ML_DSA65_PK_LEN, ML_DSA65_SIG_LEN, ML_DSA65_SK_LEN } from "./pq.js";

/** An engine table that instantiates synchronously, as every loader's does. */
export type SyncEngine = (wasm: Uint8Array, imports: EngineImports) => EngineInstance;

/** `ShellSodium` plus the keypair producers a node's identity comes from. */
export interface HostSodium extends ShellSodium {
  crypto_sign_keypair(): Keypair;
  crypto_sign_seed_keypair(seed: Uint8Array): Keypair;
}

// libsodium.wasm's minified export names, for the pinned build (the libsodium npm dist's
// glue maps them; tests/crypto.test.mjs checks this table against it). Re-derive them, and the
// two EM_JS entropy addresses, if libsodium.wasm is rebuilt.
const EXPORTS = {
  malloc: "Ee", free: "Fe", sodium_init: "xe",
  crypto_generichash: "Ja",
  crypto_sign_detached: "wd", crypto_sign_verify_detached: "xd",
  crypto_sign_keypair: "td", crypto_sign_seed_keypair: "sd",
  crypto_scalarmult: "Jc",
  crypto_aead_chacha20poly1305_ietf_encrypt: "D", crypto_aead_chacha20poly1305_ietf_decrypt: "H",
} as const;
export const SODIUM_EXPORTS: Readonly<Record<keyof typeof EXPORTS, string>> = EXPORTS;
/** The EM_JS snippets randombytes reaches through import `a.b`: one random word, and the
 *  RNG's lazy init. */
const RAND_U32 = 40216, RAND_INIT = 40252;
const AEAD_TAG = 16;
const PAGE = 65536;

/** libsodium plus the ML-DSA-65 verifier over `engine`. `random` is the platform CSPRNG. */
export function engineSodium(engine: SyncEngine, sodiumWasm: Uint8Array, mldsaWasm: Uint8Array,
  random: (n: number) => Uint8Array): HostSodium {
  // ── libsodium ──
  let lib!: EngineInstance;
  lib = engine(sodiumWasm, {
    a: {
      a: () => { throw new Error("libsodium: assertion failed"); },
      b: (code) => {
        if (code === RAND_INIT) return 0;
        if (code !== RAND_U32) throw new Error(`libsodium: unexpected asm-const code ${code}`);
        const w = random(4);
        return w[0] | (w[1] << 8) | (w[2] << 16) | (w[3] << 24);
      },
      c: () => { throw new Error("libsodium: abort"); },
      // emscripten_resize_heap(requestedBytes): grow linear memory to fit.
      d: (requested) => {
        const want = requested >>> 0, have = lib.grow(0) * PAGE;
        return want <= have || lib.grow(Math.ceil((want - have) / PAGE)) >= 0 ? 1 : 0;
      },
    },
  });
  const fn = {} as Record<keyof typeof EXPORTS, EngineExport>;
  for (const [name, min] of Object.entries(EXPORTS)) fn[name as keyof typeof EXPORTS] = lib.exported(min);
  if (fn.sodium_init() < 0) throw new Error("libsodium: sodium_init failed");

  // One scratch block, grown to the largest operation so far and reused. Each operation
  // lays its fixed-width parts out first and its variable ones after, at offsets it adds
  // up itself, and writes each part where it goes.
  let arena = 0, arenaCap = 0;
  /** The scratch block, holding at least `n` bytes. */
  const scratch = (n: number): number => {
    if (n > arenaCap) {
      if (arena !== 0) fn.free(arena);
      arena = fn.malloc(n);
      if (arena === 0) throw new Error(`libsodium: malloc(${n}) failed`);
      arenaCap = n;
    }
    return arena;
  };
  /** Write `bytes` at `ptr` unless there are none, which saves the crossing. */
  const put = (ptr: number, bytes: Uint8Array): void => {
    if (bytes.length > 0) lib.write(ptr, bytes);
  };
  // [pk 32][sk 64][seed 32]
  const keypair = (seed: Uint8Array | null): Keypair => {
    const at = scratch(128);
    if (seed) lib.write(at + 96, seed);
    const r = seed ? fn.crypto_sign_seed_keypair(at, at + 32, at + 96) : fn.crypto_sign_keypair(at, at + 32);
    if (r !== 0) throw new Error("crypto_sign_keypair failed");
    const both = lib.read(at, 96);
    return { publicKey: both.slice(0, 32), privateKey: both.slice(32) };
  };

  // ── ML-DSA-65 ──
  const pq = engine(mldsaWasm, {});
  const mldsaVerify = pq.exported("mldsa65_verify");
  const widths: [string, number, number][] = [
    ["public key", pq.exported("mldsa65_publickeybytes")(), ML_DSA65_PK_LEN],
    ["secret key", pq.exported("mldsa65_secretkeybytes")(), ML_DSA65_SK_LEN],
    ["signature", pq.exported("mldsa65_signaturebytes")(), ML_DSA65_SIG_LEN],
  ];
  for (const [what, got, want] of widths) {
    if (got !== want) throw new Error(`pq: mldsa65.wasm reports ${what} width ${got}, expected ${want}`);
  }
  // The module never allocates and keeps nothing between calls, so its inputs go on its
  // heap, from the base each time.
  const pqBase = pq.global("__heap_base");
  if (pqBase === null) throw new Error("pq: mldsa65.wasm exports no __heap_base");

  return {
    // [out len][key][message]
    crypto_generichash(len, message, key) {
      const keyLen = key ? key.length : 0;
      const out = scratch(len + keyLen + message.length), m = out + len + keyLen;
      if (key) put(out + len, key);
      put(m, message);
      if (fn.crypto_generichash(out, len, m, message.length, 0, keyLen > 0 ? out + len : 0, keyLen) !== 0) {
        throw new Error("crypto_generichash: invalid output or key length");
      }
      return lib.read(out, len);
    },
    // [sk 64][sig 64][message]
    crypto_sign_detached(message, sk) {
      if (sk.length !== 64) throw new Error("crypto_sign_detached: secret key must be 64 bytes");
      const at = scratch(128 + message.length);
      lib.write(at, sk);
      put(at + 128, message);
      if (fn.crypto_sign_detached(at + 64, 0, at + 128, message.length, 0, at) !== 0) {
        throw new Error("crypto_sign_detached failed");
      }
      return lib.read(at + 64, 64);
    },
    // [sig 64][pk 32][message]
    crypto_sign_verify_detached(sig, message, pk) {
      // Fixed widths cross without lengths, so check them before writing.
      if (sig.length !== 64 || pk.length !== 32) return false;
      const at = scratch(96 + message.length);
      lib.write(at, sig);
      lib.write(at + 64, pk);
      put(at + 96, message);
      return fn.crypto_sign_verify_detached(at, at + 96, message.length, 0, at + 64) === 0;
    },
    crypto_sign_keypair: () => keypair(null),
    crypto_sign_seed_keypair(seed) {
      if (seed.length !== 32) throw new Error("crypto_sign_seed_keypair: seed must be 32 bytes");
      return keypair(seed);
    },
    // [n 32][pt 32][out 32]
    crypto_scalarmult(n, pt) {
      if (n.length !== 32 || pt.length !== 32) throw new Error("crypto_scalarmult: inputs must be 32 bytes");
      const at = scratch(96);
      lib.write(at, n);
      lib.write(at + 32, pt);
      if (fn.crypto_scalarmult(at + 64, at, at + 32) !== 0) {
        throw new Error("crypto_scalarmult: unexpected result of the multiplication");
      }
      return lib.read(at + 64, 32);
    },
    // [key 32][npub 16][ad][message][out]
    crypto_aead_chacha20poly1305_ietf_encrypt(message, ad, _nsec, npub, key) {
      const adLen = ad ? ad.length : 0, n = message.length;
      const at = scratch(48 + adLen + 2 * n + AEAD_TAG), m = at + 48 + adLen, out = m + n;
      lib.write(at, key);
      lib.write(at + 32, npub);
      if (ad) put(at + 48, ad);
      put(m, message);
      if (fn.crypto_aead_chacha20poly1305_ietf_encrypt(out, 0, m, n, 0,
        adLen > 0 ? at + 48 : 0, adLen, 0, 0, at + 32, at) !== 0) {
        throw new Error("crypto_aead_chacha20poly1305_ietf_encrypt failed");
      }
      return lib.read(out, n + AEAD_TAG);
    },
    // [key 32][npub 16][ad][ciphertext][out]
    crypto_aead_chacha20poly1305_ietf_decrypt(_nsec, ciphertext, ad, npub, key) {
      if (ciphertext.length < AEAD_TAG) throw new Error("crypto_aead_chacha20poly1305_ietf_decrypt: verification failed");
      const adLen = ad ? ad.length : 0, n = ciphertext.length - AEAD_TAG;
      const at = scratch(48 + adLen + ciphertext.length + n), c = at + 48 + adLen, out = c + ciphertext.length;
      lib.write(at, key);
      lib.write(at + 32, npub);
      if (ad) put(at + 48, ad);
      lib.write(c, ciphertext);
      if (fn.crypto_aead_chacha20poly1305_ietf_decrypt(out, 0, 0, c, ciphertext.length, 0,
        adLen > 0 ? at + 48 : 0, adLen, 0, at + 32, at) !== 0) {
        throw new Error("crypto_aead_chacha20poly1305_ietf_decrypt: verification failed");
      }
      return lib.read(out, n);
    },
    randombytes_buf: random,
    // [sig][pk][message], from the heap base each time.
    ml_dsa65_verify_detached(sig, message, pk) {
      // Never throws: a wrong-width key or signature is just invalid, as for Ed25519.
      if (sig.length !== ML_DSA65_SIG_LEN || pk.length !== ML_DSA65_PK_LEN) return false;
      const k = pqBase + ML_DSA65_SIG_LEN, m = k + ML_DSA65_PK_LEN;
      const short = m + message.length - pq.grow(0) * PAGE;
      if (short > 0 && pq.grow(Math.ceil(short / PAGE)) < 0) return false;
      pq.write(pqBase, sig);
      pq.write(k, pk);
      if (message.length > 0) pq.write(m, message);
      // ctx = (0, 0): the runtime signs with an empty FIPS 204 context; its domain separation
      // is inside the preimage (§16.1).
      return mldsaVerify(pqBase, m, message.length, 0, 0, k) === 1;
    },
  };
}
