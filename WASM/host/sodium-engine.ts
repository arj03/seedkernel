// The host's crypto (§12.9): the shared libsodium.wasm and mldsa65.wasm, run on the
// platform's engine table, under libsodium-wrappers' method names. The host carries its
// own crypto, so a fix to it ships with the host script; the loader only supplies
// entropy and the engine.
//
// Each operation stages its inputs with one write, makes one call and reads its outputs
// with one read: on the native target every engine call is a crossing out of the
// interpreted host realm, so the count matters more than the bytes.

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

// libsodium.wasm's minified export names, for the pinned build (browser/libsodium-core.mjs
// maps them; tests/crypto.test.mjs checks this table against it). Re-derive them, and the
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

/** Inputs laid out at 16-byte-aligned offsets from `base`, then room for the outputs:
 *  one buffer to write and the pointer to each part. */
function layout(base: number, inputs: (Uint8Array | null)[], outputs: number[]) {
  const align = (n: number) => (n + 15) & ~15;
  let at = 0;
  const inPtrs: number[] = [];
  for (const b of inputs) {
    inPtrs.push(base + at);
    at = align(at + Math.max(b ? b.length : 0, 1));
  }
  const staged = new Uint8Array(at);
  inputs.forEach((b, i) => { if (b) staged.set(b, inPtrs[i] - base); });
  const outPtrs: number[] = [];
  for (const n of outputs) {
    outPtrs.push(base + at);
    at = align(at + Math.max(n, 1));
  }
  return { staged, inPtrs, outPtrs, total: at };
}

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

  // One scratch block, grown to the largest operation so far and reused.
  let arena = 0, arenaCap = 0;
  const stage = (inputs: (Uint8Array | null)[], outputs: number[]) => {
    let plan = layout(arena, inputs, outputs);
    if (plan.total > arenaCap) {
      if (arena !== 0) fn.free(arena);
      arena = fn.malloc(plan.total);
      if (arena === 0) throw new Error(`libsodium: malloc(${plan.total}) failed`);
      arenaCap = plan.total;
      plan = layout(arena, inputs, outputs);
    }
    if (plan.staged.length > 0) lib.write(arena, plan.staged);
    return plan;
  };
  /** The outputs of one call, read together. */
  const outputs = (plan: { outPtrs: number[] }, lens: number[]): Uint8Array[] => {
    const first = plan.outPtrs[0], last = plan.outPtrs[lens.length - 1] + lens[lens.length - 1];
    const span = lib.read(first, last - first);
    return lens.map((n, i) => span.slice(plan.outPtrs[i] - first, plan.outPtrs[i] - first + n));
  };
  const keypair = (seed: Uint8Array | null): Keypair => {
    const p = stage(seed ? [seed] : [], [32, 64]);
    const r = seed ? fn.crypto_sign_seed_keypair(p.outPtrs[0], p.outPtrs[1], p.inPtrs[0])
      : fn.crypto_sign_keypair(p.outPtrs[0], p.outPtrs[1]);
    if (r !== 0) throw new Error("crypto_sign_keypair failed");
    const [publicKey, privateKey] = outputs(p, [32, 64]);
    return { publicKey, privateKey };
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
    crypto_generichash(len, message, key) {
      const k = key && key.length > 0 ? key : null;
      const p = stage([message, k], [len]);
      if (fn.crypto_generichash(p.outPtrs[0], len, p.inPtrs[0], message.length, 0,
        k ? p.inPtrs[1] : 0, k ? k.length : 0) !== 0) {
        throw new Error("crypto_generichash: invalid output or key length");
      }
      return outputs(p, [len])[0];
    },
    crypto_sign_detached(message, sk) {
      if (sk.length !== 64) throw new Error("crypto_sign_detached: secret key must be 64 bytes");
      const p = stage([message, sk], [64]);
      if (fn.crypto_sign_detached(p.outPtrs[0], 0, p.inPtrs[0], message.length, 0, p.inPtrs[1]) !== 0) {
        throw new Error("crypto_sign_detached failed");
      }
      return outputs(p, [64])[0];
    },
    crypto_sign_verify_detached(sig, message, pk) {
      // Fixed widths cross without lengths, so check them before staging.
      if (sig.length !== 64 || pk.length !== 32) return false;
      const p = stage([sig, message, pk], []);
      return fn.crypto_sign_verify_detached(p.inPtrs[0], p.inPtrs[1], message.length, 0, p.inPtrs[2]) === 0;
    },
    crypto_sign_keypair: () => keypair(null),
    crypto_sign_seed_keypair(seed) {
      if (seed.length !== 32) throw new Error("crypto_sign_seed_keypair: seed must be 32 bytes");
      return keypair(seed);
    },
    crypto_scalarmult(n, pt) {
      if (n.length !== 32 || pt.length !== 32) throw new Error("crypto_scalarmult: inputs must be 32 bytes");
      const p = stage([n, pt], [32]);
      if (fn.crypto_scalarmult(p.outPtrs[0], p.inPtrs[0], p.inPtrs[1]) !== 0) {
        throw new Error("crypto_scalarmult: unexpected result of the multiplication");
      }
      return outputs(p, [32])[0];
    },
    crypto_aead_chacha20poly1305_ietf_encrypt(message, ad, _nsec, npub, key) {
      const a = ad && ad.length > 0 ? ad : null;
      const p = stage([message, a, npub, key], [message.length + AEAD_TAG]);
      if (fn.crypto_aead_chacha20poly1305_ietf_encrypt(p.outPtrs[0], 0, p.inPtrs[0], message.length, 0,
        a ? p.inPtrs[1] : 0, a ? a.length : 0, 0, 0, p.inPtrs[2], p.inPtrs[3]) !== 0) {
        throw new Error("crypto_aead_chacha20poly1305_ietf_encrypt failed");
      }
      return outputs(p, [message.length + AEAD_TAG])[0];
    },
    crypto_aead_chacha20poly1305_ietf_decrypt(_nsec, ciphertext, ad, npub, key) {
      if (ciphertext.length < AEAD_TAG) throw new Error("crypto_aead_chacha20poly1305_ietf_decrypt: verification failed");
      const a = ad && ad.length > 0 ? ad : null;
      const n = ciphertext.length - AEAD_TAG;
      const p = stage([ciphertext, a, npub, key], [n]);
      if (fn.crypto_aead_chacha20poly1305_ietf_decrypt(p.outPtrs[0], 0, 0, p.inPtrs[0], ciphertext.length, 0,
        a ? p.inPtrs[1] : 0, a ? a.length : 0, 0, p.inPtrs[2], p.inPtrs[3]) !== 0) {
        throw new Error("crypto_aead_chacha20poly1305_ietf_decrypt: verification failed");
      }
      return outputs(p, [n])[0];
    },
    randombytes_buf: random,
    ml_dsa65_verify_detached(sig, message, pk) {
      // Never throws: a wrong-width key or signature is just invalid, as for Ed25519.
      if (sig.length !== ML_DSA65_SIG_LEN || pk.length !== ML_DSA65_PK_LEN) return false;
      const p = layout(pqBase, [sig, message, pk], []);
      const short = pqBase + p.total - pq.grow(0) * PAGE;
      if (short > 0 && pq.grow(Math.ceil(short / PAGE)) < 0) return false;
      pq.write(pqBase, p.staged);
      // ctx = (0, 0): the runtime signs with an empty FIPS 204 context; its domain separation
      // is inside the preimage (§16.1).
      return mldsaVerify(p.inPtrs[0], p.inPtrs[1], message.length, 0, 0, p.inPtrs[2]) === 1;
    },
  };
}
