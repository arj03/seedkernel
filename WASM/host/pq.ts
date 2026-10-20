// The post-quantum half of the hybrid manifest suite (§12.4, §14.1): ML-DSA-65 (FIPS 204)
// from browser/mldsa65.wasm, under libsodium-wrappers-style method names so it sits on the
// same `sodium` object as Ed25519 (sodium-engine.ts).
//
// The driver runs the module on the platform's engine table. The field widths below are
// format constants of the suite (bundle.ts has its own copy); they are here so the driver
// can check them against the module at load.
//
// One implementation on all three targets: the wasm is built from pinned mldsa-native
// (scripts/build-mldsa.mjs) and the same bytes run in the browser, in Node and in wazero,
// on each target's engine table. Where a verifier accepts or rejects is consensus, and two independent
// lattice implementations can disagree at the edges while both pass their own tests.
//
// This file imports only a type (the caller hands it the instance), so it loads as plain
// ESM in the browser and evaluates in QuickJS on the native target.

import type { EngineInstance } from "./engine-realm.js";

/** FIPS 204 ML-DSA-65 field widths. The manifest envelope is fixed-width per suite
 *  (§12.4), so these are format constants. `createMlDsa65` checks them against the
 *  module's exports at load. */
export const ML_DSA65_PK_LEN = 1952;
export const ML_DSA65_SK_LEN = 4032;
export const ML_DSA65_SIG_LEN = 3309;
export const ML_DSA65_SEED_LEN = 32;
export const ML_DSA65_RND_LEN = 32;

const PAGE = 65536;

/** The verify half, which is all install needs (§12.4). Named and ordered like
 *  `crypto_sign_verify_detached`, which sits on the same object. */
export interface MlDsa65Verifier {
  ml_dsa65_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
}

/** The sign half, used when building bundles. */
export interface MlDsa65Signer extends MlDsa65Verifier {
  ml_dsa65_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  ml_dsa65_keypair_from_seed(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
}

/** ML-DSA-65 over an instance of mldsa65.wasm (pq/shim.c). `random` is the platform
 *  CSPRNG, for the hedging randomness FIPS 204 mixes into a signature, so the module needs
 *  no imports; unlike verification, that need not match across nodes. */
export function createMlDsa65(pq: EngineInstance, random: (n: number) => Uint8Array): MlDsa65Signer {
  // Fail at load, not at first verify: a module built for another parameter set would
  // otherwise look fine until it rejected a real bundle as a bad signature.
  const widths: [string, number, number][] = [
    ["public key", pq.exported("mldsa65_publickeybytes")(), ML_DSA65_PK_LEN],
    ["secret key", pq.exported("mldsa65_secretkeybytes")(), ML_DSA65_SK_LEN],
    ["signature", pq.exported("mldsa65_signaturebytes")(), ML_DSA65_SIG_LEN],
  ];
  for (const [what, got, want] of widths) {
    if (got !== want) throw new Error(`pq: mldsa65.wasm reports ${what} width ${got}, expected ${want}`);
  }
  const verify = pq.exported("mldsa65_verify");
  const sign = pq.exported("mldsa65_sign");
  const keypair = pq.exported("mldsa65_keypair");
  // The module never allocates and keeps nothing between calls, so each call lays its
  // buffers out on its heap, from the base each time.
  const base = pq.global("__heap_base");
  if (base === null) throw new Error("pq: mldsa65.wasm exports no __heap_base");
  /** Grow linear memory to `end` bytes, answering whether it could. */
  const fits = (end: number): boolean => {
    const short = end - pq.grow(0) * PAGE;
    return short <= 0 || pq.grow(Math.ceil(short / PAGE)) >= 0;
  };

  return {
    // [sig][pk][message]
    ml_dsa65_verify_detached(sig, message, pk) {
      // Never throws: a wrong-width key or signature is just invalid, as with
      // `crypto_sign_verify_detached`, so both halves of the suite fail the same way.
      if (sig.length !== ML_DSA65_SIG_LEN || pk.length !== ML_DSA65_PK_LEN) return false;
      const k = base + ML_DSA65_SIG_LEN, m = k + ML_DSA65_PK_LEN;
      if (!fits(m + message.length)) return false;
      pq.write(base, sig);
      pq.write(k, pk);
      if (message.length > 0) pq.write(m, message);
      // ctx = (0, 0): the runtime always signs with an empty FIPS 204 context, because its
      // domain separation is DOMAIN_manifest inside the preimage (§16.1).
      return verify(base, m, message.length, 0, 0, k) === 1;
    },

    // [sig][sk][rnd][message]
    ml_dsa65_sign_detached(message, sk) {
      if (sk.length !== ML_DSA65_SK_LEN) {
        throw new Error(`pq: ml-dsa-65 secret key must be ${ML_DSA65_SK_LEN} bytes, got ${sk.length}`);
      }
      const k = base + ML_DSA65_SIG_LEN, r = k + ML_DSA65_SK_LEN, m = r + ML_DSA65_RND_LEN;
      if (!fits(m + message.length)) throw new Error("pq: ml-dsa-65 out of memory");
      pq.write(k, sk);
      pq.write(r, random(ML_DSA65_RND_LEN));
      if (message.length > 0) pq.write(m, message);
      if (sign(base, m, message.length, 0, 0, r, k) !== 1) throw new Error("pq: ml-dsa-65 signing failed");
      return pq.read(base, ML_DSA65_SIG_LEN);
    },

    // [pk][sk][seed]
    ml_dsa65_keypair_from_seed(seed) {
      if (seed.length !== ML_DSA65_SEED_LEN) {
        throw new Error(`pq: ml-dsa-65 seed must be ${ML_DSA65_SEED_LEN} bytes, got ${seed.length}`);
      }
      const k = base + ML_DSA65_PK_LEN, s = k + ML_DSA65_SK_LEN;
      if (!fits(s + ML_DSA65_SEED_LEN)) throw new Error("pq: ml-dsa-65 out of memory");
      pq.write(s, seed);
      if (keypair(base, k, s) !== 1) throw new Error("pq: ml-dsa-65 keygen failed");
      const both = pq.read(base, ML_DSA65_PK_LEN + ML_DSA65_SK_LEN);
      return { publicKey: both.slice(0, ML_DSA65_PK_LEN), privateKey: both.slice(ML_DSA65_PK_LEN) };
    },
  };
}
