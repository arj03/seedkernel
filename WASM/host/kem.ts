// kem.ts — ML-KEM-768 (FIPS 203) for the primitive catalog (§12.2, §14.1), driven
// from browser/mlkem768.wasm and exposed under `sodium`-shaped method names so it
// mixes straight into the object the guest seam already consumes, exactly as pq.ts
// does for ML-DSA-65.
//
// **Host code, not core**, on the same grounds as pq.ts: this is the JS targets'
// *driver* for mlkem768.wasm, the twin of native/mlkem.go. What is core is the catalog
// NAME a guest reaches (`ml-kem-768/*`, core/domains.ts) — which is the thing every
// host must agree on — not which driver serves it.
//
// **Why it is here before anything asks for it.** A bundle is replaceable; the
// vocabulary it draws on is not. The channel's post-quantum suite is content — a
// signed transport bundle and one policy entry — but only once the primitive it
// needs exists on all three targets, and a primitive cannot be delivered as a
// bundle because the trusted base does not hand-write crypto. So a core vocabulary
// is provisioned ahead of need or not at all (§14.1). This file is that
// provisioning; nothing in the tree calls it yet, and that is the point.
//
// **One artifact, three targets.** The wasm is built from mlkem-native
// (pq/mlkem-native, pinned; scripts/build-mlkem.mjs) and the same bytes are
// instantiated by the browser, by Node, and by wazero in the Go loader
// (native/mlkem.go). The reason is weaker than ML-DSA's — a KEM is not a verifier,
// so its accept/reject boundary is not consensus — but the conclusion is the same:
// two implementations that disagree on a rejected encoding fail to share a key, and
// the cheapest way not to discover that in production is not to have two.
//
// **Nothing here draws entropy.** Every operation takes its coins as an argument,
// because a catalog entry is a pure function of its argument bytes (guest-seam.ts):
// a guest gets randomness from `node/random`, an authority it was granted, and hands it
// in — the same shape as an ephemeral X25519 pair being `node/random(32)` plus
// `x25519/dh`. Keeping the grant out of the primitive is what makes the primitive
// free to call.
//
// **This file imports nothing**, for the reason pq.ts states: a caller hands it an
// instantiated module, so it loads as plain ESM in the browser and carries no
// specifier for a non-npm target to resolve. The small bump arena below is repeated
// from pq.ts rather than shared for exactly that reason — the invariant is worth
// more than the twenty lines.

/** FIPS 203 ML-KEM-768 field widths. Fixed by the parameter set, and cross-checked
 *  against the module's own exports at load (`createMlKem768`). */
export const ML_KEM768_PK_LEN = 1184;
export const ML_KEM768_SK_LEN = 2400;
export const ML_KEM768_CT_LEN = 1088;
export const ML_KEM768_SS_LEN = 32;
/** Encapsulation coins (`m`). */
export const ML_KEM768_COINS_LEN = 32;
/** Key generation coins (`d ‖ z`). */
export const ML_KEM768_SEED_LEN = 64;

/** The KEM, in the shape the primitive catalog dispatches to. Every method is a
 *  pure function of its arguments; `null` is a *rejection*, never an error state:
 *  a public key that fails FIPS 203 §7.2's modulus check, or a secret key that
 *  fails §7.3's hash check. */
export interface MlKem768 {
  ml_kem768_keypair_from_seed(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
  ml_kem768_encaps(pk: Uint8Array, coins: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } | null;
  ml_kem768_decaps(sk: Uint8Array, ct: Uint8Array): Uint8Array | null;
}

/** The wasm module's exports (pq/kem-shim.c). Every buffer is a pointer into the
 *  module's own linear memory; nothing is allocated inside. */
interface MlKemExports {
  memory: WebAssembly.Memory;
  __heap_base: WebAssembly.Global;
  mlkem768_keypair(pk: number, sk: number, coins: number): number;
  mlkem768_encaps(ct: number, ss: number, pk: number, coins: number): number;
  mlkem768_decaps(ss: number, ct: number, sk: number): number;
  mlkem768_publickeybytes(): number;
  mlkem768_secretkeybytes(): number;
  mlkem768_ciphertextbytes(): number;
  mlkem768_bytes(): number;
}

/** Instantiate mlkem768.wasm. Async because browsers refuse synchronous
 *  compilation of anything over 4 KB on the main thread — but only the *load* is
 *  async: every operation below is synchronous, which is what lets the seam's
 *  `crypto/` prefix stay a synchronous byte transform. */
export async function loadMlKem768(wasm: BufferSource): Promise<MlKem768> {
  const { instance } = await WebAssembly.instantiate(wasm, {});
  return createMlKem768(instance);
}

/** Wrap an already-instantiated module. Separate from `loadMlKem768` so a target
 *  that gets its instance elsewhere (a cached compile, a worker) can still use it. */
export function createMlKem768(instance: WebAssembly.Instance): MlKem768 {
  const e = instance.exports as unknown as MlKemExports;
  // Fail at load, not at first encapsulation: a module built for another parameter
  // set would otherwise sit there looking like a working ML-KEM-768 until two nodes
  // tried to agree on a key and silently did not.
  const widths: [string, number, number][] = [
    ["public key", e.mlkem768_publickeybytes(), ML_KEM768_PK_LEN],
    ["secret key", e.mlkem768_secretkeybytes(), ML_KEM768_SK_LEN],
    ["ciphertext", e.mlkem768_ciphertextbytes(), ML_KEM768_CT_LEN],
    ["shared secret", e.mlkem768_bytes(), ML_KEM768_SS_LEN],
  ];
  for (const [what, got, want] of widths) {
    if (got !== want) throw new Error(`kem: mlkem768.wasm reports ${what} width ${got}, expected ${want}`);
  }

  const heapBase = e.__heap_base.value as number;
  let top = heapBase;
  // A bump allocator over the module's own heap, rewound before every call. The
  // module never allocates and never retains anything across a call — the host
  // calls in, it runs to completion, the host reads bytes back out — so a bump
  // pointer is the whole memory manager, and there is no free list to corrupt.
  const rewind = () => { top = heapBase; };
  const alloc = (n: number): number => {
    const p = (top + 15) & ~15;
    top = p + n;
    const short = top - e.memory.buffer.byteLength;
    if (short > 0) e.memory.grow(Math.ceil(short / 65536) + 1);
    return p;
  };
  // Re-read the buffer after every grow: growing detaches the old ArrayBuffer, so a
  // view held across an alloc is a stale view onto freed memory.
  const bytes = () => new Uint8Array(e.memory.buffer);
  const put = (b: Uint8Array): number => {
    const p = alloc(b.length);
    bytes().set(b, p);
    return p;
  };

  return {
    ml_kem768_keypair_from_seed(seed: Uint8Array) {
      if (seed.length !== ML_KEM768_SEED_LEN) {
        throw new Error(`kem: ml-kem-768 seed must be ${ML_KEM768_SEED_LEN} bytes (d ‖ z), got ${seed.length}`);
      }
      rewind();
      const pkP = alloc(ML_KEM768_PK_LEN), skP = alloc(ML_KEM768_SK_LEN), seedP = put(seed);
      if (e.mlkem768_keypair(pkP, skP, seedP) !== 1) throw new Error("kem: ml-kem-768 keygen failed");
      const m = bytes();
      return {
        publicKey: m.slice(pkP, pkP + ML_KEM768_PK_LEN),
        privateKey: m.slice(skP, skP + ML_KEM768_SK_LEN),
      };
    },

    ml_kem768_encaps(pk: Uint8Array, coins: Uint8Array) {
      // A wrong-width key is the same answer as a malformed one — null. The caller
      // holds a peer's key it did not choose, and "this key is unusable" is the only
      // distinction it can act on.
      if (pk.length !== ML_KEM768_PK_LEN || coins.length !== ML_KEM768_COINS_LEN) return null;
      rewind();
      const ctP = alloc(ML_KEM768_CT_LEN), ssP = alloc(ML_KEM768_SS_LEN);
      const pkP = put(pk), coinsP = put(coins);
      if (e.mlkem768_encaps(ctP, ssP, pkP, coinsP) !== 1) return null;
      const m = bytes();
      return {
        ciphertext: m.slice(ctP, ctP + ML_KEM768_CT_LEN),
        sharedSecret: m.slice(ssP, ssP + ML_KEM768_SS_LEN),
      };
    },

    ml_kem768_decaps(sk: Uint8Array, ct: Uint8Array) {
      if (sk.length !== ML_KEM768_SK_LEN || ct.length !== ML_KEM768_CT_LEN) return null;
      rewind();
      const ssP = alloc(ML_KEM768_SS_LEN), ctP = put(ct), skP = put(sk);
      // null here means the SECRET KEY failed its hash check — never that the
      // ciphertext was bad. ML-KEM answers a bad ciphertext with a shared secret
      // derived from the key's own z, in constant time, and reporting that apart
      // from success is exactly the oracle implicit rejection exists to deny.
      if (e.mlkem768_decaps(ssP, ctP, skP) !== 1) return null;
      return bytes().slice(ssP, ssP + ML_KEM768_SS_LEN);
    },
  };
}

/** Mix ML-KEM-768 into a libsodium instance. A target calls this once at boot, at
 *  the same seam it mixes in ML-DSA-65 (`withMlDsa65`), so "which primitives does
 *  this host serve" has one answer set in one place. */
export function withMlKem768<T extends object>(sodium: T, kem: MlKem768): T & MlKem768 {
  return Object.assign(sodium, kem);
}
