// pq.ts — the post-quantum half of the hybrid manifest suite (§12.4, §14.1):
// ML-DSA-65 (FIPS 204), driven from browser/mldsa65.wasm and exposed in
// libsodium-wrappers-shaped method names so it mixes straight into the `sodium`
// object the shared loader already consumes.
//
// **Host code, not core**, for the same reason `native/mldsa.go` is not: it is a
// *driver* — a bump arena over a wasm module's linear memory — and which library a
// target reaches its primitives through decides nothing about the protocol. What is
// core here is the vocabulary (`PRIMITIVE_NAMES`, core/domains.ts) and the manifest
// suite that names ML-DSA-65 (§12.4); the field widths below are format constants of
// that suite, kept beside the driver only because it cross-checks them at load.
//
// **One implementation, three targets.** The wasm is built from mldsa-native
// (pq/mldsa-native, pinned; scripts/build-mldsa.mjs) and the same bytes are
// instantiated by the browser, by Node, and by wazero in the Go loader
// (native/mldsa.go). This matters more here than performance ever could: the
// accept/reject boundary of a *verifier* is consensus — a bundle one node admits,
// every node must admit — and two independent implementations of a lattice scheme
// can disagree at the edges (malformed encodings, hint bounds, out-of-range z)
// while both pass their own tests. It is the same reason Ed25519 stays on the
// shared libsodium.wasm instead of each target's native library.
//
// **This file imports nothing.** No package, no `fs`, no `fetch` — a caller hands
// it an instantiated module. That is what lets it load as plain ESM in the browser
// (§12.9) and be evaluated in QuickJS on the native target, where a bare specifier
// would simply fail to resolve.

/** FIPS 204 ML-DSA-65 field widths. The manifest envelope is fixed-width per suite
 *  (§12.4), so these are format constants, not hints. They are cross-checked
 *  against the module's own exports at load (`createMlDsa65`). */
export const ML_DSA65_PK_LEN = 1952;
export const ML_DSA65_SK_LEN = 4032;
export const ML_DSA65_SIG_LEN = 3309;
export const ML_DSA65_SEED_LEN = 32;
export const ML_DSA65_RND_LEN = 32;

/** The verify half — all a loader is ever handed (§12.4: a verifier gets no way to
 *  make a signature). Named to sit alongside `crypto_sign_verify_detached` on the
 *  same object, with the same argument order. */
export interface MlDsa65Verifier {
  ml_dsa65_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
}

/** The sign half — the build side of the format. */
export interface MlDsa65Signer extends MlDsa65Verifier {
  ml_dsa65_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  ml_dsa65_keypair_from_seed(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
}

/** The wasm module's exports (pq/shim.c). Every buffer is a pointer into the
 *  module's own linear memory; nothing is allocated inside. */
interface MlDsaExports {
  memory: WebAssembly.Memory;
  __heap_base: WebAssembly.Global;
  mldsa65_verify(sig: number, m: number, mlen: number, ctx: number, ctxlen: number, pk: number): number;
  mldsa65_sign(sig: number, m: number, mlen: number, ctx: number, ctxlen: number, rnd: number, sk: number): number;
  mldsa65_keypair(pk: number, sk: number, seed: number): number;
  mldsa65_publickeybytes(): number;
  mldsa65_secretkeybytes(): number;
  mldsa65_signaturebytes(): number;
}

/** Instantiate mldsa65.wasm. Async because browsers refuse synchronous compilation
 *  of anything over 4 KB on the main thread — but only the *load* is async: every
 *  operation below is synchronous, which is what lets `verifyManifest` stay
 *  synchronous (§12.4) rather than turning the whole load path into promises. */
export async function loadMlDsa65(wasm: BufferSource): Promise<MlDsa65Signer> {
  const { instance } = await WebAssembly.instantiate(wasm, {});
  return createMlDsa65(instance);
}

/** Wrap an already-instantiated module. Separate from `loadMlDsa65` so a target
 *  that gets its instance elsewhere (a cached compile, a worker) can still use it. */
export function createMlDsa65(instance: WebAssembly.Instance): MlDsa65Signer {
  const e = instance.exports as unknown as MlDsaExports;
  // Fail at load, not at first verify: a module built for another parameter set
  // would otherwise sit there looking like a working ML-DSA-65 verifier until a
  // real bundle arrived, and then reject it as a bad signature.
  const widths: [string, number, number][] = [
    ["public key", e.mldsa65_publickeybytes(), ML_DSA65_PK_LEN],
    ["secret key", e.mldsa65_secretkeybytes(), ML_DSA65_SK_LEN],
    ["signature", e.mldsa65_signaturebytes(), ML_DSA65_SIG_LEN],
  ];
  for (const [what, got, want] of widths) {
    if (got !== want) throw new Error(`pq: mldsa65.wasm reports ${what} width ${got}, expected ${want}`);
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
  // Re-read the buffer after every grow: growing detaches the old ArrayBuffer, so
  // a view held across an alloc is a stale view onto freed memory.
  const bytes = () => new Uint8Array(e.memory.buffer);
  const put = (b: Uint8Array): number => {
    const p = alloc(b.length);
    bytes().set(b, p);
    return p;
  };

  return {
    ml_dsa65_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean {
      // Never throws: a wrong-width key or signature is an invalid signature, the
      // same verdict `crypto_sign_verify_detached` returns for the same input, so
      // one suite cannot report a structural failure as an exception where the
      // other reports `false`.
      if (sig.length !== ML_DSA65_SIG_LEN || pk.length !== ML_DSA65_PK_LEN) return false;
      rewind();
      const sigP = put(sig), msgP = put(message), pkP = put(pk);
      // ctx = (0, 0): the runtime always signs with an empty FIPS 204 context. Its
      // domain separation is DOMAIN_manifest inside the preimage (§16.1) and must
      // not be split across two mechanisms.
      return e.mldsa65_verify(sigP, msgP, message.length, 0, 0, pkP) === 1;
    },

    ml_dsa65_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array {
      if (sk.length !== ML_DSA65_SK_LEN) {
        throw new Error(`pq: ml-dsa-65 secret key must be ${ML_DSA65_SK_LEN} bytes, got ${sk.length}`);
      }
      rewind();
      const sigP = alloc(ML_DSA65_SIG_LEN);
      const msgP = put(message);
      const rndP = put(randomBytes(ML_DSA65_RND_LEN));
      const skP = put(sk);
      if (e.mldsa65_sign(sigP, msgP, message.length, 0, 0, rndP, skP) !== 1) {
        throw new Error("pq: ml-dsa-65 signing failed");
      }
      return bytes().slice(sigP, sigP + ML_DSA65_SIG_LEN);
    },

    ml_dsa65_keypair_from_seed(seed: Uint8Array) {
      if (seed.length !== ML_DSA65_SEED_LEN) {
        throw new Error(`pq: ml-dsa-65 seed must be ${ML_DSA65_SEED_LEN} bytes, got ${seed.length}`);
      }
      rewind();
      const pkP = alloc(ML_DSA65_PK_LEN), skP = alloc(ML_DSA65_SK_LEN), seedP = put(seed);
      if (e.mldsa65_keypair(pkP, skP, seedP) !== 1) throw new Error("pq: ml-dsa-65 keygen failed");
      const m = bytes();
      return {
        publicKey: m.slice(pkP, pkP + ML_DSA65_PK_LEN),
        privateKey: m.slice(skP, skP + ML_DSA65_SK_LEN),
      };
    },
  };
}

/** The hedging randomness FIPS 204 mixes into a signature. Taken from the host's
 *  own CSPRNG rather than from inside the module, which is what keeps mldsa65.wasm
 *  import-free — and an entropy source is the one thing that need NOT match across
 *  nodes, since only its consumers' deterministic structure does. */
function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.getRandomValues) throw new Error("pq: no CSPRNG (globalThis.crypto.getRandomValues) available");
  c.getRandomValues(out);
  return out;
}

/** Mix ML-DSA-65 into a libsodium instance. A target calls this once at boot; every
 *  consumer downstream just sees a `sodium` that happens to know the method, which
 *  is how `verifyManifest` discovers whether this host can accept suite `0x02`. */
export function withMlDsa65<T extends object>(sodium: T, mldsa: MlDsa65Signer): T & MlDsa65Signer {
  return Object.assign(sodium, mldsa);
}
