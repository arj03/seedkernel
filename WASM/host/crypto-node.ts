// The Node.js crypto seam — this target's one place for readying the whole crypto
// surface, and the package's `.` entry point. Three artifacts, not just libsodium: the
// bundled sumo build, `mldsa65.wasm` and `mlkem768.wasm`, mixed onto one object so the
// §12.1 primitive catalog has a single backing instance (`ensureCrypto`). The `-node`
// suffix means Node.js, as it does in `fs-node.ts` / `net-node.ts` — never a network
// node. Node-only: everything here needs the npm package or a local file read; a browser
// page readies its own crypto (docs/EXPORTS.md).

import { readFileSync } from "node:fs";
import { withMlDsa65, loadMlDsa65, ML_DSA65_SEED_LEN } from "./pq.js";
import { withMlKem768, loadMlKem768 } from "./kem.js";

// The sumo build, so apps needing symbols beyond Ed25519 + BLAKE2b reuse one libsodium
// rather than shipping a second (§12.1). A *static* import so `bun build --compile`
// bundles the package into the standalone binary; the cast turns the default wrapper
// object into the module-namespace type the rest of the host is written against.
import sodiumDefault from "libsodium-wrappers-sumo";
const sodium = sodiumDefault as unknown as typeof import("libsodium-wrappers-sumo");

// ML-DSA-65 rides on the same object under libsodium-shaped names (pq.ts), and ML-KEM-768
// rides along as a `PRIMITIVE_NAMES` entry — both from the SAME .wasm the browser fetches
// and the Go loader embeds, so the three targets share one verifier and cannot drift on
// which manifests they admit (§12.4, §14.1). Both are mixed in at the one crypto seam: a
// catalog name advertised at load and unserveable at call time would pass the manifest
// check and fail the guest mid-run — the whole surface is readied together.
const MLDSA_WASM = new URL("../../browser/mldsa65.wasm", import.meta.url);
const MLKEM_WASM = new URL("../../browser/mlkem768.wasm", import.meta.url);
let pqReady: Promise<void> | null = null;
function ensurePq(): Promise<void> {
  if (!pqReady) {
    pqReady = Promise.all([
      loadMlDsa65(readFileSync(MLDSA_WASM)).then((mldsa) => { withMlDsa65(sodium, mldsa); }),
      loadMlKem768(readFileSync(MLKEM_WASM)).then((kem) => { withMlKem768(sodium, kem); }),
    ]).then(() => {});
  }
  return pqReady;
}

// Every half of the crypto surface, always together: a caller that awaited only libsodium
// would get a host that silently refuses manifest suite 0x02 as unsupported.
export async function ensureCrypto(): Promise<void> {
  await Promise.all([sodium.ready, ensurePq()]);
}

/** Ready the whole crypto surface and return the one shared instance: sumo libsodium with
 *  ML-DSA-65 and ML-KEM-768 mixed on. Apps and the host reuse this rather than each
 *  importing their own copy (§12.1). */
export async function loadCrypto(): Promise<typeof sodium> {
  await ensureCrypto();
  return sodium;
}

/** A fresh ML-DSA-65 keypair — the PQ half of a hybrid author identity (§12.4); the
 *  Ed25519 half is `generateKeyPair` below, and `hybridAuthorId` (bundle.ts) turns the two
 *  public keys into the 32-byte id. Requires `ensureCrypto()` first. */
export function generatePqKeyPair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const pq = sodium as unknown as Partial<import("./pq.js").MlDsa65Signer>;
  if (!pq.ml_dsa65_keypair_from_seed) throw new Error("crypto: call ensureCrypto() before generatePqKeyPair()");
  return pq.ml_dsa65_keypair_from_seed(sodium.randombytes_buf(ML_DSA65_SEED_LEN));
}

export function generateKeyPair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}
