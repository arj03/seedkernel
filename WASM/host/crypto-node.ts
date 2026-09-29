// The Node.js crypto seam: where this target readies the whole crypto surface, and the
// package's `.` entry point. The libsodium core and `mldsa65.wasm` are the host trust
// root; application and transport transforms ship in their own bundles. `-node` means
// Node.js here, as in `fs-node.ts` and `net-node.ts`, not a network node. A browser page
// readies its own crypto (docs/CLIENT.md).

import { readFileSync } from "node:fs";
import { withMlDsa65, loadMlDsa65, ML_DSA65_SEED_LEN } from "./pq.js";

// A static import so `bun build --compile` bundles the package into the standalone
// binary. The cast gives the default export the module-namespace type the host uses.
import sodiumDefault from "libsodium-wrappers";
const sodium = sodiumDefault as unknown as typeof import("libsodium-wrappers");

// ML-DSA-65 is attached to the same object under libsodium-style names (pq.ts). It
// verifies bundles, so it cannot itself ship as one.
const MLDSA_WASM = new URL("../../browser/mldsa65.wasm", import.meta.url);
let pqReady: Promise<void> | null = null;
function ensurePq(): Promise<void> {
  if (!pqReady) {
    pqReady = loadMlDsa65(readFileSync(MLDSA_WASM))
      .then((mldsa) => { withMlDsa65(sodium, mldsa); });
  }
  return pqReady;
}

// Both halves together: a caller that awaited only libsodium would get a host that
// refuses the hybrid manifest suite as unsupported.
export async function ensureCrypto(): Promise<void> {
  await Promise.all([sodium.ready, ensurePq()]);
}

/** Ready the host crypto surface: core libsodium plus ML-DSA-65. */
export async function loadCrypto(): Promise<typeof sodium> {
  await ensureCrypto();
  return sodium;
}

/** A fresh ML-DSA-65 keypair, the PQ half of a hybrid author identity (§12.4). The
 *  Ed25519 half is `generateKeyPair` below; `hybridAuthorId` (bundle.ts) turns the two
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
