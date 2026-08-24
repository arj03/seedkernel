// The Node.js crypto seam — this target's one place for readying the whole crypto
// surface, and the package's `.` entry point. The core build and `mldsa65.wasm` are the
// host trust root; application and transport transforms ship in their own bundles. The `-node`
// suffix means Node.js, as it does in `fs-node.ts` / `net-node.ts` — never a network
// node. Node-only: everything here needs the npm package or a local file read; a browser
// page readies its own crypto (docs/CLIENT.md).

import { readFileSync } from "node:fs";
import { withMlDsa65, loadMlDsa65, ML_DSA65_SEED_LEN } from "./pq.js";

// A *static* core-wrapper import so `bun build --compile`
// bundles the package into the standalone binary; the cast turns the default wrapper
// object into the module-namespace type the rest of the host is written against.
import sodiumDefault from "libsodium-wrappers";
const sodium = sodiumDefault as unknown as typeof import("libsodium-wrappers");

// ML-DSA-65 rides on the same object under libsodium-shaped names (pq.ts). It is the
// verifier that cannot be delivered through the bundle format it verifies.
const MLDSA_WASM = new URL("../../browser/mldsa65.wasm", import.meta.url);
let pqReady: Promise<void> | null = null;
function ensurePq(): Promise<void> {
  if (!pqReady) {
    pqReady = loadMlDsa65(readFileSync(MLDSA_WASM))
      .then((mldsa) => { withMlDsa65(sodium, mldsa); });
  }
  return pqReady;
}

// Every half of the crypto surface, always together: a caller that awaited only libsodium
// would get a host that silently refuses manifest suite 0x02 as unsupported.
export async function ensureCrypto(): Promise<void> {
  await Promise.all([sodium.ready, ensurePq()]);
}

/** Ready the host crypto surface: core libsodium plus ML-DSA-65. */
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
