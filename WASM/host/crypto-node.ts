// The Node.js crypto seam, and the package's `.` entry point: the host trust root this
// package's own host blob (build/host.skb) carries, libsodium and ML-DSA-65, on
// WebAssembly. It is the crypto every host this package boots runs (§12.9), so the package
// ships one copy of each. Application and transport transforms ship in their own bundles.
// `-node` means Node.js here, as in `fs-node.ts` and `platform-node.ts`, not a network
// node. A page takes its host's crypto from the blob it is served (docs/CLIENT.md).

import { readFileSync } from "node:fs";
import { createMlDsa65, randomBytes, ML_DSA65_SEED_LEN, type MlDsa65Signer } from "./pq.js";
import { engineSodium, type HostSodium } from "./sodium-engine.js";
import { syncWebEngine } from "./platform-web.js";
import { readHostBlob } from "./host-blob.js";
import type { Keypair } from "../services/subkeys.js";

/** The host's crypto, and the ML-DSA-65 signing half a bundle author needs (§12.4). */
export type HostCrypto = HostSodium & MlDsa65Signer;

let packageHost: Uint8Array | undefined;
/** The host blob this package was built with (scripts/build-host-blob.mjs). */
export const packageHostBlob = (): Uint8Array =>
  (packageHost ??= new Uint8Array(readFileSync(new URL("../host.skb", import.meta.url))));

let crypto: HostCrypto | undefined;
function hostCrypto(): HostCrypto {
  if (crypto) return crypto;
  const parts = readHostBlob(packageHostBlob());
  // The host verifies with its own instance; signing, which no host does, gets another
  // instance of the same module.
  const signer = createMlDsa65(new WebAssembly.Instance(new WebAssembly.Module(parts.mldsa as BufferSource), {}));
  crypto = {
    ...engineSodium(syncWebEngine, parts.sodium, parts.mldsa, randomBytes),
    ml_dsa65_sign_detached: signer.ml_dsa65_sign_detached,
    ml_dsa65_keypair_from_seed: signer.ml_dsa65_keypair_from_seed,
  };
  return crypto;
}

/** The host crypto surface: libsodium plus ML-DSA-65. */
export async function loadCrypto(): Promise<HostCrypto> {
  return hostCrypto();
}

/** A fresh ML-DSA-65 keypair, the PQ half of a hybrid author identity (§12.4). The
 *  Ed25519 half is `generateKeyPair` below; `hybridAuthorId` (bundle.ts) turns the two
 *  public keys into the 32-byte id. */
export function generatePqKeyPair(): Keypair {
  return hostCrypto().ml_dsa65_keypair_from_seed(randomBytes(ML_DSA65_SEED_LEN));
}

export function generateKeyPair(): Keypair {
  return hostCrypto().crypto_sign_keypair();
}
