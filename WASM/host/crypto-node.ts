// The Node.js crypto seam, and the package's `.` entry point: the host trust root this
// package's own host blob (build/host.skb) carries, libsodium and ML-DSA-65, on
// WebAssembly. It is the crypto every host this package boots runs (§12.9), so the package
// ships one copy of each. Application and transport transforms ship in their own bundles.
// `-node` means Node.js here, as in `fs-node.ts` and `platform-node.ts`, not a network
// node. A page takes its host's crypto from the blob it is served (docs/CLIENT.md).

import { readFileSync } from "node:fs";
import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { engineSodium, type HostSodium } from "./sodium-engine.js";
import { randomBytes, syncWebEngine } from "./platform-web.js";
import { readHostBlob } from "./host-blob.js";
import type { Keypair } from "./subkeys.js";
import type { Symmetric } from "./abi.js";

/** The host's crypto, the ML-DSA-65 signing half a bundle author needs (§12.4) included. */
export type HostCrypto = HostSodium;

let packageHost: Uint8Array | undefined;
/** The host blob this package was built with (scripts/build-host-blob.mjs). */
export const packageHostBlob = (): Uint8Array =>
  (packageHost ??= new Uint8Array(readFileSync(new URL("../host.skb", import.meta.url))));

/** An AES-GCM tag's length. */
const GCM_TAG = 16;

/** The symmetric primitives (abi.ts) by OpenSSL, synchronously. */
export const nodeSymmetric: Symmetric = {
  aesGcmSeal: (key, nonce, ad, pt) => {
    const c = createCipheriv("aes-256-gcm", key, nonce);
    c.setAAD(ad);
    return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  },
  aesGcmOpen: (key, nonce, ad, ct) => {
    if (ct.length < GCM_TAG) return null;
    const d = createDecipheriv("aes-256-gcm", key, nonce);
    d.setAAD(ad);
    d.setAuthTag(ct.subarray(ct.length - GCM_TAG));
    try {
      return Buffer.concat([d.update(ct.subarray(0, ct.length - GCM_TAG)), d.final()]);
    } catch {
      return null;
    }
  },
  sha256: (msg) => createHash("sha256").update(msg).digest(),
};

let crypto: HostCrypto | undefined;
function hostCrypto(): HostCrypto {
  if (crypto) return crypto;
  const parts = readHostBlob(packageHostBlob());
  crypto = engineSodium(syncWebEngine, parts.sodium, parts.mldsa, randomBytes, nodeSymmetric);
  return crypto;
}

/** The host crypto surface: libsodium plus ML-DSA-65. */
export async function loadCrypto(): Promise<HostCrypto> {
  return hostCrypto();
}

export function generateKeyPair(): Keypair {
  return hostCrypto().crypto_sign_keypair();
}
