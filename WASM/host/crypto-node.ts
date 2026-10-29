// The Node.js crypto seam, and the package's `.` entry point: the host trust root this
// package's own host blob (build/host.skb) carries, libsodium and ML-DSA-65, on
// WebAssembly. It is the crypto every host this package boots runs (§12.9), so the package
// ships one copy of each. Application and transport transforms ship in their own bundles.
// `-node` means Node.js here, as in `fs-node.ts` and `platform-node.ts`, not a network
// node. A page takes its host's crypto from the blob it is served (docs/CLIENT.md).

import { readFileSync } from "node:fs";
import { engineSodium, type HostSodium } from "./sodium-engine.js";
import { randomBytes, syncWebEngine } from "./platform-web.js";
import { readHostBlob } from "./host-blob.js";
import type { Keypair } from "./subkeys.js";

/** The host's crypto, the ML-DSA-65 signing half a bundle author needs (§12.4) included. */
export type HostCrypto = HostSodium;

let packageHost: Uint8Array | undefined;
/** The host blob this package was built with (scripts/build-host-blob.mjs). */
export const packageHostBlob = (): Uint8Array =>
  (packageHost ??= new Uint8Array(readFileSync(new URL("../host.skb", import.meta.url))));

let crypto: HostCrypto | undefined;
function hostCrypto(): HostCrypto {
  if (crypto) return crypto;
  const parts = readHostBlob(packageHostBlob());
  crypto = engineSodium(syncWebEngine, parts.sodium, parts.mldsa, randomBytes);
  return crypto;
}

/** The host crypto surface: libsodium plus ML-DSA-65. */
export async function loadCrypto(): Promise<HostCrypto> {
  return hostCrypto();
}

export function generateKeyPair(): Keypair {
  return hostCrypto().crypto_sign_keypair();
}
