// Node entry point — bridges the portable KernelHost to Node's filesystem
// and libsodium-wrappers. Use this when running on Node / Bun / Deno (with
// Node compat); for the browser see ./browser.ts.

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

import { KernelHost } from "./kernel-host.js";

const require = createRequire(import.meta.url);
const sodium = require("libsodium-wrappers") as typeof import("libsodium-wrappers");

/** Read the two WASM modules from disk, await sodium readiness, and
 *  instantiate a KernelHost. */
export async function loadKernelHost(
  kernelWasmPath: string,
  bootstrapWasmPath: string,
): Promise<KernelHost> {
  const [kernelBytes, bootstrapBytes] = await Promise.all([
    readFile(kernelWasmPath),
    readFile(bootstrapWasmPath),
    sodium.ready,
  ]);
  return KernelHost.load(kernelBytes, bootstrapBytes, sodium);
}

export async function ensureSodium(): Promise<void> {
  await sodium.ready;
}

export function generateKeyPair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export {
  KernelHost,
  GENESIS_ALGO_ID,
  GENESIS_PUBKEY_LEN,
  GENESIS_SIGNATURE_LEN,
  GENESIS_SECRET_KEY_LEN,
} from "./kernel-host.js";
export type { Handler, Signer } from "./kernel-host.js";
export {
  Installer,
  referencePolicy,
} from "./installer.js";
export type {
  ApproveInstall,
  FirstInstallPolicy,
  AcknowledgeCaps,
  InstallRecord,
  SuiteSlot,
} from "./installer.js";
export {
  MAGIC,
  CURRENT_VERSION,
} from "./envelope.js";
