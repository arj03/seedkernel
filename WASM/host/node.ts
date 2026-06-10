// Node entry point — bridges the portable KernelHost to Node's filesystem
// and libsodium-wrappers. Use this when running on Node / Bun / Deno (with
// Node compat); for the browser see ./browser.ts.

import { readFile } from "node:fs/promises";

import { KernelHost } from "./kernel-host.js";

// The runtime bundles the sumo build so apps that need symbols beyond the
// kernel's own Ed25519 + SHA-3 (e.g. seedstore's crypto_stream_xchacha20_xor)
// reuse one libsodium rather than shipping a second (README §13.1). A *static*
// import (not createRequire) so `bun build --compile` bundles the package into
// the standalone shell binary — a dynamic require resolves to nothing there. The
// default export is the wrapper object; cast it to the module-namespace type the
// rest of the host (and KernelHost.load) is written against.
import sodiumDefault from "libsodium-wrappers-sumo";
const sodium = sodiumDefault as unknown as typeof import("libsodium-wrappers-sumo");

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

/** Load and ready the bundled sumo libsodium and return the shared instance.
 *  Apps (and the host) reuse this one instance rather than each importing their
 *  own copy of the crypto library (README §13.1). */
export async function loadSodium(): Promise<typeof sodium> {
  await sodium.ready;
  return sodium;
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
