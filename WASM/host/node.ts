// Node entry point — bridges the portable KernelHost to libsodium-wrappers. Use
// this when running on Node / Bun / Deno (with Node compat); for the browser see
// ./browser.ts.

import { KernelHost } from "./kernel-host.js";

// The runtime bundles the sumo build so apps that need symbols beyond the
// kernel's own Ed25519 + BLAKE2b (e.g. seedstore's crypto_stream_xchacha20_xor)
// reuse one libsodium rather than shipping a second (README §12.1). A *static*
// import (not createRequire) so `bun build --compile` bundles the package into
// the standalone shell binary — a dynamic require resolves to nothing there. The
// default export is the wrapper object; cast it to the module-namespace type the
// rest of the host (and the KernelHost constructor) is written against.
import sodiumDefault from "libsodium-wrappers-sumo";
const sodium = sodiumDefault as unknown as typeof import("libsodium-wrappers-sumo");

/** Await sodium readiness and stand up a KernelHost. The handler table is host
 *  state — there is no kernel blob to load — so booting is "ready libsodium, done"
 *  (§9); installing bundles stays the caller's job. */
export async function createKernelHost(): Promise<KernelHost> {
  await sodium.ready;
  return new KernelHost(sodium);
}

export async function ensureSodium(): Promise<void> {
  await sodium.ready;
}

/** Load and ready the bundled sumo libsodium and return the shared instance.
 *  Apps (and the host) reuse this one instance rather than each importing their
 *  own copy of the crypto library (README §12.1). */
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

export { KernelHost } from "./kernel-host.js";
export type { Handler } from "./kernel-host.js";
export type {
  InstallRecord,
  AdmitPolicy,
} from "./bundle.js";
