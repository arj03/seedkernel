// Node entry point — bridges the portable KernelHost to libsodium-wrappers. Use
// this when running on Node / Bun / Deno (with Node compat); for the browser see
// ./browser.ts.

import { readFileSync } from "node:fs";
import { KernelHost } from "../core/kernel-host.js";
import { withMlDsa65, loadMlDsa65, ML_DSA65_SEED_LEN } from "../core/pq.js";

// The runtime bundles the sumo build so apps that need symbols beyond the
// kernel's own Ed25519 + BLAKE2b (e.g. seedstore's crypto_stream_xchacha20_xor)
// reuse one libsodium rather than shipping a second (README §12.1). A *static*
// import (not createRequire) so `bun build --compile` bundles the package into
// the standalone shell binary — a dynamic require resolves to nothing there. The
// default export is the wrapper object; cast it to the module-namespace type the
// rest of the host (and the KernelHost constructor) is written against.
import sodiumDefault from "libsodium-wrappers-sumo";
const sodium = sodiumDefault as unknown as typeof import("libsodium-wrappers-sumo");

// ML-DSA-65 rides on the same object under libsodium-shaped names (pq.ts), because
// the loader's crypto surface is "an object with these methods" and libsodium has no
// PQ signature to supply. It comes from browser/mldsa65.wasm — the SAME artifact the
// browser fetches and the Go loader embeds (native/mldsa.go), so all three targets
// share one verifier and cannot drift on which manifests they admit (§12.4, §14.1).
// Mixed in once here, at the target's one crypto seam, so "does this host accept
// manifest suite 0x02" has exactly one answer, set in one place.
const MLDSA_WASM = new URL("../../browser/mldsa65.wasm", import.meta.url);
let pqReady: Promise<void> | null = null;
function ensurePq(): Promise<void> {
  if (!pqReady) {
    pqReady = loadMlDsa65(readFileSync(MLDSA_WASM)).then((mldsa) => {
      withMlDsa65(sodium, mldsa);
    });
  }
  return pqReady;
}

/** Await sodium readiness and stand up a KernelHost. The handler table is host
 *  state — there is no kernel blob to load — so booting is "ready libsodium, done"
 *  (§3); installing bundles stays the caller's job. */
export async function createKernelHost(): Promise<KernelHost> {
  await ensureSodium();
  return new KernelHost();
}

// Both halves of the crypto surface, always together. A caller that awaited only
// libsodium would get a host that silently refuses manifest suite 0x02 as
// unsupported — a readiness bug wearing the costume of a policy decision.
export async function ensureSodium(): Promise<void> {
  await Promise.all([sodium.ready, ensurePq()]);
}

/** Load and ready the bundled sumo libsodium and return the shared instance.
 *  Apps (and the host) reuse this one instance rather than each importing their
 *  own copy of the crypto library (README §12.1). */
export async function loadSodium(): Promise<typeof sodium> {
  await ensureSodium();
  return sodium;
}

/** A fresh ML-DSA-65 keypair — the PQ half of a hybrid author identity (§12.4).
 *  The Ed25519 half is `generateKeyPair` below; `hybridAuthorId` (bundle.ts) turns
 *  the two public keys into the 32-byte id policy and kernel names are written
 *  against. Requires `ensureSodium()` first, like every other call here. */
export function generatePqKeyPair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const pq = sodium as unknown as Partial<import("../core/pq.js").MlDsa65Signer>;
  if (!pq.ml_dsa65_keypair_from_seed) throw new Error("node: call ensureSodium() before generatePqKeyPair()");
  return pq.ml_dsa65_keypair_from_seed(sodium.randombytes_buf(ML_DSA65_SEED_LEN));
}

export function generateKeyPair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export { KernelHost } from "../core/kernel-host.js";
