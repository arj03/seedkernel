// Node entry point — bridges the portable ModuleTable to libsodium-wrappers. Use
// this when running on Node / Bun / Deno (with Node compat). A browser page reaches
// the runtime through `./shell-core` and readies its own libsodium (docs/EXPORTS.md).

import { readFileSync } from "node:fs";
import { ModuleTable } from "./module-table.js";
import { withMlDsa65, loadMlDsa65, ML_DSA65_SEED_LEN } from "./pq.js";
import { withMlKem768, loadMlKem768 } from "./kem.js";

// The runtime bundles the sumo build so apps that need symbols beyond the
// host's own Ed25519 + BLAKE2b (e.g. seedstore's crypto_stream_xchacha20_xor)
// reuse one libsodium rather than shipping a second (README §12.1). A *static*
// import (not createRequire) so `bun build --compile` bundles the package into
// the standalone shell binary — a dynamic require resolves to nothing there. The
// default export is the wrapper object; cast it to the module-namespace type the
// rest of the host (and the ModuleTable constructor) is written against.
import sodiumDefault from "libsodium-wrappers-sumo";
const sodium = sodiumDefault as unknown as typeof import("libsodium-wrappers-sumo");

// ML-DSA-65 rides on the same object under libsodium-shaped names (pq.ts), because
// the loader's crypto surface is "an object with these methods" and libsodium has no
// PQ signature to supply. It comes from browser/mldsa65.wasm — the SAME artifact the
// browser fetches and the Go loader embeds (native/mldsa.go), so all three targets
// share one verifier and cannot drift on which manifests they admit (§12.4, §14.1).
// Mixed in once here, at the target's one crypto seam, so "does this host accept
// manifest suite 0x02" has exactly one answer, set in one place.
// ML-KEM-768 rides on the same object for the same reason, but answers to a different
// consumer: it is a `PRIMITIVE_NAMES` entry (domains.ts), so the cap-bridge dispatches
// `ml-kem-768/*` straight to `sodium.ml_kem768_*`. A catalog name this target advertises
// at load and then cannot serve at call time is the worst of both — the manifest check
// passes and the guest fails mid-run — so the two PQ modules are mixed in together, on
// the one seam, exactly as the comment above says.
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

/** Await sodium readiness and stand up a ModuleTable. The module table is host
 *  state — there is no blob to load — so booting is "ready libsodium, done"
 *  (§3); installing bundles stays the caller's job. */
export async function createModuleTable(): Promise<ModuleTable> {
  await ensureSodium();
  return new ModuleTable();
}

// Every half of the crypto surface, always together. A caller that awaited only
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
 *  the two public keys into the 32-byte id policy and table names are written
 *  against. Requires `ensureSodium()` first, like every other call here. */
export function generatePqKeyPair(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const pq = sodium as unknown as Partial<import("./pq.js").MlDsa65Signer>;
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

export { ModuleTable } from "./module-table.js";
