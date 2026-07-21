// Browser entry point — bridges the portable KernelHost to the caller's libsodium
// instance. The page is responsible for importing and readying libsodium (the
// build/browser folder ships a patched libsodium-wrappers.mjs that streams the
// .wasm separately) and passing it in. For Node, see ./node.ts.

import { KernelHost } from "./kernel-host.js";

type Sodium = typeof import("libsodium-wrappers-sumo");

/** Await sodium readiness and stand up a KernelHost. The handler table is host
 *  state — there is no kernel blob to fetch — so booting is "ready libsodium, done"
 *  (§3); installing bundles stays the caller's job. */
export async function createKernelHost(sodium: Sodium): Promise<KernelHost> {
  await sodium.ready;
  return new KernelHost(sodium);
}

export { KernelHost } from "./kernel-host.js";
export type {
  InstallRecord,
  AdmitPolicy,
} from "./bundle.js";
