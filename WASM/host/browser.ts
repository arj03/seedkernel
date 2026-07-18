// Browser entry point — bridges the portable KernelHost to fetch + the
// caller's libsodium instance. The page is responsible for importing and
// readying libsodium (the build/browser folder ships a patched
// libsodium-wrappers.mjs that streams the .wasm separately) and passing
// it in. For Node, see ./node.ts.

import { KernelHost } from "./kernel-host.js";

type Sodium = typeof import("libsodium-wrappers-sumo");

/** Fetch kernel.wasm, await sodium readiness, and instantiate a KernelHost. Pass
 *  the URL as a string or URL object relative to the page. The signature wrapper
 *  and genesis suite are host code now (registered via `host.registerSignature`),
 *  so this fetches the one WASM blob and only packages the platform I/O —
 *  bootstrap stays the caller's job (§9). */
export async function loadKernelHost(
  kernelUrl: string | URL,
  sodium: Sodium,
): Promise<KernelHost> {
  const [kernelBytes] = await Promise.all([
    fetch(kernelUrl).then((r) => r.arrayBuffer()),
    sodium.ready,
  ]);
  return KernelHost.load(kernelBytes, sodium);
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
  InstallRecord,
} from "./installer.js";
export {
  MAGIC,
  CURRENT_VERSION,
} from "./envelope.js";
