// Browser entry point — bridges the portable KernelHost to fetch + the
// caller's libsodium instance. The page is responsible for importing and
// readying libsodium (the build/browser folder ships a patched
// libsodium-wrappers.mjs that streams the .wasm separately) and passing
// it in. For Node, see ./node.ts.

import { KernelHost } from "./kernel-host.js";

type Sodium = typeof import("libsodium-wrappers-sumo");

/** Fetch the two WASM modules, await sodium readiness, and instantiate a
 *  KernelHost. Pass URLs as strings or URL objects relative to the page. */
export async function loadKernelHost(
  kernelUrl: string | URL,
  bootstrapUrl: string | URL,
  sodium: Sodium,
): Promise<KernelHost> {
  const [kernelBytes, bootstrapBytes] = await Promise.all([
    fetch(kernelUrl).then((r) => r.arrayBuffer()),
    fetch(bootstrapUrl).then((r) => r.arrayBuffer()),
    sodium.ready,
  ]);
  return KernelHost.load(kernelBytes, bootstrapBytes, sodium);
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
