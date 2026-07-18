// Browser entry point — bridges the portable KernelHost to fetch + the
// caller's libsodium instance. The page is responsible for importing and
// readying libsodium (the build/browser folder ships a patched
// libsodium-wrappers.mjs that streams the .wasm separately) and passing
// it in. For Node, see ./node.ts.

import { KernelHost } from "./kernel-host.js";

type Sodium = typeof import("libsodium-wrappers-sumo");

/** Fetch the two WASM modules, await sodium readiness, and instantiate a
 *  KernelHost. Pass URLs as strings or URL objects relative to the page.
 *
 *  Returns the signature module's bytes alongside the host rather than wiring
 *  them in: bootstrap is the host's job (§9), so the caller passes them to
 *  `registerSignature` under whatever name it bootstraps at — exactly as it
 *  does for the installer. This entry point only packages the platform I/O. */
export async function loadKernelHost(
  kernelUrl: string | URL,
  signatureUrl: string | URL,
  sodium: Sodium,
): Promise<{ host: KernelHost; signatureBytes: Uint8Array }> {
  const [kernelBytes, signatureBytes] = await Promise.all([
    fetch(kernelUrl).then((r) => r.arrayBuffer()),
    fetch(signatureUrl).then((r) => r.arrayBuffer()),
    sodium.ready,
  ]);
  return {
    host: await KernelHost.load(kernelBytes, sodium),
    signatureBytes: new Uint8Array(signatureBytes),
  };
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
