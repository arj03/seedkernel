// Browser crypto seam: crypto-node.ts's loadCrypto for a target without node:fs. Adds
// ML-DSA-65 to a libsodium instance the caller supplies.
import { loadMlDsa65, withMlDsa65, type MlDsa65Signer } from "./pq.js";

/** Ready the caller's libsodium and add ML-DSA-65 to it. */
export async function loadCrypto<T extends { ready: Promise<void> }>(
  sodium: T, baseUrl: string | URL = "./",
): Promise<T & MlDsa65Signer> {
  const base = typeof baseUrl === "string" ? baseUrl : baseUrl.href;
  const fetchWasm = (name: string) =>
    fetch(base + name, { cache: "no-store" }).then((r) => r.arrayBuffer());
  const [, mldsa] = await Promise.all([
    sodium.ready,
    fetchWasm("mldsa65.wasm").then(loadMlDsa65),
  ]);
  return withMlDsa65(sodium, mldsa);
}
