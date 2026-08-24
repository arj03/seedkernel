// Browser crypto seam — crypto-node.ts's loadCrypto for a target with no node:fs: the
// ML-DSA verifier mixed onto one caller-readied core libsodium instance.
import { loadMlDsa65, withMlDsa65, type MlDsa65Signer } from "./pq.js";

/** Ready a caller's core libsodium with ML-DSA-65 — the browser counterpart to
 *  crypto-node.ts's Node-only `loadCrypto`. */
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
