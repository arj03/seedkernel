// Browser crypto seam: crypto-node.ts's loadCrypto for a target without node:fs. Adds
// ML-DSA-65 to a libsodium instance the caller supplies.
import { loadMlDsa65, randomBytes, withMlDsa65, type MlDsa65Signer } from "./pq.js";

/** Ready the caller's libsodium, add ML-DSA-65 to it, and put the platform CSPRNG under
 *  `randombytes_buf`, as crypto-node.ts does and for its reason. */
export async function loadCrypto<T extends { ready: Promise<void> }>(
  sodium: T, baseUrl: string | URL = "./",
): Promise<T & MlDsa65Signer> {
  const base = typeof baseUrl === "string" ? baseUrl : baseUrl.href;
  // A page that does not serve the file answers with an error page, which would otherwise
  // reach the compiler and fail there as a bad module.
  const fetchWasm = (name: string) =>
    fetch(base + name, { cache: "no-store" }).then((r) => {
      if (!r.ok) throw new Error(`crypto: ${base + name} was not served (HTTP ${r.status})`);
      return r.arrayBuffer();
    });
  const [, mldsa] = await Promise.all([
    sodium.ready,
    fetchWasm("mldsa65.wasm").then(loadMlDsa65),
  ]);
  return withMlDsa65(Object.assign(sodium, { randombytes_buf: randomBytes }), mldsa);
}
