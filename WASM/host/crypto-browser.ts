// Browser crypto seam — the counterpart to crypto-node.ts's loadCrypto for a target
// with no node:fs. Same two artifacts (mldsa65.wasm, mlkem768.wasm) mixed onto one
// caller-readied sumo libsodium instance, fetched by URL instead of read from disk.
import { loadMlDsa65, withMlDsa65, type MlDsa65Signer } from "./pq.js";
import { loadMlKem768, withMlKem768, type MlKem768 } from "./kem.js";

/** Ready a caller's sumo libsodium with ML-DSA-65 + ML-KEM-768 mixed on — the
 *  browser counterpart to crypto-node.ts's Node-only `loadCrypto` (§12.1). Both,
 *  always: bootShell's verifyBundle needs the PQ half for ANY bundle, and KEM
 *  rides along so a future guest capability doesn't hit the same gap (§14.1).
 *  `baseUrl` is where the caller's own build staged both .wasm files (siblings,
 *  by convention — same as every current consumer's vendored tree). */
export async function loadCrypto<T extends { ready: Promise<void> }>(
  sodium: T, baseUrl: string | URL = "./",
): Promise<T & MlDsa65Signer & MlKem768> {
  const base = typeof baseUrl === "string" ? baseUrl : baseUrl.href;
  const fetchWasm = (name: string) =>
    fetch(base + name, { cache: "no-store" }).then((r) => r.arrayBuffer());
  const [, mldsa, mlkem] = await Promise.all([
    sodium.ready,
    fetchWasm("mldsa65.wasm").then(loadMlDsa65),
    fetchWasm("mlkem768.wasm").then(loadMlKem768),
  ]);
  return withMlDsa65(withMlKem768(sodium, mlkem), mldsa);
}
