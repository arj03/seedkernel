// Builds the signed host blob (§12.9, host/host-blob.ts): the host script, the realm engine
// and the host's crypto, signed under the hybrid suite. Writes build/host.skb, which every
// loader carries as its genesis host.
//
// The author key is `--key <seed>` or host-author.key, generated on first build, so each
// clone has its own host author. A loader that runs this blob accepts updates only from
// the same author. The version is package.json's `hostVersion`: raise it for a release a
// running node should take, since loaders refuse a version at or below their floor.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import sodiumDefault from "libsodium-wrappers";
import { hybridAuthorKeysFromSeed, signHostBlob } from "../build/scripts/bundle-author.js";
import { createMlDsa65, withMlDsa65 } from "../build/host/pq.js";
import { PLATFORM_ABI } from "../build/host/abi.js";
import { hybridAuthorId } from "../build/host/bundle.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const keyFlag = (() => {
  const i = args.indexOf("--key");
  return i >= 0 && args[i + 1] ? args[i + 1] : undefined;
})();
const toHex = (b) => Buffer.from(b).toString("hex");

await sodiumDefault.ready;
let seed;
const keyPath = join(root, "host-author.key");
if (keyFlag) {
  seed = Uint8Array.from(Buffer.from(keyFlag, "hex"));
} else if (existsSync(keyPath)) {
  seed = Uint8Array.from(Buffer.from(readFileSync(keyPath, "utf8").trim(), "hex"));
} else {
  seed = sodiumDefault.randombytes_buf(32);
  writeFileSync(keyPath, toHex(seed) + "\n", { mode: 0o600 });
  console.log("  wrote host-author.key (keep it; this clone's hosts are signed by it)");
}
if (seed.length !== 32) throw new Error("--key must be 32 bytes of hex");
const sodium = withMlDsa65(sodiumDefault, createMlDsa65(new WebAssembly.Instance(
  new WebAssembly.Module(readFileSync(join(root, "browser", "mldsa65.wasm"))), {})));
const keys = hybridAuthorKeysFromSeed(sodium, seed);

const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).hostVersion;
if (!Number.isSafeInteger(version) || version < 1) throw new Error("package.json hostVersion must be a positive integer");
const blob = signHostBlob(sodium, keys, { version, abi: PLATFORM_ABI }, {
  script: readFileSync(join(root, "build", "host.js")),
  qjs: readFileSync(join(root, "browser", "qjs.wasm")),
  sodium: readFileSync(join(root, "browser", "libsodium.wasm")),
  mldsa: readFileSync(join(root, "browser", "mldsa65.wasm")),
});
writeFileSync(join(root, "build", "host.skb"), blob);
console.log(`  host blob: build/host.skb (${blob.length} B), version ${version}, abi ${PLATFORM_ABI}`);
console.log(`  host author: ${toHex(hybridAuthorId(sodium, keys.ed.publicKey, keys.mlDsa.publicKey))} (hybrid 0x02)`);
