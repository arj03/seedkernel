// Builds the signed host blob (§12.9, host/host-blob.ts): the host script, the realm engine
// and the host's crypto, signed under the hybrid suite. Writes build/host.skb, which every
// loader carries as its genesis host.
//
// The author key is `--key <seed>` or host-author.key, generated on first build, so each
// clone has its own host author. A loader that runs this blob accepts updates only from
// the same author. The version is package.json's `hostVersion`: raise it for a release a
// running node should take, since loaders refuse a version at or below their floor.
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildAuthor, signHostBlob } from "../build/scripts/bundle-author.js";
import { PLATFORM_ABI } from "../build/host/abi.js";
import { hybridAuthorId } from "../build/host/bundle.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const toHex = (b) => Buffer.from(b).toString("hex");
const { sodium, keys } = buildAuthor(root, "host-author.key", process.argv.slice(2));

const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).hostVersion;
if (!Number.isSafeInteger(version) || version < 1) throw new Error("package.json hostVersion must be a positive integer");
const blob = signHostBlob(sodium, keys, { version, abi: PLATFORM_ABI }, {
  script: readFileSync(join(root, "build", "host.js")),
  // Where the native build keeps it (native/qjs/build-qjs.sh), checked in there since
  // go:embed cannot reach outside native/.
  qjs: readFileSync(join(root, "..", "native", "qjs", "qjs.wasm")),
  sodium: readFileSync(join(root, "browser", "libsodium.wasm")),
  mldsa: readFileSync(join(root, "browser", "mldsa65.wasm")),
});
writeFileSync(join(root, "build", "host.skb"), blob);
console.log(`  host blob: build/host.skb (${blob.length} B), version ${version}, abi ${PLATFORM_ABI}`);
console.log(`  host author: ${toHex(hybridAuthorId(sodium, keys.ed.publicKey, keys.mlDsa.publicKey))} (hybrid 0x02)`);
