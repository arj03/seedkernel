// Copy the WASM artifacts from their canonical build outputs into ../native/wasm/ so the
// Go loader can embed them (go:embed cannot cross the native/ module boundary). All of
// them are built from this repo's source and gitignored where they live.

import { copyFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const dst = resolve(root, "../native/wasm");
mkdirSync(dst, { recursive: true });

const copies = [
  ["browser/libsodium.wasm", "libsodium.wasm"],
  // ML-DSA-65 for manifest suite 0x02 (§12.4): the Go loader instantiates the very
  // artifact the browser fetches, so there is one accept/reject boundary.
  ["browser/mldsa65.wasm", "mldsa65.wasm"],
];

for (const [from, to] of copies) {
  const src = resolve(root, from);
  if (!existsSync(src)) {
    throw new Error(`missing ${from} — run its build first (npm run build:loader builds these)`);
  }
  copyFileSync(src, resolve(dst, to));
  console.log(`copied ${from} -> ../native/wasm/${to}`);
}
