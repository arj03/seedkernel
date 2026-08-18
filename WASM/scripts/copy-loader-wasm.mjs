// Copy the WASM artifacts the Go loader embeds (//go:embed wasm/*.wasm) from their
// canonical build outputs into ../native/wasm/. go:embed cannot reach across the
// native/ module boundary to WASM/build or WASM/browser, hence the copy; all of them
// are built from this repo's source and gitignored there.

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
  // ML-KEM-768 for the primitive catalog (§14.1) — a name in the catalog must mean the
  // same bytes on every target.
  ["browser/mlkem768.wasm", "mlkem768.wasm"],
];

for (const [from, to] of copies) {
  const src = resolve(root, from);
  if (!existsSync(src)) {
    throw new Error(`missing ${from} — run its build first (npm run build:loader builds these)`);
  }
  copyFileSync(src, resolve(dst, to));
  console.log(`copied ${from} -> ../native/wasm/${to}`);
}
