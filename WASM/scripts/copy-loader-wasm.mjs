// Copy the WASM artifacts the Go loader embeds (//go:embed wasm/*.wasm) from
// their canonical build outputs into ../native/wasm/ (the top-level Go module).
// All three are BUILT from this repo's source, so they're gitignored under
// native/wasm/ and produced here by `npm run build:loader` — go:embed can't reach
// across the native/ module boundary to WASM/build or WASM/browser, hence the copy.
// Only native/qjs/qjs.wasm stays committed (vendored upstream, not built here).

import { copyFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const dst = resolve(root, "../native/wasm");
mkdirSync(dst, { recursive: true });

const copies = [
  ["build/kernel.wasm", "kernel.wasm"],
  ["build/bootstrap.wasm", "bootstrap.wasm"],
  ["build/ws.wasm", "ws.wasm"],
  ["browser/libsodium.wasm", "libsodium.wasm"],
];

for (const [from, to] of copies) {
  const src = resolve(root, from);
  if (!existsSync(src)) {
    throw new Error(`missing ${from} — run its build first (npm run build:loader builds these)`);
  }
  copyFileSync(src, resolve(dst, to));
  console.log(`copied ${from} -> ../native/wasm/${to}`);
}
