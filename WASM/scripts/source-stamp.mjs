// What the generated native host bundle was built from: the in-repo sources behind it and
// their hashes at build time. bundle-native-host.mjs writes this stamp into
// native/host-shell.gen.js; the Go tests re-hash the same files and refuse an artifact
// whose sources have changed (native/shell_stamp_test.go).
//
// The artifact is generated, gitignored and never pruned, so nothing else says whether it
// matches the checkout, and everything the native target runs goes through it, including
// the transport guest and ws.wasm inside the embedded transport bundle. A stale one means
// the native suite tests code that is no longer in the repository.
//
// Sources only: the .ts each bundled module was compiled from, the transport guest's
// parts, the ws module's AssemblyScript, and the signed transport config. The generator
// scripts are left out, since editing one means running it anyway.
//
// The stamp assumes `npm run build:native`, which rebuilds the chain in order (ws.wasm,
// transport bundle, tsc, this). Running one step by hand can stamp a source the artifact
// did not pick up, so run the whole thing.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative, resolve, sep } from "node:path";
import { guestSourcePaths } from "./guest-source.mjs";

const wasmDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const posix = (p) => p.split(sep).join("/");

/** Sources for one bundle-native-host input list, as WASM-relative posix paths, sorted.
 *  `build/x/y.js` is tsc's output for `x/y.ts`; host/transport-bundle.ts is itself
 *  generated, so the guest parts and the ws module stand in for it. */
export function stampedSources(buildFiles) {
  const ts = buildFiles
    .map(posix)
    .filter((f) => f.startsWith("build/"))
    .map((f) => f.slice("build/".length).replace(/\.js$/, ".ts"))
    .filter((f) => f !== "host/transport-bundle.ts");
  const guest = guestSourcePaths().map((p) => posix(relative(wasmDir, p)));
  const ws = readdirSync(join(wasmDir, "assembly", "ws"))
    .filter((f) => f.endsWith(".ts"))
    .map((f) => "assembly/ws/" + f);
  // The guest config the bundle is signed over: part of the artifact's content.
  return [...new Set([...ts, ...guest, ...ws, "scripts/transport-config.mjs"])].sort();
}

/** The stamp: `{ "services/util.ts": "<sha256 hex>", ... }`. */
export function sourceStamp(buildFiles) {
  const out = {};
  for (const p of stampedSources(buildFiles)) {
    // A listed source missing from the tree means the mapping is wrong; fail instead of
    // skipping it, which would stamp the bundle as covering less than it does.
    out[p] = createHash("sha256").update(readFileSync(join(wasmDir, p))).digest("hex");
  }
  return out;
}
