// What the generated loader bundle was made FROM: the in-repo sources behind it, and what
// each hashed to when it was written. bundle-loader.mjs stamps the answer into
// native/host-shell.gen.js; the Go side re-hashes the same files and refuses an artifact
// whose sources have moved on (native/shell_stamp_test.go).
//
// The artifact is generated, gitignored and never pruned, so nothing about a checkout says
// whether it matches the tree beside it — and everything the native target runs goes
// through it, including, inside the signed transport blob it embeds, the transport guest
// and ws.wasm. A stale one is a whole suite quietly asserting about a program that is no
// longer in the repository.
//
// SOURCES, NOT TOOLS: the .ts each bundled module was compiled from, the transport guest's
// own parts, the ws module's AssemblyScript, and the signed app config that ships with the
// bundle. The generators are deliberately absent — editing one is an edit whose whole point
// was to run it.
//
// The stamp is a statement about `npm run build:loader`, which rebuilds the chain in
// order (ws.wasm → transport bundle → tsc → this). Running one sub-step of that by hand can
// stamp a source the artifact did not really pick up; the answer is to run the whole thing.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative, resolve, sep } from "node:path";
import { guestSourcePaths } from "./guest-source.mjs";

const wasmDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const posix = (p) => p.split(sep).join("/");

/** Sources for one bundle-loader input list, as WASM-relative posix paths, sorted.
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
  // The guest config the bundle is SIGNED over: content of the artifact, not a build knob,
  // and the caps every fuzz target reads back out of the manifest.
  return [...new Set([...ts, ...guest, ...ws, "scripts/transport-config.mjs"])].sort();
}

/** `{ "core/util.ts": "<sha256 hex>", ... }` — the stamp itself. */
export function sourceStamp(buildFiles) {
  const out = {};
  for (const p of stampedSources(buildFiles)) {
    // A source the mapping names but the tree does not have is a mapping that has drifted,
    // not a file to skip: skipping it would stamp a bundle as covering less than it does.
    out[p] = createHash("sha256").update(readFileSync(join(wasmDir, p))).digest("hex");
  }
  return out;
}
