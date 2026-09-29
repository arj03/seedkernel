// Delete compiled files in build/ whose TypeScript source no longer exists.
//
// tsc emits into `build/` but never cleans it, so a deleted host module's compiled output
// stays behind, and since package entry points resolve into `build/`, it stays importable.
// `build-min/` is a separate tsc pass that wipes its destination first, so only `build/`
// needs this.
//
// Limited to `host/`, `services/` and `scripts/`, the subtrees tsconfig.json covers
// (rootDir "."), so the asc outputs and `transport.skb` in `build/` are never touched.

import { readdirSync, statSync, existsSync, rmSync, rmdirSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = join(root, "build");

/** The source a compiled file came from: `build/host/x.js` and `build/host/x.d.ts` both
 *  map to `host/x.ts`. Other extensions are not tsc output and are left alone. */
function sourceOf(abs) {
  const rel = relative(buildDir, abs).split("\\").join("/");
  const stem = rel.endsWith(".d.ts") ? rel.slice(0, -5)
    : rel.endsWith(".js") ? rel.slice(0, -3)
    : null;
  return stem === null ? null : join(root, stem + ".ts");
}

function prune(dir) {
  if (!statSync(dir, { throwIfNoEntry: false })?.isDirectory()) return [];
  const removed = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      removed.push(...prune(p));
      // A directory emptied above belonged to a source directory that is also gone.
      if (readdirSync(p).length === 0) rmdirSync(p);
      continue;
    }
    const src = sourceOf(p);
    if (src === null || existsSync(src)) continue;
    rmSync(p);
    removed.push(relative(buildDir, p).split("\\").join("/"));
  }
  return removed;
}

const removed = ["host", "services", "scripts"].flatMap((d) => prune(join(buildDir, d)));
if (removed.length > 0) {
  console.log(`pruned ${removed.length} orphaned build file(s): ${removed.join(", ")}`);
}
