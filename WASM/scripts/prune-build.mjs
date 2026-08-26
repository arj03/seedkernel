// Delete compiled files in build/ whose TypeScript source is gone — the one link in the
// publish chain that does not prune itself.
//
// tsc emits into `build/` but never cleans it, so deleting a host module leaves its
// compiled corpse behind forever. Everything downstream then copies that corpse
// faithfully: `minify.mjs` walks the runtime-eligible files in `build/` into `build-min/`
// (excluding only the intentional offline `bundle-author.js` entry point), and a client's
// vendor step copies `build-min/` wholesale into its own tree. Both of those already wipe
// their destination first, so neither can be blamed for the stale file and neither can
// remove it — the orphan is re-created from `build/` on every run. That is how `host/kem.js`
// outlived the move of ML-KEM into the transport bundle.
//
// Scoped to `host/` and `core/`, the two subtrees tsconfig.json owns (rootDir "."), so
// the asc outputs and `transport.skb` that share `build/` are never candidates.

import { readdirSync, statSync, existsSync, rmSync, rmdirSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = join(root, "build");

/** The source a compiled artifact came from: `build/host/x.js` and `build/host/x.d.ts`
 *  both trace back to `host/x.ts`. Anything with another extension is not tsc's and is
 *  left alone — a file this script cannot attribute is not one it may delete. */
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
      // A directory emptied by the walk above was a source directory that is gone too.
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

const removed = [...prune(join(buildDir, "host")), ...prune(join(buildDir, "core"))];
if (removed.length > 0) {
  console.log(`pruned ${removed.length} orphaned build file(s): ${removed.join(", ")}`);
}
