// The shipped host tree (§10.2). `build/` keeps its doc comments for debugging;
// `build-min/` is what a browser vendors, and over half its gzipped bytes would be those
// comments — so this is a second `tsc` pass with `removeComments`, nothing more. Letting
// the compiler strip them is what keeps a hand-written lexer, which cannot tell a regex
// literal from a division, out of the build. One `npm run build` produces both trees.

import { readFileSync, rmSync, readdirSync, statSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { execFileSync } from "node:child_process";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const srcDir = join(root, "build");
const outDir = join(root, "build-min");

function walk(d) {
  const files = [];
  for (const name of readdirSync(d)) {
    const p = join(d, name);
    if (statSync(p).isDirectory()) files.push(...walk(p));
    else if (name.endsWith(".js")) files.push(p);
  }
  return files;
}

rmSync(outDir, { recursive: true, force: true });
execFileSync(
  process.execPath,
  [join(root, "node_modules", "typescript", "bin", "tsc"), "-p", "tsconfig.min.json"],
  { cwd: root, stdio: "inherit" },
);

// Offline authoring is a package entry point from build/host, but build-min is the runtime
// tree staged into browser shells. Keeping the signer out here makes that boundary physical.
rmSync(join(outDir, "host", "bundle-author.js"), { force: true });

const files = walk(outDir);
let gzIn = 0, gzOut = 0;
for (const f of files) {
  gzIn += gzipSync(readFileSync(join(srcDir, relative(outDir, f)), "utf8"), { level: 9 }).length;
  gzOut += gzipSync(readFileSync(f, "utf8"), { level: 9 }).length;
}
const kb = (n) => (n / 1024).toFixed(1) + " KB";
console.log(`minified ${files.length} host files → build-min  (${kb(gzIn)} → ${kb(gzOut)} gz, −${(100 * (1 - gzOut / gzIn)).toFixed(0)}%)`);
