// Dependency-free "minifier" for the compiled host JS.
//
// The source is heavily documented and over half the gzipped host bytes are doc
// comments, so simply stripping comments ~halves the wire size — no bundler, no
// terser, no new dependencies. It reads the commented build/host (kept as-is for
// debugging) and emits a comment-stripped build/host-min (for shipping). One
// `npm run build` produces both.
//
// The host has no regex literals (verified), so a bare `/` is never a regex
// start here and a small string/template-aware scanner is enough. As a safety
// net, every emitted file is syntax-checked with `node --check`, so any scanner
// mistake fails the build loudly rather than shipping broken JS.

import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync, statSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { execFileSync } from "node:child_process";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const srcDir = join(root, "build", "host");
const outDir = join(root, "build", "host-min");

/** Strip `//` and block comments, preserving string and template-literal
 *  contents (including `${ }` interpolations, tracked with a brace stack). */
function stripComments(src) {
  let out = "";
  let st = "code";
  const interp = []; // brace depth of each open ${ } interpolation
  for (let i = 0; i < src.length; i++) {
    const c = src[i], d = src[i + 1];
    if (st === "code") {
      if (c === "/" && d === "/") { st = "line"; i++; continue; }
      if (c === "/" && d === "*") { st = "block"; i++; continue; }
      if (c === "'") { st = "sq"; out += c; continue; }
      if (c === '"') { st = "dq"; out += c; continue; }
      if (c === "`") { st = "tpl"; out += c; continue; }
      if (interp.length) {
        if (c === "{") { interp[interp.length - 1]++; }
        else if (c === "}") {
          if (interp[interp.length - 1] === 0) { interp.pop(); st = "tpl"; out += c; continue; }
          interp[interp.length - 1]--;
        }
      }
      out += c; continue;
    }
    if (st === "line") { if (c === "\n") { st = "code"; out += c; } continue; }
    if (st === "block") { if (c === "*" && d === "/") { st = "code"; i++; } continue; }
    if (st === "sq") { out += c; if (c === "\\") { out += d ?? ""; i++; } else if (c === "'") st = "code"; continue; }
    if (st === "dq") { out += c; if (c === "\\") { out += d ?? ""; i++; } else if (c === '"') st = "code"; continue; }
    if (st === "tpl") {
      out += c;
      if (c === "\\") { out += d ?? ""; i++; continue; }
      if (c === "`") { st = "code"; continue; }
      if (c === "$" && d === "{") { out += d; i++; interp.push(0); st = "code"; continue; }
      continue;
    }
  }
  return out;
}

const minify = (src) =>
  stripComments(src)
    .replace(/[ \t]+$/gm, "")    // trailing whitespace
    .replace(/\n{3,}/g, "\n\n"); // collapse blank-line runs

function walk(d) {
  const files = [];
  for (const name of readdirSync(d)) {
    const p = join(d, name);
    if (statSync(p).isDirectory()) files.push(...walk(p));
    else if (name.endsWith(".js")) files.push(p);
  }
  return files;
}

if (!statSync(srcDir, { throwIfNoEntry: false })?.isDirectory()) {
  console.error("build/host not found — run `npm run build:host` first.");
  process.exit(1);
}

rmSync(outDir, { recursive: true, force: true });
const files = walk(srcDir);
let gzIn = 0, gzOut = 0;
for (const f of files) {
  const src = readFileSync(f, "utf8");
  const min = minify(src);
  const dst = join(outDir, relative(srcDir, f));
  mkdirSync(dirname(dst), { recursive: true });
  writeFileSync(dst, min);
  execFileSync(process.execPath, ["--check", dst]); // throws on any syntax breakage
  gzIn += gzipSync(src, { level: 9 }).length;
  gzOut += gzipSync(min, { level: 9 }).length;
}
const kb = (n) => (n / 1024).toFixed(1) + " KB";
console.log(`minified ${files.length} host files → build/host-min  (${kb(gzIn)} → ${kb(gzOut)} gz, −${(100 * (1 - gzOut / gzIn)).toFixed(0)}%)`);
