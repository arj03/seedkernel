// Computes the README's LOC figures ("one implementation, three targets"): `npm run loc`
// exits 1 on drift, and `--write` updates the README. Counts non-test sources, without
// blank or comment lines. Every set is derived, the shared one from the scripts that build
// it, so a new file is counted without touching this script.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { guestSourcePaths } from "./guest-source.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const wasmDir = resolve(here, "..");
const repoDir = resolve(wasmDir, "..");
const readmePath = resolve(repoDir, "README.md");

/** Code lines, excluding blank lines, `//` lines and block comments. Intentionally
 *  simple; a real parser would be another language implementation to maintain. A block
 *  comment must start the line: a `/*` elsewhere is a `crypto/*` in prose or a regex, and
 *  treating it as a comment would drop code up to the next close. */
function loc(path) {
  const text = readFileSync(resolve(repoDir, path), "utf8");
  let inBlock = false;
  return text.split(/\r?\n/).filter((l) => {
    const t = l.trim();
    if (inBlock) {
      inBlock = !t.includes("*/");
      return false;
    }
    if (t.startsWith("/*")) {
      inBlock = !t.includes("*/", 2);
      return false;
    }
    return t.length > 0 && !t.startsWith("//");
  }).length;
}

const sum = (files) => files.reduce((n, f) => n + loc(f), 0);
const fmt = (n) => n.toLocaleString("en-US");

// ── the shared set, from the build script that defines it ────────────────────
const pkg = JSON.parse(readFileSync(resolve(wasmDir, "package.json"), "utf8"));
const sharedSet = new Set(
  // Sources sit under build/<dir>/; each script's first path is its output, build/host.js
  // or build/loader.js. The loader script is shared too: both loaders run it.
  ([pkg.scripts["build:host-script"], pkg.scripts["build:loader-script"]].join(" ").match(/build\/[^\s/]+\/\S+\.js/g) ?? [])
    .map((p) => "WASM/" + p.replace(/^build\//, "").replace(/\.js$/, ".ts")));

/** Per-target JS: every non-test TS under services/ and host/ that the shared bundle does
 *  not include. Derived, so a new backend is counted automatically. */
const jsFiles = ["services", "host"].flatMap((d) =>
  readdirSync(resolve(wasmDir, d))
    .filter((f) => f.endsWith(".ts"))
    .map((f) => `WASM/${d}/${f}`))
  .filter((f) => !sharedSet.has(f));

const goFiles = readdirSync(resolve(repoDir, "native"))
  .filter((f) => f.endsWith(".go") && !f.endsWith("_test.go"))
  .map((f) => `native/${f}`);

// ── report ───────────────────────────────────────────────────────────────────
// Each pattern matches only the number, found by its row label or source path, so
// rewording the prose around it cannot break a count.
const row = (label, unit) => new RegExp(`(?<=^\\| \\*\\*${label}\\*\\* .*\\| )[\\d,]+(?= ${unit} \\|)`, "m");
const figures = [
  ["shared", row("Shared", "TS"), sum([...sharedSet])],
  ["per-target JS", row("JS", "TS"), sum(jsFiles)],
  ["native Go", row("Native", "Go"), sum(goFiles)],
  ["transport/src/*.js", /[\d,]+(?= lines of `transport\/src\/\*\.js`)/, sum(guestSourcePaths())],
];

const write = process.argv.includes("--write");
let readme = readFileSync(readmePath, "utf8");
let drift = 0;

for (const [label, re, n] of figures) {
  const m = readme.match(re);
  if (!m) {
    console.error(`  MISSING  no README figure matches ${label}`);
    drift++;
    continue;
  }
  const want = fmt(n);
  if (m[0] === want) {
    console.log(`  ok       ${String(n).padStart(5)}  ${label}`);
  } else {
    drift++;
    console.log(`  ${write ? "fixed" : "DRIFT"}    ${String(n).padStart(5)}  ${label}   README says ${m[0]}`);
    readme = readme.replace(re, want);
  }
}

if (write && (drift > 0)) {
  writeFileSync(readmePath, readme);
  console.log(`\nloc: README updated (${drift} figure${drift === 1 ? "" : "s"}).`);
} else if (drift > 0) {
  console.error("\nloc: README is out of date; run `npm run loc -- --write`.");
  process.exit(1);
} else {
  console.log("\nloc: README matches.");
}
