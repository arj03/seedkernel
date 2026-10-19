// Computes the README's LOC figures ("one implementation, three targets"): `npm run loc`
// exits 1 on drift, and `--write` updates the README. Counted by the README's own rule
// (non-test sources, no blank or comment lines). The shared set is derived from
// build:host-script and checked against the rows, so a shared file missing from every row
// also fails.
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

// ── the rows, exactly as the README groups them ──────────────────────────────
// `find` matches the row's file cell, not its prose, so rewording cannot break a count;
// `--write` puts `render(n)` into the row's last cell.
const cell = (n) => `| ${fmt(n)} |`;

const sharedRows = [
  { find: /`host\/bundle\.ts`, `host\/policy\.ts`/,
    files: ["WASM/host/bundle.ts", "WASM/host/policy.ts", "WASM/host/wasm-limits.ts", "WASM/host/host-blob.ts",
      "WASM/host/slots.ts", "WASM/host/pure-module.ts"] },
  { find: /`host\/transport-host\.ts`/,
    files: ["WASM/host/transport-host.ts"] },
  { find: /`host\/guest-seam\.ts`, `host\/realm-queue\.ts`/,
    files: ["WASM/host/guest-seam.ts", "WASM/host/realm-queue.ts",
      "WASM/host/realm-timers.ts", "WASM/host/fs-view.ts"] },
  { find: /`host\/shell-core\.ts`/,
    files: ["WASM/host/shell-core.ts", "WASM/host/slot-table.ts"] },
  { find: /`host\/cli\.ts`/,
    files: ["WASM/host/cli.ts"] },
  { find: /`host\/engine-realm\.ts`, `host\/sodium-engine\.ts`/,
    files: ["WASM/host/engine-realm.ts", "WASM/host/sodium-engine.ts", "WASM/host/pq.ts"] },
  { find: /`host\/platform\.ts`, `host\/abi\.ts`/,
    files: ["WASM/host/platform.ts", "WASM/host/abi.ts", "WASM/host/host-main.ts", "WASM/host/native-polyfills.ts"] },
  { find: /`services\/\*\.ts` \(\d+ shared files\)/,
    files: [...sharedSet].filter((f) => f.startsWith("WASM/services/") && !f.startsWith("WASM/services/udp/")) },
];

/** The UDP path, counted on its own line: what the shared bundle carries of services/udp/.
 *  A platform's own socket there (node.ts) is per-target, and counted with the JS row. */
const udpFiles = readdirSync(resolve(wasmDir, "services/udp"))
  .filter((f) => f.endsWith(".ts"))
  .map((f) => `WASM/services/udp/${f}`)
  .filter((f) => sharedSet.has(f));

// In the shared bundle but counted elsewhere: the UDP path, and transport-bundle.ts, which
// is one line of signed bundle base64, not host code. Listed so reconciliation can tell them
// from files counted nowhere.
const countedElsewhere = [...udpFiles, "WASM/host/transport-bundle.ts"];

/** Per-target JS: every non-test TS under services/ (and services/udp/) and host/ that the
 *  shared bundle does not include. Derived, so a new backend is counted automatically. */
const jsFiles = ["services", "services/udp", "host"].flatMap((d) =>
  readdirSync(resolve(wasmDir, d))
    .filter((f) => f.endsWith(".ts"))
    .map((f) => `WASM/${d}/${f}`))
  .filter((f) => !sharedSet.has(f) && !countedElsewhere.includes(f));

const goFiles = readdirSync(resolve(repoDir, "native"))
  .filter((f) => f.endsWith(".go") && !f.endsWith("_test.go"))
  .map((f) => `native/${f}`);

const rows = [
  ...sharedRows.map((r) => ({ ...r, n: sum(r.files), render: cell })),
  { find: /\*\*JS\*\* \(browser \+ Node\)/, n: sum(jsFiles),
    render: (n) => `| ${fmt(n)} TS |` },
  { find: /\*\*Native\*\* \(Go\)/, n: sum(goFiles),
    render: (n) => `| ${fmt(n)} Go |` },
];
const sharedTotal = sharedRows.reduce((n, r) => n + sum(r.files), 0);

// ── reconcile the shared set against the rows ────────────────────────────────
const accounted = new Set([...sharedRows.flatMap((r) => r.files), ...countedElsewhere]);
const orphans = [...sharedSet].filter((f) => !accounted.has(f));
const phantoms = [...accounted].filter((f) => !sharedSet.has(f) && !f.startsWith("native/"));

// ── report ───────────────────────────────────────────────────────────────────
const write = process.argv.includes("--write");
let readme = readFileSync(readmePath, "utf8");
const lines = readme.split(/\r?\n/);
let drift = 0;

for (const row of rows) {
  const i = lines.findIndex((l) => row.find.test(l));
  if (i < 0) {
    console.error(`  MISSING  no README row matches ${row.find}`);
    drift++;
    continue;
  }
  const want = row.render(row.n);
  const have = lines[i].slice(lines[i].lastIndexOf("|", lines[i].length - 2));
  const label = lines[i].split("|")[1].trim().replace(/`/g, "").slice(0, 52);
  if (have.trim() === want.trim()) {
    console.log(`  ok       ${String(row.n).padStart(5)}  ${label}`);
  } else {
    drift++;
    console.log(`  ${write ? "fixed" : "DRIFT"}    ${String(row.n).padStart(5)}  ${label}   README says ${have.trim()}`);
    lines[i] = lines[i].slice(0, lines[i].lastIndexOf("|", lines[i].length - 2)) + want;
  }
}
readme = lines.join("\n");

// Prose figures (not cells): match only the number, using the heading or source path
// to identify it. The transport count does not depend on the surrounding sentence.
// The shared total lives in the heading; the guest figure is summed from guest-source.mjs.
const proseFigures = [
  ["shared total (heading)", /(?<=all three targets \()[\d,]+(?= LOC\))/, sharedTotal],
  ["transport/src/*.js", /[\d,]+(?= lines of `transport\/src\/\*\.js`)/,
    sum(guestSourcePaths())],
  ["services/udp/*.ts", /[\d,]+(?= lines of `services\/udp\/\*\.ts`)/, sum(udpFiles)],
];
for (const [label, re, n] of proseFigures) {
  const m = readme.match(re);
  if (!m) { console.error(`  MISSING  no README figure matches ${label}`); drift++; continue; }
  const want = fmt(n);
  if (m[0] === want) {
    console.log(`  ok       ${String(n).padStart(5)}  ${label}`);
  } else {
    drift++;
    console.log(`  ${write ? "fixed" : "DRIFT"}    ${String(n).padStart(5)}  ${label}   README says ${m[0]}`);
    readme = readme.replace(re, want);
  }
}

for (const f of orphans)
  console.error(`  ORPHAN   ${f} is in the shared bundle but in no README row`);
for (const f of phantoms)
  console.error(`  PHANTOM  ${f} is in a README row but not in the shared bundle`);

if (write && (drift > 0)) {
  writeFileSync(readmePath, readme);
  console.log(`\nloc: README updated (${drift} figure${drift === 1 ? "" : "s"}).`);
} else if (drift > 0 || orphans.length || phantoms.length) {
  console.error("\nloc: README is out of date; run `npm run loc -- --write`.");
  process.exit(1);
} else {
  console.log("\nloc: README matches.");
}
