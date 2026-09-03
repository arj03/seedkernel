// Computes the README's LOC figures ("one implementation, three targets") rather than
// remembering them: `npm run loc` drifts → exit 1, `--write` rewrites the README.
// Counted per the README's own rule (non-test sources, no blanks/comments), and the
// shared set is DERIVED from build:loader-bundles and reconciled against the rows, so a
// shared file appearing in no row fails too.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { guestSourcePaths } from "./guest-source.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const wasmDir = resolve(here, "..");
const repoDir = resolve(wasmDir, "..");
const readmePath = resolve(repoDir, "README.md");

/** Code lines: blank lines, `//` lines and block comments excluded. Deliberately
 *  crude — it is counting the same way a reader eyeballing the file would, and a
 *  parser here would be a second language implementation to keep correct. */
function loc(path) {
  const text = readFileSync(resolve(repoDir, path), "utf8");
  return text.replace(/\/\*[\s\S]*?\*\//g, "").split(/\r?\n/).filter((l) => {
    const t = l.trim();
    return t.length > 0 && !t.startsWith("//") && !t.startsWith("*");
  }).length;
}

const sum = (files) => files.reduce((n, f) => n + loc(f), 0);
const fmt = (n) => n.toLocaleString("en-US");

// ── the shared set, from the build script that defines it ────────────────────
const pkg = JSON.parse(readFileSync(resolve(wasmDir, "package.json"), "utf8"));
const sharedSet = new Set(
  (pkg.scripts["build:loader-bundles"].match(/build\/\S+\.js/g) ?? [])
    .map((p) => "WASM/" + p.replace(/^build\//, "").replace(/\.js$/, ".ts")));

// ── the rows, exactly as the README groups them ──────────────────────────────
// `find` matches the row's file cell rather than its prose (re-wording can't orphan a
// count); `--write` puts `render(n)` back into the row's last cell.
const cell = (n) => `| ${fmt(n)} |`;

const sharedRows = [
  { find: /`host\/bundle\.ts`, `host\/policy\.ts`/,
    files: ["WASM/host/bundle.ts", "WASM/host/policy.ts"] },
  { find: /`host\/transport-host\.ts`/,
    files: ["WASM/host/transport-host.ts"] },
  { find: /`host\/guest-seam\.ts`, `host\/realm-queue\.ts`/,
    files: ["WASM/host/guest-seam.ts", "WASM/host/realm-queue.ts",
      "WASM/host/realm-timers.ts", "WASM/host/fs-view.ts"] },
  { find: /`host\/shell-core\.ts`/,
    files: ["WASM/host/shell-core.ts", "WASM/host/slot-table.ts"] },
  { find: /`host\/cli\.ts`, `host\/peer-addr\.ts`, `host\/op-frame\.ts`/,
    files: ["WASM/host/cli.ts", "WASM/host/peer-addr.ts", "WASM/host/op-frame.ts"] },
  { find: /`core\/\*\.ts` \(\d+ files\)/,
    files: [...sharedSet].filter((f) => f.startsWith("WASM/core/")) },
];

// Ride in the shared bundle but counted elsewhere on purpose (the Go target's own;
// transport-bundle.ts is one line of signed blob base64, content not host code) — named
// so reconciliation can tell them from "counted nowhere".
const nativeTs = ["WASM/host/native-shim.ts", "WASM/host/native-polyfills.ts"];
const countedElsewhere = [...nativeTs, "WASM/host/transport-bundle.ts"];
// A public build-tool entry point, deliberately absent from both runtime artifacts.
const offlineTs = ["WASM/host/bundle-author.ts"];

/** Per-target JS: every non-test TS under core/ and host/ that the shared bundle does
 *  not compile in. Derived rather than listed, so a new backend counts itself. */
const jsFiles = ["core", "host"].flatMap((d) =>
  readdirSync(resolve(wasmDir, d))
    .filter((f) => f.endsWith(".ts"))
    .map((f) => `WASM/${d}/${f}`))
  .filter((f) => !sharedSet.has(f) && !countedElsewhere.includes(f) && !offlineTs.includes(f));

const goFiles = readdirSync(resolve(repoDir, "native"))
  .filter((f) => f.endsWith(".go") && !f.endsWith("_test.go"))
  .map((f) => `native/${f}`);

// The Native row's TS side follows from `nativeTs` above, so a third such file extends
// that list and the row's numbers follow — one list, not a list plus a row.
const rows = [
  ...sharedRows.map((r) => ({ ...r, n: sum(r.files), render: cell })),
  { find: /\*\*JS\*\* \(browser \+ Node\)/, n: sum(jsFiles),
    render: (n) => `| ${fmt(n)} TS |` },
  { find: /\*\*Native\*\* \(Go\)/, n: sum(goFiles),
    render: (n) => `| ${fmt(n)} Go + ${fmt(sum(nativeTs))} TS |` },
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

// The Native row's prose gives each of its TS files its own figure (`native-shim.ts`
// (N)). Checked like the cells above: an inline figure drifts just as easily as a cell,
// and nothing else would notice.
const inlineChecks = [
  { file: "WASM/host/native-shim.ts", re: /native-shim\.ts` \((\d+)\)/ },
  { file: "WASM/host/native-polyfills.ts", re: /native-polyfills\.ts` \((\d+)\)/ },
];
for (const { file, re } of inlineChecks) {
  const base = file.split("/").pop();
  const m = readme.match(re);
  if (!m) {
    console.error(`  MISSING  no README count matches ${base}`);
    drift++;
    continue;
  }
  const want = loc(file);
  if (Number(m[1]) === want) {
    console.log(`  ok       ${String(want).padStart(5)}  ${base}`);
  } else {
    drift++;
    console.log(`  ${write ? "fixed" : "DRIFT"}    ${String(want).padStart(5)}  ${base}   README says (${m[1]})`);
    readme = readme.replace(re, `${base}\` (${want})`);
  }
}

// Prose figures (not cells): matched on the words either side, so the number is the only
// thing rewritten. The shared total lives in the heading; the guest figure is summed
// from guest-source.mjs.
const proseFigures = [
  ["shared total (heading)", /(all three targets \()[\d,]+( LOC\))/, sharedTotal],
  ["transport/src/*.js", /(transport bundle — )[\d,]+( lines of `transport\/src\/\*\.js`)/,
    sum(guestSourcePaths())],
];
for (const [label, re, n] of proseFigures) {
  const m = readme.match(re);
  if (!m) { console.error(`  MISSING  no README figure matches ${label}`); drift++; continue; }
  const want = `${m[1]}${fmt(n)}${m[2]}`;
  if (m[0] === want) {
    console.log(`  ok       ${String(n).padStart(5)}  ${label}`);
  } else {
    drift++;
    console.log(`  ${write ? "fixed" : "DRIFT"}    ${String(n).padStart(5)}  ${label}   README says ${m[0].match(/[\d,]+/)[0]}`);
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
  console.error("\nloc: README is out of date — run `npm run loc -- --write`.");
  process.exit(1);
} else {
  console.log("\nloc: README matches.");
}
