// The LOC figures in README §"One implementation, three targets", computed rather
// than remembered.
//
//   npm run loc            print the table and check the README against it (exit 1 on drift)
//   npm run loc -- --write rewrite the README's numbers to match
//
// **Why this exists.** Those counts carry an argument — that the shared set is small
// and that each target's plumbing is the larger, replaceable part — so a wrong one is
// not a typo, it is a claim the repo cannot support. They are also the most
// mechanically drift-prone text in the file: every refactor invalidates them and none
// of them fails a test. A row once sat 13 lines high on two files the change never
// touched, which made a real reduction read as flat.
//
// The counting rule is the README's own sentence: "lines of code — non-test sources
// with blank lines and comments excluded."
//
// **The shared set is derived, not listed.** `build:loader-bundles` names the files
// compiled into `host-shell.gen.js`, and the README says that list *is* the shared
// set — so it is read from package.json and reconciled against the rows below. A file
// that joins the shared bundle without joining a row fails this script, which is the
// drift worth catching: a wrong number misinforms, but a file that quietly entered the
// trusted shared set and appears in no row is invisible.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

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
//
// `find` is the README line this row's number lives on, matched on the row's file
// cell rather than its prose, so re-wording a row does not silently orphan its count.
// `sharedFiles` are the shared-set members a row accounts for; `--write` puts
// `render(n)` back into the row's last cell.
const cell = (n) => `| ${fmt(n)} |`;

const sharedRows = [
    { find: /`host\/bundle\.ts`, `host\/policy\.ts`/,
      files: ["WASM/host/bundle.ts", "WASM/host/policy.ts"] },
    { find: /`host\/transport-host\.ts`/,
      files: ["WASM/host/transport-host.ts"] },
    { find: /`host\/cap-bridge\.ts`, `host\/realm-queue\.ts`/,
      files: ["WASM/host/cap-bridge.ts", "WASM/host/realm-queue.ts"] },
    { find: /`host\/shell-core\.ts`, `host\/bindings\.ts`/,
      files: ["WASM/host/shell-core.ts", "WASM/host/bindings.ts"] },
    { find: /`core\/\*\.ts` \(\d+ files\)/,
      files: [...sharedSet].filter((f) => f.startsWith("WASM/core/")) },
];

// `native-shim.ts` and `transport-bundle.ts` ride in the shared bundle but are counted
// elsewhere and on purpose: the shim is the Go binding (a per-target row), and
// transport-bundle.ts is one line holding the signed blob's base64, which is content,
// not host code. Named here so the reconciliation below can tell "counted elsewhere"
// apart from "counted nowhere".
const countedElsewhere = ["WASM/host/native-shim.ts", "WASM/host/transport-bundle.ts"];

/** Per-target JS: every non-test TS under core/ and host/ that the shared bundle does
 *  not compile in. Derived rather than listed, so a new backend counts itself. */
const jsFiles = ["core", "host"].flatMap((d) =>
    readdirSync(resolve(wasmDir, d))
        .filter((f) => f.endsWith(".ts"))
        .map((f) => `WASM/${d}/${f}`))
    .filter((f) => !sharedSet.has(f) && !countedElsewhere.includes(f));

const goFiles = readdirSync(resolve(repoDir, "native"))
    .filter((f) => f.endsWith(".go") && !f.endsWith("_test.go"))
    .map((f) => `native/${f}`);

const shimLoc = loc("WASM/host/native-shim.ts");
const rows = [
    ...sharedRows.map((r) => ({ ...r, n: sum(r.files), render: cell })),
    { find: /\*\*JS\*\* \(browser \+ Node\)/, n: sum(jsFiles),
      render: (n) => `| ${fmt(n)} TS |` },
    { find: /\*\*Native\*\* \(Go\)/, n: sum(goFiles),
      render: (n) => `| ${fmt(n)} Go + ${fmt(shimLoc)} TS |` },
    { find: /`transport\/guest\.js` \+ `ws\.wasm`/, n: loc("WASM/transport/guest.js"),
      render: (n) => `| ${fmt(n)} + 5 KB |` },
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

// The two prose totals, which have to agree with the shared rows above. Both are
// checked, not just the heading: they are the same claim stated twice, 30 lines apart,
// which is exactly how one of them ends up saying something the other does not.
const totals = [
    ["shared total (heading)", /(all three targets \()[\d,]+( LOC\))/],
    ["shared total (prose)", /(therefore runs )[\d,]+( shared lines)/],
];
for (const [label, re] of totals) {
    const m = readme.match(re);
    if (!m) { console.error(`  MISSING  no README total matches ${label}`); drift++; continue; }
    const want = `${m[1]}${fmt(sharedTotal)}${m[2]}`;
    if (m[0] === want) {
        console.log(`  ok       ${String(sharedTotal).padStart(5)}  ${label}`);
    } else {
        drift++;
        console.log(`  ${write ? "fixed" : "DRIFT"}    ${String(sharedTotal).padStart(5)}  ${label}   README says ${m[0].match(/[\d,]+/)[0]}`);
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
