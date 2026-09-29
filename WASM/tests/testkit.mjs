// The assertion, reporting and teardown helpers the standalone test files share.
// Throw-based: `test(name, fn)` with `assert(c, m)`; a failed assertion stops that test,
// which is reported, and the run moves on. Report-based: `ok(c, m)` / `throws(fn, m)`; a
// failed check is logged and counted and the file keeps going. `keep(o)` closes everything
// kept so far after each test; `summary()` sets the exit code, so a test file never calls
// process.exit itself. `testkit({ verbose: false })` silences the per-check `ok:` lines.

import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/** An `imp(path)` closure bound to `root`: resolves a `build/...`-relative path to a file
 *  URL and imports it. */
export function importBuilt(root) {
  return (p) => import(pathToFileURL(join(root, p)).href);
}

export function testkit({ verbose = true } = {}) {
  let pass = 0, fail = 0;
  const cleanups = [];

  const assert = (c, m) => { if (!c) throw new Error(m); };
  const ok = (c, m) => { if (c) { pass++; if (verbose) console.log(`  ok:   ${m}`); } else { fail++; console.error(`  FAIL: ${m}`); } };
  const throws = (fn, m) => { try { fn(); ok(false, m); } catch { ok(true, m); } };
  const note = (s) => console.log(`       \u00b7 ${s}`);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  /** `ok`, normalizing both sides first, so a mismatch reports readable expected/got text
   *  instead of `[object Object]`. */
  const assertEqual = (actual, expected, m) => {
    const norm = (v) => {
      if (v === null || v === undefined) return String(v);
      if (typeof v === "object") return JSON.stringify([...v]);
      return v;
    };
    const a = norm(actual), e = norm(expected);
    ok(a === e, `${m}: expected ${e}, got ${a}`);
  };
  /** Register a per-test cleanup (a shell to close, a node to dispose). */
  const keep = (o) => { cleanups.push(o); return o; };
  /** Close everything kept so far. */
  const cleanup = () => {
    for (const o of cleanups.splice(0)) {
      // A test keeps either an object with `close()` or a node whose `.shell` has one.
      const target = o?.shell ?? o;
      try { target.close?.(); } catch { /* already down */ }
    }
  };
  /** Run one test. A synchronous `fn` runs synchronously, so a file that calls `test(...)`
   *  in sequence and then `summary()` counts correctly; an async `fn` returns a promise
   *  the caller should `await`. `fn` receives `keep`. */
  const test = (name, fn) => {
    let run;
    try { run = fn(keep); }
    catch (e) { fail++; console.log(`  FAIL ${name}\n       ${e.message}`); cleanup(); return; }
    if (run && typeof run.then === "function") {
      return run.then(
        () => { pass++; console.log(`  OK   ${name}`); },
        (e) => { fail++; console.log(`  FAIL ${name}\n       ${e.message}`); },
      ).finally(cleanup);
    }
    pass++;
    console.log(`  OK   ${name}`);
    cleanup();
  };
  const summary = (label = "Results") => {
    console.log(`\n${label}: ${pass} passed, ${fail} failed`);
    process.exit(fail === 0 ? 0 : 1);
  };
  return { assert, ok, assertEqual, throws, note, sleep, keep, test, summary };
}

// The author helper below uses the host's own derivations instead of a test-side copy,
// which would only agree with itself. Resolved from this file's location; every suite
// runs after `npm run build`.
const impBuilt = importBuilt(join(dirname(fileURLToPath(import.meta.url)), ".."));
const { hybridAuthorId } = await impBuilt("build/host/bundle.js");
const { hybridAuthorKeysFromSeed } = await impBuilt("build/scripts/bundle-author.js");

/** A manifest author (§12.4): the Ed25519 half, the ML-DSA-65 half, and the 32-byte id
 *  derived from both, built with the shipped seed-to-key-set derivation. Takes the
 *  caller's `sodium`, which must be the same instance the test verifies with. Fresh keys
 *  per call: freshness is keyed by (author, app), so shared authors would inherit marks. */
export function makeAuthor(sodium) {
  const keys = hybridAuthorKeysFromSeed(sodium, sodium.randombytes_buf(32));
  return { ...keys, id: hybridAuthorId(sodium, keys.ed.publicKey, keys.mlDsa.publicKey) };
}
