// testkit.mjs — the assertion/reporting/teardown skeleton the standalone test files share.
// throw-based flavor: `test(name, fn)` + `assert(c, m)` — a failed assertion stops that
// test, the wrapper reports it and moves on. report-based: `ok(c, m)` / `throws(fn, m)` —
// a failed check is logged and counted, the file keeps going. `keep(o)` closes everything
// kept so far after each test; `summary()` owns the exit code, so a test file never calls
// process.exit itself. `testkit({ verbose: false })` silences the per-check `ok:` lines.

import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export function testkit({ verbose = true } = {}) {
  let pass = 0, fail = 0;
  const cleanups = [];

  const assert = (c, m) => { if (!c) throw new Error(m); };
  const ok = (c, m) => { if (c) { pass++; if (verbose) console.log(`  ok:   ${m}`); } else { fail++; console.error(`  FAIL: ${m}`); } };
  const throws = (fn, m) => { try { fn(); ok(false, m); } catch { ok(true, m); } };
  const note = (s) => console.log(`       \u00b7 ${s}`);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  /** Register a per-test cleanup (a shell to close, a node to dispose). */
  const keep = (o) => { cleanups.push(o); return o; };
  /** Close everything kept so far. */
  const cleanup = () => {
    for (const o of cleanups.splice(0)) {
      // A test keeps either the state object itself (a `close()`) or a node whose
      // cleanup hangs off `.shell` — close whichever shape it kept.
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
  return { assert, ok, throws, note, sleep, keep, test, summary };
}

// The author helper below reaches the loader's own derivations rather than restating them
// — a test-side copy of an identity rule would agree with itself and nothing else.
// Resolved from this file's location; every suite runs after `npm run build`.
const { hybridAuthorId } = await import(
  pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "..", "build", "host", "bundle.js")).href);
const { hybridAuthorKeysFromSeed } = await import(
  pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "..", "build", "host", "bundle-author.js")).href);

/** A manifest author (§12.4): the Ed25519 half, the ML-DSA-65 half, and the 32-byte id
 *  the two derive — built through the SHIPPED seed→key-set derivation, so a suite that
 *  signs a bundle exercises the rule real publishers use. Takes the caller's own
 *  `sodium` — it must be the SAME instance the test verifies with. Fresh keys per call:
 *  freshness is keyed by (author, app), so shared authors would inherit high-water marks. */
export function makeAuthor(sodium) {
  const keys = hybridAuthorKeysFromSeed(sodium, sodium.randombytes_buf(32));
  return { ...keys, id: hybridAuthorId(sodium, keys.ed.publicKey, keys.mlDsa.publicKey) };
}
