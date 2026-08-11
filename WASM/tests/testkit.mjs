// testkit.mjs — the assertion/reporting/teardown skeleton the standalone test
// files share. These shapes used to be copied into every file — the pass/fail
// counters, the `test` wrapper, assert/ok/throws, note/sleep, and the teardown
// that kept drifting between files (each had its own finally) — so one copy of
// each lives here, and a test file takes the flavor it wants:
//
//   throw-based:  `test(name, fn)` + `assert(c, m)`  — a failed assertion stops
//                 that test; the wrapper reports it and moves to the next.
//   report-based: `ok(c, m)` / `throws(fn, m)`        — a failed check is logged
//                 and counted, but the file keeps running.
//
// `keep(o)` hands a created node/shell to the wrapper, which closes everything
// kept so far after each test; `summary()` prints the score and owns the exit
// code, so a test file never touches process.exit itself.
//
// `testkit({ verbose: false })` silences the per-check `ok:` lines — for a suite
// that already reports a result per test and only wants the failures counted.

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
  /** Run one test. A synchronous `fn` is run synchronously — so a file that just
   *  calls `test(...)` in sequence and then `summary()` counts correctly; an
   *  async `fn` returns a promise the caller should `await`, and `fn` receives
   *  `keep` for the teardown flavor that constructs one state object per test. */
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

// The author helper below reaches the loader's own derivations rather than restating
// them — a test-side copy of an identity rule would agree with itself and with nothing
// else. Resolved from this file's location so a test file's own root juggling is not
// part of it; every suite runs after `npm run build`, so build/ is there.
const { hybridAuthorId, hybridAuthorKeysFromSeed } = await import(
  pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "..", "build", "host", "bundle.js")).href);

/** A manifest author (seedkernel §12.4), for tests that sign one: the Ed25519 half, the
 *  ML-DSA-65 half, and the 32-byte id the two derive. `signManifest` takes the whole
 *  object, and everything the runtime keys by an author — a policy pin, an app key, a
 *  freshness mark — takes `.id`, so no test can pin half an identity and no test file has
 *  to remember which half is which.
 *
 *  Built through the SHIPPED seed→key-set derivation, so every suite that signs a bundle
 *  exercises the rule real publishers use rather than a test-local imitation of it.
 *
 *  Takes the `sodium` the caller already has, because the test files reach the crypto
 *  differently (`crypto-node`'s readied instance, or a bare libsodium with ML-DSA mixed
 *  in) — and it must be the SAME instance the test verifies with, or the id is hashed by
 *  one implementation and checked by another. Requires ML-DSA-65 to be mixed in already
 *  (`withMlDsa65`); without it a manifest cannot be signed at all.
 *
 *  Fresh keys per call: bundle freshness is keyed by `(author, app)`, so tests sharing an
 *  author would inherit each other's high-water marks. */
export function makeAuthor(sodium) {
  const keys = hybridAuthorKeysFromSeed(sodium, sodium.randombytes_buf(32));
  return { ...keys, id: hybridAuthorId(sodium, keys.ed.publicKey, keys.mlDsa.publicKey) };
}
