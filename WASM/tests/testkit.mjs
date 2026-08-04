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
