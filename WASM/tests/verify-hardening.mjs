import { signTestBundle, verifyTestBundle } from "./bundle-fixtures.mjs";
// Focused checks of the resource bounds (§4.3 memory bounds, §12.2 scoping and seam gates,
// §12.3 realm budgets, §12.4 guest-only apps). Standalone because each block is a tight
// loop over one seam; the *.test.mjs suites cover the same ground end to end. Run after
// `npm run build`.

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import _sodium from "libsodium-wrappers";
import { testkit, makeAuthor, importBuilt } from "./testkit.mjs";
import { readGuestSource } from "../scripts/guest-source.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = importBuilt(root);

await _sodium.ready;
const sodium = _sodium;

const { ModuleTable } = await imp("build/host/module-table.js");
const { readModuleLimits, checkModuleLimits, DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES, DEFAULT_MAX_BUNDLE_MODULES,
  DEFAULT_MAX_APP_SLOTS, DEFAULT_GUEST_DEADLINE_MS,
  SELF_INITIATED_CLOCK_DIVISOR,
  DEFAULT_REALM_MEMORY_BYTES, DEFAULT_MAX_MODULE_MEMORY_BYTES }
  = await imp("build/host/wasm-limits.js");
const { DEFAULT_MEMORY_FS_MAX_BYTES } = await imp("build/services/fs-memory.js");
const { MAX_OUTBOUND_QUEUE_BYTES, MAX_OUTBOUND_QUEUE_SLICES,
  MAX_NODE_OUTBOUND_QUEUE_BYTES, MAX_INBOUND_HOLD_BYTES }
  = await imp("build/services/net-limits.js");
const { MemoryFs } = await imp("build/services/fs-memory.js");
const { appScopeFor, loadBundleModules, FreshnessMarks }
  = await imp("build/host/bundle.js");
const { guestOpFraming } = await imp("build/scripts/bundle-author.js");
// Add ML-DSA-65 to this instance, as a target does at its crypto seam: a manifest is
// signed and verified with both halves of the author's key set (§12.4), so plain
// libsodium cannot sign one.
const { withMlDsa65, loadMlDsa65 } = await imp("build/host/pq.js");
withMlDsa65(sodium, await loadMlDsa65(readFileSync(join(root, "browser/mldsa65.wasm"))));
/** A manifest author: both halves of the key set, plus the 32-byte id derived from them,
 *  which policies and freshness marks use. `ed` also serves as a node identity. */
const testAuthor = () => makeAuthor(sodium);
const { bootShell, scopedFs } = await imp("build/host/shell-core.js");
const { createRealmTimers } = await imp("build/host/realm-timers.js");
const { toHex } = await imp("build/services/util.js");
const { admitAll } = await imp("build/host/policy.js");
const { createGuestSeam, CallBudget, HOST_CALLER_ID } = await imp("build/host/guest-seam.js");
const ALL_HOST_SERVICES = ["node", "fs", "timer", "link"];
const TEST_TIMERS = { arm() {}, clear() {} };
const TEST_CALL_LOCAL = () => null;
const TEST_LINK = { open: () => ({ linkId: 0, stream: false }), send() {}, close() {}, deliver: async () => new Uint8Array(0) };
const { callerOf, readOp, writeOp } = await imp("build/services/op-frame.js");
const isWake = (arg) => arg.length > 32 && callerOf(arg).fromHost && readOp(arg.subarray(32)).op === "wake";
const { createSafeRealm, createActiveHostCallRegistry } = await imp("build/host/safe-js.js");
const { createDeadlineQueue, serializeCalls } = await imp("build/host/realm-queue.js");

const { ok, throws, summary, sleep } = testkit();
/** Await a promise and assert it rejects: the async form of `throws`, needed because
 *  `PureModuleLoader.build` is async. */
const rejects = async (p, msg) => { let threw = false; try { await p; } catch { threw = true; } ok(threw, msg); };

const withMax = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
const noMax = new Uint8Array(readFileSync(join(root, "build/forwarder-nomax.wasm")));
const leb = (n) => { const out = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b); } while (n); return out; };
const section = (id, body) => [id, ...leb(body.length), ...body];
/** A module header plus only the sections the bounds check reads. That check walks
 *  section headers without validating the rest (host/wasm-limits.ts), so an oversized
 *  declaration is cheap to build here. */
const rawModule = (...sections) => new Uint8Array([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0, ...sections.flat()]);
const memSection = (initialPages, maxPages) => section(5, [0x01, 0x01, ...leb(initialPages), ...leb(maxPages)]); // one memory, flags=1 (a maximum is declared)
/** One funcref table of `initial` elements; `max` null declares no maximum. */
const tableSection = (initial, max) => section(4, [0x01, 0x70,
  ...(max === null ? [0x00, ...leb(initial)] : [0x01, ...leb(initial), ...leb(max)])]);
/** A module importing a table (`e.t`) instead of declaring one. */
const importedTableModule = () => rawModule(section(2, [0x01, 0x01, 0x65, 0x01, 0x74, 0x01, 0x70, 0x00, ...leb(1)]));
const memModule = (initialPages, maxPages) => rawModule(memSection(initialPages, maxPages));

console.log("\n§4.3 — declared memory and tables are bounded before instantiation");
{
  const a = readModuleLimits(withMax);
  const b = readModuleLimits(noMax);
  ok(a.memory.maxPages === 256, `built module declares a 256-page maximum (got ${a.memory.maxPages})`);
  ok(b.memory.maxPages === null, "the no-maximum build declares none");
  ok(checkModuleLimits(withMax, 64 * 1024 * 1024).memory !== null, "a bounded module passes the budget");
  throws(() => checkModuleLimits(noMax, 64 * 1024 * 1024), "a module with no declared maximum is refused");
  throws(() => checkModuleLimits(withMax, 1024 * 1024), "a module above the host budget is refused");
  throws(() => checkModuleLimits(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), 1 << 20), "a non-wasm blob is refused");

  // A table is the other allocation a declaration alone causes: the engine reserves every
  // element at instantiation (~28 bytes each on V8), so it counts against the same budget.
  ok(a.maxTableElements === 0, "the built module declares no table");
  ok(checkModuleLimits(rawModule(memSection(1, 1), tableSection(16, 16)), 64 * 1024 * 1024).maxTableElements === 16,
    "a module with a small bounded table passes the budget");
  throws(() => checkModuleLimits(rawModule(memSection(1, 1), tableSection(1, null)), 64 * 1024 * 1024),
    "a table with no declared maximum is refused, as an unbounded memory is");
  throws(() => checkModuleLimits(rawModule(memSection(1, 1), tableSection(10_000_000, 10_000_000)), 64 * 1024 * 1024),
    "a table above the host budget is refused though the module's memory fits");
  throws(() => checkModuleLimits(rawModule(tableSection(10_000_000, 10_000_000)), 64 * 1024 * 1024),
    "a module declaring no memory is still charged for its tables");
  throws(() => checkModuleLimits(importedTableModule(), 64 * 1024 * 1024),
    "an imported table is refused like an imported memory (§4.2)");

  // The ceiling is applied once, on the shared load path (bundle.ts `loadBundleModules`),
  // for every target. A stub loader is enough, since this tests that path, not an isolate.
  const stub = () => ({
    build: async () => ({ call: async () => ({ bytes: null, ms: 0 }), dispose() { } }),
  });
  const bundleOf = (wasm) => ({ modules: [{ mod: { name: "m" }, wasm }] });
  ok(await loadBundleModules(stub(), bundleOf(withMax)) !== null,
    "a module inside the shared ceiling loads");
  await rejects(loadBundleModules(stub(), bundleOf(noMax)),
    "an unbounded module is refused on the load path, whatever a loader would have built");
  // 128 MiB declared against a 64 MiB ceiling.
  await rejects(loadBundleModules(stub(), bundleOf(memModule(1, 2048))),
    "a module above the shared ceiling is refused whatever the loader would have built");
  await rejects(loadBundleModules(stub(), {
    modules: [
      { mod: { name: "a" }, wasm: memModule(1, 600) },
      { mod: { name: "b" }, wasm: memModule(1, 600) },
    ],
  }), "module maxima are bounded in aggregate across one bundle");
  // Table elements count toward the same total: 1.5M elements is 48 MiB, so one such
  // module fits and two do not.
  const tabled = rawModule(memSection(1, 1), tableSection(1, 1_500_000));
  ok(await loadBundleModules(stub(), bundleOf(tabled)) !== null,
    "a module whose table fits the budget loads");
  await rejects(loadBundleModules(stub(), {
    modules: [{ mod: { name: "a" }, wasm: tabled }, { mod: { name: "b" }, wasm: tabled }],
  }), "declared tables are bounded in aggregate across one bundle");

  const host = new ModuleTable();
  const loaded = await host.build([{ name: "ok", wasm: withMax }]);
  const echoed = await loaded.call("ok", new Uint8Array());
  ok(echoed instanceof Object && echoed.bytes instanceof Uint8Array && typeof echoed.ms === "number",
    "ModuleTable builds a bounded module set (call resolves { bytes, ms })");

  // Module loading is all or none (§3.1): a bundle whose second module is malformed
  // leaves the table as it was, without the caller doing anything.
  const atomic = new ModuleTable();
  await rejects(atomic.build([
    { name: "first", wasm: withMax },
    { name: "second", wasm: new Uint8Array() },
  ]), "a bundle with one bad module is refused whole");
  loaded.dispose();
}

console.log("\n§12.2 — fs is scoped per app label");
{
  const disk = new MemoryFs();
  const chat = scopedFs(disk, appScopeFor(sodium, "chat"));
  const notes = scopedFs(disk, appScopeFor(sodium, "notes"));
  // Every method is awaited: the seam is async so a browser backend can implement it
  // (services/fs.ts), and MemoryFs answers in a microtask like any other.
  await chat.put("secret", new Uint8Array([1, 2, 3]));
  await notes.put("secret", new Uint8Array([9]));
  ok((await chat.get("secret")).length === 3, "chat reads its own key");
  ok((await notes.get("secret")).length === 1, "notes' same-named key is a different value");
  const notesKeys = await notes.list("");
  ok(notesKeys.length === 1 && notesKeys[0] === "secret", "list() shows only this app's keys, unprefixed");
  ok(await notes.delete("secret") && (await chat.get("secret")) !== null, "notes' delete cannot reach chat's key");
  ok((await disk.list("")).length === 1, "the backend holds both under distinct physical keys");

  // Colons in an app name cannot make two scopes overlap, and cannot reach the backend.
  const amb1 = scopedFs(disk, appScopeFor(sodium, "x:y"));
  const amb2 = scopedFs(disk, appScopeFor(sodium, "x"));
  await amb1.put("z", new Uint8Array([1]));
  ok((await amb2.get("y:z")) === null, "app 'x:y' key 'z' does not collide with app 'x' key 'y:z'");
  ok(/^[A-Za-z0-9._-]+$/.test(appScopeFor(sodium, "x:y")), "the derived scope is inside the backend key charset");
  // Keys are filenames, and a case-folding filesystem would merge two labels differing
  // only in case if the label were the prefix. The hash is lowercase hex.
  const upper = appScopeFor(sodium, "Chat");
  ok(upper !== appScopeFor(sodium, "chat") && upper === upper.toLowerCase(),
    "labels differing only in case get distinct lowercase prefixes");
  // The real backends reject anything outside that charset, so an unsafe scope must fail
  // at construction, not on the first write.
  throws(() => scopedFs(disk, "aa:bb"), "an unsafe scope prefix is refused up front");

  const bounded = new MemoryFs(4, 2);
  await bounded.put("a", Uint8Array.of(1, 2, 3));
  await rejects(bounded.put("b", Uint8Array.of(4, 5)),
    "an in-memory backend refuses cumulative bytes beyond its quota");
  ok((await bounded.get("a")).join() === "1,2,3",
    "a refused put leaves existing stored state intact");
  await bounded.put("a", Uint8Array.of(9));
  await bounded.put("b", Uint8Array.of(8, 7, 6));
  await rejects(bounded.put("c", new Uint8Array()),
    "the storage owner also bounds retained entry objects");
  await bounded.delete("a");
  await bounded.put("c", Uint8Array.of(5));
  ok((await bounded.stat()).used === 4 && (await bounded.stat()).available === 0,
    "replacement and deletion transactionally release storage custody");
}

console.log("\n§12.4 — every app is a guest, modules are its library");
{
  const kp = testAuthor();
  const verify = (m) => verifyTestBundle(sodium, signTestBundle(sodium, kp, m));
  // A missing guest gets its own error instead of "malformed manifest", so the author
  // learns the rule.
  const refusal = (m) => { try { verify(m); return ""; } catch (e) { return e.message; } };
  const none = refusal({ app: "x", version: 1, modules: [] });
  ok(none.includes("every app is a guest"), `a manifest without a guest is refused by name (got: ${none})`);
  ok(verify({ app: "x", version: 1, modules: [], guest: { requires: [] } }) !== null,
    "a guest may declare no modules at all");
  ok(verify({ app: "x", version: 1, modules: [{ name: "a" }, { name: "b" }], guest: { requires: [] } }) !== null,
    "a guest may declare multiple modules within the admission cap");
  const tooMany = Array.from({ length: DEFAULT_MAX_BUNDLE_MODULES + 1 }, (_, i) => ({ name: `m${i}` }));
  ok(refusal({ app: "x", version: 1, modules: tooMany, guest: { requires: [] } }).includes("malformed manifest"),
    "the manifest module-count cap is enforced before module extraction");
  for (const version of [-1, Number.MAX_SAFE_INTEGER + 1]) {
    ok(refusal({ app: "x", version, modules: [], guest: { requires: [] } }).includes("malformed manifest"),
      `version ${version} is refused before it can poison freshness state`);
  }
}

console.log("\n§12.2 — the service gates cannot be reached by omission");
{
  const base = {
    sodium,
    backends: {
      node: { domain: new Uint8Array(1), scope: new Uint8Array(1), key: sodium.crypto_sign_keypair() },
      fs: new MemoryFs(), timer: TEST_TIMERS, link: TEST_LINK,
    },
    callLocal: TEST_CALL_LOCAL,
    modules: { names: new Set(), call: async () => ({ bytes: null, ms: 0 }) },
  };
  throws(() => createGuestSeam({ ...base }), "omitting requires throws at construction");
  ok(typeof createGuestSeam({ ...base, requires: ALL_HOST_SERVICES }) === "function",
    "an explicit full service set is accepted");

  // A guest reaches its own app's modules without declaring them: a bare name is the
  // calling bundle's own code, scoped to the app the seam was built for, so it resolves
  // with an empty requires list, like `crypto`.
  const chat = new ModuleTable();
  const chatModules = await chat.build([{ name: "codec", wasm: withMax }]);
  const otherModules = await chat.build([{ name: "evil", wasm: withMax }]);
  const scoped = createGuestSeam({
    ...base,
    requires: [],
    modules: { names: new Set(["codec"]), call: chatModules.call },
  });
  // The forwarder echoes its input, so a resolved module answers with the body.
  const budget = () => new CallBudget(Infinity, undefined, undefined);
  ok((await scoped("codec", new Uint8Array([7, 7, 7]), budget())).length === 3, "a module of this app resolves and runs");
  throws(() => scoped("evil", new Uint8Array([7, 7, 7]), budget()),
    "another app's module name reaches nothing through this seam");
  chatModules.dispose(); otherModules.dispose();
}

console.log("\n§4.3 — the guest realm has an execution budget");
{

  const enc = new TextEncoder();
  const noop = () => new Uint8Array();

  // Construction runs in a child process: without its guard the regression blocks the
  // thread forever, so the parent kills a broken child instead of hanging the suite.
  const initProbe = spawnSync(process.execPath, [join(root, "tests/fixtures/guest-init-deadline.mjs")], {
    timeout: 3000, encoding: "utf8",
  });
  ok(initProbe.status === 0 && !initProbe.error,
    `top-level guest code is interrupted during realm construction (${initProbe.error?.message ?? initProbe.stderr.trim()})`);

  // A guest that loops forever is interrupted instead of wedging the host thread.
  const spinner = await createSafeRealm({
    source: 'function handle() { for(;;){} }',
    hostCall: noop, deadlineMs: 300,
  });
  const t0 = Date.now();
  let interrupted = false;
  try { await spinner.call(new Uint8Array()); } catch { interrupted = true; }
  const spent = Date.now() - t0;
  ok(interrupted, "an infinite loop in a holder entrypoint is interrupted");
  ok(spent < 3000, `it is interrupted near its budget, not eventually (${spent}ms)`);
  spinner.dispose();

  // A host handoff spends wall time as well as guest run time. A backend that never
  // returns therefore cannot pin the caller's active-call registry indefinitely.
  const slowSeam = (name) => name === "slow"
    ? new Promise((r) => setTimeout(() => r(new Uint8Array([1])), 400))
    : new Uint8Array();
  const waiter = await createSafeRealm({
    source: 'async function handle() { await host.call("slow", new Uint8Array()); return new Uint8Array([9]); }',
    hostCall: slowSeam, deadlineMs: 200,
  });
  await rejects(waiter.call(new Uint8Array()),
    "an initiator parked past its handoff deadline is released");
  waiter.dispose();

  // Invocations are serialized per realm: a second invocation arriving while the first is
  // waiting waits for it instead of interleaving, and then runs on its own budget, not on
  // what the first left (§12.3).
  const order = [];
  const both = await createSafeRealm({
    source: 'async function handle(a) { if (a[0] === 1) { await host.call("slow", new Uint8Array()); return new Uint8Array([1]); } return new Uint8Array([2]); }',
    hostCall: slowSeam, deadlineMs: 1000,
  });
  const parked = both.call(new Uint8Array([1])).then((r) => { order.push("initiator"); return r; });
  const holder = both.call(new Uint8Array([2])).then((r) => { order.push("holder"); return r; });
  ok((await holder)[0] === 2, "a holder queued behind a parked initiator still runs");
  ok((await parked)[0] === 1, "and the initiator completes on its own budget");
  ok(order[0] === "initiator" && order[1] === "holder",
    `the queue runs them in acceptance order, never interleaved (got ${order.join(",")})`);
  both.dispose();

  // The queue does not strand callers on dispose: one still queued fails instead of
  // entering a torn-down realm, which would abort the whole wasm module.
  const closing = await createSafeRealm({
    source: 'async function handle() { await host.call("slow", new Uint8Array()); return new Uint8Array([1]); }',
    hostCall: slowSeam, deadlineMs: 5000,
  });
  const first = closing.call(new Uint8Array()).catch(() => "failed");
  const queued = closing.call(new Uint8Array()).catch(() => "failed");
  closing.dispose();
  ok(await first === "failed", "a parked call is failed by dispose rather than left pending");
  ok(await queued === "failed", "and so is one still waiting in the queue");

  // The default is a real number, so omitting the field bounds the guest instead of
  // leaving it unbounded, like the seam gates above.
  const defaulted = await createSafeRealm({ source: 'function handle() { for(;;){} }', hostCall: noop });
  let defaultInterrupted = false;
  const t1 = Date.now();
  try { await defaulted.call(new Uint8Array()); } catch { defaultInterrupted = true; }
  ok(defaultInterrupted, "with no deadlineMs configured the 5s default still interrupts");
  ok(Date.now() - t1 >= 4000, "the default budget is the documented 5s, not something tighter");
  defaulted.dispose();

  // Fire-and-forget calls retain copied payloads and promise state in the host. Once the
  // per-realm count is reached, the next call fails before its payload crosses; settling
  // the retained calls returns the allowance to the realm.
  const held = [];
  let hold = true;
  const boundedCalls = await createSafeRealm({
    source: `function handle(a) {
      if (a[0]) {
        for (let i = 0; i <= ${DEFAULT_MAX_OUTSTANDING_HOST_CALLS}; i++)
          host.call("hold", new Uint8Array([i & 255]));
        return new Uint8Array();
      }
      return host.call("hold", new Uint8Array());
    }`,
    hostCall: () => hold ? new Promise((resolve) => held.push(resolve)) : new Uint8Array([7]),
    deadlineMs: 1000,
  });
  await rejects(boundedCalls.call(new Uint8Array([1])), "a realm cannot accumulate unbounded unresolved host calls");
  ok(held.length === DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
    `the refusal happens before copy ${DEFAULT_MAX_OUTSTANDING_HOST_CALLS + 1}`);
  hold = false;
  for (const resolve of held) resolve(new Uint8Array());
  await sleep(20);
  ok((await boundedCalls.call(new Uint8Array([0])))[0] === 7,
    "settled host calls release their per-realm accounting");
  boundedCalls.dispose();

  const duplicateHeld = [];
  const duplicateIds = await createSafeRealm({
    source: `function handle(a) {
      __host_call("first", 77, new ArrayBuffer(1));
      if (a[0]) __host_call("second", 77, new ArrayBuffer(1));
      return new Uint8Array();
    }`,
    hostCall: () => new Promise((resolve) => duplicateHeld.push(resolve)),
    deadlineMs: 1000,
  });
  await rejects(duplicateIds.call(Uint8Array.of(1)), "a duplicate live host-call id is rejected");
  ok(duplicateHeld.length === 1, "duplicate-id rejection occurs before a second host copy");
  duplicateHeld.shift()(new Uint8Array());
  await sleep(20);
  const reused = duplicateIds.call(Uint8Array.of(0));
  await sleep(0);
  duplicateHeld.shift()(new Uint8Array());
  ok((await reused).length === 0, "a settled id can be admitted again");
  duplicateIds.dispose();

  // Reach the byte limit with only eight calls, then check the ninth is rejected before
  // the host seam receives another copied payload.
  const hostCallChunk = 2 * 1024 * 1024;
  const callsAtByteCap = DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES / hostCallChunk;
  const byteHeld = [];
  let holdBytes = true;
  const byteBoundedCalls = await createSafeRealm({
    source: `function handle(a) {
      if (a[0]) {
        const payload = new Uint8Array(${hostCallChunk});
        for (let i = 0; i <= ${callsAtByteCap}; i++) host.call("link/deliver", payload);
        return new Uint8Array();
      }
      return host.call("link/deliver", new Uint8Array());
    }`,
    hostCall: () => holdBytes ? new Promise((resolve) => byteHeld.push(resolve)) : new Uint8Array([8]),
    deadlineMs: 1000,
  });
  await rejects(byteBoundedCalls.call(new Uint8Array([1])),
    "a realm cannot retain unbounded copied host-call payload bytes");
  ok(byteHeld.length === callsAtByteCap,
    `the byte refusal happens before copy ${callsAtByteCap + 1}`);
  holdBytes = false;
  for (const resolve of byteHeld) resolve(new Uint8Array());
  await sleep(20);
  ok((await byteBoundedCalls.call(new Uint8Array([0])))[0] === 8,
    "settled host calls release their per-realm byte accounting");
  byteBoundedCalls.dispose();

  // Changing only the operation name does not escape the accounting.
  const ordinaryHeld = [];
  const ordinaryCalls = await createSafeRealm({
    source: `function handle() {
      const payload = new Uint8Array(${hostCallChunk});
      for (let i = 0; i < ${callsAtByteCap + 1}; i++) host.call("send", payload);
      return new Uint8Array();
    }`,
    hostCall: () => new Promise((resolve) => ordinaryHeld.push(resolve)),
    deadlineMs: 1000,
  });
  await rejects(ordinaryCalls.call(new Uint8Array()),
    "an ordinary call name is subject to the same byte cap");
  ok(ordinaryHeld.length === callsAtByteCap,
    "the owner of the resource admits, and no name relaxes what it admits");
  for (const resolve of ordinaryHeld) resolve(new Uint8Array());
  ordinaryCalls.dispose();
}

console.log("\n§12.3 — a bounded realm count is what makes the node total a ceiling");
{
  // Every allowance is per realm and none is shared between realms: a shared one would let
  // a busy app starve a quiet one, and one realm's ceiling times the realm cap gives the
  // same total without that. So the multiplication must appear in the sum, or the total
  // would grow with every install. This sum is the node total: a new node-wide owner of
  // host memory must add its term here, not just declare its own constant.
  const perRealm = DEFAULT_REALM_MEMORY_BYTES  // §12.3: one confined guest heap
    + DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES  // copied host-call inputs and their answers
    + 2 * (HOST_CALLER_ID.length + 4)           // one armed and one in-flight wake
    + DEFAULT_MAX_MODULE_MEMORY_BYTES;         // §4.3: one bundle's total module memory
  const nodeMemoryCeiling = DEFAULT_MAX_APP_SLOTS * perRealm
    + MAX_NODE_OUTBOUND_QUEUE_BYTES // §12.6: outbound socket queues, over every link
    + 2 * MAX_INBOUND_HOLD_BYTES    // §12.6: native staging and the driver window can hold
  // the same read at once (native/sock.go). WebRTC negotiation uses the same link windows
  // (§12.7), so it adds nothing of its own.
    + DEFAULT_MEMORY_FS_MAX_BYTES;  // the in-memory fs backend's whole quota
  // Measured against a real machine's memory, so growing any term has to be a deliberate
  // choice.
  ok(nodeMemoryCeiling <= 2 * 1024 * 1024 * 1024,
    "the summed worst case of every node-scoped owner still fits a modest machine");
}

console.log("\n§12.3 — guest-created invocation roots have a bounded clock share");
{
  // The memory total above is a real total. Time is not: a peer or the host can replace
  // settled work immediately. A wake is different because it is the only new invocation a
  // guest creates itself; calls descended from an existing invocation inherit its
  // deadline. Any second way for a guest to create invocations belongs in this sum.
  ok(DEFAULT_MAX_APP_SLOTS * DEFAULT_GUEST_DEADLINE_MS <= 60_000,
    "every slot spending its banked invocation at once is a stall someone added up");
  ok(DEFAULT_MAX_APP_SLOTS / SELF_INITIATED_CLOCK_DIVISOR <= 1 / 2,
    "a full node's summed self-initiated share is at most half the clock, so it cannot be the majority");
}

console.log("\n§12.3 — active-call and realm-entry owners have complete lifecycle rules");
{
  const active = createActiveHostCallRegistry(2, 8);
  active.admit(1, 5);
  throws(() => active.admit(1, 0), "a registry refuses a duplicate live id");
  active.reserve(1, 3);
  throws(() => active.admit(2, 1), "responses awaiting delivery remain charged");
  active.release(1);
  throws(() => active.reserve(1, 1), "a settled call cannot reserve more against its realm");
  active.admit(2, 8);
  active.release(2);
  ok(true, "terminal settlement releases request, response, id, and count together");

  // A realm that dies with calls still pending releases them: nothing is left to consume
  // those answers or release them later, so keeping the charge would pin the allowance on
  // a backend that never answers. Both ways a realm can die (construction failure,
  // dispose) are checked, and a backend that settles afterwards must be a no-op, never a
  // second release.
  const liveTimers = () => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
  const timersBeforeFailedConstruction = liveTimers();
  let settleOrphan;
  await rejects(createSafeRealm({
    source: 'host.call("hold", Uint8Array.of(1)); throw new Error("init failed");',
    hostCall: () => new Promise((resolve) => { settleOrphan = resolve; }),
  }), "failed realm construction reports its source error");
  ok(liveTimers() === timersBeforeFailedConstruction,
    "failed realm construction disarms host-call deadlines it can no longer own");
  const afterFailure = await createSafeRealm({
    source: 'async function handle() { await host.call("ok", Uint8Array.of(1)); return Uint8Array.of(7); }',
    hostCall: () => new Uint8Array(),
  });
  ok((await afterFailure.call(new Uint8Array()))[0] === 7,
    "a realm that failed to construct released what its parked call held");
  settleOrphan(new Uint8Array());
  await sleep(20);
  ok((await afterFailure.call(new Uint8Array()))[0] === 7,
    "an orphaned backend settling later is a no-op, not a second release");

  let settleAtDispose;
  const disposedWithParked = await createSafeRealm({
    source: 'async function handle() { await host.call("park", Uint8Array.of(1)); return Uint8Array.of(1); }',
    hostCall: () => new Promise((resolve) => { settleAtDispose = resolve; }),
  });
  // dispose() rejects this invocation; the caller holds the error, so consume it here.
  disposedWithParked.call(new Uint8Array()).catch(() => {});
  await sleep(20);
  // The pending call's handoff deadline is host-side state like its byte charge, and
  // dispose() must end both (§12.3), so the timer count is read before and after dispose.
  const armedAtDispose = liveTimers();
  disposedWithParked.dispose();
  ok(armedAtDispose > 0 && liveTimers() < armedAtDispose,
    "disposing a realm disarms the handoff deadline of the call it abandoned");
  ok((await afterFailure.call(new Uint8Array()))[0] === 7,
    "disposing a realm with a call still parked releases its charge too");
  settleAtDispose(new Uint8Array());
  afterFailure.dispose();

  // Fast serialized calls share one retained timer instead of crossing the host timer
  // seam per invocation, and disposal still clears it at once (realm-queue.ts).
  const nativeSetTimeout = globalThis.setTimeout;
  const nativeClearTimeout = globalThis.clearTimeout;
  let deadlineArms = 0, deadlineClears = 0;
  try {
    globalThis.setTimeout = (fn, ms, ...args) => {
      deadlineArms++;
      return nativeSetTimeout(fn, ms, ...args);
    };
    globalThis.clearTimeout = (timer) => {
      deadlineClears++;
      return nativeClearTimeout(timer);
    };
    const shared = createDeadlineQueue();
    const batched = serializeCalls(shared,
      (payload) => ({ result: Promise.resolve(payload), cancel: () => {} }), () => null, 5000);
    await Promise.all([batched(Uint8Array.of(1)), batched(Uint8Array.of(2)), batched(Uint8Array.of(3))]);
    ok(deadlineArms === 1 && deadlineClears === 0,
      "fast serialized calls share one armed deadline instead of cycling timers");
    shared.disarmAll();
    ok(deadlineClears === 1, "disposing the realm's deadline queue clears its shared wakeup");
  } finally {
    globalThis.setTimeout = nativeSetTimeout;
    globalThis.clearTimeout = nativeClearTimeout;
  }

  let closed = false;
  const gates = [];
  const seen = [];
  const queuedDeadlines = createDeadlineQueue();
  const queued = serializeCalls(queuedDeadlines, (payload) => {
    seen.push(payload);
    let release, fail;
    const gate = new Promise((resolve, reject) => { release = resolve; fail = reject; });
    gates.push(release);
    return { result: gate.then(() => payload), cancel: (reason) => fail(reason) };
  }, () => closed ? new Error("closed") : null, 500);
  const one = Uint8Array.of(1);
  const firstInvocation = queued(one);
  await sleep(0);
  const two = Uint8Array.of(2, 3, 4, 5);
  const secondInvocation = queued(two, 25);
  const three = Uint8Array.of(6);
  const thirdInvocation = queued(three, 500);
  await rejects(secondInvocation, "a queued invocation spends the deadline admitted with it");
  gates.shift()();
  await firstInvocation;
  await sleep(0);
  ok(seen[0] === one && seen[1] === three && !seen.includes(two),
    "an expired queue entry never draws a fresh realm segment");
  gates.shift()();
  await thirdInvocation;
  // Queue depth is bounded by the upstream owners, and payload bytes stay charged to
  // those owners instead of being counted or copied again here.
  const large = queued(new Uint8Array(32 * 1024 * 1024));
  await sleep(0);
  gates.shift()();
  ok((await large).length === 32 * 1024 * 1024,
    "the entry queue borrows bytes already charged to the initiating owner");
  // The running entry's deadline frees the realm, not just its caller: `cancel` rejects
  // the invocation the queue waits on, so a wedged answer cannot hold the realm past its
  // budget, and the entry behind it still runs.
  const wedged = queued(Uint8Array.of(9), 25);
  await sleep(0);
  const behind = queued(Uint8Array.of(10), 500);
  await rejects(wedged, "a wedged invocation is failed by the deadline it was admitted under");
  await sleep(0);
  ok(gates.length === 2, "…and the realm went to the entry behind it rather than staying held");
  gates.pop()();
  await behind;
  closed = true;
  await rejects(queued(new Uint8Array()), "a closed realm stops admitting immediately");
  queuedDeadlines.disarmAll();

  // A deferred result keeps no fresh clock of its own: it retains the handoff deadline
  // admitted with the call, including across another realm's host.call.
  const deferring = await createSafeRealm({
    source: 'function handle() { globalThis.__deferred = true; return new Promise(() => {}); }',
    hostCall: () => new Uint8Array(),
  });
  const waiting = await createSafeRealm({
    source: 'function handle() { return host.call("ask", new Uint8Array()); }',
    hostCall: () => deferring.call(new Uint8Array(1), 75),
    deadlineMs: 500,
  });
  const deferredAt = Date.now();
  const hung = waiting.call(new Uint8Array()).catch(() => "failed");
  ok(await hung === "failed",
    "a deferred realm call settles on the initiating owner's deadline without disposal");
  ok(Date.now() - deferredAt < 1000, "the deferred deadline fires on its own schedule");
  deferring.dispose();
  waiting.dispose();

}

console.log("\nOne replaceable wake and one in-flight notification per realm");
{
  const fired = [];
  const wake = createRealmTimers((body) => { fired.push(body); });
  wake.arm(1);
  await sleep(20);
  ok(fired.length === 1 && isWake(fired[0]), "a wake arrives as the host's `wake` event");
  for (let i = 0; i < 2000; i++) wake.arm(10);
  throws(() => wake.arm(1.5), "a fractional delay is refused without replacing the wake");
  throws(() => wake.arm(0x80000000), "delay overflow is refused rather than firing immediately");
  await sleep(30);
  ok(fired.length === 2, "replacement retains only the latest wake, with no timer-count cap");
  wake.arm(1); wake.clear();
  await sleep(20);
  ok(fired.length === 2, "clear cancels the armed wake");
  wake.clearAll();
  throws(() => wake.arm(0), "disposal permanently closes the wake");

  let releaseFired, calls = 0;
  const inFlight = createRealmTimers(() => {
    calls++;
    if (calls === 1) return new Promise((resolve) => { releaseFired = resolve; });
  });
  inFlight.arm(0);
  await sleep(20);
  for (let i = 0; i < 2000; i++) inFlight.arm(0);
  await sleep(20);
  ok(calls === 1, "a deferred wake cannot accumulate in-flight notifications");
  releaseFired();
  await sleep(20);
  ok(calls === 2, "only the latest due successor enters after settlement");
  inFlight.clearAll();
}

console.log("\n§12.3 — a realm's self-initiated work is paced by its share of the node's clock");
{
  // Re-arming at ms=0 from inside the wake: the only new invocation a guest creates itself,
  // each with a full budget (§12.3). Scaled down so the ratio is what is tested, with a
  // divisor of 1 as the control, where a busy realm earns back exactly what it spends
  // (unpaced).
  const budgetMs = 40, occupyMs = 20, spinForMs = 400;
  const spin = async (clockDivisor) => {
    let fires = 0;
    let table;
    table = createRealmTimers((_body, causalClock) => {
      fires += 1;
      table.arm(0);
      // Stand in for the realm's execution report. Burn real time too, so at divisor 1
      // execution spend and concurrent credit cancel exactly.
      const started = performance.now();
      while (performance.now() - started < occupyMs) { /* guest is computing */ }
      causalClock.charge(performance.now() - started);
    }, budgetMs, clockDivisor);
    table.arm(0);
    await sleep(spinForMs);
    table.clearAll();
    return fires;
  };
  const unpaced = await spin(1);
  const paced = await spin(4);
  ok(unpaced > 2 * paced,
    `an unpaced table holds the clock the whole window (${unpaced} fires vs ${paced} paced)`);
  // The bank is one whole invocation, so the first fires come free and the share paces the rest.
  ok(paced * occupyMs <= spinForMs / 4 + 2 * budgetMs,
    `a spinning guest stays inside its share of the clock (${paced} × ${occupyMs}ms in ${spinForMs}ms)`);

  // Replacement is cheap and leaves just one pending host wake.
  let cheap = 0;
  const honest = createRealmTimers(() => { cheap += 1; });
  for (let id = 0; id < 64; id++) honest.arm(0);
  await sleep(60);
  ok(cheap === 1, `64 replacements produce one cheap wake (${cheap})`);
  honest.clearAll();

  // A successor waits for settlement, but I/O wait still earns execution credit.
  let waitingFires = 0;
  let releaseWait;
  const waiting = createRealmTimers((_body, causalClock) => {
    waitingFires += 1;
    if (waitingFires !== 1) return;
    causalClock.charge(2 * budgetMs); // clamps the bank to -budgetMs
    return new Promise((resolve) => { releaseWait = resolve; });
  }, budgetMs, 4);
  waiting.arm(0);
  await sleep(20);
  waiting.arm(0);
  await sleep(220); // -40 -> +1 earns in 164 ms at a divisor of 4
  ok(waitingFires === 1, "a due successor waits for the in-flight wake to settle");
  releaseWait();
  await sleep(20);
  ok(waitingFires === 2, "clock credit earned during I/O admits the successor promptly after settlement");
  waiting.clearAll();

  // Host compute counts as execution too, and no guest segment sees it: a body that only
  // calls host services waits between each call. The seam times the synchronous part of
  // each handler, so libsodium's work is billed while an I/O name (whose promise returns at
  // once) bills nothing, with no list of which names are which. A failed verify still did
  // the work, so the measurement is in `finally`; otherwise a re-arm loop of bad
  // signatures would be free.
  {
    const burnMs = 15;
    const burningSodium = Object.create(sodium);
    burningSodium.crypto_sign_verify_detached = (...args) => {
      const started = performance.now();
      while (performance.now() - started < burnMs) { /* libsodium is working */ }
      return sodium.crypto_sign_verify_detached(...args);
    };
    const identity = sodium.crypto_sign_keypair();
    const seam = createGuestSeam({
      sodium: burningSodium,
      requires: ALL_HOST_SERVICES,
      backends: {
        node: { domain: new Uint8Array(1), scope: new Uint8Array(1), key: identity },
        fs: new MemoryFs(), timer: TEST_TIMERS, link: TEST_LINK,
      },
      callLocal: TEST_CALL_LOCAL,
      modules: { names: new Set(), call: async () => ({ bytes: null, ms: 0 }) },
    });
    const meter = () => {
      let charged = 0;
      return { budget: { remainingMs: 5_000, charge() {}, causalClock: { charge(ms) { charged += ms; } } },
        spent: () => charged };
    };
    // 96 bytes is the fixed prefix: a garbage pk and sig over an empty message, which the
    // handler runs to completion before answering [0].
    const cpu = meter();
    ok((await seam("node/verify", new Uint8Array(96), cpu.budget))[0] === 0,
      "a bad signature answers [0] rather than throwing");
    ok(cpu.spent() >= burnMs,
      `a host-service call bills its compute to the causal root (${cpu.spent().toFixed(1)}ms >= ${burnMs}ms)`);
    const io = meter();
    await seam("fs/get", new TextEncoder().encode("absent"), io.budget);
    ok(io.spent() < burnMs / 2,
      `a host name that round-trips bills only its dispatch (${io.spent().toFixed(1)}ms)`);
  }

  // The opposite escape is returning before descendant work finishes: await once (so the
  // clock must survive settlement), call a second realm without awaiting it, and let that
  // callee start module-like work without awaiting that either. The late charge must still
  // reach the wake's clock after both entrypoints have answered.
  let moduleCharged;
  const callee = await createSafeRealm({
    source: 'function handle() { void host.call("work", new Uint8Array()); return new Uint8Array(); }',
    hostCall: (_name, _payload, budget) => new Promise((resolve) => {
      setTimeout(() => {
        budget.charge(2 * budgetMs);
        moduleCharged?.();
        resolve(new Uint8Array());
      }, 10);
    }),
  });
  const caller = await createSafeRealm({
    source: `async function handle() {
      await host.call("pause", new Uint8Array());
      void host.call("callee", new Uint8Array());
      return new Uint8Array();
    }`,
    hostCall: (name, payload, budget) => name === "pause"
      ? sleep(10).then(() => new Uint8Array())
      : callee.call(payload, budget.remainingMs, budget.causalClock),
  });
  let rootedFires = 0;
  const rooted = createRealmTimers((body, causalClock) => {
    rootedFires += 1;
    return caller.call(body, undefined, causalClock);
  }, budgetMs, 4);
  const charged = new Promise((resolve) => { moduleCharged = resolve; });
  rooted.arm(0);
  await charged;
  rooted.arm(0);
  await sleep(30);
  ok(rootedFires === 1,
    "fire-and-forget work remains charged through an await and a cross-realm call");
  await sleep(210);
  ok(rootedFires === 2, "the descendant charge slips only the root's next fire, then recovers");
  rooted.clearAll();
  caller.dispose();
  callee.dispose();
}

console.log("\n§12.3 — the bounds a target sets actually reach the realm");
{
  // A bound can be declared on every interface between the operator and the realm and
  // still not be passed through, so this boots a node on a stub realm factory and checks
  // the numbers arrive. No transport, so nothing here may require `link`.
  const kp = testAuthor();
  const guestSrc = 'function handle() { return new Uint8Array([1]); }';
  const guestBytes = new TextEncoder().encode(guestSrc);
  const signedConfig = JSON.parse('{"mode":"signed","nested":[true,null,{"n":3}],"__proto__":{"kept":"data"}}');
  const manifest = {
    app: "probe", version: 1, modules: [],
    guest: {
      requires: [],
      config: signedConfig,
    },
  };
  const blob = signTestBundle(sodium, kp, manifest, guestBytes);

  const seen = [];
  const { shell } = await bootShell({
    sodium, identity: kp.ed, modules: new ModuleTable(), fs: new MemoryFs(),
    freshnessStore: new FreshnessMarks(),
    createRealm: async (o) => {
      seen.push(o);
      return { call: async () => new Uint8Array(), dispose() {} };
    },
    admit: admitAll,
    guestDeadlineMs: 1234,
    realmMemoryBytes: 7 * 1024 * 1024,
  });
  const probe = await shell.install(blob, {
    localConfig: { mode: "local", localOnly: { quota: 7 }, flags: [false, true] },
  });
  // Every install after this one replaces this same slot (an install without `replaces`
  // only takes a free label), and a replacement takes per-install config and bounds just
  // like a first install, which is what is tested below.
  const reload = (loadOpts) => shell.install(blob, { ...loadOpts, replaces: probe.manifest.app });
  await probe.invoke(new Uint8Array());
  ok(seen.length === 1, "the shell created a realm for the loaded guest");
  ok(seen[0]?.deadlineMs === 1234, `guestDeadlineMs reaches the realm factory (got ${seen[0]?.deadlineMs})`);
  ok(seen[0]?.memoryLimitBytes === 7 * 1024 * 1024, "realmMemoryBytes reaches the realm factory");
  ok(!seen[0]?.ownTurns, "an app's turns stay on its callers' clocks; only the link occupant's are its own");

  // HOST, APP and LOCAL are three separate values, not one merge: what the runtime
  // provides, what the author signed, and what the operator set for this install.
  // Evaluate only the three generated preamble lines (the guest body is self-contained).
  const valuesFrom = (source) => Function(
    source.split("\n").slice(0, 3).join("\n") + "\nreturn [APP, LOCAL, HOST];",
  )();
  const [app, local] = valuesFrom(seen[0].source);
  ok(app.mode === "signed" && !("localOnly" in app), "LOCAL never overwrites or extends signed APP");
  ok(local.mode === "local" && local.localOnly.quota === 7, "the load's local JSON arrives separately as LOCAL");
  ok(app.nested[1] === null && app.nested[2].n === 3, "signed config accepts general nested JSON");
  ok(Object.hasOwn(app, "__proto__") && app.__proto__.kept === "data" && Object.getPrototypeOf(app) === Object.prototype,
    "JSON config preserves an own __proto__ key as data");

  // A second install gets nothing from the first install's LOCAL value.
  await reload();
  const [appAgain, localAgain] = valuesFrom(seen[1].source);
  ok(appAgain.mode === "signed" && Object.keys(localAgain).length === 0,
    "local config is scoped to one load, not retained by the shell for another app or reload");
  ok(seen[1]?.memoryLimitBytes === 7 * 1024 * 1024 && seen[1]?.deadlineMs === 1234,
    "a load naming no bounds of its own falls back to the shell's");

  // An install that sets them overrides the shell's, which is why they are per install:
  // one shell hosts unrelated apps, and a storage guest needs a different heap from the
  // transport bundle beside it.
  await reload({ realmMemoryBytes: 9 * 1024 * 1024, guestDeadlineMs: 77 });
  ok(seen.at(-1)?.memoryLimitBytes === 9 * 1024 * 1024, "a load's own realmMemoryBytes overrides the shell's");
  ok(seen.at(-1)?.deadlineMs === 77, "a load's own guestDeadlineMs overrides the shell's");
  // A bound the two engines would read differently is refused where it is resolved, for
  // one install and the node's defaults alike: a heap limit that truncates to 0 (or is NaN)
  // is no limit on JS and a refused realm on native, 2^32 and up wraps on JS, and a budget
  // under 1 ms is no budget on native and a refused realm on JS.
  const realmsBefore = seen.length;
  for (const bad of [0, 0.5, NaN, -1, 2 ** 32]) {
    await rejects(reload({ realmMemoryBytes: bad }), `a load's realmMemoryBytes of ${bad} is refused`);
  }
  for (const bad of [0, 0.5, NaN, -5]) {
    await rejects(reload({ guestDeadlineMs: bad }), `a load's guestDeadlineMs of ${bad} is refused`);
  }
  ok(seen.length === realmsBefore, "…before a realm is stood for it");
  await reload({ guestDeadlineMs: Infinity });
  ok(seen.at(-1)?.deadlineMs === Infinity, "Infinity is still the one way to say no budget");
  for (const bad of [{ realmMemoryBytes: 0 }, { guestDeadlineMs: -5 }]) {
    await rejects(bootShell({ sodium, identity: kp.ed, transport: false, ...bad }),
      `a node default of ${JSON.stringify(bad)} fails the boot`);
  }
  const cyclic = {}; cyclic.self = cyclic;
  await rejects(reload({ localConfig: cyclic }),
    "a non-JSON local value is refused instead of being silently changed during injection");
  // Both config values are objects. A guest reads config by name, so a scalar or array
  // would make every `LOCAL.x` read `undefined` at run time instead of failing the install.
  await rejects(reload({ localConfig: [1, 2] }),
    "a JSON array is refused as local config — a guest reads config by name");
  await rejects(reload({ localConfig: 7 }),
    "a JSON scalar is refused as local config");
  // The same rule on the signed side, enforced by the manifest's structural check: an
  // author who signs a scalar `config` gets a refused bundle, not a guest reading undefined.
  {
    const scalarManifest = {
      ...manifest,
      guest: { ...manifest.guest, config: "not-an-object" },
    };
    const scalarBlob = signTestBundle(sodium, kp, scalarManifest, guestBytes);
    await rejects(shell.install(scalarBlob),
      "a signed guest.config that is not a JSON object is a refused manifest");
  }

  // §12.5: uninstalling a guest-only app reports success. An app is its modules and its
  // realm, and this bundle declares no modules at all, so a count of dropped modules would
  // wrongly say nothing was there.
  ok(shell.uninstall("probe") === true,
    "uninstalling a guest-only app reports success, not 'nothing there'");
  ok(shell.uninstall("probe") === false,
    "uninstalling it twice reports nothing the second time");
  shell.close();

  // When omitted, the shared defaults arrive at the seam (host/wasm-limits.ts), not
  // undefined and not unbounded. The shell resolves them so no factory owns the numbers.
  let seen2 = null;
  const { shell: bare } = await bootShell({
    sodium, identity: kp.ed, modules: new ModuleTable(), fs: new MemoryFs(),
    freshnessStore: new FreshnessMarks(),
    createRealm: async (o) => {
      seen2 = o;
      return { call: async () => new Uint8Array(), dispose() {} };
    },
    admit: admitAll,
  });
  const bareProbe = await bare.install(blob);
  await bareProbe.invoke(new Uint8Array());
  ok(seen2 && seen2.deadlineMs === 5000, "an unset budget arrives as the shared default (5000 ms)");
  ok(seen2 && seen2.memoryLimitBytes === 64 * 1024 * 1024, "an unset heap cap arrives as the shared default (64 MiB)");
  // The budgets a guest is measured against are passed to it (the `HOST` preamble), so an
  // app can pace its own fan-out instead of discovering them by being refused.
  const advertised = Function(
    seen2.source.split("\n").slice(0, 3).join("\n") + "\nreturn HOST;",
  )();
  ok(advertised.maxOutstandingHostCallBytes === DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES
    && advertised.maxOutstandingHostCalls === DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  "the realm's host-call budget is advertised to the guest, not only enforced against it");
  // So is the node's public key, as hex: the key `node/sign` signs with, so what a guest
  // publishes as its node and what its signatures verify under cannot disagree.
  ok(advertised.identity === toHex(kp.ed.publicKey),
    "HOST.identity is the node's public key, the one node/sign signs with");
  bare.close();
}

console.log("\n§12.6 — host socket send queues are bounded");
{
  const { MessageChannel } = await imp("build/services/net-channel.js");
  const { NodeChannelFactory } = await imp("build/services/net-node.js");
  const { TransportHost } = await imp("build/host/transport-host.js");
  const ownedChannel = (channel, limits = {}) => {
    let ownerClosed = false;
    const closeChannel = channel.close.bind(channel);
    channel.close = (graceful) => { ownerClosed = true; closeChannel(graceful); };
    const channels = {
      connect: () => channel,
      listen: async (addrs) => addrs.map(() => 0),
      close() {},
    };
    const driver = new TransportHost({ channels, ...limits });
    driver.activate(() => Promise.resolve(new Uint8Array()));
    const raw = driver.rawNet();
    const { linkId } = raw.open("test");
    return {
      send: (bytes) => raw.send(linkId, bytes),
      // Observe the adapter directly. Its backlog is not visible to the guest; only the
      // host uses it for outbound accounting.
      buffered: () => {
        try { return channel.buffered?.() ?? 0; } catch { return 0; }
      },
      closed: () => ownerClosed,
      close: () => driver.close(),
    };
  };
  // A transport that never becomes writable, as with an unfinished connect. Until `open`
  // fires, everything written is host memory spent on a peer that has proved nothing, so
  // the queue a handshake frame or two needs must not hold a megabyte per stalled socket.
  const sent = [];
  let closed = false;
  const stuck = {
    binaryType: "", bufferedAmount: 0,
    send: (b) => sent.push(b),
    close: () => { closed = true; },
    addEventListener: () => { },
  };
  const ch = new MessageChannel(stuck);
  const owned = ownedChannel(ch);
  let died = false;
  ch.onClose(() => { died = true; });
  const frame = new Uint8Array(64 * 1024);
  for (let i = 0; i < 256; i++) owned.send(frame);
  ok(!died && sent.length === 0, "a channel that has not opened buffers rather than writes");
  ok(owned.buffered() === MAX_OUTBOUND_QUEUE_BYTES,
    `the link owner reports pre-open bytes (got ${owned.buffered()})`);
  owned.send(frame);
  // Failed, not silently trimmed: dropping a frame from an ordered stream leaves the far
  // end waiting on a gap forever, while a dead channel is reported to the occupant.
  ok(!died && closed, "crossing the ceiling closes the adapter instead of growing the queue");
  ok(owned.buffered() === 0, "a failed link releases its queue rather than holding it to be collected");

  const openedChannel = () => {
    const listeners = new Map();
    const transport = {
      binaryType: "", bufferedAmount: 0, closed: false,
      send(bytes) { this.bufferedAmount += bytes.length; },
      close() { this.closed = true; },
      addEventListener(type, cb) { listeners.set(type, cb); },
    };
    const channel = new MessageChannel(transport);
    let failed = false;
    channel.onClose(() => { failed = true; });
    listeners.get("open")();
    return { channel: ownedChannel(channel), transport, failed: () => failed };
  };

  // Once open, the platform's own queue is host memory too. Exactly the byte window is
  // accepted; the next message fails the link instead of being dropped.
  const byBytes = openedChannel();
  const block = new Uint8Array(1 << 20);
  for (let n = block.length; n <= MAX_OUTBOUND_QUEUE_BYTES; n += block.length) {
    byBytes.channel.send(block);
  }
  ok(!byBytes.failed() && byBytes.channel.buffered() === MAX_OUTBOUND_QUEUE_BYTES,
    "the exact outbound byte ceiling remains writable");
  byBytes.channel.send(Uint8Array.of(1));
  ok(byBytes.channel.closed() && byBytes.transport.closed,
    "crossing the outbound byte ceiling closes and releases the link");

  // A byte cap alone allows millions of one-byte message objects. The separate count
  // ceiling applies while the byte total is still tiny.
  const byCount = openedChannel();
  for (let i = 0; i < MAX_OUTBOUND_QUEUE_SLICES; i++) byCount.channel.send(Uint8Array.of(i));
  ok(!byCount.failed() && byCount.channel.buffered() < MAX_OUTBOUND_QUEUE_BYTES,
    "tiny writes reach the exact outbound slice ceiling below the byte ceiling");
  byCount.channel.send(Uint8Array.of(1));
  ok(byCount.channel.closed() && byCount.transport.closed,
    "crossing the outbound slice ceiling closes and releases the link");

  // Writes are released as a drained prefix, not all at once when the queue empties. The
  // count is shared node-wide, so a busy link that never goes idle would otherwise hold it
  // at its high-water mark until the socket closed.
  const half = MAX_OUTBOUND_QUEUE_SLICES / 2;
  const drain = openedChannel();
  for (let i = 0; i < MAX_OUTBOUND_QUEUE_SLICES; i++) drain.channel.send(Uint8Array.of(1));
  drain.transport.bufferedAmount -= half; // the platform put half of them on the wire
  for (let i = 0; i < half; i++) drain.channel.send(Uint8Array.of(1));
  ok(!drain.failed() && drain.channel.buffered() === MAX_OUTBOUND_QUEUE_SLICES,
    "exactly the slices the platform wrote are freed for reuse");
  drain.channel.send(Uint8Array.of(1));
  ok(drain.transport.closed,
    "and no more: the ceiling still bites on the undrained remainder");

  const parentLinks = [0, 1].map(() => {
    const listeners = new Map();
    return {
      held: 0, closed: false,
      send(bytes) { this.held += bytes.length; },
      buffered() { return this.held; },
      close() { this.closed = true; },
      onData(cb) { listeners.set("data", cb); },
      onClose(cb) { listeners.set("close", cb); },
    };
  });
  let parentNext = 0;
  const parentDriver = new TransportHost({
    channels: {
      connect: () => parentLinks[parentNext++],
      listen: async (addrs) => addrs.map(() => 0),
      close() {},
    },
    maxOutboundBytes: 6,
  });
  parentDriver.activate(() => Promise.resolve(new Uint8Array()));
  const parentRaw = parentDriver.rawNet();
  const firstLink = parentRaw.open("a").linkId;
  const secondLink = parentRaw.open("b").linkId;
  parentRaw.send(firstLink, new Uint8Array(4));
  parentRaw.send(secondLink, new Uint8Array(3));
  ok(!parentLinks[0].closed && parentLinks[1].closed,
    "the node allowance prevents individually legal links multiplying retained bytes");
  parentDriver.close();

  // Node reports its platform backlog to the same link owner. A connect cannot progress
  // while this synchronous loop runs, so both exact boundaries are deterministic without
  // depending on a peer or on kernel socket-buffer sizes.
  const nodeLink = () => {
    const link = new NodeChannelFactory().connect("tcp://127.0.0.1:1");
    if (!link) throw new Error("node test link was not created");
    link.onClose(() => {}); // consume the expected destroy/connect-error events
    return ownedChannel(link);
  };
  const nodeBytes = nodeLink();
  for (let n = block.length; n <= MAX_OUTBOUND_QUEUE_BYTES; n += block.length) {
    nodeBytes.send(block);
  }
  ok(nodeBytes.buffered() === MAX_OUTBOUND_QUEUE_BYTES,
    "Node accepts exactly the outbound byte ceiling before connect");
  nodeBytes.send(Uint8Array.of(1));
  ok(nodeBytes.closed(),
    "the link owner destroys Node's socket before accepting bytes past the ceiling");

  const nodeCount = nodeLink();
  const one = Uint8Array.of(1);
  for (let i = 0; i < MAX_OUTBOUND_QUEUE_SLICES; i++) nodeCount.send(one);
  nodeCount.send(one);
  ok(nodeCount.closed(),
    "the link owner destroys Node's socket before accepting a write past the count ceiling");

  // An adapter whose `RawLink.buffered` returns 0, or that has none (socket-seam.ts),
  // states it retains nothing; one whose call throws says nothing at all, and the two must
  // not be treated alike. Reading "cannot say" as 0 would release this link's charge and
  // the node's while the platform still holds the bytes; freezing the accounting instead
  // would choke a healthy link at its cumulative ceiling. The link fails on the write, and
  // only that teardown releases, since a destroyed socket has dropped what it held.
  let silentClosed = false, silentWrote = 0;
  const silent = ownedChannel({
    stream: true, send: () => { silentWrote++; }, onData: () => {}, onClose: () => {},
    close: () => { silentClosed = true; },
    // No `buffered` at all: an adapter declaring it retains nothing past send.
  });
  for (let i = 0; i < 4 * MAX_OUTBOUND_QUEUE_SLICES; i++) silent.send(Uint8Array.of(1));
  ok(!silentClosed && silentWrote === 4 * MAX_OUTBOUND_QUEUE_SLICES && silent.buffered() === 0,
    "an adapter that declares no backlog keeps writing, its custody released at each send");

  let brokenClosed = false, brokenWrote = 0;
  const broken = ownedChannel({
    stream: true, send: () => { brokenWrote++; }, onData: () => {}, onClose: () => {},
    close: () => { brokenClosed = true; },
    buffered: () => { throw new Error("cannot say"); },
  });
  for (let i = 0; i < 4 * MAX_OUTBOUND_QUEUE_SLICES; i++) broken.send(Uint8Array.of(1));
  ok(brokenClosed && brokenWrote === 0,
    "a buffered() that cannot answer fails the link on its first write rather than writing uncharged");
  ok(broken.buffered() === 0, "and leaves nothing charged to the link its teardown released");
}

console.log("\n§12.2 — timers are an ordinary authority, wired per realm");
{
  // `timer` is an ordinary host service (services/domains.ts), so this tests that an
  // ordinary app gets it: no transport bundle is installed below. If it were wired off the
  // transport driver, such an app would install and then fail at its first `host.call`.
  // Which deadline is due is the guest's own state, never a host-side id.
  const kp = testAuthor();
  const guestSrc = `
    let fired = [], armedId = null;
${guestOpFraming()}
    function handle(arg) {
      const { fromHost, body } = callerOf(arg);
      const { op, args: p } = readOp(body);
      if (fromHost && op === "wake") {
        if (armedId !== null) fired.push(armedId);
        armedId = null;
        return new Uint8Array(0);
      }
      if (op === "arm") {
        armedId = p[0];
        return host.call("timer/arm", new Uint8Array([0, 0, 0, p[1]])).then(() => new Uint8Array(0));
      }
      if (op === "clear") {
        armedId = null;
        return host.call("timer/clear", new Uint8Array(0)).then(() => new Uint8Array(0));
      }
      if (op === "fired") return new Uint8Array(fired);
      return new Uint8Array(0);
    }
  `;
  const guestBytes = new TextEncoder().encode(guestSrc);
  const mkBlob = (requires) => {
    const manifest = {
      app: "ticker", version: 1, modules: [],
      guest: { requires },
    };
    return signTestBundle(sodium, kp, manifest, guestBytes);
  };
  // `fs: false` explicitly: these bundles do not require `fs`, and the in-memory default
  // would give this node a backend it does not need.
  const newShell = async () => (await bootShell({
    sodium, identity: kp.ed, modules: new ModuleTable(),
    freshnessStore: new FreshnessMarks(), createRealm: createSafeRealm,
    fs: false,
    admit: admitAll,
  })).shell;

  const shell = await newShell();
  const ticker = await shell.install(mkBlob(["timer"]));
  // The op frame is this app's own format (its `handle` reads it); the shell never
  // interprets the bytes. The same `writeOp` whose reader the guest inlines.
  const opInput = (op, p = new Uint8Array(0)) => writeOp(op, p);
  await ticker.invoke(opInput("arm", new Uint8Array([7, 5])));    // arm: id 7, in 5ms
  await sleep(80);
  const fired = await ticker.invoke(opInput("fired"));
  ok(fired.length === 1 && fired[0] === 7,
    `an app with no transport arms a deadline and its timer entrypoint fires (got [${[...fired]}])`);

  // Re-arming replaces the deadline instead of adding one, and `clear` cancels it.
  await ticker.invoke(opInput("arm", new Uint8Array([9, 5])));
  await ticker.invoke(opInput("arm", new Uint8Array([9, 5])));
  await ticker.invoke(opInput("clear", new Uint8Array([9])));
  await sleep(80);
  const after = await ticker.invoke(opInput("fired"));
  ok(after.length === 1, `a cleared wake does not fire, and repeated arms replace it (got [${[...after]}])`);
  shell.close();

  // The manifest still decides: a bundle that did not declare `timer` is refused by name
  // at the seam, even though the shell has timers.
  const ungated = await newShell();
  const ungatedApp = await ungated.install(mkBlob([]));
  let refused = false;
  try { await ungatedApp.invoke(opInput("arm", new Uint8Array([1, 1]))); } catch { refused = true; }
  ok(refused, "an undeclared timer service is refused at the seam, wired backend or not");
  ungated.close();

  // Uninstall cancels: a pending setTimeout holds a callback that re-enters the realm, so
  // one outliving its realm would call into a freed QuickJS context (§12.3). Uses a stub
  // realm, since what must be observed is the entrypoint not being invoked, which a real
  // realm would show only by crashing, or not at all.
  let armed = null;
  const entries = [];
  const { shell: stub } = await bootShell({
    sodium, identity: kp.ed, modules: new ModuleTable(),
    freshnessStore: new FreshnessMarks(),
    fs: false,
    createRealm: async (o) => {
      armed = o.hostCall;
      return {
        call: async (p) => {
          entries.push(isWake(p) ? "timer" : "invoke");
          return new Uint8Array();
        },
        dispose() {},
      };
    },
    admit: admitAll,
  });
  const stubApp = await stub.install(mkBlob(["timer"]));
  await stubApp.invoke(opInput("arm", new Uint8Array([0, 0])));
  // Arm through the seam the realm was given, then uninstall the app.
  const pending = new Uint8Array([0, 0, 0, 5]);
  await armed("timer/arm", pending, new CallBudget(Infinity, undefined, undefined));
  ok(stub.uninstall("ticker") === true, "the app uninstalls with a deadline still pending");
  await sleep(80);
  ok(!entries.includes("timer"), `uninstalling an app cancels its pending deadlines (entries: ${entries.join(", ")})`);
  stub.close();
}

// ── §12.2: the host's caller id is matched whole, never by prefix ──────────
// There is one host caller id, 32 zero bytes, matched over all 32 bytes. Every other
// caller id is a hashed app label or a peer key, which their owners choose, so any byte
// can be ground (~256 tries per byte). A reader checking only a prefix would let anyone
// pass as the host, so the match covers all 32 bytes.
console.log("\n§12.2 — the host caller id is matched over all 32 bytes, not by its prefix");
{
  const body = new Uint8Array([9, 9, 9, 9]);
  const withCaller = (caller) => { const a = new Uint8Array(36); a.set(caller, 0); a.set(body, 32); return a; };

  // This test app's reader; the host contributes only the 32-byte attribution prefix.
  ok(callerOf(withCaller(new Uint8Array(32))).fromHost, "32 zero bytes read as the host proper");
  // A near-miss on the host id is not the host: one bit in the last byte is enough.
  const nearHost = new Uint8Array(32); nearHost[31] = 1;
  ok(!callerOf(withCaller(nearHost)).fromHost, "a caller id that is zero but for its last byte is not the host");
  const leadingZero = new Uint8Array(32); leadingZero[31] = 0xff; // zero everywhere but the LAST byte
  ok(!callerOf(withCaller(leadingZero)).fromHost,
    "a caller id that is zero everywhere but its last byte is not the host — the match is not a leading-zero-run shortcut");

  // The transport build injects the generated reader into its signed source. Evaluate that
  // assembled source instead of copying the reader into this test.
  const transportSrc = readGuestSource(guestOpFraming());
  const m = /function callerOf\(arg\) \{[\s\S]*?\n\}/.exec(transportSrc);
  ok(m !== null, "the transport assembler injected the canonical callerOf");
  const transportCallerOf = new Function(`${m[0]}; return callerOf;`)();
  ok(transportCallerOf(withCaller(new Uint8Array(32))).fromHost, "the transport reads 32 zero bytes as the host proper");
  ok(!transportCallerOf(withCaller(nearHost)).fromHost, "…and refuses a near-miss as the host proper");
}

summary("hardening checks");
