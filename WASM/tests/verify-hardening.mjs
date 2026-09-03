// Focused checks for the hardening changes (§4.3 memory bounds, §12.2 scoping and seam
// gates, §12.3 realm budgets, §12.4 guest-only apps). Standalone because each block is a
// tight loop over one seam; run.mjs covers the same ground end-to-end. Run after `npm run build`.

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
const { readMemoryLimits, checkModuleMemory, DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES, DEFAULT_MAX_BUNDLE_MODULES,
  DEFAULT_MAX_TIMER_PAYLOAD_BYTES, DEFAULT_MAX_APP_SLOTS, DEFAULT_GUEST_DEADLINE_MS,
  SELF_INITIATED_CLOCK_DIVISOR,
  DEFAULT_REALM_MEMORY_BYTES, DEFAULT_MAX_MODULE_MEMORY_BYTES,
  DEFAULT_MEMORY_FS_MAX_BYTES }
  = await imp("build/core/wasm-limits.js");
const { MAX_OUTBOUND_QUEUE_BYTES, MAX_OUTBOUND_QUEUE_SLICES,
  MAX_NODE_OUTBOUND_QUEUE_BYTES, MAX_INBOUND_HOLD_BYTES }
  = await imp("build/core/net-limits.js");
const { MAX_QUEUED_SIGNAL_BYTES, MAX_QUEUED_SIGNALS, MAX_UNESTABLISHED_PEERS,
  MAX_PENDING_ICE_BYTES, MAX_SDP_BYTES }
  = await imp("build/host/net-rtc.js");
const { MemoryFs } = await imp("build/host/fs-memory.js");
const { appKeyFor, appScopeFor, genesisHash, verifyManifest, loadBundleModules, MANIFEST_FILE, GUEST_FILE, FreshnessMarks }
  = await imp("build/host/bundle.js");
const { signManifest, packBundle, guestOpFraming } = await imp("build/host/bundle-author.js");
// ML-DSA-65 onto this instance, exactly as a target does at its crypto seam: a manifest
// is signed and verified with both halves of the author's key set (§12.4), so a bare
// libsodium cannot sign one.
const { withMlDsa65, loadMlDsa65 } = await imp("build/host/pq.js");
withMlDsa65(sodium, await loadMlDsa65(readFileSync(join(root, "browser/mldsa65.wasm"))));
/** A manifest author: both halves of the key set, plus the 32-byte id they derive — the
 *  identity policy pins and app keys lead with. `ed` doubles as a node identity. */
const testAuthor = () => makeAuthor(sodium);
const { bootShell, scopedFs, createRealmTimers } = await imp("build/host/shell-core.js");
const { toHex } = await imp("build/core/util.js");
const { admitAll } = await imp("build/host/policy.js");
const { createGuestSeam, HOST_CALLER_ID } = await imp("build/host/guest-seam.js");
const ALL_HOST_SERVICES = ["node", "fs", "clock", "timer", "link"];
const TEST_TIMERS = { arm() {}, clear() {} };
const TEST_CALLS = { call: () => null };
const { callerOf, readOp, writeOp } = await imp("build/host/op-frame.js");
const { createSafeRealm } = await imp("build/host/safe-js.js");
const { createActiveHostCallRegistry, serializeCalls } = await imp("build/host/realm-queue.js");

const { ok, throws, summary, sleep } = testkit();
/** Await a promise and assert it rejects — the async form of `throws`, which is what a
 *  build that stands up workers now needs (`PureModuleLoader.build` is async). */
const rejects = async (p, msg) => { let threw = false; try { await p; } catch { threw = true; } ok(threw, msg); };

const withMax = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
const noMax = new Uint8Array(readFileSync(join(root, "build/forwarder-nomax.wasm")));
/** A module header plus a memory section declaring `initial`/`max` pages, and nothing else.
 *  Enough for the bounds read, which walks section headers and deliberately does not
 *  validate (core/wasm-limits.ts) — so an oversized declaration is cheap to state here. */
const memModule = (initialPages, maxPages) => {
  const leb = (n) => { const out = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b); } while (n); return out; };
  const body = [0x01, 0x01, ...leb(initialPages), ...leb(maxPages)]; // one memory, flags=1 (a maximum is declared)
  return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 5, body.length, ...body]);
};

console.log("\n§4.3 — declared memory is bounded before instantiation");
{
  const a = readMemoryLimits(withMax);
  const b = readMemoryLimits(noMax);
  ok(a.maxPages === 256, `built module declares a 256-page maximum (got ${a.maxPages})`);
  ok(b.maxPages === null, "the no-maximum build declares none");
  ok(checkModuleMemory(withMax, 64 * 1024 * 1024) !== null, "a bounded module passes the budget");
  throws(() => checkModuleMemory(noMax, 64 * 1024 * 1024), "a module with no declared maximum is refused");
  throws(() => checkModuleMemory(withMax, 1024 * 1024), "a module above the host budget is refused");
  throws(() => checkModuleMemory(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), 1 << 20), "a non-wasm blob is refused");

  // The ceiling is applied ONCE, by the shared load path, against the tighter of the shared
  // default and the ceiling the target's loader declares (bundle.ts `loadBundleModules`) —
  // so a loader may hold itself to less than a bundle may land, and none can be looser.
  // A stub loader is the whole fixture: under test is the composition, not an isolate.
  const stub = (maxModuleMemoryBytes) => ({
    maxModuleMemoryBytes,
    build: async () => ({ call: async () => ({ bytes: null, ms: 0 }), dispose() { } }),
  });
  const bundleOf = (wasm) => ({ modules: [{ mod: { name: "m" }, wasm }] });
  ok(await loadBundleModules(stub(undefined), bundleOf(withMax)) !== null,
    "a loader declaring no ceiling of its own gets the shared one");
  await rejects(loadBundleModules(stub(undefined), bundleOf(noMax)),
    "an unbounded module is refused on the load path, whatever a loader would have built");
  await rejects(loadBundleModules(stub(1024 * 1024), bundleOf(withMax)),
    "a loader's TIGHTER ceiling is the one the load path applies");
  // 128 MiB declared against a loader that would allow 1 GiB: the shared ceiling still wins.
  await rejects(loadBundleModules(stub(1 << 30), bundleOf(memModule(1, 2048))),
    "a loader's LOOSER ceiling cannot raise what a bundle may land");
  await rejects(loadBundleModules(stub(undefined), {
    modules: [
      { mod: { name: "a" }, wasm: memModule(1, 600) },
      { mod: { name: "b" }, wasm: memModule(1, 600) },
    ],
  }), "module maxima are bounded in aggregate across one bundle");
  await rejects(loadBundleModules(stub(undefined), {
    modules: Array.from({ length: DEFAULT_MAX_BUNDLE_MODULES + 1 }, (_, i) => ({
      mod: { name: `m${i}` }, wasm: memModule(0, 0),
    })),
  }), "a bundle cannot evade memory accounting with unbounded zero-memory modules");

  const host = new ModuleTable();
  const loaded = await host.build([{ name: "ok", wasm: withMax }]);
  const echoed = await loaded.call("ok", new Uint8Array());
  ok(echoed instanceof Object && echoed.bytes instanceof Uint8Array && typeof echoed.ms === "number",
    "ModuleTable builds a bounded module set (call resolves { bytes, ms })");
  ok(host.maxModuleMemoryBytes === 64 * 1024 * 1024,
    "a table declares the shared ceiling through the loader seam by default");
  ok(new ModuleTable({ maxModuleMemoryBytes: 1024 * 1024 }).maxModuleMemoryBytes === 1024 * 1024,
    "the budget is configurable per host, and declared rather than applied");

  // The bind is all-or-none (§3.1): a bundle whose SECOND module is malformed leaves the
  // table exactly as it was. The host's guarantee, so a caller does nothing to earn it.
  const atomic = new ModuleTable();
  await rejects(atomic.build([
    { name: "first", wasm: withMax },
    { name: "second", wasm: new Uint8Array() },
  ]), "a bundle with one bad module is refused whole");
  loaded.dispose();
}

console.log("\n§12.2 — fs is scoped per app key");
{
  const disk = new MemoryFs();
  const A = new Uint8Array(32).fill(0xaa), B = new Uint8Array(32).fill(0xbb);
  const alice = scopedFs(disk, appScopeFor(sodium, A, "chat"));
  const bob = scopedFs(disk, appScopeFor(sodium, B, "chat"));
  // Every method awaits: the seam is async so a browser backend can implement it
  // (core/fs.ts), and MemoryFs answers in a microtask like any other.
  await alice.put("secret", new Uint8Array([1, 2, 3]));
  await bob.put("secret", new Uint8Array([9]));
  ok((await alice.get("secret")).length === 3, "alice reads her own key");
  ok((await bob.get("secret")).length === 1, "bob's same-named key is a different value");
  const bobKeys = await bob.list("");
  ok(bobKeys.length === 1 && bobKeys[0] === "secret", "list() shows only this app's keys, unprefixed");
  ok(await bob.delete("secret") && (await alice.get("secret")) !== null, "bob's delete cannot reach alice's key");
  ok((await disk.list("")).length === 1, "the backend holds both under distinct physical keys");

  // Colons in an app name cannot make two scopes overlap, and cannot reach the backend.
  const amb1 = scopedFs(disk, appScopeFor(sodium, A, "x:y"));
  const amb2 = scopedFs(disk, appScopeFor(sodium, A, "x"));
  await amb1.put("z", new Uint8Array([1]));
  ok((await amb2.get("y:z")) === null, "app 'x:y' key 'z' does not collide with app 'x' key 'y:z'");
  ok(/^[A-Za-z0-9._-]+$/.test(appScopeFor(sodium, A, "x:y")), "the derived scope is inside the backend key charset");
  // The real backends reject anything outside that charset, so an unsafe scope must
  // fail at construction rather than on the first write.
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
  const verify = (m) => verifyManifest(sodium, signManifest(sodium, kp, m));
  // Refused BY NAME, like an unimplemented ABI: this is what a bundle written against the
  // retired module-only format produces, so its author has to learn the rule rather than
  // read "malformed manifest".
  const refusal = (m) => { try { verify(m); return ""; } catch (e) { return e.message; } };
  const none = refusal({ app: "x", version: 1, modules: [] });
  ok(none.includes("every app is a guest"), `a manifest without a guest is refused by name (got: ${none})`);
  ok(verify({ app: "x", version: 1, modules: [], guest: { hash: "aa", requires: [] } }) !== null,
    "a guest may declare no modules at all");
  ok(verify({ app: "x", version: 1, modules: [{ name: "a", hash: "aa" }, { name: "b", hash: "bb" }], guest: { hash: "aa", requires: [] } }) !== null,
    "a guest may declare multiple modules within the admission cap");
  const tooMany = Array.from({ length: DEFAULT_MAX_BUNDLE_MODULES + 1 }, (_, i) => ({ name: `m${i}`, hash: "aa" }));
  ok(refusal({ app: "x", version: 1, modules: tooMany, guest: { hash: "aa", requires: [] } }).includes("malformed manifest"),
    "the manifest module-count cap is enforced before file extraction");
  for (const version of [-1, Number.MAX_SAFE_INTEGER + 1]) {
    ok(refusal({ app: "x", version, modules: [], guest: { hash: "aa", requires: [] } }).includes("malformed manifest"),
      `version ${version} is refused before it can poison freshness state`);
  }
}

console.log("\n§12.2 — the capability gates cannot be reached by omission");
{
  const identity = sodium.crypto_sign_keypair();
  const base = {
    platform: { sodium, identity, now: () => Date.now(), peers: () => [] },
    grants: { transport: { request: async () => new Uint8Array() }, fs: new MemoryFs(), calls: TEST_CALLS, timers: TEST_TIMERS },
    modules: { names: new Set(), call: async () => ({ bytes: null, ms: 0 }) },
  };
  throws(() => createGuestSeam({ ...base }), "omitting grants.names throws at construction");
  ok(typeof createGuestSeam({ ...base, grants: { ...base.grants, names: ALL_HOST_SERVICES } }) === "function",
    "an explicit full service set is accepted");

  // A guest reaches its own app's modules with NO grant: a bare name is the asking
  // bundle's own code, scoped by the app key the seam was wired with, so it resolves under
  // an empty requires set exactly like `crypto`.
  const chat = new ModuleTable();
  const chatModules = await chat.build([{ name: "codec", wasm: withMax }]);
  const otherModules = await chat.build([{ name: "evil", wasm: withMax }]);
  const scoped = createGuestSeam({
    ...base,
    grants: { ...base.grants, names: [] },
    modules: { names: new Set(["codec"]), call: chatModules.call },
  });
  // The forwarder echoes its input, so a resolved module answers with the body.
  ok((await scoped("codec", new Uint8Array([7, 7, 7]))).length === 3, "a module of this app resolves and runs");
  throws(() => scoped("evil", new Uint8Array([7, 7, 7])),
    "another app's module name reaches nothing through this seam");
  chatModules.dispose(); otherModules.dispose();
}

console.log("\n§4.3 — the guest realm has an execution budget");
{

  const enc = new TextEncoder();
  const noop = () => new Uint8Array();

  // Construction has to be isolated from this runner: the regression shape blocks the
  // thread forever when its guard is missing, so the parent kills a broken child instead
  // of hanging the entire suite.
  const initProbe = spawnSync(process.execPath, [join(root, "tests/fixtures/guest-init-deadline.mjs")], {
    timeout: 3000, encoding: "utf8",
  });
  ok(initProbe.status === 0 && !initProbe.error,
    `top-level guest code is interrupted during realm construction (${initProbe.error?.message ?? initProbe.stderr.trim()})`);

  // A holder that loops forever is interrupted rather than wedging the host thread.
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

  // Invocations are serialized per realm: a holder invoked while an initiator is parked
  // waits for it rather than interleaving, and then runs on a budget of its own rather
  // than on what the initiator left (§12.3).
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

  // The queue does not strand callers on dispose: one still in it fails rather than
  // entering a torn-down realm, which is what aborts the whole wasm module.
  const closing = await createSafeRealm({
    source: 'async function handle() { await host.call("slow", new Uint8Array()); return new Uint8Array([1]); }',
    hostCall: slowSeam, deadlineMs: 5000,
  });
  const first = closing.call(new Uint8Array()).catch(() => "failed");
  const queued = closing.call(new Uint8Array()).catch(() => "failed");
  closing.dispose();
  ok(await first === "failed", "a parked call is failed by dispose rather than left pending");
  ok(await queued === "failed", "and so is one still waiting in the queue");

  // The default is a real number, so forgetting the field bounds the guest rather than
  // unbounding it — the same posture as the seam gates above.
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

  // Reach the byte boundary with only eight calls, then prove the ninth is rejected before
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

  // Changing only the operation name cannot buy an accounting exemption.
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
  // Every owner is per realm and none is pooled between realms: a shared allowance is a
  // standing way for a busy app to refuse a quiet sibling's calls, and one realm's ceiling
  // times a bound on realms reaches the same total without one. So the multiplication has
  // to appear in the sum — otherwise each per-realm number is a floor that an install list
  // nobody counts multiplies at will. This sum is where the node total lives: adding a
  // node-scoped owner of admitted host memory means adding its term HERE, not just
  // declaring its own constant.
  const perRealm = DEFAULT_REALM_MEMORY_BYTES  // §12.3 — one confined guest heap
    + DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES  // copied host-call inputs and their answers
    + DEFAULT_MAX_TIMER_PAYLOAD_BYTES          // copied timer bodies
    + DEFAULT_MAX_MODULE_MEMORY_BYTES;         // §4.3 — one bundle's aggregate module memory
  const nodeMemoryCeiling = DEFAULT_MAX_APP_SLOTS * perRealm
    + MAX_NODE_OUTBOUND_QUEUE_BYTES // §12.6 — outbound socket queues, over every link
    + 2 * MAX_INBOUND_HOLD_BYTES    // §12.6 — native staging and the driver window hold the
                                    // same read at once, by design (native/sock.go)
    + MAX_QUEUED_SIGNAL_BYTES       // §12.6 — the WebRTC signaling lane, one per node
    + MAX_UNESTABLISHED_PEERS * MAX_PENDING_ICE_BYTES // and one ICE queue per speculative peer
    + DEFAULT_MEMORY_FS_MAX_BYTES;  // the in-memory fs backend's whole quota
  // Not circular: the sum is measured against a real machine, so growing any owner has to
  // be a deliberate choice rather than a number nobody added up.
  ok(nodeMemoryCeiling <= 2 * 1024 * 1024 * 1024,
    "the summed worst case of every node-scoped owner still fits a modest machine");
  // Every window in the sum is a byte bound with a count companion or the reverse. The
  // signaling lane is the one whose count admits a 256 KiB message, so it is checked
  // directly: a count alone there would put the node's largest single allowance — bigger
  // than a whole confined heap — behind a bound nobody wrote down.
  ok(MAX_QUEUED_SIGNAL_BYTES < MAX_QUEUED_SIGNALS * MAX_SDP_BYTES,
    "the signaling lane's byte companion binds before its count does");
}

console.log("\n§12.3 — guest-created invocation roots have a bounded clock share");
{
  // Memory's total above is a standing quantity and really is a total. Time's is not: a
  // peer or host can replace settled work immediately. A timer is different because it is
  // the one fresh invocation root a guest creates ITSELF; calls descended from an existing
  // root inherit its deadline. A second self-created root mechanism belongs in this sum.
  ok(DEFAULT_MAX_APP_SLOTS * DEFAULT_GUEST_DEADLINE_MS <= 60_000,
    "every slot spending its banked invocation at once is a stall someone added up");
  ok(DEFAULT_MAX_APP_SLOTS / SELF_INITIATED_CLOCK_DIVISOR <= 1 / 2,
    "a full node's summed self-initiated share is at most half the clock, so it cannot be the majority");
}

console.log("\n§12.3 — active-call and realm-entry owners have complete lifecycle rules");
{
  const active = createActiveHostCallRegistry(2, 8);
  const first = active.admit(1, 5);
  throws(() => active.admit(1, 0), "a registry refuses a duplicate live id");
  first.reserve(3);
  throws(() => active.admit(2, 1), "responses awaiting delivery remain charged");
  first.release();
  throws(() => first.reserve(1), "a settled call cannot reserve more against its realm");
  active.admit(2, 8).release();
  ok(true, "terminal settlement releases request, response, id, and count together");

  // A realm that dies with calls still parked releases them: nothing is left to consume
  // those answers, and no handle survives that could release them later — so holding the
  // charge would pin the realm's allowance on a backend that never answers. The two ways a
  // realm can die (construction failure, dispose) are both checked, and a backend that
  // settles afterwards must be a no-op, never a second release.
  let settleOrphan;
  await rejects(createSafeRealm({
    source: 'host.call("hold", Uint8Array.of(1)); throw new Error("init failed");',
    hostCall: () => new Promise((resolve) => { settleOrphan = resolve; }),
  }), "failed realm construction reports its source error");
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
  // The parked call's handoff deadline is host-side state exactly like its byte charge, and
  // dispose() must end both. A timer nobody is left waiting for still holds the host's event
  // loop open for the whole of its remainder — enough to make a one-shot process linger a
  // full budget past the work it came to do — so the count is read either side of dispose.
  const liveTimers = () => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
  const armedAtDispose = liveTimers();
  disposedWithParked.dispose();
  ok(armedAtDispose > 0 && liveTimers() < armedAtDispose,
    "disposing a realm disarms the handoff deadline of the call it abandoned");
  ok((await afterFailure.call(new Uint8Array()))[0] === 7,
    "disposing a realm with a call still parked releases its charge too");
  settleAtDispose(new Uint8Array());
  afterFailure.dispose();

  let closed = false;
  const gates = [];
  const seen = [];
  const queued = serializeCalls((payload) => {
    seen.push(payload);
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    gates.push(release);
    return { result: gate.then(() => payload), released: gate };
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
  // Queue depth is derived from bounded upstream owners, while payload bytes remain
  // charged to those owners rather than counted or copied again here.
  const large = queued(new Uint8Array(32 * 1024 * 1024));
  await sleep(0);
  gates.shift()();
  ok((await large).length === 32 * 1024 * 1024,
    "the entry queue borrows bytes already charged to the initiating owner");
  closed = true;
  await rejects(queued(new Uint8Array()), "a closed realm stops admitting immediately");

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

console.log("\n§12.3 — timer count and copied payload bytes are bounded per realm");
{
  const countBound = createRealmTimers(() => {}, 2, 100);
  countBound.arm(1, 60_000, new Uint8Array(1));
  countBound.arm(2, 60_000, new Uint8Array(1));
  throws(() => countBound.arm(3, 60_000, new Uint8Array(1)), "a third live id is refused at a two-timer cap");
  countBound.clearAll();

  // What the table retains is the realm-entry buffer, so the caller-id prefix is part of
  // every charge — read from the seam rather than restated, since a hand-copied 32 here
  // would pass while the real accounting drifted.
  const frame = HOST_CALLER_ID.length;
  let fired = 0;
  const byteBound = createRealmTimers(() => { fired++; }, 10, 2 * frame + 8);
  byteBound.arm(1, 60_000, new Uint8Array(6));
  throws(() => byteBound.arm(2, 60_000, new Uint8Array(3)), "aggregate copied timer bodies cannot cross their byte cap");
  byteBound.arm(1, 60_000, new Uint8Array(8));
  byteBound.clear(1);
  byteBound.arm(2, 1, new Uint8Array(8));
  await sleep(20);
  ok(fired === 1, "a timer fires once under the byte cap");
  byteBound.arm(3, 60_000, new Uint8Array(8));
  byteBound.clearAll();
  byteBound.arm(4, 60_000, new Uint8Array(8));
  byteBound.clearAll();
  ok(true, "clear, fire, and disposal release timer payload accounting");

  // Firing hands the body to a realm that borrows it (realm-queue.ts counts depth only),
  // so custody MOVES rather than ending: the deadline is not a release event, the answer
  // is. Otherwise the moment a realm is busiest — fired bodies queued behind it — is the
  // moment they are charged to nobody.
  let releaseFired;
  const inFlight = createRealmTimers(
    () => new Promise((resolve) => { releaseFired = resolve; }), 10, 2 * frame + 8);
  inFlight.arm(1, 1, new Uint8Array(8));
  await sleep(20);
  throws(() => inFlight.arm(2, 60_000, new Uint8Array(8)),
    "a fired body stays charged while the realm still holds it");
  releaseFired();
  await sleep(20);
  inFlight.arm(2, 60_000, new Uint8Array(8));
  ok(true, "and is released once the invocation it was handed to settles");
  inFlight.clearAll();
}

console.log("\n§12.3 — a realm's self-initiated work is paced by its share of the node's clock");
{
  // Re-arming at ms=0 from inside the timer entrypoint: the one fresh invocation root a guest
  // creates itself, each fire taking a fresh full budget (§12.3). Scaled down so the RATIO is
  // under test, and run at a divisor of 1 as its own control — there a busy table earns back
  // exactly what it spends, which is the unpaced behaviour this replaced.
  const budgetMs = 40, occupyMs = 20, spinForMs = 400;
  const spin = async (clockDivisor) => {
    let fires = 0;
    let table;
    table = createRealmTimers((_body, causalClock) => {
      fires += 1;
      table.arm(1, 0, new Uint8Array(1));
      // Stand in for the realm's execution report. Burn real time too, so divisor 1 is
      // the control where execution spend and concurrent credit accrual cancel exactly.
      const started = performance.now();
      while (performance.now() - started < occupyMs) { /* guest is computing */ }
      causalClock.charge(performance.now() - started);
    }, 10, 4096, budgetMs, clockDivisor);
    table.arm(1, 0, new Uint8Array(1));
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

  // Metered on the clock the fires occupy and never on how many there are, so the transport's
  // own shape — a cheap deadline per link, all coming due at once — meets none of it. Pacing
  // THAT would be a regression rather than a bound.
  let cheap = 0;
  const honest = createRealmTimers(() => { cheap += 1; });
  for (let id = 0; id < 64; id++) honest.arm(id, 0, new Uint8Array(1));
  await sleep(60);
  ok(cheap === 64, `64 deadlines that cost nothing all fire at once (${cheap})`);
  honest.clearAll();

  // Waiting is not execution. Start below an empty bank, then keep the first fire parked
  // longer than recovery takes. Its successor must become admissible WHILE the first is
  // still awaiting; charging dispatch-to-settlement wall time would keep it slipped until
  // the wait ended and then make it buy the same credit a second time.
  let waitingFires = 0;
  let releaseWait;
  const waiting = createRealmTimers((_body, causalClock) => {
    waitingFires += 1;
    if (waitingFires !== 1) return;
    causalClock.charge(2 * budgetMs); // clamps the bank to -budgetMs
    return new Promise((resolve) => { releaseWait = resolve; });
  }, 10, 4096, budgetMs, 4);
  waiting.arm(1, 0, new Uint8Array(1));
  await sleep(20);
  waiting.arm(2, 0, new Uint8Array(1));
  await sleep(220); // -40 -> +1 earns in 164 ms at a divisor of 4
  ok(waitingFires === 2,
    "a timer root earns clock credit while its entrypoint is parked on I/O");
  releaseWait();
  waiting.clearAll();

  // The inverse escape is returning before descendant work: await once (so lineage must
  // survive settlement), call a second realm without awaiting it, and let that callee
  // launch module-like work without awaiting that either. The late charge must still land
  // on the timer root after both entrypoints have already answered.
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
  }, 10, 4096, budgetMs, 4);
  const charged = new Promise((resolve) => { moduleCharged = resolve; });
  rooted.arm(1, 0, new Uint8Array(1));
  await charged;
  rooted.arm(2, 0, new Uint8Array(1));
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
  // A bound can be declared on every interface between the operator and the realm and be
  // passed by none of them, so this boots a node onto a stub realm factory and asserts the
  // numbers arrive. No transport, so nothing here may reach a privilege.
  const kp = testAuthor();
  const guestSrc = 'function handle() { return new Uint8Array([1]); }';
  const guestBytes = new TextEncoder().encode(guestSrc);
  const signedConfig = JSON.parse('{"mode":"signed","nested":[true,null,{"n":3}],"__proto__":{"kept":"data"}}');
  const manifest = {
    app: "probe", version: 1, modules: [],
    guest: {
      hash: toHex(genesisHash(sodium, guestBytes)), requires: [],
      config: signedConfig,
    },
  };
  const blob = packBundle({
    [MANIFEST_FILE]: signManifest(sodium, kp, manifest),
    [GUEST_FILE]: guestBytes,
  });

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
  const probe = await shell.loadBundleBlob(blob, {
    localConfig: { mode: "local", localOnly: { quota: 7 }, flags: [false, true] },
  });
  await probe.invoke(new Uint8Array());
  ok(seen.length === 1, "the shell created a realm for the loaded guest");
  ok(seen[0]?.deadlineMs === 1234, `guestDeadlineMs reaches the realm factory (got ${seen[0]?.deadlineMs})`);
  ok(seen[0]?.memoryLimitBytes === 7 * 1024 * 1024, "realmMemoryBytes reaches the realm factory");

  // HOST, APP and LOCAL are three provenance-preserving values, not one host-side merge:
  // what the runtime admits, what the author signed, what the operator set for this load.
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

  // A second load receives no residue from the first load's LOCAL value.
  await shell.loadBundleBlob(blob);
  const [appAgain, localAgain] = valuesFrom(seen[1].source);
  ok(appAgain.mode === "signed" && Object.keys(localAgain).length === 0,
    "local config is scoped to one load, not retained by the shell for another app or reload");
  ok(seen[1]?.memoryLimitBytes === 7 * 1024 * 1024 && seen[1]?.deadlineMs === 1234,
    "a load naming no bounds of its own falls back to the shell's");

  // …and a load that names them OVERRIDES the shell's, which is the point of their being
  // per load: one shell hosts unrelated apps, and the heap a storage guest needs is not the
  // heap the transport bundle beside it should be handed.
  await shell.loadBundleBlob(blob, { realmMemoryBytes: 9 * 1024 * 1024, guestDeadlineMs: 77 });
  ok(seen.at(-1)?.memoryLimitBytes === 9 * 1024 * 1024, "a load's own realmMemoryBytes overrides the shell's");
  ok(seen.at(-1)?.deadlineMs === 77, "a load's own guestDeadlineMs overrides the shell's");
  const cyclic = {}; cyclic.self = cyclic;
  await rejects(shell.loadBundleBlob(blob, { localConfig: cyclic }),
    "a non-JSON local value is refused instead of being silently changed during injection");
  // Both channels are OBJECTS. A guest reads config by name, so a scalar or array would
  // make every `LOCAL.x` read `undefined` at run time rather than fail at the load.
  await rejects(shell.loadBundleBlob(blob, { localConfig: [1, 2] }),
    "a JSON array is refused as local config — a guest reads config by name");
  await rejects(shell.loadBundleBlob(blob, { localConfig: 7 }),
    "a JSON scalar is refused as local config");
  // The same rule on the signed side, enforced by the manifest's structural check: an
  // author who signs a scalar `config` gets a refused bundle, not a guest reading undefined.
  {
    const scalarManifest = {
      ...manifest,
      guest: { ...manifest.guest, config: "not-an-object" },
    };
    const scalarBlob = packBundle({
      [MANIFEST_FILE]: signManifest(sodium, kp, scalarManifest),
      [GUEST_FILE]: guestBytes,
    });
    await rejects(shell.loadBundleBlob(scalarBlob),
      "a signed guest.config that is not a JSON object is a refused manifest");
  }

  // §12.5 — uninstalling a GUEST-ONLY app reports success. An app is its modules and
  // its realm, and this bundle legitimately declares no modules at all, so a count of
  // dropped modules is the wrong answer to "was there anything here".
  ok(shell.uninstall(appKeyFor(kp.id, "probe")) === true,
    "uninstalling a guest-only app reports success, not 'nothing there'");
  ok(shell.uninstall(appKeyFor(kp.id, "probe")) === false,
    "uninstalling it twice reports nothing the second time");
  shell.close();

  // Omitted ⇒ the SHARED defaults arrive at the seam (core/wasm-limits.ts), not undefined
  // and not "unbounded". The shell resolves them so no factory owns the numbers.
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
  const bareProbe = await bare.loadBundleBlob(blob);
  await bareProbe.invoke(new Uint8Array());
  ok(seen2 && seen2.deadlineMs === 5000, "an unset budget arrives as the shared default (5000 ms)");
  ok(seen2 && seen2.memoryLimitBytes === 64 * 1024 * 1024, "an unset heap cap arrives as the shared default (64 MiB)");
  // The budgets a guest is measured against are TOLD to it (the `HOST` preamble), so an app
  // can window its own fan-out to them instead of discovering them by being refused.
  const advertised = Function(
    seen2.source.split("\n").slice(0, 3).join("\n") + "\nreturn HOST;",
  )();
  ok(advertised.maxOutstandingHostCallBytes === DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES
    && advertised.maxOutstandingHostCalls === DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
    "the realm's host-call budget is advertised to the guest, not only enforced against it");
  bare.close();
}

console.log("\n§12.6 — host socket send queues are bounded");
{
  const { MessageChannel } = await imp("build/host/net-channel.js");
  const { NodeChannelFactory } = await imp("build/host/net-node.js");
  const { TransportHost } = await imp("build/host/transport-host.js");
  const ownedChannel = (channel, limits = {}) => {
    let ownerClosed = false;
    const closeChannel = channel.close.bind(channel);
    channel.close = (graceful) => { ownerClosed = true; closeChannel(graceful); };
    const channels = {
      connect: () => channel,
      listen: async () => ({ port: 0, wsPort: 0 }),
      close() {},
    };
    const driver = new TransportHost({ channels, ...limits }, {});
    driver.activate(() => Promise.resolve(new Uint8Array()));
    const raw = driver.rawNet();
    const { linkId } = raw.open("test");
    return {
      send: (bytes) => raw.send(linkId, bytes),
      // Observe the adapter directly. Its backlog is no longer guest-visible: the host
      // owner still uses it for custody reconciliation, but transport content has no
      // `link/stat` clock to rebuild deadlines from.
      buffered: () => {
        try { return channel.buffered?.() ?? 0; } catch { return 0; }
      },
      closed: () => ownerClosed,
      close: () => driver.close(),
    };
  };
  // A transport that never becomes writable — the state an unfinished connect leaves a
  // channel in. Until `open` fires, everything written is HOST memory spent by a peer that
  // has proved nothing, so the queue a handshake frame or two needs must not be a place an
  // occupant can put a megabyte per stalled socket.
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
  // Failed, not silently trimmed: dropping a frame off an ordered stream leaves the far end
  // waiting on a gap forever, where a dead channel is one the occupant is told about.
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
  // accepted; the next whole ordered message fails the link rather than being dropped.
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

  // A byte cap alone admits millions of one-byte message objects. The independent count
  // ceiling bites while the byte total is still tiny.
  const byCount = openedChannel();
  for (let i = 0; i < MAX_OUTBOUND_QUEUE_SLICES; i++) byCount.channel.send(Uint8Array.of(i));
  ok(!byCount.failed() && byCount.channel.buffered() < MAX_OUTBOUND_QUEUE_BYTES,
    "tiny writes reach the exact outbound slice ceiling below the byte ceiling");
  byCount.channel.send(Uint8Array.of(1));
  ok(byCount.channel.closed() && byCount.transport.closed,
    "crossing the outbound slice ceiling closes and releases the link");

  // Slices retire as the drained PREFIX, not all at once at an empty queue. The count is
  // shared node-wide, so a link that stays busy and never reaches an idle instant would
  // otherwise hold it at its high-water mark until the socket closed.
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
      listen: async () => ({ port: 0, wsPort: 0 }),
      close() {},
    },
    maxOutboundBytes: 6,
  }, {});
  parentDriver.activate(() => Promise.resolve(new Uint8Array()));
  const parentRaw = parentDriver.rawNet();
  const firstLink = parentRaw.open("a").linkId;
  const secondLink = parentRaw.open("b").linkId;
  parentRaw.send(firstLink, new Uint8Array(4));
  parentRaw.send(secondLink, new Uint8Array(3));
  ok(!parentLinks[0].closed && parentLinks[1].closed,
    "the node allowance prevents individually legal links multiplying retained bytes");
  parentDriver.close();

  // Node reports its platform backlog to the same link owner. A connect cannot progress while
  // this synchronous loop runs, which makes both exact boundaries deterministic without
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

  // `RawLink.buffered` is a required member of the contract (socket-seam.ts). An adapter
  // reporting 0 ASSERTS it retains nothing; one whose call throws — or, since a JS double
  // is not type-checked, is missing entirely — asserts nothing at all, and the two must not
  // read alike. Reading "cannot say" as 0 would release this link's charge and the node's
  // while the platform still holds the bytes, which is the uncharged interval this owner
  // exists to rule out; freezing the accounting instead would strangle a healthy link at
  // its cumulative ceiling. The link fails on the write instead, and only that teardown
  // releases — a destroyed socket really has dropped what it held.
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
  // The catalog calls `timer` an app service (core/domains.ts), so what is under test is
  // that an ORDINARY app gets one: no transport bundle is loaded anywhere below. Wiring it
  // off the transport driver would admit such an app and then fail it at its first
  // `host.call` — a manifest the loader accepted naming a backend nothing wired.
  const kp = testAuthor();
  const guestSrc = `
    let fired = [];
    const u32x2 = (a, b) => new Uint8Array([a >>> 24, a >>> 16, a >>> 8, a, b >>> 24, b >>> 16, b >>> 8, b]);
    // handle reads [caller 32][body]: ONE entrypoint, and the body is this app's own
    // op framing ([opLen u8][op][args]), supplied by this test app. When arming a
    // deadline the app gives the host its complete future loopback body; the host stores
    // and returns those bytes opaquely after the same zero caller id used by invoke.
${guestOpFraming()}
    function handle(arg) {
      const { body } = callerOf(arg);
      const { op, args: p } = readOp(body);
      if (op === "timer") { fired.push((p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]) >>> 0); return new Uint8Array(0); }
      if (op === "arm") {
        const event = writeOp("timer", u32x2(p[0], 0).slice(0, 4));
        const request = new Uint8Array(8 + event.length);
        request.set(u32x2(p[0], p[1])); request.set(event, 8);
        host.call("timer/arm", request); return new Uint8Array(0);
      }
      if (op === "clear") { host.call("timer/clear", u32x2(p[0], 0).slice(0, 4)); return new Uint8Array(0); }
      if (op === "fired") return new Uint8Array(fired);
      return new Uint8Array(0);
    }
  `;
  const guestBytes = new TextEncoder().encode(guestSrc);
  const mkBlob = (requires) => {
    const manifest = {
      app: "ticker", version: 1, modules: [],
      guest: { hash: toHex(genesisHash(sodium, guestBytes)), requires },
    };
    return packBundle({
      [MANIFEST_FILE]: signManifest(sodium, kp, manifest),
      [GUEST_FILE]: guestBytes,
    });
  };
  // `fs: false` said rather than omitted: these bundles declare no `fs` cap, and the
  // in-memory default would hand this node a backend it is not meant to have.
  const newShell = async () => (await bootShell({
    sodium, identity: kp.ed, modules: new ModuleTable(),
    freshnessStore: new FreshnessMarks(), createRealm: createSafeRealm,
    fs: false,
    admit: admitAll,
  })).shell;

  const shell = await newShell();
  const ticker = await shell.loadBundleBlob(mkBlob(["timer"]));
  // The op frame is this app's own format (its `handle` reads it); the invoke below
  // passes bytes the shell never interprets. Same `writeOp` the guest's inlined block
  // reads back, from the one definition of it.
  const opInput = (op, p = new Uint8Array(0)) => writeOp(op, p);
  await ticker.invoke(opInput("arm", new Uint8Array([7, 5])));    // arm: id 7, in 5ms
  await sleep(80);
  const fired = await ticker.invoke(opInput("fired"));
  ok(fired.length === 1 && fired[0] === 7,
    `an app with no transport arms a deadline and its timer entrypoint fires (got [${[...fired]}])`);

  // Re-arming a live id replaces the deadline rather than adding one, and `clear` takes
  // it back: the id is the GUEST's throughout, so the host keeps no second name for it.
  await ticker.invoke(opInput("arm", new Uint8Array([9, 5])));
  await ticker.invoke(opInput("arm", new Uint8Array([9, 5])));
  await ticker.invoke(opInput("clear", new Uint8Array([9])));
  await sleep(80);
  const after = await ticker.invoke(opInput("fired"));
  ok(after.length === 1, `a cleared id does not fire, and two arms of it are one deadline (got [${[...after]}])`);
  shell.close();

  // The gate is still the manifest: a bundle that did not declare `timer` is refused by
  // NAME at the seam, not handed a table because the shell has one to give.
  const ungated = await newShell();
  const ungatedApp = await ungated.loadBundleBlob(mkBlob([]));
  let refused = false;
  try { await ungatedApp.invoke(opInput("arm", new Uint8Array([1, 1]))); } catch { refused = true; }
  ok(refused, "an undeclared timer service is refused at the seam, wired backend or not");
  ungated.close();

  // Uninstall CANCELS: a pending setTimeout holds a callback that re-enters the realm, so
  // one outliving its realm is a call into a freed QuickJS context (§2.1) rather than an
  // error. Through a stub realm, since what must be observed is the entrypoint NOT being
  // invoked — which a real realm would report only by crashing, or not at all.
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
          let op = "";
          try { op = readOp(p.subarray(32)).op; } catch { /* empty body — not an op call */ }
          entries.push(op === "timer" ? "timer" : "invoke");
          return new Uint8Array();
        },
        dispose() {},
      };
    },
    admit: admitAll,
  });
  const stubApp = await stub.loadBundleBlob(mkBlob(["timer"]));
  await stubApp.invoke(opInput("arm", new Uint8Array([0, 0])));
  // Arm through the very seam the realm was handed, then drop the app underneath it.
  const pending = new Uint8Array(8 + opInput("timer", new Uint8Array([0, 0, 0, 1])).length);
  pending.set(new Uint8Array([0, 0, 0, 1, 0, 0, 0, 5]));
  pending.set(opInput("timer", new Uint8Array([0, 0, 0, 1])), 8);
  await armed("timer/arm", pending);
  ok(stub.uninstall(appKeyFor(kp.id, "ticker")) === true, "the app uninstalls with a deadline still pending");
  await sleep(80);
  ok(!entries.includes("timer"), `uninstalling an app cancels its pending deadlines (entries: ${entries.join(", ")})`);
  stub.close();
}

// ── §12.2 — the host's one caller id is matched whole, never by prefix ──────────
// There is exactly ONE host caller id — 32 zero bytes — matched over the WHOLE 32 bytes.
// Every other caller id is an app key or peer key: a hash of facts its author picks, so
// ANY byte of it is grindable (~256 tries per byte). A reader stopping at the first zero
// byte would hand the "host proper" verdict to whoever wants it, so the match runs the
// whole prefix rather than a shortcut over its lead byte.
console.log("\n§12.2 — the host caller id is matched over all 32 bytes, not by its prefix");
{
  const body = new Uint8Array([9, 9, 9, 9]);
  const withCaller = (caller) => { const a = new Uint8Array(36); a.set(caller, 0); a.set(body, 32); return a; };

  // This test app's reader; the kernel contributes only the 32-byte attribution prefix.
  ok(callerOf(withCaller(new Uint8Array(32))).fromHost, "32 zero bytes read as the host proper");
  // A near-miss on the host id is not the host: one late bit is all it takes.
  const nearHost = new Uint8Array(32); nearHost[31] = 1;
  ok(!callerOf(withCaller(nearHost)).fromHost, "an app key that is zero but for its last byte is not the host");
  const leadingZero = new Uint8Array(32); leadingZero[31] = 0xff; // zero everywhere but the LAST byte
  ok(!callerOf(withCaller(leadingZero)).fromHost,
    "an app key that is zero everywhere but its last byte is not the host — the match is not a leading-zero-run shortcut");

  // The transport assembler injects the canonical generated reader into its signed source.
  // Evaluate that assembled source rather than restating the reader in this test.
  const transportSrc = readGuestSource(guestOpFraming());
  const m = /function callerOf\(arg\) \{[\s\S]*?\n\}/.exec(transportSrc);
  ok(m !== null, "the transport assembler injected the canonical callerOf");
  const transportCallerOf = new Function(`${m[0]}; return callerOf;`)();
  ok(transportCallerOf(withCaller(new Uint8Array(32))).fromHost, "the transport reads 32 zero bytes as the host proper");
  ok(!transportCallerOf(withCaller(nearHost)).fromHost, "…and refuses a near-miss as the host proper");
}

summary("hardening checks");
