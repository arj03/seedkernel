// Focused checks for the hardening changes (§4.3 memory bounds, §12.2 scoping and
// seam gates, §12.3 realm budgets, §12.4 guest-only apps). Standalone because each
// block is a tight loop over one seam; run.mjs covers the same ground end-to-end.
//
// Run: node tests/verify-hardening.mjs   (after `npm run build`)

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import _sodium from "libsodium-wrappers-sumo";
import { testkit, makeAuthor } from "./testkit.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

await _sodium.ready;
const sodium = _sodium;

const { ModuleTable } = await imp("build/host/module-table.js");
const { readMemoryLimits, checkModuleMemory } = await imp("build/core/wasm-limits.js");
const { MemoryFs } = await imp("build/host/fs-memory.js");
const { appKeyFor, appScopeFor, genesisHash, signManifest, verifyManifest, packBundle, MANIFEST_FILE, GUEST_FILE, FreshnessMarks }
  = await imp("build/host/bundle.js");
// ML-DSA-65 onto this instance, exactly as a target does at its crypto seam: a manifest
// is signed and verified with both halves of the author's key set (§12.4), so a bare
// libsodium cannot sign one.
const { withMlDsa65, loadMlDsa65 } = await imp("build/host/pq.js");
withMlDsa65(sodium, await loadMlDsa65(readFileSync(join(root, "browser/mldsa65.wasm"))));
/** A manifest author: both halves of the key set, plus the 32-byte id they derive — the
 *  identity policy pins and app keys lead with. `ed` doubles as a node identity. */
const testAuthor = () => makeAuthor(sodium);
const { createShell, scopedFs } = await imp("build/host/shell-core.js");
const { toHex } = await imp("build/core/util.js");
const { admitAll } = await imp("build/host/policy.js");
const { createGuestSeam, UNRESTRICTED_NAMES, GUEST_ABI_VERSION } = await imp("build/host/guest-seam.js");
const { createSafeRealm } = await imp("build/host/safe-js.js");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const { ok, throws, summary } = testkit();
/** Await a promise and assert it rejects — the async form of `throws`, which is what a
 *  bind that stands up workers now needs (bindAll is async). */
const rejects = async (p, msg) => { let threw = false; try { await p; } catch { threw = true; } ok(threw, msg); };

const withMax = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
const noMax = new Uint8Array(readFileSync(join(root, "build/forwarder-nomax.wasm")));

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

  const host = new ModuleTable();
  await host.bindAll("aa:app", [{ name: "ok", wasm: withMax }]);
  ok(host.isBound("aa:app", "ok"), "ModuleTable binds a bounded module");
  await rejects(host.bindAll("aa:app", [{ name: "bad", wasm: noMax }]),
    "ModuleTable refuses an unbounded module at install");
  const tiny = new ModuleTable({ maxModuleMemoryBytes: 1024 * 1024 });
  await rejects(tiny.bindAll("aa:app", [{ name: "ok", wasm: withMax }]), "the budget is configurable per host");

  // The bind is all-or-none (§3.1): a bundle whose SECOND module is malformed leaves the
  // table exactly as it was. The host's guarantee, so a caller does nothing to earn it.
  const atomic = new ModuleTable();
  await rejects(atomic.bindAll("aa:app", [
    { name: "first", wasm: withMax },
    { name: "second", wasm: noMax },
  ]), "a bundle with one bad module is refused whole");
  ok(!atomic.isBound("aa:app", "first"), "the good module of a refused bundle did not land");
  ok(!atomic.isBound("aa:app", "second"), "neither did the bad one");
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
  ok(verify({ app: "x", version: 1, modules: [], guest: { hash: "aa", abi: GUEST_ABI_VERSION, requires: [] } }) !== null,
    "a guest may declare no modules at all — zero-to-many, no count rule");
  ok(verify({ app: "x", version: 1, modules: [{ name: "a", hash: "aa" }, { name: "b", hash: "bb" }], guest: { hash: "aa", abi: GUEST_ABI_VERSION, requires: [] } }) !== null,
    "a guest may declare many modules — the guest dispatches them");
}

console.log("\n§12.2 — the capability gates cannot be reached by omission");
{
  const identity = sodium.crypto_sign_keypair();
  const base = {
    platform: { sodium, identity, peers: () => [] },
    grants: { transport: { request: async () => new Uint8Array() }, fs: new MemoryFs() },
    modules: { call: () => null, has: () => false },
  };
  throws(() => createGuestSeam({ ...base }), "omitting grants.names throws at construction");
  ok(typeof createGuestSeam({ ...base, grants: { ...base.grants, names: UNRESTRICTED_NAMES } }) === "function",
    "naming the sentinel is accepted");

  // A guest reaches its own app's modules with NO grant: a bare name is the asking
  // bundle's own code, scoped by the app key the seam was wired with, so it resolves under
  // an empty requires set exactly like `crypto`.
  const chat = new ModuleTable();
  await chat.bindAll("aa:chat", [{ name: "codec", wasm: withMax }]);
  await chat.bindAll("bb:other", [{ name: "evil", wasm: withMax }]);
  const scoped = createGuestSeam({
    ...base,
    grants: { ...base.grants, names: [] },
    modules: {
      call: (n, p, deadlineMs) => chat.callModule("aa:chat", n, p, deadlineMs),
      has: (n) => chat.isBound("aa:chat", n),
    },
  });
  // The forwarder echoes its input, so a resolved module answers with the body. A module
  // call is async since ABI 6 (it round-trips through the module's worker).
  ok((await scoped("codec", new Uint8Array([7, 7, 7]))).length === 3, "a module of this app resolves and runs");
  throws(() => scoped("evil", new Uint8Array([7, 7, 7])),
    "another app's module name reaches nothing through this seam");
}

console.log("\n§4.3 — the guest realm has an execution budget");
{

  const enc = new TextEncoder();
  const noop = () => new Uint8Array();

  // A holder that loops forever is interrupted rather than wedging the host thread.
  const spinner = await createSafeRealm({
    source: 'register("handle", () => { for(;;){} });',
    hostCall: noop, deadlineMs: 300,
  });
  const t0 = Date.now();
  let interrupted = false;
  try { await spinner.call("handle", new Uint8Array()); } catch { interrupted = true; }
  const spent = Date.now() - t0;
  ok(interrupted, "an infinite loop in a holder entrypoint is interrupted");
  ok(spent < 3000, `it is interrupted near its budget, not eventually (${spent}ms)`);
  spinner.dispose();

  // The budget is guest RUN time: parking on a slow seam does not spend it, so an
  // initiator legitimately awaiting the network outlives a budget far shorter than the
  // wait — the case a wall-clock deadline would kill.
  const slowSeam = (name) => name === "slow"
    ? new Promise((r) => setTimeout(() => r(new Uint8Array([1])), 400))
    : new Uint8Array();
  const waiter = await createSafeRealm({
    source: 'register("go", async () => { await host.call("slow", new Uint8Array()); return new Uint8Array([9]); });',
    hostCall: slowSeam, deadlineMs: 200,
  });
  const out = await waiter.call("go", new Uint8Array());
  ok(out.length === 1 && out[0] === 9, "an initiator parked 400ms on a 200ms budget still completes");
  waiter.dispose();

  // Invocations are serialized per realm: a holder invoked while an initiator is parked
  // waits for it rather than interleaving, and then runs on a budget of its own rather
  // than on what the initiator left (§12.3).
  const order = [];
  const both = await createSafeRealm({
    source: 'register("go", async () => { await host.call("slow", new Uint8Array()); return new Uint8Array([1]); });'
          + 'register("handle", () => new Uint8Array([2]));',
    hostCall: slowSeam, deadlineMs: 200,
  });
  const parked = both.call("go", new Uint8Array()).then((r) => { order.push("initiator"); return r; });
  const holder = both.call("handle", new Uint8Array()).then((r) => { order.push("holder"); return r; });
  ok((await holder)[0] === 2, "a holder queued behind a parked initiator still runs");
  ok((await parked)[0] === 1, "and the initiator completes on its own budget");
  ok(order[0] === "initiator" && order[1] === "holder",
    `the queue runs them in acceptance order, never interleaved (got ${order.join(",")})`);
  both.dispose();

  // The queue does not strand callers on dispose: one still in it fails rather than
  // entering a torn-down realm, which is what aborts the whole wasm module.
  const closing = await createSafeRealm({
    source: 'register("go", async () => { await host.call("slow", new Uint8Array()); return new Uint8Array([1]); });',
    hostCall: slowSeam, deadlineMs: 5000,
  });
  const first = closing.call("go", new Uint8Array()).catch(() => "failed");
  const queued = closing.call("go", new Uint8Array()).catch(() => "failed");
  closing.dispose();
  ok(await first === "failed", "a parked call is failed by dispose rather than left pending");
  ok(await queued === "failed", "and so is one still waiting in the queue");

  // The default is a real number, so forgetting the field bounds the guest rather than
  // unbounding it — the same posture as the seam gates above.
  const defaulted = await createSafeRealm({ source: 'register("handle", () => { for(;;){} });', hostCall: noop });
  let defaultInterrupted = false;
  const t1 = Date.now();
  try { await defaulted.call("handle", new Uint8Array()); } catch { defaultInterrupted = true; }
  ok(defaultInterrupted, "with no deadlineMs configured the 5s default still interrupts");
  ok(Date.now() - t1 >= 4000, "the default budget is the documented 5s, not something tighter");
  defaulted.dispose();
}

console.log("\n§12.3 — the bounds a target sets actually reach the realm");
{
  // A bound can be declared on every interface between the operator and the realm and
  // passed by none of them, so this drives createShell with a stub realm factory and
  // asserts the numbers arrive.
  const kp = testAuthor();
  const guestSrc = 'register("handle", () => new Uint8Array([1]));';
  const guestBytes = new TextEncoder().encode(guestSrc);
  const manifest = {
    app: "probe", version: 1, modules: [],
    guest: { hash: toHex(genesisHash(sodium, guestBytes)), abi: GUEST_ABI_VERSION, requires: [] },
  };
  const blob = packBundle({
    [MANIFEST_FILE]: signManifest(sodium, kp, manifest),
    [GUEST_FILE]: guestBytes,
  });

  let seen = null;
  const shell = createShell({
    platform: {
      sodium, identity: kp.ed, table: new ModuleTable(), fs: new MemoryFs(),
      freshnessStore: new FreshnessMarks(),
      createRealm: async (o) => {
        seen = o;
        return { call: async () => new Uint8Array(), dispose() {} };
      },
    },
    admit: admitAll,
    guestDeadlineMs: 1234,
    realmMemoryBytes: 7 * 1024 * 1024,
  });
  await shell.loadBundleBlob(blob);
  await shell.invoke("probe", new Uint8Array());
  ok(seen !== null, "the shell created a realm for the loaded guest");
  ok(seen && seen.deadlineMs === 1234, `guestDeadlineMs reaches the realm factory (got ${seen && seen.deadlineMs})`);
  ok(seen && seen.memoryLimitBytes === 7 * 1024 * 1024, "realmMemoryBytes reaches the realm factory");

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
  const bare = createShell({
    platform: {
      sodium, identity: kp.ed, table: new ModuleTable(), fs: new MemoryFs(),
      freshnessStore: new FreshnessMarks(),
      createRealm: async (o) => {
        seen2 = o;
        return { call: async () => new Uint8Array(), dispose() {} };
      },
    },
    admit: admitAll,
  });
  await bare.loadBundleBlob(blob);
  await bare.invoke("probe", new Uint8Array());
  ok(seen2 && seen2.deadlineMs === 5000, "an unset budget arrives as the shared default (5000 ms)");
  ok(seen2 && seen2.memoryLimitBytes === 64 * 1024 * 1024, "an unset heap cap arrives as the shared default (64 MiB)");
  bare.close();
}

console.log("\n§12.2 — timers are an ordinary authority, wired per realm");
{
  // The catalog calls `timer/*` an app authority (core/domains.ts), so what is under test
  // is that an ORDINARY app gets one: no transport bundle is loaded anywhere below. Wiring
  // it off the transport driver would admit such an app and then fail it at its first
  // `host.call` — a manifest the loader accepted naming a backend nothing wired.
  const kp = testAuthor();
  const guestSrc = `
    let fired = [];
    const u32x2 = (a, b) => new Uint8Array([a >>> 24, a >>> 16, a >>> 8, a, b >>> 24, b >>> 16, b >>> 8, b]);
    // handle reads [caller 32][opLen u8][op][args] through the preamble's callerOf/readOp;
    // the ops are this app's own vocabulary. timer is the deadline callback, reached by
    // the shell rather than by invoke.
    register("handle", (arg) => {
      const { op, args: p } = readOp(callerOf(arg).body);
      if (op === "arm") { host.call("timer/arm", u32x2(p[0], p[1])); return new Uint8Array(0); }
      if (op === "clear") { host.call("timer/clear", u32x2(p[0], 0).slice(0, 4)); return new Uint8Array(0); }
      if (op === "fired") return new Uint8Array(fired);
      return new Uint8Array(0);
    });
    register("timer", (a) => { fired.push(a[3]); return new Uint8Array(0); });
  `;
  const guestBytes = new TextEncoder().encode(guestSrc);
  const mkBlob = (requires) => {
    const manifest = {
      app: "ticker", version: 1, modules: [],
      guest: { hash: toHex(genesisHash(sodium, guestBytes)), abi: GUEST_ABI_VERSION, requires },
    };
    return packBundle({
      [MANIFEST_FILE]: signManifest(sodium, kp, manifest),
      [GUEST_FILE]: guestBytes,
    });
  };
  const newShell = () => createShell({
    platform: {
      sodium, identity: kp.ed, table: new ModuleTable(),
      freshnessStore: new FreshnessMarks(), createRealm: createSafeRealm,
    },
    admit: admitAll,
  });

  const shell = newShell();
  await shell.loadBundleBlob(mkBlob(["timer/arm", "timer/clear"]));
  await shell.invoke("arm", new Uint8Array([7, 5]));    // arm: id 7, in 5ms
  await sleep(80);
  const fired = await shell.invoke("fired", new Uint8Array());
  ok(fired.length === 1 && fired[0] === 7,
    `an app with no transport arms a deadline and its timer entrypoint fires (got [${[...fired]}])`);

  // Re-arming a live id replaces the deadline rather than adding one, and `clear` takes
  // it back: the id is the GUEST's throughout, so the host keeps no second name for it.
  await shell.invoke("arm", new Uint8Array([9, 5]));
  await shell.invoke("arm", new Uint8Array([9, 5]));
  await shell.invoke("clear", new Uint8Array([9]));
  await sleep(80);
  const after = await shell.invoke("fired", new Uint8Array());
  ok(after.length === 1, `a cleared id does not fire, and two arms of it are one deadline (got [${[...after]}])`);
  shell.close();

  // The gate is still the manifest: a bundle that did not declare `timer/arm` is refused
  // by NAME at the seam, not handed a table because the shell has one to give.
  const ungated = newShell();
  await ungated.loadBundleBlob(mkBlob([]));
  let refused = false;
  try { await ungated.invoke("arm", new Uint8Array([1, 1])); } catch { refused = true; }
  ok(refused, "an undeclared timer/arm is refused at the seam, wired backend or not");
  ungated.close();

  // Uninstall CANCELS: a pending setTimeout holds a callback that re-enters the realm, so
  // one outliving its realm is a call into a freed QuickJS context (§2.1) rather than an
  // error. Through a stub realm, since what must be observed is the entrypoint NOT being
  // invoked — which a real realm would report only by crashing, or not at all.
  let armed = null;
  const entries = [];
  const stub = createShell({
    platform: {
      sodium, identity: kp.ed, table: new ModuleTable(),
      freshnessStore: new FreshnessMarks(),
      createRealm: async (o) => { armed = o.hostCall; return { call: async (n) => { entries.push(n); return new Uint8Array(); }, dispose() {} }; },
    },
    admit: admitAll,
  });
  await stub.loadBundleBlob(mkBlob(["timer/arm", "timer/clear"]));
  await stub.invoke("arm", new Uint8Array([0, 0]));
  // Arm through the very seam the realm was handed, then drop the app underneath it.
  await armed("timer/arm", new Uint8Array([0, 0, 0, 1, 0, 0, 0, 5]));
  ok(stub.uninstall(appKeyFor(kp.id, "ticker")) === true, "the app uninstalls with a deadline still pending");
  await sleep(80);
  ok(!entries.includes("timer"), `uninstalling an app cancels its pending deadlines (entries: ${entries.join(", ")})`);
  stub.close();
}

summary("hardening checks");
