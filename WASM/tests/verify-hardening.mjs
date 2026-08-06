// Focused checks for the four hardening changes. Standalone rather than folded into
// run.mjs only because run.mjs currently dies at its second test on a clean install
// (its own sodium handle is used before `ready` resolves) — see the note in the review.
//
// Run: node tests/verify-hardening.mjs   (after `npm run build`)

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import _sodium from "libsodium-wrappers-sumo";
import { testkit } from "./testkit.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

await _sodium.ready;
const sodium = _sodium;

const { KernelHost } = await imp("build/host/kernel-host.js");
const { readMemoryLimits, checkHandlerMemory } = await imp("build/core/wasm-limits.js");
const { MemoryFs } = await imp("build/host/fs-memory.js");
const { appKeyFor, appScopeFor, genesisHash, signManifest, verifyManifest, packBundle, MANIFEST_FILE, GUEST_FILE, FreshnessMarks }
  = await imp("build/host/bundle.js");
const { createShell, scopedFs } = await imp("build/host/shell-core.js");
const { toHex } = await imp("build/core/util.js");
const { admitAll } = await imp("build/host/policy.js");
const { createCapBridge, UNRESTRICTED_CAPS, GUEST_ABI_VERSION } = await imp("build/host/cap-bridge.js");

const { ok, throws, summary } = testkit();

const withMax = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
const noMax = new Uint8Array(readFileSync(join(root, "build/forwarder-nomax.wasm")));

console.log("\n§4.3 — declared memory is bounded before instantiation");
{
  const a = readMemoryLimits(withMax);
  const b = readMemoryLimits(noMax);
  ok(a.maxPages === 256, `built handler declares a 256-page maximum (got ${a.maxPages})`);
  ok(b.maxPages === null, "the no-maximum build declares none");
  ok(checkHandlerMemory(withMax, 64 * 1024 * 1024) !== null, "a bounded handler passes the budget");
  throws(() => checkHandlerMemory(noMax, 64 * 1024 * 1024), "a handler with no declared maximum is refused");
  throws(() => checkHandlerMemory(withMax, 1024 * 1024), "a handler above the host budget is refused");
  throws(() => checkHandlerMemory(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), 1 << 20), "a non-wasm blob is refused");

  const host = new KernelHost();
  host.bindAll("aa:app", [{ name: "ok", wasm: withMax }]);
  ok(host.isBound("aa:app", "ok"), "KernelHost binds a bounded handler");
  throws(() => host.bindAll("aa:app", [{ name: "bad", wasm: noMax }]),
    "KernelHost refuses an unbounded handler at install");
  const tiny = new KernelHost({ maxHandlerMemoryBytes: 1024 * 1024 });
  throws(() => tiny.bindAll("aa:app", [{ name: "ok", wasm: withMax }]), "the budget is configurable per host");

  // The bind is all-or-none (§3.1): a bundle whose SECOND module is malformed leaves the
  // table exactly as it was, rather than with its first module landed. Atomicity is the
  // host's guarantee, so it holds without the caller doing anything to earn it.
  const atomic = new KernelHost();
  throws(() => atomic.bindAll("aa:app", [
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
  const kp = sodium.crypto_sign_keypair();
  const verify = (m) => verifyManifest(sodium, signManifest(sodium, kp.privateKey, kp.publicKey, m));
  // Refused BY NAME, like an unimplemented ABI or an unknown cap domain: this is the
  // manifest a bundle written against the retired handler-only format produces, so its
  // author has to learn the rule, not read "malformed manifest".
  const refusal = (m) => { try { verify(m); return ""; } catch (e) { return e.message; } };
  const none = refusal({ app: "x", version: 1, modules: [] });
  ok(none.includes("every app is a guest"), `a manifest without a guest is refused by name (got: ${none})`);
  ok(verify({ app: "x", version: 1, modules: [], guest: { hash: "aa", abi: GUEST_ABI_VERSION, caps: [] } }) !== null,
    "a guest may declare no modules at all — zero-to-many, no count rule");
  ok(verify({ app: "x", version: 1, modules: [{ name: "a", hash: "aa" }, { name: "b", hash: "bb" }], guest: { hash: "aa", abi: GUEST_ABI_VERSION, caps: [] } }) !== null,
    "a guest may declare many modules — the guest dispatches them");
}

console.log("\n§12.2 — the capability gates cannot be reached by omission");
{
  const identity = sodium.crypto_sign_keypair();
  const base = {
    sodium, identity, callModule: () => null,
    transport: { request: async () => new Uint8Array() },
    peers: () => [], fs: new MemoryFs(),
  };
  throws(() => createCapBridge({ ...base }), "omitting allowedCaps throws at construction");
  ok(typeof createCapBridge({ ...base, allowedCaps: UNRESTRICTED_CAPS }) === "function",
    "naming the sentinel is accepted");

  // A guest reaches its own app's modules and has no way to name anything else: the
  // bridge is built against ONE app's module map (the shell binds the app key), so
  // scoping is the shape rather than a lookup table that could be omitted.
  const chat = new KernelHost();
  chat.bindAll("aa:chat", [{ name: "codec", wasm: withMax }]);
  chat.bindAll("bb:other", [{ name: "evil", wasm: withMax }]);
  const scoped = createCapBridge({
    ...base,
    callModule: (n, p) => chat.callModule("aa:chat", n, p),
    allowedCaps: ["module"],
  });
  // The forwarder echoes its input, so a resolved module answers with the body and an
  // unresolved one answers empty — which is what tells the two apart.
  const call = (name) => {
    const n = new TextEncoder().encode(name);
    return scoped("module/call", new Uint8Array([n.length, ...n, 7, 7, 7]));
  };
  ok(call("codec").length === 3, "a module of this app resolves and runs");
  ok(call("evil").length === 0, "another app's module name reaches nothing through this bridge");
}

console.log("\n§4.3 — the guest realm has an execution budget");
{
  const { createSafeRealm } = await imp("build/host/safe-js.js");
  const enc = new TextEncoder();
  const noop = () => new Uint8Array();

  // A holder that loops forever is interrupted rather than wedging the host thread.
  const spinner = await createSafeRealm({
    source: 'register("handle", () => { for(;;){} });',
    bridge: noop, deadlineMs: 300,
  });
  const t0 = Date.now();
  let interrupted = false;
  try { await spinner.call("handle", new Uint8Array()); } catch { interrupted = true; }
  const spent = Date.now() - t0;
  ok(interrupted, "an infinite loop in a holder entrypoint is interrupted");
  ok(spent < 3000, `it is interrupted near its budget, not eventually (${spent}ms)`);
  spinner.dispose();

  // The budget is guest RUN time: parking on a slow bridge does not spend it, so an
  // initiator legitimately awaiting the network outlives a budget far shorter than
  // the wait. This is the case a wall-clock deadline would have killed.
  const slowBridge = (name) => name === "slow"
    ? new Promise((r) => setTimeout(() => r(new Uint8Array([1])), 400))
    : new Uint8Array();
  const waiter = await createSafeRealm({
    source: 'register("go", async () => { await host.call("slow", new Uint8Array()); return new Uint8Array([9]); });',
    bridge: slowBridge, deadlineMs: 200,
  });
  const out = await waiter.call("go", new Uint8Array());
  ok(out.length === 1 && out[0] === 9, "an initiator parked 400ms on a 200ms budget still completes");
  waiter.dispose();

  // Invocations are serialized per realm: a holder invoked while an initiator is parked
  // waits for it rather than interleaving with it, and then runs on a budget of its own
  // rather than on what the initiator left. This is the guarantee the old re-entrant
  // callSync got from the host's call stack, now that every role can yield (§12.3).
  const order = [];
  const both = await createSafeRealm({
    source: 'register("go", async () => { await host.call("slow", new Uint8Array()); return new Uint8Array([1]); });'
          + 'register("handle", () => new Uint8Array([2]));',
    bridge: slowBridge, deadlineMs: 200,
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
    bridge: slowBridge, deadlineMs: 5000,
  });
  const first = closing.call("go", new Uint8Array()).catch(() => "failed");
  const queued = closing.call("go", new Uint8Array()).catch(() => "failed");
  closing.dispose();
  ok(await first === "failed", "a parked call is failed by dispose rather than left pending");
  ok(await queued === "failed", "and so is one still waiting in the queue");

  // Default is a real number, so forgetting the field bounds the guest rather than
  // unbounding it — the same posture as the cap gates above.
  const defaulted = await createSafeRealm({ source: 'register("handle", () => { for(;;){} });', bridge: noop });
  let defaultInterrupted = false;
  const t1 = Date.now();
  try { await defaulted.call("handle", new Uint8Array()); } catch { defaultInterrupted = true; }
  ok(defaultInterrupted, "with no deadlineMs configured the 5s default still interrupts");
  ok(Date.now() - t1 >= 4000, "the default budget is the documented 5s, not something tighter");
  defaulted.dispose();
}

console.log("\n§12.3 — the bounds a target sets actually reach the realm");
{
  // The regression that let safe-js's deadlineMs rot: a bound declared on every
  // interface between the operator and the realm, and passed by none of them. This
  // drives createShell with a stub realm factory and asserts the numbers arrive.
  const kp = sodium.crypto_sign_keypair();
  const guestSrc = 'register("handle", () => new Uint8Array([1]));';
  const guestBytes = new TextEncoder().encode(guestSrc);
  const manifest = {
    app: "probe", version: 1, modules: [],
    guest: { hash: toHex(genesisHash(sodium, guestBytes)), abi: GUEST_ABI_VERSION, caps: [] },
  };
  const blob = packBundle({
    [MANIFEST_FILE]: signManifest(sodium, kp.privateKey, kp.publicKey, manifest),
    [GUEST_FILE]: guestBytes,
  });

  let seen = null;
  const shell = createShell({
    platform: {
      sodium, identity: kp, kernel: new KernelHost(), fs: new MemoryFs(),
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
  await shell.runGuest("handle", new Uint8Array());
  ok(seen !== null, "the shell created a realm for the loaded guest");
  ok(seen && seen.deadlineMs === 1234, `guestDeadlineMs reaches the realm factory (got ${seen && seen.deadlineMs})`);
  ok(seen && seen.memoryLimitBytes === 7 * 1024 * 1024, "realmMemoryBytes reaches the realm factory");

  // §12.5 — uninstalling a GUEST-ONLY app reports success. An app is its modules and
  // its realm, and this bundle legitimately declares no modules at all, so a count of
  // dropped modules is the wrong answer to "was there anything here".
  ok(shell.uninstall(appKeyFor(kp.publicKey, "probe")) === true,
    "uninstalling a guest-only app reports success, not 'nothing there'");
  ok(shell.uninstall(appKeyFor(kp.publicKey, "probe")) === false,
    "uninstalling it twice reports nothing the second time");
  shell.close();

  // Omitted ⇒ the SHARED defaults arrive at the seam (core/wasm-limits.ts) — not
  // undefined, and not "unbounded". The shell resolves them so a factory never has
  // to own the numbers (safe-js and the native realm once carried their own copies).
  let seen2 = null;
  const bare = createShell({
    platform: {
      sodium, identity: kp, kernel: new KernelHost(), fs: new MemoryFs(),
      freshnessStore: new FreshnessMarks(),
      createRealm: async (o) => {
        seen2 = o;
        return { call: async () => new Uint8Array(), dispose() {} };
      },
    },
    admit: admitAll,
  });
  await bare.loadBundleBlob(blob);
  await bare.runGuest("handle", new Uint8Array());
  ok(seen2 && seen2.deadlineMs === 5000, "an unset budget arrives as the shared default (5000 ms)");
  ok(seen2 && seen2.memoryLimitBytes === 64 * 1024 * 1024, "an unset heap cap arrives as the shared default (64 MiB)");
  bare.close();
}

summary("hardening checks");
