// Focused checks for the hardening changes (§4.3 memory bounds, §12.2 scoping and seam
// gates, §12.3 realm budgets, §12.4 guest-only apps). Standalone because each block is a
// tight loop over one seam; run.mjs covers the same ground end-to-end. Run after `npm run build`.

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
const { appKeyFor, appScopeFor, genesisHash, signManifest, verifyManifest, packBundle, loadBundleModules, MANIFEST_FILE, GUEST_FILE, FreshnessMarks }
  = await imp("build/host/bundle.js");
// ML-DSA-65 onto this instance, exactly as a target does at its crypto seam: a manifest
// is signed and verified with both halves of the author's key set (§12.4), so a bare
// libsodium cannot sign one.
const { withMlDsa65, loadMlDsa65 } = await imp("build/host/pq.js");
withMlDsa65(sodium, await loadMlDsa65(readFileSync(join(root, "browser/mldsa65.wasm"))));
/** A manifest author: both halves of the key set, plus the 32-byte id they derive — the
 *  identity policy pins and app keys lead with. `ed` doubles as a node identity. */
const testAuthor = () => makeAuthor(sodium);
const { bootShell, scopedFs } = await imp("build/host/shell-core.js");
const { toHex } = await imp("build/core/util.js");
const { admitAll } = await imp("build/host/policy.js");
const { createGuestSeam, UNRESTRICTED_NAMES } = await imp("build/host/guest-seam.js");
const { GUEST_ABI_VERSION } = await imp("build/core/domains.js");
const { callerOf, readOp, writeOp, guestOpFraming } = await imp("build/core/op-frame.js");
const { createSafeRealm } = await imp("build/host/safe-js.js");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const { ok, throws, summary } = testkit();
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
    modules: { names: new Set(), call: () => null },
  };
  throws(() => createGuestSeam({ ...base }), "omitting grants.names throws at construction");
  ok(typeof createGuestSeam({ ...base, grants: { ...base.grants, names: UNRESTRICTED_NAMES } }) === "function",
    "naming the sentinel is accepted");

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
  // The forwarder echoes its input, so a resolved module answers with the body. A module
  // call is async since ABI 6 (it round-trips through the module's worker).
  ok((await scoped("codec", new Uint8Array([7, 7, 7]))).length === 3, "a module of this app resolves and runs");
  throws(() => scoped("evil", new Uint8Array([7, 7, 7])),
    "another app's module name reaches nothing through this seam");
  chatModules.dispose(); otherModules.dispose();
}

console.log("\n§4.3 — the guest realm has an execution budget");
{

  const enc = new TextEncoder();
  const noop = () => new Uint8Array();

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

  // The budget is guest RUN time: parking on a slow seam does not spend it, so an
  // initiator legitimately awaiting the network outlives a budget far shorter than the
  // wait — the case a wall-clock deadline would kill.
  const slowSeam = (name) => name === "slow"
    ? new Promise((r) => setTimeout(() => r(new Uint8Array([1])), 400))
    : new Uint8Array();
  const waiter = await createSafeRealm({
    source: 'async function handle() { await host.call("slow", new Uint8Array()); return new Uint8Array([9]); }',
    hostCall: slowSeam, deadlineMs: 200,
  });
  const out = await waiter.call(new Uint8Array());
  ok(out.length === 1 && out[0] === 9, "an initiator parked 400ms on a 200ms budget still completes");
  waiter.dispose();

  // Invocations are serialized per realm: a holder invoked while an initiator is parked
  // waits for it rather than interleaving, and then runs on a budget of its own rather
  // than on what the initiator left (§12.3).
  const order = [];
  const both = await createSafeRealm({
    source: 'async function handle(a) { if (a[0] === 1) { await host.call("slow", new Uint8Array()); return new Uint8Array([1]); } return new Uint8Array([2]); }',
    hostCall: slowSeam, deadlineMs: 200,
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
      hash: toHex(genesisHash(sodium, guestBytes)), abi: GUEST_ABI_VERSION, requires: [],
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

  // APP and LOCAL are two provenance-preserving values, not one host-side merge. Evaluate
  // only the two generated preamble lines (the guest body is self-contained).
  const valuesFrom = (source) => Function(
    source.split("\n").slice(0, 2).join("\n") + "\nreturn [APP, LOCAL];",
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
  bare.close();
}

console.log("\n§12.6 — the host's pre-open send queue is bounded");
{
  const { MessageChannel } = await imp("build/host/net-channel.js");
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
  let died = false;
  ch.onClose(() => { died = true; });
  const frame = new Uint8Array(64 * 1024);
  for (let i = 0; i < 16; i++) ch.send(frame); // 1 MiB exactly — the last byte still inside
  ok(!died && sent.length === 0, "a channel that has not opened buffers rather than writes");
  ok(ch.buffered() === 1024 * 1024, `the queue reports its own bytes (got ${ch.buffered()})`);
  ch.send(frame); // …and the frame that crosses it
  // Failed, not silently trimmed: dropping a frame off an ordered stream leaves the far end
  // waiting on a gap forever, where a dead channel is one the occupant is told about.
  ok(died && closed, "crossing the ceiling fails the channel instead of growing the queue");
  ok(ch.buffered() === 0, "a failed channel releases its queue rather than holding it to be collected");
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
    // op framing ([opLen u8][op][args]) — composed here with the kernel's own spelling
    // of that convention (core/op-frame.ts, content). A fired deadline re-enters this
    // realm as an ORDINARY host loopback naming the "timer" op, body a bare [id u32] —
    // the host writes the same zero caller id either way, so what says "this is a
    // deadline" is the op name this app reads, never a second caller identity.
${guestOpFraming()}
    function handle(arg) {
      const { body } = callerOf(arg);
      const { op, args: p } = readOp(body);
      if (op === "timer") { fired.push((p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]) >>> 0); return new Uint8Array(0); }
      if (op === "arm") { host.call("timer/arm", u32x2(p[0], p[1])); return new Uint8Array(0); }
      if (op === "clear") { host.call("timer/clear", u32x2(p[0], 0).slice(0, 4)); return new Uint8Array(0); }
      if (op === "fired") return new Uint8Array(fired);
      return new Uint8Array(0);
    }
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
  await armed("timer/arm", new Uint8Array([0, 0, 0, 1, 0, 0, 0, 5]));
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

  // The kernel's own spelling, shipped to apps as content (core/op-frame.ts).
  ok(callerOf(withCaller(new Uint8Array(32))).fromHost, "32 zero bytes read as the host proper");
  // A near-miss on the host id is not the host: one late bit is all it takes.
  const nearHost = new Uint8Array(32); nearHost[31] = 1;
  ok(!callerOf(withCaller(nearHost)).fromHost, "an app key that is zero but for its last byte is not the host");
  const leadingZero = new Uint8Array(32); leadingZero[31] = 0xff; // zero everywhere but the LAST byte
  ok(!callerOf(withCaller(leadingZero)).fromHost,
    "an app key that is zero everywhere but its last byte is not the host — the match is not a leading-zero-run shortcut");

  // The transport bundle carries its OWN copy of this reader (transport/src/util.js) —
  // content paired with its driver, so the fix has to hold there too. Evaluated out of
  // the signed source rather than restated, so the two cannot drift apart silently.
  const utilSrc = readFileSync(join(root, "transport", "src", "util.js"), "utf8");
  const m = /function callerOf\(arg\) \{[\s\S]*?\n\}/.exec(utilSrc);
  ok(m !== null, "the transport bundle's own callerOf is where this test expects it");
  const transportCallerOf = new Function(`${m[0]}; return callerOf;`)();
  ok(transportCallerOf(withCaller(new Uint8Array(32))).fromHost, "the transport reads 32 zero bytes as the host proper");
  ok(!transportCallerOf(withCaller(nearHost)).fromHost, "…and refuses a near-miss as the host proper");
}

summary("hardening checks");
