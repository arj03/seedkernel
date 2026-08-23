// End-to-end test: bootstrap -> signed message -> module dispatch.
//
// Run: node tests/run.mjs

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);
import { testkit, makeAuthor } from "./testkit.mjs";

const {
  generateKeyPair,
  loadCrypto,
} = await imp("build/host/crypto-node.js");
const { ModuleTable: JsModuleLoader } = await imp("build/host/module-table.js");
const { bootShell } = await imp("build/host/shell-core.js");
const { bootRuntime } = await imp("build/host/main.js");
const { TransportHost } = await imp("build/host/transport-host.js");

// The host's already-readied instance rather than our own copy:
// libsodium-wrappers-sumo declares separate "import" and "require" conditions pointing at
// different builds, so a require() here returns a SECOND instance with its own wasm heap
// that nothing awaits .ready on. One shared instance is the rule (§12.1).
const sodium = await loadCrypto();

// One contact secret for the whole harness. In production each node has its own and
// hands it out with its address; one value here just means every test node is reachable
// by every other.
const TEST_CONTACT = new Uint8Array(32).fill(3);
const { createGuestSeam, guestSignScope, appSignScope, UNRESTRICTED_NAMES }
  = await imp("build/host/guest-seam.js");
const { GUEST_ABI_VERSION } = await imp("build/core/domains.js");
const { readOp } = await imp("build/core/op-frame.js");
const { MemoryFs } = await imp("build/host/fs-memory.js");
const enc = new TextEncoder();
const _testProto = enc.encode("_test");
const { NodeFs } = await imp("build/host/fs-node.js");
const { createSafeRealm } = await imp("build/host/safe-js.js");
const { toHex, fromHex, concatBytes, writeU32BE } = await imp("build/core/util.js");
import { bytesEqual } from "./bytes.mjs";
// The loader's admission step and name derivation (§5.1, §12.4) — tests drive the SAME
// code path a bundle load does rather than a parallel copy of it.
const { appKeyFor, genesisHash: bundleGenesisHash, hybridAuthorId, FreshnessMarks,
         signManifest, verifyManifest, verifyBundle, loadBundleModules, packBundle, moduleFile, MANIFEST_FILE, GUEST_FILE }
  = await imp("build/host/bundle.js");
const { policyFromJson, authorAllowlist, hostGates } = await imp("build/host/policy.js");
const { withMlDsa65, loadMlDsa65, ML_DSA65_PK_LEN, ML_DSA65_SIG_LEN } = await imp("build/host/pq.js");
const { withMlKem768, loadMlKem768 } = await imp("build/host/kem.js");
const gHash = (b) => bundleGenesisHash(sodium, b);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Every app is a guest (§12.4), so every bundle a test builds declares one. The stub
// used by tests that do not exercise the guest is the same minimal program throughout.
const GUEST_TEXT = "function handle() { return new Uint8Array([1]); }";
const GUEST_BYTES = new TextEncoder().encode(GUEST_TEXT);
const GUEST = (extra = {}) => ({ hash: toHex(gHash(GUEST_BYTES)), abi: GUEST_ABI_VERSION, requires: [], ...extra });

/** A manifest author (§12.4): the Ed25519 half, the ML-DSA-65 half, and the 32-byte id the
 *  two derive. Tests name `a.id` wherever the runtime names an author (policy pins, app
 *  keys, freshness marks) and hand the whole object to `signManifest`, so none can pin
 *  half an identity. */
const testAuthor = () => makeAuthor(sodium);

/** A NODE-platform node for one test: `bootRuntime` (main.ts) minus the channel
 *  adapter, which these tests do not drive. The disk-backed platform — NodeFs on a data
 *  directory, a file-backed freshness store — is the point of reaching for it over
 *  {@link bootTestShell}, which stands a node with no disk. */
const boot = async (cfg) => (await bootRuntime(cfg)).shell;

/** A node for ONE test, through the one assembly (`bootShell`, §12.9). The platform
 *  members are stated flat, as the assembly takes them; `fs` defaults to `false` — most
 *  bundles here declare no `fs` cap, and handing them the in-memory backend would be a
 *  seam open the test never asked for.
 *
 *  `pinAuthor` is whose signature the TRANSPORT PIN admits (§12.5). The pin is derived
 *  from a blob, and with no blob it is fail-closed — every bundle reaching `link` is
 *  refused before any predicate under test is consulted. What is handed over is a real
 *  signed bundle of that author's, because the pin is read off a signature rather than
 *  off a name; the socket-less driver beside it is the browser-edge shape (§12.6). */
async function bootTestShell({ pinAuthor, ...opts } = {}) {
  const identity = opts.identity ?? generateKeyPair();
  const pinned = pinAuthor ? {
    transport: new TransportHost({ identity }),
    transportBundle: packBundle({
      [MANIFEST_FILE]: signManifest(sodium, pinAuthor,
        { app: "pin", version: 1, modules: [], guest: GUEST() }),
      [GUEST_FILE]: GUEST_BYTES,
    }),
  } : {};
  const { shell } = await bootShell({
    sodium,
    modules: new JsModuleLoader(),
    freshnessStore: new FreshnessMarks(),
    fs: false,
    ...pinned,
    ...opts,
    identity,
  });
  return shell;
}

/** The admission context a bundle with no history lands under: an ordinary app, never
 *  loaded here before, from a key nobody has written off. The shell reads these off its
 *  freshness store; a test composing the load by hand states them. */
const APP_CTX = { privileges: [], highWater: -Infinity, revoked: false };
const LINK_CTX = { ...APP_CTX, privileges: ["link"] };

/** `verifyBundle` → `admit` → `installBundle` (§12.4), for the policy + integrity tests
 *  that own their own ModuleTable without a shell. `admit` is AWAITED — a composed
 *  policy answers with a Promise, and reading one as a verdict is fail-open. */
async function loadBundle(host, blob, admit, ctx = APP_CTX) {
  const v = verifyBundle(sodium, blob);
  if (!(await admit(v, ctx))) throw new Error("admit rejected");
  return installBundle(host, v);
}

// The empty payload — a module whose `handle` takes no meaningful input.
const EMPTY = new Uint8Array(0);

const { ok, summary } = testkit({ verbose: false });
// Report-style: a failed check is logged and counted, and the suite keeps going.
const assert = ok;
const assertEqual = (actual, expected, msg) => {
  const norm = (v) => {
    if (v === null || v === undefined) return String(v);
    if (typeof v === "object") return JSON.stringify([...v]);
    return v;
  };
  const a = norm(actual);
  const e = norm(expected);
  assert(a === e, `${msg}: expected ${e}, got ${a}`);
};

// Standard bootstrap (§3): a fresh module table. The host holds no policy — it is the
// map and nothing else.
class TestModuleHost {
  constructor(loader) { this.loader = loader; this.slots = new Map(); this.names = new Map(); }
  build(mods) { return this.loader.build(mods); }
  adopt(key, modules, names = []) {
    this.slots.get(key)?.dispose();
    this.slots.set(key, modules);
    this.names.set(key, names);
  }
  async bindAll(key, mods) { this.adopt(key, await this.build(mods), mods.map((m) => m.name)); }
  callModule(key, name, payload, deadlineMs) {
    // PureModules.call resolves `{ bytes, ms }`; the direct-call tests want the bytes.
    const p = this.slots.get(key)?.call(name, payload, deadlineMs);
    return p ? p.then((r) => r.bytes) : Promise.resolve(null);
  }
  isBound(key, name) { return this.names.get(key)?.includes(name) ?? false; }
  removeApp(key) {
    const slot = this.slots.get(key);
    if (!slot) return 0;
    const n = this.names.get(key)?.length ?? 0;
    slot.dispose(); this.slots.delete(key); this.names.delete(key); return n;
  }
}
const testHost = (loader) => new TestModuleHost(loader);
const installBundle = async (host, v) => {
  const modules = await loadBundleModules(host, v);
  host.adopt(appKeyFor(v.author, v.manifest.app), modules, v.modules.map(({ mod }) => mod.name));
  return { manifest: v.manifest, author: v.author, authorKeys: v.authorKeys, guestSource: v.guestSource };
};
async function makeHost() {
  return { host: testHost(new JsModuleLoader()) };
}

const { readFileSync } = await import("node:fs");
const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));

// ML-DSA-65 onto the test instance exactly as a target does at its crypto seam — the
// hybrid manifest suite is "a sodium that knows this method" (§12.4).
withMlDsa65(sodium, await loadMlDsa65(readFileSync(join(root, "browser/mldsa65.wasm"))));
// And ML-KEM-768, the catalog primitive the same seam mixes in: a manifest is checked
// against PRIMITIVE_NAMES, so those methods must be on the object handed to the seam.
withMlKem768(sodium, await loadMlKem768(readFileSync(join(root, "browser/mlkem768.wasm"))));

// Install one verified module as the whole of `appKey`'s module set. Async: a bind stands
// each module up in its own worker and returns when it has loaded.
async function installMod(host, appKey, module, wasm) {
  await host.bindAll(appKey, [{ name: module, wasm }]);
}

// The §5.1 app key a bundle's modules land under, `"<author hex>:<app>"` — the real
// derivation, not a mirror, so a test can name a table entry without packing a whole
// bundle and still land where the loader would put it.
const appKey = (authorPk, app) => appKeyFor(authorPk, app);

// ─── Test: install a module, reach it by name ───────────────────────────

async function testFullLifecycle() {
  console.log("Test: install a bundle module and reach it by name (§4, §12.4)");

  const { host } = await makeHost();

  const { id: pk } = testAuthor();
  const chatKey = appKey(pk, "chat");

  // Installed through the same path the bundle loader uses. The forwarder fixture is a
  // pure transform that echoes its input.
  await installMod(host, chatKey, "chat", forwarderBytes);
  assert(host.isBound(chatKey, "chat"), "chat module installed");
  // No install record to consult: the author is IN the app key (§5.1), so the table
  // itself says who authored what it holds.
  assert(chatKey.startsWith(toHex(pk) + ":"), "the app key leads with the author");

  // Reach it by name: the host stages input at the module's scratch, calls handle, and
  // reads the response back (§4). A guest reaches the same module through its seam by
  // the bare name (§12.2); here the host calls it directly.
  const text = new TextEncoder().encode("hello from author");
  const resp = await host.callModule(chatKey, "chat", text);
  assert(resp !== null && bytesEqual(resp, text), "module echoed its input");

  console.log("  OK\n");
}

// ─── Test: installBundle rejects an untrusted author ─────────────────────

async function testInstallRejectsUntrustedAuthor() {
  console.log("Test: installBundle rejects a manifest whose author is not in the policy");

  const author = testAuthor();
  const { host } = await makeHost();

  // A valid manifest signed by an untrusted author — the author is not in the policy.
  const manifest = { app: "demo", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
    guest: GUEST() };
  const manifestEnv = signManifest(sodium, author, manifest);
  const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes, [GUEST_FILE]: GUEST_BYTES });

  // The predicate only trusts a DIFFERENT key.
  const stranger = testAuthor();
  const admit = authorAllowlist([toHex(stranger.id)]);
  let threw = false;
  try { await loadBundle(host, blob, admit); } catch { threw = true; }
  assert(threw, "installBundle throws when the author is not in the policy");

  console.log("  OK\n");
}

async function testManifestHashIsEnforced() {
  console.log("Test: verifyBundle enforces the manifest's module hash (§5.1)");

  const author = testAuthor();
  // A manifest that declares the CORRECT hash — loadBundle should accept it.
  const manifest = { app: "demo", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
    guest: GUEST() };
  const manifestEnv = signManifest(sodium, author, manifest);
  const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes, [GUEST_FILE]: GUEST_BYTES });

  // verifyBundle (now the single verify step) must accept a hash-matched module.
  const v = verifyBundle(sodium, blob);
  assert(bytesEqual(v.author, author.id), "matched hash verifies");

  // A manifest that declares a WRONG hash — verifyBundle must throw.
  const badManifest = { app: "demo", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(new Uint8Array([1, 2, 3]))) }],
    guest: GUEST() };
  const badEnv = signManifest(sodium, author, badManifest);
  const badBlob = packBundle({ [MANIFEST_FILE]: badEnv, [moduleFile("fwd")]: forwarderBytes, [GUEST_FILE]: GUEST_BYTES });
  let threw = false;
  try { verifyBundle(sodium, badBlob); } catch { threw = true; }
  assert(threw, "verifyBundle throws when a module hash does not match the bytes");

  console.log("  OK\n");
}

async function testDenyAllPolicyRejects() {
  console.log("Test: an omitted policy is deny-all, not 'no policy' (§12.5, §14)");

  // `policyFromJson(null)` is the boot default every target shares: a predicate
  // that returns false for every bundle. The absence of a decision is never permission.
  const admit = policyFromJson(null);
  assert(!admit({ author: new Uint8Array(32), manifest: { app: "x", version: 1, modules: [] }, modules: [], guestSource: "" }, APP_CTX),
    "deny-all predicate returns false for any VerifiedBundle");

  const { host } = await makeHost();
  const author = testAuthor();
  const manifest = { app: "demo", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
    guest: GUEST() };
  const manifestEnv = signManifest(sodium, author, manifest);
  const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes, [GUEST_FILE]: GUEST_BYTES });

  let threw = false;
  try { await loadBundle(host, blob, admit); } catch { threw = true; }
  assert(threw, "a deny-all admit predicate prevents install");

  console.log("  OK\n");
}

// ─── Test: a non-instantiable module fails the whole load (§12.4) ───

async function testBundleRefusesNonModule() {
  console.log("Test: a hash-correct file that isn't a valid module fails the whole bundle");

  const author = testAuthor();
  const { host } = await makeHost();

  // Two modules the author genuinely signed: the real forwarder, and arbitrary bytes that
  // hash-match their manifest entry but will not instantiate. With a two-phase install, a
  // module failing phase 1 must fail the whole load — nothing lands.
  const notAModule = new Uint8Array([0, 1, 2, 3, 4]);   // not even valid wasm
  const guestText = "function handle() { return new Uint8Array([1]); }";
  const guestBytes = new TextEncoder().encode(guestText);
  const manifest = { app: "demo", version: 1, modules: [
    { name: "fwd", hash: toHex(gHash(forwarderBytes)) },
    { name: "broken", hash: toHex(gHash(notAModule)) },
  ], guest: { hash: toHex(gHash(guestBytes)), abi: GUEST_ABI_VERSION, requires: [] } };
  const manifestEnv = signManifest(sodium, author, manifest);
  const blob = packBundle({
    [MANIFEST_FILE]: manifestEnv,
    [moduleFile("fwd")]: forwarderBytes,
    [moduleFile("broken")]: notAModule,
    [GUEST_FILE]: guestBytes,
  });

  const admit = authorAllowlist([toHex(author.id)]);
  let threw = false;
  try { await loadBundle(host, blob, admit); } catch { threw = true; }
  assert(threw, "a bundle with a non-instantiable module fails the whole load — nothing lands");
  // Neither module is bound — the install was atomic.
  assert(!host.isBound(appKey(author.id, "demo"), "fwd"), "the valid module is NOT bound (the load failed atomically)");
  assert(!host.isBound(appKey(author.id, "demo"), "broken"), "the non-module is not bound");

  console.log("  OK\n");
}

// ─── Test: ownership is structural (§5.1, §12.5) ────────────────────────

async function testDerivedNamesKeepAuthorsApart() {
  console.log("Test: derived app keys keep two authors' same-named apps apart (§5.1)");

  // No policy can let one author land on another's app, because there is no shared entry
  // to land on: `fwd` under A and `fwd` under B are keys in two different maps rather
  // than two strings something had to keep distinct.
  const { host } = await makeHost();

  const { id: aPk } = testAuthor();
  const { id: bPk } = testAuthor();

  // Both authors ship an app called "shared" with a module called "fwd".
  const aKey = appKey(aPk, "shared");
  const bKey = appKey(bPk, "shared");
  assert(aKey !== bKey, "the same app name under different authors derives distinct keys");
  assert(aKey.startsWith(toHex(aPk) + ":"), "A's key leads with A's key");
  assert(bKey.startsWith(toHex(bPk) + ":"), "B's key leads with B's key");

  // Both install. Neither displaces the other — they coexist.
  await installMod(host, aKey, "fwd", forwarderBytes);
  await installMod(host, bKey, "fwd", forwarderBytes);
  assert(host.isBound(aKey, "fwd"), "A's app is bound");
  assert(host.isBound(bKey, "fwd"), "B's app is bound — it did not have to contend for a name");

  // A re-install by the SAME author lands on the SAME entry: an update, in place, with no
  // ownership rule consulted anywhere.
  await installMod(host, aKey, "fwd", forwarderBytes);
  assert(host.isBound(aKey, "fwd"), "A's re-install still occupies the entry");
  assertEqual(appKey(aPk, "shared"), aKey, "the same key derives the same app key");

  console.log("  OK\n");
}

// ─── Test: the manifest's claim IS the routing (§12.10) ──────────────────────
// The bundle declares the protocol ids it serves and the load claims them: one act, no
// operator step in between. Claims have one active owner: an update replaces its own
// claims atomically, and a different bundle cannot silently displace it.
async function testManifestClaimIsTheRouting() {
  console.log("Test: the manifest's claim IS the routing (§12.10)");
  const { verifyManifest } = await imp("build/host/bundle.js");
  const { admitAll, denyAll, byPrivilege } = await imp("build/host/policy.js");

  const author = testAuthor();
  const other = testAuthor();
  // One bundle shape, parameterised by who signs it, what it is called, which version it
  // is, and what it claims — every case below is a different point in that space.
  const blob = (signer, app, version, protocols) => packBundle({
    [MANIFEST_FILE]: signManifest(sodium, signer, {
      app, version, protocols,
      modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
      guest: GUEST(),
    }),
    [moduleFile("fwd")]: forwarderBytes,
    [GUEST_FILE]: GUEST_BYTES,
  });
  let realmBuilds = 0;
  const shell = await bootTestShell({
    createRealm: async () => {
      realmBuilds++;
      return { call: async () => new Uint8Array(), dispose() {} };
    },
    admit: byPrivilege({ base: admitAll, grants: { link: denyAll } }),
  });
  try {
    const key = appKey(author.id, "store");
    await shell.loadBundleBlob(blob(author, "store", 1, ["seedstore/v1"]));
    assertEqual(shell.resolve("seedstore/v1"), key,
      "the load claimed the manifest's protocol — no second operator action");
    assert(shell.resolve("store") === null,
      "…and exactly the id it declared, never a default to the app's own name");

    // An app that claims nothing serves nothing: the initiator-only shape (§12.8), and
    // the reason the field is optional rather than a required empty list.
    const quiet = appKey(author.id, "quiet");
    await shell.loadBundleBlob(blob(author, "quiet", 1, undefined));
    assertEqual(shell.routes().length, 1, "a bundle claiming nothing adds no route");

    // An update re-projects from the NEW manifest, so a claim that was dropped stops
    // being served — the table cannot outlive the manifest that put it there.
    await shell.loadBundleBlob(blob(author, "store", 2, ["seedstore/v2"]));
    assertEqual(shell.resolve("seedstore/v2"), key, "an update claims what the new manifest declares");
    assert(shell.resolve("seedstore/v1") === null, "…and drops the claim it no longer makes");

    // A second identity cannot shadow an active claim. Rejection leaves both the existing
    // route and the candidate's install state untouched — including never evaluating its
    // guest, whose top level could already exercise its admitted capabilities.
    const rival = appKey(other.id, "store");
    const buildsBeforeConflict = realmBuilds;
    let conflict = "";
    try { await shell.loadBundleBlob(blob(other, "store", 1, ["seedstore/v2"])); }
    catch (e) { conflict = String(e); }
    assert(conflict.includes("claim 'seedstore/v2' is already held"),
      `a contested claim is rejected by name, got: ${conflict || "no error"}`);
    assertEqual(shell.resolve("seedstore/v2"), key,
      "a rejected claimant does not disturb the active route");
    assert(shell.uninstall(rival) === false, "the rejected candidate did not install a slot");
    assertEqual(realmBuilds, buildsBeforeConflict,
      "a known claim conflict is refused before the candidate guest executes");

    // Uninstall drops what the app claimed: a route never outlives its app.
    shell.uninstall(key);
    shell.uninstall(quiet);
    assert(shell.resolve("seedstore/v2") === null, "uninstall drops the app's claims");
    assertEqual(shell.routes().length, 0, "…leaving no route behind");

    // The format's half of the rule: an id that is not routable is a manifest its author
    // got wrong, refused whole at verify rather than dropped quietly.
    for (const bad of [["bad id"], ["dup", "dup"], ["a".repeat(65)], [""], [7]]) {
      let threw = false;
      try {
        verifyManifest(sodium, signManifest(sodium, author,
          { app: "bad", version: 1, protocols: bad, modules: [], guest: GUEST() }));
      } catch (e) { threw = /malformed manifest/.test(String(e)); }
      assert(threw, `a manifest claiming ${JSON.stringify(bad)} is refused as malformed`);
    }
    // No spelling is reserved to the kernel: a `_`-led name is legal in either claim
    // list, and it is the LIST — never the spelling — that decides who may reach it.
    for (const claim of ["_offer", "_host", "_net", "plain"]) {
      verifyManifest(sodium, signManifest(sodium, author,
        { app: "reserved", version: 1, protocols: [claim], modules: [], guest: GUEST() }));
      verifyManifest(sodium, signManifest(sodium, author,
        { app: "reserved", version: 1, services: [claim], modules: [], guest: GUEST() }));
    }
    // The same name in both lists would be ambiguous about which reach it grants, so it
    // is refused as malformed rather than admitted under either.
    {
      let threw = false;
      try {
        verifyManifest(sodium, signManifest(sodium, author,
          { app: "ambiguous", version: 1, protocols: ["dual"], services: ["dual"], modules: [], guest: GUEST() }));
      } catch (e) { threw = /malformed manifest/.test(String(e)); }
      assert(threw, "a name claimed in both `protocols` and `services` is refused");
    }
    // The property that actually matters: a name in `services` is unreachable from a
    // PEER while the SAME bundle's `protocols` name is — checked through the real
    // delivery path (`shell.dispatch`) rather than by inspecting the claim table.
    {
      const pub = "reach/public", priv = "_reach-private";
      const reachKey = appKey(author.id, "reach");
      await shell.loadBundleBlob(packBundle({
        [MANIFEST_FILE]: signManifest(sodium, author,
          { app: "reach", version: 1, protocols: [pub], services: [priv], modules: [], guest: GUEST() }),
        [GUEST_FILE]: GUEST_BYTES,
      }));
      const senderHex = "11".repeat(32);
      const payload = new Uint8Array([1, 2, 3]);
      const publicAnswer = shell.dispatch(senderHex, pub, payload);
      assert(publicAnswer !== null, "a name in `protocols` is reachable by a peer");
      await publicAnswer;
      assert(shell.dispatch(senderHex, priv, payload) === null,
        "the same bundle's `services` name is unreachable by a peer, however it is spelled");
      shell.uninstall(reachKey);
    }
  } finally { shell.close(); }
  console.log("  OK\n");
}

// ─── Test: the link slot's delivery return is the ONLY delivery path ──────────
// Inbound attributed delivery is the link occupant's return convention, not a grant
// (README §12.10): the one slot that sees the plaintext is the one that attributes, so
// there is no second privilege to grant or forget. The properties that had to be pinned
// live at the one place they can be — over the real driver, claims and transport bundle:
// a delivery reaches exactly the named ordinary claim, never a `services` LOCAL claim,
// and a non-link app can never name a delivery path at all (transport-link.test.mjs:
// "EXACT CLAIM", "a peer cannot reach a bundle's local service claim", "CALLER BOUNDARY").

// ─── Test: the raw-link binding has ONE owner (§12.10) ───────────────────────
// The driver has one event sink, so a second link-capable slot cannot be a composition: it
// would take the node's sockets while the incumbent kept its claims and its realm, leaving
// a node that looks installed and answers nothing. Refused instead, on the same rule as a
// contested claim — and the incumbent's OWN next version still replaces it in place.
async function testOneRawLinkOwner() {
  console.log("Test: a second link-capable identity is refused the raw-link binding (§12.10)");
  const { admitAll } = await imp("build/host/policy.js");

  const author = testAuthor();
  const blob = (app, version, requires) => packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author,
      { app, version, protocols: undefined, modules: [], guest: GUEST({ requires }) }),
    [GUEST_FILE]: GUEST_BYTES,
  });
  // Both candidates are this author's, so the pin admits both and what refuses the
  // second is the binding rule under test rather than an earlier gate.
  const shell = await bootTestShell({
    createRealm: async () => ({ async call() { return new Uint8Array(); }, dispose() { } }),
    pinAuthor: author,
    admit: admitAll,
  });
  try {
    await shell.loadBundleBlob(blob("transport", 1, ["link"]));
    // A link-capable bundle that claims nothing — the initiator shape. Same privilege, so
    // the same binding, so it must not land quietly.
    let refused = "";
    try { await shell.loadBundleBlob(blob("dialer", 1, ["link"])); } catch (e) { refused = String(e); }
    assert(/binding is already held by/.test(refused),
      `a second link-capable identity is refused: ${refused || "no error"}`);
    // A bundle reaching no `link` name is unaffected — the binding is the privilege's, not
    // a global lock on loading.
    await shell.loadBundleBlob(blob("app", 1, ["clock"]));
    // The holder's own next version replaces it in place: an upgrade is not a contest.
    await shell.loadBundleBlob(blob("transport", 2, ["link"]));
    // And uninstalling the holder frees it for anyone.
    shell.uninstall(appKey(author.id, "transport"));
    await shell.loadBundleBlob(blob("dialer", 1, ["link"]));
  } finally { shell.close(); }
  console.log("  OK\n");
}

// ─── Test: removeApp, the per-app unbind ────────────────────────────────

async function testInstallerRemove() {
  console.log("Test: removeApp drops exactly one app (§3.1, §12.5)");

  const { host } = await makeHost();

  // Two apps of one author, plus a SECOND author's app sharing the app name — the
  // case the app key exists to separate (§5.1).
  const { id: pk } = testAuthor();
  const { id: other } = testAuthor();
  const chat = appKey(pk, "chat");
  const notes = appKey(pk, "notes");
  const theirs = appKey(other, "chat");

  await host.bindAll(chat, [{ name: "text", wasm: forwarderBytes }, { name: "media", wasm: forwarderBytes }]);
  await installMod(host, notes, "text", forwarderBytes);
  await installMod(host, theirs, "text", forwarderBytes);
  assert(host.isBound(chat, "text") && host.isBound(chat, "media"), "the app's two modules installed");
  assert(host.isBound(notes, "text") && host.isBound(theirs, "text"), "the other two apps installed");

  // The unbind is per APP, and the app is the key: one delete takes every module the app
  // landed and nothing else.
  assertEqual(host.removeApp(chat), 2, "both modules of the app went in one call");
  assert(!host.isBound(chat, "text") && !host.isBound(chat, "media"), "the app is gone");
  assert(host.isBound(notes, "text"), "the same author's other app is untouched");
  assert(host.isBound(theirs, "text"), "another author's same-named app is untouched");

  // Nothing else to clear: a freed entry is contended for by nobody, since the key can
  // only be derived by the author whose public key is half of it. No tombstone.
  assertEqual(host.removeApp(chat), 0, "a second call removes nothing");
  await installMod(host, chat, "text", forwarderBytes);
  assert(host.isBound(chat, "text"), "reinstall after remove succeeds");

  console.log("  OK\n");
}

// ─── Test: fs.* capability (opaque key → bytes) ─────────────────────────

async function testFs() {
  console.log("Test: fs.* capability — opaque key → bytes (NodeFs + MemoryFs)");

  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  // Both backends must satisfy the same contract.
  const backends = [
    { name: "MemoryFs", make: () => ({ fs: new MemoryFs(), cleanup: () => {} }) },
    {
      name: "NodeFs",
      make: () => {
        const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-fs-"));
        return { fs: new NodeFs(dir), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
      },
    },
  ];

  for (const { name, make } of backends) {
    const { fs, cleanup } = make();
    try {
      // The seam is async on every backend (core/fs.ts), which is what lets a browser
      // backend satisfy this shape at all.
      const bytes = new Uint8Array([1, 2, 3, 4, 5]);
      assert(await fs.size("a.blk") < 0, `${name}: absent before put`);
      assertEqual(await fs.size("a.blk"), -1, `${name}: size -1 when absent`);
      assertEqual(await fs.get("a.blk"), null, `${name}: get null when absent`);

      await fs.put("a.blk", bytes);
      assert(await fs.size("a.blk") >= 0, `${name}: present after put`);
      assertEqual(await fs.size("a.blk"), 5, `${name}: size reflects bytes`);
      assert(bytesEqual(await fs.get("a.blk"), bytes), `${name}: get round-trips`);

      await fs.put("a.dsc", new Uint8Array([9]));
      await fs.put("b.blk", new Uint8Array([7, 7]));
      assertEqual((await fs.list()).sort().join(","), "a.blk,a.dsc,b.blk", `${name}: list sees all keys`);
      assertEqual((await fs.list("a.")).sort().join(","), "a.blk,a.dsc", `${name}: list filters by prefix`);
      assertEqual((await fs.stat()).used, 5 + 1 + 2, `${name}: stat.used sums all values`);
      assert((await fs.stat()).available > 0, `${name}: stat.available is positive`);

      assert(await fs.delete("a.blk"), `${name}: delete reports removal`);
      assert(await fs.size("a.blk") < 0, `${name}: absent after delete`);
      assert(!(await fs.delete("a.blk")), `${name}: second delete is false`);
    } finally {
      cleanup();
    }
  }

  // The node backend must refuse keys that could escape its directory.
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-fs-"));
  try {
    const fs = new NodeFs(dir);
    // The key check throws inside an async method, so it surfaces as a rejection —
    // still a refusal the caller cannot miss, and still before any syscall.
    let threw = false;
    try { await fs.put("../escape", new Uint8Array([0])); } catch { threw = true; }
    assert(threw, "NodeFs rejects a path-traversal key on put");
    assertEqual(await fs.get("../escape"), null, "NodeFs reads an unsafe key as absent");
    threw = false;
    try { await fs.put("..", new Uint8Array([0])); } catch { threw = true; }
    assert(threw, "NodeFs rejects the bare '..' key");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  console.log("  OK\n");
}

// ─── Test: the fs key space is ONE rule, shared by every target ──────────
// Which keys a node admits decides which blocks it stores and advertises, so it is a
// consensus predicate: a Go node and a Bun node that disagree about it disagree about
// their contents. The rule lives in shared JS (core/fs.ts `isSafeFsKey`), applied over
// whatever backend a target supplies (`validatedFs`, shell-core.ts).

async function testFsKeyRule() {
  console.log("Test: fs key space is one rule — isSafeFsKey over any backend (validatedFs)");

  const { isSafeFsKey } = await imp("build/core/fs.js");
  const { validatedFs, scopedFs } = await imp("build/host/shell-core.js");

  const legal = ["a", "a.blk", "A_b-c.9", "0".repeat(64) + ".blk", "_", "-", "..a", "a.."];
  for (const k of legal) assert(isSafeFsKey(k), `isSafeFsKey(${JSON.stringify(k)}) should hold`);

  const illegal = [
    "", ".", "..",                       // names nothing, or names a directory
    "a/b", "..\\escape", "../escape",     // separators and traversal
    "a b", "a\x00b", "a:b", "a*b", "~tmp", "é",  // outside the charset
    "CON", "nul", "Aux", "COM1", "COM0", "LPT9", "con.txt", "NUL.tar.gz", // Windows devices,
  ];                                     // case- and extension-insensitively
  for (const k of illegal) assert(!isSafeFsKey(k), `isSafeFsKey(${JSON.stringify(k)}) should not hold`);

  // validatedFs applies it to every op that NAMES a key, as a rejection rather than a
  // silent miss: an unrepresentable key is a caller bug on read exactly as on write.
  const fs = validatedFs(new MemoryFs());
  await fs.put("ok.blk", new Uint8Array([1]));
  for (const [what, call] of [
    ["put", () => fs.put("a/b", new Uint8Array([1]))],
    ["get", () => fs.get("a/b")],
    ["size", () => fs.size("CON")],
    ["delete", () => fs.delete("")],
  ]) {
    let rejected = false;
    try { await call(); } catch { rejected = true; }
    assert(rejected, `validatedFs rejects an unsafe key on ${what}`);
  }

  // …and to none that does not. `list()` takes a PREFIX, and the empty prefix — "every
  // key I can see" — is exactly the call a key rule applied here would wrongly refuse.
  assertEqual((await fs.list()).join(","), "ok.blk", "validatedFs leaves list(undefined) alone");
  assertEqual((await fs.list("ok")).join(","), "ok.blk", "validatedFs leaves a list prefix alone");
  assert((await fs.stat()).used === 1, "validatedFs leaves stat alone");

  // The shell wraps the backend UNDER scopedFs, so what the rule sees is the composite
  // key the medium sees — a guest key that would escape its scope is refused even though
  // the scope prefix is itself legal.
  const scoped = scopedFs(fs, "abcd1234");
  await scoped.put("mine.blk", new Uint8Array([2]));
  assert((await fs.get("abcd1234mine.blk")) !== null, "scoped put lands under the scope");
  let escaped = false;
  try { await scoped.put("../../etc", new Uint8Array([3])); } catch { escaped = true; }
  assert(escaped, "a scoped key with separators is refused on the composite");

  console.log("  OK\n");
}

// ─── Test: guest-side fan-out over the cross-realm call (Promise.all) ────────────
// Fan-out is not a host op: with real promises at the seam, a confined guest scatters a
// distinct request per peer itself with Promise.all over `_net`. Driven here through the
// seam's single-peer cross-realm call, concurrently, so the round trips overlap in one realm.

async function testGuestSeam() {
  console.log("Test: guest seam — generic primitive capabilities, no app vocabulary (step 7)");

  const id = generateKeyPair();
  const otherKey = generateKeyPair();
  const fs = new MemoryFs();
  // The routing a local service id resolves through — the shell's job in production, a
  // stub here so the seam is tested for what it does: gate the name, then hand the
  // payload to whatever claims the id. `_net` and `chat/v1` are claimed; `_nobody` is not.
  const claimed = new Set(["_net", "chat/v1"]);
  const calls = { call: (idName) => (claimed.has(idName) ? Promise.resolve(U(9, 9)) : null) };
  // THIS realm's declared local services (§12.10) — what tells them apart from a bare
  // module name at the dispatch, independent of `names` (which opts out of gating below
  // via UNRESTRICTED_NAMES). `chat/v1` is here because a local service id is an ordinary
  // claim: it may carry a `/` exactly like a wire protocol id.
  const localServices = new Set(["_net", "_nobody", "chat/v1"]);

  // A module reachable by name, for the catalog's app-module half.
  const { host } = await makeHost();
  const testKey = appKey(id.publicKey, "testapp");
  await installMod(host, testKey, "echo", forwarderBytes);

  // A host-derived signing scope binds the guest's node/sign name to a bundle namespace
  // (§12.2); a real node derives it from the manifest's (author, app).
  const signScope = appSignScope(id, id.publicKey, "testapp");
  const scopeBytes = guestSignScope(id.publicKey, "testapp");
  const seam = createGuestSeam({
    platform: { sodium, identity: id },
    grants: { names: UNRESTRICTED_NAMES, localServices, signScope, fs, calls },
    // Scoped to one app, exactly as the shell scopes it: a bare name is a module
    // inside this app's map and cannot reach out of it.
    modules: {
      names: new Set(["echo"]),
      call: (name, p) => host.slots.get(testKey)?.call(name, p) ?? Promise.resolve({ bytes: null, ms: 0 }),
    },
  });
  const U = (...xs) => new Uint8Array(xs);

  try {
    // Primitives are reached BY NAME through the `crypto/` prefix: there is no op
    // number per algorithm, so adding one is a catalog entry and the seam never learns
    // what a cipher suite is.
    const prim = (name, argBytes) => seam(`crypto/${name}`, argBytes);
    const msg = U(1, 2, 3, 4, 5);
    assert(bytesEqual(await prim("blake2b-256", msg), sodium.crypto_generichash(32, msg)), "crypto/blake2b-256, by name");
    const key = sodium.randombytes_buf(32), nonce = sodium.randombytes_buf(24);
    assert(bytesEqual(await prim("xchacha20/xor", concatBytes([nonce, key, msg])),
      sodium.crypto_stream_xchacha20_xor(msg, nonce, key)), "crypto/xchacha20/xor, by name");
    // node/sign is scoped, never raw (§12.2): it signs DOMAIN_guest ‖ scope ‖ msg.
    // node/verify applies the SAME scope host-side, so a guest checks a signature by
    // naming the key, never by reconstructing the prefix the host owns.
    const DOMAIN_GUEST = new TextEncoder().encode("seedkernel-guest-sig-v1\0");
    const sig = await seam("node/sign", msg);
    const preimage = concatBytes([DOMAIN_GUEST, scopeBytes, msg]);
    assert(sodium.crypto_sign_verify_detached(sig, preimage, id.publicKey), "node/sign signs DOMAIN_guest ‖ scope ‖ msg under the node identity");
    assert(!sodium.crypto_sign_verify_detached(sig, msg, id.publicKey), "node/sign never signs the raw message (scoped, not raw)");
    assertEqual((await seam("node/verify", concatBytes([id.publicKey, sig, msg])))[0], 1, "node/verify accepts what node/sign signed — the same scope, host-applied");
    assertEqual((await seam("node/verify", concatBytes([otherKey.publicKey, sig, msg])))[0], 0, "node/verify rejects the signature under a different key");
    assertEqual((await seam("node/verify", concatBytes([id.publicKey, sig, U(9, 9)])))[0], 0, "node/verify rejects a forged message");
    // A mis-framed call is not a failed verification: too few bytes to hold [pk][sig]
    // throws, where 0 would have been a verdict about bytes nothing checked. The bound
    // is exactly the fixed prefix — an empty message is a legitimate question.
    const emptySig = await seam("node/sign", new Uint8Array(0));
    assertEqual((await seam("node/verify", concatBytes([id.publicKey, emptySig])))[0], 1, "node/verify takes an empty message — 96 bytes is a whole call");
    let verifyThrew = false;
    try { await seam("node/verify", concatBytes([id.publicKey, sig.slice(0, 63)])); } catch { verifyThrew = true; }
    assert(verifyThrew, "node/verify refuses a short payload rather than answering 0 (mis-framed ≠ invalid)");
    assertEqual((await prim("ed25519/verify", concatBytes([id.publicKey, sig, preimage])))[0], 1, "crypto/ed25519/verify accepts the scoped preimage — the raw primitive node/verify wraps");
    assertEqual((await prim("ed25519/verify", concatBytes([id.publicKey, sig, U(9, 9)])))[0], 0, "crypto/ed25519/verify rejects a forged message");
    // ML-KEM-768 is in the catalog ahead of any caller, so what is checked here is that
    // it is REACHABLE like every other primitive: by name, with no capability declared.
    // Derandomized, so the coins come from node/random and the entry stays pure.
    {
      const seed = await seam("node/random", U(0, 0, 0, 64));
      const kp = await prim("ml-kem-768/keypair", seed);
      assertEqual(kp.length, 1184 + 2400, "crypto/ml-kem-768/keypair returns [pk 1184][sk 2400]");
      const kemPk = kp.slice(0, 1184), kemSk = kp.slice(1184);
      const coins = await seam("node/random", U(0, 0, 0, 32));
      const enc = await prim("ml-kem-768/encaps", concatBytes([kemPk, coins]));
      assertEqual(enc[0], 1, "crypto/ml-kem-768/encaps accepts a well-formed encapsulation key");
      assertEqual(enc.length, 1 + 1088 + 32, "encaps returns [ok][ct 1088][ss 32]");
      const ct = enc.slice(1, 1 + 1088), ss = enc.slice(1 + 1088);
      const dec = await prim("ml-kem-768/decaps", concatBytes([kemSk, ct]));
      assertEqual(dec[0], 1, "crypto/ml-kem-768/decaps accepts a well-formed decapsulation key");
      assert(bytesEqual(dec.slice(1), ss), "both ends derive the same shared secret");
      // Encapsulation is deterministic in its coins — that is what makes it a catalog
      // entry rather than an authority.
      const again = await prim("ml-kem-768/encaps", concatBytes([kemPk, coins]));
      assert(bytesEqual(again, enc), "encaps is a pure function of (key, coins)");
      // A malformed peer key is an answer, not a throw: the caller did not choose it.
      // 12-bit little-endian packing: 0xff,0xff decodes to 4095, out of [0, q-1].
      const badPk = kemPk.slice(); badPk[0] = 0xff; badPk[1] = 0xff;
      assertEqual((await prim("ml-kem-768/encaps", concatBytes([badPk, coins]))).length, 1,
        "a key failing the FIPS 203 modulus check answers [0], not an exception");
      // A tampered ciphertext is NOT an error — implicit rejection returns a different
      // shared secret in constant time, and saying so would be the oracle.
      const badCt = ct.slice(); badCt[0] ^= 1;
      const implicit = await prim("ml-kem-768/decaps", concatBytes([kemSk, badCt]));
      assertEqual(implicit[0], 1, "a bad ciphertext still succeeds — ML-KEM rejects implicitly");
      assert(!bytesEqual(implicit.slice(1), ss), "…but derives an unrelated shared secret");
    }

    assert(bytesEqual(await seam("node/identity", U()), id.publicKey), "node/identity = the node pubkey");
    assertEqual((await seam("node/random", U(0, 0, 0, 16))).length, 16, "node/random returns n bytes");
    assertEqual((await seam("clock/now", U())).length, 8, "clock/now returns a u64");

    // fs.* over the raw backend
    const fk = new TextEncoder().encode("dead.blk"), fv = U(7, 7, 7);
    await seam("fs/put", concatBytes([U(0, 0, 0, fk.length), fk, fv]));
    const got = await seam("fs/get", fk);
    assert(got[0] === 1 && bytesEqual(got.slice(1), fv), "fs/put + fs/get round-trips under an opaque key");
    assertEqual((await seam("fs/get", new TextEncoder().encode("missing")))[0], 0, "fs/get of an absent key → [0]");
    const szPresent = await seam("fs/size", fk);
    assertEqual(new DataView(szPresent.buffer, szPresent.byteOffset).getUint32(0, false), fv.length, "fs/size returns the value's byte length");
    const szAbsent = await seam("fs/size", new TextEncoder().encode("missing"));
    assertEqual(new DataView(szAbsent.buffer, szAbsent.byteOffset).getUint32(0, false), 0xffffffff, "fs/size of an absent key → -1 (0xFFFFFFFF)");

    // Which side of the sync/async line a name sits on is the ABI (§12.2), and what
    // `guest.abi` versions: a primitive is a function of its arguments and resolves
    // inline, while net and fs genuinely round-trip and hand back a Promise.
    assert(!(prim("blake2b-256", msg) instanceof Promise), "a catalog primitive resolves synchronously (bytes, no Promise)");
    assert(seam("fs/size", fk) instanceof Promise, "fs/size returns a Promise (fs round-trips)");

    // The CROSS-REALM call: a name in THIS realm's declared local services is another
    // realm, reached on a later turn, so it is a Promise like fs. There is no `net`
    // domain — the network is a bundle that declares the service `_net`, and this seam's
    // routing answers it (§12.10).
    const crossed = seam("_net", U(1, 2, 3));
    assert(crossed instanceof Promise, "a local service id returns a Promise (the callee runs on a later turn)");
    assertEqual([...await crossed], [9, 9], "…and resolves with what the callee's handle returned");
    let unclaimed = false;
    try { await seam("_nobody", U()); } catch { unclaimed = true; }
    assert(unclaimed, "a local service id no realm claims is refused by name, not left pending");
    // The declaration is asked BEFORE the charset, so an id spelled with a `/` — legal
    // for any claim (§12.10) — reaches the routing rather than the host table, where it
    // would have died as an unknown host name.
    assertEqual([...await seam("chat/v1", U(1))], [9, 9],
      "a declared local service id carrying a `/` still routes to the claiming realm");

    // A bare name reaches this app's module by its LOGICAL name, in the same `host.call`
    // shape as every other name (§12.2). The app key is the seam's, never the caller's.
    assertEqual([...await seam("echo", U(8, 9))], [8, 9], "a bare name invokes this app's module");
    let noSuch = false;
    try { await seam("nosuchmodule", U(1)); } catch { noSuch = true; }
    assert(noSuch, "a bare name this app never installed is refused, like any unknown name");
  } finally { /* nothing host-side to tear down: the seam holds no transport */ }

  console.log("  OK\n");
}

// ──── Test: channel identity pinning (transport §12.6) ────

async function testPolicy() {
  console.log("Test: shell install policy — closed author sets gate bundle loads");
  const { parsePolicy } = await imp("build/host/policy.js");

  const good = testAuthor();
  const bad = testAuthor();

  // Build a signed bundle from each author; loadBundle accepts/rejects by predicate.
  const { ModuleTable } = await imp("build/host/module-table.js");
  const tryLoad = async (policyJson, author, links) => {
    const host = testHost(new ModuleTable());
    const manifest = { app: "mod", version: 1,
      modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
      guest: GUEST({ requires: links ? ["link"] : [] }) };
    const manifestEnv = signManifest(sodium, author, manifest);
    const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes, [GUEST_FILE]: GUEST_BYTES });
    const admit = parsePolicy(policyJson);
    let landed = false;
    try { await loadBundle(host, blob, admit, links ? LINK_CTX : APP_CTX); landed = true; } catch { /* author not in policy */ }
    return landed;
  };

  // ── author allowlist ───────────────────────────────────────────────────
  const okAuthor = await tryLoad(JSON.stringify({ authors: [toHex(good.id)] }), good);
  assert(okAuthor, "install by an allowed author is accepted");

  const badAuthor = await tryLoad(JSON.stringify({ authors: [toHex(good.id)] }), bad);
  assert(!badAuthor, "install by an author not on the allowlist is rejected");

  // ── the transport is a GRANTED CAPABILITY, not a kind of bundle (§12.5) ────
  // The `link` privilege carries raw links and network-scoped signing, so the ordinary
  // author list must NOT admit one even for an author it already trusts with apps.
  const goodHex = toHex(good.id);
  const appOnly = JSON.stringify({ authors: [goodHex] });
  const withTransport = JSON.stringify({ authors: [goodHex], grants: { link: [goodHex] } });

  const linkDenied = await tryLoad(appOnly, good, true);
  assert(!linkDenied, "an author trusted for apps does NOT thereby hold `link`");
  const linkAllowed = await tryLoad(withTransport, good, true);
  assert(linkAllowed, "a grants.link entry admits that author to the transport");
  const strangerLink = await tryLoad(withTransport, bad, true);
  assert(!strangerLink, "an author outside the `link` grant is refused it");
  const appStillOk = await tryLoad(withTransport, good, false);
  assert(appStillOk, "adding a grant does not disturb ordinary app admission");

  // The two answers are independent: a grant alone admits no unprivileged bundle.
  const transportOnly = JSON.stringify({ grants: { link: [goodHex] } });
  const appUnderTransportList = await tryLoad(transportOnly, good, false);
  assert(!appUnderTransportList, "a `link` grant is not a licence to load — `authors` still decides that");

  // ── parse validation ───────────────────────────────────────────────────
  let threw = false;
  try { parsePolicy("{ not json"); } catch { threw = true; }
  assert(threw, "malformed policy JSON throws (fails the boot loudly)");
  threw = false;
  try { parsePolicy(JSON.stringify({ authors: [] })); } catch { threw = true; }
  assert(threw, "an empty author set is rejected");
  threw = false;
  try { parsePolicy(JSON.stringify({ authors: [goodHex], grants: { link: [] } })); } catch { threw = true; }
  assert(threw, "an empty grant list is rejected (omit the key to grant none)");
  // A key the host does not know is refused at the top level too, not just under `grants`:
  // ignoring it is how a mistyped file boots looking configured and silently holds nothing.
  threw = false;
  try { parsePolicy(JSON.stringify({ authorss: [goodHex], grants: { link: [goodHex] } })); } catch { threw = true; }
  assert(threw, "a mistyped top-level key is refused rather than ignored");
  // The privilege NAMES come from the catalog, which is the whole reason the key is a
  // capability rather than free-form text.
  threw = false;
  try { parsePolicy(JSON.stringify({ grants: { links: [goodHex] } })); } catch { threw = true; }
  assert(threw, "a grant naming no privilege this host has is refused by name");
  // `route` is gone: delivery is the link slot's return convention, and a policy file
  // written for the separate grant is a file this host does not mean — refused at the
  // boot rather than read as an empty grant.
  threw = false;
  try { parsePolicy(JSON.stringify({ grants: { route: [goodHex] } })); } catch { threw = true; }
  assert(threw, "`grants.route` is no longer a privilege key — refused by name, kept nobody");
  threw = false;
  try { parsePolicy(JSON.stringify({})); } catch { threw = true; }
  assert(threw, "a policy listing neither authors nor grants is refused");

  console.log("  OK\n");
}

// ─── Test: the requires decide which privileges are in play (§12.5) ────────
// One install path, no `role` field: what a bundle must be granted is read off
// `guest.requires` alone. The derivation cannot be pushed the wrong way — naming a
// `link/*` name puts `link` in the set and nothing takes it out — so the most permissive
// `authors` list expressible (`admitAll`) still buys an author no sockets; otherwise every
// policy test above is a lock on an open door. Driven through the assembly, because the
// derivation is the shell's — the policy tests above compose verifyBundle → admit →
// installBundle by hand and would not see it.
async function testRequiresPickThePrivileges() {
  console.log("Test: guest.requires decides which privileges a bundle must be granted");
  const { admitAll, denyAll, byPrivilege } = await imp("build/host/policy.js");

  const author = testAuthor();
  const blobWithRequires = (requires) => packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author, {
      app: "mod", version: 1,
      modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
      // The transport claims the local service id it is reached by (§12.10); an ordinary
      // app claims nothing here.
      ...(requires.includes("link") ? { services: ["_net"] } : {}),
      guest: GUEST({ requires }),
    }),
    [moduleFile("fwd")]: forwarderBytes,
    [GUEST_FILE]: GUEST_BYTES,
  });
  // ONE predicate, with the capability set as an argument (`byPrivilege`) rather than a
  // choice between predicates. The pin names this author, so every candidate reaches the
  // predicate whose choice is being counted — a pin refusing first would zero every count.
  const mkTestShell = (base, link) => bootTestShell({
    createRealm: async () => ({ call: async () => new Uint8Array(), dispose() {} }),
    pinAuthor: author,
    admit: byPrivilege({ base, grants: { link } }),
  });
  const load = async (shell, requires) => {
    try { await shell.loadBundleBlob(blobWithRequires(requires)); return null; }
    catch (e) { return String(e); }
  };

  // 1. Which predicate was ASKED, counted rather than inferred from the outcome: a
  //    transport's outcome also depends on the driver standing, which the stub guest
  //    cannot do.
  {
    let appAsked = 0, transportAsked = 0;
    const shell = await mkTestShell(() => { appAsked++; return true; }, () => { transportAsked++; return true; });
    try {
      await load(shell, ["fs", "clock"]);
      assert(appAsked === 1 && transportAsked === 0, "a bundle reaching no privilege is governed by the base predicate");
      appAsked = transportAsked = 0;
      await load(shell, ["link"]);
      assert(transportAsked === 1 && appAsked === 0, "a bundle naming the `link/*` names is governed by the `link` grant alone");
    } finally { shell.close(); }
  }

  // 2. The direction that matters: admitAll for apps, denyAll for the transport. An
  //    author trusted for every app there is still cannot land raw links.
  {
    const shell = await mkTestShell(admitAll, denyAll);
    try {
      const err = await load(shell, ["link"]);
      assert(err !== null && /rejected by admission/.test(err),
        "a permissive author list does not admit a bundle naming the `link/*` names");
      assert(await load(shell, ["fs", "clock"]) === null, "the same shell still lands an ordinary app");
    } finally { shell.close(); }
  }

  // 3. A privilege is ONE thing, so there are no halves to claim: `link` beside ordinary
  //    app services is still governed by the `link` grant alone, never the base.
  //    Otherwise a bundle could reach sockets while falling through to the unprivileged
  //    list by mixing in an ordinary service.
  {
    const requires = ["fs", "link"];
    let appAsked = 0, linkAsked = 0;
    const shell = await mkTestShell(() => { appAsked++; return true; }, () => { linkAsked++; return true; });
    try {
      await load(shell, requires);
      assert(linkAsked === 1 && appAsked === 0,
        `${JSON.stringify(requires)} reaches the \`link\` grant, not the base`);
    } finally { shell.close(); }
  }
  console.log("  OK\n");
}

// ─── Test: node/sign is the one sign name; its scope is the slot's — the app scope for ──
// ─── an app slot, the network scope for the link slot, on EVERY load path ──────────────
// `slotSignScope` is a function of admitted facts — the node's identity, the manifest and
// the privileges it reaches — which is the whole reason it cannot drift. Driven through a
// real shell because the property is about the point where a signed manifest becomes a
// realm, and because the path that could silently lose it is the in-place UPDATE: a
// transport that re-scoped itself on upgrade would keep serving while every handshake
// with an un-upgraded peer failed as an authentication error naming nothing.
async function testSigningScopeFollowsSlot() {
  console.log("Test: node/sign is the slot's scope — app scope for an app, network scope for the link slot, on every load path");
  const { byPrivilege, admitAll } = await imp("build/host/policy.js");
  const { slotSignScope } = await imp("build/host/guest-seam.js");
  const linkAuthor = testAuthor(), appAuthor = testAuthor();
  const identity = generateKeyPair();
  const networkKey = new Uint8Array(32).fill(0x7a);
  let seam;
  // The pin is `linkAuthor`'s: it is the only author here whose bundle reaches `link`,
  // and the app author's never does, so one pin covers both loads.
  const shell = await bootTestShell({
    identity, networkKey,
    createRealm: async ({ hostCall }) => {
      seam = hostCall;
      return { call: async () => new Uint8Array(), dispose() {} };
    },
    pinAuthor: linkAuthor,
    admit: byPrivilege({ base: admitAll, grants: { link: admitAll } }),
  });
  const blob = (author, app, version, requires) => packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author, {
      app, version, modules: [], guest: GUEST({ requires }),
    }),
    [GUEST_FILE]: GUEST_BYTES,
  });
  const DOMAIN_GUEST = new TextEncoder().encode("seedkernel-guest-sig-v1\0");
  const DOMAIN_LINK = new TextEncoder().encode("seedkernel-link-scope-v1\0");
  const preimage = (domain, scope, msg) => concatBytes([domain, scope, msg]);
  const signs = (sig, domain, scope, msg) =>
    sodium.crypto_sign_verify_detached(sig, preimage(domain, scope, msg), identity.publicKey);
  const msg = new Uint8Array([5, 4, 3]);
  const linkApp = guestSignScope(linkAuthor.id, "linkprobe");
  try {
    // The link slot's one scope is the NETWORK scope: the channel AUTH is a fact of the
    // slot, not a second name.
    await shell.loadBundleBlob(blob(linkAuthor, "linkprobe", 1, ["node", "link"]));
    const v1 = await seam("node/sign", msg);
    assert(signs(v1, DOMAIN_LINK, networkKey, msg),
      "the link slot's node/sign signs under DOMAIN_link_scope ‖ networkKey");
    assert(!signs(v1, DOMAIN_GUEST, linkApp, msg),
      "…and never under the transport author's app scope — the slot's scope is what the name means");
    assertEqual((await seam("node/verify", concatBytes([identity.publicKey, v1, msg])))[0], 1,
      "node/verify on the link slot checks under the same network scope");

    // The path a lease would be dropped on: the standing slot is replaced in place.
    await shell.loadBundleBlob(blob(linkAuthor, "linkprobe", 2, ["node", "link"]));
    const v2 = await seam("node/sign", msg);
    assert(signs(v2, DOMAIN_LINK, networkKey, msg),
      "an in-place update of the link slot keeps the SAME network scope — an upgrade cannot re-scope a node");

    // And the other arm, on a shell that already has a link occupant: an ordinary app
    // signs under its own scope, and there is only one pair of sign names — nothing under
    // a second name to reach.
    await shell.loadBundleBlob(blob(appAuthor, "plainapp", 1, ["node"]));
    const app = await seam("node/sign", msg);
    assert(signs(app, DOMAIN_GUEST, guestSignScope(appAuthor.id, "plainapp"), msg),
      "an ordinary app's node/sign signs under DOMAIN_guest ‖ author ‖ app");
    assert(!signs(app, DOMAIN_LINK, networkKey, msg),
      "…and cannot reach the link slot's network scope");
    let refused = false;
    try { await seam("link/sign", msg); } catch { refused = true; }
    assert(refused, "there is no link/sign name — the sign pair is one names pair per slot");

    // The two arms are the one exported constructor, so a caller building a scope by hand
    // agrees with what the slot got.
    assert(bytesEqual(slotSignScope({ identity, networkKey }, linkAuthor.id, "linkprobe", ["link"]).scope, networkKey),
      "slotSignScope gives the link slot the network scope");
    assert(bytesEqual(slotSignScope({ identity, networkKey }, appAuthor.id, "plainapp", []).scope,
      guestSignScope(appAuthor.id, "plainapp")), "slotSignScope gives an app slot author ‖ app");
  } finally { shell.close(); }
  console.log("  OK\n");
}

// ─── Test: the guest ABI field (§12.2, §12.4) ───────────────────────────

async function testGuestAbi() {
  console.log("Test: a guest declares the host ABI it was written against");

  const author = testAuthor();
  const guestText = "function handle() { return new Uint8Array([1]); }";
  const guestBytes = new TextEncoder().encode(guestText);
  const mk = (guest) => signManifest(sodium, author,
    { app: "abi", version: 1, modules: [], guest });
  const hash = toHex(gHash(guestBytes));

  assert(verifyManifest(sodium, mk({ hash, abi: GUEST_ABI_VERSION, requires: [] })) !== null,
    "a guest declaring this host's ABI verifies");

  // Missing: the field is required, not defaulted. A guest author who never thought
  // about the seam version is indistinguishable from one who meant the old one, and
  // defaulting would silently pick the population a bump exists to catch.
  let threw = false;
  try { verifyManifest(sodium, mk({ hash, requires: [] })); } catch { threw = true; }
  assert(threw, "a guest with no declared ABI is refused as malformed");

  // Present but unimplemented: a legibility failure ("this bundle wants a host I am
  // not"), so it throws with its own message rather than reading as a bad signature.
  let msg = "";
  try { verifyManifest(sodium, mk({ hash, abi: GUEST_ABI_VERSION + 1, requires: [] })); }
  catch (e) { msg = e.message; }
  assert(msg.includes("guest ABI"), `an unimplemented guest ABI is refused by name (got: ${msg})`);

  // Every bundle declares a guest (§12.4), and a manifest without one is refused BY NAME
  // like the ABI above: it is what a bundle written against the retired module-only
  // format produces, so the message has to state the rule.
  let noGuest = "";
  try { verifyManifest(sodium, signManifest(sodium, author,
    { app: "abi", version: 1, modules: [] })); } catch (e) { noGuest = e.message; }
  assert(noGuest.includes("every app is a guest"), `a manifest without a guest is refused by name (got: ${noGuest})`);

  // Requires speak at SERVICE granularity (§12.2): a finer method name is a refused
  // manifest, since the seam gates a `host.call` by the method's service, never by the
  // exact method — a manifest naming one would ask for a grant finer than the seam can
  // enforce.
  {
    let refused = "";
    try { verifyManifest(sodium, mk({ hash, abi: GUEST_ABI_VERSION, requires: ["fs/get"] })); }
    catch (e) { refused = e.message; }
    assert(refused.includes("names a host METHOD") && refused.includes('"fs"'),
      `a manifest requiring the method "fs/get" is refused, naming the service to declare instead (got: ${refused})`);
  }
  // …and the SERVICE, by exact name, is what a manifest may require — the guest still
  // calls the finer-grained method; being undeclarable at that granularity is not being
  // unavailable.
  assert(verifyManifest(sodium, mk({ hash, abi: GUEST_ABI_VERSION, requires: ["fs"] })) !== null,
    "a service, by exact name, is what a manifest may require");

  // A bare name colliding with this bundle's OWN module name is refused: the seam's
  // dispatch resolves a declared local service before this bundle's modules, so a
  // collision would silently shadow the module (guest-seam.ts).
  {
    const withModule = (requires) => signManifest(sodium, author, {
      app: "abi", version: 1,
      modules: [{ name: "codec", hash: "aa" }],
      guest: { hash, abi: GUEST_ABI_VERSION, requires },
    });
    let refused = "";
    try { verifyManifest(sodium, withModule(["codec"])); } catch (e) { refused = e.message; }
    assert(refused.includes("codec") && refused.includes("module"),
      `a local service id colliding with this bundle's own module name is refused (got: ${refused})`);
    assert(verifyManifest(sodium, withModule([])) !== null,
      "…and the same module name is fine when nothing declares it as a local service too");
  }

  // Any OTHER bare or slashed name — not a known service, not a collision — is a
  // legitimate LOCAL service id (§12.10): the vocabulary is open on that half, since
  // whether anything actually claims it is answered at the call, never at the manifest.
  assert(verifyManifest(sodium, mk({ hash, abi: GUEST_ABI_VERSION, requires: ["_backup", "reporting/v2"] })) !== null,
    "an arbitrary local service id verifies; nothing claiming it yet is not a manifest error");

  console.log("  OK\n");
}

// ─── Test: the transport's freshness (§12.4) ───────────────────

async function testSlotFreshness() {
  console.log("Test: the transport carries the ordinary (author, app) freshness mark");

  const { FreshnessMarks } = await imp("build/host/bundle.js");
  const { ModuleTable } = await imp("build/host/module-table.js");

  const a = testAuthor();
  const b = testAuthor();
  const blobFrom = (author, version) => packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author,
      { app: "link", version, modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }], guest: GUEST() }),
    [moduleFile("fwd")]: forwarderBytes,
    [GUEST_FILE]: GUEST_BYTES,
  });
  // The load path as the shell composes it: the host's gates read the store into an
  // `AdmissionContext` and answer once, installBundle lands the modules, and the mark is
  // advanced last — after the guest stands, which is the shell's job and why the mark is
  // written here rather than inside installBundle. The predicate never touches the store,
  // so "who refuses a downgrade" is one place.
  const land = async (host, freshness, author, version) => {
    const v = verifyBundle(sodium, blobFrom(author, version));
    await hostGates(v, {
      privileges: ["link"],
      highWater: freshness.get(v.author, v.manifest.app),
      revoked: freshness.isRevoked(v.author),
    });
    await installBundle(host, v);
    freshness.set(v.author, v.manifest.app, v.manifest.version);
  };

  // Versions are an author's own lineage, transport or not: a floor keyed to the
  // transport would put two independent authors on one shared version line with no owner,
  // and would only pay where an attacker chooses which signed bundle arrives (§12.4).
  {
    const freshness = new FreshnessMarks();
    const host = testHost(new ModuleTable());
    await land(host, freshness, a, 5);
    assertEqual(freshness.get(a.id, "link"), 5, "landing a transport advances its (author, app) mark");
    await land(host, freshness, b, 1);
    assertEqual(freshness.get(b.id, "link"), 1, "a second author's transport answers to its own lineage");
  }

  // Each author is still held to their own mark.
  {
    const freshness = new FreshnessMarks();
    const host = testHost(new ModuleTable());
    await land(host, freshness, a, 5);
    let refused = false;
    try { await land(host, freshness, a, 4); } catch { refused = true; }
    assert(refused, "an author's own stale transport is still refused as a downgrade");
  }

  // The store holds marks and revocations only. A file carrying an unrecognized key —
  // one a newer version added, say — still loads (it is ignored, not refused) and is
  // rewritten without it.
  {
    const legacy = new FreshnessMarks(JSON.stringify({ marks: { "aa:app": 2 }, futureKey: { anything: 1 }, revoked: [] }));
    const round = JSON.parse(legacy.serialize());
    assertEqual(round.marks["aa:app"], 2, "a store carrying an unknown key still loads its marks");
    assert(round.futureKey === undefined, "…and is rewritten without it");
  }

  console.log("  OK\n");
}

async function testShellBoot() {
  console.log("Test: seedkernel-shell boots under a policy and wires its capability backends");
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = testAuthor();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-shell-"));
  let shell;
  try {
    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.id)] }),
      dir,
      identity, // dial-only: no listen/wsListen, so start() binds nothing
    });
    // Admitting an allowed author's code is the bundle path, covered end-to-end by
    // testBundle (§12.4).
    assert((await shell.fs.list()).length === 0, "fs.* backend is wired over the data dir");
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: app bundle — signed manifest + governed load (step 6) ────────

async function testBundle() {
  console.log("Test: app bundle — signed manifest, integrity, governed load by the shell");
  const { signManifest, verifyManifest, packBundle, MANIFEST_FILE, GUEST_FILE, moduleFile }
    = await imp("build/host/bundle.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = testAuthor();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-bundle-"));
  const bundlePath = pjoin(dir, "app.skb");
  let shell, shell2;
  try {
    // A minimal one-module bundle (forwarder.wasm) plus a guest stub. Modules install
    // straight from the manifest (§12.4) under the app key the loader DERIVES from the
    // signed `(author, app)` pair, each at its own logical name — so the manifest declares
    // no bind name and names no file: they are `<name>.wasm` and `guest.js`.
    const { host: h } = await makeHost();
    const testKey = appKey(author.id, "test");
    const guestText = "function handle() { return new Uint8Array([1]); }";
    const manifest = {
      app: "test", version: 1,
      modules: [{ name: "codec", hash: toHex(gHash(forwarderBytes)) }],
      // requires + config live INSIDE guest (§12.4) — a bundle's authority is the guest's.
      guest: {
        hash: toHex(gHash(new TextEncoder().encode(guestText))),
        abi: GUEST_ABI_VERSION,
        requires: [],
      },
    };
    const writeBundle = (m) => wf(bundlePath, packBundle({
      [MANIFEST_FILE]: signManifest(sodium, author, m),
      [moduleFile("codec")]: forwarderBytes,
      [GUEST_FILE]: new TextEncoder().encode(guestText),
    }));
    writeBundle(manifest);

    // sign / verify / tamper
    const env = signManifest(sodium, author, manifest);
    assert(verifyManifest(sodium, env) !== null, "a well-formed manifest verifies");
    const tampered = env.slice(); tampered[tampered.length - 1] ^= 1;
    assert(verifyManifest(sodium, tampered) === null, "a tampered manifest fails verification");

    // A manifest whose module names collide is ambiguous (the name keys both the
    // container and the guest's module map), so it is refused even though it is
    // validly signed (§12.4).
    const dupEnv = signManifest(sodium, author, {
      ...manifest,
      modules: [manifest.modules[0], { ...manifest.modules[0] }],
    });
    let dupRefused = false;
    try { verifyManifest(sodium, dupEnv); } catch { dupRefused = true; }
    assert(dupRefused, "a manifest with duplicate module names is refused as malformed");

    // booted shell, policy allows the author → bundle loads + module installs
    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.id)] }),
      dir: pjoin(dir, "_data"), identity,
    });
    const loaded = await shell.loadBundle(bundlePath);
    assert(loaded.guestSource.includes("function handle"), "guest source loaded + integrity-checked");

    // Freshness (§12.4): version is an enforced monotonic high-water per (author, app),
    // set to 1 by the load above.
    const remanifest = (version) => writeBundle({ ...manifest, version });
    remanifest(1); await shell.loadBundle(bundlePath); // equal version reloads (an ordinary reboot)
    remanifest(2); await shell.loadBundle(bundlePath); // newer version advances the mark to 2
    remanifest(1);                                // now a downgrade
    let downgradeRefused = false;
    try { await shell.loadBundle(bundlePath); } catch { downgradeRefused = true; }
    assert(downgradeRefused, "a version below the (author, app) high-water mark is refused as a downgrade");
    remanifest(2); await shell.loadBundle(bundlePath);  // the mark held at 2, so v2 still loads
    remanifest(1);                                // restore the original for the shell2 check below

    // a shell whose policy does NOT allow the author refuses the bundle
    shell2 = await boot({
      policyJson: JSON.stringify({ authors: [toHex(generateKeyPair().publicKey)] }),
      dir: pjoin(dir, "_data2"), identity,
    });
    let refused = false;
    try { await shell2.loadBundle(bundlePath); } catch { refused = true; }
    assert(refused, "a bundle from a non-allowed author is refused");
  } finally {
    if (shell) shell.close();
    if (shell2) shell2.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: every app is a guest (§12.4) + the verify/install split ────
// A chat-style app is a guest plus its module; since requires live inside `guest`, an
// empty list IS declaring zero authority. Covers the one app shape (guestSource
// round-trips), a bundle blob round-tripping as one value, and `verifyBundle`
// authenticating + integrity-checking WITHOUT a host or policy — the seam the browser
// shell peeks a received Offer through before asking for consent.
async function testGuestBundleAndArchive() {
  console.log("Test: every app is a guest — bundle blob + verify/install split");
  const { signManifest, verifyManifest, verifyBundle,
          packBundle, unpackBundle, MANIFEST_FILE, moduleFile }
    = await imp("build/host/bundle.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = testAuthor();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-guest-"));
  const bundlePath = pjoin(dir, "demo.skb");
  let shell;
  try {
    const { host: h } = await makeHost();
    const demoKey = appKey(author.id, "demo");
    // A manifest with NO `guest` field is refused: every app is a guest (§12.4).
    let noGuest = "";
    try {
      verifyManifest(sodium, signManifest(sodium, author,
        { app: "demo", version: 1, modules: [{ name: "demo", hash: toHex(gHash(forwarderBytes)) }] }));
    } catch (e) { noGuest = e.message; }
    assert(noGuest.includes("every app is a guest"), `a manifest without a guest is refused by name (got: ${noGuest})`);

    const manifest = {
      app: "demo", version: 1,
      modules: [{ name: "demo", hash: toHex(gHash(forwarderBytes)) }],
      guest: GUEST(),
    };
    const manifestEnv = signManifest(sodium, author, manifest);
    assert(verifyManifest(sodium, manifestEnv) !== null, "a manifest with a guest verifies");

    // Blob round-trip: a bundle IS one blob, and this is what an Offer carries over a
    // data channel and what the loader reads from disk — one format, one path.
    const packed = packBundle({
      [MANIFEST_FILE]: manifestEnv,
      [moduleFile("demo")]: forwarderBytes,
      [GUEST_FILE]: GUEST_BYTES,
    });
    const files = unpackBundle(packed);
    assert(bytesEqual(files[MANIFEST_FILE], manifestEnv), "packed manifest round-trips");
    assert(bytesEqual(files[moduleFile("demo")], forwarderBytes), "packed module round-trips");
    let badArchive = false;
    try { unpackBundle(new Uint8Array([1, 2, 3])); } catch { badArchive = true; }
    assert(badArchive, "a non-bundle blob is rejected fail-loud");

    // The verify half on its own: no host, no policy, no freshness — the browser
    // shell's peek path. It authenticates and yields every verified byte.
    const v = verifyBundle(sodium, packed);
    assert(bytesEqual(v.author, author.id), "verifyBundle returns the signing author");
    assertEqual(v.modules.length, 1, "verifyBundle yields the manifest's modules");
    assertEqual(v.guestSource, GUEST_TEXT, "verifyBundle yields the verified guest source");
    // Corrupting a module must fail integrity even though the manifest still verifies.
    const corrupt = packBundle({
      [MANIFEST_FILE]: manifestEnv,
      [moduleFile("demo")]: forwarderBytes.slice(0, forwarderBytes.length - 1),
      [GUEST_FILE]: GUEST_BYTES,
    });
    let integrityFailed = false;
    try { verifyBundle(sodium, corrupt); }
    catch { integrityFailed = true; }
    assert(integrityFailed, "a module that does not match its declared hash fails integrity");
    // Corrupting the guest fails the same way — the guest is signed content too.
    const corruptGuest = packBundle({
      [MANIFEST_FILE]: manifestEnv,
      [moduleFile("demo")]: forwarderBytes,
      [GUEST_FILE]: GUEST_BYTES.slice(0, GUEST_BYTES.length - 1),
    });
    let guestIntegrityFailed = false;
    try { verifyBundle(sodium, corruptGuest); }
    catch { guestIntegrityFailed = true; }
    assert(guestIntegrityFailed, "a guest that does not match its declared hash fails integrity");

    // Load the bundle through the shared §12.4 loader.
    wf(bundlePath, packed);
    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.id)] }),
      dir: pjoin(dir, "_data"), identity,
    });
    const loaded = await shell.loadBundle(bundlePath);
    assertEqual(loaded.guestSource, GUEST_TEXT, "the shell yields the verified guest source");
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: safe-js zero-authority JS confinement (§2.1) ─────────────────
// Run zero-authority guest JS over a single host-call seam. Three load-bearing properties,
// over stand-in seams: airtight by construction, the async seam + byte boundary, and realm
// isolation.

async function testSafeJs() {
  console.log("Test: safe-js — zero-authority JS confinement (§2.1)");

  // 1. Airtight: the guest cannot name fs/net/Bun/process/fetch/require, and
  //    dynamic import() is unavailable (no module loader).
  {
    const DANGER = ["Bun", "process", "require", "fetch", "Buffer", "WebAssembly", "globalThis"];
    const probeSrc = `
      function handle() {
        const names = ${JSON.stringify(DANGER)};
        const out = new Uint8Array(names.length);
        for (let i = 0; i < names.length; i++) {
          try { out[i] = (typeof globalThis[names[i]] === "undefined") ? 0 : 1; }
          catch { out[i] = 2; }
        }
        return out;
      }
    `;
    const realm = await createSafeRealm({ source: probeSrc, hostCall: async () => new Uint8Array() });
    const res = await realm.call(new Uint8Array());
    for (let i = 0; i < DANGER.length - 1; i++) {
      assertEqual(res[i], 0, `${DANGER[i]} is unreachable in the realm`);
    }
    assert(res[DANGER.length - 1] === 1, "globalThis exists (the realm's own, no authority)");
    realm.dispose();
  }
  {
    const src = `
      async function handle() {
        try { await import("node:fs"); return new Uint8Array([1]); }
        catch { return new Uint8Array([0]); }
      }
    `;
    const realm = await createSafeRealm({ source: src, hostCall: async () => new Uint8Array() });
    const res = await realm.call(new Uint8Array());
    assertEqual(res[0], 0, "import('node:fs') rejects — no path out of the realm");
    realm.dispose();
  }

  // 2. The seam: a sync name returns bytes directly (no yield); a net-like name returns a
  //    real Promise the guest awaits. Bytes round-trip across the copy boundary both ways.
  {
    let hostCalls = 0;
    const hostCall = (name, payload) => {
      hostCalls++;
      if (name === "inc") return payload.map((b) => (b + 1) & 0xff);                          // sync name — bytes directly
      if (name === "slow") return sleep(3).then(() => payload.map((b) => (b + 1) & 0xff));     // net-like name — a Promise
      return new Uint8Array();
    };
    const src = `
      function handle(a) {
        const sel = a[0], arg = a.subarray(1);
        if (sel === 1) return host.call("inc", arg);                  // sync name: host.call returns bytes, no await
        if (sel === 2) return (async () => await host.call("slow", arg))();  // net-like name: a genuinely awaited Promise
        throw new Error("no such sel " + sel);
      }
    `;
    const realm = await createSafeRealm({ source: src, hostCall });
    const input = new Uint8Array([0, 1, 2, 254, 255]);
    const U = (...xs) => new Uint8Array(xs);
    const sync = await realm.call(U(1, ...input));
    assertEqual([...sync], [1, 2, 3, 255, 0], "sync name: bytes crossed in and back with no promise");
    const asyncR = await realm.call(U(2, ...input));
    assertEqual([...asyncR], [1, 2, 3, 255, 0], "net-like name: await host.call resolves the real Promise");
    assert(hostCalls === 2, "the host seam was invoked for each call");
    const again = await realm.call(U(1, 10));
    assertEqual([...again], [11], "realm is reusable across calls");
    realm.dispose();
  }

  // 3. Orchestration control-flow shapes run as ordinary async guest JS, including a
  //    concurrent fan-out with the guest's own Promise.all over a net-like name — the
  //    real-promise seam is what makes this possible in one realm.
  {
    const hostCall = (name, payload) => {
      const peer = payload[0];
      if (name === "offer") return sleep(1).then(() => new Uint8Array([peer % 2 === 0 ? 1 : 0]));
      if (name === "have") return sleep(1).then(() => new Uint8Array([peer % 3 === 0 ? 1 : 0]));
      return new Uint8Array();
    };
    const src = `
      async function handle(arg) {
        const count = arg[0], peerCount = arg[1];
        // Fan out OFFERs concurrently — the guest's own Promise.all, no host sendMany.
        const offers = await Promise.all(
          Array.from({ length: peerCount }, (_, p) => host.call("offer", new Uint8Array([p]))),
        );
        const placed = [];
        for (let p = 0; p < peerCount && placed.length < count; p++) {
          if (offers[p][0] === 1) placed.push(p);
        }
        const haves = await Promise.all(
          Array.from({ length: peerCount }, (_, p) => host.call("have", new Uint8Array([p]))),
        );
        const holders = haves.filter((h) => h[0] === 1).length;
        return new Uint8Array([placed.length, holders, ...placed]);
      }
    `;
    const realm = await createSafeRealm({ source: src, hostCall });
    const res = await realm.call(new Uint8Array([3, 10]));
    assertEqual(res[0], 3, "loop placed exactly `count` blocks on distinct peers");
    assertEqual([...res.slice(2)], [0, 2, 4], "placement followed peer order and the accept rule");
    assertEqual(res[1], 4, "concurrent have/want fan-out (Promise.all) collected the right holders");
    realm.dispose();
  }

  // 4. Realm isolation: a poisoned guest cannot reach a sibling's global.
  {
    const a = await createSafeRealm({
      source: `globalThis.SECRET = 42; function handle() { return new Uint8Array([globalThis.SECRET ?? 0]); }`,
      hostCall: async () => new Uint8Array(),
    });
    const b = await createSafeRealm({
      source: `function handle() { return new Uint8Array([globalThis.SECRET ?? 0]); }`,
      hostCall: async () => new Uint8Array(),
    });
    const ra = await a.call(new Uint8Array());
    const rb = await b.call(new Uint8Array());
    assertEqual(ra[0], 42, "realm A sees its own global");
    assertEqual(rb[0], 0, "realm B does not see realm A's global");
    a.dispose();
    b.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: one entry seam, serialized per realm (§12.3) ─────────────────
// One way in, `call`, which may yield. That one invocation runs to completion before the
// next begins is the realm's own FIFO queue (host/realm-queue.ts) rather than a property
// of the host's call stack — which is what a synchronous entry used to give for free.

async function testRealmSerialization() {
  console.log("Test: one entry seam, serialized per realm (§12.3)");

  // 1. A synchronous entrypoint over a synchronous seam still round-trips, and the
  //    realm is reusable — it just resolves through a promise like everything else.
  {
    let calls = 0;
    const hostCall = (name, payload) => { calls++; return name === "inc" ? payload.map((b) => (b + 1) & 0xff) : new Uint8Array(); };
    const realm = await createSafeRealm({
      source: `function handle(arg) { return host.call("inc", arg); }`,
      hostCall,
    });
    const out = await realm.call(new Uint8Array([0, 9, 255]));
    assertEqual([...out], [1, 10, 0], "sync host.call round-trips through the copy boundary");
    assertEqual([...(await realm.call(new Uint8Array([41])))], [42], "the realm is reusable across calls");
    assertEqual(calls, 2, "the synchronous seam was invoked once per call");
    realm.dispose();
  }

  // 2. An invocation accepted while another is parked mid-await waits for the queue
  //    rather than interleaving. Worth its head-of-line cost: two frames resuming into
  //    each other at every await is state no guest author can reason about.
  {
    let release;
    const gate = new Promise((r) => { release = r; });
    const hostCall = (name, payload) => {
      if (name === "park") return gate.then(() => new Uint8Array([42]));   // parks until released
      if (name === "inc") return payload.map((b) => (b + 1) & 0xff);       // sync — holder path
      return new Uint8Array();
    };
    const realm = await createSafeRealm({
      source: `function handle(a) {
                 if (a[0] === 1) return (async () => await host.call("park", new Uint8Array()))();
                 if (a[0] === 2) return host.call("inc", a.subarray(1)); // sync — holder path
                 throw new Error("no such sel " + a[0]);
               }`,
      hostCall,
    });
    const order = [];
    const initP = realm.call(new Uint8Array([1])).then((r) => { order.push("init"); return r; });
    const heldP = realm.call(new Uint8Array([2, 7])).then((r) => { order.push("hold"); return r; });

    // Give the holder every chance to jump the queue before the initiator is released.
    for (let i = 0; i < 10; i++) await Promise.resolve();
    assertEqual(order.length, 0, "the holder did not run while the initiator was parked");

    release();
    assertEqual([...(await initP)], [42], "the parked initiator resumed and settled");
    assertEqual([...(await heldP)], [8], "and the holder ran after it, on its own budget");
    assertEqual(order.join(","), "init,hold", "the queue preserved acceptance order");
    realm.dispose();
  }

  // 3. Still airtight — the one seam is the same zero-authority sandbox.
  {
    const realm = await createSafeRealm({
      source: `function handle() { return new Uint8Array([typeof globalThis.process === "undefined" ? 0 : 1, typeof globalThis.fetch === "undefined" ? 0 : 1]); }`,
      hostCall: async () => new Uint8Array(),
    });
    const r = await realm.call(new Uint8Array());
    assertEqual([...r], [0, 0], "process / fetch are unreachable from an entrypoint");
    realm.dispose();
  }

  // 4. Disposing a realm while an invocation is parked mid-await — the ordinary state of
  //    a node whose initiator waits on the network — fails the parked caller and frees
  //    the context WITHOUT taking the wasm module with it: the engine asserts an empty gc
  //    object list when a runtime is freed, and a parked call releases its handle from a
  //    `finally` that runs as a microtask after dispose() returns, so freeing the context
  //    in the same turn aborts the whole module. Hence the deferred teardown, pinned here.
  {
    const realm = await createSafeRealm({
      source: `async function handle() { await host.call("park", new Uint8Array()); }`,
      hostCall: (name) => (name === "park" ? new Promise(() => {}) : new Uint8Array()),  // never settles
    });
    const parked = realm.call(new Uint8Array());
    for (let i = 0; i < 10; i++) await Promise.resolve();   // let it reach its await
    realm.dispose();

    let msg = "";
    try { await parked; } catch (e) { msg = e.message; }
    assertEqual(msg, "guest realm disposed", "the parked invocation is failed by dispose, not stranded");
    let after = "";
    try { await realm.call(new Uint8Array()); } catch (e) { after = e.message; }
    assertEqual(after, "guest realm disposed", "a call accepted after dispose is refused, not run");

    // A realm built after the deferred teardown has run proves the module survived it.
    await sleep(1);
    const next = await createSafeRealm({
      source: `function handle(arg) { return arg; }`,
      hostCall: async () => new Uint8Array(),
    });
    assertEqual([...(await next.call(new Uint8Array([7])))], [7],
      "the engine is still alive after the parked realm's context was freed");
    next.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: PR-review hardening — seam gating, guarded callModule, ───────
// ─── sender-bound responses, WS fragmentation, redial after failure ──────

async function testSeamGating() {
  console.log("Test: the guest seam enforces the manifest's declared requires + allocation caps");

  const id = generateKeyPair();
  const stubTransport = { request: async (_peer, _proto, _payload) => new Uint8Array() };
  const mk = (names) => createGuestSeam({
    platform: { sodium, identity: id, peers: () => [] },
    grants: { names, signScope: appSignScope(id, new Uint8Array(32), "probe"), transport: stubTransport, fs: new MemoryFs() },
    modules: { names: new Set(), call: () => null },
  });
  const U = (...xs) => new Uint8Array(xs);
  let threw = false;

  // A PRIMITIVE is exempt from the gate by a rule about one prefix: `crypto/` reaches
  // nothing, so there is nothing to grant. A seam built for a bundle declaring NO
  // names still hashes.
  const clockOnly = mk(["clock"]);
  assertEqual((await clockOnly("crypto/blake2b-256", U(1, 2))).length, 32,
    "crypto/blake2b-256 resolves for a bundle declaring no crypto name — a pure transform is not a grant");
  threw = false;
  try { await clockOnly("crypto/no-such-primitive", U(1)); } catch { threw = true; }
  assert(threw, "an unknown crypto name is refused by name (this host cannot serve it)");
  // A bare name is the asking bundle's own module map — code it already holds, scoped by
  // the app key the seam was built with — so it passes the gate under an empty requires
  // set. This seam's `hasModule` says no, so it is refused for NOT EXISTING rather than
  // for not being declared, and the message is the assertion.
  let gateMsg = "";
  try { await clockOnly("echo", U(1, 120)); } catch (e) { gateMsg = e.message; }
  assert(gateMsg.includes("no module by that name"),
    `a bare name passes the gate ungated and fails only on existence (got: ${gateMsg})`);

  // Grants are gated by SERVICE, not by method: declaring `clock` resolves `clock/now`,
  // and a different, undeclared service is still refused beside it.
  threw = false;
  try { await clockOnly("node/sign", U(1)); } catch { threw = true; }
  assert(threw, "an undeclared service (node) is refused by the seam");
  threw = false;
  try { await clockOnly("fs/delete", U(120)); } catch { threw = true; }
  assert(threw, "an undeclared service (fs) is refused by the seam");
  threw = false;
  try { await clockOnly("clock/now", U()); } catch { threw = true; }
  assert(!threw, "clock/now resolves under the declared service");

  // The unit a manifest grants is the WHOLE service: declaring `node` grants every
  // `node/*` method — `node/identity` beside `node/sign` included — because there was
  // never a finer boundary anyone held (§12.2).
  const nodeOnly = mk(["node"]);
  assertEqual((await nodeOnly("node/sign", U(1, 2))).length, 64, "node/sign resolves under the declared service");
  assertEqual((await nodeOnly("node/identity", U())).length, 32, "…and so does node/identity, the SAME declared service");
  threw = false;
  try { await nodeOnly("fs/get", U(120)); } catch { threw = true; }
  assert(threw, "a different, undeclared service (fs) is still refused beside the declared one");

  // Declaring the method's exact STRING is not declaring its service: the gate checks
  // `serviceOf(name)` against the declared set, so a manifest naming `node/sign` (rather
  // than `node`) grants nothing at all — `requires` speaks in services.
  const methodNameOnly = mk(["node/sign"]);
  threw = false;
  try { await methodNameOnly("node/sign", U(1, 2)); } catch { threw = true; }
  assert(threw, "declaring a method's exact name, not its service, grants nothing");

  // guest-controlled allocation caps. UNRESTRICTED_NAMES is the host-side caller that
  // opts out of gating *by name* — omitting grants.names entirely now throws (§12.2).
  const open = mk(UNRESTRICTED_NAMES);
  let omitted = false;
  try { mk(undefined); } catch { omitted = true; }
  assert(omitted, "omitting grants.names throws rather than granting every name");
  assertEqual((await open("node/random", U(0, 0, 4, 0))).length, 1024, "node/random under the cap works");
  threw = false;
  try { await open("node/random", U(0xff, 0xff, 0xff, 0xff)); } catch { threw = true; }
  assert(threw, "node/random over the cap is refused");

  // The vocabulary is closed at LOAD, not at first use: an unknown name in a manifest is
  // a refused bundle (verifyManifest), and the seam answers "no such name" besides.
  threw = false;
  try { await open("transform/do", U()); } catch { threw = true; }
  assert(threw, "`transform` is gone from the vocabulary — a manifest naming it is refused");

  console.log("  OK\n");
}

async function testCallModuleGuards() {
  console.log("Test: ModuleTable.callModule resolves by name, or null when unbound (§4)");

  const { host } = await makeHost();
  const { publicKey: pk } = generateKeyPair();
  const guards = appKey(pk, "guards");

  // An unbound module resolves to null, distinct from an empty response — and so does a
  // module under an app that was never installed: neither is a thing that exists.
  assert(await host.callModule(guards, "missing", new Uint8Array([1])) === null,
    "callModule returns null for an unbound module");
  assert(await host.callModule(appKey(pk, "nope"), "echo", new Uint8Array([1])) === null,
    "callModule returns null for an app that installed nothing");

  // An installed module is reached by name. A confined guest reaches the same module
  // through the guest seam by its bare name (§12.2).
  await installMod(host, guards, "echo", forwarderBytes);
  const r = await host.callModule(guards, "echo", new Uint8Array([5]));
  assertEqual([...r], [5], "callModule reaches an installed module");

  // A 0-length response is a valid EMPTY answer, not the null of an unbound name, so a
  // caller can tell "module ran, said nothing" from "nothing there".
  const empty = await host.callModule(guards, "echo", EMPTY);
  assert(empty !== null && empty.length === 0,
    "an empty response is an empty array, distinct from null");

  console.log("  OK\n");
}

// ─── Test: a module call is bounded — the §4.3 compute residual, closed ──────────
// The JS platform's WebAssembly exposes no fuel or timeout, so a module call in the host
// thread that never returned would wedge the node irrecoverably — a restart would
// re-trigger it from the same inbound frame. The worker-per-module table closes that: a
// spinning module answers EMPTY at its deadline, the host thread stays alive, and a fresh
// instance serves the next call.
async function testModuleCallBound() {
  console.log("Test: a spinning module is killed at its deadline and respawned (§4.3)");

  const { ModuleTable } = await imp("build/host/module-table.js");
  const { SPIN_WASM } = await import("./fixtures/spin-wasm.mjs");
  const { publicKey: pk } = generateKeyPair();
  const spinKey = appKey(pk, "spin");

  // The default table bound is generous; a bounded host is the deployment's number. The
  // call's OWN deadline is what a guest's call carries — the guest's remaining segment.
  const host = testHost(new ModuleTable({ deadlineMs: 60_000 }));
  await host.bindAll(spinKey, [{ name: "spin", wasm: SPIN_WASM }]);
  assert(host.isBound(spinKey, "spin"), "the spinning module binds (its memory is bounded at admission)");

  // The host thread is never blocked: timers keep firing while the module spins in its
  // worker. Running the call in this thread would let a spinner wedge everything,
  // transport included.
  let heartbeats = 0;
  const beats = setInterval(() => heartbeats++, 25);

  const t0 = Date.now();
  // A 120 ms bound. Null at the table — exactly what a trap produces — which the guest
  // seam reads as empty BYTES, so nothing downstream changes.
  const r = await host.callModule(spinKey, "spin", new Uint8Array([1]), 120);
  const spent = Date.now() - t0;
  clearInterval(beats);

  assert(r === null, "the spin answers like a trap — null at the table, empty bytes at the seam");
  assert(spent >= 100 && spent < 3000, `it is killed near its bound, not eventually (${spent}ms)`);
  assert(heartbeats > 0, "the host thread was alive the whole time the module spun");

  // A fresh instance serves the next call: the kill terminated the old worker and a
  // respawn stands a new one in, statics gone.
  await host.bindAll(spinKey, [{ name: "spin", wasm: forwarderBytes }]);
  const echo = await host.callModule(spinKey, "spin", new Uint8Array([9]), 1000);
  assertEqual([...echo], [9], "a module called again after a kill-and-respawn still runs");

  // Two calls to the SAME module cannot run at once: the table keeps one in flight per
  // module (§3, "one transform at a time"), so a spinner burns one core for one bound.
  const host2 = testHost(new ModuleTable());
  await host2.bindAll(spinKey, [{ name: "spin", wasm: SPIN_WASM }]);
  const t1 = Date.now();
  const [a, b] = await Promise.all([
    host2.callModule(spinKey, "spin", new Uint8Array(), 80),
    host2.callModule(spinKey, "spin", new Uint8Array(), 80),
  ]);
  const serial = Date.now() - t1;
  assert(a === null && b === null,
    "both spins answered like traps, at their own deadlines");
  assert(serial >= 140 && serial < 5000, `the two calls ran one after the other (${serial}ms)`);
  // …and the module still answers after two kills in a row, on ONE worker: the respawn a
  // kill starts and the respawn the queued call would start are the same load
  // (`ModuleTable.respawn`), and two loads per kill would leak an idle never-terminated
  // worker (invisible: an unref'd worker is absent from `getActiveResourcesInfo`).
  await host2.bindAll(spinKey, [{ name: "spin", wasm: forwarderBytes }]);
  const after = await host2.callModule(spinKey, "spin", new Uint8Array([3]), 1000);
  assertEqual([...after], [3], "the module answers on its one respawned worker after two kills");
  host2.removeApp(spinKey);

  // An unbounded call is an operator's explicit opt-out: Infinity disables the bound,
  // and the worker then spins until the app is dropped — the host stays responsive, and
  // dropping the app settles the in-flight call as empty rather than stranding it.
  const host3 = testHost(new ModuleTable({ deadlineMs: Infinity }));
  await host3.bindAll(spinKey, [{ name: "spin", wasm: SPIN_WASM }]);
  let beats3 = 0;
  const beats3Timer = setInterval(() => beats3++, 25);
  const forever = host3.callModule(spinKey, "spin", new Uint8Array(), Infinity);
  await sleep(60);
  clearInterval(beats3Timer);
  assert(beats3 > 0, "host alive with an unbounded spin in flight");
  host3.removeApp(spinKey);
  const dropped = await forever;
  assert(dropped === null, "removing the app settles the in-flight spin as a trap would");

  console.log("  OK\n");
}

// ─── Test: the guest's module call runs under the guest's own budget ─────────────
//
// "Charged to the calling guest's budget" (§4.3) made literal: the realm computes the
// caller's remaining execution segment at the moment of the call and hands it to the
// module as the call's deadline. A guest that has already spent most of its budget gets
// a module call killed far sooner than the deployment's default bound.
async function testModuleCallChargedToGuestBudget() {
  console.log("Test: a module call is charged to the calling guest's remaining segment (§4.3)");

  const { ModuleTable } = await imp("build/host/module-table.js");
  const { SPIN_WASM } = await import("./fixtures/spin-wasm.mjs");
  const { createGuestSeam, UNRESTRICTED_NAMES } = await imp("build/host/guest-seam.js");
  const { createSafeRealm } = await imp("build/host/safe-js.js");
  const id = generateKeyPair();

  const host = testHost(new ModuleTable({ deadlineMs: 60_000 }));
  const spinKey = appKey(id.publicKey, "app");
  await host.bindAll(spinKey, [{ name: "spin", wasm: SPIN_WASM }]);
  const seam = createGuestSeam({
    platform: { sodium, identity: id },
    grants: { names: UNRESTRICTED_NAMES },
    modules: {
      names: new Set(["spin"]),
      call: (n, p, deadlineMs) => host.slots.get(spinKey)?.call(n, p, deadlineMs) ?? Promise.resolve({ bytes: null, ms: 0 }),
    },
  });
  // The realm's budget is 5 s, but the guest burns most of it before calling the module:
  // the call must then be killed near what remains, not at the table's 60 s.
  const realm = await createSafeRealm({
    source: `async function handle() {
      const t0 = Date.now();
      while (Date.now() - t0 < 4900) { /* burn the segment */ }
      return await host.call("spin", new Uint8Array());
    }`,
    hostCall: seam,
    deadlineMs: 5000,
  });
  const t0 = Date.now();
  const out = await realm.call(new Uint8Array());
  const spent = Date.now() - t0;
  realm.dispose();
  assert(out !== null && out.length === 0, "the module answered empty at the guest's deadline");
  // The burn is ~4.9s, so the whole call is ~5s; the module itself died at the ~100ms
  // that remained, NOT at the table's 60s default — a broken deadline flow would hang
  // this call for a minute instead.
  assert(spent >= 4800 && spent < 8000,
    `the call died with the guest's remaining budget, not the table's (${spent}ms)`);

  // The other half of "charged": what a module BURNS is billed back to the segment that
  // called it, and a segment with nothing left refuses the next call. Both halves are
  // needed — the guest is parked while the module runs, so its own spend advances by
  // microseconds per turn, and QuickJS's interrupt is consulted per bytecode, of which
  // this guest executes almost none between parks.
  const looper = await createSafeRealm({
    source: `async function handle() {
      for (;;) await host.call("spin", new Uint8Array());
    }`,
    hostCall: seam,
    deadlineMs: 1000,
  });
  const t1 = Date.now();
  let killed = "";
  try { await looper.call(new Uint8Array()); }
  catch (e) { killed = e.message; }
  const looped = Date.now() - t1;
  looper.dispose();
  assert(killed.includes("budget exhausted"),
    `a guest looping on a spinning module is refused, not endless (ran ${looped}ms, got: ${killed || "no throw"})`);
  // ~1 s of module burn spends the 1 s budget, and the next turn throws. The upper bound
  // is what fails if either half is dropped.
  assert(looped >= 900 && looped < 6000,
    `the guest died once the module burn added up to its budget (${looped}ms)`);

  console.log("  OK\n");
}

// ─── Test: the seam version just retired is refused, not tolerated ───────────────
//
// The number is only worth carrying if the host refuses a seam it does not implement, and
// the case that matters is always the one just retired — the population that actually
// exists. A guest written against the previous seam calls names this host no longer has,
// or reads a shape it no longer sends; tolerating it would run a program against a
// contract neither side agreed to, and the failure that follows is silent (a name that
// answers nothing, a field read at the wrong offset). Written against the constant, so
// the boundary moves with the seam rather than pinning whichever version was current the
// day this was written.
async function testPreviousAbiRefused() {
  const stale = GUEST_ABI_VERSION - 1;
  console.log(`Test: guest ABI ${stale} is refused at load — a retired seam is not tolerated`);

  const author = testAuthor();
  const manifest = { app: "legacy", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
    guest: { hash: "aa", abi: stale, requires: [] } };
  const env = signManifest(sodium, author, manifest);
  const blob = packBundle({
    [MANIFEST_FILE]: env,
    [moduleFile("fwd")]: forwarderBytes,
    [GUEST_FILE]: GUEST_BYTES,
  });
  let msg = "";
  try { verifyBundle(sodium, blob); } catch (e) { msg = e.message; }
  assert(msg.includes(`guest ABI ${stale} is not implemented`),
    `ABI ${stale} is refused by name (got: ${msg || "no throw"})`);
  assert(msg.includes(String(GUEST_ABI_VERSION)), "the refusal names the supported ABI");

  console.log("  OK\n");
}

async function testSafeRealmConcurrency() {
  console.log("Test: concurrent call()s on one safe-js realm interleave without __arg clobber");

  // No Asyncify, so overlapping initiator calls are allowed to run concurrently. Each
  // call stages __arg and consumes it synchronously (before the first await) during its
  // evalCode, so a second call staging __arg can never corrupt the first's captured arg —
  // no host-side serialization needed.
  const realm = await createSafeRealm({
    source: `async function handle(a) { return await host.call("echo", a); }`,
    hostCall: (_name, p) => sleep(10).then(() => p),
  });
  try {
    const [r1, r2] = await Promise.all([
      realm.call(new Uint8Array([1])),
      realm.call(new Uint8Array([2])),
    ]);
    assertEqual([...r1], [1], "first concurrent call returns its own bytes");
    assertEqual([...r2], [2], "second concurrent call returns its own bytes");
  } finally {
    realm.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: manifest suite byte — signed, so it cannot be edited in flight ────────
//
// The suite byte leads the §12.4 envelope and is part of the signed preimage
// `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖ json`. That is what makes it safe to read
// the byte *before* verifying: a verifier needs it to know the field widths, and the
// signature it then checks commits to the same byte, so rewriting it only breaks the
// manifest. Algorithm confusion with a later suite is unrepresentable (§14.1).
//
// There is ONE live suite (§12.4), `0x02`. The retired Ed25519-only `0x01` is refused as
// a suite this host does not implement, which is what keeps the retirement from being a
// downgrade path an attacker can ask for.
async function testManifestSuiteByte() {
  console.log("Test: manifest suite byte — signed preimage, so an edited suite cannot verify");
  const { signManifest, verifyManifest } = await imp("build/host/bundle.js");

  const author = testAuthor();
  // One module: this test is about the suite byte, not the module count.
  const manifest = { app: "suite-probe", version: 1, modules: [{ name: "fwd", hash: "aa" }], guest: { hash: "aa", abi: GUEST_ABI_VERSION, requires: [] } };
  const env = signManifest(sodium, author, manifest);

  // Layout: the suite byte leads, and the author's Ed25519 key follows it (not at
  // offset 0). The rest of the envelope is testHybridManifestSuite's subject.
  assertEqual(env[0], 0x02, "the envelope opens with the one manifest suite id");
  assertEqual(toHex(env.slice(1, 33)), toHex(author.ed.publicKey), "the Ed25519 key follows the suite byte");

  // 1. Untouched, it verifies and returns the author id + manifest.
  {
    const v = verifyManifest(sodium, env);
    assert(v !== null, "an untouched manifest verifies");
    assertEqual(toHex(v.author), toHex(author.id), "the derived author id round-trips");
    assertEqual(v.manifest.app, "suite-probe", "the manifest round-trips");
  }

  // 2. A suite this host does not implement is refused with its own message, not as a bad
  //    signature — which would misdirect an operator whose real problem is a bundle built
  //    for a host they are not running. `0x01` goes by the same rule as `0x7f`; there is
  //    no retired-suite special case.
  for (const suite of [0x01, 0x7f]) {
    const bad = env.slice(); bad[0] = suite;
    let msg = "";
    try { verifyManifest(sodium, bad); } catch (e) { msg = String(e.message); }
    assert(msg.includes("unsupported manifest suite"),
      `suite 0x${suite.toString(16)} reports itself (got: ${msg || "no throw"})`);
    assert(!msg.includes("signature"), "an unimplemented suite is not reported as a signature failure");
  }

  // 3. A whole, validly-signed 0x01 envelope — the shape a bundle built against the
  //    retired suite actually has — is refused the same way. The retirement is a property
  //    of the verifier, not of the fact that nobody happens to hold such a bundle.
  {
    const json = new TextEncoder().encode(JSON.stringify(manifest));
    const pre = concatBytes([new TextEncoder().encode("seedkernel-manifest-sig-v1\0"), Uint8Array.of(0x01), json]);
    const sig = sodium.crypto_sign_detached(pre, author.ed.privateKey);
    const legacyEnv = concatBytes([Uint8Array.of(0x01), author.ed.publicKey, sig, json]);
    let msg = "";
    try { verifyManifest(sodium, legacyEnv); } catch (e) { msg = String(e.message); }
    assert(msg.includes("unsupported manifest suite 0x01"),
      `a well-formed genesis-suite envelope is refused by suite (got: ${msg || "no throw"})`);
  }

  // 4. The load-bearing property: the suite byte is inside the signed preimage, so
  //    tampering anywhere in the envelope breaks the signature rather than the parse.
  {
    const forged = env.slice();
    forged[33] ^= 0x01; // flip a byte of the ML-DSA public key → must not verify
    assert(verifyManifest(sodium, forged) === null, "a tampered envelope does not verify");
  }

  console.log("  OK\n");
}

// ─── Test: ML-DSA-65 against NIST's own vectors (ACVP known-answer test) ─────────
//
// A round trip — sign, verify, flip a bit, verify again — is satisfied by an
// implementation that is wrong but self-consistent, and says nothing about whether two
// targets will agree. These are NIST's published ACVP vectors for ML-DSA-65 (external
// interface, pure, FIPS 204): fixed keys, messages and signatures with a verdict
// attached, plus sigGen cases where the signature must match byte for byte.
//
// That makes "one implementation across three targets" checkable rather than asserted:
// the same bytes the browser fetches, Node reads and the Go loader embeds, so a drifting
// build fails here instead of splitting the network into nodes that admit a bundle and
// nodes that refuse it.
async function testMlDsaAcvpVectors() {
  console.log("Test: ML-DSA-65 ACVP known-answer vectors (FIPS 204, external/pure)");
  const kat = JSON.parse(readFileSync(join(root, "tests/fixtures/mldsa65-acvp.json"), "utf8"));
  const hex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
  const mldsa = await loadMlDsa65(readFileSync(join(root, "browser/mldsa65.wasm")));

  // The vectors carry FIPS 204 context strings; the runtime always signs with an
  // empty one (§12.4), so the raw module is exercised through the same low-level
  // entry the adapter wraps.
  const inst = (await WebAssembly.instantiate(readFileSync(join(root, "browser/mldsa65.wasm")), {})).instance;
  const e = inst.exports;
  const base = e.__heap_base.value;
  let top = base;
  const alloc = (n) => {
    const p = (top + 15) & ~15;
    top = p + n;
    const short = top - e.memory.buffer.byteLength;
    if (short > 0) e.memory.grow(Math.ceil(short / 65536) + 1);
    return p;
  };
  const put = (b) => { const p = alloc(b.length); new Uint8Array(e.memory.buffer).set(b, p); return p; };

  let checked = 0;
  for (const t of kat.sigVer) {
    top = base;
    const sig = put(hex(t.sig)), msg = hex(t.msg), m = put(msg);
    const ctx = hex(t.ctx), c = put(ctx), pk = put(hex(t.pk));
    const got = e.mldsa65_verify(sig, m, msg.length, c, ctx.length, pk) === 1;
    assertEqual(got, t.pass, `ACVP sigVer tc${t.tcId} (${t.reason})`);
    checked++;
  }
  for (const t of kat.sigGen) {
    top = base;
    const sk = put(hex(t.sk)), msg = hex(t.msg), m = put(msg);
    const ctx = hex(t.ctx), c = put(ctx), rnd = put(hex(t.rnd)), sig = alloc(ML_DSA65_SIG_LEN);
    assertEqual(e.mldsa65_sign(sig, m, msg.length, c, ctx.length, rnd, sk), 1, `ACVP sigGen tc${t.tcId} signs`);
    const out = new Uint8Array(e.memory.buffer).slice(sig, sig + ML_DSA65_SIG_LEN);
    assertEqual(toHex(out), t.sig, `ACVP sigGen tc${t.tcId} signature is byte-exact`);
    checked++;
  }

  // The adapter's own path (empty context, the runtime's only mode) must agree with the
  // raw module: a wrapper passing a stray context byte would still pass every vector
  // above.
  {
    const seed = new Uint8Array(32).fill(9);
    const kp = mldsa.ml_dsa65_keypair_from_seed(seed);
    assertEqual(kp.publicKey.length, ML_DSA65_PK_LEN, "keygen returns a full-width public key");
    const msg = new TextEncoder().encode("adapter path");
    const sig = mldsa.ml_dsa65_sign_detached(msg, kp.privateKey);
    assert(mldsa.ml_dsa65_verify_detached(sig, msg, kp.publicKey), "adapter verifies its own signature");
    top = base;
    const sp = put(sig), mp = put(msg), pp = put(kp.publicKey);
    assertEqual(e.mldsa65_verify(sp, mp, msg.length, 0, 0, pp), 1,
      "the raw module verifies what the adapter signed, with an empty context");
    sig[0] ^= 1;
    assert(!mldsa.ml_dsa65_verify_detached(sig, msg, kp.publicKey), "a flipped bit fails");
    assert(!mldsa.ml_dsa65_verify_detached(sig.slice(0, 10), msg, kp.publicKey),
      "a wrong-width signature is false, not a throw");
  }

  console.log(`  OK (${checked} NIST vectors)\n`);
}

// ─── Test: hybrid manifest suite 0x02 — Ed25519 + ML-DSA-65, both required ───────
//
// The §14.1 migration that cannot be delivered through its own mechanism: a PQ verifier
// shipped as a bundle would be admitted by the classical verifier, so the suite goes into
// the artifact ahead of need. What is pinned below is the *shape* — both signatures
// required, the author id bound to both keys, and a host without the PQ half refusing
// rather than falling back.
// ─── Test: ML-KEM-768 against NIST's own vectors (ACVP known-answer test) ────────
//
// testMlDsaAcvpVectors' argument, applied to the catalog's KEM: NIST's published ACVP
// vectors for ML-KEM-768 (FIPS 203) — fixed coins with the key, ciphertext and shared
// secret that must come out of them byte for byte.
//
// Three of the five groups pin behaviour a round trip cannot reach at all: `decaps` over
// MODIFIED ciphertexts, where implicit rejection must produce NIST's specific unrelated
// secret rather than an error, and the two key checks (§7.2's modulus, §7.3's hash).
async function testMlKemAcvpVectors() {
  console.log("Test: ML-KEM-768 ACVP known-answer vectors (FIPS 203)");
  const kat = JSON.parse(readFileSync(join(root, "tests/fixtures/mlkem768-acvp.json"), "utf8"));
  const hex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
  const kem = await loadMlKem768(readFileSync(join(root, "browser/mlkem768.wasm")));

  let checked = 0;
  for (const t of kat.keyGen) {
    const kp = kem.ml_kem768_keypair_from_seed(hex(t.d + t.z));
    assertEqual(toHex(kp.publicKey), t.ek, `ACVP keyGen tc${t.tcId} encapsulation key is byte-exact`);
    assertEqual(toHex(kp.privateKey), t.dk, `ACVP keyGen tc${t.tcId} decapsulation key is byte-exact`);
    checked++;
  }
  for (const t of kat.encaps) {
    const r = kem.ml_kem768_encaps(hex(t.ek), hex(t.m));
    assert(r !== null, `ACVP encaps tc${t.tcId} accepts the vector's key`);
    assertEqual(toHex(r.ciphertext), t.c, `ACVP encaps tc${t.tcId} ciphertext is byte-exact`);
    assertEqual(toHex(r.sharedSecret), t.k, `ACVP encaps tc${t.tcId} shared secret is byte-exact`);
    checked++;
  }
  for (const t of kat.decaps) {
    const ss = kem.ml_kem768_decaps(hex(t.dk), hex(t.c));
    assert(ss !== null, `ACVP decaps tc${t.tcId} accepts the vector's key`);
    // Both "valid decapsulation" and "modified ciphertext" cases run through here and
    // both must match: the modified ones are implicit rejection, which has one right
    // answer, not an error.
    assertEqual(toHex(ss), t.k, `ACVP decaps tc${t.tcId} shared secret is byte-exact (${t.reason})`);
    checked++;
  }
  for (const t of kat.encapsKeyCheck) {
    const r = kem.ml_kem768_encaps(hex(t.ek), new Uint8Array(32));
    assertEqual(r !== null, t.pass, `ACVP encapsulationKeyCheck tc${t.tcId} (${t.reason})`);
    checked++;
  }
  for (const t of kat.decapsKeyCheck) {
    const ss = kem.ml_kem768_decaps(hex(t.dk), new Uint8Array(1088));
    assertEqual(ss !== null, t.pass, `ACVP decapsulationKeyCheck tc${t.tcId} (${t.reason})`);
    checked++;
  }

  // Wrong-width arguments are the same rejection as a malformed key, never a throw: the
  // seam turns `null` into a leading zero byte, and there is no second channel for a
  // structural failure to come back through.
  assertEqual(kem.ml_kem768_encaps(new Uint8Array(10), new Uint8Array(32)), null,
    "a wrong-width encapsulation key is null, not a throw");
  assertEqual(kem.ml_kem768_decaps(new Uint8Array(10), new Uint8Array(1088)), null,
    "a wrong-width decapsulation key is null, not a throw");

  console.log(`  OK (${checked} NIST vectors)\n`);
}

async function testHybridManifestSuite() {
  console.log("Test: hybrid manifest suite 0x02 — both signatures required, id binds both keys");
  const { signManifest, verifyManifest, hybridAuthorId,
          verifyBundle, packBundle, MANIFEST_FILE }
    = await imp("build/host/bundle.js");

  const keys = testAuthor();
  const ed = keys.ed, pq = keys.mlDsa;
  // One module: this test is about the envelope, not the module count.
  const manifest = { app: "pq-probe", version: 1, modules: [{ name: "fwd", hash: "aa" }], guest: { hash: "aa", abi: GUEST_ABI_VERSION, requires: [] } };
  const env = signManifest(sodium, keys, manifest);

  // 1. Layout: `[0x02][edPk 32][mlDsaPk 1952][edSig 64][mlDsaSig 3309][json]`. Both keys
  //    lead, so a verifier reads the whole key set before either signature.
  const OFF_ML_PK = 33, OFF_ED_SIG = OFF_ML_PK + ML_DSA65_PK_LEN;
  const OFF_ML_SIG = OFF_ED_SIG + 64, OFF_JSON = OFF_ML_SIG + ML_DSA65_SIG_LEN;
  assertEqual(env[0], 0x02, "the envelope opens with the hybrid manifest suite id");
  assertEqual(toHex(env.slice(1, 33)), toHex(ed.publicKey), "the Ed25519 key follows the suite byte");
  assertEqual(toHex(env.slice(OFF_ML_PK, OFF_ED_SIG)), toHex(pq.publicKey), "the ML-DSA key follows it");
  assertEqual(new TextDecoder().decode(env.slice(OFF_JSON)), JSON.stringify(manifest),
    "the manifest JSON is carried verbatim after both signatures");

  // 2. Untouched, it verifies — and the author id is the hash over BOTH keys, never
  //    either one (§12.4). That is what hybrid signing rests on: an attacker who breaks
  //    one algorithm cannot reach this identity while choosing the other half's key.
  {
    const v = verifyManifest(sodium, env);
    assert(v !== null, "an untouched hybrid manifest verifies");
    assertEqual(toHex(v.author), toHex(hybridAuthorId(sodium, ed.publicKey, pq.publicKey)),
      "the author id is the derived key-set hash");
    assert(toHex(v.author) !== toHex(ed.publicKey), "the author id is not the Ed25519 key");
    assertEqual(toHex(v.authorKeys.ed), toHex(ed.publicKey), "both signing keys are reported");
    assertEqual(toHex(v.authorKeys.mlDsa), toHex(pq.publicKey), "including the PQ one");
    assertEqual(v.manifest.app, "pq-probe", "the manifest round-trips");
  }

  // 3. Both halves are load-bearing: tampering with either signature fails the whole
  //    manifest. "Either verifies" would be exactly as strong as the weaker algorithm.
  {
    const badEd = env.slice(); badEd[OFF_ED_SIG] ^= 0x01;
    assert(verifyManifest(sodium, badEd) === null, "a broken Ed25519 half fails the manifest");
    const badMl = env.slice(); badMl[OFF_ML_SIG] ^= 0x01;
    assert(verifyManifest(sodium, badMl) === null, "a broken ML-DSA half fails the manifest");
  }

  // 4. The splice a hybrid format has to survive: swap in a different Ed25519 key with a
  //    validly-made signature of its own, keeping the original PQ key and signature.
  //    Both preimages commit to BOTH keys, so the surviving half no longer verifies —
  //    the pair cannot be taken apart and half-replaced.
  {
    const attacker = generateKeyPair();
    const json = new TextEncoder().encode(JSON.stringify(manifest));
    const pre = concatBytes([
      new TextEncoder().encode("seedkernel-manifest-sig-v1\0"), Uint8Array.of(0x02),
      attacker.publicKey, pq.publicKey, json,
    ]);
    const spliced = concatBytes([
      Uint8Array.of(0x02), attacker.publicKey, pq.publicKey,
      sodium.crypto_sign_detached(pre, attacker.privateKey),
      env.slice(OFF_ML_SIG, OFF_JSON), json,
    ]);
    assert(verifyManifest(sodium, spliced) === null,
      "an Ed25519 key swap invalidates the untouched ML-DSA half");
  }

  // 5. A host with no ML-DSA verifier REFUSES rather than falling back to the Ed25519
  //    signature alone — the downgrade the suite exists to prevent. Its own message, like
  //    an unknown suite's: a legibility failure, not a verdict on the bundle.
  {
    const classicalOnly = {
      crypto_sign_verify_detached: (...a) => sodium.crypto_sign_verify_detached(...a),
      crypto_generichash: (...a) => sodium.crypto_generichash(...a),
    };
    let msg = "";
    try { verifyManifest(classicalOnly, env); } catch (e) { msg = String(e.message); }
    assert(msg.includes("unsupported manifest suite 0x02"),
      `a host without ML-DSA refuses 0x02 (got: ${msg || "no throw"})`);
    assert(!msg.includes("signature invalid"), "and does not report it as a bad signature");
  }

  // 6. End to end: a signed bundle loads and its modules bind under the DERIVED id — the
  //    key-set hash, never either key — so names, policy and freshness are all keyed by
  //    the one identity the format produces.
  {
    const wasm = forwarderBytes;
    const m = { app: "pq-app", version: 1, modules: [{ name: "codec", hash: toHex(gHash(wasm)) }], guest: GUEST() };
    const blob = packBundle({
      [MANIFEST_FILE]: signManifest(sodium, keys, m),
      [moduleFile("codec")]: wasm,
      [GUEST_FILE]: GUEST_BYTES,
    });
    const v = verifyBundle(sodium, blob);
    assertEqual(toHex(v.authorKeys.mlDsa), toHex(pq.publicKey),
      "verifyBundle carries the signing key set through to the policy seam");
    const host = testHost(new JsModuleLoader());
    await installBundle(host, v);
    const derived = appKey(hybridAuthorId(sodium, ed.publicKey, pq.publicKey), "pq-app");
    assert(host.isBound(derived, "codec"), "the module binds under the derived author id");
    assert(!host.isBound(appKey(ed.publicKey, "pq-app"), "codec"),
      "…and never under the Ed25519 key alone");
  }

  console.log("  OK\n");
}

// ─── Test: a corrupt newer bundle does not advance the freshness mark ────────────
//
// The freshness high-water mark must record only versions that fully loaded. A newer
// bundle whose manifest is intact and signed but whose module bytes are corrupt (a
// half-landed upgrade) must fail the content check WITHOUT raising the mark, or reloading
// the known-good older bundle is refused as a downgrade and rollback is bricked (§12.4).
async function testBundleCorruptNewerRollback() {
  console.log("Test: a corrupt newer bundle leaves the freshness mark intact (rollback stays possible)");
  const { signManifest, packBundle, MANIFEST_FILE, GUEST_FILE, moduleFile }
    = await imp("build/host/bundle.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = testAuthor();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-rollback-"));
  const bundlePath = pjoin(dir, "rollback.skb");
  let shell;
  try {
    const { host: h } = await makeHost();
    const guestText = "function handle() { return new Uint8Array([1]); }";
    const manifest = (version) => ({
      app: "rollback", version,
      modules: [{ name: "codec", hash: toHex(gHash(forwarderBytes)) }],
      guest: {
        hash: toHex(gHash(new TextEncoder().encode(guestText))),
        abi: GUEST_ABI_VERSION,
        requires: [],
      },
    });
    // `wasm` is the module's actual bytes — passed corrupt below to model a
    // half-written upgrade whose manifest is nonetheless intact and signed.
    const writeBundle = (version, wasm = forwarderBytes) => wf(bundlePath, packBundle({
      [MANIFEST_FILE]: signManifest(sodium, author, manifest(version)),
      [moduleFile("codec")]: wasm,
      [GUEST_FILE]: new TextEncoder().encode(guestText),
    }));

    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.id)] }),
      dir: pjoin(dir, "_data"), identity,
    });

    // 1. Good v4 loads and sets the mark to 4.
    writeBundle(4);
    await shell.loadBundle(bundlePath);

    // 2. A corrupt v5: validly signed at version 5, but the module bytes no longer
    //    match their declared hash. The load must throw on the content check.
    writeBundle(5, forwarderBytes.slice(0, forwarderBytes.length - 1));
    let v5Failed = false;
    try { await shell.loadBundle(bundlePath); } catch { v5Failed = true; }
    assert(v5Failed, "a corrupt v5 bundle fails to load");

    // 3. Restore the good v4 bundle and reload. If the failed v5 load had advanced the
    //    mark to 5, this would now be refused as a downgrade. It must still load.
    writeBundle(4);
    let v4Reloaded = true;
    try { await shell.loadBundle(bundlePath); } catch { v4Reloaded = false; }
    assert(v4Reloaded, "the known-good v4 reloads after the corrupt v5 attempt (mark not advanced)");
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: writing off a compromised author key (§12.5) ─────────────────────────
//
// Freshness cannot answer "is this key still the author's?": a stolen key signs
// `version + 1`, clears the high-water mark, and lands on the SAME derived names (§5.1)
// forever. `shell.revoke` is the remedy, and what is tested is that both of its halves
// happen and that the refusal survives a reboot — an operator doing this by hand can
// uninstall without closing the door, or close it with the code still running.
async function testAuthorRevocation() {
  console.log("Test: revoking an author key refuses its bundles and tears down what it landed");
  const { signManifest, packBundle, MANIFEST_FILE, moduleFile } = await imp("build/host/bundle.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = testAuthor();
  const identity = generateKeyPair();
  const authorHex = toHex(author.id);
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-revoke-"));
  const bundlePath = pjoin(dir, "app.skb");
  const dataDir = pjoin(dir, "_data");
  const policyJson = JSON.stringify({ authors: [authorHex] });
  let shell;
  try {
    const manifest = (version) => ({
      app: "victim", version,
      modules: [{ name: "codec", hash: toHex(gHash(forwarderBytes)) }],
      guest: GUEST(),
    });
    const writeBundle = (version) => wf(bundlePath, packBundle({
      [MANIFEST_FILE]: signManifest(sodium, author, manifest(version)),
      [moduleFile("codec")]: forwarderBytes,
      [GUEST_FILE]: GUEST_BYTES,
    }));

    shell = await boot({ policyJson, dir: dataDir, identity });
    const victimKey = appKeyFor(author.id, "victim");

    // 1. The author is trusted: v1 loads and binds.
    writeBundle(1);
    await shell.loadBundle(bundlePath);

    // 2. The key is stolen. Freshness does NOT stop it — v2 is strictly newer, so it
    //    loads over the same name. This is the gap, asserted rather than assumed.
    writeBundle(2);
    await shell.loadBundle(bundlePath);

    // 3. Write the key off. Both halves must happen in the one call.
    const gone = shell.revoke(authorHex);
    assert(gone.includes(victimKey), "revoke reports the app it tore down");
    assert(shell.uninstall(victimKey) === false, "revoke uninstalls the running slot");

    // 4. The thief's next bundle is refused even though the version keeps climbing
    //    and the author is still in the policy allowlist.
    writeBundle(3);
    let refused = false;
    try { await shell.loadBundle(bundlePath); } catch { refused = true; }
    assert(refused, "a bundle from a revoked key is refused despite a higher version");
    assert(shell.uninstall(victimKey) === false, "nothing landed on the refused load");

    // 4b. The refusal must come BEFORE the admission predicate: an interactive shell puts
    //     its consent dialog there (§12.4), and prompting a user to approve a bundle this
    //     host has already decided to refuse is the wrong order to ask in.
    {
      const store = new FreshnessMarks();
      let admitCalls = 0;
      const probe = await bootTestShell({
        identity, freshnessStore: store,
        createRealm: async () => ({ call: async () => new Uint8Array(), dispose() {} }),
        admit: () => { admitCalls++; return true; },
      });
      probe.revoke(authorHex);
      try { await probe.loadBundleBlob(new Uint8Array(readFileSync(bundlePath))); } catch { /* expected */ }
      assert(admitCalls === 0, "a revoked author never reaches the admission predicate");
      probe.close();
    }

    // 5. The refusal is persisted, not process-local: a fresh boot over the same data
    //    directory — same unedited policy file — still refuses. This is the half an
    //    operator calling uninstall by hand does not get.
    shell.close();
    shell = await boot({ policyJson, dir: dataDir, identity });
    let refusedAfterReboot = false;
    try { await shell.loadBundle(bundlePath); } catch { refusedAfterReboot = true; }
    assert(refusedAfterReboot, "the revocation survives a reboot with the policy untouched");

    // 6. Recovery is a NEW key, not an un-revoke: it derives its own names (§5.1) and
    //    its own mark, so it is unaffected by the dead key's state.
    const heir = testAuthor();
    wf(bundlePath, packBundle({
      [MANIFEST_FILE]: signManifest(sodium, heir, manifest(1)),
      [moduleFile("codec")]: forwarderBytes,
      [GUEST_FILE]: GUEST_BYTES,
    }));
    shell.close();
    shell = await boot({
      policyJson: JSON.stringify({ authors: [authorHex, toHex(heir.id)] }),
      dir: dataDir, identity,
    });
    await shell.loadBundle(bundlePath);
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: a pre-revocation store file is refused, not silently emptied ─────────
//
// The store's shape is `{ marks, revoked }`, not the bare `{ "authorHex:app": version }`
// map it once was. An old file parsed leniently would read as NO marks — every downgrade
// guard silently dropped on the first boot after a host upgrade, with the next stale
// bundle accepted and nothing saying why. It must fail loudly instead (§12.4).
async function testPreRevocationStoreIsRefused() {
  console.log("Test: a store file predating revocation is refused rather than read as empty");
  const { FreshnessMarks } = await imp("build/host/bundle.js");
  const key = "aa".repeat(32) + ":app";

  let msg = "";
  try { new FreshnessMarks(JSON.stringify({ [key]: 7 })); } catch (e) { msg = e.message; }
  assert(msg.includes("predates author revocation"), "the old bare-map format throws with a migration message");

  // The current format round-trips, marks and revocations both.
  const cur = new FreshnessMarks(JSON.stringify({ marks: { [key]: 7 }, revoked: ["bb".repeat(32)] }));
  assert(cur.get(new Uint8Array(32).fill(0xaa), "app") === 7, "the current format reads marks back");
  assert(cur.isRevoked(new Uint8Array(32).fill(0xbb)), "the current format reads revocations back");

  // The first-boot cases must NOT throw: absent, unparseable, or an empty object are
  // all "nothing known yet", and only a populated bare map is the old format.
  let firstBootThrew = false;
  try {
    new FreshnessMarks(null);
    new FreshnessMarks("not json at all");
    new FreshnessMarks("{}");
  } catch { firstBootThrew = true; }
  assert(!firstBootThrew, "absent, unparseable and empty stores still start empty");
  console.log("  OK\n");
}

// ─── Test: a WRONG-TYPED store is refused, not silently emptied ──────────────
//
// The guard above catches only the old bare-map shape. The same silent discard — every
// downgrade guard AND every revocation gone for one boot — is reachable through a
// NEW-shaped file with wrong-typed fields (`{"marks":"garbage"}`) reading as "no marks,
// nothing revoked". Guard data that exists but cannot be read is a corrupt store (§12.5).
async function testWrongTypedStoreIsRefused() {
  console.log("Test: a wrong-typed freshness store fails the boot loudly, never silently empty");
  const { FreshnessMarks } = await imp("build/host/bundle.js");

  for (const [what, json] of [
    ['a string "marks"', JSON.stringify({ marks: "garbage", revoked: [] })],
    ['a null "marks"', JSON.stringify({ marks: null, revoked: [] })],
    ['a marks array', JSON.stringify({ marks: [], revoked: [] })],
    ['a string mark value', JSON.stringify({ marks: { "aa:app": "2" }, revoked: [] })],
    ['a fractional mark', JSON.stringify({ marks: { "aa:app": 2.5 }, revoked: [] })],
    ['a negative mark', JSON.stringify({ marks: { "aa:app": -1 }, revoked: [] })],
    ['a non-array "revoked"', JSON.stringify({ marks: {}, revoked: "nul" })],
    ['a non-string revoked entry', JSON.stringify({ marks: {}, revoked: [1] })],
  ]) {
    let threw = false;
    try { new FreshnessMarks(json); } catch { threw = true; }
    assert(threw, `${what} must throw as a corrupt store`);
  }

  // The well-formed shapes still load — including a file carrying an unrecognized
  // key (one a newer version added), which is ignored rather than refused.
  const good = new FreshnessMarks(JSON.stringify({
    marks: { ["aa".repeat(32) + ":app"]: 2 }, revoked: ["bb".repeat(32)], futureKey: { anything: 1 },
  }));
  assert(good.get(new Uint8Array(32).fill(0xaa), "app") === 2, "a well-formed store still loads its marks");
  assert(good.isRevoked(new Uint8Array(32).fill(0xbb)), "…and its revocations");
  console.log("  OK\n");
}

// ─── Test: an app the runtime cannot serve is refused at load ────────────────
//
// `app` is the guest's signing scope, which caps at 255 UTF-8 bytes (guestSignScope's
// one-byte length). Refused at load, or a longer name verifies, installs, and then fails
// at first use — a bundle the host can admit but can never serve (§12.2, §12.4).
async function testAppNameLengthRefused() {
  console.log("Test: an over-long app name is refused at load, not at first use");
  const { verifyManifest, signManifest } = await imp("build/host/bundle.js");
  const author = testAuthor();
  const mk = (app, extra = {}) => signManifest(sodium, author,
    { app, version: 1, modules: [], guest: GUEST(), ...extra });

  // At the limit, everything works — 255 bytes is exactly what the scope can carry.
  assert(verifyManifest(sodium, mk("a".repeat(255))) !== null,
    "a 255-byte app name verifies");

  for (const [what, env] of [
    ["a 256-byte app name", mk("a".repeat(256))],
    // The limit counts UTF-8 BYTES, the unit the scope uses.
    ["a 200-char (600-byte) UTF-8 app name", mk("\u{1f600}".repeat(200))],
  ]) {
    let threw = false;
    try { verifyManifest(sodium, env); } catch { threw = true; }
    assert(threw, `${what} is refused as malformed`);
  }
  console.log("  OK\n");
}

// ─── Test: a freshness persist failure fails the load and keeps nothing ──────
//
// A failed persist must be a failed load with nothing kept, and the mark rolled back so a
// retry persists a fresh advance (§12.4). Otherwise a durable write that failed leaves the
// modules on the table while the load reports failure, and the stale in-memory mark makes
// the retry a no-op against a store that still lacks it.
async function testPersistFailureRollsBack() {
  console.log("Test: a failed freshness persist fails the load — nothing is kept, the mark is rolled back");
  const { ModuleTable } = await imp("build/host/module-table.js");
  const { admitAll } = await imp("build/host/policy.js");

  const author = testAuthor();
  const manifest = { app: "persist", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
    guest: GUEST() };
  const blob = packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author, manifest),
    [moduleFile("fwd")]: forwarderBytes,
    [GUEST_FILE]: GUEST_BYTES,
  });
  const key = appKey(author.id, "persist");

  // A store whose durable write always fails, as a full disk would.
  class BrokenStore extends FreshnessMarks {
    persist() { throw new Error("disk full"); }
  }
  // Driven through the shell, since the shell is what advances the mark — last, after the
  // guest stands, so the write it rolls back is one that was about to record a version
  // that really ran.
  const host = testHost(new ModuleTable());
  const shellOver = (freshnessStore) => bootTestShell({
    modules: host, freshnessStore,
    createRealm: async () => ({ call: async () => new Uint8Array(), dispose() {} }),
    admit: admitAll,
  });

  const broken = new BrokenStore();
  const brokenShell = await shellOver(broken);
  let msg = "";
  try { await brokenShell.loadBundleBlob(blob); } catch (e) { msg = e.message; }
  assert(msg.includes("could not be persisted"), "a failed persist fails the load");
  assert(msg.includes("disk full"), `the original persist error survives the wrap (got: ${msg})`);
  assert(brokenShell.uninstall(key) === false, "nothing was kept — no slot was committed");
  assertEqual(broken.get(author.id, "persist"), -Infinity, "the in-memory mark was rolled back");

  // A retry against a healthy store completes cleanly: the rollback is what makes
  // it persist a FRESH advance rather than no-op'ing against the stale mark.
  const healthy = new FreshnessMarks();
  const healthyShell = await shellOver(healthy);
  await healthyShell.loadBundleBlob(blob);
  assert(healthyShell.uninstall(key), "the retry lands");
  assertEqual(healthy.get(author.id, "persist"), 1, "…and persists its mark");
  console.log("  OK\n");
}

// ─── Test: a candidate realm cannot act before its installation commits ─────
//
// Guest source is evaluated before the freshness mark and claim table land so it can
// register its entrypoints. In that window the seam refuses what disposing the candidate
// could not take back — a durable write, a call that already reached another realm — and
// nothing else: a rejected upgrade must not leave the installed version's keyspace or its
// neighbours touched.
async function testCandidateRealmCannotActBeforeCommit() {
  console.log("Test: a candidate realm cannot act before its installation commits");
  const { admitAll } = await imp("build/host/policy.js");

  const author = testAuthor();
  const fs = new MemoryFs();
  let reached = 0;
  const guest = new TextEncoder().encode(GUEST_TEXT);
  const blob = packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author, {
      app: "offside", version: 1, protocols: ["offside/v1"],
      modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
      guest: {
        hash: toHex(gHash(guest)), abi: GUEST_ABI_VERSION,
        requires: ["fs", "link", "_svc"],
      },
    }),
    [moduleFile("fwd")]: forwarderBytes,
    [GUEST_FILE]: guest,
  });
  // The neighbour a candidate must not reach: a REAL second bundle declaring `_svc`
  // under `services` (a co-resident guest's to reach, never a peer's), installed under
  // its own slot rather than stood in for by a host closure — dispatch has only ever had
  // one owner kind. Its own realm is a plain counting stub; what is under test is
  // whether the OFFSIDE candidate can reach it, not what it does once reached.
  const neighborBlob = packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author, {
      app: "svc-neighbor", version: 1, services: ["_svc"],
      modules: [], guest: GUEST(),
    }),
    [GUEST_FILE]: GUEST_BYTES,
  });
  class FlakyStore extends FreshnessMarks {
    fail = true;
    persist() { if (this.fail) throw new Error("disk full"); }
  }
  const store = new FlakyStore();
  const candidates = [];
  // Set only while `neighborBlob` is the one loading, so the ONE factory both bundles
  // share can tell which realm it is being asked to stand: the neighbour gets a stub that
  // only counts entries, and everything else — including every offside attempt — gets the
  // offside probing below, pushed into `candidates` in load order.
  let loadingNeighbor = false;
  // A REAL socket-less driver (the browser-edge shape), so a link read is the seam's true
  // read through the candidate's own unpublished binding, and the pin — this author's — is
  // what lets a `link`-reaching candidate get as far as the seam under test.
  const shell = await bootTestShell({
      fs, freshnessStore: store, pinAuthor: author,
      createRealm: async ({ hostCall }) => {
        if (loadingNeighbor) {
          return { call: async () => { reached++; return new Uint8Array(); }, dispose() {} };
        }
        const refused = [];
        for (const [name, payload] of [["fs/put", Uint8Array.of(0, 0, 0, 1, 120, 9)], ["_svc", new Uint8Array()]]) {
          try { await hostCall(name, payload); } catch { refused.push(name); }
        }
        // The node facts are no longer a seam name a candidate reads offside — the host
        // hands them to the freshly stood slot as its `init` op. A link READ stays open:
        // `link/open` answers "no route" for the unpublished binding rather than throwing.
        const openBytes = await hostCall("link/open", new Uint8Array(32));
        const moduleAnswer = await hostCall("fwd", Uint8Array.of(4));
        candidates.push({ hostCall, refused, openBytes, moduleAnswer });
        return { call: async () => new Uint8Array(), dispose() {} };
      },
      admit: admitAll,
  });
  const key = appKey(author.id, "offside");
  try {
    // The neighbour goes in FIRST, so `_svc` is a claim held by a standing realm before the
    // candidate ever reaches for it: the refusal below is then the offside gate's, and not
    // the absence of a claimant. Its own mark has to persist, so the store is let through
    // for that one load and put back to failing afterwards.
    store.fail = false;
    loadingNeighbor = true;
    await shell.loadBundleBlob(neighborBlob);
    loadingNeighbor = false;
    store.fail = true;
    assertEqual(shell.resolve("_svc"), appKey(author.id, "svc-neighbor"),
      "the neighbour holds the claim the candidate is about to reach for");

    let rejected = false;
    try { await shell.loadBundleBlob(blob); } catch { rejected = true; }
    assert(rejected, "a failed freshness write rejects the candidate");
    assertEqual(candidates[0].refused.sort(), ["_svc", "fs/put"],
      "a candidate reaches neither a durable write nor another realm");
    assertEqual(reached, 0, "…so the realm it called was never entered");
    assertEqual((await fs.stat()).used, 0, "…and it left nothing on disk");
    assertEqual(candidates[0].openBytes[0] & 0xff, 0,
      "the reads a guest initializes from stay open — a link read answers no route");
    assert(candidates[0].moduleAnswer[0] === 4, "…as do its own verified modules");
    assert(shell.uninstall(key) === false, "a failed candidate never publishes its claim");

    store.fail = false;
    await shell.loadBundleBlob(blob);
    assertEqual(shell.resolve("offside/v1"), key, "the claim commits before the seam opens");
    await candidates[1].hostCall("fs/put", Uint8Array.of(0, 0, 0, 1, 120, 9));
    await candidates[1].hostCall("_svc", new Uint8Array());
    assertEqual((await fs.stat()).used, 1, "the committed realm writes");
    assertEqual(reached, 1, "…and reaches its neighbour");
  } finally {
    shell.close();
  }
  console.log("  OK\n");
}

// ─── Test: a failed revocation persist is a failed revocation ───────────────
//
// The same rule as the mark, one method over. A write that throws must not leave the key
// revoked only in memory: that reads as safe for the rest of this boot while making the
// retry a silent no-op, and the next boot admits the author regardless (§12.5).
async function testFailedRevokePersistRollsBack() {
  console.log("Test: a revocation that cannot be persisted is refused, not held in memory");
  const { FreshnessMarks } = await imp("build/host/bundle.js");
  const author = new Uint8Array(32).fill(0xcd);

  let broken = true;
  const written = [];
  class FlakyStore extends FreshnessMarks {
    persist(json) { if (broken) throw new Error("disk full"); written.push(json); }
  }
  const store = new FlakyStore();
  let msg = "";
  try { store.revoke(author); } catch (e) { msg = e.message; }
  assert(msg.includes("NOT revoked"), `a failed revoke says so plainly (got: ${msg})`);
  assert(msg.includes("disk full"), "the original persist error survives the wrap");
  assert(!store.isRevoked(author), "the key is not left revoked in memory only");

  // The retry is the point of the rollback: without it the early return would see
  // the key already revoked and never write.
  broken = false;
  store.revoke(author);
  assert(store.isRevoked(author), "the retry revokes");
  assert(written.length === 1 && written[0].includes("cd".repeat(32)),
    "…and the retry is what actually reached the store");
  console.log("  OK\n");
}

// ─── Test: an in-place upgrade releases the version it replaces ──────────────
//
// An upgrade is a teardown of what it displaces, by the same rule as uninstall (§12.4).
// Leaving the outgoing slot whole would keep its realm undisposed and its deadlines armed,
// and since a timer's callback reads the slot's realm, the superseded guest would go on
// running `timer` turns — re-arming more, and holding ~1.2 MB of engine per upgrade.
async function testInPlaceUpgradeReleasesTheOldSlot() {
  console.log("Test: an in-place upgrade disposes the realm and deadlines it replaces");
  const { admitAll, denyAll, byPrivilege } = await imp("build/host/policy.js");

  const author = testAuthor();
  const key = appKey(author.id, "upgrade");
  const blob = (version) => packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author, {
      app: "upgrade", version,
      protocols: ["upgrade/v1"],
      modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
      guest: GUEST({ requires: ["timer"] }),
    }),
    [moduleFile("fwd")]: forwarderBytes,
    [GUEST_FILE]: GUEST_BYTES,
  });

  // Each realm records what it was asked to run and whether it was released, and arms a
  // 200 ms deadline on construction — the guest's half, since a deadline exists only
  // because a guest asked for one and re-enters THAT guest's realm. 200 rather than 5
  // because the upgrade loads the replacing bundle's modules in workers, and a deadline
  // firing inside that window is a legitimate turn of the guest that armed it.
  const realms = [];
  let failNextRealm = false;
  const arm = (id, ms) => { const p = new Uint8Array(8); writeU32BE(p, 0, id); writeU32BE(p, 4, ms); return p; };
  // A fired deadline and an ordinary loopback invoke arrive with the SAME (zero) caller
  // id now, so what tells them apart is the op name in the body, not a caller byte —
  // `invoke` above sends an empty body, which has no op to read at all.
  const opNameOf = (p) => {
    if (p.length <= 32) return null;
    try { return readOp(p.subarray(32)).op; } catch { return null; }
  };
  const shell = await bootTestShell({
    createRealm: async (o) => {
      if (failNextRealm) { failNextRealm = false; throw new Error("broken candidate guest"); }
      const r = { calls: [], disposed: false, call: async (p) => { r.calls.push(opNameOf(p) === "timer" ? "timer" : "invoke"); return new Uint8Array(); }, dispose() { r.disposed = true; } };
      realms.push(r);
      await o.hostCall("timer/arm", arm(1, 200));
      return r;
    },
    admit: byPrivilege({ base: admitAll, grants: { link: denyAll } }),
  });
  try {
    await shell.loadBundleBlob(blob(1));
    await shell.invoke(new Uint8Array(), key);
    assertEqual(realms.length, 1, "the first slot stands one realm");

    failNextRealm = true;
    let failed = false;
    try { await shell.loadBundleBlob(blob(2)); } catch { failed = true; }
    assert(failed, "a candidate whose guest cannot stand is refused");
    assert(!realms[0].disposed, "the failed candidate leaves the running realm intact");
    assertEqual(shell.resolve("upgrade/v1"), key, "…and leaves its claim intact");

    await shell.loadBundleBlob(blob(2));
    assert(realms[0].disposed, "the upgrade disposed the realm it replaced");
    await shell.invoke(new Uint8Array(), key);
    assertEqual(realms.length, 2, "…and the app answers from a NEW realm");
    assert(!realms[1].disposed, "…which is the one left standing");

    // Past the 200ms deadline both realms armed. Only the standing one may hear it: a
    // `timer` turn in realms[0] is the superseded guest still executing.
    await new Promise((r) => setTimeout(r, 350));
    assert(!realms[0].calls.includes("timer"),
      `the replaced guest ran no timer turn after the upgrade (ran: ${realms[0].calls.join(",")})`);
    assert(realms[1].calls.includes("timer"), "…while the standing guest's own deadline still fires");
  } finally {
    shell.close();
  }
  console.log("  OK\n");
}

// ─── Run ────────────────────────────────────────────────────────────────

await testFullLifecycle();
await testInstallRejectsUntrustedAuthor();
await testManifestHashIsEnforced();
await testDenyAllPolicyRejects();
await testBundleRefusesNonModule();
await testDerivedNamesKeepAuthorsApart();
await testManifestClaimIsTheRouting();
await testOneRawLinkOwner();
await testInstallerRemove();
await testFs();
await testFsKeyRule();
await testGuestSeam();
await testPolicy();
await testRequiresPickThePrivileges();
await testSigningScopeFollowsSlot();
await testGuestAbi();
await testSlotFreshness();
await testShellBoot();
await testBundle();
await testGuestBundleAndArchive();
await testBundleCorruptNewerRollback();
await testSafeJs();
await testRealmSerialization();
await testSeamGating();
await testCallModuleGuards();
await testModuleCallBound();
await testModuleCallChargedToGuestBudget();
await testPreviousAbiRefused();
await testManifestSuiteByte();
await testMlDsaAcvpVectors();
await testMlKemAcvpVectors();
await testHybridManifestSuite();
await testSafeRealmConcurrency();
await testAuthorRevocation();
await testPreRevocationStoreIsRefused();
await testWrongTypedStoreIsRefused();
await testAppNameLengthRefused();
await testPersistFailureRollsBack();
await testCandidateRealmCannotActBeforeCommit();
await testFailedRevokePersistRollsBack();
await testInPlaceUpgradeReleasesTheOldSlot();

summary("Results");
