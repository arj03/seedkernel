// bundle-install.test.mjs — bundle/manifest verify → admit → install (§12.4, §12.5,
// §12.10): routing claims, fs, freshness, revocation, and in-place upgrade. Split out of
// the former single-file run.mjs so this topic reads on its own; realm-guest.test.mjs
// covers the guest seam and privilege derivation, crypto.test.mjs the manifest-suite and
// ACVP vector suites.
//
// Positive-path bundle fixtures go through `authorBundle` (host/bundle-author.ts), which
// hashes, assembles, validates and signs in one call — the same path a real publisher
// uses. A handful of tests build a manifest or envelope by hand instead, because what they
// assert on is deliberately malformed or corrupted: a wrong hash, duplicate module names,
// a corrupted archive, a tampered envelope byte. `authorBundle` calls `validateManifest`
// internally and cannot produce any of those on purpose, so those cases keep
// `signManifest`/`packBundle` directly.

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { testkit } from "./testkit.mjs";
import {
  sodium, generateKeyPair, JsModuleLoader, bootShell, bootNodeShell, TransportHost,
  toHex, fromHex, concatBytes, writeU32BE, appKeyFor, hybridAuthorId, FreshnessMarks,
  verifyManifest, verifyBundle, loadBundleModules, moduleFile, MANIFEST_FILE, GUEST_FILE,
  signManifest, packBundle, guestOpFraming, authorBundle, policyFromJson, authorAllowlist,
  hostGates, gHash, GUEST_TEXT, GUEST_BYTES, GUEST, testAuthor, boot, bootTestShell,
  APP_CTX, LINK_CTX, loadBundle, EMPTY, TestModuleHost, testHost, installBundle, makeHost,
  forwarderBytes, installMod, appKey, imp, root, bytesEqual, callerOf, readOp, writeOp,
  MemoryFs, NodeFs, enc,
} from "./fixtures.mjs";

const { ok, assertEqual, summary } = testkit({ verbose: false });
const assert = ok;

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
  const { blob } = authorBundle(sodium, author, {
    app: "demo", version: 1,
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: [],
  });

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

  // A manifest that declares the CORRECT hash — loadBundle should accept it.

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
  const { blob } = authorBundle(sodium, author, {
    app: "demo", version: 1,
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: [],
  });

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
  const { blob } = authorBundle(sodium, author, {
    app: "demo", version: 1,
    modules: [{ name: "fwd", wasm: forwarderBytes }, { name: "broken", wasm: notAModule }],
    guestSource: GUEST_TEXT, guestRequires: [],
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
  const blob = (signer, app, version, protocols) => authorBundle(sodium, signer, {
    app, version, protocols,
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: [],
  }).blob;
  let realmBuilds = 0;
  const identity = generateKeyPair();
  let routeDeliver;
  const routeInbound = TransportHost.prototype.routeInbound;
  TransportHost.prototype.routeInbound = function (deliver) {
    routeDeliver = deliver;
    return routeInbound.call(this, deliver);
  };
  let shell;
  try {
    shell = await bootTestShell({
      identity,
      transport: { load: false },
      createRealm: async () => {
        realmBuilds++;
        return { call: async () => new Uint8Array(), dispose() {} };
      },
      admit: byPrivilege({ base: admitAll, grants: { link: denyAll } }),
    });
  } finally {
    TransportHost.prototype.routeInbound = routeInbound;
  }
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

    // Realms are the multiplicand every per-realm ceiling is multiplied by (§12.3), so the
    // install list is counted: without this bound each of those ceilings is a floor. A
    // REPLACEMENT is never refused — it takes the slot its own key already holds — and an
    // uninstall gives one back.
    const { DEFAULT_MAX_APP_SLOTS } = await imp("build/core/wasm-limits.js");
    for (let i = 0; i < DEFAULT_MAX_APP_SLOTS; i++) {
      await shell.loadBundleBlob(blob(author, `filler${i}`, 1, [`filler/${i}`]));
    }
    let overfull = "";
    try { await shell.loadBundleBlob(blob(author, "one-too-many", 1, ["filler/x"])); }
    catch (e) { overfull = String(e); }
    assert(overfull.includes("app slots"), `a full node refuses another app, got: ${overfull || "no error"}`);
    assert(shell.resolve("filler/x") === null, "…and the refused candidate claimed nothing");
    await shell.loadBundleBlob(blob(author, "filler0", 2, ["filler/0"]));
    assertEqual(shell.resolve("filler/0"), appKey(author.id, "filler0"),
      "a replacement takes the slot its own key already holds");
    shell.uninstall(appKey(author.id, "filler0"));
    await shell.loadBundleBlob(blob(author, "one-too-many", 1, ["filler/x"]));
    assertEqual(shell.resolve("filler/x"), appKey(author.id, "one-too-many"),
      "uninstalling gives the slot back");
    shell.uninstall(appKey(author.id, "one-too-many"));
    for (let i = 1; i < DEFAULT_MAX_APP_SLOTS; i++) shell.uninstall(appKey(author.id, `filler${i}`));
    assertEqual(shell.routes().length, 0, "the node is empty again");

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
    // Two maps, so uniqueness is PER LIST. A name in both is not ambiguous — it says
    // "reachable by a peer AND by a co-resident guest", which is a thing a bundle may mean
    // and the two maps express without a rule. A duplicate WITHIN one list still is.
    {
      assert(verifyManifest(sodium, signManifest(sodium, author,
        { app: "dual", version: 1, protocols: ["both"], services: ["both"], modules: [], guest: GUEST() })) !== null,
      "a name claimed in BOTH `protocols` and `services` is two reaches, not a conflict");
      let threw = false;
      try {
        verifyManifest(sodium, signManifest(sodium, author,
          { app: "dup", version: 1, protocols: ["twice", "twice"], modules: [], guest: GUEST() }));
      } catch (e) { threw = /malformed manifest/.test(String(e)); }
      assert(threw, "a name claimed twice in the SAME list is still refused");
    }
    // The property that actually matters: a name in `services` is unreachable from a
    // PEER while the SAME bundle's `protocols` name is — checked through the real
    // delivery callback wired through `TransportHost.routeInbound`, rather than by
    // inspecting the claim table or entering the shell through a second test-only method.
    {
      const pub = "reach/public", priv = "_reach-private";
      const reachKey = appKey(author.id, "reach");
      await shell.loadBundleBlob(authorBundle(sodium, author, {
        app: "reach", version: 1, protocols: [pub], services: [priv],
        modules: [], guestSource: GUEST_TEXT, guestRequires: [],
      }).blob);
      const sender = new Uint8Array(32).fill(0x11);
      const payload = new Uint8Array([1, 2, 3]);
      assert(typeof routeDeliver === "function", "the shell wires inbound delivery through the transport route");
      const publicAnswer = routeDeliver(pub, sender, payload);
      assert(publicAnswer !== null, "a name in `protocols` is reachable by a peer");
      await publicAnswer;
      assert(routeDeliver(priv, sender, payload) === null,
        "the same bundle's `services` name is unreachable by a peer, however it is spelled");
      shell.uninstall(reachKey);
    }
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
// whatever backend a target supplies (`validatedFs`, host/fs-view.ts).

async function testFsKeyRule() {
  console.log("Test: fs key space is one rule — isSafeFsKey over any backend (validatedFs)");

  const { isSafeFsKey } = await imp("build/core/fs.js");
  const { validatedFs, scopedFs } = await imp("build/host/fs-view.js");

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

// ─── Test: the transport's freshness (§12.4) ───────────────────

async function testSlotFreshness() {
  console.log("Test: the transport carries the ordinary (author, app) freshness mark");

  const { FreshnessMarks } = await imp("build/host/bundle.js");
  const { ModuleTable } = await imp("build/host/module-table.js");

  const a = testAuthor();
  const b = testAuthor();
  const blobFrom = (author, version) => authorBundle(sodium, author, {
    app: "link", version,
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: [],
  }).blob;
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
    const markKey = "aa".repeat(32) + ":app";
    const legacy = new FreshnessMarks(JSON.stringify({ marks: { [markKey]: 2 }, futureKey: { anything: 1 }, revoked: [] }));
    const round = JSON.parse(legacy.serialize());
    assertEqual(round.marks[markKey], 2, "a store carrying an unknown key still loads its marks");
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
  const { unpackBundle }
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

    // The container's three self-consistency rules, stated by name. It is the one part of
    // a bundle no signature covers — the manifest signs its own contents, not the blob
    // that carries it — so a reader's good manners are all that stand between "one blob,
    // one bundle" and a blob that is two bundles depending on who reads it. Hand-built,
    // because these are things a `Record` cannot say.
    const containerOf = (entries) => {
      const header = new Uint8Array(6);
      header.set([0x53, 0x4b, 0x42, 0x31], 0); // "SKB1"
      new DataView(header.buffer).setUint16(4, entries.length, false);
      const parts = [header];
      for (const [name, data] of entries) {
        const nameBytes = enc.encode(name);
        const rec = new Uint8Array(2 + nameBytes.length + 4);
        const dv = new DataView(rec.buffer);
        dv.setUint16(0, nameBytes.length, false);
        rec.set(nameBytes, 2);
        dv.setUint32(2 + nameBytes.length, data.length, false);
        parts.push(rec, data);
      }
      return concatBytes(parts);
    };
    const refuses = (blob, why) => {
      let threw = false;
      try { unpackBundle(blob); } catch { threw = true; }
      assert(threw, why);
    };
    // Two entries under one name: only the LAST manifest.bundle is the one whose signature
    // gets checked, so a reader that keeps the first and one that keeps the last make two
    // different bundles out of these same bytes.
    refuses(containerOf([[MANIFEST_FILE, enc.encode("first")], [MANIFEST_FILE, enc.encode("second")]]),
      "two files under one name are refused");
    // Bytes past the last declared file: the blob's hash is the identity a denylist, a
    // freshness mark and an operator's pin are all keyed by (§12.4), and this would give
    // one bundle unboundedly many of them.
    refuses(concatBytes([containerOf([["a", enc.encode("x")]]), new Uint8Array([0])]),
      "trailing bytes after the last file are refused");
    // A count that under-declares what follows says the same thing a different way.
    refuses(concatBytes([containerOf([]), enc.encode("junk")]),
      "a count that under-declares the entries is refused");
    // `__proto__` is a file name like any other. On an object literal it is the prototype
    // slot instead, so that one entry would vanish from the map AND re-point it at bytes
    // the sender chose — before anything has been verified.
    const withProto = unpackBundle(containerOf([["__proto__", enc.encode("x")], [GUEST_FILE, enc.encode("y")]]));
    assert(Object.getPrototypeOf(withProto) === null, "the unpacked map has no prototype to poison");
    assert(bytesEqual(withProto["__proto__"], enc.encode("x")), "__proto__ arrives as an ordinary entry");
    assertEqual(Object.keys(withProto).length, 2, "a __proto__ entry costs the map nothing");

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

// ─── Test: a corrupt newer bundle does not advance the freshness mark ────────────
//
// The freshness high-water mark must record only versions that fully loaded. A newer
// bundle whose manifest is intact and signed but whose module bytes are corrupt (a
// half-landed upgrade) must fail the content check WITHOUT raising the mark, or reloading
// the known-good older bundle is refused as a downgrade and rollback is bricked (§12.4).
async function testBundleCorruptNewerRollback() {
  console.log("Test: a corrupt newer bundle leaves the freshness mark intact (rollback stays possible)");
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
    const writeBundle = (version, signer = author) => wf(bundlePath, authorBundle(sodium, signer, {
      app: "victim", version,
      modules: [{ name: "codec", wasm: forwarderBytes }],
      guestSource: GUEST_TEXT, guestRequires: [],
    }).blob);

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
    writeBundle(1, heir);
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

  // Only actual absence is first boot. Bytes that exist but cannot reconstruct both
  // guard-bearing fields must fail closed.
  let absentThrew = false;
  try { new FreshnessMarks(null); } catch { absentThrew = true; }
  assert(!absentThrew, "an absent store starts empty on first boot");
  for (const json of ["", "not json at all", "{}", '{"marks":{}}', '{"revoked":[]}']) {
    let threw = false, msg = "";
    try { new FreshnessMarks(json); } catch (e) { threw = true; msg = String(e.message); }
    assert(threw, `an existing malformed or partial store fails closed (${json})`);
    if (json === "" || json === "{}") {
      assert(msg.includes("delete it to start from no marks") || msg.includes("Delete it to start from no marks"),
        `a ${json === "" ? "zero-byte" : "fieldless"} store explains operator recovery`);
    }
  }
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
    ['an unsafe-integer mark', JSON.stringify({ marks: { "aa:app": Number.MAX_SAFE_INTEGER + 1 }, revoked: [] })],
    ['a non-array "revoked"', JSON.stringify({ marks: {}, revoked: "nul" })],
    ['a non-string revoked entry', JSON.stringify({ marks: {}, revoked: [1] })],
    ['a malformed mark key', JSON.stringify({ marks: { "aa:app": 2 }, revoked: [] })],
    ['a malformed revoked author', JSON.stringify({ marks: {}, revoked: ["aa"] })],
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
  const oddApp = "line\nbreak:still-app";
  const odd = new FreshnessMarks(JSON.stringify({
    marks: { ["cc".repeat(32) + ":" + oddApp]: 3 }, revoked: [],
  }));
  assert(odd.get(new Uint8Array(32).fill(0xcc), oddApp) === 3,
    "freshness accepts every app spelling the manifest accepts");
  for (const version of [-1, Number.MAX_SAFE_INTEGER + 1]) {
    let threw = false;
    try { good.set(new Uint8Array(32).fill(0xaa), "new", version); } catch { threw = true; }
    assert(threw, `persistence refuses invalid version ${version}`);
  }

  // The Node adapter distinguishes a missing first-boot file from malformed or unreadable
  // state. A directory at the file path is a portable read failure that cannot be mistaken
  // for ENOENT.
  const { FileFreshnessStore } = await imp("build/host/shell-node.js");
  const { mkdtempSync, rmSync, writeFileSync, mkdirSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-freshness-read-"));
  const path = pjoin(dir, "marks.json");
  try {
    new FileFreshnessStore(path); // genuine absence
    writeFileSync(path, "not json");
    let malformed = false;
    try { new FileFreshnessStore(path); } catch { malformed = true; }
    assert(malformed, "Node refuses a malformed freshness file");
    rmSync(path);
    mkdirSync(path);
    let unreadable = false;
    try { new FileFreshnessStore(path); } catch { unreadable = true; }
    assert(unreadable, "Node refuses freshness read errors other than file-not-found");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: an app the runtime cannot serve is refused at load ────────────────
//
// `app` is the guest's signing scope, which caps at 255 UTF-8 bytes (guestSignScope's
// one-byte length). Refused at load, or a longer name verifies, installs, and then fails
// at first use — a bundle the host can admit but can never serve (§12.2, §12.4).
async function testAppNameLengthRefused() {
  console.log("Test: an over-long app name is refused at load, not at first use");
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
  const { blob } = authorBundle(sodium, author, {
    app: "persist", version: 1,
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: [],
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
// register its entrypoints, and the realm factory runs it SYNCHRONOUSLY inside the seam —
// so anything it reaches for has already landed by the time the commit window decides. The
// seam therefore refuses the WHOLE vocabulary in that window, reads and the bundle's own
// modules included: a rejected upgrade must leave the installed version's keyspace, its
// neighbours, and the links of whatever it was replacing untouched. A guest initializes
// from its preamble, which is why the candidate's `LOCAL` is still asserted complete here.
async function testCandidateRealmCannotActBeforeCommit() {
  console.log("Test: a candidate realm cannot act before its installation commits");
  const { admitAll } = await imp("build/host/policy.js");

  const author = testAuthor();
  const fs = new MemoryFs();
  let reached = 0;
  const { blob } = authorBundle(sodium, author, {
    app: "offside", version: 1, protocols: ["offside/v1"],
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: ["fs", "link"], guestCalls: ["_svc"],
  });
  // The neighbour a candidate must not reach: a REAL second bundle declaring `_svc`
  // under `services` (a co-resident guest's to reach, never a peer's), installed under
  // its own slot rather than stood in for by a host closure — dispatch has only ever had
  // one owner kind. Its own realm is a plain counting stub; what is under test is
  // whether the OFFSIDE candidate can reach it, not what it does once reached.
  const { blob: neighborBlob } = authorBundle(sodium, author, {
    app: "svc-neighbor", version: 1, services: ["_svc"],
    modules: [], guestSource: GUEST_TEXT, guestRequires: [],
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
  // A REAL socket-less driver (the browser-edge shape): a `link`-reaching bundle has
  // nowhere to go on a shell with no raw-link driver, so without one this candidate never
  // reaches the seam under test. The pin — this author's — is the other half of that.
  const shell = await bootTestShell({
    fs, freshnessStore: store, pinAuthor: author,
    createRealm: async ({ hostCall, source }) => {
      if (loadingNeighbor) {
        return { call: async () => { reached++; return new Uint8Array(); }, dispose() {} };
      }
      // One per kind the old irreversibility list sorted into open and closed: a durable
      // write, a cross-realm call, a link op, a pure read, a crypto transform, and this
      // bundle's own module. All six are one kind now.
      const refused = [];
      for (const [name, payload] of [
        ["fs/put", Uint8Array.of(0, 0, 0, 1, 120, 9)],
        ["_svc", new Uint8Array()],
        ["link/open", new Uint8Array(32)],
        ["node/identity", new Uint8Array()],
        ["crypto/blake2b-256", new Uint8Array()],
        ["fwd", Uint8Array.of(4)],
      ]) {
        try { await hostCall(name, payload); } catch { refused.push(name); }
      }
      const candidate = { hostCall, refused, source, calls: 0 };
      candidates.push(candidate);
      return {
        call: async () => { candidate.calls++; return new Uint8Array(); },
        dispose() {},
      };
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
    const localConfig = { custom: "kept", networkKey: "caller-value", linkIdleTimeoutMs: 1 };
    try { await shell.loadBundleBlob(blob, { localConfig }); } catch { rejected = true; }
    assert(rejected, "a failed freshness write rejects the candidate");
    const [, candidateLocal] = Function(
      candidates[0].source.split("\n").slice(0, 3).join("\n") + "\nreturn [APP, LOCAL];",
    )();
    assert(candidateLocal.custom === "kept",
      "a link slot keeps the load's ordinary installation-local config");
    assert(candidateLocal.networkKey === "00".repeat(32) &&
      candidateLocal.linkIdleTimeoutMs === 1 && candidateLocal.peerId === undefined,
    "only the driver's one immutable node fact overrides a same-named LOCAL key");
    assert(candidates[0].calls === 0,
      "standing a link slot does not invoke a second privileged init path");
    assertEqual(candidates[0].refused.sort(),
      ["_svc", "crypto/blake2b-256", "fs/put", "fwd", "link/open", "node/identity"],
      "a candidate reaches nothing at all — not a write, another realm, a link, or a read");
    assertEqual(reached, 0, "…so the realm it called was never entered");
    assertEqual((await fs.stat()).used, 0, "…and it left nothing on disk");
    assert(shell.uninstall(key) === false, "a failed candidate never publishes its claim");

    store.fail = false;
    await shell.loadBundleBlob(blob, { localConfig });
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
  const blob = (version) => authorBundle(sodium, author, {
    app: "upgrade", version,
    protocols: ["upgrade/v1"],
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: ["timer"],
  }).blob;

  // Each realm records what it was asked to run and whether it was released, and arms a
  // 200 ms deadline on construction — the guest's half, since a deadline exists only
  // because a guest asked for one and re-enters THAT guest's realm. 200 rather than 5
  // because the upgrade loads the replacing bundle's modules in workers, and a deadline
  // firing inside that window is a legitimate turn of the guest that armed it.
  const realms = [];
  let failNextRealm = false;
  const arm = (id, ms) => {
    const event = writeOp("timer", Uint8Array.from([id >>> 24, id >>> 16, id >>> 8, id]));
    const p = new Uint8Array(8 + event.length);
    writeU32BE(p, 0, id); writeU32BE(p, 4, ms); p.set(event, 8);
    return p;
  };
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
      // Armed on this realm's FIRST entry, not from `createRealm`: a candidate's seam
      // refuses everything until its installation commits (§3.1), which is the same
      // reason a real guest defers its setup to its first invocation.
      const r = { calls: [], disposed: false, call: async (p) => {
        r.calls.push(opNameOf(p) === "timer" ? "timer" : "invoke");
        if (!r.armed) { r.armed = true; await o.hostCall("timer/arm", arm(1, 200)); }
        return new Uint8Array();
      }, dispose() { r.disposed = true; } };
      realms.push(r);
      return r;
    },
    admit: byPrivilege({ base: admitAll, grants: { link: denyAll } }),
  });
  try {
    const first = await shell.loadBundleBlob(blob(1));
    await first.invoke(new Uint8Array());
    assertEqual(realms.length, 1, "the first slot stands one realm");

    failNextRealm = true;
    let failed = false;
    try { await shell.loadBundleBlob(blob(2)); } catch { failed = true; }
    assert(failed, "a candidate whose guest cannot stand is refused");
    assert(!realms[0].disposed, "the failed candidate leaves the running realm intact");
    assertEqual(shell.resolve("upgrade/v1"), key, "…and leaves its claim intact");

    const replacement = await shell.loadBundleBlob(blob(2));
    assert(realms[0].disposed, "the upgrade disposed the realm it replaced");
    let staleRejected = false;
    try { await first.invoke(new Uint8Array()); } catch { staleRejected = true; }
    assert(staleRejected, "the replaced slot's handle is revoked");
    await replacement.invoke(new Uint8Array());
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

// ─── Test: generated guest op-frame source is the canonical implementation ─────
//
// host/op-frame.ts owns the functions. `guestOpFraming` serializes those exact compiled
// functions for import-free guests; the transport assembler injects the same fragment.
// Exercise the emitted program at every boundary so serialization cannot change behavior.
function testGeneratedOpFrame() {
  console.log("Test: generated guest op-frame source preserves the canonical implementation");
  // Every caller inlines this fragment into a guest it then SIGNS, so the bytes must not
  // depend on the machine that compiled op-frame.ts. Line endings are the part that does.
  assert(!guestOpFraming().includes("\r"), "the emitted op-frame source is LF-only, so a signed guest is the same bytes anywhere");
  const host = { callerOf, readOp, writeOp };
  const guest = new Function(`"use strict";${guestOpFraming()}
    return { callerOf, readOp, writeOp };`)();
  // Outcome, not message: the emitted source and module execute in different contexts, so
  // what must agree is accept-vs-reject and the bytes on accept.
  const out = (impl, fn, args) => { try { return JSON.stringify(impl[fn](...args)); } catch { return "threw"; } };
  const agree = (label, fn, ...args) =>
    assert(out(guest, fn, args) === out(host, fn, args), `${label}: generated source and host disagree`);

  // A caller id differing from the host's all-zero one in its LAST byte: a prefix test
  // would call this the host.
  const peer = new Uint8Array(32); peer[31] = 1;
  agree("a host loopback", "callerOf", concatBytes([new Uint8Array(32), enc.encode("hi")]));
  agree("a caller differing only in its last byte", "callerOf", concatBytes([peer, new Uint8Array(0)]));
  agree("a well-formed op", "readOp", Uint8Array.from([2, 0x68, 0x69, 9]));
  // Declared length equal to the bytes left after it — what separates `len < 1 + n`
  // from `len < n`.
  agree("a length one byte past the end", "readOp", Uint8Array.from([2, 0x61]));
  agree("an ordinary op", "writeOp", "put", Uint8Array.from([1, 2, 3]));
  agree("an empty op name", "writeOp", "", new Uint8Array(0));
  agree("a 255-byte op name", "writeOp", "a".repeat(255), new Uint8Array(0));
  agree("a 256-byte op name", "writeOp", "a".repeat(256), new Uint8Array(0));
  // 0x80 is the only code point that separates a `> 127` ceiling from a `> 128` one.
  agree("an op at the first non-ASCII code point", "writeOp", "a" + String.fromCharCode(0x80), new Uint8Array(0));
  console.log("  OK\n");
}

// ─── Run ────────────────────────────────────────────────────────────────

await testFullLifecycle();
await testInstallRejectsUntrustedAuthor();
await testManifestHashIsEnforced();
await testDenyAllPolicyRejects();
testGeneratedOpFrame();
await testBundleRefusesNonModule();
await testDerivedNamesKeepAuthorsApart();
await testManifestClaimIsTheRouting();
await testInstallerRemove();
await testFs();
await testFsKeyRule();
await testSlotFreshness();
await testShellBoot();
await testBundle();
await testGuestBundleAndArchive();
await testBundleCorruptNewerRollback();
await testAuthorRevocation();
await testPreRevocationStoreIsRefused();
await testWrongTypedStoreIsRefused();
await testAppNameLengthRefused();
await testPersistFailureRollsBack();
await testCandidateRealmCannotActBeforeCommit();
await testFailedRevokePersistRollsBack();
await testInPlaceUpgradeReleasesTheOldSlot();

summary("Results");
