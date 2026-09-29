// Bundle verify, admit and install (§12.4, §12.5, §12.10): routing claims, fs, freshness,
// revocation, and in-place upgrade. realm-guest.test.mjs covers the guest seam,
// bundle-replacement.test.mjs explicit slot replacement, and crypto.test.mjs the manifest
// suite and ACVP vectors.
//
// Valid bundle fixtures go through `authorBundle` (scripts/bundle-author.ts), which
// assembles, validates and signs in one call, as a real publisher does. A few tests build
// a manifest or envelope by hand because they need it malformed or corrupted (duplicate
// module names, a corrupted body, a tampered envelope byte), which `authorBundle` cannot
// produce since it calls `validateManifest`; those use `signTestBundle`.

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { testkit } from "./testkit.mjs";
import {
  sodium, generateKeyPair, JsModuleLoader, bootShell, bootNodeShell,
  toHex, fromHex, concatBytes, writeU32BE, hybridAuthorId, FreshnessMarks,
  verifyTestBundle, verifyBundle, loadBundleModules,
  signTestBundle, guestOpFraming, authorBundle, policyFromJson, authorAllowlist,
  checkHostGates, GUEST_TEXT, GUEST_BYTES, GUEST, testAuthor, boot, bootTestShell,
  loadBundle, EMPTY, TestModuleHost, testHost, installBundle, makeHost,
  forwarderBytes, installMod, imp, root, bytesEqual, callerOf, readOp, writeOp, isWake,
  MemoryFs, NodeFs, enc, withTestBudget,
} from "./fixtures.mjs";

const { ok, assertEqual, summary } = testkit({ verbose: false });
const assert = ok;

// ─── Test: install a module, reach it by name ───────────────────────────

async function testFullLifecycle() {
  console.log("Test: install a bundle module and reach it by name (§4, §12.4)");

  const { host } = await makeHost();
  const chatKey = "chat";

  // Installed through the same path install uses. The forwarder fixture is a
  // pure transform that echoes its input.
  await installMod(host, chatKey, "chat", forwarderBytes);
  assert(host.isBound(chatKey, "chat"), "chat module installed");

  // Reach it by name: the host writes input at the module's scratch, calls handle, and
  // reads the response back (§4). A guest reaches the same module through its seam by the
  // bare name (§12.2); here the host calls it directly.
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

  // A valid manifest signed by an author who is not in the policy.
  const { blob } = authorBundle(sodium, author, {
    app: "demo", version: 1,
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: [],
  });

  // The predicate only trusts a different key.
  const stranger = testAuthor();
  const admit = authorAllowlist([toHex(stranger.id)]);
  let threw = false;
  try { await loadBundle(host, blob, admit); } catch { threw = true; }
  assert(threw, "installBundle throws when the author is not in the policy");

  console.log("  OK\n");
}

async function testWholeBundleIsSigned() {
  console.log("Test: both signatures cover the manifest, guest, module order and framing");
  const author = testAuthor();
  const wasm = [forwarderBytes, Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0)];
  const { blob, manifest } = authorBundle(sodium, author, {
    app: "demo", version: 1,
    modules: [{ name: "second", wasm: wasm[0] }, { name: "first", wasm: wasm[1] }],
    guestSource: GUEST_TEXT, guestRequires: [],
  });
  const v = verifyBundle(sodium, blob);
  assert(bytesEqual(v.modules[0].wasm, wasm[0]) && v.modules[0].mod.name === "second",
    "modules retain manifest order, regardless of logical names");
  assert(!("hash" in v.manifest.guest) && v.manifest.modules.every(m => !("hash" in m)),
    "the signed manifest contains no per-file hashes");
  const bodyOffset = 1 + 32 + 1952 + 64 + 3309;
  const manifestLength = enc.encode(JSON.stringify(manifest)).length;
  const guestOffset = bodyOffset + 4 + manifestLength;
  const moduleOffset = guestOffset + 4 + GUEST_BYTES.length;
  const refuses = (bytes, why, expected = "signature invalid") => {
    let message = "";
    try { verifyBundle(sodium, bytes); } catch (e) { message = e.message; }
    assert(message.includes(expected), why + ": " + message);
  };
  for (const offset of [bodyOffset, bodyOffset + 4, guestOffset, guestOffset + 4, moduleOffset, moduleOffset + 4]) {
    const bad = blob.slice(); bad[offset] ^= 1;
    refuses(bad, "tampering with any body field or length fails authentication");
  }
  refuses(blob.slice(0, -1), "truncation fails authentication");
  refuses(concatBytes([blob, Uint8Array.of(0)]), "appending bytes fails authentication");
  const reordered = signTestBundle(sodium, author, manifest, GUEST_BYTES, wasm.toReversed());
  const swapped = blob.slice(); swapped.set(reordered.subarray(bodyOffset), bodyOffset);
  refuses(swapped, "reordering modules without resigning fails authentication");
  // Signed but inconsistent layouts are rejected after authentication.
  refuses(signTestBundle(sodium, author, manifest, GUEST_BYTES, [wasm[0]]),
    "missing signed module is rejected", "truncated body");
  refuses(signTestBundle(sodium, author, manifest, GUEST_BYTES, [...wasm, wasm[0]]),
    "extra signed module is rejected", "trailing bytes");
  // Neither keys nor module bytes retain aliases to caller-owned Node Buffers.
  const buffer = Buffer.from(blob), owned = verifyBundle(sodium, buffer);
  buffer.fill(0);
  assert(bytesEqual(owned.modules[0].wasm, wasm[0]) && bytesEqual(owned.authorKeys.ed, author.ed.publicKey),
    "verified bytes own their storage");
  console.log("  OK\n");
}

async function testDenyAllPolicyRejects() {
  console.log("Test: an omitted policy is deny-all, not 'no policy' (§12.5, §14)");

  // `policyFromJson(null)` is the boot default on every target: a predicate that returns
  // false for every bundle. No policy never means permission.
  const admit = policyFromJson(null);
  assert(!admit({ author: new Uint8Array(32), manifest: { app: "x", version: 1, modules: [] }, modules: [], guestSource: "" }),
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
  console.log("Test: a signed WASM payload that isn't a valid module fails the whole bundle");

  const author = testAuthor();
  const { host } = await makeHost();

  // Two modules the author really signed: the forwarder, and arbitrary bytes that are
  // signed but will not instantiate. A module failing to build must fail the whole
  // install, leaving nothing installed.
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
  // Neither module is bound: the install was atomic.
  assert(!host.isBound("demo", "fwd"), "the valid module is NOT bound (the load failed atomically)");
  assert(!host.isBound("demo", "broken"), "the non-module is not bound");

  console.log("  OK\n");
}


// ─── Test: the manifest's claims are the routing (§12.10) ──────────────────────
// The bundle declares the protocol ids it serves and the install claims them, with no
// operator step in between. Each claim has one owner: an update replaces its own claims
// atomically, and a different bundle cannot silently displace it.
async function testManifestClaimIsTheRouting() {
  console.log("Test: the manifest's claim IS the routing (§12.10)");
  const { admitAll } = await imp("build/host/policy.js");

  const author = testAuthor();
  const other = testAuthor();
  // One bundle shape, parameterized by signer, label, version and claims.
  const blob = (signer, app, version, protocols) => authorBundle(sodium, signer, {
    app, version, protocols,
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: [],
  }).blob;
  let realmBuilds = 0;
  const identity = generateKeyPair();
  const shell = await bootTestShell({
    identity,
    createRealm: async () => {
      realmBuilds++;
      return { call: async () => new Uint8Array(), dispose() {} };
    },
    admit: admitAll,
  });
  try {
    const key = "store";
    await shell.install(blob(author, "store", 1, ["seedstore/v1"]));
    assertEqual(shell.resolve("seedstore/v1"), key,
      "the load claimed the manifest's protocol — no second operator action");
    assert(shell.resolve("store") === null,
      "…and exactly the id it declared, never a default to the app's own name");

    // An app that claims nothing serves nothing: the initiator-only shape (§12.8), which
    // is why the field is optional.
    const quiet = "quiet";
    await shell.install(blob(author, "quiet", 1, undefined));
    assertEqual(shell.routes().length, 1, "a bundle claiming nothing adds no route");

    // An install without `replaces` needs a free label: this one is taken, and taking it
    // over has to be explicit.
    let taken = "";
    try { await shell.install(blob(author, "store", 2, ["seedstore/v2"])); }
    catch (e) { taken = String(e); }
    assert(taken.includes("is already installed") && taken.includes("replaces"),
      `an install onto a running label is refused by name, got: ${taken || "no error"}`);
    assertEqual(shell.resolve("seedstore/v1"), key, "…leaving the running version's claim untouched");

    // An update takes its claims from the new manifest, so a dropped claim stops being
    // served.
    await shell.install(blob(author, "store", 2, ["seedstore/v2"]), { replaces: key });
    assertEqual(shell.resolve("seedstore/v2"), key, "an update claims what the new manifest declares");
    assert(shell.resolve("seedstore/v1") === null, "…and drops the claim it no longer makes");

    // A second app cannot shadow an active claim. Rejection leaves the existing route
    // untouched and never evaluates the candidate's guest.
    const rival = "rival-store";
    const buildsBeforeConflict = realmBuilds;
    let conflict = "";
    try { await shell.install(blob(other, rival, 1, ["seedstore/v2"])); }
    catch (e) { conflict = String(e); }
    assert(conflict.includes("claim 'seedstore/v2' is already held"),
      `a contested claim is rejected by name, got: ${conflict || "no error"}`);
    assertEqual(shell.resolve("seedstore/v2"), key,
      "a rejected claimant does not disturb the active route");
    assert(shell.uninstall(rival) === false, "the rejected candidate did not install a slot");
    assertEqual(realmBuilds, buildsBeforeConflict,
      "a known claim conflict is refused before the candidate guest executes");

    // Uninstall drops what the app claimed.
    shell.uninstall(key);
    shell.uninstall(quiet);
    assert(shell.resolve("seedstore/v2") === null, "uninstall drops the app's claims");
    assertEqual(shell.routes().length, 0, "…leaving no route behind");

    // Every per-realm ceiling is multiplied by the number of realms (§12.3), so the number
    // of installs is capped. A replacement is never refused (it takes the slot its label
    // already holds), and an uninstall frees one.
    const { DEFAULT_MAX_APP_SLOTS } = await imp("build/host/wasm-limits.js");
    for (let i = 0; i < DEFAULT_MAX_APP_SLOTS; i++) {
      await shell.install(blob(author, `filler${i}`, 1, [`filler/${i}`]));
    }
    let overfull = "";
    try { await shell.install(blob(author, "one-too-many", 1, ["filler/x"])); }
    catch (e) { overfull = String(e); }
    assert(overfull.includes("app slots"), `a full node refuses another app, got: ${overfull || "no error"}`);
    assert(shell.resolve("filler/x") === null, "…and the refused candidate claimed nothing");
    await shell.install(blob(author, "filler0", 2, ["filler/0"]), { replaces: "filler0" });
    assertEqual(shell.resolve("filler/0"), "filler0",
      "a replacement takes the slot its own label already holds");
    shell.uninstall("filler0");
    await shell.install(blob(author, "one-too-many", 1, ["filler/x"]));
    assertEqual(shell.resolve("filler/x"), "one-too-many",
      "uninstalling gives the slot back");
    shell.uninstall("one-too-many");
    for (let i = 1; i < DEFAULT_MAX_APP_SLOTS; i++) shell.uninstall(`filler${i}`);
    assertEqual(shell.routes().length, 0, "the node is empty again");

    // The format's half of the rule: an id that is not routable is refused at verify, not
    // dropped quietly.
    for (const bad of [["bad id"], ["dup", "dup"], ["a".repeat(65)], [""], [7]]) {
      let threw = false;
      try {
        verifyTestBundle(sodium, signTestBundle(sodium, author,
          { app: "bad", version: 1, protocols: bad, modules: [], guest: GUEST() }));
      } catch (e) { threw = /malformed manifest/.test(String(e)); }
      assert(threw, `a manifest claiming ${JSON.stringify(bad)} is refused as malformed`);
    }
    // No spelling is reserved to the host: a name starting with `_` is valid in either
    // claim list, and the list, not the spelling, decides who may reach it.
    for (const claim of ["_offer", "_host", "_net", "plain"]) {
      verifyTestBundle(sodium, signTestBundle(sodium, author,
        { app: "reserved", version: 1, protocols: [claim], modules: [], guest: GUEST() }));
      verifyTestBundle(sodium, signTestBundle(sodium, author,
        { app: "reserved", version: 1, services: [claim], modules: [], guest: GUEST() }));
    }
    // Two maps, so uniqueness is per list. A name in both is not ambiguous: it is reachable
    // by a peer and by a co-resident guest. A duplicate within one list is refused.
    {
      assert(verifyTestBundle(sodium, signTestBundle(sodium, author,
        { app: "dual", version: 1, protocols: ["both"], services: ["both"], modules: [], guest: GUEST() })) !== null,
      "a name claimed in BOTH `protocols` and `services` is two reaches, not a conflict");
      let threw = false;
      try {
        verifyTestBundle(sodium, signTestBundle(sodium, author,
          { app: "dup", version: 1, protocols: ["twice", "twice"], modules: [], guest: GUEST() }));
      } catch (e) { threw = /malformed manifest/.test(String(e)); }
      assert(threw, "a name claimed twice in the SAME list is still refused");
    }
    // The property that matters: a peer cannot reach a name in `services` but can reach
    // the same bundle's `protocols` name, checked through `link/deliver` instead of by
    // inspecting the claim table. A separate node, since this one's transport is gone; its
    // realms echo the payload after the caller.
    {
      const pub = "reach/public", priv = "_reach-private";
      const seams = [];
      const node = await bootTestShell({
        identity,
        transport: {},
        createRealm: async (o) => {
          seams.push(o.hostCall);
          return { call: async (input) => input.slice(32), dispose() {} };
        },
        admit: admitAll,
      });
      try {
        await node.install(authorBundle(sodium, author, {
          app: "reach", version: 1, protocols: [pub], services: [priv],
          modules: [], guestSource: GUEST_TEXT, guestRequires: [],
        }).blob);
        // The boot transport was created first. Its `link/deliver` body is
        // `[claimLen u8][claim]` followed by the realm argument
        // `[attribution 32][payload ...]`.
        const deliver = withTestBudget(seams[0]);
        const framed = concatBytes([new Uint8Array(32).fill(0x11), new Uint8Array([1, 2, 3])]);
        const to = (claim) => concatBytes([Uint8Array.of(claim.length), enc.encode(claim), framed]);
        assertEqual([...await deliver("link/deliver", to(pub))], [1, 2, 3],
          "a name in `protocols` is reachable by a peer");
        assertEqual((await deliver("link/deliver", to(priv))).length, 0,
          "the same bundle's `services` name is unreachable by a peer, however it is spelled");
      } finally { node.close(); }
    }
  } finally { shell.close(); }
  console.log("  OK\n");
}

// ─── Test: removeApp, the per-app unbind ────────────────────────────────

async function testInstallerRemove() {
  console.log("Test: removeApp drops exactly one app (§3.1, §12.5)");

  const { host } = await makeHost();

  // Two apps, one of them holding two modules.
  const chat = "chat";
  const notes = "notes";

  await host.bindAll(chat, [{ name: "text", wasm: forwarderBytes }, { name: "media", wasm: forwarderBytes }]);
  await installMod(host, notes, "text", forwarderBytes);
  assert(host.isBound(chat, "text") && host.isBound(chat, "media"), "the app's two modules installed");
  assert(host.isBound(notes, "text"), "the other app installed");

  // Removal is per app: one call removes every module the app installed and nothing else.
  assertEqual(host.removeApp(chat), 2, "both modules of the app went in one call");
  assert(!host.isBound(chat, "text") && !host.isBound(chat, "media"), "the app is gone");
  assert(host.isBound(notes, "text"), "the other app is untouched");

  // Nothing else to clear: no tombstone.
  assertEqual(host.removeApp(chat), 0, "a second call removes nothing");
  await installMod(host, chat, "text", forwarderBytes);
  assert(host.isBound(chat, "text"), "reinstall after remove succeeds");

  console.log("  OK\n");
}

// ─── Test: fs service (opaque key to bytes) ─────────────────────────

async function testFs() {
  console.log("Test: fs service — opaque key → bytes (NodeFs + MemoryFs)");

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
      // The seam is async on every backend (services/fs.ts), so a browser backend can
      // implement it.
      const bytes = new Uint8Array([1, 2, 3, 4, 5]);
      assert(await fs.size("a.blk") < 0, `${name}: absent before put`);
      assertEqual(await fs.size("a.blk"), -1, `${name}: size -1 when absent`);
      assertEqual(await fs.get("a.blk"), null, `${name}: get null when absent`);

      await fs.put("a.blk", bytes);
      assert(await fs.size("a.blk") >= 0, `${name}: present after put`);
      assertEqual(await fs.size("a.blk"), 5, `${name}: size reflects bytes`);
      assert(bytesEqual(await fs.get("a.blk"), bytes), `${name}: get round-trips`);
      const read = await fs.get("a.blk");
      const copy = read.slice();
      copy.fill(0);
      assert(bytesEqual(read, bytes), `${name}: returned bytes keep copying slice semantics`);
      read.fill(0);
      assert(bytesEqual(await fs.get("a.blk"), bytes), `${name}: a read owns its bytes independently of the store`);

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
    // The key check throws inside an async method, so it surfaces as a rejection, still
    // before any syscall.
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

  // A cold store must seed its byte total before concurrent mutations start changing it.
  // Only same-file mutations need ordering, and a failed write must not poison the queue
  // or leave the old size charged after the file was partially overwritten.
  const disk = (await import("node:fs/promises")).default;
  const { syncBuiltinESMExports } = await import("node:module");
  const cachedDir = mkdtempSync(pjoin(tmpdir(), "seedkernel-fs-cached-"));
  const write = disk.writeFile;
  try {
    await write(pjoin(cachedDir, "existing"), new Uint8Array(17));
    await write(pjoin(cachedDir, "other"), new Uint8Array(2));
    class CountedFs extends NodeFs {
      sizeCalls = 0;
      async size(key) { this.sizeCalls++; return super.size(key); }
    }
    const fs = new CountedFs(cachedDir);
    await Promise.all([
      fs.put("existing", new Uint8Array(5)),
      fs.put("shared", new Uint8Array(3)),
      fs.put("shared", new Uint8Array(11)),
      fs.delete("shared"),
      fs.put("shared", new Uint8Array(7).fill(42)),
      ...Array.from({ length: 32 }, (_, i) => fs.put(`block-${i}`, new Uint8Array(i + 1))),
      fs.stat(),
    ]);
    assertEqual((await fs.stat()).used, 5 + 2 + 7 + 528, "NodeFs: cold scan and concurrent size deltas agree");
    assert(bytesEqual(await fs.get("shared"), new Uint8Array(7).fill(42)), "NodeFs: overlapping same-file mutations preserve call order");
    const probes = fs.sizeCalls;
    await Promise.all(Array.from({ length: 10 }, () => fs.stat()));
    assertEqual(fs.sizeCalls, probes, "NodeFs: repeated statistics never probe individual files");
    await fs.put("shared", new Uint8Array(0));
    assert(await fs.delete("shared"), "NodeFs: deleting an empty value succeeds");
    assert(!(await fs.delete("shared")), "NodeFs: deleting a missing value leaves accounting alone");
    assertEqual((await fs.stat()).used, 5 + 2 + 528, "NodeFs: shrinking and deleting adjust the total");

    disk.writeFile = async (path, data, ...args) => {
      if (path === pjoin(cachedDir, "existing")) {
        await write(path, data.subarray(0, 3), ...args);
        throw new Error("injected failure after partial write");
      }
      return write(path, data, ...args);
    };
    syncBuiltinESMExports();
    let failed = false;
    try { await fs.put("existing", new Uint8Array(20)); } catch { failed = true; }
    assert(failed, "NodeFs: a partial write still rejects");
    assertEqual((await fs.stat()).used, 3 + 2 + 528, "NodeFs: partial-write failure accounts for the bytes actually left");
    disk.writeFile = write;
    syncBuiltinESMExports();
    await fs.put("existing", new Uint8Array(8));
    assertEqual((await fs.stat()).used, 8 + 2 + 528, "NodeFs: a failed write does not poison later writes");
    assertEqual((await new NodeFs(cachedDir).stat()).used, (await fs.stat()).used, "NodeFs: reopening reconstructs the same total");
  } finally {
    disk.writeFile = write;
    syncBuiltinESMExports();
    rmSync(cachedDir, { recursive: true, force: true });
  }

  console.log("  OK\n");
}

// ─── Test: the fs key space is one rule, shared by every target ──────────
// Which keys a node accepts decides which blocks it stores and advertises, so it is
// consensus: a Go node and a Bun node that disagree about it disagree about their
// contents. The rule lives in shared code (services/fs.ts `isSafeFsKey`), applied over
// whatever backend a target supplies (`validatedFs`, host/fs-view.ts).

async function testFsKeyRule() {
  console.log("Test: fs key space is one rule — isSafeFsKey over any backend (validatedFs)");

  const { isSafeFsKey } = await imp("build/services/fs.js");
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

  // validatedFs applies it to every op that names a key, as a rejection, not a silent
  // miss: an invalid key is a caller bug on read as much as on write.
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

  // It does not apply to ops that take no key. `list()` takes a prefix, and the empty
  // prefix (every key) is exactly what a key rule here would wrongly refuse.
  assertEqual((await fs.list()).join(","), "ok.blk", "validatedFs leaves list(undefined) alone");
  assertEqual((await fs.list("ok")).join(","), "ok.blk", "validatedFs leaves a list prefix alone");
  assert((await fs.stat()).used === 1, "validatedFs leaves stat alone");

  // The shell puts validatedFs under scopedFs, so the rule sees the full key the backend
  // sees: a guest key that would escape its scope is refused even though the scope prefix
  // is itself valid.
  const scoped = scopedFs(fs, "abcd1234");
  await scoped.put("mine.blk", new Uint8Array([2]));
  assert((await fs.get("abcd1234mine.blk")) !== null, "scoped put lands under the scope");
  let escaped = false;
  try { await scoped.put("../../etc", new Uint8Array([3])); } catch { escaped = true; }
  assert(escaped, "a scoped key with separators is refused on the composite");

  console.log("  OK\n");
}

// ─── Test: freshness is per (author, app), transport included (§12.4) ──────────

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
  // The install path as the shell runs it: the host's gates read the store, the modules
  // are loaded, and the mark is advanced last, after the guest starts. That is the shell's
  // job, so the mark is written here. The predicate never touches the store, so only one
  // place refuses a downgrade.
  const land = async (host, freshness, author, version) => {
    const v = verifyBundle(sodium, blobFrom(author, version));
    checkHostGates(v, freshness);
    await installBundle(host, v);
    freshness.set(v.author, v.manifest.app, v.manifest.version);
  };

  // Versions are per author, transport or not: a floor keyed to the transport would put
  // two independent authors on one shared version line (§12.4).
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

  // The store holds marks and revocations only. A file with an unrecognized key (one a
  // newer version added, say) still loads; the key is ignored and dropped on rewrite.
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
  console.log("Test: seedkernel-shell boots under a policy and wires its host service backends");
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
      identity, // no transport, so no network
    });
    // Installing an allowed author's bundle is covered end to end by testBundle (§12.4).
    assert((await shell.fs.list()).length === 0, "fs.* backend is wired over the data dir");
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: app bundle, signed manifest and policy-gated install ────────

async function testBundle() {
  console.log("Test: app bundle — signed manifest, integrity, governed load by the shell");
  const { mkdtempSync, rmSync, writeFileSync: wf, readFileSync: rf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = testAuthor();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-bundle-"));
  const bundlePath = pjoin(dir, "app.skb");
  let shell, shell2;
  try {
    // A minimal one-module bundle (forwarder.wasm) plus a guest stub. Modules install
    // from the manifest (§12.4) under the signed `app` label, each by its own name; the
    // manifest has no filenames, and module bytes follow the guest in manifest order.
    const { host: h } = await makeHost();
    const testKey = "test";
    const guestText = "function handle() { return new Uint8Array([1]); }";
    const manifest = {
      app: "test", version: 1,
      modules: [{ name: "codec" }],
      // requires and config live inside `guest` (§12.4): only the guest has authority.
      guest: {
        requires: [],
      },
    };
    const writeBundle = (m) => wf(bundlePath, signTestBundle(sodium, author, m, enc.encode(guestText), [forwarderBytes]));
    writeBundle(manifest);

    // sign / verify / tamper
    const env = signTestBundle(sodium, author, manifest);
    assert(verifyTestBundle(sodium, env) !== null, "a well-formed manifest verifies");
    const tampered = env.slice(); tampered[tampered.length - 1] ^= 1;
    assert(verifyTestBundle(sodium, tampered) === null, "a tampered manifest fails verification");

    // A manifest whose module names collide is ambiguous (the name is the guest's key for
    // the module), so it is refused even though it is validly signed (§12.4).
    const dupEnv = signTestBundle(sodium, author, {
      ...manifest,
      modules: [manifest.modules[0], { ...manifest.modules[0] }],
    });
    let dupRefused = false;
    try { verifyTestBundle(sodium, dupEnv); } catch { dupRefused = true; }
    assert(dupRefused, "a manifest with duplicate module names is refused as malformed");

    // A shell whose policy allows the author installs the bundle and its module.
    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.id)] }),
      dir: pjoin(dir, "_data"), identity,
    });
    const loaded = await shell.installFile(bundlePath);
    assert(loaded.guestSource.includes("function handle"), "guest source loaded + integrity-checked");

    // Freshness (§12.4): the version is a monotonic high-water mark per (author, app), set
    // to 1 by the install above. Installing this label again needs `replaces`, since an
    // install without it only takes a free label.
    const remanifest = (version) => writeBundle({ ...manifest, version });
    const reload = () => shell.install(new Uint8Array(rf(bundlePath)), { replaces: loaded.manifest.app });
    remanifest(1); await reload();                // equal version reinstalls (an ordinary reboot)
    remanifest(2); await reload();                // newer version advances the mark to 2
    remanifest(1);                                // now a downgrade
    let downgradeRefused = false;
    try { await reload(); } catch { downgradeRefused = true; }
    assert(downgradeRefused, "a version below the (author, app) high-water mark is refused as a downgrade");
    remanifest(2); await reload();                // the mark held at 2, so v2 still loads
    remanifest(1);                                // restore the original for the shell2 check below

    // A shell whose policy does not allow the author refuses the bundle.
    shell2 = await boot({
      policyJson: JSON.stringify({ authors: [toHex(generateKeyPair().publicKey)] }),
      dir: pjoin(dir, "_data2"), identity,
    });
    let refused = false;
    try { await shell2.installFile(bundlePath); } catch { refused = true; }
    assert(refused, "a bundle from a non-allowed author is refused");
  } finally {
    if (shell) shell.close();
    if (shell2) shell2.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: every app is a guest (§12.4), and the verify/install split ────
// A chat-style app is a guest plus its module; since requires live inside `guest`, an
// empty list declares no authority. Covers the one app shape (guestSource round-trips),
// a bundle blob round-tripping as one value, and `verifyBundle` authenticating and
// checking integrity without a host or policy, which is how a browser shell inspects a
// received Offer before asking for consent.
async function testGuestBundle() {
  console.log("Test: every app is a guest — bundle blob + verify/install split");
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
    const demoKey = "demo";
    // A manifest with no `guest` field is refused: every app is a guest (§12.4).
    let noGuest = "";
    try {
      verifyTestBundle(sodium, signTestBundle(sodium, author,
        { app: "demo", version: 1, modules: [{ name: "demo" }] }));
    } catch (e) { noGuest = e.message; }
    assert(noGuest.includes("every app is a guest"), `a manifest without a guest is refused by name (got: ${noGuest})`);

    const manifest = {
      app: "demo", version: 1,
      modules: [{ name: "demo" }],
      guest: GUEST(),
    };
    const packed = signTestBundle(sodium, author, manifest, GUEST_BYTES, [forwarderBytes]);
    assert(bytesEqual(verifyBundle(sodium, packed).modules[0].wasm, forwarderBytes), "module bytes round-trip");

    // Verification on its own, with no host, policy or freshness (a browser shell's
    // inspection path). It authenticates and returns every verified byte.
    const v = verifyBundle(sodium, packed);
    assert(bytesEqual(v.author, author.id), "verifyBundle returns the signing author");
    assertEqual(v.modules.length, 1, "verifyBundle yields the manifest's modules");
    assertEqual(v.guestSource, GUEST_TEXT, "verifyBundle yields the verified guest source");
    // Load the bundle through the shared install path.
    wf(bundlePath, packed);
    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.id)] }),
      dir: pjoin(dir, "_data"), identity,
    });
    const loaded = await shell.installFile(bundlePath);
    assertEqual(loaded.guestSource, GUEST_TEXT, "the shell yields the verified guest source");
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: a corrupt newer bundle does not advance the freshness mark ────────────
//
// The freshness mark must only record versions that fully installed. A newer bundle whose
// manifest is intact and signed but whose module bytes are corrupt (a half-written
// upgrade) must fail without raising the mark, or reinstalling the known-good older bundle
// is refused as a downgrade and rollback is impossible (§12.4).
async function testBundleCorruptNewerRollback() {
  console.log("Test: a corrupt newer bundle leaves the freshness mark intact (rollback stays possible)");
  const { mkdtempSync, rmSync, writeFileSync: wf, readFileSync: rf } = await import("node:fs");
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
      modules: [{ name: "codec" }],
      guest: {
        requires: [],
      },
    });
    const writeBundle = (version, wasm = forwarderBytes) => {
      const blob = signTestBundle(sodium, author, manifest(version), enc.encode(guestText), [forwarderBytes]);
      // Model a partially written bundle by truncating after signing.
      wf(bundlePath, blob.slice(0, blob.length - (forwarderBytes.length - wasm.length)));
    };

    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.id)] }),
      dir: pjoin(dir, "_data"), identity,
    });

    // 1. Good v4 installs and sets the mark to 4. Every step after it is an upgrade of
    //    this slot, as a real half-written upgrade would be.
    writeBundle(4);
    const v4 = await shell.installFile(bundlePath);
    const upgrade = () => shell.install(new Uint8Array(rf(bundlePath)), { replaces: v4.manifest.app });

    // 2. A corrupt v5: validly signed at version 5, but the module bytes no longer match
    //    the signed body. The install must fail signature verification.
    writeBundle(5, forwarderBytes.slice(0, forwarderBytes.length - 1));
    let v5Failed = false;
    try { await upgrade(); } catch { v5Failed = true; }
    assert(v5Failed, "a corrupt v5 bundle fails to load");

    // 3. Restore the good v4 bundle and reinstall. If the failed v5 install had advanced
    //    the mark to 5, this would be refused as a downgrade. It must still install.
    writeBundle(4);
    let v4Reloaded = true;
    try { await upgrade(); } catch { v4Reloaded = false; }
    assert(v4Reloaded, "the known-good v4 reloads after the corrupt v5 attempt (mark not advanced)");
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: revoking a compromised author key (§12.5) ─────────────────────────
//
// Freshness cannot tell whether a key still belongs to its author: a stolen key signs
// `version + 1`, passes the high-water mark, and installs again whenever it likes.
// `shell.revoke` is the remedy; this tests that it both uninstalls and refuses, and that
// the refusal survives a reboot. An operator doing it by hand could uninstall without
// blocking the key, or block it with the code still running.
async function testAuthorRevocation() {
  console.log("Test: revoking an author key refuses its bundles and tears down what it landed");
  const { mkdtempSync, rmSync, writeFileSync: wf, readFileSync: rf } = await import("node:fs");
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
    const victimKey = "victim";

    // 1. The author is trusted: v1 installs.
    writeBundle(1);
    await shell.installFile(bundlePath);

    // 2. The key is stolen. Freshness does not stop it: v2 is strictly newer, so it
    //    upgrades the same label with nothing to show the key changed hands.
    writeBundle(2);
    await shell.install(new Uint8Array(rf(bundlePath)), { replaces: victimKey });

    // 3. Revoke the key. Both halves must happen in the one call.
    const gone = shell.revoke(authorHex);
    assert(gone.includes(victimKey), "revoke reports the app it tore down");
    assert(shell.uninstall(victimKey) === false, "revoke uninstalls the running slot");

    // 4. The thief's next bundle is refused even though the version keeps increasing and
    //    the author is still in the policy allowlist.
    writeBundle(3);
    let refused = false;
    try { await shell.installFile(bundlePath); } catch { refused = true; }
    assert(refused, "a bundle from a revoked key is refused despite a higher version");
    assert(shell.uninstall(victimKey) === false, "nothing landed on the refused load");

    // 4b. The refusal must come before the admission predicate: an interactive shell puts
    //     its consent dialog there (§12.4), and a user should not be asked to approve a
    //     bundle this host will refuse anyway.
    {
      const store = new FreshnessMarks();
      let admitCalls = 0;
      const probe = await bootTestShell({
        identity, freshnessStore: store,
        createRealm: async () => ({ call: async () => new Uint8Array(), dispose() {} }),
        admit: () => { admitCalls++; return true; },
      });
      probe.revoke(authorHex);
      try { await probe.install(new Uint8Array(readFileSync(bundlePath))); } catch { /* expected */ }
      assert(admitCalls === 0, "a revoked author never reaches the admission predicate");
      probe.close();
    }

    // 5. The refusal is persisted, not per process: a fresh boot over the same data
    //    directory, with the same policy file, still refuses. A manual uninstall would not
    //    give this.
    shell.close();
    shell = await boot({ policyJson, dir: dataDir, identity });
    let refusedAfterReboot = false;
    try { await shell.installFile(bundlePath); } catch { refusedAfterReboot = true; }
    assert(refusedAfterReboot, "the revocation survives a reboot with the policy untouched");

    // 6. Recovery is a new key, not an un-revoke: it has its own id (§5) and its own
    //    marks, so it is unaffected by the revoked key's state.
    const heir = testAuthor();
    writeBundle(1, heir);
    shell.close();
    shell = await boot({
      policyJson: JSON.stringify({ authors: [authorHex, toHex(heir.id)] }),
      dir: dataDir, identity,
    });
    await shell.installFile(bundlePath);
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: a store file without revocations is refused, not silently emptied ─────
//
// The store's shape is `{ marks, revoked }`. A bare `{ "authorHex:app": version }` map
// parsed leniently would read as no marks, silently dropping every downgrade guard and
// accepting the next stale bundle with no explanation. It must fail loudly instead
// (§12.4).
async function testPreRevocationStoreIsRefused() {
  console.log("Test: a store file predating revocation is refused rather than read as empty");
  const { FreshnessMarks } = await imp("build/host/bundle.js");
  const key = "aa".repeat(32) + ":app";

  let msg = "";
  try { new FreshnessMarks(JSON.stringify({ [key]: 7 })); } catch (e) { msg = e.message; }
  assert(msg.includes('expected both "marks" and "revoked" fields'),
    `the old bare-map format is refused for the fields it lacks (got: ${msg})`);

  // The current format round-trips, marks and revocations both.
  const cur = new FreshnessMarks(JSON.stringify({ marks: { [key]: 7 }, revoked: ["bb".repeat(32)] }));
  assert(cur.get(new Uint8Array(32).fill(0xaa), "app") === 7, "the current format reads marks back");
  assert(cur.isRevoked(new Uint8Array(32).fill(0xbb)), "the current format reads revocations back");

  // Only a missing file means first boot. A file that exists but lacks either field must
  // fail closed.
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

// ─── Test: a wrong-typed store is refused, not silently emptied ──────────────
//
// The test above only catches the bare-map shape. The same silent loss (every downgrade
// guard and every revocation gone for one boot) could come from a correctly shaped file
// with wrong-typed fields (`{"marks":"garbage"}`) read as "no marks, nothing revoked".
// Data that exists but cannot be read is a corrupt store (§12.5).
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

  // Well-formed files still load, including one with an unrecognized key (one a newer
  // version added), which is ignored.
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
  // A hand-edited file may write an author in capitals. It is accepted, so it must also
  // protect: marks are looked up by lowercase hex, like revocations.
  const shouted = new FreshnessMarks(JSON.stringify({
    marks: { ["DD".repeat(32) + ":app"]: 4 }, revoked: ["EE".repeat(32)],
  }));
  assert(shouted.get(new Uint8Array(32).fill(0xdd), "app") === 4, "a mark spelled in capitals still guards");
  assert(shouted.isRevoked(new Uint8Array(32).fill(0xee)), "…as a revocation spelled in capitals does");
  for (const version of [-1, Number.MAX_SAFE_INTEGER + 1]) {
    let threw = false;
    try { good.set(new Uint8Array(32).fill(0xaa), "new", version); } catch { threw = true; }
    assert(threw, `persistence refuses invalid version ${version}`);
  }

  // The shared store over the Node file seam distinguishes a missing first-boot file from
  // malformed or unreadable state. A directory at the file path is a portable read failure
  // that cannot be mistaken for ENOENT.
  const { freshnessStoreFor } = await imp("build/host/cli.js");
  const { nodeFiles } = await imp("build/host/shell-node.js");
  const { freshnessPathFor } = await imp("build/host/bundle.js");
  const { mkdtempSync, rmSync, writeFileSync, mkdirSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-freshness-read-"));
  const dataDir = pjoin(dir, "data");
  const path = freshnessPathFor(dataDir);
  try {
    freshnessStoreFor(nodeFiles, dataDir); // genuine absence
    writeFileSync(path, "not json");
    let malformed = false;
    try { freshnessStoreFor(nodeFiles, dataDir); } catch { malformed = true; }
    assert(malformed, "Node refuses a malformed freshness file");
    rmSync(path);
    mkdirSync(path);
    let unreadable = false;
    try { freshnessStoreFor(nodeFiles, dataDir); } catch { unreadable = true; }
    assert(unreadable, "Node refuses freshness read errors other than file-not-found");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: an app the runtime cannot serve is refused at load ────────────────
//
// `app` is the guest's signing scope, limited to 255 UTF-8 bytes (guestSignScope's
// one-byte length). Refused at install, or a longer name would verify and install, then
// fail at first use (§12.2, §12.4).
async function testAppNameLengthRefused() {
  console.log("Test: an over-long app name is refused at load, not at first use");
  const author = testAuthor();
  const mk = (app, extra = {}) => signTestBundle(sodium, author,
    { app, version: 1, modules: [], guest: GUEST(), ...extra });

  // At the limit everything works: 255 bytes is exactly what the scope can hold.
  assert(verifyTestBundle(sodium, mk("a".repeat(255))) !== null,
    "a 255-byte app name verifies");

  for (const [what, env] of [
    ["a 256-byte app name", mk("a".repeat(256))],
    // The limit counts UTF-8 bytes, the unit the scope uses.
    ["a 200-char (600-byte) UTF-8 app name", mk("\u{1f600}".repeat(200))],
  ]) {
    let threw = false;
    try { verifyTestBundle(sodium, env); } catch { threw = true; }
    assert(threw, `${what} is refused as malformed`);
  }
  console.log("  OK\n");
}

// ─── Test: a freshness persist failure fails the load and keeps nothing ──────
//
// A failed persist must be a failed install with nothing kept, and the mark rolled back
// so a retry persists it again (§12.4). Otherwise the modules would stay installed while
// the install reports failure, and the stale in-memory mark would make the retry a no-op
// against a store that still lacks it.
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
  const key = "persist";

  // Tested through the shell, since the shell advances the mark, last, after the guest
  // starts, so the write it rolls back would have recorded a version that really ran.
  const host = testHost(new ModuleTable());
  const shellOver = (freshnessStore) => bootTestShell({
    modules: host, freshnessStore,
    createRealm: async () => ({ call: async () => new Uint8Array(), dispose() {} }),
    admit: admitAll,
  });

  // A store whose durable write always fails, as a full disk would.
  const broken = new FreshnessMarks(null, () => { throw new Error("disk full"); });
  const brokenShell = await shellOver(broken);
  let msg = "";
  try { await brokenShell.install(blob); } catch (e) { msg = e.message; }
  assert(msg.includes("could not be persisted"), "a failed persist fails the load");
  assert(msg.includes("disk full"), `the original persist error survives the wrap (got: ${msg})`);
  assert(brokenShell.uninstall(key) === false, "nothing was kept — no slot was committed");
  assertEqual(broken.get(author.id, "persist"), -Infinity, "the in-memory mark was rolled back");

  // A retry against a healthy store succeeds: the rollback makes it persist the advance
  // again instead of doing nothing against the stale mark.
  const healthy = new FreshnessMarks();
  const healthyShell = await shellOver(healthy);
  await healthyShell.install(blob);
  assert(healthyShell.uninstall(key), "the retry lands");
  assertEqual(healthy.get(author.id, "persist"), 1, "…and persists its mark");
  console.log("  OK\n");
}

// ─── Test: a candidate realm cannot act before its installation commits ─────
//
// Guest source is evaluated before the freshness mark and claims are committed, so it can
// define its entrypoint, and the realm factory runs it synchronously inside the seam, so
// anything it did would already have happened by the time the commit is decided. The seam
// therefore refuses every name in that window, reads and the bundle's own modules
// included: a rejected upgrade must leave the installed version's keyspace, its neighbours
// and the links of whatever it was replacing untouched. A guest initializes from its
// preamble, which is why the candidate's `LOCAL` is still checked complete here.
async function testCandidateRealmCannotActBeforeCommit() {
  console.log("Test: a candidate realm cannot act before its installation commits");
  const { admitAll } = await imp("build/host/policy.js");

  const author = testAuthor();
  const fs = new MemoryFs();
  let reached = 0;
  const { blob } = authorBundle(sodium, author, {
    app: "offside", version: 1, protocols: ["offside/v1"],
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: ["fs", "link", "_svc"],
  });
  // The neighbour a candidate must not reach: a real second bundle claiming `_svc` under
  // `services` (reachable by a co-resident guest, never a peer), installed in its own
  // slot. Its realm is a counting stub, since this tests whether the uncommitted candidate
  // can reach it, not what it does.
  const { blob: neighborBlob } = authorBundle(sodium, author, {
    app: "svc-neighbor", version: 1, services: ["_svc"],
    modules: [], guestSource: GUEST_TEXT, guestRequires: [],
  });
  const flaky = { fail: false };
  const store = new FreshnessMarks(null, () => { if (flaky.fail) throw new Error("disk full"); });
  const candidates = [];
  // Set only while `neighborBlob` is installing, so the factory both bundles share can
  // tell which realm it is creating: the neighbour gets a stub that counts entries, and
  // everything else, including every candidate, gets the probing below, pushed into
  // `candidates` in install order.
  let loadingNeighbor = false;
  // A real socket-less driver (as in a browser) running a fixture transport: a `link`
  // candidate is only allowed as the replacement of the current link owner, so without
  // one this candidate would never reach the seam under test.
  const shell = await bootTestShell({
    fs, freshnessStore: store, transportAuthor: author,
    createRealm: async ({ hostCall, source }) => {
      if (loadingNeighbor) {
        return { call: async () => { reached++; return new Uint8Array(); }, dispose() {} };
      }
      // One of each kind of name: a durable write, a cross-realm call, a link op, a pure
      // read, a crypto transform, and this bundle's own module. All six are refused.
      const refused = [];
      for (const [name, payload] of [
        ["fs/put", Uint8Array.of(0, 0, 0, 1, 120, 9)],
        ["_svc", new Uint8Array()],
        ["link/open", new Uint8Array(32)],
        ["crypto/random", Uint8Array.of(0, 0, 0, 1)],
        ["crypto/blake2b", Uint8Array.of(32, 0)],
        ["fwd", Uint8Array.of(4)],
      ]) {
        try { await withTestBudget(hostCall)(name, payload); } catch { refused.push(name); }
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
  const key = "offside";
  try {
    // The neighbour installs first, so `_svc` is claimed by a running realm before the
    // candidate tries it, and the refusal below comes from the commit gate, not from a
    // missing claimant. The store starts healthy, because the boot transport's mark and the
    // neighbour's have to persist, and fails from here on.
    loadingNeighbor = true;
    await shell.install(neighborBlob);
    loadingNeighbor = false;
    flaky.fail = true;
    assertEqual(shell.resolve("_svc"), "svc-neighbor",
      "the neighbour holds the claim the candidate is about to reach for");

    let rejected = false;
    const localConfig = { custom: "kept", networkKey: "caller-value", linkIdleTimeoutMs: 1 };
    try { await shell.install(blob, { replaces: shell.resolve("_fixture-transport"), localConfig }); } catch { rejected = true; }
    assert(rejected, "a failed freshness write rejects the candidate");
    const [, candidateLocal] = Function(
      candidates[0].source.split("\n").slice(0, 3).join("\n") + "\nreturn [APP, LOCAL];",
    )();
    assert(candidateLocal.custom === "kept",
      "a link slot keeps the load's ordinary installation-local config");
    assert(candidateLocal.networkKey === localConfig.networkKey &&
      candidateLocal.linkIdleTimeoutMs === 1 && candidateLocal.peerId === undefined,
    "the host passes LOCAL unchanged even for a link slot");
    assert(candidates[0].calls === 0,
      "standing a link slot does not invoke a second init path");
    assertEqual(candidates[0].refused.sort(),
      ["_svc", "crypto/blake2b", "crypto/random", "fs/put", "fwd", "link/open"],
      "a candidate reaches nothing at all — not a write, another realm, a link, or a read");
    assertEqual(reached, 0, "…so the realm it called was never entered");
    assertEqual((await fs.stat()).used, 0, "…and it left nothing on disk");
    assert(shell.uninstall(key) === false, "a failed candidate never publishes its claim");

    flaky.fail = false;
    await shell.install(blob, { replaces: shell.resolve("_fixture-transport"), localConfig });
    assertEqual(shell.resolve("offside/v1"), key, "the claim commits before the seam opens");
    await withTestBudget(candidates[1].hostCall)("fs/put", Uint8Array.of(0, 0, 0, 1, 120, 9));
    await withTestBudget(candidates[1].hostCall)("_svc", new Uint8Array());
    assertEqual((await fs.stat()).used, 1, "the committed realm writes");
    assertEqual(reached, 1, "…and reaches its neighbour");
  } finally {
    shell.close();
  }
  console.log("  OK\n");
}

// ─── Test: a failed revocation persist is a failed revocation ───────────────
//
// The same rule as for the mark. A write that throws must not leave the key revoked only
// in memory: that looks safe for the rest of this boot while making the retry a silent
// no-op, and the next boot accepts the author anyway (§12.5).
async function testFailedRevokePersistRollsBack() {
  console.log("Test: a revocation that cannot be persisted is refused, not held in memory");
  const { FreshnessMarks } = await imp("build/host/bundle.js");
  const author = new Uint8Array(32).fill(0xcd);

  let broken = true;
  const written = [];
  const store = new FreshnessMarks(null, (json) => {
    if (broken) throw new Error("disk full");
    written.push(json);
  });
  let msg = "";
  try { store.revoke(author); } catch (e) { msg = e.message; }
  assert(msg.includes("NOT revoked"), `a failed revoke says so plainly (got: ${msg})`);
  assert(msg.includes("disk full"), "the original persist error survives the wrap");
  assert(!store.isRevoked(author), "the key is not left revoked in memory only");

  // The retry is why the rollback matters: without it the early return would see the key
  // already revoked and never write.
  broken = false;
  store.revoke(author);
  assert(store.isRevoked(author), "the retry revokes");
  assert(written.length === 1 && written[0].includes("cd".repeat(32)),
    "…and the retry is what actually reached the store");
  console.log("  OK\n");
}

// ─── Test: an in-place upgrade releases the version it replaces ──────────────
//
// An upgrade tears down what it replaces, like uninstall (§12.4). Leaving the old slot in
// place would keep its realm alive and its wakes armed, so the replaced guest would keep
// running wake turns, re-arming more and holding ~1.2 MB of engine per upgrade.
async function testInPlaceUpgradeReleasesTheOldSlot() {
  console.log("Test: an in-place upgrade disposes the realm and deadlines it replaces");
  const { admitAll } = await imp("build/host/policy.js");

  const author = testAuthor();
  const key = "upgrade";
  const blob = (version) => authorBundle(sodium, author, {
    app: "upgrade", version,
    protocols: ["upgrade/v1"],
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    guestSource: GUEST_TEXT, guestRequires: ["timer"],
  }).blob;

  // Each realm records what it was asked to run and whether it was released, and arms a
  // 200 ms wake on its first entry, as a guest would, since a wake re-enters the guest that
  // armed it. 200 instead of 5 because the upgrade loads the new bundle's modules in
  // workers, and a wake firing during that is a valid turn of the guest that armed it.
  const realms = [];
  let failNextRealm = false;
  const arm = (ms) => {
    const p = new Uint8Array(4);
    writeU32BE(p, 0, ms);
    return p;
  };
  const shell = await bootTestShell({
    createRealm: async (o) => {
      if (failNextRealm) { failNextRealm = false; throw new Error("broken candidate guest"); }
      // Armed on this realm's first entry, not in `createRealm`: a candidate's seam
      // refuses everything until its install commits (§3.1), which is also why a real
      // guest defers its setup to its first invocation.
      const r = { calls: [], disposed: false, call: async (p) => {
        r.calls.push(isWake(p) ? "timer" : "invoke");
        if (!r.armed) { r.armed = true; await withTestBudget(o.hostCall)("timer/arm", arm(200)); }
        return new Uint8Array();
      }, dispose() { r.disposed = true; } };
      realms.push(r);
      return r;
    },
    admit: admitAll,
  });
  try {
    const first = await shell.install(blob(1));
    await first.invoke(new Uint8Array());
    assertEqual(realms.length, 1, "the first slot stands one realm");

    failNextRealm = true;
    let failed = false;
    try { await shell.install(blob(2), { replaces: key }); } catch { failed = true; }
    assert(failed, "a candidate whose guest cannot stand is refused");
    assert(!realms[0].disposed, "the failed candidate leaves the running realm intact");
    assertEqual(shell.resolve("upgrade/v1"), key, "…and leaves its claim intact");

    const replacement = await shell.install(blob(2), { replaces: key });
    assert(realms[0].disposed, "the upgrade disposed the realm it replaced");
    let staleRejected = false;
    try { await first.invoke(new Uint8Array()); } catch { staleRejected = true; }
    assert(staleRejected, "the replaced slot's handle is revoked");
    await replacement.invoke(new Uint8Array());
    assertEqual(realms.length, 2, "…and the app answers from a NEW realm");
    assert(!realms[1].disposed, "…which is the one left standing");

    // Past the 200ms wake both realms armed. Only the current one may receive it: a wake
    // in realms[0] would mean the replaced guest is still running.
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
// services/op-frame.ts defines the functions. `guestOpFraming` serializes the compiled
// functions for import-free guests, and the transport build injects the same fragment.
// Run the emitted program at every boundary so serialization cannot change behavior.
function testGeneratedOpFrame() {
  console.log("Test: generated guest op-frame source preserves the canonical implementation");
  // Every caller inlines this fragment into a guest it then signs, so the bytes must not
  // depend on the machine that compiled op-frame.ts, which line endings otherwise would.
  assert(!guestOpFraming().includes("\r"), "the emitted op-frame source is LF-only, so a signed guest is the same bytes anywhere");
  const host = { callerOf, readOp, writeOp };
  const guest = new Function(`"use strict";${guestOpFraming()}
    return { callerOf, readOp, writeOp };`)();
  // Outcome, not message: the emitted source and module execute in different contexts, so
  // what must agree is accept-vs-reject and the bytes on accept.
  const out = (impl, fn, args) => { try { return JSON.stringify(impl[fn](...args)); } catch { return "threw"; } };
  const agree = (label, fn, ...args) =>
    assert(out(guest, fn, args) === out(host, fn, args), `${label}: generated source and host disagree`);

  // A caller id differing from the host's all-zero one only in its last byte: a prefix
  // test would call this the host.
  const peer = new Uint8Array(32); peer[31] = 1;
  agree("a host loopback", "callerOf", concatBytes([new Uint8Array(32), enc.encode("hi")]));
  agree("a caller differing only in its last byte", "callerOf", concatBytes([peer, new Uint8Array(0)]));
  agree("a well-formed op", "readOp", Uint8Array.from([2, 0x68, 0x69, 9]));
  // Declared length one past the bytes that follow it, which separates `len < 1 + n`
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

// ─── Test: the commit window re-asks the host's gates (§12.4, §12.5) ────────────
//
// Module construction, the guest's top level and a consent dialog all run between
// admission and commit, and the mark, the revocation set and the installed slots can all
// change in that time.
async function testCommitRevalidatesHostGates() {
  console.log("Test: a candidate is re-checked against freshness and revocation at commit");

  const author = testAuthor();
  const racerKey = "racer";
  const blobAt = (version) => authorBundle(sodium, author, {
    app: "racer", version, modules: [],
    guestSource: `${GUEST_TEXT}//v${version}`, guestRequires: [],
  }).blob;
  // Which version is installed, read from the guest source, the only thing that tells the
  // two candidates apart from inside the shell.
  const createRealm = async ({ source }) => ({
    call: async () => Uint8Array.of(Number(/\/\/v(\d+)$/.exec(source)[1])),
    dispose() { },
  });

  // Two overlapping installs of the same label. Installing is not replacing, so the second
  // is refused instead of quietly taking the slot the first is already running in.
  // Freshness cannot catch this, since it only refuses a lower version and these are equal.
  {
    let release, held = null;
    const shell = await bootTestShell({
      freshnessStore: new FreshnessMarks(), createRealm,
      admit: async () => {
        if (held === null) { held = new Promise((r) => { release = r; }); await held; }
        return true;
      },
    });
    try {
      const slow = shell.install(blobAt(1));
      const winner = await shell.install(blobAt(1));
      release();
      let refused = null;
      try { await slow; } catch (e) { refused = e; }
      assert(refused !== null && /already installed/.test(refused.message),
        "the second load of one identity is refused, never silently handed the slot");
      assertEqual((await winner.invoke(EMPTY))[0], 1, "…and the load that committed still answers");
    } finally { shell.close(); }
  }

  // A v1 held in admission while v2 installs and is then uninstalled: fresh when admitted,
  // a downgrade by commit. The uninstall lets v1 reach its commit at all, since an install
  // never takes a label another slot holds; in practice, an operator removing an app while
  // a consent dialog is open.
  {
    const store = new FreshnessMarks();
    let release;
    const held = new Promise((r) => { release = r; });
    const shell = await bootTestShell({
      freshnessStore: store, createRealm,
      admit: async (v) => { if (v.manifest.version === 1) await held; return true; },
    });
    try {
      const slow = shell.install(blobAt(1));
      const winner = await shell.install(blobAt(2));
      assertEqual((await winner.invoke(EMPTY))[0], 2, "the newer slot is the one that stood");
      assert(shell.uninstall(racerKey), "…and is removed before the held candidate resumes");
      release();
      let refused = null;
      try { await slow; } catch (e) { refused = e; }
      assert(refused !== null && /downgrade/.test(refused.message),
        "a candidate admitted before the newer version is refused at commit");
      assertEqual(store.get(author.id, "racer"), 2, "the mark still records the version that ran");
    } finally { shell.close(); }
  }

  // An author revoked while its own install waits on the predicate. `revoke` tears down
  // what is installed, and a candidate is not, so the install has to refuse itself.
  {
    let release;
    const held = new Promise((r) => { release = r; });
    const shell = await bootTestShell({
      freshnessStore: new FreshnessMarks(), createRealm,
      admit: async () => { await held; return true; },
    });
    try {
      const pending = shell.install(blobAt(1));
      shell.revoke(toHex(author.id));
      release();
      let refused = null;
      try { await pending; } catch (e) { refused = e; }
      assert(refused !== null && /revoked/.test(refused.message),
        "an author revoked mid-load does not get its pending installation");
      assert(shell.uninstall(racerKey) === false, "nothing landed for the revoked author");
    } finally { shell.close(); }
  }

  console.log("  OK\n");
}

// ─── Run ────────────────────────────────────────────────────────────────

await testFullLifecycle();
await testInstallRejectsUntrustedAuthor();
await testWholeBundleIsSigned();
await testDenyAllPolicyRejects();
testGeneratedOpFrame();
await testBundleRefusesNonModule();
await testManifestClaimIsTheRouting();
await testInstallerRemove();
await testFs();
await testFsKeyRule();
await testSlotFreshness();
await testShellBoot();
await testBundle();
await testGuestBundle();
await testBundleCorruptNewerRollback();
await testAuthorRevocation();
await testPreRevocationStoreIsRefused();
await testWrongTypedStoreIsRefused();
await testAppNameLengthRefused();
await testPersistFailureRollsBack();
await testCandidateRealmCannotActBeforeCommit();
await testFailedRevokePersistRollsBack();
await testInPlaceUpgradeReleasesTheOldSlot();
await testCommitRevalidatesHostGates();

summary("Results");
