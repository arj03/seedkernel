// End-to-end test: bootstrap -> signed message -> module dispatch.
//
// Run: node tests/run.mjs

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);
import { makeTransportHost } from "./transport-harness.mjs";
import { testkit } from "./testkit.mjs";

const {
  createModuleTable,
  generateKeyPair,
  loadCrypto,
} = await imp("build/host/crypto-node.js");

// Take the host's already-readied instance instead of importing our own copy.
// libsodium-wrappers-sumo declares separate "import" and "require" conditions
// pointing at different builds, so a require() here returns a SECOND instance
// with its own wasm heap — one nothing ever awaits .ready on, which leaves every
// crypto_* symbol undefined at call time. One shared instance is the documented
// rule (README §12.1), and these tests have to follow it like any other consumer.
const sodium = await loadCrypto();

// `./net-node`'s own coverage is transport-tcp.test.mjs, which stands two nodes on
// real sockets through `NodeChannelFactory` — the only path that exercises the
// transport bundle's framing.

// One contact secret for the whole harness. In production each node has its own and
// hands it out with its address; a single value here just means every test node is
// reachable by every other.
const TEST_CONTACT = new Uint8Array(32).fill(3);
const { createCapBridge, guestSignScope, appSignScope, transportSignScope, UNRESTRICTED_CAPS, GUEST_ABI_VERSION }
  = await imp("build/host/cap-bridge.js");
// ws.wasm through the same 4-op ABI the transport bundle drives it over — the codec
// itself is the bundle's now, so what is reachable from here is the module.
const { MemoryFs } = await imp("build/host/fs-memory.js");
const enc = new TextEncoder();
const _testProto = enc.encode("_test");
const { NodeFs } = await imp("build/host/fs-node.js");
const { createSafeRealm } = await imp("build/host/safe-js.js");
const { toHex, fromHex, concatBytes } = await imp("build/core/util.js");
import { bytesEqual } from "./bytes.mjs";
// The loader's admission step and name derivation (§5.1, §12.4) — tests drive the SAME
// code path a bundle load does rather than a parallel copy of it.
const { appKeyFor, genesisHash: bundleGenesisHash,
         signManifest, verifyManifest, verifyBundle, installBundle, packBundle, moduleFile, MANIFEST_FILE, GUEST_FILE }
  = await imp("build/host/bundle.js");
const { policyFromJson, authorAllowlist } = await imp("build/host/policy.js");
const { withMlDsa65, loadMlDsa65, ML_DSA65_PK_LEN, ML_DSA65_SIG_LEN } = await imp("build/host/pq.js");
const { withMlKem768, loadMlKem768 } = await imp("build/host/kem.js");
const gHash = (b) => bundleGenesisHash(sodium, b);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Every app is a guest (§12.4), so every bundle a test builds declares one. The stub
// used by tests that do not exercise the guest is the same minimal program throughout.
const GUEST_TEXT = "register('ping', () => new Uint8Array([1]));";
const GUEST_BYTES = new TextEncoder().encode(GUEST_TEXT);
const GUEST = () => ({ hash: toHex(gHash(GUEST_BYTES)), abi: GUEST_ABI_VERSION, caps: [] });

/** Inline compose of `verifyBundle` → `admit` → `installBundle` for the four
 *  policy + integrity tests that own their own ModuleTable without a shell. */
// The two halves of a load with the admission seam between them (§12.4). `admit` may
// answer with a Promise — a composed policy does — so this awaits it: reading an
// unawaited Promise as a verdict is fail-OPEN, which is the one way this seam must never
// be wrong.
async function loadBundle(host, blob, admit) {
  const v = verifyBundle(sodium, blob);
  if (!(await admit(v))) throw new Error("admit rejected");
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

// Standard bootstrap (README §3): a fresh module table. The host holds no policy — it
// is the §3 map and nothing else. Modules are pure transforms with no
// signature/dispatch seam, so there is nothing else to wire.
async function makeHost() {
  const host = await createModuleTable();
  return { host };
}

const { readFileSync } = await import("node:fs");
const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));

// ML-DSA-65 onto the test instance, exactly as a target does at its crypto seam
// (node.ts) — the hybrid manifest suite is "a sodium that knows this method" (§12.4).
// Same browser/mldsa65.wasm the browser fetches and the Go loader embeds.
withMlDsa65(sodium, await loadMlDsa65(readFileSync(join(root, "browser/mldsa65.wasm"))));
// And ML-KEM-768, the catalog primitive the same seam mixes in (kem.ts): a manifest is
// checked against PRIMITIVE_NAMES, so the methods behind those names have to be on the
// object every target hands the cap-bridge.
withMlKem768(sodium, await loadMlKem768(readFileSync(join(root, "browser/mlkem768.wasm"))));

// Install one verified module as the whole of `appKey`'s module set. Bundles are the only
// way code arrives (§12.4); there is no wire install envelope. Throws on structural failure.
function installMod(host, appKey, module, wasm) {
  host.bindAll(appKey, [{ name: module, wasm }]);
}

// The §5.1 app key a bundle's modules land under, `"<author hex>:<app>"` — the real
// derivation, not a mirror of it, so a test can name a table entry without packing a whole
// bundle and still land exactly where the loader would put it. Note the author: two
// authors using the same `app` get different keys, which is what makes ownership
// structural rather than a rule anything has to enforce.
const appKey = (authorPk, app) => appKeyFor(authorPk, app);

// ─── Test: install a module, reach it by name ───────────────────────────

async function testFullLifecycle() {
  console.log("Test: install a bundle module and reach it by name (§4, §12.4)");

  const { host } = await makeHost();

  const { publicKey: pk } = generateKeyPair();
  const chatKey = appKey(pk, "chat");

  // Install the chat module under its app's key, through the same path the bundle
  // loader uses. It is a pure transform (the forwarder fixture echoes its input).
  installMod(host, chatKey, "chat", forwarderBytes);
  assert(host.isBound(chatKey, "chat"), "chat module installed");

  // There is no install record to consult: the author is IN the app key (§5.1), so the
  // table itself says who authored what it holds — without parsing a module name out of
  // anything, because the module is a key one level down.
  assert(chatKey.startsWith(toHex(pk) + ":"), "the app key leads with the author");

  // Reach it by name: the host stages input at the module's scratch, calls handle, and
  // reads the response back (README §4). A guest reaches the same module through the
  // cap-bridge's module/call (§12.2), against the app key its bridge holds; here the host
  // calls it directly.
  const text = new TextEncoder().encode("hello from author");
  const resp = host.callModule(chatKey, "chat", text);
  assert(resp !== null && bytesEqual(resp, text), "module echoed its input");

  console.log("  OK\n");
}

// ─── Test: installBundle rejects an untrusted author ─────────────────────

async function testInstallRejectsUntrustedAuthor() {
  console.log("Test: installBundle rejects a manifest whose author is not in the policy");

  const author = generateKeyPair();
  const { host } = await makeHost();

  // A valid manifest signed by an untrusted author — the author is not in the policy.
  const manifest = { app: "demo", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
    guest: GUEST() };
  const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
  const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes, [GUEST_FILE]: GUEST_BYTES });

  // The predicate only trusts a DIFFERENT key.
  const stranger = generateKeyPair();
  const admit = authorAllowlist([toHex(stranger.publicKey)]);
  let threw = false;
  try { await loadBundle(host, blob, admit); } catch { threw = true; }
  assert(threw, "installBundle throws when the author is not in the policy");

  console.log("  OK\n");
}

async function testManifestHashIsEnforced() {
  console.log("Test: verifyBundle enforces the manifest's module hash (§5.1)");

  const author = generateKeyPair();
  // A manifest that declares the CORRECT hash — loadBundle should accept it.
  const manifest = { app: "demo", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
    guest: GUEST() };
  const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
  const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes, [GUEST_FILE]: GUEST_BYTES });

  // verifyBundle (now the single verify step) must accept a hash-matched module.
  const v = verifyBundle(sodium, blob);
  assert(bytesEqual(v.author, author.publicKey), "matched hash verifies");

  // A manifest that declares a WRONG hash — verifyBundle must throw.
  const badManifest = { app: "demo", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(new Uint8Array([1, 2, 3]))) }],
    guest: GUEST() };
  const badEnv = signManifest(sodium, author.privateKey, author.publicKey, badManifest);
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
  assert(!admit({ author: new Uint8Array(32), manifest: { app: "x", version: 1, modules: [] }, modules: [], guestSource: "" }),
    "deny-all predicate returns false for any VerifiedBundle");

  const { host } = await makeHost();
  const author = generateKeyPair();
  const manifest = { app: "demo", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
    guest: GUEST() };
  const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
  const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes, [GUEST_FILE]: GUEST_BYTES });

  let threw = false;
  try { await loadBundle(host, blob, admit); } catch { threw = true; }
  assert(threw, "a deny-all admit predicate prevents install");

  console.log("  OK\n");
}

// ─── Test: a non-instantiable module fails the whole load (§12.4) ───

async function testBundleRefusesNonModule() {
  console.log("Test: a hash-correct file that isn't a valid module fails the whole bundle");

  const author = generateKeyPair();
  const { host } = await makeHost();

  // A well-formed manifest committing to two modules the author genuinely signed. One is
  // the real forwarder (a valid §4 module); the other is arbitrary bytes that hash-match
  // their manifest module entry but won't instantiate as a module. A guest is declared —
  // every app is a guest (§12.4) — and the multi-module shape is exactly what tests
  // atomicity. With a two-phase install, a module that fails phase 1 (instantiate)
  // should fail the entire load — nothing lands.
  const notAModule = new Uint8Array([0, 1, 2, 3, 4]);   // not even valid wasm
  const guestText = "register('ping', () => new Uint8Array([1]));";
  const guestBytes = new TextEncoder().encode(guestText);
  const manifest = { app: "demo", version: 1, modules: [
    { name: "fwd", hash: toHex(gHash(forwarderBytes)) },
    { name: "broken", hash: toHex(gHash(notAModule)) },
  ], guest: { hash: toHex(gHash(guestBytes)), abi: GUEST_ABI_VERSION, caps: [] } };
  const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
  const blob = packBundle({
    [MANIFEST_FILE]: manifestEnv,
    [moduleFile("fwd")]: forwarderBytes,
    [moduleFile("broken")]: notAModule,
    [GUEST_FILE]: guestBytes,
  });

  const admit = authorAllowlist([toHex(author.publicKey)]);
  let threw = false;
  try { await loadBundle(host, blob, admit); } catch { threw = true; }
  assert(threw, "a bundle with a non-instantiable module fails the whole load — nothing lands");
  // Neither module is bound — the install was atomic.
  assert(!host.isBound(appKey(author.publicKey, "demo"), "fwd"), "the valid module is NOT bound (the load failed atomically)");
  assert(!host.isBound(appKey(author.publicKey, "demo"), "broken"), "the non-module is not bound");

  console.log("  OK\n");
}

// ─── Test: ownership is structural (§5.1, §12.5) ────────────────────────

async function testDerivedNamesKeepAuthorsApart() {
  console.log("Test: derived app keys keep two authors' same-named apps apart (§5.1)");

  // policy cannot let one author land on another's app, because there is no shared entry
  // to land on. Squat-resistance is a property of the shape, not of any policy rule — and
  // a module name is not part of it at all: `fwd` under A and `fwd` under B are two keys
  // in two different maps rather than two strings that had to be made distinct.
  const { host } = await makeHost();

  const { publicKey: aPk } = generateKeyPair();
  const { publicKey: bPk } = generateKeyPair();

  // Both authors ship an app called "shared" with a module called "fwd".
  const aKey = appKey(aPk, "shared");
  const bKey = appKey(bPk, "shared");
  assert(aKey !== bKey, "the same app name under different authors derives distinct keys");
  assert(aKey.startsWith(toHex(aPk) + ":"), "A's key leads with A's key");
  assert(bKey.startsWith(toHex(bPk) + ":"), "B's key leads with B's key");

  // Both install. Neither displaces the other — they coexist.
  installMod(host, aKey, "fwd", forwarderBytes);
  installMod(host, bKey, "fwd", forwarderBytes);
  assert(host.isBound(aKey, "fwd"), "A's app is bound");
  assert(host.isBound(bKey, "fwd"), "B's app is bound — it did not have to contend for a name");

  // A re-install by the SAME author lands on the SAME entry: an update, in place, with no
  // ownership rule consulted anywhere.
  installMod(host, aKey, "fwd", forwarderBytes);
  assert(host.isBound(aKey, "fwd"), "A's re-install still occupies the entry");
  assertEqual(appKey(aPk, "shared"), aKey, "the same key derives the same app key");

  console.log("  OK\n");
}

// ─── Test: the `handles` declaration is inert (§12.10) ──────────────────

async function testHandlesIsADeclarationNotAClaim() {
  console.log("Test: `handles` is a declaration, not a claim (§12.10)");

  const { handlesOf } = await imp("build/host/bundle.js");

  // Absent ⇒ [app]: an app that speaks only its own protocol declares nothing.
  assertEqual(JSON.stringify(handlesOf({ app: "chat", version: 1, modules: [] })),
    JSON.stringify(["chat"]), "absent handles defaults to [app]");

  // Any number of apps may declare the same protocol. Nothing in the loader arbitrates
  // between them, because declaring confers no traffic — a binding does, and that is the
  // shell's user-owned table (§12.10), not loader state.
  const mine  = { app: "chat", version: 1, modules: [], handles: ["chat"] };
  const yours = { app: "natter", version: 1, modules: [], handles: ["chat"] };
  assertEqual(JSON.stringify(handlesOf(mine)), JSON.stringify(["chat"]), "explicit handles kept");
  assertEqual(JSON.stringify(handlesOf(yours)), JSON.stringify(["chat"]),
    "a second app may declare the same protocol");

  console.log("  OK\n");
}

// ─── Test: removeApp, the per-app unbind ────────────────────────────────

async function testInstallerRemove() {
  console.log("Test: removeApp drops exactly one app (§3.1, §12.5)");

  const { host } = await makeHost();

  // Two apps of one author, plus a SECOND author's app sharing the app name — the
  // case the app key exists to separate (§5.1).
  const { publicKey: pk } = generateKeyPair();
  const { publicKey: other } = generateKeyPair();
  const chat = appKey(pk, "chat");
  const notes = appKey(pk, "notes");
  const theirs = appKey(other, "chat");

  host.bindAll(chat, [{ name: "text", wasm: forwarderBytes }, { name: "media", wasm: forwarderBytes }]);
  installMod(host, notes, "text", forwarderBytes);
  installMod(host, theirs, "text", forwarderBytes);
  assert(host.isBound(chat, "text") && host.isBound(chat, "media"), "the app's two modules installed");
  assert(host.isBound(notes, "text") && host.isBound(theirs, "text"), "the other two apps installed");

  // The unbind is per APP, and the app is the key: one delete takes every module the app
  // landed and nothing else. A second author's identically-named app is untouched, as is
  // the same author's other app.
  assertEqual(host.removeApp(chat), 2, "both modules of the app went in one call");
  assert(!host.isBound(chat, "text") && !host.isBound(chat, "media"), "the app is gone");
  assert(host.isBound(notes, "text"), "the same author's other app is untouched");
  assert(host.isBound(theirs, "text"), "another author's same-named app is untouched");

  // Nothing else to clear. There is no shared namespace for a freed entry to be contended
  // for — the key can only be derived by the author whose public key is half of it — so
  // there is no stale ownership to misattribute onto new bytes and no tombstone.
  assertEqual(host.removeApp(chat), 0, "a second call removes nothing");
  installMod(host, chat, "text", forwarderBytes);
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
      // The seam is async on every backend (core/fs.ts), so every call awaits — the
      // point of the change being that a browser backend can satisfy this shape at all.
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
//
// Which keys a node admits decides which blocks it stores and advertises, so it is a
// consensus predicate: a Go node and a Bun node that disagree about it disagree about
// their contents. The rule therefore lives in shared JS (core/fs.ts `isSafeFsKey`) and
// is applied over whatever backend a target supplies (`validatedFs`, shell-core.ts),
// rather than being
// written once in host/fs-node.ts and again in native/fs.go — which is where it was,
// under a comment on each copy saying the two had to match.

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

// ─── Test: guest-side net fan-out over net/send (Promise.all) ────────────
//
// Fan-out is no longer a host op: with real promises at the seam, a confined guest
// scatters a DISTINCT request per peer itself with Promise.all over net/send and
// gathers the responses. This is what NET_SEND_MANY used to do host-side. We drive
// it through the cap-bridge's single-peer net/send name, concurrently, from an async
// safe-js realm — proving the round trips genuinely overlap in one realm.

async function testCapBridge() {
  console.log("Test: cap-bridge — generic primitive capabilities, no app vocabulary (step 7)");

  const id = generateKeyPair();
  const fs = new MemoryFs();
  // A transport host for the net ops: its peer id is the identity's, and a request
  // to itself drops at the guest's own-frame guard, so net/send drains.
  const { driver: transport } = await makeTransportHost({ identity: id, requestDeadlineMs: 200 });

  // A module reachable by name, to exercise module/call. The forwarder fixture
  // echoes its input, admitted the one way code arrives (§12.4).
  const { host } = await makeHost();
  const testKey = appKey(id.publicKey, "testapp");
  installMod(host, testKey, "echo", forwarderBytes);

  // A host-derived signing scope binds the guest's node/sign name to a bundle
  // namespace (README §12.2); a real node derives it from the manifest's (author, app).
  const signScope = appSignScope(id, id.publicKey, "testapp");
  const scopeBytes = guestSignScope(id.publicKey, "testapp");
  const bridge = createCapBridge({
    sodium, identity: id,
    // Scoped to one app, exactly as the shell scopes it: module/call names a module
    // inside this app's map and cannot reach out of it.
    callModule: (name, p) => host.callModule(testKey, name, p),
    transport, peers: () => [toHex(id.publicKey)], fs, signScope,
    allowedCaps: UNRESTRICTED_CAPS,
  });
  const U = (...xs) => new Uint8Array(xs);

  try {
    // Primitives are reached BY NAME through the `crypto/` prefix: there is no op
    // number per algorithm, so adding one is a catalog entry and the seam never learns
    // what a cipher suite is.
    const prim = (name, argBytes) => bridge(`crypto/${name}`, argBytes);
    const msg = U(1, 2, 3, 4, 5);
    assert(bytesEqual(await prim("blake2b-256", msg), sodium.crypto_generichash(32, msg)), "crypto/blake2b-256, by name");
    const key = sodium.randombytes_buf(32), nonce = sodium.randombytes_buf(24);
    assert(bytesEqual(await prim("xchacha20/xor", concatBytes([nonce, key, msg])),
      sodium.crypto_stream_xchacha20_xor(msg, nonce, key)), "crypto/xchacha20/xor, by name");
    // node/sign is scoped, never raw (README §12.2): it signs DOMAIN_guest ‖ scope ‖ msg.
    const DOMAIN_GUEST = new TextEncoder().encode("seedkernel-guest-sig-v1\0");
    const sig = await bridge("node/sign", msg);
    const preimage = concatBytes([DOMAIN_GUEST, scopeBytes, msg]);
    assert(sodium.crypto_sign_verify_detached(sig, preimage, id.publicKey), "node/sign signs DOMAIN_guest ‖ scope ‖ msg under the node identity");
    assert(!sodium.crypto_sign_verify_detached(sig, msg, id.publicKey), "node/sign never signs the raw message (scoped, not raw)");
    assertEqual((await prim("ed25519/verify", concatBytes([id.publicKey, sig, preimage])))[0], 1, "crypto/ed25519/verify accepts the scoped preimage");
    assertEqual((await prim("ed25519/verify", concatBytes([id.publicKey, sig, U(9, 9)])))[0], 0, "crypto/ed25519/verify rejects a forged message");
    // ML-KEM-768 is in the catalog ahead of any caller — a bundle is replaceable, the
    // vocabulary it draws on is not — so what is checked here is that it is REACHABLE
    // the same way every other primitive is: by name, with no capability declared.
    // Derandomized, so the coins come from node/random (an authority the guest holds)
    // and the entry stays a pure function.
    {
      const seed = await bridge("node/random", U(0, 0, 0, 64));
      const kp = await prim("ml-kem-768/keypair", seed);
      assertEqual(kp.length, 1184 + 2400, "crypto/ml-kem-768/keypair returns [pk 1184][sk 2400]");
      const kemPk = kp.slice(0, 1184), kemSk = kp.slice(1184);
      const coins = await bridge("node/random", U(0, 0, 0, 32));
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

    assert(bytesEqual(await bridge("node/identity", U()), id.publicKey), "node/identity = the node pubkey");
    assertEqual((await bridge("node/random", U(0, 0, 0, 16))).length, 16, "node/random returns n bytes");
    assertEqual((await bridge("clock/now", U())).length, 8, "clock/now returns a u64");

    // fs.* over the raw backend
    const fk = new TextEncoder().encode("dead.blk"), fv = U(7, 7, 7);
    await bridge("fs/put", concatBytes([U(0, 0, 0, fk.length), fk, fv]));
    const got = await bridge("fs/get", fk);
    assert(got[0] === 1 && bytesEqual(got.slice(1), fv), "fs/put + fs/get round-trips under an opaque key");
    assertEqual((await bridge("fs/get", new TextEncoder().encode("missing")))[0], 0, "fs/get of an absent key → [0]");
    const szPresent = await bridge("fs/size", fk);
    assertEqual(new DataView(szPresent.buffer, szPresent.byteOffset).getUint32(0, false), fv.length, "fs/size returns the value's byte length");
    const szAbsent = await bridge("fs/size", new TextEncoder().encode("missing"));
    assertEqual(new DataView(szAbsent.buffer, szAbsent.byteOffset).getUint32(0, false), 0xffffffff, "fs/size of an absent key → -1 (0xFFFFFFFF)");

    // Sync vs async, and which side of that line a name sits on is the ABI (§12.2): a
    // primitive is a function of its arguments and resolves inline; net and fs
    // genuinely round-trip and hand back a Promise. Which side a name sits on is what
    // `guest.abi` versions, which is why it is declared and checked rather than assumed.
    assert(!(prim("blake2b-256", msg) instanceof Promise), "a catalog primitive resolves synchronously (bytes, no Promise)");
    assert(bridge("fs/size", fk) instanceof Promise, "fs/size returns a Promise (fs round-trips)");
    assert(bridge("net/peers", U()) instanceof Uint8Array, "net/peers is synchronous");
    const protoEnc = new TextEncoder().encode("_test");
    const sendFrame = concatBytes([id.publicKey, U(protoEnc.length), protoEnc, U(7)]);
    const sendResult = bridge("net/send", sendFrame);
    assert(sendResult instanceof Promise, "net/send returns a Promise (a real round trip)");
    await sendResult.catch(() => {}); // drain (no live peer) so it doesn't dangle

    // net/peers
    const peers = await bridge("net/peers", U());
    assertEqual(new DataView(peers.buffer, peers.byteOffset).getUint32(0, false), 1, "net/peers counts the cohort");

    // module/call reaches this app's module by its LOGICAL name — the name crosses the
    // seam as its UTF-8 bytes (§12.2 module/call: [nameLen u8][name utf8][req]), and the
    // app key is the one the bridge was built with, never something the caller supplies.
    const echoNameBytes = new TextEncoder().encode("echo");
    const mc = new Uint8Array(1 + echoNameBytes.length + 2);
    mc[0] = echoNameBytes.length; mc.set(echoNameBytes, 1); mc.set(U(8, 9), 1 + echoNameBytes.length);
    assertEqual([...await bridge("module/call", mc)], [8, 9], "module/call invokes the named module");
  } finally {
    transport.close();
  }

  console.log("  OK\n");
}

// ──── Test: channel identity pinning (transport §12.6) ────

async function testPolicy() {
  console.log("Test: shell install policy — closed author set gates bundle loads");
  const { parsePolicy } = await imp("build/host/policy.js");

  const good = generateKeyPair();
  const bad = generateKeyPair();

  // Build a signed bundle from each author; loadBundle accepts/rejects by predicate.
  const { ModuleTable } = await imp("build/host/module-table.js");
  const tryLoad = async (policyJson, author, extra = {}) => {
    const host = new ModuleTable();
    const manifest = { app: "mod", version: 1, ...extra,
      modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
      guest: GUEST() };
    const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
    const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes, [GUEST_FILE]: GUEST_BYTES });
    const admit = parsePolicy(policyJson);
    let landed = false;
    try { await loadBundle(host, blob, admit); landed = true; } catch { /* author not in policy */ }
    return landed;
  };

  // ── author allowlist ───────────────────────────────────────────────────
  const okAuthor = await tryLoad(JSON.stringify({ authors: [toHex(good.publicKey)] }), good);
  assert(okAuthor, "install by an allowed author is accepted");

  const badAuthor = await tryLoad(JSON.stringify({ authors: [toHex(good.publicKey)] }), bad);
  assert(!badAuthor, "install by an author not on the allowlist is rejected");

  // ── the slot admission class (§12.5) ───────────────────────────────────
  // A bundle claiming a slot is an authority grant — the transport sees all plaintext
  // and holds the session keys — so the ordinary author allowlist must NOT admit one,
  // even for an author it already trusts with apps. Only a `roles` entry does.
  const goodHex = toHex(good.publicKey);
  const appOnly = JSON.stringify({ authors: [goodHex] });
  const withSlot = JSON.stringify({ authors: [goodHex], roles: { transport: [goodHex] } });

  const slotLanded = await tryLoad(appOnly, good, { role: "transport" });
  assert(!slotLanded, "an author trusted for apps does NOT thereby occupy the transport slot");
  const slotAllowed = await tryLoad(withSlot, good, { role: "transport" });
  assert(slotAllowed, "a roles entry admits that author into the slot it names");
  const strangerSlot = await tryLoad(withSlot, bad, { role: "transport" });
  assert(!strangerSlot, "an author outside the slot's list is refused the slot");
  const appStillOk = await tryLoad(withSlot, good, {});
  assert(appStillOk, "adding a slot entry does not disturb ordinary app admission");

  // The two classes partition the bundles: a slot list alone admits no apps.
  const slotsOnly = JSON.stringify({ authors: [toHex(bad.publicKey)], roles: { transport: [goodHex] } });
  const appUnderSlotList = await tryLoad(slotsOnly, good, {});
  assert(!appUnderSlotList, "a slot entry is not an app grant — the app allowlist still decides apps");

  // ── parse validation ───────────────────────────────────────────────────
  let threw = false;
  try { parsePolicy("{ not json"); } catch { threw = true; }
  assert(threw, "malformed policy JSON throws (fails the boot loudly)");
  threw = false;
  try { parsePolicy(JSON.stringify({ authors: [] })); } catch { threw = true; }
  assert(threw, "an empty author set is rejected");
  threw = false;
  try { parsePolicy(JSON.stringify({ authors: [goodHex], roles: { transprot: [goodHex] } })); } catch { threw = true; }
  assert(threw, "a typo'd slot name fails the boot rather than silently admitting nothing");
  threw = false;
  try { parsePolicy(JSON.stringify({ authors: [goodHex], roles: { transport: [] } })); } catch { threw = true; }
  assert(threw, "an empty slot list is rejected (omit the slot to allow none)");

  // A manifest may only claim a slot this host knows (§12.4) — an unknown role is a
  // malformed manifest, not an ignored field that lands as an ordinary app.
  threw = false;
  try {
    verifyManifest(sodium, signManifest(sodium, good.privateKey, good.publicKey,
      { app: "mod", version: 1, role: "quantum-relay", modules: [], guest: GUEST() }));
  } catch { threw = true; }
  assert(threw, "a manifest claiming an unknown slot is refused as malformed");

  console.log("  OK\n");
}

// ─── Test: the guest ABI field (§12.2, §12.4) ───────────────────────────

async function testGuestAbi() {
  console.log("Test: a guest declares the host ABI it was written against");

  const author = generateKeyPair();
  const guestText = "register('ping', () => new Uint8Array([1]));";
  const guestBytes = new TextEncoder().encode(guestText);
  const mk = (guest) => signManifest(sodium, author.privateKey, author.publicKey,
    { app: "abi", version: 1, modules: [], guest });
  const hash = toHex(gHash(guestBytes));

  assert(verifyManifest(sodium, mk({ hash, abi: GUEST_ABI_VERSION, caps: [] })) !== null,
    "a guest declaring this host's ABI verifies");

  // Missing: the field is required, not defaulted. A guest author who never thought
  // about the seam version is indistinguishable from one who meant the old one, and
  // defaulting would silently pick the population a bump exists to catch.
  let threw = false;
  try { verifyManifest(sodium, mk({ hash, caps: [] })); } catch { threw = true; }
  assert(threw, "a guest with no declared ABI is refused as malformed");

  // Present but unimplemented: a legibility failure ("this bundle wants a host I am
  // not"), so it throws with its own message rather than reading as a bad signature.
  let msg = "";
  try { verifyManifest(sodium, mk({ hash, abi: GUEST_ABI_VERSION + 1, caps: [] })); }
  catch (e) { msg = e.message; }
  assert(msg.includes("guest ABI"), `an unimplemented guest ABI is refused by name (got: ${msg})`);

  // A manifest without a guest is not an app at all: every bundle declares a guest
  // (§12.4). Refused BY NAME, like the ABI above — it is the manifest a bundle written
  // against the retired module-only format produces, so the message has to say what
  // the rule is rather than "malformed manifest".
  let noGuest = "";
  try { verifyManifest(sodium, signManifest(sodium, author.privateKey, author.publicKey,
    { app: "abi", version: 1, modules: [] })); } catch (e) { noGuest = e.message; }
  assert(noGuest.includes("every app is a guest"), `a manifest without a guest is refused by name (got: ${noGuest})`);

  // `module` is not a domain: a bundle's own modules are a primitive (§12.1), like the
  // `crypto/` prefix, so a manifest still granting it is refused as an unknown domain —
  // the same loud failure a typo gets, never a cap that quietly grants nothing.
  let moduleCaps = "";
  try { verifyManifest(sodium, mk({ hash, abi: GUEST_ABI_VERSION, caps: ["module"] })); }
  catch (e) { moduleCaps = e.message; }
  assert(moduleCaps.includes("unknown capability domain"), `a manifest declaring "module" in caps is refused at load (got: ${moduleCaps})`);

  console.log("  OK\n");
}

// ─── Test: a slot occupant's freshness (§12.4) ──────────────────────────

async function testSlotFreshness() {
  console.log("Test: a slot occupant carries the ordinary (author, app) freshness mark");

  const { FreshnessMarks } = await imp("build/host/bundle.js");
  const { ModuleTable } = await imp("build/host/module-table.js");

  const a = generateKeyPair();
  const b = generateKeyPair();
  const blobFrom = (author, version, role) => packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author.privateKey, author.publicKey,
      { app: "link", version, ...(role ? { role } : {}), modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }], guest: GUEST() }),
    [moduleFile("fwd")]: forwarderBytes,
    [GUEST_FILE]: GUEST_BYTES,
  });
  const land = (host, freshness, author, version, role) => {
    installBundle(host, verifyBundle(sodium, blobFrom(author, version, role)), freshness);
  };

  // Versions are an author's own lineage, slot or no slot. A's v5 landing does NOT bind
  // B to number above it: a floor keyed to the slot would put two independent authors on
  // one shared version line with no owner, and would only pay where an attacker chooses
  // which signed bundle arrives — which nothing delivering a bundle allows (§12.4).
  {
    const freshness = new FreshnessMarks();
    const host = new ModuleTable();
    land(host, freshness, a, 5, "transport");
    assertEqual(freshness.get(a.publicKey, "link"), 5, "landing a slot occupant advances its (author, app) mark");
    land(host, freshness, b, 1, "transport");
    assertEqual(freshness.get(b.publicKey, "link"), 1, "a second author's slot bundle answers to its own lineage");
  }

  // Each author is still held to their own mark — dropping the slot floor weakens
  // nothing about the downgrade that has always been in scope.
  {
    const freshness = new FreshnessMarks();
    const host = new ModuleTable();
    land(host, freshness, a, 5, "transport");
    let refused = false;
    try { land(host, freshness, a, 4, "transport"); } catch { refused = true; }
    assert(refused, "an author's own stale slot bundle is still refused as a downgrade");
  }

  // The store holds marks and revocations only. A file written by a host that also kept
  // per-slot floors still loads — an unrecognized key is ignored, not refused — and is
  // rewritten without it.
  {
    const legacy = new FreshnessMarks(JSON.stringify({ marks: { "aa:app": 2 }, roles: { transport: 4 }, revoked: [] }));
    const round = JSON.parse(legacy.serialize());
    assertEqual(round.marks["aa:app"], 2, "a store carrying slot floors still loads its marks");
    assert(round.roles === undefined, "…and is rewritten with no slot floors");
  }

  console.log("  OK\n");
}

async function testShellBoot() {
  console.log("Test: seedkernel-shell boots under a policy and wires its capability backends");
  const { boot } = await imp("build/host/main.js");
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = generateKeyPair();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-shell-"));
  let shell;
  try {
    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.publicKey)] }),
      dir,
      identity, // dial-only: no listen/wsListen, so start() binds nothing
    });
    // The shell boots under the policy and wires its backends. Admitting an allowed
    // author's code is the bundle path, covered end-to-end by testBundle (§12.4) — the
    // only way code arrives now that the wire install path is gone.
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
  const { boot } = await imp("build/host/main.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = generateKeyPair();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-bundle-"));
  const bundlePath = pjoin(dir, "app.skb");
  let shell, shell2;
  try {
    // Build a minimal one-module bundle (forwarder.wasm) + a guest stub, using a
    // throwaway host to hash content. Modules install directly from the manifest
    // (§12.4) — no per-module .install envelope — under the app key the loader DERIVES
    // from the signed `(author, app)` pair, each at its own logical name, so the manifest
    // declares no bind name at all. Neither the module nor the guest names a file: they
    // are `<name>.wasm` and `guest.js`.
    const { host: h } = await makeHost();
    const testKey = appKey(author.publicKey, "test");
    const guestText = "register('ping', () => new Uint8Array([1]));";
    const manifest = {
      app: "test", version: 1,
      modules: [{ name: "codec", hash: toHex(gHash(forwarderBytes)) }],
      // caps + config live INSIDE guest (§12.4) — a bundle's authority is the guest's.
      guest: {
        hash: toHex(gHash(new TextEncoder().encode(guestText))),
        abi: GUEST_ABI_VERSION,
        caps: [],
      },
    };
    const writeBundle = (m) => wf(bundlePath, packBundle({
      [MANIFEST_FILE]: signManifest(sodium, author.privateKey, author.publicKey, m),
      [moduleFile("codec")]: forwarderBytes,
      [GUEST_FILE]: new TextEncoder().encode(guestText),
    }));
    writeBundle(manifest);

    // sign / verify / tamper
    const env = signManifest(sodium, author.privateKey, author.publicKey, manifest);
    assert(verifyManifest(sodium, env) !== null, "a well-formed manifest verifies");
    const tampered = env.slice(); tampered[tampered.length - 1] ^= 1;
    assert(verifyManifest(sodium, tampered) === null, "a tampered manifest fails verification");

    // A manifest whose module names collide is ambiguous (the name keys both the
    // container and the guest's module map), so it is refused even though it is
    // validly signed (§12.4).
    const dupEnv = signManifest(sodium, author.privateKey, author.publicKey, {
      ...manifest,
      modules: [manifest.modules[0], { ...manifest.modules[0] }],
    });
    let dupRefused = false;
    try { verifyManifest(sodium, dupEnv); } catch { dupRefused = true; }
    assert(dupRefused, "a manifest with duplicate module names is refused as malformed");

    // booted shell, policy allows the author → bundle loads + module installs
    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.publicKey)] }),
      dir: pjoin(dir, "_data"), identity,
    });
    const loaded = await shell.loadBundle(bundlePath);
    assert(loaded.guestSource.includes("register('ping'"), "guest source loaded + integrity-checked");
    assert(shell.host.isBound(testKey, "codec"), "module registered under its app key");

    // Freshness (§12.4): version is an enforced monotonic high-water per (author, app).
    // The first load (v1 above) set the mark to 1; re-signing the manifest at a new
    // version and reloading through the same shell exercises the downgrade gate.
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
//
// A chat-style app is a guest plus its module — and because caps live inside `guest`,
// an empty list IS declaring zero authority; there is no second shape without one. A
// manifest without a guest is refused by name. Proves the shared §12.4 loader
// accepts the one app shape (guestSource round-trips), that a bundle blob round-trips
// as one value, and that `verifyBundle` authenticates + integrity-checks WITHOUT a
// host or a policy — the seam the browser shell peeks a received Offer through before
// asking for consent.
async function testGuestBundleAndArchive() {
  console.log("Test: every app is a guest — bundle blob + verify/install split");
  const { signManifest, verifyManifest, verifyBundle,
          packBundle, unpackBundle, MANIFEST_FILE, moduleFile }
    = await imp("build/host/bundle.js");
  const { boot } = await imp("build/host/main.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = generateKeyPair();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-guest-"));
  const bundlePath = pjoin(dir, "demo.skb");
  let shell;
  try {
    const { host: h } = await makeHost();
    const demoKey = appKey(author.publicKey, "demo");
    // A manifest with NO `guest` field is refused: every app is a guest (§12.4).
    let noGuest = "";
    try {
      verifyManifest(sodium, signManifest(sodium, author.privateKey, author.publicKey,
        { app: "demo", version: 1, modules: [{ name: "demo", hash: toHex(gHash(forwarderBytes)) }] }));
    } catch (e) { noGuest = e.message; }
    assert(noGuest.includes("every app is a guest"), `a manifest without a guest is refused by name (got: ${noGuest})`);

    const manifest = {
      app: "demo", version: 1,
      modules: [{ name: "demo", hash: toHex(gHash(forwarderBytes)) }],
      guest: GUEST(),
    };
    const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
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
    assert(bytesEqual(v.author, author.publicKey), "verifyBundle returns the signing author");
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
      policyJson: JSON.stringify({ authors: [toHex(author.publicKey)] }),
      dir: pjoin(dir, "_data"), identity,
    });
    const loaded = await shell.loadBundle(bundlePath);
    assert(shell.host.isBound(demoKey, "demo"), "module registered under its app key");
    assertEqual(loaded.guestSource, GUEST_TEXT, "the shell yields the verified guest source");
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: safe-js zero-authority JS confinement (§2.1) ─────────────────
//
// The §2.1 confinement primitive: run zero-authority guest JS over a single
// host-call seam. This is a seedkernel capability (`./safe-js`); storage's
// Tier-2 orchestration is built on top of it and tested in seedstore. Proves the
// three load-bearing properties — airtight by construction, the Asyncify async
// seam + byte boundary, and realm isolation — with stand-in bridges.

async function testSafeJs() {
  console.log("Test: safe-js — zero-authority JS confinement (§2.1)");

  // 1. Airtight: the guest cannot name fs/net/Bun/process/fetch/require, and
  //    dynamic import() is unavailable (no module loader).
  {
    const DANGER = ["Bun", "process", "require", "fetch", "Buffer", "WebAssembly", "globalThis"];
    const probeSrc = `
      register("probe", () => {
        const names = ${JSON.stringify(DANGER)};
        const out = new Uint8Array(names.length);
        for (let i = 0; i < names.length; i++) {
          try { out[i] = (typeof globalThis[names[i]] === "undefined") ? 0 : 1; }
          catch { out[i] = 2; }
        }
        return out;
      });
    `;
    const realm = await createSafeRealm({ source: probeSrc, bridge: async () => new Uint8Array() });
    const res = await realm.call("probe", new Uint8Array());
    for (let i = 0; i < DANGER.length - 1; i++) {
      assertEqual(res[i], 0, `${DANGER[i]} is unreachable in the realm`);
    }
    assert(res[DANGER.length - 1] === 1, "globalThis exists (the realm's own, no authority)");
    realm.dispose();
  }
  {
    const src = `
      register("tryImport", async () => {
        try { await import("node:fs"); return new Uint8Array([1]); }
        catch { return new Uint8Array([0]); }
      });
    `;
    const realm = await createSafeRealm({ source: src, bridge: async () => new Uint8Array() });
    const res = await realm.call("tryImport", new Uint8Array());
    assertEqual(res[0], 0, "import('node:fs') rejects — no path out of the realm");
    realm.dispose();
  }

  // 2. The seam: a sync name returns bytes directly (no yield); a net-like name returns a
  //    real Promise the guest awaits. Bytes round-trip across the copy boundary both ways.
  {
    let bridgeCalls = 0;
    const bridge = (name, payload) => {
      bridgeCalls++;
      if (name === "inc") return payload.map((b) => (b + 1) & 0xff);                          // sync name — bytes directly
      if (name === "slow") return sleep(3).then(() => payload.map((b) => (b + 1) & 0xff));     // net-like name — a Promise
      return new Uint8Array();
    };
    const src = `
      register("sync", (arg) => host.call("inc", arg));                  // sync name: host.call returns bytes, no await
      register("net", async (arg) => { return await host.call("slow", arg); });  // net-like name: a genuinely awaited Promise
    `;
    const realm = await createSafeRealm({ source: src, bridge });
    const input = new Uint8Array([0, 1, 2, 254, 255]);
    const sync = await realm.call("sync", input);
    assertEqual([...sync], [1, 2, 3, 255, 0], "sync name: bytes crossed in and back with no promise");
    const asyncR = await realm.call("net", input);
    assertEqual([...asyncR], [1, 2, 3, 255, 0], "net-like name: await host.call resolves the real Promise");
    assert(bridgeCalls === 2, "the host bridge was invoked for each call");
    const again = await realm.call("sync", new Uint8Array([10]));
    assertEqual([...again], [11], "realm is reusable across calls");
    realm.dispose();
  }

  // 3. Orchestration control-flow shapes run as ordinary async guest JS, including a
  //    concurrent fan-out with the guest's own Promise.all over a net-like name — the
  //    real-promise seam is what makes this possible in one realm.
  {
    const bridge = (name, payload) => {
      const peer = payload[0];
      if (name === "offer") return sleep(1).then(() => new Uint8Array([peer % 2 === 0 ? 1 : 0]));
      if (name === "have") return sleep(1).then(() => new Uint8Array([peer % 3 === 0 ? 1 : 0]));
      return new Uint8Array();
    };
    const src = `
      register("orchestrate", async (arg) => {
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
      });
    `;
    const realm = await createSafeRealm({ source: src, bridge });
    const res = await realm.call("orchestrate", new Uint8Array([3, 10]));
    assertEqual(res[0], 3, "loop placed exactly `count` blocks on distinct peers");
    assertEqual([...res.slice(2)], [0, 2, 4], "placement followed peer order and the accept rule");
    assertEqual(res[1], 4, "concurrent have/want fan-out (Promise.all) collected the right holders");
    realm.dispose();
  }

  // 4. Realm isolation: a poisoned guest cannot reach a sibling's global.
  {
    const a = await createSafeRealm({
      source: `globalThis.SECRET = 42; register("leak", () => new Uint8Array([globalThis.SECRET ?? 0]));`,
      bridge: async () => new Uint8Array(),
    });
    const b = await createSafeRealm({
      source: `register("leak", () => new Uint8Array([globalThis.SECRET ?? 0]));`,
      bridge: async () => new Uint8Array(),
    });
    const ra = await a.call("leak", new Uint8Array());
    const rb = await b.call("leak", new Uint8Array());
    assertEqual(ra[0], 42, "realm A sees its own global");
    assertEqual(rb[0], 0, "realm B does not see realm A's global");
    a.dispose();
    b.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: one entry seam, serialized per realm (§12.3) ─────────────────
//
// There used to be two ways into a realm: `call`, which could yield, and `callSync`,
// which could not. `callSync` existed because a holder answered from local fs and fs
// answered in the same turn; once fs became async (core/fs.ts — no browser backend can
// implement a synchronous `get`) nothing distinguished it any more. What it gave for
// free was that one invocation ran to completion before the next began, and that is now
// the realm's own FIFO queue (host/realm-queue.ts) rather than a property of the host's
// call stack.

async function testRealmSerialization() {
  console.log("Test: one entry seam, serialized per realm (§12.3)");

  // 1. A synchronous entrypoint over a synchronous bridge still round-trips, and the
  //    realm is reusable — it just resolves through a promise like everything else.
  {
    let calls = 0;
    const bridge = (name, payload) => { calls++; return name === "inc" ? payload.map((b) => (b + 1) & 0xff) : new Uint8Array(); };
    const realm = await createSafeRealm({
      source: `register("inc", (arg) => host.call("inc", arg));`,
      bridge,
    });
    const out = await realm.call("inc", new Uint8Array([0, 9, 255]));
    assertEqual([...out], [1, 10, 0], "sync host.call round-trips through the copy boundary");
    assertEqual([...(await realm.call("inc", new Uint8Array([41])))], [42], "the realm is reusable across calls");
    assertEqual(calls, 2, "the synchronous bridge was invoked once per call");
    realm.dispose();
  }

  // 2. An invocation accepted while another is parked mid-await does NOT interleave with
  //    it: it waits for the queue. This is the guarantee stack discipline used to give,
  //    and the reason it is worth its head-of-line cost — two frames resuming into each
  //    other at every await is state no guest author can reason about.
  {
    let release;
    const gate = new Promise((r) => { release = r; });
    const bridge = (name, payload) => {
      if (name === "park") return gate.then(() => new Uint8Array([42]));   // parks until released
      if (name === "inc") return payload.map((b) => (b + 1) & 0xff);       // sync — holder path
      return new Uint8Array();
    };
    const realm = await createSafeRealm({
      source: `register("init", async () => host.call("park", new Uint8Array()));
               register("hold", (arg) => host.call("inc", arg));`,
      bridge,
    });
    const order = [];
    const initP = realm.call("init", new Uint8Array()).then((r) => { order.push("init"); return r; });
    const heldP = realm.call("hold", new Uint8Array([7])).then((r) => { order.push("hold"); return r; });

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
      source: `register("probe", () => new Uint8Array([typeof globalThis.process === "undefined" ? 0 : 1, typeof globalThis.fetch === "undefined" ? 0 : 1]));`,
      bridge: async () => new Uint8Array(),
    });
    const r = await realm.call("probe", new Uint8Array());
    assertEqual([...r], [0, 0], "process / fetch are unreachable from an entrypoint");
    realm.dispose();
  }

  // 4. Disposing a realm while an invocation is parked mid-await — the ordinary state of
  //    a node whose initiator is waiting on the network — fails the parked caller and
  //    frees the context WITHOUT taking the wasm module with it. The engine asserts an
  //    empty gc object list when a runtime is freed, and a parked call releases its own
  //    handle from a `finally` that runs as a MICROTASK after dispose() returns: freeing
  //    the context in the same turn aborts the whole module, which is every realm in the
  //    process, not just this one. Hence the teardown is deferred a macrotask, and this
  //    pins it — a regression here is a host crash, not a failed assertion.
  {
    const realm = await createSafeRealm({
      source: `register("park", async () => await host.call("park", new Uint8Array()));`,
      bridge: (name) => (name === "park" ? new Promise(() => {}) : new Uint8Array()),  // never settles
    });
    const parked = realm.call("park", new Uint8Array());
    for (let i = 0; i < 10; i++) await Promise.resolve();   // let it reach its await
    realm.dispose();

    let msg = "";
    try { await parked; } catch (e) { msg = e.message; }
    assertEqual(msg, "guest realm disposed", "the parked invocation is failed by dispose, not stranded");
    let after = "";
    try { await realm.call("park", new Uint8Array()); } catch (e) { after = e.message; }
    assertEqual(after, "guest realm disposed", "a call accepted after dispose is refused, not run");

    // A realm built after the deferred teardown has run proves the module survived it.
    await sleep(1);
    const next = await createSafeRealm({
      source: `register("ping", (arg) => arg);`,
      bridge: async () => new Uint8Array(),
    });
    assertEqual([...(await next.call("ping", new Uint8Array([7])))], [7],
      "the engine is still alive after the parked realm's context was freed");
    next.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: PR-review hardening — cap enforcement, guarded callModule, ───
// ─── sender-bound responses, WS fragmentation, redial after failure ──────

async function testCapBridgeEnforcement() {
  console.log("Test: cap-bridge enforces the manifest's declared cap set + allocation caps");

  const id = generateKeyPair();
  const stubTransport = { request: async (_peer, _proto, _payload) => new Uint8Array() };
  const mk = (allowedCaps) => createCapBridge({
    sodium, identity: id, callModule: () => null,
    transport: stubTransport, peers: () => [], fs: new MemoryFs(),
    allowedCaps,
  });
  const U = (...xs) => new Uint8Array(xs);
  let threw = false;

  // A PRIMITIVE is exempt from the gate by a rule about one prefix: `crypto/` reaches
  // nothing, so there is nothing to grant. A bridge built for a bundle declaring NO
  // domains still hashes.
  const clockOnly = mk(["clock"]);
  assertEqual((await clockOnly("crypto/blake2b-256", U(1, 2))).length, 32,
    "crypto/blake2b-256 resolves for a bundle declaring no crypto domain — a pure transform is not a grant");
  threw = false;
  try { await clockOnly("crypto/no-such-primitive", U(1)); } catch { threw = true; }
  assert(threw, "an unknown crypto name is refused by name (this host cannot serve it)");
  // module/call is the same KIND of name: the asking bundle's own module map — code it
  // already holds, scoped structurally by the app key the bridge was built with — so a
  // bundle declaring no `module` domain still reaches it.
  threw = false;
  try { await clockOnly("module/call", U(1, 120)); } catch { threw = true; }
  assert(!threw, "module/call resolves for a bundle declaring no module domain — the bundle's own modules are not a grant");

  // Authorities are gated by their domain PREFIX, and each one names something no
  // confined module can hold.
  threw = false;
  try { await clockOnly("node/sign", U(1)); } catch { threw = true; }
  assert(threw, "an undeclared authority (node/sign) is refused by the bridge");
  threw = false;
  try { await clockOnly("fs/delete", U(120)); } catch { threw = true; }
  assert(threw, "an undeclared authority (fs/delete) is refused by the bridge");
  threw = false;
  try { await clockOnly("clock/now", U()); } catch { threw = true; }
  assert(!threw, "clock/now resolves under the declared clock prefix");

  // guest-controlled allocation caps. UNRESTRICTED_CAPS is the host-side caller that
  // opts out of gating *by name* — omitting allowedCaps entirely now throws (§12.2).
  const open = mk(UNRESTRICTED_CAPS);
  let omitted = false;
  try { mk(undefined); } catch { omitted = true; }
  assert(omitted, "omitting allowedCaps throws rather than granting every prefix");
  assertEqual((await open("node/random", U(0, 0, 4, 0))).length, 1024, "node/random under the cap works");
  threw = false;
  try { await open("node/random", U(0xff, 0xff, 0xff, 0xff)); } catch { threw = true; }
  assert(threw, "node/random over the cap is refused");

  // caps → prefixes: a bundle declares capability DOMAINS and the bridge enforces them
  // as first-component prefix checks.
  const nodeOnly = createCapBridge({
    sodium, identity: id, callModule: () => null,
    transport: stubTransport, peers: () => [], fs: new MemoryFs(),
    allowedCaps: ["node"],
    signScope: appSignScope(id, new Uint8Array(32), "probe"),
  });
  assertEqual((await nodeOnly("node/sign", U(1, 2))).length, 64, "node grants the node-key names");
  assertEqual((await nodeOnly("crypto/blake2b-256", U(1, 2))).length, 32,
    "…and hashing needs no domain at all");
  threw = false;
  try { await nodeOnly("fs/get", U(120)); } catch { threw = true; }
  assert(threw, "a name outside the declared domains (fs) is refused");

  // The vocabulary is closed at LOAD, not at first use: an unknown domain in a manifest
  // is a refused bundle (verifyManifest, bundle.ts) — the bridge itself answers "no
  // such name" for anything it was not built to serve.
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

  // An unbound module resolves to nothing — null, distinct from an empty response. So
  // does a module under an app that was never installed at all: the outer miss and the
  // inner miss are the same answer, because neither is a thing that exists.
  assert(host.callModule(guards, "missing", new Uint8Array([1])) === null,
    "callModule returns null for an unbound module");
  assert(host.callModule(appKey(pk, "nope"), "echo", new Uint8Array([1])) === null,
    "callModule returns null for an app that installed nothing");

  // An installed module is reached by name. A confined guest reaches the same module
  // through the cap-bridge's module/call (§12.2).
  installMod(host, guards, "echo", forwarderBytes);
  const r = host.callModule(guards, "echo", new Uint8Array([5]));
  assertEqual([...r], [5], "callModule reaches an installed module");

  // A 0-length response is a valid EMPTY answer, NOT the null of an unbound name — the
  // two are distinct at this seam, so a caller can tell "module ran, said nothing" from
  // "nothing there". The forwarder echoes, so an empty input produces an empty response.
  const empty = host.callModule(guards, "echo", EMPTY);
  assert(empty !== null && empty.length === 0,
    "an empty response is an empty array, distinct from null");

  console.log("  OK\n");
}

async function testSafeRealmConcurrency() {
  console.log("Test: concurrent call()s on one safe-js realm interleave without __arg clobber");

  // No Asyncify, so overlapping initiator calls are allowed to run concurrently. Each
  // call stages __arg and consumes it synchronously (before the first await) during its
  // evalCode, so a second call staging __arg can never corrupt the first's captured arg —
  // no host-side serialization needed.
  const realm = await createSafeRealm({
    source: `register("echo", async (a) => await host.call("echo", a));`,
    bridge: (_name, p) => sleep(10).then(() => p),
  });
  try {
    const [r1, r2] = await Promise.all([
      realm.call("echo", new Uint8Array([1])),
      realm.call("echo", new Uint8Array([2])),
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
// The §12.4 envelope is `[suite 1][pk 32][sig 64][json]` and the suite byte is part of
// the signed preimage `DOMAIN_manifest ‖ suite ‖ json`. That is what makes it safe to
// read the byte *before* verifying: a verifier needs it to know the field widths, and
// the signature it then checks commits to the same byte, so rewriting it only breaks the
// manifest. Algorithm confusion between two suites is unrepresentable (§14.1).
async function testManifestSuiteByte() {
  console.log("Test: manifest suite byte — signed preimage, so an edited suite cannot verify");
  const { signManifest, verifyManifest } = await imp("build/host/bundle.js");

  const author = generateKeyPair();
  // One module: this test is about the suite byte, not the module count.
  const manifest = { app: "suite-probe", version: 1, modules: [{ name: "fwd", hash: "aa" }], guest: { hash: "aa", abi: GUEST_ABI_VERSION, caps: [] } };
  const env = signManifest(sodium, author.privateKey, author.publicKey, manifest);

  // Layout: the suite byte leads, and the author key follows it (not at offset 0).
  assertEqual(env[0], 0x01, "the envelope opens with the genesis manifest suite id");
  assertEqual(toHex(env.slice(1, 33)), toHex(author.publicKey), "the author key follows the suite byte");

  // 1. Untouched, it verifies and returns the author + manifest.
  {
    const v = verifyManifest(sodium, env);
    assert(v !== null, "an untouched manifest verifies");
    assertEqual(toHex(v.author), toHex(author.publicKey), "the author key round-trips");
    assertEqual(v.manifest.app, "suite-probe", "the manifest round-trips");
  }

  // 2. An unknown suite is refused as a legibility failure, with its own message —
  //    not silently reported as a bad signature, which would misdirect an operator
  //    whose real problem is a bundle built for a newer host.
  {
    const bad = env.slice(); bad[0] = 0x7f;
    let msg = "";
    try { verifyManifest(sodium, bad); } catch (e) { msg = String(e.message); }
    assert(msg.includes("unsupported manifest suite"), `unknown suite reports itself (got: ${msg || "no throw"})`);
    assert(!msg.includes("signature"), "an unknown suite is not reported as a signature failure");
  }

  // 3. The load-bearing property: the suite byte is inside the signed preimage, so an
  //    attacker who rewrites it to a suite the verifier DOES accept still fails — the
  //    preimage no longer matches what was signed. (0x01 signed, re-presented as 0x01
  //    after tampering the json proves the same binding from the other direction.)
  {
    const forged = env.slice();
    forged[33] ^= 0x01; // flip a signature byte → must not verify
    assert(verifyManifest(sodium, forged) === null, "a tampered signature does not verify");
  }
  {
    // Re-sign under a preimage WITHOUT the suite byte (the pre-§14.1 construction) and
    // present it as suite 0x01: the verifier computes the suite-bound preimage, so the
    // legacy signature fails. A signature is bound to the suite it was made under.
    const json = new TextEncoder().encode(JSON.stringify(manifest));
    const legacyPre = concatBytes([new TextEncoder().encode("seedkernel-manifest-sig-v1\0"), json]);
    const legacySig = sodium.crypto_sign_detached(legacyPre, author.privateKey);
    const legacyEnv = concatBytes([Uint8Array.of(0x01), author.publicKey, legacySig, json]);
    assert(verifyManifest(sodium, legacyEnv) === null,
      "a signature made without the suite byte does not verify as suite 0x01");
  }

  console.log("  OK\n");
}

// ─── Test: ML-DSA-65 against NIST's own vectors (ACVP known-answer test) ─────────
//
// Round-trip tests — sign, verify, flip a bit, verify again — are satisfied by an
// implementation that is wrong but self-consistent, and they say nothing about
// whether two targets will agree. These are NIST's published ACVP vectors for
// ML-DSA-65 (external interface, pure, FIPS 204): fixed public keys, messages and
// signatures with a verdict attached, plus sigGen cases where the signature itself
// must match byte for byte.
//
// This is what makes "one implementation across three targets" checkable rather
// than asserted: the browser fetches these bytes, Node reads them, and the Go
// loader embeds them (native/mldsa.go), so a build that drifts — wrong parameter
// set, a bad compiler flag, a resurrected second implementation — fails here
// instead of silently splitting the network into nodes that admit a bundle and
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

  // The adapter's own path (empty context, the runtime's only mode) must agree with
  // the raw module — a wrapper that quietly passed a stray context byte would still
  // pass every vector above.
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
// shipped as a bundle would be admitted by the classical verifier, so the manifest suite
// goes into the artifact ahead of need. What the tests below pin is the *shape* of that
// suite rather than the algorithm — both signatures required, the author id bound to
// both keys, and a host without the PQ half refusing rather than falling back.
// ─── Test: ML-KEM-768 against NIST's own vectors (ACVP known-answer test) ────────
//
// The same argument testMlDsaAcvpVectors makes, applied to the catalog's KEM: a round
// trip is satisfied by an implementation that is wrong but self-consistent, and it says
// nothing about whether two targets will agree. These are NIST's published ACVP vectors
// for ML-KEM-768 (FIPS 203) — fixed coins with the key, ciphertext and shared secret
// that must come out of them byte for byte.
//
// Three of the five groups exist because they pin behaviour a round trip cannot reach at
// all: `decaps` over MODIFIED ciphertexts, where implicit rejection must produce NIST's
// specific unrelated secret rather than an error; and the two key checks, where a key
// failing §7.2's modulus check or §7.3's hash check must be refused.
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
  // cap-bridge turns `null` into a leading zero byte, and there is no second channel for
  // a structural failure to come back through.
  assertEqual(kem.ml_kem768_encaps(new Uint8Array(10), new Uint8Array(32)), null,
    "a wrong-width encapsulation key is null, not a throw");
  assertEqual(kem.ml_kem768_decaps(new Uint8Array(10), new Uint8Array(1088)), null,
    "a wrong-width decapsulation key is null, not a throw");

  console.log(`  OK (${checked} NIST vectors)\n`);
}

async function testHybridManifestSuite() {
  console.log("Test: hybrid manifest suite 0x02 — both signatures required, id binds both keys");
  const { signManifest, signManifestHybrid, verifyManifest, hybridAuthorId,
          verifyBundle, packBundle, MANIFEST_FILE }
    = await imp("build/host/bundle.js");
  const { generatePqKeyPair } = await imp("build/host/crypto-node.js");

  const ed = generateKeyPair();
  const pq = generatePqKeyPair();
  const keys = { ed, mlDsa: pq };
  // One module: this test is about the hybrid envelope, not the module count.
  const manifest = { app: "pq-probe", version: 1, modules: [{ name: "fwd", hash: "aa" }], guest: { hash: "aa", abi: GUEST_ABI_VERSION, caps: [] } };
  const env = signManifestHybrid(sodium, keys, manifest);

  // 1. Layout: `[0x02][edPk 32][mlDsaPk 1952][edSig 64][mlDsaSig 3309][json]`. Both keys
  //    lead, so a verifier reads the whole key set before either signature.
  const OFF_ML_PK = 33, OFF_ED_SIG = OFF_ML_PK + ML_DSA65_PK_LEN;
  const OFF_ML_SIG = OFF_ED_SIG + 64, OFF_JSON = OFF_ML_SIG + ML_DSA65_SIG_LEN;
  assertEqual(env[0], 0x02, "the envelope opens with the hybrid manifest suite id");
  assertEqual(toHex(env.slice(1, 33)), toHex(ed.publicKey), "the Ed25519 key follows the suite byte");
  assertEqual(toHex(env.slice(OFF_ML_PK, OFF_ED_SIG)), toHex(pq.publicKey), "the ML-DSA key follows it");
  assertEqual(new TextDecoder().decode(env.slice(OFF_JSON)), JSON.stringify(manifest),
    "the manifest JSON is carried verbatim after both signatures");

  // 2. Untouched, it verifies — and the author id is NOT either public key, it is the
  //    hash over both (§12.4). That is the property hybrid signing actually rests on:
  //    an attacker who breaks one algorithm cannot reach this identity while holding a
  //    key of their own choosing for the other half.
  {
    const v = verifyManifest(sodium, env);
    assert(v !== null, "an untouched hybrid manifest verifies");
    assertEqual(v.suite, 0x02, "the verified result reports the suite it was signed under");
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
  //    signature alone — the downgrade the suite exists to prevent. It throws with its
  //    own message, the same way an unknown suite does: this is a legibility failure,
  //    not a verdict on the bundle.
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

  // 6. End to end: a hybrid-signed bundle loads, and its modules bind under names
  //    derived from the DERIVED id — so nothing downstream of the verifier knows or
  //    cares which suite signed. Same-content bundles under the two suites are two
  //    different authors, which is the honest reading of a stronger statement.
  {
    const wasm = forwarderBytes;
    const m = { app: "pq-app", version: 1, modules: [{ name: "codec", hash: toHex(gHash(wasm)) }], guest: GUEST() };
    const blob = packBundle({
      [MANIFEST_FILE]: signManifestHybrid(sodium, keys, m),
      [moduleFile("codec")]: wasm,
      [GUEST_FILE]: GUEST_BYTES,
    });
    const v = verifyBundle(sodium, blob);
    assertEqual(v.suite, 0x02, "verifyBundle carries the suite through to the policy seam");
    const host = await createModuleTable();
    installBundle(host, v);
    const derived = appKey(hybridAuthorId(sodium, ed.publicKey, pq.publicKey), "pq-app");
    assert(host.isBound(derived, "codec"), "the module binds under the derived hybrid author id");

    const edOnly = packBundle({
      [MANIFEST_FILE]: signManifest(sodium, ed.privateKey, ed.publicKey, m),
      [moduleFile("codec")]: wasm,
      [GUEST_FILE]: GUEST_BYTES,
    });
    assert(toHex(verifyBundle(sodium, edOnly).author) !== toHex(v.author),
      "the same author's 0x01 and 0x02 identities are distinct");
  }

  console.log("  OK\n");
}

// ─── Test: policy may require a manifest suite (§12.5) ───────────────────────────
//
// The verifier accepts every suite it can check; which ones a deployment TRUSTS is a
// separate, operator-owned question. Without it there is no way to finish a migration —
// the classical suite would stay acceptable forever on every host that can still verify
// it.
async function testPolicyManifestSuite() {
  console.log("Test: policy manifestSuites — a deployment can insist on PQ-signed manifests");
  const { signManifest, signManifestHybrid, verifyBundle, packBundle, MANIFEST_FILE }
    = await imp("build/host/bundle.js");
  const { generatePqKeyPair } = await imp("build/host/crypto-node.js");

  const ed = generateKeyPair();
  const pq = generatePqKeyPair();
  const wasm = forwarderBytes;
  const m = { app: "suite-policy", version: 1, modules: [{ name: "codec", hash: toHex(gHash(wasm)) }], guest: GUEST() };
  const pack = (envelope) => packBundle({ [MANIFEST_FILE]: envelope, [moduleFile("codec")]: wasm, [GUEST_FILE]: GUEST_BYTES });

  const classical = verifyBundle(sodium, pack(signManifest(sodium, ed.privateKey, ed.publicKey, m)));
  const hybrid = verifyBundle(sodium, pack(signManifestHybrid(sodium, { ed, mlDsa: pq }, m)));

  const pqOnly = policyFromJson(JSON.stringify({
    authors: [toHex(classical.author), toHex(hybrid.author)],
    manifestSuites: [2],
  }));
  assert(await pqOnly(hybrid) === true, "a hybrid-signed bundle is admitted");
  assert(await pqOnly(classical) === false, "an Ed25519-only bundle from a trusted author is refused");

  // Absent, the field constrains nothing — an existing policy file keeps its meaning.
  const anySuite = policyFromJson(JSON.stringify({ authors: [toHex(classical.author)] }));
  assert(await anySuite(classical) === true, "a policy without manifestSuites admits any suite");

  // Strict parsing, like every other field: a typo fails the boot loudly.
  for (const bad of [{ manifestSuites: 2 }, { manifestSuites: [] }, { manifestSuites: ["2"] }]) {
    let threw = false;
    try { policyFromJson(JSON.stringify({ authors: [toHex(classical.author)], ...bad })); }
    catch { threw = true; }
    assert(threw, `malformed manifestSuites is rejected: ${JSON.stringify(bad)}`);
  }

  console.log("  OK\n");
}

// ─── Test: a corrupt newer bundle does not advance the freshness mark ────────────
//
// Finding guard: the freshness high-water mark must record only versions that fully
// loaded. A newer bundle whose manifest is intact and signed but whose module bytes are
// corrupt (a half-landed upgrade) must fail the content check WITHOUT raising the mark —
// otherwise reloading the known-good older bundle would be refused as a downgrade,
// bricking rollback (README §12.4).
async function testBundleCorruptNewerRollback() {
  console.log("Test: a corrupt newer bundle leaves the freshness mark intact (rollback stays possible)");
  const { signManifest, packBundle, MANIFEST_FILE, GUEST_FILE, moduleFile }
    = await imp("build/host/bundle.js");
  const { boot } = await imp("build/host/main.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = generateKeyPair();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-rollback-"));
  const bundlePath = pjoin(dir, "rollback.skb");
  let shell;
  try {
    const { host: h } = await makeHost();
    const guestText = "register('ping', () => new Uint8Array([1]));";
    const manifest = (version) => ({
      app: "rollback", version,
      modules: [{ name: "codec", hash: toHex(gHash(forwarderBytes)) }],
      guest: {
        hash: toHex(gHash(new TextEncoder().encode(guestText))),
        abi: GUEST_ABI_VERSION,
        caps: [],
      },
    });
    // `wasm` is the module's actual bytes — passed corrupt below to model a
    // half-written upgrade whose manifest is nonetheless intact and signed.
    const writeBundle = (version, wasm = forwarderBytes) => wf(bundlePath, packBundle({
      [MANIFEST_FILE]: signManifest(sodium, author.privateKey, author.publicKey, manifest(version)),
      [moduleFile("codec")]: wasm,
      [GUEST_FILE]: new TextEncoder().encode(guestText),
    }));

    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.publicKey)] }),
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
// Finding guard: freshness cannot answer "is this key still the author's?". A stolen
// key signs `version + 1`, clears the high-water mark, and lands on the SAME derived
// names (§5.1) — forever. `shell.revoke` is the remedy, and the test is that both of
// its halves happen and that the refusal survives a reboot: an operator doing this by
// hand can uninstall without closing the door, or close it with the code still running.
async function testAuthorRevocation() {
  console.log("Test: revoking an author key refuses its bundles and tears down what it landed");
  const { signManifest, packBundle, MANIFEST_FILE, moduleFile } = await imp("build/host/bundle.js");
  const { boot } = await imp("build/host/main.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = generateKeyPair();
  const identity = generateKeyPair();
  const authorHex = toHex(author.publicKey);
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
      [MANIFEST_FILE]: signManifest(sodium, author.privateKey, author.publicKey, manifest(version)),
      [moduleFile("codec")]: forwarderBytes,
      [GUEST_FILE]: GUEST_BYTES,
    }));

    shell = await boot({ policyJson, dir: dataDir, identity });
    const victimKey = appKeyFor(author.publicKey, "victim");

    // 1. The author is trusted: v1 loads and binds.
    writeBundle(1);
    await shell.loadBundle(bundlePath);
    assert(shell.host.isBound(victimKey, "codec"), "the app binds while the author is trusted");

    // 2. The key is stolen. Freshness does NOT stop it — v2 is strictly newer, so it
    //    loads over the same name. This is the gap, asserted rather than assumed.
    writeBundle(2);
    await shell.loadBundle(bundlePath);
    assert(shell.host.isBound(victimKey, "codec"), "freshness does not stop a newer bundle from a stolen key");

    // 3. Write the key off. Both halves must happen in the one call.
    const gone = shell.revoke(authorHex);
    assert(gone.includes(victimKey), "revoke reports the app it tore down");
    assert(!shell.host.isBound(victimKey, "codec"), "revoke uninstalls what the key already landed");

    // 4. The thief's next bundle is refused even though the version keeps climbing
    //    and the author is still in the policy allowlist.
    writeBundle(3);
    let refused = false;
    try { await shell.loadBundle(bundlePath); } catch { refused = true; }
    assert(refused, "a bundle from a revoked key is refused despite a higher version");
    assert(!shell.host.isBound(victimKey, "codec"), "nothing landed on the refused load");

    // 4b. The refusal must come BEFORE the admission predicate, not after it. An
    //     interactive shell puts its consent dialog there (§12.4), and prompting a
    //     user to approve a bundle this host has already decided to refuse — then
    //     failing once they say yes — is the wrong order to ask in.
    {
      const { createShell: mkShell, ModuleTable: KH } = await imp("build/host/shell-core.js");
      const { FreshnessMarks } = await imp("build/host/bundle.js");
      const store = new FreshnessMarks();
      let admitCalls = 0;
      const probe = mkShell({
        platform: {
          sodium, identity, table: new KH(), freshnessStore: store,
          createRealm: async () => ({ call: async () => new Uint8Array(), dispose() {} }),
        },
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
    const heir = generateKeyPair();
    wf(bundlePath, packBundle({
      [MANIFEST_FILE]: signManifest(sodium, heir.privateKey, heir.publicKey, manifest(1)),
      [moduleFile("codec")]: forwarderBytes,
      [GUEST_FILE]: GUEST_BYTES,
    }));
    shell.close();
    shell = await boot({
      policyJson: JSON.stringify({ authors: [authorHex, toHex(heir.publicKey)] }),
      dir: dataDir, identity,
    });
    await shell.loadBundle(bundlePath);
    assert(shell.host.isBound(appKeyFor(heir.publicKey, "victim"), "codec"),
      "a replacement author key installs normally after the old one is written off");
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: a pre-revocation store file is refused, not silently emptied ─────────
//
// Finding guard: the store gained a `revoked` set, so its shape changed from a bare
// `{ "authorHex:app": version }` map to `{ marks, revoked }`. An old file parsed
// leniently would read as NO marks — every downgrade guard silently dropped on the
// first boot after a host upgrade, with the next stale bundle accepted and nothing
// saying why. It must fail loudly instead (§12.4).
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
// Finding guard: the legacy guard above catches only the OLD bare-map shape. The
// same silent discard — every downgrade guard AND every revocation gone on the one
// boot after an edit — was reachable through a NEW-shaped file whose fields have
// the wrong types: `{"marks":"garbage"}` or `{"marks":{"aa:app":"x"}}` parsed as
// "no marks, nothing revoked". Guard data that exists but cannot be read is a
// corrupt store, and it throws (§12.5).
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
  // key (legacy slot floors), which is ignored rather than refused.
  const good = new FreshnessMarks(JSON.stringify({
    marks: { ["aa".repeat(32) + ":app"]: 2 }, revoked: ["bb".repeat(32)], roles: { transport: 4 },
  }));
  assert(good.get(new Uint8Array(32).fill(0xaa), "app") === 2, "a well-formed store still loads its marks");
  assert(good.isRevoked(new Uint8Array(32).fill(0xbb)), "…and its revocations");
  console.log("  OK\n");
}

// ─── Test: an app the runtime cannot serve is refused at load ────────────────
//
// Finding guard: `app` is the default protocol id and the guest's signing scope,
// both of which cap at 255 UTF-8 bytes (the wire's one-byte protocol length, and
// guestSignScope). A longer name passed verification, installed, and then failed
// at first use — a bundle the host can verify and install but can never serve
// (§12.2, §12.4).
async function testAppNameLengthRefused() {
  console.log("Test: an over-long app name (or declared handle) is refused at load, not at first use");
  const { verifyManifest, signManifest } = await imp("build/host/bundle.js");
  const author = generateKeyPair();
  const mk = (app, extra = {}) => signManifest(sodium, author.privateKey, author.publicKey,
    { app, version: 1, modules: [], guest: GUEST(), ...extra });

  // At the limit, everything works — 255 bytes is exactly what the seam can carry.
  assert(verifyManifest(sodium, mk("a".repeat(255), { handles: ["b".repeat(255)] })) !== null,
    "a 255-byte app name and a 255-byte declared handle verify");

  for (const [what, env] of [
    ["a 256-byte app name", mk("a".repeat(256))],
    ["a 256-byte declared handle", mk("app", { handles: ["b".repeat(256)] })],
    // The limit counts UTF-8 BYTES, the unit both the scope and the wire use.
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
// Finding guard: the freshness mark was advanced AFTER the modules bound, so a
// durable write that failed left the modules on the table while the load reported
// failure — and the stale in-memory mark made a retry no-op against a store that
// still lacked it. A failed persist must be a failed load with nothing kept, and
// the mark rolled back so a retry persists a fresh advance (§12.4).
async function testPersistFailureRollsBack() {
  console.log("Test: a failed freshness persist fails the load — nothing is kept, the mark is rolled back");
  const { FreshnessMarks, installBundle, verifyBundle, signManifest, packBundle, MANIFEST_FILE, GUEST_FILE, moduleFile }
    = await imp("build/host/bundle.js");
  const { ModuleTable } = await imp("build/host/module-table.js");

  const author = generateKeyPair();
  const manifest = { app: "persist", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }],
    guest: GUEST() };
  const blob = packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author.privateKey, author.publicKey, manifest),
    [moduleFile("fwd")]: forwarderBytes,
    [GUEST_FILE]: GUEST_BYTES,
  });
  const v = verifyBundle(sodium, blob);
  const key = appKey(author.publicKey, "persist");

  // A store whose durable write always fails, as a full disk would.
  class BrokenStore extends FreshnessMarks {
    persist() { throw new Error("disk full"); }
  }
  const host = new ModuleTable();
  const broken = new BrokenStore();
  let msg = "";
  try { installBundle(host, v, broken); } catch (e) { msg = e.message; }
  assert(msg.includes("could not be persisted"), "a failed persist fails the load");
  assert(msg.includes("disk full"), `the original persist error survives the wrap (got: ${msg})`);
  assert(!host.isBound(key, "fwd"), "nothing was kept — the modules did not stay bound");
  assertEqual(broken.get(author.publicKey, "persist"), -Infinity, "the in-memory mark was rolled back");

  // A retry against a healthy store completes cleanly: the rollback is what makes
  // it persist a FRESH advance rather than no-op'ing against the stale mark.
  const healthy = new FreshnessMarks();
  installBundle(host, v, healthy);
  assert(host.isBound(key, "fwd"), "the retry lands");
  assertEqual(healthy.get(author.publicKey, "persist"), 1, "…and persists its mark");
  console.log("  OK\n");
}

// ─── Test: a failed revocation persist is a failed revocation ───────────────
//
// The same rule as the mark, one method over: `revoke` adds the key to the live
// set and then writes. A write that throws must not leave the key revoked only in
// memory — that reads as safe (the author is refused for the rest of this boot)
// while making the retry a silent no-op against a store that never got it, and
// the next boot admits the author regardless (§12.5).
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

// ─── Run ────────────────────────────────────────────────────────────────

await testFullLifecycle();
await testInstallRejectsUntrustedAuthor();
await testManifestHashIsEnforced();
await testDenyAllPolicyRejects();
await testBundleRefusesNonModule();
await testDerivedNamesKeepAuthorsApart();
await testHandlesIsADeclarationNotAClaim();
await testInstallerRemove();
await testFs();
await testFsKeyRule();
await testCapBridge();
await testPolicy();
await testGuestAbi();
await testSlotFreshness();
await testShellBoot();
await testBundle();
await testGuestBundleAndArchive();
await testBundleCorruptNewerRollback();
await testSafeJs();
await testRealmSerialization();
await testCapBridgeEnforcement();
await testCallModuleGuards();
await testManifestSuiteByte();
await testMlDsaAcvpVectors();
await testMlKemAcvpVectors();
await testHybridManifestSuite();
await testPolicyManifestSuite();
await testSafeRealmConcurrency();
await testAuthorRevocation();
await testPreRevocationStoreIsRefused();
await testWrongTypedStoreIsRefused();
await testAppNameLengthRefused();
await testPersistFailureRollsBack();
await testFailedRevokePersistRollsBack();

summary("Results");
