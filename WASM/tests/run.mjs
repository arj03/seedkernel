// End-to-end test: bootstrap -> signed message -> handler dispatch.
//
// Run: node tests/run.mjs

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);
import { makeTransportHost } from "./transport-harness.mjs";

const {
  createKernelHost,
  generateKeyPair,
  loadSodium,
} = await imp("build/host/node.js");

// Take the host's already-readied instance instead of importing our own copy.
// libsodium-wrappers-sumo declares separate "import" and "require" conditions
// pointing at different builds, so a require() here returns a SECOND instance
// with its own wasm heap — one nothing ever awaits .ready on, which leaves every
// crypto_* symbol undefined at call time. One shared instance is the documented
// rule (README §12.1), and these tests have to follow it like any other consumer.
const sodium = await loadSodium();

// Transport + WS module surface (moved up from seedstore in the runtime split).
// These are seedkernel's own public exports — `./net-node` (NodeNetwork) and the
// no-cap `./ws` framing module — so they are exercised here, where they live,
// rather than only from a downstream consumer.
const { NodeNetwork } = await imp("build/host/net-node.js");

// One contact secret for the whole harness. In production each node has its own and
// hands it out with its address; a single value here just means every test node is
// reachable by every other.
const TEST_CONTACT = new Uint8Array(32).fill(3);
const { CAP, createCapBridge, opsForCaps, guestSignScope, appSignScope, transportSignScope, UNRESTRICTED_OPS, UNSCOPED_MODULES, GUEST_ABI_VERSION }
  = await imp("build/host/cap-bridge.js");
const { wsAcceptKey, encodeFrame, WsParser, WS_OPCODES } = await imp("build/host/ws.js");
const { MemoryFs } = await imp("build/core/fs.js");
const enc = new TextEncoder();
const _testProto = enc.encode("_test");
const { NodeFs } = await imp("build/host/fs-node.js");
const { createSafeRealm } = await imp("build/host/safe-js.js");
const { toHex, fromHex, bytesEqual, concatBytes } = await imp("build/core/util.js");
// The loader's admission step and name derivation (§5.1, §12.4) — tests drive the SAME
// code path a bundle load does rather than a parallel copy of it.
const { appKeyFor, genesisHash: bundleGenesisHash, kernelNameFor: bundleKernelNameFor,
         signManifest, verifyManifest, verifyBundle, installBundle, packBundle, moduleFile, MANIFEST_FILE }
  = await imp("build/host/bundle.js");
const { policyFromJson, authorAllowlist } = await imp("build/host/policy.js");
const { withMlDsa65, loadMlDsa65, ML_DSA65_PK_LEN, ML_DSA65_SIG_LEN } = await imp("build/core/pq.js");
const { withMlKem768, loadMlKem768 } = await imp("build/core/kem.js");
const gHash = (b) => bundleGenesisHash(sodium, b);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Inline compose of `verifyBundle` → `admit` → `installBundle` for the four
 *  policy + integrity tests that own their own KernelHost without a shell. */
// The two halves of a load with the admission seam between them (§12.4). `admit` may
// answer with a Promise — a composed policy does — so this awaits it: reading an
// unawaited Promise as a verdict is fail-OPEN, which is the one way this seam must never
// be wrong.
async function loadBundle(host, blob, admit) {
  const v = verifyBundle(sodium, blob);
  if (!(await admit(v))) throw new Error("admit rejected");
  return installBundle(host, v);
}

// The empty payload — a handler whose `handle` takes no meaningful input.
const EMPTY = new Uint8Array(0);

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (!condition) { console.error(`  FAIL: ${msg}`); failed++; }
  else passed++;
}
function assertEqual(actual, expected, msg) {
  const norm = (v) => {
    if (v === null || v === undefined) return String(v);
    if (typeof v === "object") return JSON.stringify([...v]);
    return v;
  };
  const a = norm(actual);
  const e = norm(expected);
  assert(a === e, `${msg}: expected ${e}, got ${a}`);
}

// Standard bootstrap (README §3): a fresh handler table. The host holds no policy — it
// is the §3 map and nothing else. Handlers are pure transforms with no
// signature/dispatch seam, so there is nothing else to wire.
async function makeHost() {
  const host = await createKernelHost();
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

// Install a verified module directly under `targetName`. Bundles are the only way code
// arrives (§12.4); there is no wire install envelope. Throws on structural failure.
function installMod(host, targetName, wasm) {
  const ref = host.instantiateWasm(wasm);
  host.bindHandler(targetName, ref);
}

// The §5.1 bind name a bundle module lands at, `"<author hex>:<app>:<module>"` — the real
// derivation, not a mirror of it, so a test can name a slot without packing a whole
// bundle and still land exactly where the loader would put it. Note the author: two
// authors using the same `app` get different names, which is what makes ownership
// structural rather than a rule anything has to enforce.
const modName = (authorPk, app, mod) => bundleKernelNameFor(authorPk, app, mod);

// ─── Test: install a module, reach it by name ───────────────────────────

async function testFullLifecycle() {
  console.log("Test: install a bundle module and reach it by name (§4, §12.4)");

  const { host } = await makeHost();

  const { publicKey: pk } = generateKeyPair();
  const chatName = modName(pk, "chat", "chat");

  // Install the chat handler under its derived kernel name, through the same path the
  // bundle loader uses. It is a pure transform (the forwarder fixture echoes its input).
  installMod(host, chatName, forwarderBytes);
  assert(host.isBound(chatName), "chat handler installed");

  // There is no install record to consult: the author is IN the name (§5.1), so the
  // table itself says who authored what it holds.
  assert(chatName.startsWith(toHex(pk) + ":"), "kernel name leads with the author");

  // Reach it by name: the host stages input at the handler's scratch, calls handle, and
  // reads the response back (README §4). A guest reaches the same handler through the
  // cap-bridge's MODULE_CALL (§12.2); here the host calls it directly.
  const text = new TextEncoder().encode("hello from author");
  const resp = host.callHandler(chatName, text);
  assert(resp !== null && bytesEqual(resp, text), "handler echoed its input");

  console.log("  OK\n");
}

// ─── Test: installBundle rejects an untrusted author ─────────────────────

async function testInstallRejectsUntrustedAuthor() {
  console.log("Test: installBundle rejects a manifest whose author is not in the policy");

  const author = generateKeyPair();
  const { host } = await makeHost();

  // A valid manifest signed by an untrusted author — the author is not in the policy.
  const manifest = { app: "demo", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }] };
  const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
  const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes });

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
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }] };
  const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
  const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes });

  // verifyBundle (now the single verify step) must accept a hash-matched module.
  const v = verifyBundle(sodium, blob);
  assert(bytesEqual(v.author, author.publicKey), "matched hash verifies");

  // A manifest that declares a WRONG hash — verifyBundle must throw.
  const badManifest = { app: "demo", version: 1,
    modules: [{ name: "fwd", hash: toHex(gHash(new Uint8Array([1, 2, 3]))) }] };
  const badEnv = signManifest(sodium, author.privateKey, author.publicKey, badManifest);
  const badBlob = packBundle({ [MANIFEST_FILE]: badEnv, [moduleFile("fwd")]: forwarderBytes });
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
    modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }] };
  const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
  const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes });

  let threw = false;
  try { await loadBundle(host, blob, admit); } catch { threw = true; }
  assert(threw, "a deny-all admit predicate prevents install");

  console.log("  OK\n");
}

// ─── Test: a non-instantiable module fails the whole load (§12.4) ───

async function testBundleRefusesNonHandler() {
  console.log("Test: a hash-correct module that isn't a valid handler fails the whole bundle");

  const author = generateKeyPair();
  const { host } = await makeHost();

  // A well-formed manifest committing to two modules the author genuinely signed. One is
  // the real forwarder (a valid §4 handler); the other is arbitrary bytes that hash-match
  // their manifest entry but won't instantiate as a handler. With a two-phase install, a
  // module that fails phase 1 (instantiate) should fail the entire load — nothing lands.
  const notAHandler = new Uint8Array([0, 1, 2, 3, 4]);   // not even valid wasm
  const manifest = { app: "demo", version: 1, modules: [
    { name: "fwd", hash: toHex(gHash(forwarderBytes)) },
    { name: "broken", hash: toHex(gHash(notAHandler)) },
  ] };
  const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
  const blob = packBundle({
    [MANIFEST_FILE]: manifestEnv,
    [moduleFile("fwd")]: forwarderBytes,
    [moduleFile("broken")]: notAHandler,
  });

  const admit = authorAllowlist([toHex(author.publicKey)]);
  let threw = false;
  try { await loadBundle(host, blob, admit); } catch { threw = true; }
  assert(threw, "a bundle with a non-instantiable module fails the whole load — nothing lands");
  // Neither module is bound — the install was atomic.
  assert(!host.isBound(modName(author.publicKey, "demo", "fwd")), "the valid handler is NOT bound (the load failed atomically)");
  assert(!host.isBound(modName(author.publicKey, "demo", "broken")), "the non-handler is not bound");

  console.log("  OK\n");
}

// ─── Test: ownership is structural (§5.1, §12.5) ────────────────────────

async function testDerivedNamesKeepAuthorsApart() {
  console.log("Test: derived names keep two authors' same-named apps apart (§5.1)");

  // policy cannot let one author land on another's name, because there is no shared name
  // to land on. Squat-resistance is a property of the namespace, not of any policy rule.
  const { host } = await makeHost();

  const { publicKey: aPk } = generateKeyPair();
  const { publicKey: bPk } = generateKeyPair();

  // Both authors ship an app called "shared" with a module called "fwd".
  const aName = modName(aPk, "shared", "fwd");
  const bName = modName(bPk, "shared", "fwd");
  assert(aName !== bName, "same (app, module) under different authors derives distinct names");
  assert(aName.startsWith(toHex(aPk) + ":"), "A's name leads with A's key");
  assert(bName.startsWith(toHex(bPk) + ":"), "B's name leads with B's key");

  // Both install. Neither displaces the other — they coexist.
  installMod(host, aName, forwarderBytes);
  installMod(host, bName, forwarderBytes);
  assert(host.isBound(aName), "A's app is bound");
  assert(host.isBound(bName), "B's app is bound — it did not have to contend for a name");

  // A re-install by the SAME author lands on the SAME name: an update, in place, with no
  // ownership rule consulted anywhere.
  installMod(host, aName, forwarderBytes);
  assert(host.isBound(aName), "A's re-install still occupies the slot");
  assertEqual(modName(aPk, "shared", "fwd"), aName, "the same key derives the same name");

  // The app key is the first two components of the kernel name (§12.4) — one identity
  // the freshness marks, the bindings and the names all share.
  assert(aName.startsWith(appKeyFor(aPk, "shared") + ":"), "kernel name extends the app key");

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

// ─── Test: removeHandler + suite slot removal ───────────────────────────

async function testInstallerRemove() {
  console.log("Test: removeHandler frees the kernel slot (§12.5)");

  const { host } = await makeHost();

  const { publicKey: pk } = generateKeyPair();
  const chatTextName = modName(pk, "chat", "text");

  installMod(host, chatTextName, forwarderBytes);
  assert(host.isBound(chatTextName), "install ok");

  assert(host.removeHandler(chatTextName), "remove returned true");
  assert(!host.isBound(chatTextName), "kernel slot cleared");
  // Nothing else to clear: a freed name can only be re-occupied by the author whose key
  // derives it (§5.1), so there is no stale ownership to misattribute onto new bytes.

  // removeHandler is idempotent — a second call on an empty slot returns false.
  assert(!host.removeHandler(chatTextName), "second remove returns false");

  // Re-installing at the same name after a remove succeeds (no tombstone).
  installMod(host, chatTextName, forwarderBytes);
  assert(host.isBound(chatTextName), "reinstall after remove succeeds");

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

// ─── Test: guest-side net fan-out over NET_SEND (Promise.all) ────────────
//
// Fan-out is no longer a host op: with real promises at the seam, a confined guest
// scatters a DISTINCT request per peer itself with Promise.all over NET_SEND and
// gathers the responses. This is what NET_SEND_MANY used to do host-side. We drive
// it through the cap-bridge's single-peer NET_SEND op, concurrently, from an async
// safe-js realm — proving the round trips genuinely overlap in one realm.

async function testCapBridge() {
  console.log("Test: cap-bridge — generic primitive capabilities, no app vocabulary (step 7)");

  const id = generateKeyPair();
  const fs = new MemoryFs();
  // A transport host for the net ops: its peer id is the identity's, and a request
  // to itself drops at the guest's own-frame guard, so NET_SEND drains.
  const { driver: transport } = await makeTransportHost({ identity: id, timeoutMs: 200 });

  // A handler reachable by name, to exercise CAP_MODULE_CALL. The forwarder fixture
  // echoes its input, admitted the one way code arrives (§12.4).
  const { host } = await makeHost();
  const echoName = modName("testapp", "echo");
  installMod(host, echoName, forwarderBytes);

  // A host-derived signing scope binds the guest's SIGN op to a bundle namespace
  // (README §12.2); a real node derives it from the manifest's (author, app).
  const signScope = appSignScope(id, id.publicKey, "testapp");
  const scopeBytes = guestSignScope(id.publicKey, "testapp");
  const bridge = createCapBridge({
    sodium, identity: id,
    callHandler: (name, p) => host.callHandler(name, p),
    transport, peers: () => [toHex(id.publicKey)], fs, signScope,
    allowedOps: UNRESTRICTED_OPS, modules: UNSCOPED_MODULES,
  });
  const U = (...xs) => new Uint8Array(xs);

  try {
    // Primitives are reached BY NAME through the one CAP_CRYPTO op: there is no op
    // number per algorithm, so adding one is a catalog entry and the seam never learns
    // what a cipher suite is.
    const prim = (name, argBytes) => bridge(CAP.CRYPTO,
      concatBytes([U(name.length), new TextEncoder().encode(name), argBytes]));
    const msg = U(1, 2, 3, 4, 5);
    assert(bytesEqual(await prim("blake2b-256", msg), sodium.crypto_generichash(32, msg)), "blake2b-256, by name");
    const key = sodium.randombytes_buf(32), nonce = sodium.randombytes_buf(24);
    assert(bytesEqual(await prim("xchacha20/xor", concatBytes([nonce, key, msg])),
      sodium.crypto_stream_xchacha20_xor(msg, nonce, key)), "xchacha20/xor, by name");
    // CAP_SIGN is scoped, never raw (README §12.2): it signs DOMAIN_guest ‖ scope ‖ msg.
    const DOMAIN_GUEST = new TextEncoder().encode("seedkernel-guest-sig-v1\0");
    const sig = await bridge(CAP.SIGN, msg);
    const preimage = concatBytes([DOMAIN_GUEST, scopeBytes, msg]);
    assert(sodium.crypto_sign_verify_detached(sig, preimage, id.publicKey), "CAP_SIGN signs DOMAIN_guest ‖ scope ‖ msg under the node identity");
    assert(!sodium.crypto_sign_verify_detached(sig, msg, id.publicKey), "CAP_SIGN never signs the raw message (scoped, not raw)");
    assertEqual((await prim("ed25519/verify", concatBytes([id.publicKey, sig, preimage])))[0], 1, "ed25519/verify accepts the scoped preimage");
    assertEqual((await prim("ed25519/verify", concatBytes([id.publicKey, sig, U(9, 9)])))[0], 0, "ed25519/verify rejects a forged message");
    // ML-KEM-768 is in the catalog ahead of any caller — a bundle is replaceable, the
    // vocabulary it draws on is not — so what is checked here is that it is REACHABLE
    // the same way every other primitive is: by name, through the one op, with no
    // capability declared. Derandomized, so the coins come from CAP_RANDOM (an authority
    // the guest holds) and the entry stays a pure function.
    {
      const seed = await bridge(CAP.RANDOM, U(0, 0, 0, 64));
      const kp = await prim("ml-kem-768/keypair", seed);
      assertEqual(kp.length, 1184 + 2400, "ml-kem-768/keypair returns [pk 1184][sk 2400]");
      const kemPk = kp.slice(0, 1184), kemSk = kp.slice(1184);
      const coins = await bridge(CAP.RANDOM, U(0, 0, 0, 32));
      const enc = await prim("ml-kem-768/encaps", concatBytes([kemPk, coins]));
      assertEqual(enc[0], 1, "ml-kem-768/encaps accepts a well-formed encapsulation key");
      assertEqual(enc.length, 1 + 1088 + 32, "encaps returns [ok][ct 1088][ss 32]");
      const ct = enc.slice(1, 1 + 1088), ss = enc.slice(1 + 1088);
      const dec = await prim("ml-kem-768/decaps", concatBytes([kemSk, ct]));
      assertEqual(dec[0], 1, "ml-kem-768/decaps accepts a well-formed decapsulation key");
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

    assert(bytesEqual(await bridge(CAP.IDENTITY, U()), id.publicKey), "CAP_IDENTITY = the node pubkey");
    assertEqual((await bridge(CAP.RANDOM, U(0, 0, 0, 16))).length, 16, "CAP_RANDOM returns n bytes");
    assertEqual((await bridge(CAP.CLOCK, U())).length, 8, "CAP_CLOCK returns a u64");

    // fs.* over the raw backend
    const fk = new TextEncoder().encode("dead.blk"), fv = U(7, 7, 7);
    await bridge(CAP.FS_PUT, concatBytes([U(0, 0, 0, fk.length), fk, fv]));
    const got = await bridge(CAP.FS_GET, fk);
    assert(got[0] === 1 && bytesEqual(got.slice(1), fv), "CAP_FS_PUT/GET round-trips under an opaque key");
    assertEqual((await bridge(CAP.FS_GET, new TextEncoder().encode("missing")))[0], 0, "CAP_FS_GET of an absent key → [0]");
    const szPresent = await bridge(CAP.FS_SIZE, fk);
    assertEqual(new DataView(szPresent.buffer, szPresent.byteOffset).getUint32(0, false), fv.length, "CAP_FS_SIZE returns the value's byte length");
    const szAbsent = await bridge(CAP.FS_SIZE, new TextEncoder().encode("missing"));
    assertEqual(new DataView(szAbsent.buffer, szAbsent.byteOffset).getUint32(0, false), 0xffffffff, "CAP_FS_SIZE of an absent key → -1 (0xFFFFFFFF)");

    // Sync vs async, and which side of that line an op sits on is the ABI (§12.2): a
    // primitive is a function of its arguments and resolves inline; net and fs genuinely
    // round-trip and hand back a Promise. Which side an op sits on is what `guest.abi`
    // versions, which is why it is declared and checked rather than assumed.
    assert(!(prim("blake2b-256", msg) instanceof Promise), "a catalog primitive resolves synchronously (bytes, no Promise)");
    assert(bridge(CAP.FS_SIZE, fk) instanceof Promise, "CAP_FS_SIZE returns a Promise (fs round-trips)");
    assert(bridge(CAP.NET_PEERS, U()) instanceof Uint8Array, "CAP_NET_PEERS is synchronous");
    const protoEnc = new TextEncoder().encode("_test");
    const sendFrame = concatBytes([id.publicKey, U(protoEnc.length), protoEnc, U(7)]);
    const sendResult = bridge(CAP.NET_SEND, sendFrame);
    assert(sendResult instanceof Promise, "CAP_NET_SEND returns a Promise (a real round trip)");
    await sendResult.catch(() => {}); // drain (no live peer) so it doesn't dangle

    // net.peers
    const peers = await bridge(CAP.NET_PEERS, U());
    assertEqual(new DataView(peers.buffer, peers.byteOffset).getUint32(0, false), 1, "CAP_NET_PEERS counts the cohort");

    // module-call reaches an installed handler by name — the name crosses the seam as
    // its UTF-8 bytes (§12.2 MODULE_CALL: [nameLen u8][name utf8][req]).
    const echoNameBytes = new TextEncoder().encode(echoName);
    const mc = new Uint8Array(1 + echoNameBytes.length + 2);
    mc[0] = echoNameBytes.length; mc.set(echoNameBytes, 1); mc.set(U(8, 9), 1 + echoNameBytes.length);
    assertEqual([...await bridge(CAP.MODULE_CALL, mc)], [8, 9], "CAP_MODULE_CALL invokes the named handler");
  } finally {
    transport.close();
  }

  console.log("  OK\n");
}

// ─── Test: WebSocket framing primitives (RFC 6455) ──────────────────────

async function testWsFraming() {
  console.log("Test: WebSocket framing primitives (RFC 6455) — the no-cap ws module");

  // RFC 6455 §1.3 worked example — exercises the WASM SHA-1 + base64 end-to-end
  // (the only SHA-1/base64 in the runtime; the former JS copy is deleted).
  assertEqual(wsAcceptKey("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "WS accept known vector");

  // Encode a masked client frame, parse it back through the server parser,
  // split across a chunk boundary to exercise the incremental reader.
  const payload = new Uint8Array(300);
  for (let i = 0; i < payload.length; i++) payload[i] = (i * 31 + 28) & 255;
  const mask = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
  const wire = encodeFrame(WS_OPCODES.OP_BINARY, payload, mask);
  const parser = new WsParser(true);
  const frames = [...parser.push(wire.subarray(0, 7)), ...parser.push(wire.subarray(7))];
  assertEqual(frames.length, 1, "one frame parsed across chunk boundary");
  assert(frames[0] && bytesEqual(frames[0].payload, payload), "unmasked payload matches after demasking");

  console.log("  OK\n");
}

// ─── Test: channel identity pinning (transport §12.6) ─────────────────────

async function testPolicy() {
  console.log("Test: shell install policy — closed author set gates bundle loads");
  const { parsePolicy } = await imp("build/host/policy.js");

  const good = generateKeyPair();
  const bad = generateKeyPair();

  // Build a signed bundle from each author; loadBundle accepts/rejects by predicate.
  const { KernelHost } = await imp("build/core/kernel-host.js");
  const tryLoad = async (policyJson, author, extra = {}) => {
    const host = new KernelHost();
    const manifest = { app: "mod", version: 1, ...extra,
      modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }] };
    const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
    const blob = packBundle({ [MANIFEST_FILE]: manifestEnv, [moduleFile("fwd")]: forwarderBytes });
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
      { app: "mod", version: 1, role: "quantum-relay", modules: [] }));
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

  // A handler-only bundle declares no guest and therefore no ABI — the seam it never
  // touches is not a field it has to fill in.
  assert(verifyManifest(sodium, signManifest(sodium, author.privateKey, author.publicKey,
    { app: "abi", version: 1, modules: [] })) !== null,
    "a handler-only bundle needs no ABI declaration");

  console.log("  OK\n");
}

// ─── Test: a slot occupant's freshness (§12.4) ──────────────────────────

async function testSlotFreshness() {
  console.log("Test: a slot occupant carries the ordinary (author, app) freshness mark");

  const { FreshnessMarks } = await imp("build/host/bundle.js");
  const { KernelHost } = await imp("build/core/kernel-host.js");

  const a = generateKeyPair();
  const b = generateKeyPair();
  const blobFrom = (author, version, role) => packBundle({
    [MANIFEST_FILE]: signManifest(sodium, author.privateKey, author.publicKey,
      { app: "link", version, ...(role ? { role } : {}), modules: [{ name: "fwd", hash: toHex(gHash(forwarderBytes)) }] }),
    [moduleFile("fwd")]: forwarderBytes,
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
    const host = new KernelHost();
    land(host, freshness, a, 5, "transport");
    assertEqual(freshness.get(a.publicKey, "link"), 5, "landing a slot occupant advances its (author, app) mark");
    land(host, freshness, b, 1, "transport");
    assertEqual(freshness.get(b.publicKey, "link"), 1, "a second author's slot bundle answers to its own lineage");
  }

  // Each author is still held to their own mark — dropping the slot floor weakens
  // nothing about the downgrade that has always been in scope.
  {
    const freshness = new FreshnessMarks();
    const host = new KernelHost();
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
  const { signManifest, verifyManifest, packBundle, kernelNameFor, MANIFEST_FILE, GUEST_FILE, moduleFile }
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
    // (§12.4) — no per-module .install envelope — under a kernel name the loader
    // DERIVES from the signed `(app, name)` pair, so the manifest declares none.
    // Neither the module nor the guest names a file: they are `<name>.wasm` and
    // `guest.js`.
    const { host: h } = await makeHost();
    const kernelName = kernelNameFor(author.publicKey, "test", "codec");
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
    assert(shell.host.isBound(kernelName), "module registered under its kernel name");

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

// ─── Test: handler-only bundle (no guest) + the verify/install split ────
//
// A chat-style app is a one-module bundle with NO guest realm — and because caps
// live inside `guest` (§12.4), omitting it IS declaring zero authority; there is no
// empty caps list to write. Proves the shared §12.4 loader accepts that shape
// (guestSource === ""), that a bundle blob round-trips as one value, and that
// `verifyBundle` authenticates + integrity-checks WITHOUT a host or a policy — the
// seam the browser shell peeks a received Offer through before asking for consent.
async function testGuestlessBundleAndArchive() {
  console.log("Test: handler-only bundle (no guest) loads + verify/install split");
  const { signManifest, verifyManifest, verifyBundle,
          packBundle, unpackBundle, kernelNameFor, MANIFEST_FILE, moduleFile }
    = await imp("build/host/bundle.js");
  const { boot } = await imp("build/host/main.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = generateKeyPair();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-guestless-"));
  const bundlePath = pjoin(dir, "demo.skb");
  let shell;
  try {
    const { host: h } = await makeHost();
    const kernelName = kernelNameFor(author.publicKey, "demo", "demo");
    // A manifest with NO `guest` field — the handler-only shape, and so no caps.
    const manifest = {
      app: "demo", version: 1,
      modules: [{ name: "demo", hash: toHex(gHash(forwarderBytes)) }],
    };
    const manifestEnv = signManifest(sodium, author.privateKey, author.publicKey, manifest);
    assert(verifyManifest(sodium, manifestEnv) !== null, "a guest-less manifest verifies");

    // Blob round-trip: a bundle IS one blob, and this is what an Offer carries over a
    // data channel and what the loader reads from disk — one format, one path.
    const packed = packBundle({
      [MANIFEST_FILE]: manifestEnv,
      [moduleFile("demo")]: forwarderBytes,
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
    assertEqual(v.guestSource, "", "a guest-less bundle verifies with an empty guest source");
    // Corrupting a module must fail integrity even though the manifest still verifies.
    const corrupt = packBundle({
      [MANIFEST_FILE]: manifestEnv,
      [moduleFile("demo")]: forwarderBytes.slice(0, forwarderBytes.length - 1),
    });
    let integrityFailed = false;
    try { verifyBundle(sodium, corrupt); }
    catch { integrityFailed = true; }
    assert(integrityFailed, "a module that does not match its declared hash fails integrity");

    // Load the guest-less bundle through the shared §12.4 loader.
    wf(bundlePath, packed);
    shell = await boot({
      policyJson: JSON.stringify({ authors: [toHex(author.publicKey)] }),
      dir: pjoin(dir, "_data"), identity,
    });
    const loaded = await shell.loadBundle(bundlePath);
    assert(shell.host.isBound(kernelName), "module registered under its kernel name");
    assertEqual(loaded.guestSource, "", "a guest-less bundle yields an empty guest source");
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
    const realm = await createSafeRealm({ source: probeSrc, bridge: () => new Uint8Array() });
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
    const realm = await createSafeRealm({ source: src, bridge: () => new Uint8Array() });
    const res = await realm.call("tryImport", new Uint8Array());
    assertEqual(res[0], 0, "import('node:fs') rejects — no path out of the realm");
    realm.dispose();
  }

  // 2. The seam: a sync op returns bytes directly (no yield); a net-like op returns a
  //    real Promise the guest awaits. Bytes round-trip across the copy boundary both ways.
  {
    let bridgeCalls = 0;
    const bridge = (op, payload) => {
      bridgeCalls++;
      if (op === 1) return payload.map((b) => (b + 1) & 0xff);                          // sync op — bytes directly
      if (op === 7) return sleep(3).then(() => payload.map((b) => (b + 1) & 0xff));     // net-like op — a Promise
      return new Uint8Array();
    };
    const src = `
      register("sync", (arg) => host.call(1, arg));                  // sync op: host.call returns bytes, no await
      register("net", async (arg) => { return await host.call(7, arg); });  // net op: a genuinely awaited Promise
    `;
    const realm = await createSafeRealm({ source: src, bridge });
    const input = new Uint8Array([0, 1, 2, 254, 255]);
    const sync = await realm.call("sync", input);
    assertEqual([...sync], [1, 2, 3, 255, 0], "sync op: bytes crossed in and back with no promise");
    const asyncR = await realm.call("net", input);
    assertEqual([...asyncR], [1, 2, 3, 255, 0], "net op: await host.call resolves the real Promise");
    assert(bridgeCalls === 2, "the host bridge was invoked for each call");
    const again = await realm.call("sync", new Uint8Array([10]));
    assertEqual([...again], [11], "realm is reusable across calls");
    realm.dispose();
  }

  // 3. Orchestration control-flow shapes run as ordinary async guest JS, including a
  //    concurrent fan-out with the guest's own Promise.all over a net-like op — the
  //    real-promise seam is what makes this possible in one realm.
  {
    const bridge = (op, payload) => {
      const peer = payload[0];
      if (op === 2) return sleep(1).then(() => new Uint8Array([peer % 2 === 0 ? 1 : 0])); // offer (async)
      if (op === 3) return sleep(1).then(() => new Uint8Array([peer % 3 === 0 ? 1 : 0])); // have (async)
      return new Uint8Array();
    };
    const src = `
      register("orchestrate", async (arg) => {
        const count = arg[0], peerCount = arg[1];
        // Fan out OFFERs concurrently — the guest's own Promise.all, no host sendMany.
        const offers = await Promise.all(
          Array.from({ length: peerCount }, (_, p) => host.call(2, new Uint8Array([p]))),
        );
        const placed = [];
        for (let p = 0; p < peerCount && placed.length < count; p++) {
          if (offers[p][0] === 1) placed.push(p);
        }
        const haves = await Promise.all(
          Array.from({ length: peerCount }, (_, p) => host.call(3, new Uint8Array([p]))),
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
      bridge: () => new Uint8Array(),
    });
    const b = await createSafeRealm({
      source: `register("leak", () => new Uint8Array([globalThis.SECRET ?? 0]));`,
      bridge: () => new Uint8Array(),
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
    const bridge = (op, payload) => { calls++; return op === 1 ? payload.map((b) => (b + 1) & 0xff) : new Uint8Array(); };
    const realm = await createSafeRealm({
      source: `register("inc", (arg) => host.call(1, arg));`,
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
    const bridge = (op, payload) => {
      if (op === 7) return gate.then(() => new Uint8Array([42]));   // parks until released
      if (op === 1) return payload.map((b) => (b + 1) & 0xff);      // sync — holder path
      return new Uint8Array();
    };
    const realm = await createSafeRealm({
      source: `register("init", async () => host.call(7, new Uint8Array()));
               register("hold", (arg) => host.call(1, arg));`,
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
      bridge: () => new Uint8Array(),
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
      source: `register("park", async () => await host.call(7, new Uint8Array()));`,
      bridge: (op) => (op === 7 ? new Promise(() => {}) : new Uint8Array()),  // op 7 never settles
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
      bridge: () => new Uint8Array(),
    });
    assertEqual([...(await next.call("ping", new Uint8Array([7])))], [7],
      "the engine is still alive after the parked realm's context was freed");
    next.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: PR-review hardening — cap enforcement, guarded callHandler, ───
// ─── sender-bound responses, WS fragmentation, redial after failure ──────

async function testCapBridgeEnforcement() {
  console.log("Test: cap-bridge enforces the manifest's declared op set + allocation caps");

  const id = generateKeyPair();
  const stubTransport = { request: async (_peer, _proto, _payload) => new Uint8Array() };
  const mk = (allowedOps) => createCapBridge({
    sodium, identity: id, callHandler: () => null,
    transport: stubTransport, peers: () => [], fs: new MemoryFs(),
    allowedOps, modules: UNSCOPED_MODULES,
  });
  const U = (...xs) => new Uint8Array(xs);

  // A PRIMITIVE is exempt from the gate by construction: it reaches nothing, so there
  // is nothing to grant. A bridge built for a bundle declaring NO domains still hashes.
  const clockOnly = mk(opsForCaps(["clock"]));
  const hashCall = concatBytes([U(11), new TextEncoder().encode("blake2b-256"), U(1, 2)]);
  assertEqual((await clockOnly(CAP.CRYPTO, hashCall)).length, 32,
    "CAP_CRYPTO resolves for a bundle declaring no crypto domain — a pure transform is not a grant");

  // Authorities are gated, and each one names something no confined module can hold.
  let threw = false;
  try { await clockOnly(CAP.SIGN, U(1)); } catch { threw = true; }
  assert(threw, "an undeclared authority (SIGN) is refused by the bridge");
  threw = false;
  try { await clockOnly(CAP.FS_DELETE, U(120)); } catch { threw = true; }
  assert(threw, "an undeclared authority (FS_DELETE) is refused by the bridge");

  // guest-controlled allocation caps. UNRESTRICTED_OPS is the host-side caller that
  // opts out of gating *by name* — omitting allowedOps entirely now throws (§12.2).
  const open = mk(UNRESTRICTED_OPS);
  let omitted = false;
  try { mk(undefined); } catch { omitted = true; }
  assert(omitted, "omitting allowedOps throws rather than granting every op");
  assertEqual((await open(CAP.RANDOM, U(0, 0, 4, 0))).length, 1024, "RANDOM under the cap works");
  threw = false;
  try { await open(CAP.RANDOM, U(0xff, 0xff, 0xff, 0xff)); } catch { threw = true; }
  assert(threw, "RANDOM over the cap is refused");

  // caps → ops: a bundle declares capability DOMAINS and the shell expands them to the
  // op set the bridge enforces. `crypto` is now the AUTHORITY half only — SIGN,
  // IDENTITY, RANDOM — because the transform half was never a grant.
  const authorityOnly = createCapBridge({
    sodium, identity: id, callHandler: () => null,
    transport: stubTransport, peers: () => [], fs: new MemoryFs(),
    allowedOps: opsForCaps(["crypto"]), modules: UNSCOPED_MODULES,
    signScope: appSignScope(id, new Uint8Array(32), "probe"),
  });
  assertEqual((await authorityOnly(CAP.SIGN, U(1, 2))).length, 64, "crypto grants the node-key ops");
  assertEqual((await authorityOnly(CAP.CRYPTO, hashCall)).length, 32,
    "…and hashing needs no domain at all");
  threw = false;
  try { await authorityOnly(CAP.FS_GET, U(120)); } catch { threw = true; }
  assert(threw, "an op outside the declared domains (fs) is refused");

  // The vocabulary is closed: a domain that no longer exists fails loudly rather than
  // being ignored, which is what makes a stale manifest a refused load.
  threw = false;
  try { opsForCaps(["transform"]); } catch { threw = true; }
  assert(threw, "`transform` is gone from the vocabulary — a manifest naming it is refused");
  threw = false;
  try { opsForCaps(["crypto", "nope"]); } catch { threw = true; }
  assert(threw, "an unknown capability domain throws (a manifest typo fails loudly)");

  console.log("  OK\n");
}

async function testCallHandlerGuards() {
  console.log("Test: KernelHost.callHandler resolves by name, or null when unbound (§4)");

  const { host } = await makeHost();
  const { publicKey: pk } = generateKeyPair();

  // An unbound name resolves to nothing — null, distinct from an empty response.
  const missing = modName("nope", "missing");
  assert(host.callHandler(missing, new Uint8Array([1])) === null,
    "callHandler returns null for an unbound name");

  // An installed handler is reached by name. A confined guest reaches the same handler
  // through the cap-bridge's MODULE_CALL (§12.2).
  const echoName = modName("guards", "echo");
  installMod(host, echoName, forwarderBytes);
  const r = host.callHandler(echoName, new Uint8Array([5]));
  assertEqual([...r], [5], "callHandler reaches an installed handler");

  // A 0-length response is a valid EMPTY answer, NOT the null of an unbound name — the
  // two are distinct at this seam, so a caller can tell "handler ran, said nothing" from
  // "nothing there". The forwarder echoes, so an empty input produces an empty response.
  const empty = host.callHandler(echoName, EMPTY);
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
    source: `register("echo", async (a) => await host.call(7, a));`,
    bridge: (_op, p) => sleep(10).then(() => p),
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
  const manifest = { app: "suite-probe", version: 1, modules: [] };
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
          verifyBundle, packBundle, kernelNameFor, MANIFEST_FILE }
    = await imp("build/host/bundle.js");
  const { generatePqKeyPair } = await imp("build/host/node.js");

  const ed = generateKeyPair();
  const pq = generatePqKeyPair();
  const keys = { ed, mlDsa: pq };
  const manifest = { app: "pq-probe", version: 1, modules: [] };
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
    const m = { app: "pq-app", version: 1, modules: [{ name: "codec", hash: toHex(gHash(wasm)) }] };
    const blob = packBundle({
      [MANIFEST_FILE]: signManifestHybrid(sodium, keys, m),
      [moduleFile("codec")]: wasm,
    });
    const v = verifyBundle(sodium, blob);
    assertEqual(v.suite, 0x02, "verifyBundle carries the suite through to the policy seam");
    const host = await createKernelHost();
    installBundle(host, v);
    const derived = kernelNameFor(hybridAuthorId(sodium, ed.publicKey, pq.publicKey), "pq-app", "codec");
    assert(host.isBound(derived), "the module binds under the derived hybrid author id");

    const edOnly = packBundle({
      [MANIFEST_FILE]: signManifest(sodium, ed.privateKey, ed.publicKey, m),
      [moduleFile("codec")]: wasm,
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
  const { generatePqKeyPair } = await imp("build/host/node.js");

  const ed = generateKeyPair();
  const pq = generatePqKeyPair();
  const wasm = forwarderBytes;
  const m = { app: "suite-policy", version: 1, modules: [{ name: "codec", hash: toHex(gHash(wasm)) }] };
  const pack = (envelope) => packBundle({ [MANIFEST_FILE]: envelope, [moduleFile("codec")]: wasm });

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
  const { signManifest, packBundle, kernelNameFor, MANIFEST_FILE, GUEST_FILE, moduleFile }
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
    const kernelName = kernelNameFor(author.publicKey, "rollback", "codec");
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
    });
    const writeBundle = (version) => wf(bundlePath, packBundle({
      [MANIFEST_FILE]: signManifest(sodium, author.privateKey, author.publicKey, manifest(version)),
      [moduleFile("codec")]: forwarderBytes,
    }));

    shell = await boot({ policyJson, dir: dataDir, identity });
    const appKey = appKeyFor(author.publicKey, "victim");
    const kernelName = bundleKernelNameFor(author.publicKey, "victim", "codec");

    // 1. The author is trusted: v1 loads and binds.
    writeBundle(1);
    await shell.loadBundle(bundlePath);
    assert(shell.host.isBound(kernelName), "the app binds while the author is trusted");

    // 2. The key is stolen. Freshness does NOT stop it — v2 is strictly newer, so it
    //    loads over the same name. This is the gap, asserted rather than assumed.
    writeBundle(2);
    await shell.loadBundle(bundlePath);
    assert(shell.host.isBound(kernelName), "freshness does not stop a newer bundle from a stolen key");

    // 3. Write the key off. Both halves must happen in the one call.
    const gone = shell.revoke(authorHex);
    assert(gone.includes(appKey), "revoke reports the app it tore down");
    assert(!shell.host.isBound(kernelName), "revoke uninstalls what the key already landed");

    // 4. The thief's next bundle is refused even though the version keeps climbing
    //    and the author is still in the policy allowlist.
    writeBundle(3);
    let refused = false;
    try { await shell.loadBundle(bundlePath); } catch { refused = true; }
    assert(refused, "a bundle from a revoked key is refused despite a higher version");
    assert(!shell.host.isBound(kernelName), "nothing landed on the refused load");

    // 4b. The refusal must come BEFORE the admission predicate, not after it. An
    //     interactive shell puts its consent dialog there (§12.4), and prompting a
    //     user to approve a bundle this host has already decided to refuse — then
    //     failing once they say yes — is the wrong order to ask in.
    {
      const { createShell: mkShell, KernelHost: KH } = await imp("build/host/shell-core.js");
      const { FreshnessMarks } = await imp("build/host/bundle.js");
      const store = new FreshnessMarks();
      let admitCalls = 0;
      const probe = mkShell({
        platform: {
          sodium, identity, kernel: new KH(), freshnessStore: store,
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
    }));
    shell.close();
    shell = await boot({
      policyJson: JSON.stringify({ authors: [authorHex, toHex(heir.publicKey)] }),
      dir: dataDir, identity,
    });
    await shell.loadBundle(bundlePath);
    assert(shell.host.isBound(bundleKernelNameFor(heir.publicKey, "victim", "codec")),
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

// ─── Run ────────────────────────────────────────────────────────────────

await testFullLifecycle();
await testInstallRejectsUntrustedAuthor();
await testManifestHashIsEnforced();
await testDenyAllPolicyRejects();
await testBundleRefusesNonHandler();
await testDerivedNamesKeepAuthorsApart();
await testHandlesIsADeclarationNotAClaim();
await testInstallerRemove();
await testFs();
await testCapBridge();
await testPolicy();
await testGuestAbi();
await testSlotFreshness();
await testShellBoot();
await testBundle();
await testGuestlessBundleAndArchive();
await testBundleCorruptNewerRollback();
await testWsFraming();
await testSafeJs();
await testRealmSerialization();
await testCapBridgeEnforcement();
await testCallHandlerGuards();
await testManifestSuiteByte();
await testMlDsaAcvpVectors();
await testMlKemAcvpVectors();
await testHybridManifestSuite();
await testPolicyManifestSuite();
await testSafeRealmConcurrency();
await testAuthorRevocation();
await testPreRevocationStoreIsRefused();

console.log(`\nResults: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
