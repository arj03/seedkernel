// End-to-end test: bootstrap -> signed message -> handler dispatch.
//
// Run: node tests/run.mjs

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";
const require = createRequire(import.meta.url);
const sodium = require("libsodium-wrappers-sumo");

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

const {
  loadKernelHost,
  generateKeyPair,
  ensureSodium,
  CURRENT_VERSION,
  referencePolicy,
} = await imp("build/host/node.js");

// Transport + WS module surface (moved up from seedstore in the runtime split,
// the runtime split). These are seedkernel's own public exports — `./net-node`
// (NodeNetwork) and the no-cap `./ws` framing module — so they are exercised here,
// where they live, rather than only from a downstream consumer.
const { NodeNetwork } = await imp("build/host/net-node.js");
const { Transport, LoopbackNetwork } = await imp("build/host/net.js");
const { CAP, createCapBridge, opsForCaps } = await imp("build/host/cap-bridge.js");
const { wsAcceptKey, encodeFrame, WsParser, WS_OPCODES } = await imp("build/host/ws.js");
const { MemoryFs } = await imp("build/host/fs.js");
const { NodeFs } = await imp("build/host/fs-node.js");
const { createSafeRealm, createSyncSafeRealm } = await imp("build/host/safe-js.js");
const { toHex, bytesEqual, concatBytes } = await imp("build/host/util.js");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

await ensureSodium();

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

// Per-signer monotonic seq counter for §4.4 replay protection. Each test
// that builds install payloads instantiates one and calls seq(pubKey) to get
// a fresh strictly-increasing seq for that signer.
function makeSeq() {
  const counters = new Map();
  return (pubKey) => {
    const k = [...pubKey].join(",");
    const next = (counters.get(k) ?? 0) + 1;
    counters.set(k, next);
    return next;
  };
}

const kernelWasm = join(root, "build/kernel.wasm");
const bootstrapWasm = join(root, "build/bootstrap.wasm");

// Standard bootstrap (README §10): signature handler + installer. The default
// policy accepts every install; tests that need rejection override via
// host.setApproveInstall.
async function makeHost(approveInstall = () => true) {
  const host = await loadKernelHost(kernelWasm, bootstrapWasm);
  const signatureName = host.deriveBootstrapName("signature");
  const installName   = host.deriveBootstrapName("install");
  const lookupName    = host.deriveBootstrapName("installer.lookup");
  const capsOfName    = host.deriveBootstrapName("installer.caps_of");

  host.registerSignature(signatureName);
  host.registerInstaller(installName, lookupName, capsOfName);
  host.setApproveInstall(approveInstall);

  return { host, signatureName, installName, lookupName, capsOfName };
}

const { readFileSync } = await import("node:fs");
const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));

// Encode an install + sign it, returning the wire bytes ready for dispatch.
function buildInstall(host, signSk, signPk, installName, seq, targetName, caps, parent, wasm) {
  const payload = host.encodeInstallPayload(seq, targetName, caps, parent, wasm);
  return host.wrapAndEncode(signSk, signPk, CURRENT_VERSION, installName, payload);
}

// ─── Test: Full lifecycle ───────────────────────────────────────────────

async function testFullLifecycle() {
  console.log("Test: Full lifecycle (signed install + signed app message)");

  const { host, installName } = await makeHost();

  const seq = makeSeq();
  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  // Install the chat handler under the author's scoped name.
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk), chatTextName, [], null, forwarderBytes));
  assert(host.isRegistered(chatTextName), "chat.text installed");

  // The installer should have a record for it.
  const rec = host.lookupInstall(chatTextName);
  assert(rec !== null, "install record exists");
  assertEqual(rec.author.publicKey, pk, "record author matches signer");
  assertEqual(rec.parent, null, "first install has null parent");

  // Now send a signed app message. The chat handler is the forwarder fixture,
  // so we forward to a host-side echo handler to verify it ran.
  const echoName = host.deriveBootstrapName("test.echo");
  let echoCalls = 0;
  host.register(echoName, (_n, payload) => { echoCalls++; return new Uint8Array(payload); });

  const text = new TextEncoder().encode("hello from author");
  const forwardPayload = new Uint8Array(1 + echoName.length + text.length);
  forwardPayload[0] = echoName.length;
  forwardPayload.set(echoName, 1);
  forwardPayload.set(text, 1 + echoName.length);

  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, chatTextName, forwardPayload));
  assertEqual(echoCalls, 1, "echo invoked once via kernel.call");

  console.log("  OK\n");
}

// ─── Test: Invalid signature dropped ────────────────────────────────────

async function testInvalidSignatureDropped() {
  console.log("Test: Invalid signature silently dropped");

  const { host } = await makeHost();
  const chatTextName = host.deriveBootstrapName("chat.text");
  let received = 0;
  host.register(chatTextName, () => { received++; });

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const wire = host.wrapAndEncode(sk, pk, CURRENT_VERSION, chatTextName,
    new TextEncoder().encode("should not arrive"));
  wire[40] ^= 0xff;
  host.dispatch(wire);
  assertEqual(received, 0, "no messages received");

  console.log("  OK\n");
}

// ─── Test: 64 KB size limit ─────────────────────────────────────────────

async function testSizeLimitEnforced() {
  console.log("Test: Oversized envelope rejected (§2.2)");

  const host = await loadKernelHost(kernelWasm, bootstrapWasm);

  const chatTextName = host.deriveBootstrapName("chat.text");
  let received = 0;
  host.register(chatTextName, () => { received++; });

  const smallWire = host.encodeEnvelope(CURRENT_VERSION, chatTextName,
    new TextEncoder().encode("ok"));
  const oversized = new Uint8Array(65537);
  oversized.set(smallWire);
  host.dispatch(oversized);
  assertEqual(received, 0, "65537-byte envelope silently dropped");

  // Exactly 65,536 bytes — must not throw.
  const boundary = new Uint8Array(65536);
  boundary.set(smallWire);
  host.dispatch(boundary);

  console.log("  OK\n");
}

// ─── Test: Signature wrapping depth cap (§2.3) ──────────────────────────

async function testSignatureDepthCap() {
  console.log("Test: Signature wrapping depth capped at MAX_SIGNATURE_DEPTH=4 (§2.3)");

  const host = await loadKernelHost(kernelWasm, bootstrapWasm);
  const signatureName = host.deriveBootstrapName("signature");
  host.registerSignature(signatureName);

  const chatTextName = host.deriveBootstrapName("chat.text");
  let received = 0;
  host.register(chatTextName, () => { received++; });

  const { publicKey: pk, privateKey: sk } = generateKeyPair();

  // Build N nested signature wrappers around the same chat.text envelope and
  // dispatch the outermost. wrap() takes raw inner bytes, so we just feed the
  // previous wrap's output back in.
  const wrapN = (n, innerBytes) => {
    let bytes = innerBytes;
    for (let i = 0; i < n; i++) bytes = host.wrap(sk, pk, bytes);
    return bytes;
  };
  const inner = host.encodeEnvelope(CURRENT_VERSION, chatTextName,
    new TextEncoder().encode("hi"));

  // 4 wrappers: signer stack reaches [s4,s3,s2,s1] = length 4 at the innermost
  // verify; that verify checks length < 4 (currently 3) before pushing, so it
  // is accepted. Inner handler must run.
  received = 0;
  host.dispatch(wrapN(4, inner));
  assertEqual(received, 1, "4-deep wrap reaches handler");

  // 5 wrappers: the innermost verify sees signer stack length 4 ≥ 4 and drops
  // before any verify work. Inner handler must NOT run.
  received = 0;
  host.dispatch(wrapN(5, inner));
  assertEqual(received, 0, "5-deep wrap dropped at innermost wrapper");

  console.log("  OK\n");
}

// ─── Test: SetHandler-seeded slot is not overlaid ────────────────────────

async function testRefuseOverlayBootstrapSlot() {
  console.log("Test: reference policy refuses to overlay a SetHandler-seeded slot (§7.4)");

  // Use the reference policy with an allow-all first-install branch so this
  // test exercises only the bootstrap-slot refusal — not an unrelated first-
  // install rejection.
  const host = await loadKernelHost(kernelWasm, bootstrapWasm);
  const signatureName = host.deriveBootstrapName("signature");
  const installName   = host.deriveBootstrapName("install");
  const lookupName    = host.deriveBootstrapName("installer.lookup");
  const capsOfName    = host.deriveBootstrapName("installer.caps_of");
  host.registerSignature(signatureName);
  host.registerInstaller(installName, lookupName, capsOfName);
  host.setApproveInstall(referencePolicy(host, () => true));

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const seq = makeSeq();
  // Try to overlay the signature slot (seeded by SetHandler at bootstrap).
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    signatureName, [], null, forwarderBytes));

  // signature must still verify — if it had been overwritten with the
  // forwarder, the next signed message would fail.
  const chatTextName = host.deriveBootstrapName("chat.text");
  let received = 0;
  host.register(chatTextName, () => { received++; });
  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, chatTextName,
    new TextEncoder().encode("still works")));
  assertEqual(received, 1, "signature handler still verifying after refused overlay");

  console.log("  OK\n");
}

// ─── Test: approveInstall is the sole authorization gate ────────────────

async function testApproveInstallRejects() {
  console.log("Test: approveInstall can reject an install");

  let seen = null;
  const approve = (name, author, bytesHash, _wasm, caps, parent, existing) => {
    seen = { name, author, bytesHash, caps: [...caps], parent, existing };
    return false;
  };
  const { host, installName } = await makeHost(approve);

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);
  const netCapId = host.deriveBootstrapName("cap.net");

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatTextName, [netCapId], null, forwarderBytes));

  assert(!host.isRegistered(chatTextName), "install rejected");
  assert(seen !== null, "approveInstall was called");
  assertEqual(seen.name, chatTextName, "callback saw the target name");
  assertEqual(seen.caps.length, 1, "callback saw 1 declared cap");
  assertEqual(seen.caps[0], netCapId, "callback saw the cap value");
  assertEqual(seen.author.publicKey, pk, "callback saw the author pubkey");
  assert(seen.parent === null, "first install has null parent");
  assert(seen.existing === null, "no existing record for first install");

  console.log("  OK\n");
}

async function testApproveInstallReceivesBytesHash() {
  console.log("Test: approveInstall receives genesis-hash of FULL install payload (§7.1)");

  let seenHash = null;
  let seenPayloadLen = 0;
  const approve = (_n, _a, bytesHash, wasm, _c, _p, _e) => {
    seenHash = bytesHash;
    seenPayloadLen = wasm.length; // for sanity
    return true;
  };
  const { host, installName } = await makeHost(approve);

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  const seq = makeSeq();
  const payload = host.encodeInstallPayload(seq(pk), chatTextName, [], null, forwarderBytes);
  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, installName, payload));
  assert(host.isRegistered(chatTextName), "install accepted");

  assertEqual(seenHash.length, 32, "bytes_hash is SHA-3-256 (32 bytes)");
  // The hash must cover the ENTIRE install payload, not just the WASM.
  const expected = host.genesisHash(payload);
  assertEqual(seenHash, expected, "bytes_hash = genesisHash(install_payload)");
  assert(seenPayloadLen === forwarderBytes.length, "wasm bytes passed to callback are unchanged");

  console.log("  OK\n");
}

async function testNoApproveInstallDropsAll() {
  console.log("Test: install dropped when no approveInstall is wired");

  const { host, installName } = await makeHost();
  host.setApproveInstall(null);

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatTextName, [], null, forwarderBytes));

  assert(!host.isRegistered(chatTextName), "install dropped");

  console.log("  OK\n");
}

// ─── Test: reference policy upgrade rules (§7.4) ────────────────────────

async function testReferencePolicyUpgradeRules() {
  console.log("Test: reference policy enforces same-author + parent=bytes_hash on upgrade (§7.4)");

  const host = await loadKernelHost(kernelWasm, bootstrapWasm);
  const signatureName = host.deriveBootstrapName("signature");
  const installName   = host.deriveBootstrapName("install");
  const lookupName    = host.deriveBootstrapName("installer.lookup");
  const capsOfName    = host.deriveBootstrapName("installer.caps_of");
  host.registerSignature(signatureName);
  host.registerInstaller(installName, lookupName, capsOfName);
  host.setApproveInstall(referencePolicy(host, () => true));

  const seq = makeSeq();
  const { publicKey: aPk, privateKey: aSk } = generateKeyPair();
  const { publicKey: bPk, privateKey: bSk } = generateKeyPair();
  // Both authors target the same name so we can exercise the upgrade path.
  // (Author-scoped names would partition the space and avoid the rule.)
  const sharedName = host.deriveBootstrapName("test.shared");

  // A claims sharedName (first install — accepted).
  host.dispatch(buildInstall(host, aSk, aPk, installName, seq(aPk),
    sharedName, [], null, forwarderBytes));
  assert(host.isRegistered(sharedName), "A's first install accepted");
  const recA = host.lookupInstall(sharedName);
  assert(recA !== null, "record exists after A's install");
  const aBytesHash = recA.bytesHash;

  // B tries to install over the same name — rejected (different author).
  host.dispatch(buildInstall(host, bSk, bPk, installName, seq(bPk),
    sharedName, [], aBytesHash, forwarderBytes));
  const recAfterB = host.lookupInstall(sharedName);
  assertEqual(recAfterB.author.publicKey, aPk, "different-author install rejected, A still owns");

  // A re-installs with wrong parent — rejected.
  host.dispatch(buildInstall(host, aSk, aPk, installName, seq(aPk),
    sharedName, [], new Uint8Array(32), forwarderBytes));
  const recAfterWrongParent = host.lookupInstall(sharedName);
  assertEqual(recAfterWrongParent.bytesHash, aBytesHash,
    "same-author wrong-parent install rejected");

  // A re-installs with no parent — rejected.
  host.dispatch(buildInstall(host, aSk, aPk, installName, seq(aPk),
    sharedName, [], null, forwarderBytes));
  const recAfterNullParent = host.lookupInstall(sharedName);
  assertEqual(recAfterNullParent.bytesHash, aBytesHash,
    "same-author null-parent re-install rejected");

  // A re-installs with correct parent — accepted; record updates in place.
  host.dispatch(buildInstall(host, aSk, aPk, installName, seq(aPk),
    sharedName, [], aBytesHash, forwarderBytes));
  const recAfterUpgrade = host.lookupInstall(sharedName);
  assert(recAfterUpgrade !== null, "upgrade left a record");
  assertEqual(recAfterUpgrade.author.publicKey, aPk, "A still owns after upgrade");
  assertEqual(recAfterUpgrade.parent, aBytesHash, "parent recorded");
  assert(
    JSON.stringify([...recAfterUpgrade.bytesHash]) !== JSON.stringify([...aBytesHash]),
    "bytes_hash changed (new payload, new seq)"
  );

  console.log("  OK\n");
}

// ─── Test: reference policy capability acknowledgement (§7.4 rule 3) ─────

async function testReferencePolicyCapAcknowledgement() {
  console.log("Test: reference policy gates capability grants on acknowledgement (§7.4 rule 3)");

  const host = await loadKernelHost(kernelWasm, bootstrapWasm);
  const signatureName = host.deriveBootstrapName("signature");
  const installName   = host.deriveBootstrapName("install");
  const lookupName    = host.deriveBootstrapName("installer.lookup");
  const capsOfName    = host.deriveBootstrapName("installer.caps_of");
  host.registerSignature(signatureName);
  host.registerInstaller(installName, lookupName, capsOfName);

  // Acknowledgement hook records what it was asked and answers per `ackAnswer`.
  let ackAdded = null;
  let ackAnswer = false;
  host.setApproveInstall(referencePolicy(host, () => true, (_name, _author, added) => {
    ackAdded = added.map((c) => [...c]);
    return ackAnswer;
  }));

  const seq = makeSeq();
  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const netCap = host.deriveBootstrapName("cap.net");
  const fsCap  = host.deriveBootstrapName("cap.fs");

  // 1. Caps-free first install → accepted with no ack prompt.
  const pureName = host.deriveBootstrapName("test.pure");
  ackAdded = null;
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk), pureName, [], null, forwarderBytes));
  assert(host.isRegistered(pureName), "caps-free first install accepted");
  assert(ackAdded === null, "no ack prompt for caps-free install");

  // 2. First install requesting a cap → ack denies → dropped.
  const capName = host.deriveBootstrapName("test.capped");
  ackAnswer = false; ackAdded = null;
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk), capName, [netCap], null, forwarderBytes));
  assert(!host.isRegistered(capName), "cap-requesting install dropped when ack denies");
  assert(ackAdded !== null && ackAdded.length === 1, "ack hook saw the requested cap");

  // 3. Same install, ack approves → accepted, cap recorded.
  ackAnswer = true; ackAdded = null;
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk), capName, [netCap], null, forwarderBytes));
  assert(host.isRegistered(capName), "cap-requesting install accepted when ack approves");
  const rec1 = host.lookupInstall(capName);
  assertEqual(host.getHandlerDeclaredCaps(capName).length, 1, "one cap recorded");

  // 4. Same-author upgrade keeping the SAME cap → auto-accepted, no ack prompt.
  ackAdded = null;
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk), capName, [netCap], rec1.bytesHash, forwarderBytes));
  assert(host.isRegistered(capName), "same-cap upgrade accepted");
  assert(ackAdded === null, "no ack prompt when caps unchanged on upgrade");
  const rec2 = host.lookupInstall(capName);

  // 5. Same-author upgrade BROADENING caps (add fs) → needs ack; denied → dropped.
  ackAnswer = false; ackAdded = null;
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk), capName, [netCap, fsCap], rec2.bytesHash, forwarderBytes));
  assert(ackAdded !== null && ackAdded.length === 1, "ack hook saw only the newly-added cap");
  assertEqual(ackAdded[0], [...fsCap], "added cap is fs, not the already-held net");
  assertEqual(host.getHandlerDeclaredCaps(capName).length, 1, "broadening dropped — caps unchanged");

  console.log("  OK\n");
}

// ─── Test: install replay rejected by seq (§4.4) ────────────────────────

async function testInstallReplayRejected() {
  console.log("Test: install handler rejects wire-byte replay (§4.4)");

  let approveCalls = 0;
  const { host, installName } = await makeHost((_n, _a, _h, _w, _c, _p, _e) => {
    approveCalls++;
    return true;
  });

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  // Original install with seq=1.
  const wire = buildInstall(host, sk, pk, installName, 1, chatTextName, [], null, forwarderBytes);
  host.dispatch(wire);
  assert(host.isRegistered(chatTextName), "first install succeeded");
  assertEqual(approveCalls, 1, "approve called once");

  // Operator removes the install. Seq must NOT rewind.
  assert(host.installer.remove(chatTextName), "installer.remove succeeded");
  assert(!host.isRegistered(chatTextName), "kernel slot cleared");

  // Replay — seq=1 is no longer fresh, must drop before approve runs.
  host.dispatch(wire);
  assert(!host.isRegistered(chatTextName), "replayed install did NOT re-install");
  assertEqual(approveCalls, 1, "approve NOT re-prompted on replay");

  // Fresh install at seq=2 still works.
  host.dispatch(buildInstall(host, sk, pk, installName, 2, chatTextName, [], null, forwarderBytes));
  assert(host.isRegistered(chatTextName), "fresh higher-seq install succeeded");
  assertEqual(approveCalls, 2, "approve called for legitimate retry");

  console.log("  OK\n");
}

// ─── Test: installer.lookup query handler ───────────────────────────────

async function testInstallerLookupQuery() {
  console.log("Test: installer.lookup returns the install record over kernel.call");

  const { host, installName, lookupName } = await makeHost();

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatTextName, [], null, forwarderBytes));
  assert(host.isRegistered(chatTextName), "install ok");

  // Exercise the WASM-facing lookup handler via the forwarder fixture. The
  // forwarder calls kernel.call(target, payload); we make the target the
  // installer.lookup name and the payload a [len][name] lookup query, then
  // read back the response from the forwarder's private memory.
  const lookupQuery = new Uint8Array(1 + chatTextName.length);
  lookupQuery[0] = chatTextName.length;
  lookupQuery.set(chatTextName, 1);

  // Install a fresh forwarder under a scoped name so it can kernel.call into
  // installer.lookup.
  const forwarderName = host.deriveScopedName("test.forwarder", pk);
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    forwarderName, [], null, forwarderBytes));
  assert(host.isRegistered(forwarderName), "forwarder installed");

  // Payload format the forwarder expects: [target_name_len][target_name][forward_data]
  const fwdPayload = new Uint8Array(1 + lookupName.length + lookupQuery.length);
  fwdPayload[0] = lookupName.length;
  fwdPayload.set(lookupName, 1);
  fwdPayload.set(lookupQuery, 1 + lookupName.length);

  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, forwarderName, fwdPayload));

  // Read back the response the forwarder stored.
  const respPtr = host.callDynamicHandlerI32(forwarderName, "last_resp_ptr");
  const respLen = host.callDynamicHandlerI32(forwarderName, "last_resp_len");
  assert(respLen > 0, "installer.lookup returned a non-empty response");
  const resp = host.readDynamicHandlerMemory(forwarderName, respPtr, respLen);
  assertEqual(resp[0], 1, "response starts with [1] (record present)");

  // Lookup for an unknown name returns [0].
  const unknown = host.deriveBootstrapName("does.not.exist");
  const unknownQuery = new Uint8Array(1 + unknown.length);
  unknownQuery[0] = unknown.length;
  unknownQuery.set(unknown, 1);
  const fwdPayload2 = new Uint8Array(1 + lookupName.length + unknownQuery.length);
  fwdPayload2[0] = lookupName.length;
  fwdPayload2.set(lookupName, 1);
  fwdPayload2.set(unknownQuery, 1 + lookupName.length);
  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, forwarderName, fwdPayload2));
  const respLen2 = host.callDynamicHandlerI32(forwarderName, "last_resp_len");
  const respPtr2 = host.callDynamicHandlerI32(forwarderName, "last_resp_ptr");
  const resp2 = host.readDynamicHandlerMemory(forwarderName, respPtr2, respLen2);
  assertEqual(resp2[0], 0, "unknown name returns [0]");

  console.log("  OK\n");
}

// ─── Test: installer.caps_of returns declared caps ───────────────────────

async function testInstallerCapsOf() {
  console.log("Test: installer.caps_of reflects declared capabilities");

  const { host, installName } = await makeHost();

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);
  const netCapId = host.deriveBootstrapName("cap.net");

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatTextName, [netCapId], null, forwarderBytes));
  assert(host.isRegistered(chatTextName), "install ok");

  const declared = host.getHandlerDeclaredCaps(chatTextName);
  assertEqual(declared.length, 1, "one declared cap");
  assertEqual(declared[0], netCapId, "declared cap is netCapId");

  // SetHandler-installed handlers have no record — caps_of returns [].
  const sigName = host.deriveBootstrapName("signature");
  assertEqual(host.getHandlerDeclaredCaps(sigName).length, 0,
    "bootstrap handler has no declared caps (§8.3)");

  console.log("  OK\n");
}

// ─── Test: installer.remove + suite slot removal ────────────────────────

async function testInstallerRemove() {
  console.log("Test: installer.remove clears record and kernel slot, replay still blocked");

  let approveCalls = 0;
  const { host, installName } = await makeHost((_n, _a, _h, _w, _c, _p, _e) => {
    approveCalls++;
    return true;
  });

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatTextName, [], null, forwarderBytes));
  assert(host.isRegistered(chatTextName), "install ok");
  assert(host.lookupInstall(chatTextName) !== null, "record present");

  assert(host.installer.remove(chatTextName), "remove returned true");
  assert(!host.isRegistered(chatTextName), "kernel slot cleared");
  assert(host.lookupInstall(chatTextName) === null, "record cleared");

  // remove() is idempotent — second call returns false.
  assert(!host.installer.remove(chatTextName), "second remove returns false");

  // Fresh install at higher seq succeeds.
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatTextName, [], null, forwarderBytes));
  assert(host.isRegistered(chatTextName), "reinstall after remove succeeds");
  assertEqual(approveCalls, 2, "approve called for each accepted install");

  console.log("  OK\n");
}

// ─── Test: caller stack format ──────────────────────────────────────────

async function testCallerStackFormat() {
  console.log("Test: kernel.caller / currentCaller / currentCallerStack (§4.2)");

  const { host, installName } = await makeHost();

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const forwarderName = host.deriveScopedName("test.forwarder", pk);

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    forwarderName, [], null, forwarderBytes));
  assert(host.isRegistered(forwarderName), "forwarder installed");

  // A probe handler reads the host-side caller stack each time it's called.
  const probeName = host.deriveBootstrapName("probe.caller");
  let seenImmediate = null;
  let seenStack = null;
  host.register(probeName, (_n, _payload, h) => {
    seenImmediate = h.currentCaller ? new Uint8Array(h.currentCaller) : null;
    seenStack = h.currentCallerStack.map((n) => new Uint8Array(n));
    return new Uint8Array([0xff]);
  });

  // forwarder → probe — stack should have exactly one entry (the forwarder).
  const payload = new Uint8Array(1 + probeName.length);
  payload[0] = probeName.length;
  payload.set(probeName, 1);
  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, forwarderName, payload));
  assert(seenImmediate !== null, "probe saw a caller");
  assertEqual(seenImmediate, forwarderName, "immediate caller is the forwarder");
  assertEqual(seenStack.length, 1, "caller stack has 1 entry");
  assertEqual(seenStack[0], forwarderName, "stack entry is the forwarder");

  // Top-level dispatch directly into the probe — no caller.
  seenImmediate = null;
  seenStack = null;
  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, probeName, new Uint8Array(0)));
  assert(seenImmediate === null, "no immediate caller for top-level dispatch");
  assertEqual(seenStack.length, 0, "caller stack is empty");

  console.log("  OK\n");
}

// ─── Test: Bridge cap check end-to-end ──────────────────────────────────

async function testBridgeCapabilityCheckEndToEnd() {
  console.log("Test: Bridge enforces caller capability check end-to-end (§8.2)");

  const { host, installName } = await makeHost();

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatNoCapName   = host.deriveScopedName("chat.nocap",   pk);
  const chatWithCapName = host.deriveScopedName("chat.withcap", pk);
  const netSendName     = host.deriveBootstrapName("cap.net.send");
  const netCapId        = host.deriveBootstrapName("cap.net");

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatNoCapName, [], null, forwarderBytes));
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatWithCapName, [netCapId], null, forwarderBytes));
  assert(host.isRegistered(chatNoCapName), "chat.nocap installed");
  assert(host.isRegistered(chatWithCapName), "chat.withcap installed");

  // The bridge: §8.2 preamble. Use the immediate caller (last entry of stack).
  let bridgeCalls = 0;
  host.register(netSendName, (_n, _p, h) => {
    bridgeCalls++;
    const callerName = h.currentCaller;
    if (!callerName) return null;
    const callerCaps = h.getHandlerDeclaredCaps(callerName);
    const hasNet = callerCaps.some(
      (cap) => cap.length === netCapId.length && cap.every((b, i) => b === netCapId[i])
    );
    if (!hasNet) return null;
    return new Uint8Array([1]);
  });

  const forwardData = new TextEncoder().encode("ping");
  function makeForward(targetName) {
    const out = new Uint8Array(1 + targetName.length + forwardData.length);
    out[0] = targetName.length;
    out.set(targetName, 1);
    out.set(forwardData, 1 + targetName.length);
    return out;
  }

  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, chatNoCapName, makeForward(netSendName)));
  assertEqual(bridgeCalls, 1, "bridge invoked for no-cap caller");
  assertEqual(host.callDynamicHandlerI32(chatNoCapName, "last_resp_len"), 0,
    "no-cap caller: bridge rejected (no response)");

  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, chatWithCapName, makeForward(netSendName)));
  assertEqual(bridgeCalls, 2, "bridge invoked for with-cap caller");
  assertEqual(host.callDynamicHandlerI32(chatWithCapName, "last_resp_len"), 1,
    "with-cap caller: bridge returned 1 byte");

  console.log("  OK\n");
}

// ─── Test: blockFromCall on deployer-added mutating handler ──────────────

async function testBlockFromCall() {
  console.log("Test: blockFromCall makes a deployer handler unreachable via kernel.call (§4.4)");

  const { host, installName } = await makeHost();

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const mutateName = host.deriveBootstrapName("test.mutate");
  let mutateCalls = 0;
  const id = host.register(mutateName, () => {
    mutateCalls++;
    return new Uint8Array([0x42]);
  });
  host.blockFromCall(id);

  // Top-level dispatch must still reach the handler.
  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, mutateName, new Uint8Array(0)));
  assertEqual(mutateCalls, 1, "direct dispatch still reaches blocked handler");

  // Install a forwarder, have it kernel.call the blocked handler. Must drop.
  const seq = makeSeq();
  const fwdName = host.deriveScopedName("test.forwarder", pk);
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    fwdName, [], null, forwarderBytes));
  assert(host.isRegistered(fwdName), "forwarder installed");

  const fwdPayload = new Uint8Array(1 + mutateName.length);
  fwdPayload[0] = mutateName.length;
  fwdPayload.set(mutateName, 1);
  host.dispatch(host.wrapAndEncode(sk, pk, CURRENT_VERSION, fwdName, fwdPayload));
  assertEqual(mutateCalls, 1, "kernel.call to blocked handler did NOT invoke it");
  assertEqual(host.callDynamicHandlerI32(fwdName, "last_resp_len"), 0,
    "kernel.call to blocked handler returned -1 (no response stored)");

  console.log("  OK\n");
}

// ─── Test: wrap rejects invalid Ed25519 key sizes ───────────────────────

async function testWrapRejectsInvalidKeySizes() {
  console.log("Test: wrap() rejects invalid Ed25519 key sizes");

  const host = await loadKernelHost(kernelWasm, bootstrapWasm);
  host.registerSignature(host.deriveBootstrapName("signature"));

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const inner = host.encodeEnvelope(CURRENT_VERSION,
    host.deriveBootstrapName("chat.text"),
    new TextEncoder().encode("ok"));

  let threw = false;
  try { host.wrap(sk.slice(0, 32), pk, inner); } catch { threw = true; }
  assert(threw, "wrap rejected 32-byte privateKey");

  threw = false;
  try { host.wrap(sk, pk.slice(0, 16), inner); } catch { threw = true; }
  assert(threw, "wrap rejected 16-byte publicKey");

  const wire = host.wrap(sk, pk, inner);
  assert(wire.length > inner.length, "wrap with valid sizes succeeds");

  console.log("  OK\n");
}

// ─── Perf: 10k dispatch vs. plain Ed25519 verify ────────────────────────

async function testPerf10k() {
  console.log("Perf: 10k signed-envelope dispatch vs. plain Ed25519 verify");

  const { host } = await makeHost();
  const chatTextName = host.deriveBootstrapName("chat.text");

  const { publicKey: pk, privateKey: sk } = generateKeyPair();

  let handlerCalls = 0;
  host.register(chatTextName, () => { handlerCalls++; });

  const N = 10_000;
  const wireMessages = new Array(N);
  const signatures   = new Array(N);
  const payloads     = new Array(N);

  for (let i = 0; i < N; i++) {
    const payload = new TextEncoder().encode(`message #${i}: hello world benchmark payload data`);
    wireMessages[i] = host.wrapAndEncode(sk, pk, CURRENT_VERSION, chatTextName, payload);
    payloads[i]     = payload;
    signatures[i]   = sodium.crypto_sign_detached(payload, sk);
  }

  for (let i = 0; i < 2000; i++) host.dispatch(wireMessages[i % N]);
  for (let i = 0; i < 2000; i++) sodium.crypto_sign_verify_detached(signatures[i % N], payloads[i % N], pk);
  handlerCalls = 0;

  const t0 = performance.now();
  for (let i = 0; i < N; i++) host.dispatch(wireMessages[i]);
  const kernelMs = performance.now() - t0;
  const kernelVerified = handlerCalls;

  const t1 = performance.now();
  for (let i = 0; i < N; i++) sodium.crypto_sign_verify_detached(signatures[i], payloads[i], pk);
  const plainMs = performance.now() - t1;

  const ratio = kernelMs / plainMs;
  console.log(`  kernel pipeline  ${N.toLocaleString()} msgs: ${kernelMs.toFixed(0).padStart(6)} ms  (${(kernelMs / N * 1000).toFixed(1)} µs/msg)`);
  console.log(`  plain Ed25519    ${N.toLocaleString()} msgs: ${plainMs.toFixed(0).padStart(6)} ms  (${(plainMs / N * 1000).toFixed(1)} µs/msg)`);
  console.log(`  overhead ratio: ${ratio.toFixed(2)}x`);

  assertEqual(kernelVerified, N, `all ${N} messages reached handler`);
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
      const bytes = new Uint8Array([1, 2, 3, 4, 5]);
      assert(!fs.has("a.blk"), `${name}: absent before put`);
      assertEqual(fs.size("a.blk"), -1, `${name}: size -1 when absent`);
      assertEqual(fs.get("a.blk"), null, `${name}: get null when absent`);

      fs.put("a.blk", bytes);
      assert(fs.has("a.blk"), `${name}: present after put`);
      assertEqual(fs.size("a.blk"), 5, `${name}: size reflects bytes`);
      assert(bytesEqual(fs.get("a.blk"), bytes), `${name}: get round-trips`);

      fs.put("a.dsc", new Uint8Array([9]));
      fs.put("b.blk", new Uint8Array([7, 7]));
      assertEqual(fs.list().sort().join(","), "a.blk,a.dsc,b.blk", `${name}: list sees all keys`);
      assertEqual(fs.list("a.").sort().join(","), "a.blk,a.dsc", `${name}: list filters by prefix`);
      assertEqual(fs.stat().used, 5 + 1 + 2, `${name}: stat.used sums all values`);
      assert(fs.stat().available > 0, `${name}: stat.available is positive`);

      assert(fs.delete("a.blk"), `${name}: delete reports removal`);
      assert(!fs.has("a.blk"), `${name}: absent after delete`);
      assert(!fs.delete("a.blk"), `${name}: second delete is false`);
    } finally {
      cleanup();
    }
  }

  // The node backend must refuse keys that could escape its directory.
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-fs-"));
  try {
    const fs = new NodeFs(dir);
    let threw = false;
    try { fs.put("../escape", new Uint8Array([0])); } catch { threw = true; }
    assert(threw, "NodeFs rejects a path-traversal key on put");
    assertEqual(fs.get("../escape"), null, "NodeFs reads an unsafe key as absent");
    threw = false;
    try { fs.put("..", new Uint8Array([0])); } catch { threw = true; }
    assert(threw, "NodeFs rejects the bare '..' key");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  console.log("  OK\n");
}

// ─── Test: Transport.requestMany scatter-gather (step 7) ────────────────

async function testRequestMany() {
  console.log("Test: Transport.requestMany — scatter-gather with partial results (step 7)");

  const a = generateKeyPair(), b = generateKeyPair();
  const net = new LoopbackNetwork();
  const ta = new Transport(toHex(a.publicKey), net, 40);
  const tb = new Transport(toHex(b.publicKey), net, 40);
  tb.onRequest((_from, type, payload) => new Uint8Array([type, ...payload]));

  try {
    const dead = toHex(generateKeyPair().publicKey); // never registered → unreachable
    const results = await ta.requestMany([toHex(b.publicKey), dead], 7, new Uint8Array([3, 4]));
    assertEqual(results.length, 2, "one result per input peer, order preserved");
    assert(results[0].ok, "the live peer answered ok");
    assert(bytesEqual(results[0].bytes, new Uint8Array([7, 3, 4])), "the live peer echoed type+payload");
    assert(!results[1].ok, "the unreachable peer comes back ok:false (partial, not a reject)");
    assertEqual(results[1].bytes.length, 0, "the unreachable peer carries no bytes");
  } finally {
    ta.close(); tb.close();
  }

  console.log("  OK\n");
}

// ─── Test: cap-bridge generic primitives (step 7) ───────────────────────
//
// The capability counterpart to safe-js: a guest reaches only application-neutral
// primitives (crypto / net / fs / module-call / clock / identity) — never any
// storage vocabulary. seedstore's whole orchestration runs over exactly these.

async function testCapBridge() {
  console.log("Test: cap-bridge — generic primitive capabilities, no app vocabulary (step 7)");

  const id = generateKeyPair();
  const fs = new MemoryFs();
  const net = new LoopbackNetwork();
  const transport = new Transport(toHex(id.publicKey), net, 40);

  // A host handler reachable by name, to exercise CAP_MODULE_CALL.
  const { host } = await makeHost();
  const echoName = host.deriveBootstrapName("test.echo");
  host.register(echoName, (_n, p) => new Uint8Array([p.length, ...p]));

  const bridge = createCapBridge({
    sodium, identity: id,
    callHandler: (name, p) => host.callHandler(name, p),
    transport, peers: () => [toHex(id.publicKey)], fs,
  });
  const U = (...xs) => new Uint8Array(xs);

  try {
    // crypto primitives match sumo directly (the guest does all framing)
    const msg = U(1, 2, 3, 4, 5);
    assert(bytesEqual(await bridge(CAP.HASH, msg), sodium.crypto_generichash(32, msg)), "CAP_HASH = blake2b");
    const key = sodium.randombytes_buf(32), nonce = sodium.randombytes_buf(24);
    assert(bytesEqual(await bridge(CAP.STREAM_XOR, concatBytes([nonce, key, msg])),
      sodium.crypto_stream_xchacha20_xor(msg, nonce, key)), "CAP_STREAM_XOR = xchacha20 keystream");
    const sig = await bridge(CAP.SIGN, msg);
    assert(sodium.crypto_sign_verify_detached(sig, msg, id.publicKey), "CAP_SIGN signs as the node identity");
    assertEqual((await bridge(CAP.VERIFY, concatBytes([id.publicKey, sig, msg])))[0], 1, "CAP_VERIFY accepts a good sig");
    assertEqual((await bridge(CAP.VERIFY, concatBytes([id.publicKey, sig, U(9, 9)])))[0], 0, "CAP_VERIFY rejects a forged message");
    assert(bytesEqual(await bridge(CAP.IDENTITY, U()), id.publicKey), "CAP_IDENTITY = the node pubkey");
    assertEqual((await bridge(CAP.RANDOM, U(0, 0, 0, 16))).length, 16, "CAP_RANDOM returns n bytes");
    assertEqual((await bridge(CAP.CLOCK, U())).length, 8, "CAP_CLOCK returns a u64");

    // fs.* over the raw backend
    const fk = new TextEncoder().encode("dead.blk"), fv = U(7, 7, 7);
    await bridge(CAP.FS_PUT, concatBytes([U(0, 0, 0, fk.length), fk, fv]));
    const got = await bridge(CAP.FS_GET, fk);
    assert(got[0] === 1 && bytesEqual(got.slice(1), fv), "CAP_FS_PUT/GET round-trips under an opaque key");
    assertEqual((await bridge(CAP.FS_HAS, fk))[0], 1, "CAP_FS_HAS true after put");
    assertEqual((await bridge(CAP.FS_GET, new TextEncoder().encode("missing")))[0], 0, "CAP_FS_GET of an absent key → [0]");
    const szPresent = await bridge(CAP.FS_SIZE, fk);
    assertEqual(new DataView(szPresent.buffer, szPresent.byteOffset).getUint32(0, false), fv.length, "CAP_FS_SIZE returns the value's byte length");
    const szAbsent = await bridge(CAP.FS_SIZE, new TextEncoder().encode("missing"));
    assertEqual(new DataView(szAbsent.buffer, szAbsent.byteOffset).getUint32(0, false), 0xffffffff, "CAP_FS_SIZE of an absent key → -1 (0xFFFFFFFF)");

    // Sync vs async: every op resolves synchronously (returns bytes, not a
    // Promise) except the net ops, which round-trip — this is exactly what lets a
    // SYNC realm host the holder side while the async realm awaits net.
    assert(!(bridge(CAP.HASH, msg) instanceof Promise), "CAP_HASH resolves synchronously (bytes, no Promise)");
    assert(!(bridge(CAP.FS_HAS, fk) instanceof Promise), "CAP_FS_HAS resolves synchronously");
    assert(bridge(CAP.NET_PEERS, U()) instanceof Uint8Array, "CAP_NET_PEERS is synchronous");
    const sendResult = bridge(CAP.NET_SEND, concatBytes([id.publicKey, U(7)]));
    assert(sendResult instanceof Promise, "CAP_NET_SEND returns a Promise (a real round trip)");
    await sendResult.catch(() => {}); // drain (no live peer) so it doesn't dangle

    // net.peers
    const peers = await bridge(CAP.NET_PEERS, U());
    assertEqual(new DataView(peers.buffer, peers.byteOffset).getUint32(0, false), 1, "CAP_NET_PEERS counts the cohort");

    // module-call reaches an installed handler by name
    const mc = new Uint8Array(1 + echoName.length + 2);
    mc[0] = echoName.length; mc.set(echoName, 1); mc.set(U(8, 9), 1 + echoName.length);
    assertEqual([...await bridge(CAP.MODULE_CALL, mc)], [2, 8, 9], "CAP_MODULE_CALL invokes the named handler");
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

// ─── Test: channel identity pinning (transport §16) ─────────────────────

async function testChannelPinning() {
  console.log("Test: a connection is pinned to the peer's key — wrong key → no delivery");

  const idS = generateKeyPair(), idB = generateKeyPair();
  const netS = new NodeNetwork({ identity: idS, sodium, listen: { host: "127.0.0.1", port: 0 } });
  await netS.start();
  let received = 0;
  netS.register(toHex(idS.publicKey), () => { received++; });

  const netB = new NodeNetwork({ identity: idB, sodium }); // dials out only
  netB.register(toHex(idB.publicKey), () => {});

  try {
    // Point a made-up peerId at S's real address. S presents its true key, which
    // won't match what B was told to expect → the link must refuse to auth.
    const wrongId = toHex(sodium.randombytes_buf(32));
    netB.addPeerAddr(wrongId, { host: "127.0.0.1", port: netS.port, transport: "tcp" });
    netB.send(toHex(idB.publicKey), wrongId, new Uint8Array([1, 2, 3]));
    await sleep(200);
    assertEqual(received, 0, "frame to a mismatched identity is never delivered");

    // Now address S by its true id: the handshake succeeds and the frame arrives.
    netB.addPeerAddr(toHex(idS.publicKey), { host: "127.0.0.1", port: netS.port, transport: "tcp" });
    netB.send(toHex(idB.publicKey), toHex(idS.publicKey), new Uint8Array([4, 5, 6]));
    await sleep(200);
    assertEqual(received, 1, "frame to the correct identity is delivered");
  } finally {
    netS.close(); netB.close();
  }

  console.log("  OK\n");
}

// ─── Test: shell install policy + boot (step 5) ─────────────────────────

async function testPolicy() {
  console.log("Test: shell install policy — closed author set + module-hash allowlist");
  const { parsePolicy, buildApproveInstall } = await imp("build/host/policy.js");

  const good = generateKeyPair();
  const bad = generateKeyPair();

  // Install the forwarder under a freshly-policied host; returns whether it landed
  // and the bytesHash the installer recorded (for the module-allowlist subtest).
  const tryInstall = async (policyJson, author) => {
    const { host, installName } = await makeHost();
    host.setApproveInstall(buildApproveInstall(host, parsePolicy(policyJson)));
    const seq = makeSeq();
    const name = host.deriveScopedName("mod", author.publicKey);
    host.dispatch(buildInstall(host, author.privateKey, author.publicKey, installName, seq(author.publicKey), name, [], null, forwarderBytes));
    const rec = host.lookupInstall(name);
    return { landed: host.isRegistered(name), bytesHash: rec ? toHex(rec.bytesHash) : null };
  };

  // ── author allowlist ───────────────────────────────────────────────────
  const okAuthor = await tryInstall(JSON.stringify({ authors: [toHex(good.publicKey)] }), good);
  assert(okAuthor.landed, "install by an allowed author is accepted");
  const moduleHash = okAuthor.bytesHash;

  const badAuthor = await tryInstall(JSON.stringify({ authors: [toHex(good.publicKey)] }), bad);
  assert(!badAuthor.landed, "install by an author not on the allowlist is rejected");

  // ── module-hash allowlist ──────────────────────────────────────────────
  const okModule = await tryInstall(JSON.stringify({ authors: [toHex(good.publicKey)], modules: [moduleHash] }), good);
  assert(okModule.landed, "an allowlisted module hash is accepted");

  const wrongHash = "00".repeat(moduleHash.length / 2);
  const badModule = await tryInstall(JSON.stringify({ authors: [toHex(good.publicKey)], modules: [wrongHash] }), good);
  assert(!badModule.landed, "a module hash not on the allowlist is rejected");

  // ── parse validation ───────────────────────────────────────────────────
  let threw = false;
  try { parsePolicy("{ not json"); } catch { threw = true; }
  assert(threw, "malformed policy JSON throws (fails the boot loudly)");
  threw = false;
  try { parsePolicy(JSON.stringify({ authors: [] })); } catch { threw = true; }
  assert(threw, "an empty author set is rejected");

  console.log("  OK\n");
}

async function testShellBoot() {
  console.log("Test: seedkernel-shell boots under a policy and accepts an allowed install");
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
      kernelBytes: new Uint8Array(readFileSync(kernelWasm)),
      bootstrapBytes: new Uint8Array(readFileSync(bootstrapWasm)),
      policyJson: JSON.stringify({ authors: [toHex(author.publicKey)] }),
      dir,
      identity, // dial-only: no listen/wsListen, so start() binds nothing
    });
    assert(shell.fs.list().length === 0, "fs.* backend is wired over the data dir");

    const seq = makeSeq();
    const installName = shell.host.deriveBootstrapName("install");
    const name = shell.host.deriveScopedName("mod", author.publicKey);
    shell.installFromEnvelope(buildInstall(
      shell.host, author.privateKey, author.publicKey, installName, seq(author.publicKey), name, [], null, forwarderBytes,
    ));
    assert(shell.host.isRegistered(name), "an allowed signed install lands on the booted shell");
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
  }
  console.log("  OK\n");
}

// ─── Test: app bundle — signed manifest + governed load (step 6) ────────

async function testBundle() {
  console.log("Test: app bundle — signed manifest, integrity, governed load by the shell");
  const { signManifest, verifyManifest } = await imp("build/host/bundle.js");
  const { boot } = await imp("build/host/main.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = generateKeyPair();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-bundle-"));
  let shell, shell2;
  try {
    // Build a minimal one-module bundle (forwarder.wasm) + a guest stub, using a
    // throwaway host to derive the name, encode the install, and hash content.
    const { host: h } = await makeHost();
    const seq = makeSeq();
    const kernelName = h.deriveScopedName("codec", author.publicKey);
    const install = buildInstall(
      h, author.privateKey, author.publicKey, h.deriveBootstrapName("install"),
      seq(author.publicKey), kernelName, [], null, forwarderBytes,
    );
    const guestText = "register('ping', () => new Uint8Array([1]));";
    const manifest = {
      app: "test", version: "1",
      modules: [{
        name: "codec", file: "codec.wasm", hash: toHex(h.genesisHash(forwarderBytes)),
        install: "codec.install", kernelName: toHex(kernelName),
      }],
      guest: { file: "guest.js", hash: toHex(h.genesisHash(new TextEncoder().encode(guestText))) },
      ops: { PING: 1 }, caps: [],
    };
    wf(pjoin(dir, "codec.wasm"), forwarderBytes);
    wf(pjoin(dir, "codec.install"), install);
    wf(pjoin(dir, "guest.js"), guestText);
    wf(pjoin(dir, "manifest.bundle"), signManifest(sodium, author.privateKey, author.publicKey, manifest));

    // sign / verify / tamper
    const env = signManifest(sodium, author.privateKey, author.publicKey, manifest);
    assert(verifyManifest(sodium, env) !== null, "a well-formed manifest verifies");
    const tampered = env.slice(); tampered[tampered.length - 1] ^= 1;
    assert(verifyManifest(sodium, tampered) === null, "a tampered manifest fails verification");

    // booted shell, policy allows the author → bundle loads + module installs
    shell = await boot({
      kernelBytes: new Uint8Array(readFileSync(kernelWasm)),
      bootstrapBytes: new Uint8Array(readFileSync(bootstrapWasm)),
      policyJson: JSON.stringify({ authors: [toHex(author.publicKey)] }),
      dir: pjoin(dir, "_data"), identity,
    });
    const loaded = shell.loadBundle(dir);
    assertEqual(loaded.installed.join(","), "codec", "the bundle's module installed onto the kernel");
    assert(shell.host.isRegistered(kernelName), "module registered under its kernel name");
    assert(loaded.guestSource.includes("register('ping'"), "guest source loaded + integrity-checked");

    // a shell whose policy does NOT allow the author refuses the bundle
    shell2 = await boot({
      kernelBytes: new Uint8Array(readFileSync(kernelWasm)),
      bootstrapBytes: new Uint8Array(readFileSync(bootstrapWasm)),
      policyJson: JSON.stringify({ authors: [toHex(generateKeyPair().publicKey)] }),
      dir: pjoin(dir, "_data2"), identity,
    });
    let refused = false;
    try { shell2.loadBundle(dir); } catch { refused = true; }
    assert(refused, "a bundle from a non-allowed author is refused");
  } finally {
    if (shell) shell.close();
    if (shell2) shell2.close();
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

  // 2. The async seam: a guest reaches a host bridge and bytes round-trip across
  //    the copy boundary; Asyncify makes the host's async round trip look sync.
  {
    let bridgeCalls = 0;
    const bridge = async (op, payload) => {
      bridgeCalls++;
      if (op === 1) { await sleep(3); return payload.map((b) => (b + 1) & 0xff); }
      return new Uint8Array();
    };
    const src = `
      register("echo", (arg) => host.call(1, arg));               // sync entrypoint, blocks via Asyncify
      register("echoAsync", async (arg) => { return await host.call(1, arg); });
    `;
    const realm = await createSafeRealm({ source: src, bridge });
    const input = new Uint8Array([0, 1, 2, 254, 255]);
    const sync = await realm.call("echo", input);
    assertEqual([...sync], [1, 2, 3, 255, 0], "sync entrypoint: bytes crossed in, awaited, crossed back");
    const asyncR = await realm.call("echoAsync", input);
    assertEqual([...asyncR], [1, 2, 3, 255, 0], "async entrypoint: await host.call resolves through Asyncify");
    assert(bridgeCalls === 2, "the host bridge was invoked for each call");
    const again = await realm.call("echo", new Uint8Array([10]));
    assertEqual([...again], [11], "realm is reusable across calls");
    realm.dispose();
  }

  // 3. Orchestration control-flow shapes run as guest JS (synchronous model over
  //    the blocking bridge — the load-bearing Tier-2 finding).
  {
    const bridge = async (op, payload) => {
      const peer = payload[0];
      if (op === 2) { await sleep(1); return new Uint8Array([peer % 2 === 0 ? 1 : 0]); } // offer
      if (op === 3) { await sleep(1); return new Uint8Array([peer % 3 === 0 ? 1 : 0]); } // have
      return new Uint8Array();
    };
    const src = `
      register("orchestrate", (arg) => {
        const count = arg[0], peerCount = arg[1];
        const used = new Set();
        const placed = [];
        for (let p = 0; p < peerCount && placed.length < count; p++) {
          if (used.has(p)) continue;
          const accepted = host.call(2, new Uint8Array([p]));    // blocks via Asyncify
          if (accepted[0] === 1) { placed.push(p); used.add(p); }
        }
        const holders = new Map();
        for (let p = 0; p < peerCount; p++) {
          const r = host.call(3, new Uint8Array([p]));
          if (r[0] === 1) holders.set(p, true);
        }
        return new Uint8Array([placed.length, holders.size, ...placed]);
      });
    `;
    const realm = await createSafeRealm({ source: src, bridge });
    const res = await realm.call("orchestrate", new Uint8Array([3, 10]));
    assertEqual(res[0], 3, "loop placed exactly `count` blocks on distinct peers");
    assertEqual([...res.slice(2)], [0, 2, 4], "placement followed peer order and the accept rule");
    assertEqual(res[1], 4, "sequential have/want fan-out (blocking host calls) collected the right holders");
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

// ─── Test: synchronous safe-js realm (the holder side, step 8) ──────────
//
// The non-Asyncify realm: host.call resolves synchronously and an entrypoint
// runs straight through to its bytes without yielding the event loop. This is
// what lets a confined request handler (storage's holder side) respond while an
// async orchestration realm — a *different* WASM instance — is parked mid-await.

async function testSyncSafeRealm() {
  console.log("Test: sync safe-js — synchronous confinement for the request side (step 8)");

  // 1. A synchronous bridge round-trips, and the realm is reusable. call()
  //    returns bytes directly (no Promise) — no event-loop turn in between.
  {
    let calls = 0;
    const bridge = (op, payload) => { calls++; return op === 1 ? payload.map((b) => (b + 1) & 0xff) : new Uint8Array(); };
    const realm = await createSyncSafeRealm({
      source: `register("inc", (arg) => host.call(1, arg));`,
      bridge,
    });
    const out = realm.call("inc", new Uint8Array([0, 9, 255]));
    assert(out instanceof Uint8Array && !(out instanceof Promise), "sync call returns bytes directly, not a Promise");
    assertEqual([...out], [1, 10, 0], "sync host.call round-trips through the copy boundary");
    assertEqual([...realm.call("inc", new Uint8Array([41]))], [42], "sync realm is reusable across calls");
    assertEqual(calls, 2, "the synchronous bridge was invoked once per call");
    realm.dispose();
  }

  // 2. An async bridge (a Promise return — e.g. a net op) is a hard error in a
  //    sync realm: it cannot suspend to await one. The guard keeps the two seams
  //    honest — net stays in the async realm.
  {
    const realm = await createSyncSafeRealm({
      source: `register("net", () => host.call(7, new Uint8Array()));`,
      bridge: () => Promise.resolve(new Uint8Array([1])),
    });
    let threw = false;
    try { realm.call("net", new Uint8Array()); } catch { threw = true; }
    assert(threw, "a Promise-returning (async) op throws in a sync realm");
    realm.dispose();
  }

  // 3. Still airtight — a sync realm is the same zero-authority sandbox.
  {
    const realm = await createSyncSafeRealm({
      source: `register("probe", () => new Uint8Array([typeof globalThis.process === "undefined" ? 0 : 1, typeof globalThis.fetch === "undefined" ? 0 : 1]));`,
      bridge: () => new Uint8Array(),
    });
    const r = realm.call("probe", new Uint8Array());
    assertEqual([...r], [0, 0], "process / fetch are unreachable in the sync realm too");
    realm.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: PR-review hardening — cap enforcement, guarded callHandler, ───
// ─── sender-bound responses, WS fragmentation, redial after failure ──────

async function testCapBridgeEnforcement() {
  console.log("Test: cap-bridge enforces the manifest's declared op set + allocation caps");

  const id = generateKeyPair();
  const stubTransport = { request: async () => new Uint8Array(), requestMany: async () => [] };
  const mk = (allowedOps) => createCapBridge({
    sodium, identity: id, callHandler: () => null,
    transport: stubTransport, peers: () => [], fs: new MemoryFs(), allowedOps,
  });
  const U = (...xs) => new Uint8Array(xs);

  // declared-op filtering: only ops in the manifest catalog resolve
  const restricted = mk([CAP.HASH]);
  assertEqual((await restricted(CAP.HASH, U(1, 2))).length, 32, "a declared op (HASH) works");
  let threw = false;
  try { await restricted(CAP.SIGN, U(1)); } catch { threw = true; }
  assert(threw, "an undeclared op (SIGN) is refused by the bridge");
  threw = false;
  try { await restricted(CAP.FS_DELETE, U(120)); } catch { threw = true; }
  assert(threw, "an undeclared op (FS_DELETE) is refused by the bridge");

  // guest-controlled allocation caps (no allowedOps → unrestricted host caller)
  const open = mk(undefined);
  assertEqual((await open(CAP.RANDOM, U(0, 0, 4, 0))).length, 1024, "RANDOM under the cap works");
  threw = false;
  try { await open(CAP.RANDOM, U(0xff, 0xff, 0xff, 0xff)); } catch { threw = true; }
  assert(threw, "RANDOM over the cap is refused");
  threw = false;
  try { await open(CAP.NET_REQUEST_MANY, U(7, 0xff, 0xff, 0xff, 0xff)); } catch { threw = true; }
  assert(threw, "NET_REQUEST_MANY with a count not backed by payload bytes is refused");

  // caps → ops: a bundle declares capability DOMAINS, the shell expands them to the
  // op set the bridge enforces (the "wire the caps" path). A guest that declared
  // only "crypto" hashes fine but cannot touch fs, and a typo'd domain fails loudly.
  const cryptoOnly = mk(opsForCaps(["crypto"]));
  assertEqual((await cryptoOnly(CAP.HASH, U(1, 2))).length, 32, "a declared domain (crypto) grants its ops");
  threw = false;
  try { await cryptoOnly(CAP.FS_HAS, U(120)); } catch { threw = true; }
  assert(threw, "an op outside the declared domains (fs) is refused");
  threw = false;
  try { opsForCaps(["crypto", "nope"]); } catch { threw = true; }
  assert(threw, "an unknown capability domain throws (a manifest typo fails loudly)");

  console.log("  OK\n");
}

async function testCallHandlerGuards() {
  console.log("Test: KernelHost.callHandler applies the call-router guards (§4.4)");

  const { host, installName } = await makeHost();
  // The installer is blockedFromCall — kernel.call refuses it, so the host-side
  // by-name path must too (a confined guest reaches this via CAP_MODULE_CALL).
  assert(host.callHandler(installName, new Uint8Array([1])) === null,
    "callHandler refuses a blocked handler (installer)");
  const sigName = host.deriveBootstrapName("signature");
  assert(host.callHandler(sigName, new Uint8Array([1])) === null,
    "callHandler refuses the signature wrapper");

  // A normal handler still works, and sees an *empty* immediate caller — not a
  // stale frame from some outer dispatch (the §8.2 confused-deputy check).
  let sawCaller = "unset";
  const echoName = host.deriveBootstrapName("test.echo2");
  host.register(echoName, (_n, p, h) => { sawCaller = h.currentCaller; return p; });
  const r = host.callHandler(echoName, new Uint8Array([5]));
  assertEqual([...r], [5], "callHandler still reaches a normal handler");
  assert(sawCaller === null, "the target sees no installed caller (anonymous frame)");

  console.log("  OK\n");
}

async function testTransportResponseBinding() {
  console.log("Test: a transport response only resolves from the peer it was sent to");

  const a = generateKeyPair(), b = generateKeyPair(), c = generateKeyPair();
  const A = toHex(a.publicKey), B = toHex(b.publicKey), C = toHex(c.publicKey);
  const net = new LoopbackNetwork();
  const ta = new Transport(A, net, 200);
  const tb = new Transport(B, net, 200);
  const tc = new Transport(C, net, 200);
  tb.onRequest(() => new Uint8Array([42]));

  try {
    const reqP = ta.request(B, 7, new Uint8Array());
    // C (an authenticated cohort member in real life) races a spoofed response
    // with the predictable first correlation id. It must be ignored.
    net.send(C, A, Uint8Array.from([1, 0, 0, 0, 1, 7, 99]));
    const resp = await reqP;
    assertEqual([...resp], [42], "the real peer's response resolves, not the spoof");
  } finally {
    ta.close(); tb.close(); tc.close();
  }

  console.log("  OK\n");
}

async function testWsFragmentation() {
  console.log("Test: WS fragmented messages reassemble (FIN=0 + continuation frames)");

  const mask = new Uint8Array([9, 8, 7, 6]);
  const p1 = new Uint8Array([1, 2, 3]), p2 = new Uint8Array([4, 5]), p3 = new Uint8Array([6]);
  // encodeFrame always emits FIN=1; craft fragments by clearing the FIN bit.
  const first = encodeFrame(WS_OPCODES.OP_BINARY, p1, mask); first[0] &= 0x7f;
  const middle = encodeFrame(0x0, p2, mask); middle[0] &= 0x7f; // continuation, FIN=0
  const ping = encodeFrame(WS_OPCODES.OP_PING, new Uint8Array([0xaa]), mask); // may interleave (§5.4)
  const last = encodeFrame(0x0, p3, mask); // continuation, FIN=1

  const parser = new WsParser(true);
  const frames = [
    ...parser.push(first), ...parser.push(middle),
    ...parser.push(ping), ...parser.push(last),
  ];
  assertEqual(frames.length, 2, "the ping + one reassembled message");
  assertEqual(frames[0].opcode, WS_OPCODES.OP_PING, "interleaved control frame passes through");
  assertEqual(frames[1].opcode, WS_OPCODES.OP_BINARY, "reassembled message keeps the first opcode");
  assertEqual([...frames[1].payload], [1, 2, 3, 4, 5, 6], "fragment payloads concatenate in order");

  // A continuation with nothing in flight is a protocol error → channel teardown.
  const parser2 = new WsParser(true);
  let threw = false;
  try { parser2.push(encodeFrame(0x0, p2, mask)); } catch { threw = true; }
  assert(threw, "an orphan continuation frame is a protocol error");

  // A fragmented control frame is a protocol error (RFC 6455 §5.5).
  const parser3 = new WsParser(true);
  const badPing = encodeFrame(WS_OPCODES.OP_PING, new Uint8Array([1]), mask); badPing[0] &= 0x7f;
  threw = false;
  try { parser3.push(badPing); } catch { threw = true; }
  assert(threw, "a fragmented control frame is a protocol error");

  console.log("  OK\n");
}

async function testRedialAfterFailedDial() {
  console.log("Test: a failed dial is forgotten — the peer is reachable once it comes back");

  const idS = generateKeyPair(), idB = generateKeyPair();
  // Reserve a port, then free it so the first dial hits ECONNREFUSED.
  const probe = new NodeNetwork({ identity: idS, sodium, listen: { host: "127.0.0.1", port: 0 } });
  await probe.start();
  const port = probe.port;
  probe.close();
  await sleep(50);

  const netB = new NodeNetwork({ identity: idB, sodium });
  netB.register(toHex(idB.publicKey), () => {});
  let netS = null;
  try {
    netB.addPeerAddr(toHex(idS.publicKey), { host: "127.0.0.1", port, transport: "tcp" });
    netB.send(toHex(idB.publicKey), toHex(idS.publicKey), new Uint8Array([1]));
    await sleep(200); // the dial fails; the stale connecting entry must be cleaned up

    netS = new NodeNetwork({ identity: idS, sodium, listen: { host: "127.0.0.1", port } });
    await netS.start();
    let received = 0;
    netS.register(toHex(idS.publicKey), () => { received++; });
    netB.send(toHex(idB.publicKey), toHex(idS.publicKey), new Uint8Array([2]));
    await sleep(300);
    assertEqual(received, 1, "send() redials after the peer comes back (no permanent blackhole)");
  } finally {
    if (netS) netS.close();
    netB.close();
  }

  console.log("  OK\n");
}

async function testSafeRealmSerialization() {
  console.log("Test: concurrent call()s on one safe-js realm serialize (no __arg clobber)");

  const realm = await createSafeRealm({
    source: `register("echo", (a) => host.call(1, a));`,
    bridge: async (_op, p) => { await sleep(10); return p; },
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

// ─── Test: RtcChannel drives PeerLink over a data channel (net-rtc) ──────
//
// WebRTC as a first-class Network: an RTCDataChannel is wrapped as a RawChannel
// and the unchanged PeerLink runs its identity handshake over it. We exercise the
// genuinely new code — RtcChannel, including its pre-open send buffering — with a
// fake whole-message channel pair (no real ICE), driving a full mutual handshake
// and a post-auth frame. RtcNetwork's signaling/perfect-negotiation needs a real
// RTCPeerConnection (browser or node-datachannel) and is exercised there.

async function testRtcNetwork() {
  console.log("Test: net-rtc — RtcChannel + PeerLink handshake over a (fake) data channel");
  const { RtcChannel } = await imp("build/host/net-rtc.js");
  const { PeerLink } = await imp("build/host/net-link.js");

  // A minimal RTCDataChannel stand-in: an ordered whole-message binary pipe with
  // controllable open timing, wired to its twin. Delivery is async (a microtask)
  // to mirror a real channel; send() ships an ArrayBuffer, as binaryType
  // "arraybuffer" does on the wire.
  function fakeChannelPair() {
    const mk = () => ({
      binaryType: "blob",
      readyState: "connecting",
      _l: { message: [], open: [], close: [], error: [] },
      _twin: null,
      addEventListener(t, cb) { (this._l[t] ??= []).push(cb); },
      send(bytes) {
        const buf = bytes.slice().buffer; // copy → fresh ArrayBuffer, like the wire
        const twin = this._twin;
        queueMicrotask(() => { for (const cb of twin._l.message) cb({ data: buf }); });
      },
      close() { this.readyState = "closed"; for (const cb of this._l.close) cb(); },
      _open() { this.readyState = "open"; for (const cb of this._l.open) cb(); },
    });
    const a = mk(), b = mk();
    a._twin = b; b._twin = a;
    return [a, b];
  }

  const idA = generateKeyPair(), idB = generateKeyPair();
  const [dcA, dcB] = fakeChannelPair();

  // Construct both PeerLinks BEFORE the channels open: each emits its HELLO
  // immediately, which must queue inside RtcChannel until "open" (the pre-open
  // buffering path — the one thing RtcChannel adds over a raw pipe).
  let authA = null, authB = null;
  const framesB = [];
  const linkA = new PeerLink({
    channel: new RtcChannel(dcA), identity: idA, sodium, weDialed: true, expectPeerId: toHex(idB.publicKey),
    onAuth: (pid) => { authA = pid; }, onFrame: () => {}, onClose: () => {},
  });
  const linkB = new PeerLink({
    channel: new RtcChannel(dcB), identity: idB, sodium, weDialed: false, expectPeerId: toHex(idA.publicKey),
    onAuth: (pid) => { authB = pid; }, onFrame: (_p, f) => framesB.push(f), onClose: () => {},
  });

  try {
    // Nothing crosses while both ends are still "connecting".
    await sleep(10);
    assert(authA === null && authB === null, "no auth while channels are unopened (HELLO is buffered, not lost)");

    // Open both ends: buffered HELLOs flush and the mutual challenge completes.
    dcA._open(); dcB._open();
    await sleep(20);
    assertEqual(authA, toHex(idB.publicKey), "A authenticated B over the data channel");
    assertEqual(authB, toHex(idA.publicKey), "B authenticated A over the data channel");

    // A post-auth Network frame round-trips, attributed to the authenticated id.
    linkA.send(new Uint8Array([9, 8, 7]));
    await sleep(20);
    assert(framesB.length === 1 && bytesEqual(framesB[0], new Uint8Array([9, 8, 7])),
      "a frame sent after auth is delivered to the peer");

    // A wrong-key expectation must refuse: B presents idB, but we expect a random id.
    const [dcC, dcD] = fakeChannelPair();
    let authC = null;
    const linkC = new PeerLink({
      channel: new RtcChannel(dcC), identity: idA, sodium, weDialed: true, expectPeerId: toHex(generateKeyPair().publicKey),
      onAuth: (pid) => { authC = pid; }, onFrame: () => {}, onClose: () => {},
    });
    const linkD = new PeerLink({
      channel: new RtcChannel(dcD), identity: idB, sodium, weDialed: false, expectPeerId: toHex(idA.publicKey),
      onAuth: () => {}, onFrame: () => {}, onClose: () => {},
    });
    dcC._open(); dcD._open();
    await sleep(20);
    assert(authC === null, "a channel to a mismatched identity never authenticates");
    linkC.close(); linkD.close();
  } finally {
    linkA.close(); linkB.close();
  }

  console.log("  OK\n");
}

// ─── Test: two werift RtcNetworks connect over REAL WebRTC (net-rtc-node) ────
//
// The companion to testRtcNetwork: where that drives RtcChannel over a fake pipe,
// this stands up two *real* RtcNetworks on a werift-backed peerConnectionFactory
// and lets them complete a genuine ICE → DTLS → SCTP bring-up, then PeerLink's
// identity handshake, then a Transport request/response — all over an actual data
// channel. The relay is replaced by an in-process Signaling pair (a 2-party room
// that forwards each JSON message to the other side, as the relay would), so the
// test has no network dependency beyond loopback. This is the console side of the
// browser↔console-through-NAT story: the same stack a browser tab runs, off-browser.

function signalingPair() {
  // Two endpoints that forward to each other. JSON round-tripping each message
  // mirrors the relay wire (and proves the sdp/candidate objects RtcNetwork emits
  // are plain and serialisable). Delivery is deferred, like a real socket.
  let aCb = () => {}, bCb = () => {};
  const post = (cb, msg) => { const m = JSON.parse(JSON.stringify(msg)); queueMicrotask(() => cb(m)); };
  const a = { send: (m) => post(bCb, m), onMessage: (cb) => { aCb = cb; }, close() {} };
  const b = { send: (m) => post(aCb, m), onMessage: (cb) => { bCb = cb; }, close() {} };
  return [a, b];
}

async function testWeriftRtcNetwork() {
  console.log("Test: net-rtc-node — two werift RtcNetworks connect over real WebRTC (ICE/DTLS/SCTP)");
  const { RtcNetwork } = await imp("build/host/net-rtc.js");
  const { weriftPeerConnectionFactory } = await imp("build/host/net-rtc-node.js");

  const idA = generateKeyPair(), idB = generateKeyPair();
  const aId = toHex(idA.publicKey), bId = toHex(idB.publicKey);
  const [sigA, sigB] = signalingPair();
  // Loopback host candidate so two peers on one machine connect with no STUN.
  const pcFactory = weriftPeerConnectionFactory({ iceAdditionalHostAddresses: ["127.0.0.1"] });

  const netA = new RtcNetwork({ identity: idA, sodium, signaling: sigA, peerConnectionFactory: pcFactory });
  const netB = new RtcNetwork({ identity: idB, sodium, signaling: sigB, peerConnectionFactory: pcFactory });

  // Generous timeout: werift's pure-JS DTLS/SCTP bring-up is slower than native.
  const ta = new Transport(aId, netA, 4000);
  const tb = new Transport(bId, netB, 4000);
  tb.onRequest((_from, type, payload) => new Uint8Array([type, ...payload]));

  try {
    netA.join(); netB.join(); // announce into the room → the WebRTC dance begins

    const t0 = Date.now();
    while ((!netA.linkedPeers().includes(bId) || !netB.linkedPeers().includes(aId)) && Date.now() - t0 < 15000) {
      await sleep(100);
    }
    assert(netA.linkedPeers().includes(bId), "A holds an authenticated link to B over real WebRTC");
    assert(netB.linkedPeers().includes(aId), "B holds an authenticated link to A over real WebRTC");

    // A real request crosses the data channel and the typed response comes back.
    const res = await ta.request(bId, 7, new Uint8Array([3, 4]));
    assert(bytesEqual(res, new Uint8Array([7, 3, 4])), "request/response round-trips over the werift data channel");
  } finally {
    ta.close(); tb.close();
    netA.close(); netB.close();
  }

  console.log("  OK\n");
}

// ─── Test: WebRTC-Direct — relay-less browser→console with PeerLink (spike 2) ─
//
// The whole point of spike 2: a connection from a dial token alone — host + port +
// the console's cert hash — with NO signaling relay and NO answer coming back. The
// console is an ICE-lite agent on one UDP port (hand-rolled STUN demux driving
// werift DTLS/SCTP, host/webrtc-direct.ts); the dialer fabricates the console's
// answer locally from the certhash. We then run the unchanged PeerLink identity
// handshake over the opened data channel and round-trip a frame — proving the
// direct link is a first-class, authenticated seedstore link, not just a pipe.

async function testWebRtcDirect() {
  console.log("Test: webrtc-direct — relay-less dial-token link + PeerLink identity (spike 2)");
  const { WebRtcDirectListener, dialWebRtcDirect, makeCertKeys, certhashFromKeys, weriftChannelToRaw } =
    await imp("build/host/webrtc-direct.js");
  const { PeerLink } = await imp("build/host/net-link.js");

  const keys = await makeCertKeys();
  const certhash = certhashFromKeys(keys);
  const serverId = generateKeyPair(), clientId = generateKeyPair();
  const serverPub = toHex(serverId.publicKey);

  // The console: each opened data channel runs a PeerLink (we accepted it).
  let serverAuthed = null;
  const serverFrames = [];
  const listener = new WebRtcDirectListener({
    keys, host: "127.0.0.1", port: 0,
    onChannel: (dc) => {
      new PeerLink({
        channel: weriftChannelToRaw(dc), identity: serverId, sodium, weDialed: false,
        onAuth: (pid) => { serverAuthed = pid; },
        onFrame: (_pid, f) => serverFrames.push(f), onClose: () => {},
      });
    },
  });
  await listener.listen();
  const { host, port } = listener.address();

  let clientLink = null;
  try {
    // Dial with the token only — no relay, no answer-back.
    const { channel, opened, close } = await dialWebRtcDirect({ host, port, certhash, timeoutMs: 15000 });
    let clientAuthed = null;
    // Wrap immediately (subscribes onMessage) so the console's HELLO is not missed,
    // then let the channel finish opening.
    clientLink = new PeerLink({
      channel: weriftChannelToRaw(channel), identity: clientId, sodium, weDialed: true, expectPeerId: serverPub,
      onAuth: (pid) => { clientAuthed = pid; }, onFrame: () => {}, onClose: () => {},
    });
    await opened;

    // Wait for the mutual PeerLink handshake to complete over the direct channel.
    const t0 = Date.now();
    while ((!serverAuthed || !clientAuthed) && Date.now() - t0 < 5000) await sleep(50);
    assertEqual(clientAuthed, serverPub, "dialer authenticated the console over the direct channel");
    assertEqual(serverAuthed, toHex(clientId.publicKey), "console authenticated the dialer (in-channel AUTH, certhash untrusted)");

    // A post-auth frame crosses the relay-less link.
    clientLink.send(new Uint8Array([4, 2]));
    const t1 = Date.now();
    while (serverFrames.length === 0 && Date.now() - t1 < 3000) await sleep(50);
    assert(serverFrames.length === 1 && bytesEqual(serverFrames[0], new Uint8Array([4, 2])),
      "a frame crosses the WebRTC-Direct link after auth");

    close();
  } finally {
    clientLink?.close();
    listener.close();
  }

  console.log("  OK\n");
}

// ─── Test: WebRtcDirectNetwork — a Network over relay-less WebRTC-Direct ──────
//
// WebRtcDirectListener+dial give a raw authenticated channel; WebRtcDirectNetwork
// wraps those PeerLinks behind the same `Network` interface NodeNetwork/RtcNetwork
// expose, so the Transport (and StorageNode above it) ride on top untouched. One
// node listens (publishing a token), the other dials it — then a typed Transport
// request/response crosses the relay-less link, proving a console serveDirect node
// is a first-class storage-network peer, not just an echo pipe.

async function testWebRtcDirectNetwork() {
  console.log("Test: WebRtcDirectNetwork — a Network over relay-less WebRTC-Direct (spike 2)");
  const { WebRtcDirectNetwork, makeCertKeys } = await imp("build/host/webrtc-direct.js");

  const idS = generateKeyPair(), idC = generateKeyPair();
  const sId = toHex(idS.publicKey), cId = toHex(idC.publicKey);
  const keys = await makeCertKeys();

  const netS = new WebRtcDirectNetwork({ identity: idS, sodium, keys, listen: { host: "127.0.0.1" } });
  const netC = new WebRtcDirectNetwork({ identity: idC, sodium }); // dial-only

  const tS = new Transport(sId, netS, 4000);
  const tC = new Transport(cId, netC, 4000);
  tS.onRequest((_from, type, payload) => new Uint8Array([type, ...payload]));

  try {
    await netS.listen();
    const peer = await netC.dial(netS.token("127.0.0.1"));
    assertEqual(peer, sId, "dial resolved the server's authenticated id");
    assert(netC.linkedPeers().includes(sId), "client holds a routable link to the server");

    // The accepted side authenticates around the same time; wait for it.
    const t0 = Date.now();
    while (!netS.linkedPeers().includes(cId) && Date.now() - t0 < 3000) await sleep(50);
    assert(netS.linkedPeers().includes(cId), "server holds the reverse link (the channel is bidirectional)");

    const res = await tC.request(sId, 9, new Uint8Array([1, 2, 3]));
    assert(bytesEqual(res, new Uint8Array([9, 1, 2, 3])), "Transport request/response over WebRtcDirectNetwork");
  } finally {
    tS.close(); tC.close(); netS.close(); netC.close();
  }

  console.log("  OK\n");
}

// ─── Run ────────────────────────────────────────────────────────────────

await testFullLifecycle();
await testInvalidSignatureDropped();
await testSizeLimitEnforced();
await testSignatureDepthCap();
await testRefuseOverlayBootstrapSlot();
await testApproveInstallRejects();
await testApproveInstallReceivesBytesHash();
await testNoApproveInstallDropsAll();
await testReferencePolicyUpgradeRules();
await testReferencePolicyCapAcknowledgement();
await testInstallReplayRejected();
await testInstallerLookupQuery();
await testInstallerCapsOf();
await testInstallerRemove();
await testCallerStackFormat();
await testBridgeCapabilityCheckEndToEnd();
await testBlockFromCall();
await testWrapRejectsInvalidKeySizes();
await testFs();
await testRequestMany();
await testCapBridge();
await testPolicy();
await testShellBoot();
await testBundle();
await testWsFraming();
await testChannelPinning();
await testRtcNetwork();
await testWeriftRtcNetwork();
await testWebRtcDirect();
await testWebRtcDirectNetwork();
await testSafeJs();
await testSyncSafeRealm();
await testCapBridgeEnforcement();
await testCallHandlerGuards();
await testTransportResponseBinding();
await testWsFragmentation();
await testRedialAfterFailedDial();
await testSafeRealmSerialization();
await testPerf10k();

console.log(`\nResults: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
