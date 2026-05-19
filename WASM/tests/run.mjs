// End-to-end test: bootstrap -> signed message -> handler dispatch.
//
// Run: node tests/run.mjs

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";
const require = createRequire(import.meta.url);
const sodium = require("libsodium-wrappers");

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

// ─── Run ────────────────────────────────────────────────────────────────

await testFullLifecycle();
await testInvalidSignatureDropped();
await testSizeLimitEnforced();
await testRefuseOverlayBootstrapSlot();
await testApproveInstallRejects();
await testApproveInstallReceivesBytesHash();
await testNoApproveInstallDropsAll();
await testReferencePolicyUpgradeRules();
await testInstallReplayRejected();
await testInstallerLookupQuery();
await testInstallerCapsOf();
await testInstallerRemove();
await testCallerStackFormat();
await testBridgeCapabilityCheckEndToEnd();
await testBlockFromCall();
await testWrapRejectsInvalidKeySizes();
await testPerf10k();

console.log(`\nResults: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
