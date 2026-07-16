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
  referencePolicy,
} = await imp("build/host/node.js");

// Transport + WS module surface (moved up from seedstore in the runtime split,
// the runtime split). These are seedkernel's own public exports — `./net-node`
// (NodeNetwork) and the no-cap `./ws` framing module — so they are exercised here,
// where they live, rather than only from a downstream consumer.
const { NodeNetwork } = await imp("build/host/net-node.js");
const { Transport, LoopbackNetwork } = await imp("build/host/net.js");
const { CAP, createCapBridge, opsForCaps, guestSignScope } = await imp("build/host/cap-bridge.js");
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

  host.registerSignature(signatureName);
  host.registerInstaller(installName);
  host.setApproveInstall(approveInstall);

  return { host, signatureName, installName };
}

const { readFileSync } = await import("node:fs");
const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));

// Encode an install + sign it, returning the wire bytes ready for dispatch.
function buildInstall(host, signSk, signPk, installName, seq, targetName, wasm) {
  const payload = host.encodeInstallPayload(seq, targetName, wasm);
  return host.wrapAndEncode(signSk, signPk, installName, payload);
}

// ─── Test: Full lifecycle ───────────────────────────────────────────────

async function testFullLifecycle() {
  console.log("Test: Full lifecycle (signed install + signed app message)");

  const { host, installName } = await makeHost();

  const seq = makeSeq();
  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  // Install the chat handler under the author's scoped name.
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk), chatTextName, forwarderBytes));
  assert(host.isRegistered(chatTextName), "chat.text installed");

  // The installer should have a record for it.
  const rec = host.lookupInstall(chatTextName);
  assert(rec !== null, "install record exists");
  assertEqual(rec.author.publicKey, pk, "record author matches signer");

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

  host.dispatch(host.wrapAndEncode(sk, pk, chatTextName, forwardPayload));
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
  const wire = host.wrapAndEncode(sk, pk, chatTextName,
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

  const smallWire = host.encodeEnvelope(chatTextName,
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
  const inner = host.encodeEnvelope(chatTextName,
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
  host.registerSignature(signatureName);
  host.registerInstaller(installName);
  host.setApproveInstall(referencePolicy(host, () => true));

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const seq = makeSeq();
  // Try to overlay the signature slot (seeded by SetHandler at bootstrap).
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    signatureName, forwarderBytes));

  // signature must still verify — if it had been overwritten with the
  // forwarder, the next signed message would fail.
  const chatTextName = host.deriveBootstrapName("chat.text");
  let received = 0;
  host.register(chatTextName, () => { received++; });
  host.dispatch(host.wrapAndEncode(sk, pk, chatTextName,
    new TextEncoder().encode("still works")));
  assertEqual(received, 1, "signature handler still verifying after refused overlay");

  console.log("  OK\n");
}

// ─── Test: approveInstall is the sole authorization gate ────────────────

async function testApproveInstallRejects() {
  console.log("Test: approveInstall can reject an install");

  let seen = null;
  const approve = (name, author, bytesHash, _wasm, existing) => {
    seen = { name, author, bytesHash, existing };
    return false;
  };
  const { host, installName } = await makeHost(approve);

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatTextName, forwarderBytes));

  assert(!host.isRegistered(chatTextName), "install rejected");
  assert(seen !== null, "approveInstall was called");
  assertEqual(seen.name, chatTextName, "callback saw the target name");
  assertEqual(seen.author.publicKey, pk, "callback saw the author pubkey");
  assert(seen.existing === null, "no existing record for first install");

  console.log("  OK\n");
}

async function testApproveInstallReceivesBytesHash() {
  console.log("Test: approveInstall receives genesisHash(wasm) as bytes_hash (§7.1)");

  let seenHash = null;
  let seenPayloadLen = 0;
  const approve = (_n, _a, bytesHash, wasm, _e) => {
    seenHash = bytesHash;
    seenPayloadLen = wasm.length; // for sanity
    return true;
  };
  const { host, installName } = await makeHost(approve);

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  const seq = makeSeq();
  const payload = host.encodeInstallPayload(seq(pk), chatTextName, forwarderBytes);
  host.dispatch(host.wrapAndEncode(sk, pk, installName, payload));
  assert(host.isRegistered(chatTextName), "install accepted");

  assertEqual(seenHash.length, 32, "bytes_hash is SHA-3-256 (32 bytes)");
  // The hash is the content id of the WASM module — the same identifier a
  // manifest's modules[].hash and a policy allowlist use (§7.1), independent of
  // seq or the install framing.
  const expected = host.genesisHash(forwarderBytes);
  assertEqual(seenHash, expected, "bytes_hash = genesisHash(wasm)");
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
    chatTextName, forwarderBytes));

  assert(!host.isRegistered(chatTextName), "install dropped");

  console.log("  OK\n");
}

// ─── Test: reference policy upgrade rules (§7.4) ────────────────────────

async function testReferencePolicyUpgradeRules() {
  console.log("Test: reference policy enforces same-author on upgrade (§7.4)");

  const host = await loadKernelHost(kernelWasm, bootstrapWasm);
  const signatureName = host.deriveBootstrapName("signature");
  const installName   = host.deriveBootstrapName("install");
  host.registerSignature(signatureName);
  host.registerInstaller(installName);
  host.setApproveInstall(referencePolicy(host, () => true));

  const seq = makeSeq();
  const { publicKey: aPk, privateKey: aSk } = generateKeyPair();
  const { publicKey: bPk, privateKey: bSk } = generateKeyPair();
  // Both authors target the same name so we can exercise the upgrade path.
  // (Author-scoped names would partition the space and avoid the rule.)
  const sharedName = host.deriveBootstrapName("test.shared");

  // A claims sharedName (first install — accepted).
  host.dispatch(buildInstall(host, aSk, aPk, installName, seq(aPk),
    sharedName, forwarderBytes));
  assert(host.isRegistered(sharedName), "A's first install accepted");
  const recA = host.lookupInstall(sharedName);
  assert(recA !== null, "record exists after A's install");
  const aBytesHash = recA.bytesHash;

  // B tries to install over the same name — rejected (different author).
  host.dispatch(buildInstall(host, bSk, bPk, installName, seq(bPk),
    sharedName, forwarderBytes));
  const recAfterB = host.lookupInstall(sharedName);
  assertEqual(recAfterB.author.publicKey, aPk, "different-author install rejected, A still owns");
  assertEqual(recAfterB.bytesHash, aBytesHash, "B's bytes did not land");

  // A re-installs (same author) — accepted; record updates in place. There is
  // no parent/lineage gate anymore (§7.4): same author is the whole rule.
  host.dispatch(buildInstall(host, aSk, aPk, installName, seq(aPk),
    sharedName, forwarderBytes));
  const recAfterUpgrade = host.lookupInstall(sharedName);
  assert(recAfterUpgrade !== null, "upgrade left a record");
  assertEqual(recAfterUpgrade.author.publicKey, aPk, "A still owns after upgrade");
  // bytes_hash is genesisHash(wasm) (§7.1), so re-installing the SAME wasm under a
  // fresh seq keeps the same content id — the identifier tracks the binary, not the
  // signed install message. (A different wasm would hash differently; §7.1 makes the
  // content id, a manifest's modules[].hash, and a policy allowlist all one value.)
  assertEqual(recAfterUpgrade.bytesHash, aBytesHash,
    "bytes_hash unchanged across a same-wasm re-install");
  assertEqual(recAfterUpgrade.bytesHash, host.genesisHash(forwarderBytes),
    "bytes_hash = genesisHash(wasm)");

  console.log("  OK\n");
}

// ─── Test: install replay rejected by seq (§4.4) ────────────────────────

async function testInstallReplayRejected() {
  console.log("Test: install handler rejects wire-byte replay (§4.4)");

  let approveCalls = 0;
  const { host, installName } = await makeHost((_n, _a, _h, _w, _e) => {
    approveCalls++;
    return true;
  });

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  // Original install with seq=1.
  const wire = buildInstall(host, sk, pk, installName, 1, chatTextName, forwarderBytes);
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
  host.dispatch(buildInstall(host, sk, pk, installName, 2, chatTextName, forwarderBytes));
  assert(host.isRegistered(chatTextName), "fresh higher-seq install succeeded");
  assertEqual(approveCalls, 2, "approve called for legitimate retry");

  console.log("  OK\n");
}

// ─── Test: installer.lookup (host-side) returns the install record ───────

async function testInstallerLookupHostSide() {
  console.log("Test: host-side lookupInstall returns the install record (§7.6)");

  const { host, installName } = await makeHost();

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatTextName, forwarderBytes));
  assert(host.isRegistered(chatTextName), "install ok");

  // The installer is a pure sink: records are read host-side, not via a wire
  // query. The policy callback already receives the resolved record; bridges
  // pin kernel.caller instead of consulting a capability index.
  const rec = host.lookupInstall(chatTextName);
  assert(rec !== null, "record present for an installed name");
  assertEqual(rec.author.publicKey, pk, "record author matches signer");
  assertEqual(rec.bytesHash, host.genesisHash(forwarderBytes), "bytes_hash = genesisHash(wasm)");

  // Unknown / SetHandler-seeded names have no record.
  assert(host.lookupInstall(host.deriveBootstrapName("does.not.exist")) === null,
    "unknown name has no record");
  assert(host.lookupInstall(host.deriveBootstrapName("signature")) === null,
    "SetHandler-seeded bootstrap handler has no record");

  console.log("  OK\n");
}

// ─── Test: installer.remove + suite slot removal ────────────────────────

async function testInstallerRemove() {
  console.log("Test: installer.remove clears record and kernel slot, replay still blocked");

  let approveCalls = 0;
  const { host, installName } = await makeHost((_n, _a, _h, _w, _e) => {
    approveCalls++;
    return true;
  });

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatTextName = host.deriveScopedName("chat.text", pk);

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatTextName, forwarderBytes));
  assert(host.isRegistered(chatTextName), "install ok");
  assert(host.lookupInstall(chatTextName) !== null, "record present");

  assert(host.installer.remove(chatTextName), "remove returned true");
  assert(!host.isRegistered(chatTextName), "kernel slot cleared");
  assert(host.lookupInstall(chatTextName) === null, "record cleared");

  // remove() is idempotent — second call returns false.
  assert(!host.installer.remove(chatTextName), "second remove returns false");

  // Fresh install at higher seq succeeds.
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatTextName, forwarderBytes));
  assert(host.isRegistered(chatTextName), "reinstall after remove succeeds");
  assertEqual(approveCalls, 2, "approve called for each accepted install");

  console.log("  OK\n");
}

// ─── Test: caller stack format ──────────────────────────────────────────

async function testCallerStackFormat() {
  console.log("Test: kernel.caller / currentCaller — immediate caller only (§4.2)");

  const { host, installName } = await makeHost();

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const forwarderName = host.deriveScopedName("test.forwarder", pk);

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    forwarderName, forwarderBytes));
  assert(host.isRegistered(forwarderName), "forwarder installed");

  // A probe handler reads its immediate caller each time it's called. Only the
  // immediate caller is exposed — there is no deeper-chain surface (§4.2, §9).
  const probeName = host.deriveBootstrapName("probe.caller");
  let seenImmediate = null;
  host.register(probeName, (_n, _payload, h) => {
    seenImmediate = h.currentCaller ? new Uint8Array(h.currentCaller) : null;
    return new Uint8Array([0xff]);
  });

  // forwarder → probe — the probe's immediate caller is the forwarder.
  const payload = new Uint8Array(1 + probeName.length);
  payload[0] = probeName.length;
  payload.set(probeName, 1);
  host.dispatch(host.wrapAndEncode(sk, pk, forwarderName, payload));
  assert(seenImmediate !== null, "probe saw a caller");
  assertEqual(seenImmediate, forwarderName, "immediate caller is the forwarder");

  // Top-level dispatch directly into the probe — no caller.
  seenImmediate = null;
  host.dispatch(host.wrapAndEncode(sk, pk, probeName, new Uint8Array(0)));
  assert(seenImmediate === null, "no immediate caller for top-level dispatch");

  console.log("  OK\n");
}

// ─── Test: Bridge authorizes by pinning kernel.caller ───────────────────

async function testBridgeCallerPinning() {
  console.log("Test: Bridge authorizes its caller by pinning kernel.caller (README §9)");

  const { host, installName } = await makeHost();

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const chatPinnedName = host.deriveScopedName("chat.pinned", pk);
  const chatOtherName  = host.deriveScopedName("chat.other",  pk);
  const netSendName    = host.deriveBootstrapName("cap.net.send");

  const seq = makeSeq();
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatPinnedName, forwarderBytes));
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    chatOtherName, forwarderBytes));
  assert(host.isRegistered(chatPinnedName), "chat.pinned installed");
  assert(host.isRegistered(chatOtherName), "chat.other installed");

  // The bridge pins exactly the caller name it serves (the chat shell's UI-bridge
  // pattern, generalized): it compares kernel.caller against chatPinnedName and
  // refuses anyone else. There is no capability index to consult — kernel.caller
  // is the single bridge-authorization primitive.
  const bytesEq = (a, b) => !!a && !!b && a.length === b.length && a.every((x, i) => x === b[i]);
  let bridgeCalls = 0;
  host.register(netSendName, (_n, _p, h) => {
    bridgeCalls++;
    if (!bytesEq(h.currentCaller, chatPinnedName)) return null;
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

  host.dispatch(host.wrapAndEncode(sk, pk, chatOtherName, makeForward(netSendName)));
  assertEqual(bridgeCalls, 1, "bridge invoked for the unpinned caller");
  assertEqual(host.callDynamicHandlerI32(chatOtherName, "last_resp_len"), 0,
    "unpinned caller: bridge rejected (no response)");

  host.dispatch(host.wrapAndEncode(sk, pk, chatPinnedName, makeForward(netSendName)));
  assertEqual(bridgeCalls, 2, "bridge invoked for the pinned caller");
  assertEqual(host.callDynamicHandlerI32(chatPinnedName, "last_resp_len"), 1,
    "pinned caller: bridge returned 1 byte");

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
  host.dispatch(host.wrapAndEncode(sk, pk, mutateName, new Uint8Array(0)));
  assertEqual(mutateCalls, 1, "direct dispatch still reaches blocked handler");

  // Install a forwarder, have it kernel.call the blocked handler. Must drop.
  const seq = makeSeq();
  const fwdName = host.deriveScopedName("test.forwarder", pk);
  host.dispatch(buildInstall(host, sk, pk, installName, seq(pk),
    fwdName, forwarderBytes));
  assert(host.isRegistered(fwdName), "forwarder installed");

  const fwdPayload = new Uint8Array(1 + mutateName.length);
  fwdPayload[0] = mutateName.length;
  fwdPayload.set(mutateName, 1);
  host.dispatch(host.wrapAndEncode(sk, pk, fwdName, fwdPayload));
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
  const inner = host.encodeEnvelope(
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
    wireMessages[i] = host.wrapAndEncode(sk, pk, chatTextName, payload);
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
      assert(fs.size("a.blk") < 0, `${name}: absent before put`);
      assertEqual(fs.size("a.blk"), -1, `${name}: size -1 when absent`);
      assertEqual(fs.get("a.blk"), null, `${name}: get null when absent`);

      fs.put("a.blk", bytes);
      assert(fs.size("a.blk") >= 0, `${name}: present after put`);
      assertEqual(fs.size("a.blk"), 5, `${name}: size reflects bytes`);
      assert(bytesEqual(fs.get("a.blk"), bytes), `${name}: get round-trips`);

      fs.put("a.dsc", new Uint8Array([9]));
      fs.put("b.blk", new Uint8Array([7, 7]));
      assertEqual(fs.list().sort().join(","), "a.blk,a.dsc,b.blk", `${name}: list sees all keys`);
      assertEqual(fs.list("a.").sort().join(","), "a.blk,a.dsc", `${name}: list filters by prefix`);
      assertEqual(fs.stat().used, 5 + 1 + 2, `${name}: stat.used sums all values`);
      assert(fs.stat().available > 0, `${name}: stat.available is positive`);

      assert(fs.delete("a.blk"), `${name}: delete reports removal`);
      assert(fs.size("a.blk") < 0, `${name}: absent after delete`);
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

// ─── Test: Transport.sendMany + cap-bridge NET_SEND_MANY (op 8) ──────────
//
// The per-peer fan-out: a DISTINCT payload per peer, concurrently. This is the
// primitive the sync storage guest drives for placement/gather (one batched cap
// per round) instead of a host-side Promise.all. An all-payloads-equal broadcast
// is just N identical entries.

async function testSendMany() {
  console.log("Test: Transport.sendMany + cap-bridge NET_SEND_MANY — per-peer fan-out (op 8)");

  const u32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  const rd32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  const U = (...xs) => new Uint8Array(xs);

  const a = generateKeyPair(), b = generateKeyPair(), c = generateKeyPair();
  const net = new LoopbackNetwork();
  const ta = new Transport(toHex(a.publicKey), net, 40);
  const tb = new Transport(toHex(b.publicKey), net, 40);
  const tc = new Transport(toHex(c.publicKey), net, 40);
  // Each peer echoes type + payload, so a distinct payload comes back distinctly.
  tb.onRequest((_from, type, payload) => new Uint8Array([type, ...payload]));
  tc.onRequest((_from, type, payload) => new Uint8Array([type, ...payload]));

  try {
    // 1) Transport.sendMany directly — distinct payloads, one per peer.
    const dead = toHex(generateKeyPair().publicKey);
    const results = await ta.sendMany([
      { peer: toHex(b.publicKey), type: 7, payload: U(1, 1) },
      { peer: toHex(c.publicKey), type: 7, payload: U(2, 2) },
      { peer: dead, type: 7, payload: U(9) },
    ]);
    assertEqual(results.length, 3, "one result per request, order preserved");
    assert(bytesEqual(results[0].bytes, U(7, 1, 1)), "peer b got ITS payload (distinct fan-out)");
    assert(bytesEqual(results[1].bytes, U(7, 2, 2)), "peer c got ITS payload");
    assert(!results[2].ok && results[2].bytes.length === 0, "the unreachable peer → ok:false, no bytes (partial)");

    // 2) Same fan-out through the cap-bridge NET_SEND_MANY wire (what the guest sees).
    const id = generateKeyPair();
    const tBridge = new Transport(toHex(id.publicKey), net, 40);
    const bridge = createCapBridge({
      sodium, identity: id, callHandler: () => null,
      transport: tBridge, peers: () => [], fs: new MemoryFs(),
    });
    const entry = (peerPk, type, payload) => concatBytes([peerPk, U(type), u32(payload.length), payload]);
    const req = concatBytes([u32(2), entry(b.publicKey, 7, U(3, 3, 3)), entry(c.publicKey, 7, U(4))]);
    const sendMany = bridge(CAP.NET_SEND_MANY, req);
    assert(sendMany instanceof Promise, "CAP_NET_SEND_MANY returns a Promise (real round trips)");
    const resp = await sendMany;
    // Decode [count u32]{[peer 32][ok u8][len u32][bytes]}
    assertEqual(rd32(resp, 0), 2, "response counts both peers");
    let o = 4;
    const decoded = [];
    for (let i = 0; i < 2; i++) {
      const peer = toHex(resp.slice(o, o + 32)); o += 32;
      const ok = resp[o] === 1; o += 1;
      const len = rd32(resp, o); o += 4;
      decoded.push({ peer, ok, bytes: resp.slice(o, o + len) }); o += len;
    }
    assertEqual(decoded[0].peer, toHex(b.publicKey), "first response is peer b (order preserved)");
    assert(bytesEqual(decoded[0].bytes, U(7, 3, 3, 3)), "peer b echoed its own payload through the bridge");
    assert(bytesEqual(decoded[1].bytes, U(7, 4)), "peer c echoed its own payload through the bridge");
    tBridge.close();

    // 3) A guest-controlled count not backed by bytes is a clean throw, never an
    //    unbounded host loop.
    let threw = false;
    try { await bridge(CAP.NET_SEND_MANY, concatBytes([u32(2), entry(b.publicKey, 7, U(1))])); }
    catch { threw = true; }
    assert(threw, "NET_SEND_MANY with count past the backing bytes throws");
  } finally {
    ta.close(); tb.close(); tc.close();
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

  // A host-derived signing scope binds the guest's SIGN op to a bundle namespace
  // (README §13.2); a real node derives it from the manifest's (author, app).
  const signScope = guestSignScope(id.publicKey, "testapp");
  const bridge = createCapBridge({
    sodium, identity: id,
    callHandler: (name, p) => host.callHandler(name, p),
    transport, peers: () => [toHex(id.publicKey)], fs, signScope,
  });
  const U = (...xs) => new Uint8Array(xs);

  try {
    // crypto primitives match sumo directly (the guest does all framing)
    const msg = U(1, 2, 3, 4, 5);
    assert(bytesEqual(await bridge(CAP.HASH, msg), sodium.crypto_generichash(32, msg)), "CAP_HASH = blake2b");
    const key = sodium.randombytes_buf(32), nonce = sodium.randombytes_buf(24);
    assert(bytesEqual(await bridge(CAP.STREAM_XOR, concatBytes([nonce, key, msg])),
      sodium.crypto_stream_xchacha20_xor(msg, nonce, key)), "CAP_STREAM_XOR = xchacha20 keystream");
    // CAP_SIGN is scoped, never raw (README §13.2): it signs DOMAIN_guest ‖ scope ‖ msg.
    const DOMAIN_GUEST = new TextEncoder().encode("seedkernel-guest-sig-v1\0");
    const sig = await bridge(CAP.SIGN, msg);
    const preimage = concatBytes([DOMAIN_GUEST, signScope, msg]);
    assert(sodium.crypto_sign_verify_detached(sig, preimage, id.publicKey), "CAP_SIGN signs DOMAIN_guest ‖ scope ‖ msg under the node identity");
    assert(!sodium.crypto_sign_verify_detached(sig, msg, id.publicKey), "CAP_SIGN never signs the raw message (scoped, not raw)");
    assertEqual((await bridge(CAP.VERIFY, concatBytes([id.publicKey, sig, preimage])))[0], 1, "CAP_VERIFY (raw) accepts the scoped preimage");
    assertEqual((await bridge(CAP.VERIFY, concatBytes([id.publicKey, sig, U(9, 9)])))[0], 0, "CAP_VERIFY rejects a forged message");
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

    // Sync vs async: every op resolves synchronously (returns bytes, not a
    // Promise) except the net ops, which round-trip — this is exactly what lets a
    // SYNC realm host the holder side while the async realm awaits net.
    assert(!(bridge(CAP.HASH, msg) instanceof Promise), "CAP_HASH resolves synchronously (bytes, no Promise)");
    assert(!(bridge(CAP.FS_SIZE, fk) instanceof Promise), "CAP_FS_SIZE resolves synchronously");
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

// ─── Test: channel identity pinning (transport §13.6) ─────────────────────

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
    host.dispatch(buildInstall(host, author.privateKey, author.publicKey, installName, seq(author.publicKey), name, forwarderBytes));
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
      shell.host, author.privateKey, author.publicKey, installName, seq(author.publicKey), name, forwarderBytes,
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
    // throwaway host to derive the kernel name and hash content. Modules install
    // directly from the manifest (§13.4) — no per-module .install envelope.
    const { host: h } = await makeHost();
    const kernelName = h.deriveScopedName("codec", author.publicKey);
    const guestText = "register('ping', () => new Uint8Array([1]));";
    const manifest = {
      app: "test", version: 1,
      modules: [{
        name: "codec", file: "codec.wasm", hash: toHex(h.genesisHash(forwarderBytes)),
        kernelName: toHex(kernelName),
      }],
      guest: { file: "guest.js", hash: toHex(h.genesisHash(new TextEncoder().encode(guestText))) },
      caps: [],
    };
    wf(pjoin(dir, "codec.wasm"), forwarderBytes);
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

    // Freshness (§13.4): version is an enforced monotonic high-water per (author, app).
    // The first load (v1 above) set the mark to 1; re-signing the manifest at a new
    // version and reloading through the same shell exercises the downgrade gate.
    const remanifest = (version) =>
      wf(pjoin(dir, "manifest.bundle"), signManifest(sodium, author.privateKey, author.publicKey, { ...manifest, version }));
    remanifest(1); shell.loadBundle(dir); // equal version reloads (an ordinary reboot)
    remanifest(2); shell.loadBundle(dir); // newer version advances the mark to 2
    remanifest(1);                          // now a downgrade
    let downgradeRefused = false;
    try { shell.loadBundle(dir); } catch { downgradeRefused = true; }
    assert(downgradeRefused, "a version below the (author, app) high-water mark is refused as a downgrade");
    remanifest(2); shell.loadBundle(dir);   // the mark held at 2, so v2 still loads
    remanifest(1);                          // restore the original manifest for the shell2 check below

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
  const stubTransport = { request: async () => new Uint8Array(), sendMany: async () => [] };
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
  try { await open(CAP.NET_SEND_MANY, U(0xff, 0xff, 0xff, 0xff)); } catch { threw = true; }
  assert(threw, "NET_SEND_MANY with a count not backed by payload bytes is refused");

  // caps → ops: a bundle declares capability DOMAINS, the shell expands them to the
  // op set the bridge enforces (the "wire the caps" path). A guest that declared
  // only "crypto" hashes fine but cannot touch fs, and a typo'd domain fails loudly.
  const cryptoOnly = mk(opsForCaps(["crypto"]));
  assertEqual((await cryptoOnly(CAP.HASH, U(1, 2))).length, 32, "a declared domain (crypto) grants its ops");
  threw = false;
  try { await cryptoOnly(CAP.FS_GET, U(120)); } catch { threw = true; }
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
  // stale frame from some outer dispatch (the §9 confused-deputy check).
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

async function testTransportStallTimeout() {
  console.log("Test: the request timeout is a stall bound — frames from the peer re-arm it");

  const a = generateKeyPair(), b = generateKeyPair();
  const A = toHex(a.publicKey), B = toHex(b.publicKey);
  const net = new LoopbackNetwork();
  const ta = new Transport(A, net, 250);
  const tb = new Transport(B, net, 250);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  // B answers each request after 150·type ms: 150 / 300 / 450. Issued together at
  // t≈0, responses 2 and 3 land past the 250 ms timeout — but each arriving
  // response is a frame from B that re-arms the later requests' stall clocks
  // (every inter-frame gap is 150 ms < 250 ms), so all three must resolve. This is
  // the PUT STORE round in miniature: many requests against one issue instant,
  // with the tail alive only because the transfer is visibly progressing.
  tb.onRequest(async (_from, type) => { await sleep(150 * type); return new Uint8Array([type]); });

  try {
    const rs = await Promise.all([1, 2, 3].map((t) => ta.request(B, t, new Uint8Array())));
    assertEqual(rs.map((r) => r[0]), [1, 2, 3], "a slow-but-streaming peer never times out");

    // A silent peer still fails after ~timeoutMs — the stall clock is a real bound.
    const t0 = Date.now();
    let failed = false;
    try { await ta.request(toHex(generateKeyPair().publicKey), 9, new Uint8Array()); }
    catch { failed = true; }
    assert(failed, "a silent peer still times out");
    assert(Date.now() - t0 < 2000, "silence is detected promptly, not hung");
  } finally {
    ta.close(); tb.close();
  }

  console.log("  OK\n");
}

async function testTransportBackstop() {
  console.log("Test: an absolute backstop rejects a withheld response even from a 'live' peer");

  const a = generateKeyPair(), b = generateKeyPair();
  const A = toHex(a.publicKey), B = toHex(b.publicKey);
  const net = new LoopbackNetwork();
  // timeoutMs 50, maxStallWindows 3 → backstop ≈ 150 ms. There is no Transport for B, so
  // it never answers A's request; we keep B "live" from A's view by dribbling an unrelated
  // frame every 20 ms (< the 50 ms silence window), which re-arms A's stall clock forever.
  // This is the buggy/hostile peer: it withholds THIS response while keeping the wire warm,
  // so silence alone would never fire — only the absolute backstop bounds the request.
  const ta = new Transport(A, net, 50, 3);
  let alive = true;
  (async () => {
    // A KIND_RES frame for a corr with no pending entry: onFrame stamps lastFrameAt[B]
    // (re-arming every request pending to B) then drops it — nothing ever resolves.
    while (alive) { net.send(B, A, Uint8Array.from([1, 0, 0, 0, 255, 0])); await sleep(20); }
  })();

  try {
    const t0 = Date.now();
    let failed = false, msg = "";
    try { await ta.request(B, 7, new Uint8Array()); }
    catch (e) { failed = true; msg = String(e?.message ?? e); }
    const dt = Date.now() - t0;
    assert(failed, "a request whose response never comes still rejects, despite a live peer");
    assert(/backstop/.test(msg), `it rejects via the absolute backstop, not silence (got: ${msg})`);
    assert(dt >= 140, `the backstop waits out ~maxStallWindows×timeoutMs before firing (got ${dt}ms)`);
    assert(dt < 900, `but it DOES fire — the request is not pinned forever (got ${dt}ms)`);
  } finally {
    alive = false;
    ta.close();
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

// ─── Test: connsPerPeer opens N parallel flows and stripes across them ──────
//
// The multi-flow upload feature (net-route / net-ws): a dialer opens connsPerPeer
// parallel links to one peer and stripes frames round-robin over them, so N TCP
// flows fill a high-RTT/lossy link a single CUBIC flow can't. We drive two
// NodeNetworkCores through an in-memory ChannelFactory (no sockets) so we can
// count the dials and the per-link sends directly:
//   • connsPerPeer=3 opens exactly 3 dials, and ready() is idempotent (no over-dial);
//   • post-auth frames stripe evenly round-robin across the 3 links;
//   • the peer stays reachable while ≥1 link survives — losing one flow is not a down.

async function testConnsPerPeerFanout() {
  console.log("Test: connsPerPeer opens N parallel flows and stripes frames round-robin");
  const { NodeNetworkCore } = await imp("build/host/net-route.js");

  // An in-memory RawChannel pair: whole-message, async delivery, closing either
  // end notifies both. Each end tallies how many frames it has carried.
  function rawPair() {
    const mk = () => ({
      twin: null, onMsg: null, onCls: null, open: true, sends: 0,
      send(bytes) {
        this.sends++;
        const t = this.twin, copy = bytes.slice();
        queueMicrotask(() => { if (t.open) t.onMsg?.(copy); });
      },
      onMessage(cb) { this.onMsg = cb; },
      onClose(cb) { this.onCls = cb; },
      close() {
        if (!this.open) return;
        this.open = false; this.twin.open = false;
        queueMicrotask(() => { this.onCls?.(); this.twin.onCls?.(); });
      },
    });
    const a = mk(), b = mk(); a.twin = b; b.twin = a; return [a, b];
  }

  let onAccept = null;
  const serverFactory = {
    connect() { throw new Error("server does not dial"); },
    listen(_tcp, _ws, cb) { onAccept = cb; return Promise.resolve({ port: 1, wsPort: 0 }); },
    close() {},
  };
  const clientLinks = []; // every client-side channel we dialed, in dial order
  const clientFactory = {
    connect(_addr) { const [c, s] = rawPair(); clientLinks.push(c); queueMicrotask(() => onAccept(s)); return c; },
    listen() { return Promise.resolve({ port: 0, wsPort: 0 }); },
    close() {},
  };

  const idS = generateKeyPair(), idC = generateKeyPair();
  const server = new NodeNetworkCore({ identity: idS, sodium, channels: serverFactory, listen: { host: "x", port: 0 } });
  await server.start();
  const got = [];
  server.register(toHex(idS.publicKey), (_from, frame) => got.push(frame));

  const client = new NodeNetworkCore({ identity: idC, sodium, channels: clientFactory, connsPerPeer: 3 });
  client.register(toHex(idC.publicKey), () => {});
  client.addPeerAddr(toHex(idS.publicKey), { host: "x", port: 1, transport: "tcp" });
  const sendC = (bytes) => client.send(toHex(idC.publicKey), toHex(idS.publicKey), bytes);

  try {
    await client.ready(2000);
    assertEqual(clientLinks.length, 3, "connsPerPeer=3 opens exactly 3 parallel dials");

    // ready() resolves on the FIRST link up; let the other two finish their handshake.
    await sleep(50);
    // A second ready() must not over-dial — the shortfall is zero once all three are up.
    await client.ready(2000);
    assertEqual(clientLinks.length, 3, "a second ready() is idempotent — no redundant dials");

    // Round-robin striping: 6 post-auth frames over 3 links → 2 each (each PeerLink.send
    // is exactly one channel send post-auth, so per-link tallies read the routing directly).
    const base = clientLinks.map((l) => l.sends);
    for (let i = 0; i < 6; i++) sendC(new Uint8Array([i]));
    await sleep(50);
    const deltas = clientLinks.map((l, i) => l.sends - base[i]);
    assertEqual(deltas, [2, 2, 2], "6 frames stripe evenly across the 3 parallel links");
    assertEqual(got.length, 6, "all 6 striped frames are delivered to the peer");

    // Resilience: drop one link — the peer is still reachable over the other two.
    clientLinks[0].close();
    await sleep(50);
    const before = got.length;
    for (let i = 0; i < 4; i++) sendC(new Uint8Array([9]));
    await sleep(50);
    assertEqual(got.length - before, 4, "losing one of three flows leaves the peer reachable over the rest");
  } finally {
    client.close(); server.close();
  }

  console.log("  OK\n");
}

// ─── Test: WsNetwork connsPerPeer — N parallel WS flows, up/down fire once ──
//
// The browser-edge counterpart to testConnsPerPeerFanout: WsNetwork (what p2p.html
// and p2p-cli dial with) opens connsPerPeer WebSockets to one peer and stripes over
// them. The cohort/quorum logic keys off onPeerUp/onPeerDown, so those must fire
// exactly once per peer regardless of how many parallel links back it. We drive the
// client through an in-memory WsLike factory whose twin runs a hand-wired server
// PeerLink, so no real socket is opened:
//   • connsPerPeer=3 opens 3 WebSockets but onPeerUp fires once;
//   • frames stripe evenly round-robin across the 3 links;
//   • dropping links keeps the peer up until the LAST one goes — onPeerDown fires once.

async function testWsNetworkFanout() {
  console.log("Test: WsNetwork connsPerPeer — 3 parallel WS flows, onPeerUp/Down fire once");
  const { WsNetwork, WsChannel } = await imp("build/host/net-ws.js");
  const { PeerLink } = await imp("build/host/net-link.js");

  // An in-memory WsLike pair (numeric readyState, as WsChannel checks === OPEN):
  // whole-message async delivery, open on next tick, close notifies both ends.
  function wsPair() {
    const mk = () => ({
      binaryType: "blob", readyState: 0 /* CONNECTING */, sends: 0,
      _l: { open: [], close: [], error: [], message: [] }, twin: null,
      addEventListener(t, cb) { this._l[t].push(cb); },
      send(bytes) {
        this.sends++;
        const t = this.twin, buf = bytes.slice().buffer;
        queueMicrotask(() => { if (t.readyState === 1) for (const cb of t._l.message) cb({ data: buf }); });
      },
      close() {
        if (this.readyState === 3) return;
        this.readyState = 3; for (const cb of this._l.close) cb();
        const t = this.twin; if (t.readyState !== 3) { t.readyState = 3; for (const cb of t._l.close) cb(); }
      },
      open() { this.readyState = 1; for (const cb of this._l.open) cb(); },
    });
    const a = mk(), b = mk(); a.twin = b; b.twin = a; return [a, b];
  }

  const idS = generateKeyPair(), idC = generateKeyPair();
  const clientWs = [];   // client-side WsLike per parallel link, in dial order
  const serverGot = [];  // frames the server received
  let serverAuthed = 0;  // server-side auths (one per accepted link)

  // Each dial: make a pair, wrap the server twin in a server-side PeerLink, and open
  // both ends next tick so the buffered HELLOs flush and the handshake runs.
  const factory = (_url) => {
    const [cli, srv] = wsPair();
    clientWs.push(cli);
    new PeerLink({
      channel: new WsChannel(srv), identity: idS, sodium, weDialed: false,
      onAuth: () => { serverAuthed++; }, onFrame: (_pid, f) => serverGot.push(f), onClose: () => {},
    });
    queueMicrotask(() => { cli.open(); srv.open(); });
    return cli;
  };

  let ups = 0, downs = 0;
  const client = new WsNetwork({
    identity: idC, sodium, webSocketFactory: factory, connsPerPeer: 3,
    onPeerUp: () => { ups++; }, onPeerDown: () => { downs++; },
  });
  const sendC = (bytes) => client.send(toHex(idC.publicKey), toHex(idS.publicKey), bytes);

  try {
    client.connect(`${toHex(idS.publicKey)}@127.0.0.1:1`);
    await sleep(80); // let all three handshakes complete
    assertEqual(clientWs.length, 3, "connsPerPeer=3 opens exactly 3 WebSockets");
    assertEqual(serverAuthed, 3, "all three parallel links authenticate on the server");
    assertEqual(ups, 1, "onPeerUp fires once, when the peer first becomes reachable");
    assertEqual(client.linkedPeers().length, 1, "the three links are one logical peer");

    // Round-robin striping: 6 post-auth frames over 3 links → 2 each.
    const base = clientWs.map((w) => w.sends);
    for (let i = 0; i < 6; i++) sendC(new Uint8Array([i]));
    await sleep(50);
    const deltas = clientWs.map((w, i) => w.sends - base[i]);
    assertEqual(deltas, [2, 2, 2], "6 frames stripe evenly across the 3 WS links");
    assertEqual(serverGot.length, 6, "all 6 striped frames reach the peer");

    // Drop two of three links: the peer stays up (no onPeerDown yet) and still routes.
    clientWs[0].close();
    clientWs[1].close();
    await sleep(50);
    assertEqual(downs, 0, "losing 2 of 3 flows does not down the peer");
    const before = serverGot.length;
    for (let i = 0; i < 3; i++) sendC(new Uint8Array([9]));
    await sleep(50);
    assertEqual(serverGot.length - before, 3, "the peer is still reachable over the surviving flow");

    // Re-dial: connect() is an idempotent top-up, so it re-opens ONLY the two dropped
    // flows (not a fresh three) — the browser/CLI recovers the striping win after a
    // partial drop instead of running degraded to one flow for the rest of the session.
    client.connect(`${toHex(idS.publicKey)}@127.0.0.1:1`);
    await sleep(80);
    assertEqual(clientWs.length, 5, "re-connect() opens exactly the 2-flow shortfall, not 3 more");
    assertEqual(serverAuthed, 5, "the two topped-up links authenticate too");
    assertEqual(ups, 1, "onPeerUp does NOT fire again — the peer was already reachable");
    assertEqual(client.linkedPeers().length, 1, "still one logical peer after the top-up");

    // Striping is back to three flows: 6 frames over the survivor + 2 re-opened links.
    const survivors = [clientWs[2], clientWs[3], clientWs[4]];
    const base2 = survivors.map((w) => w.sends);
    for (let i = 0; i < 6; i++) sendC(new Uint8Array([7]));
    await sleep(50);
    assertEqual(survivors.map((w, i) => w.sends - base2[i]), [2, 2, 2],
      "after the top-up, 6 frames stripe evenly across all 3 restored flows");

    // Every remaining flow drops → onPeerDown fires exactly once.
    for (const w of survivors) w.close();
    await sleep(50);
    assertEqual(downs, 1, "onPeerDown fires once, only when the last flow drops");
    assertEqual(client.linkedPeers().length, 0, "the peer is no longer linked once every flow is gone");
  } finally {
    client.close();
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

// ─── Test: RtcNetwork media tracks + ICE restart (net-rtc) ──────────────────
//
// addLocalTrack / removeLocalTracks / onTrack and the ICE-restart recovery
// (restartAllIce, plus restartIce on a "disconnected" connectionstatechange)
// all act on the peer's RTCPeerConnection, so a fake pc lets us assert the
// mechanics deterministically without standing up real ICE. We create one peer
// entry by feeding the signaling a `hello`, drive it to "connected", then check
// that tracks are published/removed, remote tracks surface via onTrack, and ICE
// restarts fire on demand and on a transient drop.

async function testRtcNetworkMedia() {
  console.log("Test: net-rtc — media tracks + ICE restart over a fake RTCPeerConnection");
  const { RtcNetwork } = await imp("build/host/net-rtc.js");

  // A minimal RTCPeerConnection stand-in: records track/ICE calls and can emit
  // the events RtcNetwork listens for. createDataChannel hands back an inert dc
  // (RtcChannel wraps it and buffers a HELLO that never flushes — harmless).
  function fakePc() {
    const l = {};
    return {
      connectionState: "new",
      signalingState: "stable",
      localDescription: null,
      remoteDescription: null,
      addedTracks: [],
      removedSenders: [],
      restartIceCount: 0,
      addEventListener(t, cb) { (l[t] ??= []).push(cb); },
      _emit(t, ev) { for (const cb of (l[t] || [])) cb(ev || {}); },
      createDataChannel() {
        return { binaryType: "blob", readyState: "connecting", addEventListener() {}, send() {}, close() {} };
      },
      addTrack(track, stream) { const s = { track, stream }; this.addedTracks.push(s); return s; },
      removeTrack(sender) { this.removedSenders.push(sender); },
      restartIce() { this.restartIceCount++; },
      async setLocalDescription() {},
      async setRemoteDescription() {},
      async addIceCandidate() {},
      close() { this.connectionState = "closed"; },
    };
  }

  const id = generateKeyPair();
  const peerId = toHex(generateKeyPair().publicKey);
  let pc = null, sigCb = null;
  const onTrackCalls = [];

  const net = new RtcNetwork({
    identity: id,
    sodium,
    signaling: { send() {}, onMessage(cb) { sigCb = cb; }, close() {} },
    peerConnectionFactory: () => { pc = fakePc(); return pc; },
    onTrack: (pid, track) => onTrackCalls.push({ pid, track }),
  });

  // A `hello` from a peer creates its entry (and its pc via the factory).
  sigCb({ type: "hello", from: peerId });
  await sleep(5);
  assert(pc !== null, "a hello creates a peer connection via the factory");

  // Bring the link to "connected" — tracks are only published to connected peers.
  pc.connectionState = "connected";
  pc._emit("connectionstatechange");

  // Publishing two local tracks adds both to the connected peer, once each.
  const t1 = { kind: "audio" }, t2 = { kind: "video" }, stream = { id: "local" };
  net.addLocalTrack(t1, stream);
  net.addLocalTrack(t2, stream);
  assert(pc.addedTracks.length === 2, "both local tracks are added to the connected peer");
  assert(pc.addedTracks[0].track === t1 && pc.addedTracks[1].track === t2, "the exact tracks are published");

  // A remote track surfaces through onTrack, attributed to the authenticated id.
  const remoteTrack = { kind: "video" };
  pc._emit("track", { track: remoteTrack });
  assert(onTrackCalls.length === 1 && onTrackCalls[0].pid === peerId && onTrackCalls[0].track === remoteTrack,
    "a remote track is delivered to onTrack with the peer id");

  // restartAllIce kicks every peer; a transient "disconnected" also self-heals.
  net.restartAllIce();
  assert(pc.restartIceCount === 1, "restartAllIce restarts ICE on each peer");
  pc.connectionState = "disconnected";
  pc._emit("connectionstatechange");
  assert(pc.restartIceCount === 2, "a 'disconnected' connection restarts ICE rather than tearing down");

  // Hanging up removes exactly the senders we added.
  net.removeLocalTracks();
  assert(pc.removedSenders.length === 2, "removeLocalTracks removes every sender it added");

  net.close();
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

// ─── Test: PeerLink record layer — tamper / replay / reorder tears the link down ──
//
// The core security property of the §13.6 record layer: after the AKE, every FRAME is
// an AEAD record under a forward-secret key with an implicit monotonic counter as its
// nonce, and any record that fails to decrypt in strict counter order tears the link
// down. We drive two real PeerLinks over an in-memory channel pair, let the handshake
// complete untouched, then intercept the sender's post-auth records to tamper, replay,
// or reorder them — each must fail the receiver's decrypt and drop the connection.
async function testRecordLayerIntegrity() {
  console.log("Test: PeerLink record layer — tampered / replayed / reordered records tear the link down");
  const { PeerLink } = await imp("build/host/net-link.js");

  // An in-memory RawChannel pair. HELLO(1)/AUTH(2) always pass through so the handshake
  // runs; a post-auth FRAME(3) from A is routed through `hook.fn(record, deliver)` when a
  // test installs one, so it can tamper / replay / reorder / drop. B→A always passes.
  function pair(hook) {
    const mk = () => ({
      msg: null, cls: null, closed: false, twin: null,
      onMessage(cb) { this.msg = cb; }, onClose(cb) { this.cls = cb; },
      close() {
        if (this.closed) return;
        this.closed = true;
        queueMicrotask(() => this.cls && this.cls());
        const t = this.twin;
        if (t && !t.closed) { t.closed = true; queueMicrotask(() => t.cls && t.cls()); }
      },
    });
    const a = mk(), b = mk(); a.twin = b; b.twin = a;
    const deliver = (to, bytes) => queueMicrotask(() => { if (!to.closed && to.msg) to.msg(bytes); });
    a.send = (bytes) => {
      const m = bytes.slice();
      if (m[0] === 3 /* MSG_FRAME */ && hook.fn) hook.fn(m, (out) => deliver(b, out));
      else deliver(b, m);
    };
    b.send = (bytes) => deliver(a, bytes.slice());
    return { a, b, injectB: (bytes) => deliver(b, bytes.slice()) };
  }

  // Build an authenticated pair, returning handles + a live state snapshot.
  async function authedPair() {
    const hook = { fn: null };
    const { a: chA, b: chB, injectB } = pair(hook);
    const idA = generateKeyPair(), idB = generateKeyPair();
    const st = { aAuthed: false, bAuthed: false, aClosed: false, bGot: [] };
    const linkB = new PeerLink({
      channel: chB, identity: idB, sodium, weDialed: false,
      onAuth: () => { st.bAuthed = true; }, onFrame: (_p, f) => st.bGot.push(f), onClose: () => {},
    });
    const linkA = new PeerLink({
      channel: chA, identity: idA, sodium, weDialed: true, expectPeerId: toHex(idB.publicKey),
      onAuth: () => { st.aAuthed = true; }, onFrame: () => {}, onClose: () => { st.aClosed = true; },
    });
    for (let i = 0; i < 20 && !(st.aAuthed && st.bAuthed); i++) await sleep(2);
    return { hook, linkA, linkB, injectB, st };
  }

  // 1. Tamper: flip a byte of the sealed ciphertext → Poly1305 tag check fails → drop.
  {
    const p = await authedPair();
    assert(p.st.aAuthed && p.st.bAuthed, "handshake completes before tampering");
    p.hook.fn = (rec, deliver) => { rec[1] ^= 0x01; deliver(rec); };
    p.linkA.send(new Uint8Array([1, 2, 3]));
    for (let i = 0; i < 20 && !p.st.aClosed; i++) await sleep(2);
    assert(p.st.aClosed, "a tampered record tears the link down");
    assertEqual(p.st.bGot.length, 0, "the tampered frame is never delivered to the guest");
  }

  // 2. Replay: deliver a valid record, then re-deliver the identical bytes — the receiver's
  //    counter has advanced, so the reconstructed nonce no longer matches → drop.
  {
    const p = await authedPair();
    assert(p.st.aAuthed && p.st.bAuthed, "handshake completes before replay");
    let captured = null;
    p.hook.fn = (rec, deliver) => { captured = rec.slice(); deliver(rec); };
    p.linkA.send(new Uint8Array([7]));
    for (let i = 0; i < 20 && p.st.bGot.length < 1; i++) await sleep(2);
    assertEqual(p.st.bGot.length, 1, "the first record decrypts and is delivered");
    p.injectB(captured); // replay the exact same sealed record
    for (let i = 0; i < 20 && !p.st.aClosed; i++) await sleep(2);
    assert(p.st.aClosed, "a replayed record tears the link down");
    assertEqual(p.st.bGot.length, 1, "the replayed record is not delivered a second time");
  }

  // 3. Reorder: hold record ctr0, then deliver ctr1 before ctr0 — the receiver expects
  //    ctr0's nonce, so the out-of-order record fails to decrypt → drop.
  {
    const p = await authedPair();
    assert(p.st.aAuthed && p.st.bAuthed, "handshake completes before reorder");
    const recs = [];
    p.hook.fn = (rec, deliver) => {
      recs.push(rec.slice());
      if (recs.length === 2) { deliver(recs[1]); deliver(recs[0]); } // ctr1 then ctr0
    };
    p.linkA.send(new Uint8Array([10])); // ctr0 (held)
    p.linkA.send(new Uint8Array([20])); // ctr1 → triggers reordered delivery
    for (let i = 0; i < 20 && !p.st.aClosed; i++) await sleep(2);
    assert(p.st.aClosed, "an out-of-order record tears the link down");
    assertEqual(p.st.bGot.length, 0, "no reordered frame is delivered");
  }

  console.log("  OK\n");
}

// ─── Test: a corrupt newer bundle does not advance the freshness mark ────────────
//
// Finding guard: the freshness high-water mark must record only versions that fully
// loaded. A newer bundle whose manifest is intact and signed but whose module file is
// corrupt (a half-landed upgrade) must fail the content check WITHOUT raising the mark —
// otherwise reloading the known-good older directory would be refused as a downgrade,
// bricking rollback (README §13.4).
async function testBundleCorruptNewerRollback() {
  console.log("Test: a corrupt newer bundle leaves the freshness mark intact (rollback stays possible)");
  const { signManifest } = await imp("build/host/bundle.js");
  const { boot } = await imp("build/host/main.js");
  const { mkdtempSync, rmSync, writeFileSync: wf } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join: pjoin } = await import("node:path");

  const author = generateKeyPair();
  const identity = generateKeyPair();
  const dir = mkdtempSync(pjoin(tmpdir(), "seedkernel-rollback-"));
  let shell;
  try {
    const { host: h } = await makeHost();
    const kernelName = h.deriveScopedName("codec", author.publicKey);
    const guestText = "register('ping', () => new Uint8Array([1]));";
    const manifest = (version) => ({
      app: "rollback", version,
      modules: [{
        name: "codec", file: "codec.wasm", hash: toHex(h.genesisHash(forwarderBytes)),
        kernelName: toHex(kernelName),
      }],
      guest: { file: "guest.js", hash: toHex(h.genesisHash(new TextEncoder().encode(guestText))) },
      caps: [],
    });
    wf(pjoin(dir, "guest.js"), guestText);
    const writeManifest = (version) =>
      wf(pjoin(dir, "manifest.bundle"), signManifest(sodium, author.privateKey, author.publicKey, manifest(version)));

    shell = await boot({
      kernelBytes: new Uint8Array(readFileSync(kernelWasm)),
      bootstrapBytes: new Uint8Array(readFileSync(bootstrapWasm)),
      policyJson: JSON.stringify({ authors: [toHex(author.publicKey)] }),
      dir: pjoin(dir, "_data"), identity,
    });

    // 1. Good v4 loads and sets the mark to 4.
    wf(pjoin(dir, "codec.wasm"), forwarderBytes);
    writeManifest(4);
    shell.loadBundle(dir);

    // 2. A corrupt v5: validly signed at version 5, but the on-disk module no longer
    //    matches its declared hash. The load must throw on the content check.
    writeManifest(5);
    wf(pjoin(dir, "codec.wasm"), forwarderBytes.slice(0, forwarderBytes.length - 1));
    let v5Failed = false;
    try { shell.loadBundle(dir); } catch { v5Failed = true; }
    assert(v5Failed, "a corrupt v5 bundle fails to load");

    // 3. Restore the good v4 directory and reload. If the failed v5 load had advanced the
    //    mark to 5, this would now be refused as a downgrade. It must still load.
    wf(pjoin(dir, "codec.wasm"), forwarderBytes);
    writeManifest(4);
    let v4Reloaded = true;
    try { shell.loadBundle(dir); } catch { v4Reloaded = false; }
    assert(v4Reloaded, "the known-good v4 reloads after the corrupt v5 attempt (mark not advanced)");
  } finally {
    if (shell) shell.close();
    rmSync(dir, { recursive: true, force: true });
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
await testInstallReplayRejected();
await testInstallerLookupHostSide();
await testInstallerRemove();
await testCallerStackFormat();
await testBridgeCallerPinning();
await testBlockFromCall();
await testWrapRejectsInvalidKeySizes();
await testFs();
await testSendMany();
await testCapBridge();
await testPolicy();
await testShellBoot();
await testBundle();
await testBundleCorruptNewerRollback();
await testWsFraming();
await testChannelPinning();
await testRtcNetwork();
await testRtcNetworkMedia();
await testWeriftRtcNetwork();
await testSafeJs();
await testSyncSafeRealm();
await testCapBridgeEnforcement();
await testCallHandlerGuards();
await testTransportResponseBinding();
await testTransportStallTimeout();
await testTransportBackstop();
await testWsFragmentation();
await testRedialAfterFailedDial();
await testConnsPerPeerFanout();
await testWsNetworkFanout();
await testRecordLayerIntegrity();
await testSafeRealmSerialization();
await testPerf10k();

console.log(`\nResults: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
