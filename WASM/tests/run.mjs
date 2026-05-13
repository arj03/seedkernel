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
  GENESIS_ALGO_ID,
  generateKeyPair,
  ensureSodium,
  CURRENT_VERSION,
} = await imp("build/host/node.js");

await ensureSodium();

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (!condition) { console.error(`  FAIL: ${msg}`); failed++; }
  else passed++;
}
function assertEqual(actual, expected, msg) {
  const a = typeof actual === "object" ? JSON.stringify([...actual]) : actual;
  const e = typeof expected === "object" ? JSON.stringify([...expected]) : expected;
  assert(a === e, `${msg}: expected ${e}, got ${a}`);
}

// Per-signer monotonic seq counter for §4.4 replay protection. Each test
// that builds mutating-handler payloads (trust.grant, install) instantiates
// one and calls seq(pubKey) to get a fresh strictly-increasing seq for that
// signer. Tests that need to craft an explicit replay use number literals
// directly so the counter doesn't bump.
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

// Helper: standard bootstrap sequence (README §10). Wires signature, trust,
// capability.of_handler, and the install handler. By default approveInstall
// accepts every install request — tests that need to exercise rejection
// override it via host.setApproveInstall(...).
async function makeHost(approveInstall = () => true) {
  const host = await loadKernelHost(kernelWasm, bootstrapWasm);
  const signatureId       = host.deriveId("seedkernel.bootstrap.v1:signature");
  const signatureSignerId = host.deriveId("seedkernel.bootstrap.v1:signature.signer");
  const trustGrantId      = host.deriveId("seedkernel.bootstrap.v1:trust.grant");
  const sigRegisterId     = host.deriveId("seedkernel.bootstrap.v1:signature.register");
  const capOfHandlerId    = host.deriveId("seedkernel.bootstrap.v1:capability.of_handler");
  const installId         = host.deriveId("seedkernel.bootstrap.v1:install");

  host.registerSignature(signatureId, signatureSignerId);
  host.registerTrustGrant(trustGrantId);
  host.registerSignatureRegister(sigRegisterId);
  host.registerCapabilityOfHandler(capOfHandlerId);
  host.registerInstallHandler(installId);
  host.setApproveInstall(approveInstall);

  return { host, signatureId, signatureSignerId, trustGrantId, sigRegisterId,
           capOfHandlerId, installId };
}

// ─── Test: Full lifecycle ───────────────────────────────────────────────

async function testFullLifecycle() {
  console.log("Test: Full lifecycle (bootstrap -> signed message -> dispatch)");

  const { host, trustGrantId } = await makeHost();

  const chatTextId = host.deriveId("seedkernel.v1:chat.text");

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  assert(host.isTrusted(GENESIS_ALGO_ID, rootPk, trustGrantId), "root trusted for trust.grant");

  const received = [];
  host.register(chatTextId, (schemaId, payload, h) => {
    const signers = h.currentSigners;
    const signer = signers[signers.length - 1];
    const text = new TextDecoder().decode(payload);
    const pkHex = [...signer.publicKey]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .slice(0, 8);
    received.push(`${pkHex}: ${text}`);
  });

  assert(host.isRegistered(host.deriveId("seedkernel.bootstrap.v1:signature")), "signature registered");
  assert(host.isRegistered(trustGrantId), "trust.grant registered");
  assert(host.isRegistered(chatTextId), "chat.text registered");

  // Grant a dev key trust for trust.grant (signed by root)
  const seq = makeSeq();
  const { publicKey: devPk, privateKey: devSk } = generateKeyPair();
  const grantPayload = host.encodeGrant(seq(rootPk), false, GENESIS_ALGO_ID, devPk, trustGrantId);
  const grantInnerBytes = host.encodeEnvelope(CURRENT_VERSION, trustGrantId, grantPayload);
  const grantWire = host.wrap(rootSk, rootPk, grantInnerBytes);
  host.dispatch(grantWire);
  assert(host.isTrusted(GENESIS_ALGO_ID, devPk, trustGrantId), "dev key trusted for trust.grant");

  // Send a signed chat.text message from the dev key
  const chatWire = host.wrapAndEncode(devSk, devPk, CURRENT_VERSION, chatTextId,
    new TextEncoder().encode("hello from dev"));
  host.dispatch(chatWire);

  assertEqual(received.length, 1, "received count");
  assert(received[0].endsWith(": hello from dev"), "message content");
  const devPkHex = [...devPk].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 8);
  assert(received[0].startsWith(devPkHex), "signer matches dev key");

  console.log("  OK\n");
}

// ─── Test: Trust revocation ─────────────────────────────────────────────

async function testTrustRevocation() {
  console.log("Test: Trust revocation cascades");

  const { host, trustGrantId } = await makeHost();

  const seq = makeSeq();
  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);

  // Root grants dev key
  const { publicKey: devPk, privateKey: devSk } = generateKeyPair();
  const grantWire = host.wrap(rootSk, rootPk,
    host.encodeEnvelope(CURRENT_VERSION, trustGrantId,
      host.encodeGrant(seq(rootPk), false, GENESIS_ALGO_ID, devPk, trustGrantId)));
  host.dispatch(grantWire);
  assert(host.isTrusted(GENESIS_ALGO_ID, devPk, trustGrantId), "dev trusted before revoke");

  // Dev grants sub key
  const { publicKey: subPk } = generateKeyPair();
  const subGrantWire = host.wrap(devSk, devPk,
    host.encodeEnvelope(CURRENT_VERSION, trustGrantId,
      host.encodeGrant(seq(devPk), false, GENESIS_ALGO_ID, subPk, trustGrantId)));
  host.dispatch(subGrantWire);
  assert(host.isTrusted(GENESIS_ALGO_ID, subPk, trustGrantId), "sub trusted before revoke");

  // Revoke dev key — should cascade to sub
  host.trustRevoke(GENESIS_ALGO_ID, devPk, trustGrantId);
  assert(!host.isTrusted(GENESIS_ALGO_ID, devPk, trustGrantId), "dev revoked");
  assert(!host.isTrusted(GENESIS_ALGO_ID, subPk, trustGrantId), "sub cascaded revoke");

  console.log("  OK\n");
}

// ─── Test: Invalid signature dropped ────────────────────────────────────

async function testInvalidSignatureDropped() {
  console.log("Test: Invalid signature silently dropped");

  const { host } = await makeHost();

  const chatTextId = host.deriveId("seedkernel.v1:chat.text");

  const received = [];
  host.register(chatTextId, (_s, payload, _h) => {
    received.push(new TextDecoder().decode(payload));
  });

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const wire = host.wrapAndEncode(sk, pk, CURRENT_VERSION, chatTextId,
    new TextEncoder().encode("should not arrive"));
  // Corrupt a byte in the signature area
  wire[40] ^= 0xff;
  host.dispatch(wire);

  assertEqual(received.length, 0, "no messages received");
  console.log("  OK\n");
}

// ─── Test: Dynamic WASM handler + kernel.call ───────────────────────────

async function testDynamicHandlerAndKernelCall() {
  console.log("Test: Dynamic WASM handler instantiation + kernel.call");

  const { host, trustGrantId, installId } = await makeHost();

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  // App schemas use installer-scoped IDs (README §5).
  const chatTextId   = host.deriveScopedId("seedkernel.v1:chat.text", rootPk);
  // testerEchoId is a host-side handler (no signer attribution) — unscoped.
  const testerEchoId = host.deriveId("seedkernel.test.v1:tester.echo");

  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  // Root needs trust on the install schema to drive the install handler.
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);

  // Host-JS echo handler: returns its payload as a response.
  let echoInvocations = 0;
  let echoLastPayload = null;
  host.register(testerEchoId, (_s, payload, _h) => {
    echoInvocations++;
    echoLastPayload = new Uint8Array(payload);
    return new Uint8Array(payload); // response bytes
  });

  // Load the forwarder fixture and install it via a signed install message
  // addressed to the install handler. The payload carries caps, target_schema,
  // and the wasm module bytes.
  const seq = makeSeq();
  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
  const installPayload = host.encodeInstallPayload(seq(rootPk), [], chatTextId, forwarderBytes);
  const installWire = host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, installId, installPayload
  );
  host.dispatch(installWire);
  assert(host.isRegistered(chatTextId), "the forwarder installed dynamically");

  // Send a chat.text message. Payload format:
  //   [target_schema_len u8][target_schema ..][forward_payload ..]
  const forward = new TextEncoder().encode("hello via kernel.call");
  const innerPayload = new Uint8Array(1 + testerEchoId.length + forward.length);
  innerPayload[0] = testerEchoId.length;
  innerPayload.set(testerEchoId, 1);
  innerPayload.set(forward, 1 + testerEchoId.length);

  const chatWire = host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, chatTextId, innerPayload
  );
  host.dispatch(chatWire);

  assertEqual(echoInvocations, 1, "echo handler invoked once");
  assert(echoLastPayload && new TextDecoder().decode(echoLastPayload) === "hello via kernel.call",
    "echo received forwarded bytes");

  // Inspect the forwarder's stored response via exported accessors.
  const respPtr = host.callDynamicHandlerI32(chatTextId, "last_resp_ptr");
  const respLen = host.callDynamicHandlerI32(chatTextId, "last_resp_len");
  assert(respPtr !== null && respPtr > 0, "forwarder stored response ptr");
  assertEqual(respLen, forward.length, "forwarder stored response len");
  const respBytes = host.readDynamicHandlerMemory(chatTextId, respPtr, respLen);
  assert(respBytes !== null, "forwarder response readable from its memory");
  assertEqual(new TextDecoder().decode(respBytes), "hello via kernel.call",
    "kernel.call response matches echo payload");

  console.log("  OK\n");
}

// ─── Test: 64 KB size limit ──────────────────────────────────────────────

async function testSizeLimitEnforced() {
  console.log("Test: Oversized envelope rejected (§2.2)");

  const host = await loadKernelHost(kernelWasm, bootstrapWasm);

  const chatTextId = host.deriveId("seedkernel.v1:chat.text");
  const received = [];
  host.register(chatTextId, (_s, payload, _h) => {
    received.push(new TextDecoder().decode(payload));
  });

  // Build a valid envelope then pad it to exactly 65,537 bytes so only the
  // size check — not envelope parsing — causes the drop.
  const smallWire = host.encodeEnvelope(CURRENT_VERSION, chatTextId,
    new TextEncoder().encode("ok"));
  const oversized = new Uint8Array(65537);
  oversized.set(smallWire);
  host.dispatch(oversized);
  assertEqual(received.length, 0, "65537-byte envelope silently dropped");

  // Exactly 65,536 bytes: kernel accepts (padded payload won't decode as useful
  // data, but must not throw).
  const boundary = new Uint8Array(65536);
  boundary.set(smallWire);
  host.dispatch(boundary); // must not throw

  console.log("  OK\n");
}

// ─── Test: install handler refuses to overwrite a bootstrap slot ─────────

async function testProtectedHandlerNotReplaceable() {
  console.log("Test: install handler refuses to overwrite a bootstrap slot (§3.2)");

  const { host, trustGrantId, installId } = await makeHost();

  const signatureId = host.deriveId("seedkernel.bootstrap.v1:signature");
  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  // Even with trust on the install schema and an accepting approveInstall, the
  // install handler must refuse because signatureId was seeded via setHandler
  // and has no attribution row.
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);

  const seq = makeSeq();
  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
  const installPayload = host.encodeInstallPayload(seq(rootPk), [], signatureId, forwarderBytes);

  // Attempt to overwrite the signature handler with the forwarder bytes.
  const replaceWire = host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, installId, installPayload
  );
  host.dispatch(replaceWire);

  // The signature handler must still work — if it had been replaced with
  // the forwarder, subsequent signed messages would fail verification.
  const chatTextId = host.deriveId("seedkernel.v1:chat.text");
  const received = [];
  host.register(chatTextId, (_s, payload, _h) => {
    received.push(new TextDecoder().decode(payload));
  });
  const chatWire = host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, chatTextId,
    new TextEncoder().encode("still works")
  );
  host.dispatch(chatWire);
  assertEqual(received.length, 1, "signature handler still works after replacement attempt");
  assert(received[0] === "still works", "message delivered correctly");

  console.log("  OK\n");
}

// ─── Test: approveInstall callback rejects an install ──────────────────

async function testApproveInstallRejects() {
  console.log("Test: approveInstall callback can reject an install");

  let lastSeen = null;
  const approve = (schemaId, declaredCaps, signer) => {
    lastSeen = { schemaId, declaredCaps, signer };
    return false; // reject every install
  };
  const { host, trustGrantId, installId } = await makeHost(approve);

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  const chatTextId = host.deriveScopedId("seedkernel.v1:chat.text", rootPk);
  const netCapId   = host.deriveId("seedkernel.cap.v1:net");

  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);

  const seq = makeSeq();
  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(seq(rootPk), [netCapId], chatTextId, forwarderBytes),
  ));

  assert(!host.isRegistered(chatTextId), "install rejected by approveInstall");
  assert(lastSeen !== null, "approveInstall was called");
  assertEqual(lastSeen.schemaId, chatTextId, "approveInstall got the schema_id");
  assertEqual(lastSeen.declaredCaps.length, 1, "approveInstall got 1 declared cap");
  assertEqual(lastSeen.declaredCaps[0], netCapId, "approveInstall saw the net cap");
  assertEqual(lastSeen.signer.publicKey, rootPk, "approveInstall got the top signer");

  console.log("  OK\n");
}

// ─── Test: approveInstall callback accepts and the handler is installed ──

async function testApproveInstallAccepts() {
  console.log("Test: approveInstall callback can accept an install");

  // Accept only when the declared caps match an allowlist.
  const netCapPlaceholder = new Uint8Array(32); // will be overwritten below
  const approve = (_schemaId, declaredCaps, _signer) => {
    if (declaredCaps.length !== 1) return false;
    const c = declaredCaps[0];
    return c.length === netCapPlaceholder.length &&
      c.every((b, i) => b === netCapPlaceholder[i]);
  };
  const { host, trustGrantId, installId } = await makeHost(approve);

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  const chatTextId = host.deriveScopedId("seedkernel.v1:chat.text", rootPk);
  const netCapId   = host.deriveId("seedkernel.cap.v1:net");
  netCapPlaceholder.set(netCapId);

  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);

  const seq = makeSeq();
  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(seq(rootPk), [netCapId], chatTextId, forwarderBytes),
  ));

  assert(host.isRegistered(chatTextId), "install accepted by approveInstall");

  console.log("  OK\n");
}

// ─── Test: approveInstall receives the genesis-suite WASM hash ─────────

async function testApproveInstallReceivesWasmHash() {
  console.log("Test: approveInstall receives the genesis-suite hash of the WASM bytes (§3.2)");

  let seenHash = null;
  const approve = (_schemaId, _declaredCaps, _signer, wasmHash) => {
    seenHash = wasmHash;
    return true;
  };
  const { host, trustGrantId, installId } = await makeHost(approve);

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  const chatTextId = host.deriveScopedId("seedkernel.v1:chat.text", rootPk);

  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);

  const seq = makeSeq();
  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(seq(rootPk), [], chatTextId, forwarderBytes),
  ));
  assert(host.isRegistered(chatTextId), "install accepted");

  assert(seenHash !== null, "approveInstall received a wasmHash");
  assertEqual(seenHash.length, 32, "wasmHash is SHA-3-256 (32 bytes)");
  // Must equal the genesis-suite hash of the same bytes computed independently.
  const expected = host.genesisHash(forwarderBytes);
  assertEqual(seenHash, expected, "wasmHash matches genesisHash(forwarderBytes)");

  // A different binary must produce a different hash — proves the callback
  // can actually distinguish two installs by the same signer.
  const tampered = new Uint8Array(forwarderBytes);
  tampered[tampered.length - 1] ^= 0x01;
  const tamperedHash = host.genesisHash(tampered);
  assert(
    !tamperedHash.every((b, i) => b === seenHash[i]),
    "tampered binary produces a different hash"
  );

  console.log("  OK\n");
}

// ─── Test: install dropped when no approveInstall is wired ─────────────

async function testNoApproveInstallDropsAll() {
  console.log("Test: install dropped when no approveInstall callback is wired");

  // Default callback in makeHost is allow-all; explicitly clear it.
  const { host, trustGrantId, installId } = await makeHost();
  host.setApproveInstall(null);

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  const chatTextId = host.deriveScopedId("seedkernel.v1:chat.text", rootPk);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);

  const seq = makeSeq();
  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(seq(rootPk), [], chatTextId, forwarderBytes),
  ));

  assert(!host.isRegistered(chatTextId),
    "install dropped because no approveInstall was wired");

  console.log("  OK\n");
}

// ─── Test: capability.of_handler returns declared caps ─────────────────────

async function testCapabilityOfHandler() {
  console.log("Test: capability.of_handler reflects declared capabilities");

  const { host, trustGrantId, installId } = await makeHost();

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  const chatTextId = host.deriveScopedId("seedkernel.v1:chat.text", rootPk);
  const netCapId   = host.deriveId("seedkernel.cap.v1:net");

  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);

  const seq = makeSeq();
  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(seq(rootPk), [netCapId], chatTextId, forwarderBytes),
  ));
  assert(host.isRegistered(chatTextId), "forwarder installed with net cap");

  // The host-side handlerCapIndex is the source of truth queried by
  // capability.of_handler — verify via the public accessor.
  const declared = host.getHandlerDeclaredCaps(chatTextId);
  assertEqual(declared.length, 1, "one declared cap");
  assertEqual(declared[0], netCapId, "declared cap is netCapId");

  // setHandler-installed (bootstrap) handlers must have no entry in the
  // index — capability.of_handler returns [0x00] for them (§8.3).
  const sigId = host.deriveId("seedkernel.bootstrap.v1:signature");
  assertEqual(host.getHandlerDeclaredCaps(sigId).length, 0,
    "bootstrap handler has no declared caps");

  console.log("  OK\n");
}

// ─── Test: Bridge cap check end-to-end ────────────────────────────────────
//
// Installs two instances of the forwarder under different schema_ids — one with
// no capabilities (caps_count=0) and one with the `net` capability declared.
// Both try to forward to a `net.send` bridge. The bridge implements the §9
// preamble: it reads its caller's schema_id via host.currentCaller, fetches
// the caller's declared caps via host.getHandlerDeclaredCaps, and rejects the
// call if the caller lacks `net`.

async function testBridgeCapabilityCheckEndToEnd() {
  console.log("Test: Bridge enforces caller capability check end-to-end (§9)");

  const { host, trustGrantId, installId } = await makeHost();

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  // App handlers get installer-scoped IDs; the host-side bridge and the cap
  // label live outside the install namespace, so they're unscoped.
  const chatNoCapId   = host.deriveScopedId("seedkernel.test.v1:chat.nocap",   rootPk);
  const chatWithCapId = host.deriveScopedId("seedkernel.test.v1:chat.withcap", rootPk);
  const netSendId     = host.deriveId("seedkernel.cap.v1:net.send");
  const netCapId      = host.deriveId("seedkernel.cap.v1:net");

  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);

  const seq = makeSeq();
  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));

  // Install the forwarder with zero capabilities.
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(seq(rootPk), [], chatNoCapId, forwarderBytes)
  ));
  assert(host.isRegistered(chatNoCapId), "chat.nocap installed");

  // Install the forwarder with the net capability declared.
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(seq(rootPk), [netCapId], chatWithCapId, forwarderBytes)
  ));
  assert(host.isRegistered(chatWithCapId), "chat.withcap installed");

  // Register a net.send bridge. Implements the §9 preamble via the host API:
  //   1. host.currentCaller → the calling handler's schema_id
  //   2. host.getHandlerDeclaredCaps(caller) → the caps declared at install time
  //   3. check if net_cap_id is present; reject (return null) if not
  let bridgeCalls = 0;
  host.register(netSendId, (_schema, _payload, h) => {
    bridgeCalls++;
    const callerSchema = h.currentCaller;
    if (!callerSchema) return null; // top-level pipeline, not a kernel.call
    const callerCaps = h.getHandlerDeclaredCaps(callerSchema);
    const hasNet = callerCaps.some(
      (cap) => cap.length === netCapId.length && cap.every((b, i) => b === netCapId[i])
    );
    if (!hasNet) return null; // caller lacks the cap — bridge rejects
    return new Uint8Array([1]); // allowed — "I/O performed"
  });

  // Build the payload that the forwarder interprets as a kernel.call forward:
  //   [target_schema_len u8][target_schema ..][forward_data ..]
  const forwardData = new TextEncoder().encode("ping");
  function makeForwardPayload(targetId) {
    const out = new Uint8Array(1 + targetId.length + forwardData.length);
    out[0] = targetId.length;
    out.set(targetId, 1);
    out.set(forwardData, 1 + targetId.length);
    return out;
  }

  // chat.nocap → net.send: bridge must reject.
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, chatNoCapId,
    makeForwardPayload(netSendId)
  ));
  assertEqual(bridgeCalls, 1, "bridge invoked for no-cap caller");
  // Chat stores last_resp_len = 0 when kernel.call returns no response (bridge rejected).
  assertEqual(host.callDynamicHandlerI32(chatNoCapId, "last_resp_len"), 0,
    "no-cap: kernel.call to bridge returned empty (rejected)");

  // chat.withcap → net.send: bridge must allow.
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, chatWithCapId,
    makeForwardPayload(netSendId)
  ));
  assertEqual(bridgeCalls, 2, "bridge invoked for with-cap caller");
  // Chat stores last_resp_len = 1 when bridge returns its 1-byte success response.
  assertEqual(host.callDynamicHandlerI32(chatWithCapId, "last_resp_len"), 1,
    "with-cap: kernel.call to bridge returned 1-byte success response");

  console.log("  OK\n");
}

// ─── Perf: 10k dispatch vs. plain Ed25519 verify ─────────────────────────
//
// Measures the full kernel pipeline overhead relative to raw crypto.
// Printed every run so regressions are visible in CI output.
// The only hard assertion is that all N messages reached the handler —
// timing numbers are informational (no ratio threshold to avoid flakiness).

async function testPerf10k() {
  console.log("Perf: 10k signed-envelope dispatch vs. plain Ed25519 verify");

  const { host, trustGrantId } = await makeHost();

  const chatTextId = host.deriveId("seedkernel.v1:chat.text");

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);

  let handlerCalls = 0;
  host.register(chatTextId, () => { handlerCalls++; });

  const N = 10_000;
  const wireMessages = new Array(N);
  const signatures   = new Array(N);
  const payloads     = new Array(N);

  for (let i = 0; i < N; i++) {
    const payload = new TextEncoder().encode(`message #${i}: hello world benchmark payload data`);
    wireMessages[i] = host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION, chatTextId, payload);
    payloads[i]     = payload;
    signatures[i]   = sodium.crypto_sign_detached(payload, rootSk);
  }

  // Warm up (2000 of each — enough for Firefox IonMonkey to tier up WASM hot paths)
  for (let i = 0; i < 2000; i++) host.dispatch(wireMessages[i % N]);
  for (let i = 0; i < 2000; i++) sodium.crypto_sign_verify_detached(signatures[i % N], payloads[i % N], rootPk);
  handlerCalls = 0;

  const t0 = performance.now();
  for (let i = 0; i < N; i++) host.dispatch(wireMessages[i]);
  const kernelMs = performance.now() - t0;
  const kernelVerified = handlerCalls;

  const t1 = performance.now();
  for (let i = 0; i < N; i++) sodium.crypto_sign_verify_detached(signatures[i], payloads[i], rootPk);
  const plainMs = performance.now() - t1;

  const ratio = kernelMs / plainMs;
  console.log(`  kernel pipeline  ${N.toLocaleString()} msgs: ${kernelMs.toFixed(0).padStart(6)} ms  (${(kernelMs / N * 1000).toFixed(1)} µs/msg)`);
  console.log(`  plain Ed25519    ${N.toLocaleString()} msgs: ${plainMs.toFixed(0).padStart(6)} ms  (${(plainMs / N * 1000).toFixed(1)} µs/msg)`);
  console.log(`  overhead ratio: ${ratio.toFixed(2)}x`);

  assertEqual(kernelVerified, N, `all ${N} messages reached handler`);
  console.log("  OK\n");
}

// ─── Test: wrap rejects invalid key sizes (C5) ─────────────────────────────

async function testWrapRejectsInvalidKeySizes() {
  console.log("Test: wrap() rejects invalid Ed25519 key sizes (C5)");

  const host = await loadKernelHost(kernelWasm, bootstrapWasm);
  const signatureId = host.deriveId("seedkernel.bootstrap.v1:signature");
  // wrap requires the signature schema_id to have been stored by the host so
  // it knows what to envelope as. Use registerSignature to set it.
  const sigSignerId = host.deriveId("seedkernel.bootstrap.v1:signature.signer");
  host.registerSignature(signatureId, sigSignerId);

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  const inner = host.encodeEnvelope(CURRENT_VERSION,
    host.deriveId("seedkernel.v1:chat.text"),
    new TextEncoder().encode("ok"));

  // Short sk would otherwise read past the buffer in bootstrap memory
  let threw = false;
  try { host.wrap(sk.slice(0, 32), pk, inner); } catch { threw = true; }
  assert(threw, "wrap rejected 32-byte privateKey");

  threw = false;
  try { host.wrap(sk, pk.slice(0, 16), inner); } catch { threw = true; }
  assert(threw, "wrap rejected 16-byte publicKey");

  // Sanity: full sizes still succeed.
  const wire = host.wrap(sk, pk, inner);
  assert(wire.length > inner.length, "wrap with valid sizes succeeds");

  console.log("  OK\n");
}

// ─── Test: signature nesting depth bounded (C4) ────────────────────────────

async function testSignatureNestingDepthBounded() {
  console.log("Test: signature wrappers beyond depth limit are rejected (C4)");

  const { host, trustGrantId } = await makeHost();
  const chatTextId = host.deriveId("seedkernel.v1:chat.text");

  const { publicKey: pk, privateKey: sk } = generateKeyPair();
  host.trustGrant(GENESIS_ALGO_ID, pk, trustGrantId);

  let received = 0;
  host.register(chatTextId, () => { received++; });

  // 4 layers (the limit) should reach the handler.
  let wire = host.wrapAndEncode(sk, pk, CURRENT_VERSION, chatTextId,
    new TextEncoder().encode("at limit"));
  for (let i = 1; i < 4; i++) wire = host.wrap(sk, pk, wire);
  host.dispatch(wire);
  assertEqual(received, 1, "depth-4 message reaches handler");

  // 5 layers exceeds the limit — innermost handler must NOT be invoked.
  // The 5th wrap is performed at dispatch time when the stack already has 4
  // entries, so the outermost handle_signature returns 0 and drops silently.
  let wire5 = host.wrapAndEncode(sk, pk, CURRENT_VERSION, chatTextId,
    new TextEncoder().encode("over limit"));
  for (let i = 1; i < 5; i++) wire5 = host.wrap(sk, pk, wire5);
  host.dispatch(wire5);
  assertEqual(received, 1, "depth-5 message dropped (stays at 1)");

  console.log("  OK\n");
}

// ─── Test: trust revoke is selective by installer (README §3.2) ─────────
//
// Verifies the spec invariant from README §3.2: the install handler's
// RevokeInstallsBy only removes a handler if the installing key matches.
// A revoke targeting a schema installed by some other key must be a no-op
// for that handler.

async function testTrustRevokeSelectiveByInstaller() {
  console.log("Test: trust revocation only unregisters handlers installed by the revoked key (§3.2)");

  const { host, trustGrantId, installId } = await makeHost();

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  const { publicKey: bystanderPk } = generateKeyPair();
  // Scoped IDs in the normal case — root is the installer.
  const chatTextId = host.deriveScopedId("seedkernel.v1:chat.text",  rootPk);
  const otherId    = host.deriveScopedId("seedkernel.v1:chat.other", rootPk);

  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);
  // Trust grants on the target schema_ids aren't required by the install
  // handler (it gates on installId only), but we grant them so the trust
  // cascade has rows to revoke.
  host.trustGrant(GENESIS_ALGO_ID, rootPk, chatTextId);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, otherId);
  // Grant the bystander trust for root's exact schema_id bytes, even though
  // they didn't install. Trust grants are by raw schema_id — they don't
  // care about derivation — so this is a legitimate state to set up.
  host.trustGrant(GENESIS_ALGO_ID, bystanderPk, chatTextId);

  const seq = makeSeq();
  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));

  // Root installs both handlers via the install handler.
  host.dispatch(host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(seq(rootPk), [], chatTextId, forwarderBytes)));
  host.dispatch(host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(seq(rootPk), [], otherId, forwarderBytes)));
  assert(host.isRegistered(chatTextId), "chat.text installed by root");
  assert(host.isRegistered(otherId),    "chat.other installed by root");

  // Revoke trust for the BYSTANDER on chat.text. Even though they're trusted
  // for that schema, they didn't install the handler — install handler must keep it.
  host.trustRevoke(GENESIS_ALGO_ID, bystanderPk, chatTextId);
  assert(host.isRegistered(chatTextId),
    "chat.text remains: bystander wasn't the installer");

  // Now revoke ROOT's trust on chat.text. Root *was* the installer, so the
  // handler must be removed; the unrelated otherId must stay.
  host.trustRevoke(GENESIS_ALGO_ID, rootPk, chatTextId);
  assert(!host.isRegistered(chatTextId),
    "chat.text removed: root was the installer");
  assert(host.isRegistered(otherId),
    "chat.other untouched (different schema)");

  console.log("  OK\n");
}

// ─── Test: blockFromCall on deployer-added mutating handler (§4.4, §10.1) ──
//
// Verifies the §4.4 obligation that any handler that mutates kernel state
// from inside the pipeline must be blocked from kernel.call. The reference
// host blocks the four bootstrap mutators automatically; deployer-added
// mutators (canonically `bootstrap.replace`) get marked via blockFromCall.

async function testBlockFromCallOnDeployerHandler() {
  console.log("Test: blockFromCall makes a deployer handler unreachable via kernel.call (§4.4)");

  const { host, trustGrantId, installId } = await makeHost();

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  // Stand-in for bootstrap.replace — we just need a host-side handler whose
  // registration the deployer marks blocked. The handler returns 1 byte so
  // we can tell "actually invoked" from "kernel.call returned -1 before
  // invoking" — both code paths leave the forwarder with last_resp_len = 0
  // because the forwarder treats a -1 return the same as no response, so the handler-side
  // invocation counter is the discriminator.
  const replaceId = host.deriveId("seedkernel.test.v1:bootstrap.replace");
  let replaceInvocations = 0;
  const replaceHid = host.register(replaceId, () => {
    replaceInvocations++;
    return new Uint8Array([0x42]);
  });
  host.blockFromCall(replaceHid);

  // Direct top-level dispatch must still reach the handler — the §4.4 block
  // applies only to in-handler kernel.call, not to the inbound pipeline.
  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, replaceId);
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, replaceId, new Uint8Array(0)
  ));
  assertEqual(replaceInvocations, 1, "direct dispatch reaches the blocked handler");

  // Install the forwarder and have it forward to the blocked handler via
  // kernel.call. The host's call router must return -1 BEFORE invoking,
  // so replaceInvocations must remain at 1.
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);
  const seq = makeSeq();
  const chatTextId = host.deriveScopedId("seedkernel.v1:chat.text", rootPk);
  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(seq(rootPk), [], chatTextId, forwarderBytes),
  ));
  assert(host.isRegistered(chatTextId), "forwarder installed");

  const forward = new Uint8Array(0);
  const innerPayload = new Uint8Array(1 + replaceId.length + forward.length);
  innerPayload[0] = replaceId.length;
  innerPayload.set(replaceId, 1);
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, chatTextId, innerPayload
  ));

  assertEqual(replaceInvocations, 1, "kernel.call to blocked handler did NOT invoke it");
  assertEqual(host.callDynamicHandlerI32(chatTextId, "last_resp_len"), 0,
    "kernel.call to blocked handler returned -1 (forwarder saw no response)");

  // Sanity contrast: a non-blocked handler IS reachable via kernel.call.
  // Confirms it's the block, not some unrelated dispatch failure.
  const echoId = host.deriveId("seedkernel.test.v1:echo");
  let echoInvocations = 0;
  host.register(echoId, (_s, payload) => {
    echoInvocations++;
    return new Uint8Array(payload);
  });
  const echoForward = new TextEncoder().encode("ok");
  const echoInner = new Uint8Array(1 + echoId.length + echoForward.length);
  echoInner[0] = echoId.length;
  echoInner.set(echoId, 1);
  echoInner.set(echoForward, 1 + echoId.length);
  host.dispatch(host.wrapAndEncode(
    rootSk, rootPk, CURRENT_VERSION, chatTextId, echoInner
  ));
  assertEqual(echoInvocations, 1, "non-blocked handler IS reachable via kernel.call");
  assertEqual(host.callDynamicHandlerI32(chatTextId, "last_resp_len"), echoForward.length,
    "non-blocked handler's response delivered to caller");

  console.log("  OK\n");
}

// ─── Test: invalid action byte rejected (M2) ──────────────────────────────

async function testInvalidActionByteRejected() {
  console.log("Test: invalid action bytes rejected by trust.grant (M2)");

  const { host, trustGrantId } = await makeHost();

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);

  const { publicKey: targetPk } = generateKeyPair();
  const chatTextId = host.deriveId("seedkernel.v1:chat.text");

  // Forge a trust.grant payload with action=2 (undefined). Must NOT grant.
  // Layout (post-§4.4): [seq u32 BE][action u8][algo u16][pubkey_len u16][pubkey..][schema_len u8][schema..]
  const bad = new Uint8Array(4 + 1 + 2 + 2 + targetPk.length + 1 + chatTextId.length);
  let o = 0;
  // seq = 1 (any fresh value works; root has never grant-messaged before)
  for (let i = 0; i < 3; i++) bad[o++] = 0;
  bad[o++] = 1;
  bad[o++] = 2;                              // action — invalid
  bad[o++] = 0; bad[o++] = 0;                // algoId
  bad[o++] = (targetPk.length >> 8) & 0xff;  // pubkey_len u16 BE
  bad[o++] = targetPk.length & 0xff;
  bad.set(targetPk, o); o += targetPk.length;
  bad[o++] = chatTextId.length;
  bad.set(chatTextId, o);
  host.dispatch(host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION,
    trustGrantId, bad));
  assert(!host.isTrusted(GENESIS_ALGO_ID, targetPk, chatTextId),
    "action=2 trust.grant did not grant");

  console.log("  OK\n");
}

// ─── Test: trust.grant replay rejected by seq (§4.4) ───────────────────────
//
// The original hole: grant key X, revoke key X, then an attacker who captured
// the original "grant" wire bytes replays them — without seq protection
// trustGrant() finds no entry (revoked) and re-adds it. With the §4.4 seq
// prefix the replay carries seq <= last_seen and is dropped before any state
// change.

async function testTrustGrantReplayRejected() {
  console.log("Test: trust.grant rejects wire-byte replay after revocation (§4.4)");

  const { host, trustGrantId } = await makeHost();

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);

  const { publicKey: targetPk } = generateKeyPair();
  const someSchema = host.deriveId("seedkernel.test.v1:replay.target");

  // Original grant with seq=1.
  const grantWire = host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION,
    trustGrantId, host.encodeGrant(1, false, GENESIS_ALGO_ID, targetPk, someSchema));
  host.dispatch(grantWire);
  assert(host.isTrusted(GENESIS_ALGO_ID, targetPk, someSchema),
    "first grant succeeded");

  // Revoke (host-direct, doesn't consume seq).
  host.trustRevoke(GENESIS_ALGO_ID, targetPk, someSchema);
  assert(!host.isTrusted(GENESIS_ALGO_ID, targetPk, someSchema),
    "revoke succeeded");

  // Replay the EXACT same wire bytes. Without seq protection this would
  // re-add the trust entry. With §4.4 seq the handler must drop.
  host.dispatch(grantWire);
  assert(!host.isTrusted(GENESIS_ALGO_ID, targetPk, someSchema),
    "replay of original grant did NOT re-grant trust");

  // A fresh grant with seq=2 must still succeed — the replay drop must not
  // poison the channel for legitimate future messages from the same signer.
  const grantWire2 = host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION,
    trustGrantId, host.encodeGrant(2, false, GENESIS_ALGO_ID, targetPk, someSchema));
  host.dispatch(grantWire2);
  assert(host.isTrusted(GENESIS_ALGO_ID, targetPk, someSchema),
    "fresh grant with higher seq succeeded after the replay drop");

  console.log("  OK\n");
}

// ─── Test: trust.grant out-of-order seq rejected (§4.4) ────────────────────

async function testTrustGrantOutOfOrderSeqRejected() {
  console.log("Test: trust.grant rejects seq <= last_seen (§4.4 monotonicity)");

  const { host, trustGrantId } = await makeHost();

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);

  const { publicKey: aPk } = generateKeyPair();
  const { publicKey: bPk } = generateKeyPair();
  const sch = host.deriveId("seedkernel.test.v1:order.target");

  // Send seq=5 first.
  host.dispatch(host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION, trustGrantId,
    host.encodeGrant(5, false, GENESIS_ALGO_ID, aPk, sch)));
  assert(host.isTrusted(GENESIS_ALGO_ID, aPk, sch), "seq=5 grant succeeded");

  // seq=3 must be rejected (3 <= 5).
  host.dispatch(host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION, trustGrantId,
    host.encodeGrant(3, false, GENESIS_ALGO_ID, bPk, sch)));
  assert(!host.isTrusted(GENESIS_ALGO_ID, bPk, sch),
    "seq=3 (below last_seen=5) dropped");

  // seq=5 must also be rejected (5 <= 5, strictly greater required).
  host.dispatch(host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION, trustGrantId,
    host.encodeGrant(5, false, GENESIS_ALGO_ID, bPk, sch)));
  assert(!host.isTrusted(GENESIS_ALGO_ID, bPk, sch),
    "seq=5 (== last_seen) dropped");

  // Gaps are allowed — seq=10 (jumping over 6,7,8,9) succeeds.
  host.dispatch(host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION, trustGrantId,
    host.encodeGrant(10, false, GENESIS_ALGO_ID, bPk, sch)));
  assert(host.isTrusted(GENESIS_ALGO_ID, bPk, sch),
    "seq=10 (gap from 5) succeeded — gaps are allowed");

  console.log("  OK\n");
}

// ─── Test: install handler replay rejected by seq (§4.4) ───────────────────
//
// Same hole as trust.grant: an attacker who captured an install message
// could replay it after the operator removed the handler, tricking
// approveInstall into re-prompting and the operator into accidentally
// re-approving. The §4.4 seq prefix on the install payload prevents this.

async function testInstallReplayRejected() {
  console.log("Test: install handler rejects wire-byte replay (§4.4)");

  let approveCalls = 0;
  const { host, trustGrantId, installId } = await makeHost((_s, _c, _sg, _h) => {
    approveCalls++;
    return true;
  });

  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  const chatTextId = host.deriveScopedId("seedkernel.v1:chat.text", rootPk);

  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);
  host.trustGrant(GENESIS_ALGO_ID, rootPk, installId);

  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));

  // Original install with seq=1.
  const installWire = host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(1, [], chatTextId, forwarderBytes));
  host.dispatch(installWire);
  assert(host.isRegistered(chatTextId), "first install succeeded");
  assertEqual(approveCalls, 1, "approveInstall called once for first install");

  // Operator removes the handler (host-direct, doesn't consume seq).
  host.removeHandler(chatTextId);
  assert(!host.isRegistered(chatTextId), "handler removed");

  // Replay the EXACT same wire bytes. The §4.4 seq check must drop the
  // message BEFORE invoking approveInstall (so the operator never sees
  // a misleading re-prompt for a payload they already authorized).
  host.dispatch(installWire);
  assert(!host.isRegistered(chatTextId), "replayed install did NOT re-install");
  assertEqual(approveCalls, 1, "approveInstall NOT re-prompted on replay");

  // A fresh install with seq=2 succeeds — the channel isn't poisoned.
  host.dispatch(host.wrapAndEncode(rootSk, rootPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(2, [], chatTextId, forwarderBytes)));
  assert(host.isRegistered(chatTextId), "fresh install with higher seq succeeded");
  assertEqual(approveCalls, 2, "approveInstall called for the legitimate retry");

  console.log("  OK\n");
}

// ─── Test: revoke chain check (§7.2) ─────────────────────────────────
//
// Spec invariant from §7.2: a key trusted for trust.grant can revoke only
// entries whose chain of granters leads back to itself. Without this check,
// any one trust.grant-trusted key can revoke another trust.grant-trusted
// key's grants — an authority leak between admins.
//
// Topology:    root --grants--> A --grants--> B(target)
//              root --grants--> C  (C is independent of A's subtree)
//
// Expectations:
//   - C signing "revoke B" must be DROPPED (chain doesn't include C).
//   - root signing "revoke B" must SUCCEED (chain includes root).

async function testRevokeChainCheck() {
  console.log("Test: trust.grant revoke enforces granter-chain (§7.2)");

  const { host, trustGrantId } = await makeHost();

  const seq = makeSeq();
  const { publicKey: rootPk, privateKey: rootSk } = generateKeyPair();
  host.trustGrant(GENESIS_ALGO_ID, rootPk, trustGrantId);

  // root grants A trust.grant
  const { publicKey: aPk, privateKey: aSk } = generateKeyPair();
  host.dispatch(host.wrap(rootSk, rootPk,
    host.encodeEnvelope(CURRENT_VERSION, trustGrantId,
      host.encodeGrant(seq(rootPk), false, GENESIS_ALGO_ID, aPk, trustGrantId))));
  assert(host.isTrusted(GENESIS_ALGO_ID, aPk, trustGrantId), "A trusted for trust.grant");

  // A grants B for some target schema (B's chain: A -> root)
  const { publicKey: bPk } = generateKeyPair();
  const targetSchema = host.deriveId("seedkernel.test.v1:chain.target");
  host.dispatch(host.wrap(aSk, aPk,
    host.encodeEnvelope(CURRENT_VERSION, trustGrantId,
      host.encodeGrant(seq(aPk), false, GENESIS_ALGO_ID, bPk, targetSchema))));
  assert(host.isTrusted(GENESIS_ALGO_ID, bPk, targetSchema), "B trusted on target schema");

  // root grants C trust.grant (C is parallel — not in B's chain)
  const { publicKey: cPk, privateKey: cSk } = generateKeyPair();
  host.dispatch(host.wrap(rootSk, rootPk,
    host.encodeEnvelope(CURRENT_VERSION, trustGrantId,
      host.encodeGrant(seq(rootPk), false, GENESIS_ALGO_ID, cPk, trustGrantId))));
  assert(host.isTrusted(GENESIS_ALGO_ID, cPk, trustGrantId), "C trusted for trust.grant");

  // C tries to revoke B. C is trusted for trust.grant but B's chain is A -> root.
  // The chain check must drop this revoke.
  host.dispatch(host.wrap(cSk, cPk,
    host.encodeEnvelope(CURRENT_VERSION, trustGrantId,
      host.encodeGrant(seq(cPk), true, GENESIS_ALGO_ID, bPk, targetSchema))));
  assert(host.isTrusted(GENESIS_ALGO_ID, bPk, targetSchema),
    "C cannot revoke B (chain leads to A->root, not C)");

  // A revoking B must succeed (A is the immediate granter).
  host.dispatch(host.wrap(aSk, aPk,
    host.encodeEnvelope(CURRENT_VERSION, trustGrantId,
      host.encodeGrant(seq(aPk), true, GENESIS_ALGO_ID, bPk, targetSchema))));
  assert(!host.isTrusted(GENESIS_ALGO_ID, bPk, targetSchema),
    "A can revoke B (immediate granter)");

  // Re-grant B (fresh seq) so we can test root's authority on the same chain.
  host.dispatch(host.wrap(aSk, aPk,
    host.encodeEnvelope(CURRENT_VERSION, trustGrantId,
      host.encodeGrant(seq(aPk), false, GENESIS_ALGO_ID, bPk, targetSchema))));
  assert(host.isTrusted(GENESIS_ALGO_ID, bPk, targetSchema), "B re-granted by A");

  // root revoking B must succeed (chain B -> A -> root).
  host.dispatch(host.wrap(rootSk, rootPk,
    host.encodeEnvelope(CURRENT_VERSION, trustGrantId,
      host.encodeGrant(seq(rootPk), true, GENESIS_ALGO_ID, bPk, targetSchema))));
  assert(!host.isTrusted(GENESIS_ALGO_ID, bPk, targetSchema),
    "root can revoke B (chain reaches root)");

  console.log("  OK\n");
}

// ─── Test: install handler runs trust check before seq (§4.4) ────────
//
// The install handler must run the trust prefilter before consuming the
// §4.4 seq number, so that untrusted signers cannot grow the per-signer
// high-water-mark table indefinitely. Verified end-to-end:
//   1. Send an install signed by an untrusted key with seq=5. Must drop.
//      If the seq table got polluted by this drop, attempt 2 below would
//      fail because seq=1 <= last_seen=5.
//   2. Grant trust to that key. Send a fresh install with seq=1. With fix
//      in place, the seq table is empty for this key (the untrusted attempt
//      never reached _consumeSeq), so seq=1 is fresh and the install succeeds.

async function testInstallTrustCheckBeforeSeq() {
  console.log("Test: install handler trust-check runs before seq (§4.4)");

  const { host, installId } = await makeHost();

  const { publicKey: untrustedPk, privateKey: untrustedSk } = generateKeyPair();
  const targetSchema = host.deriveScopedId("seedkernel.test.v1:h2.target", untrustedPk);

  const { readFileSync } = await import("node:fs");
  const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));

  // Untrusted install attempt with a high seq (5). Must drop because the
  // signer is not trusted for the install schema.
  host.dispatch(host.wrapAndEncode(untrustedSk, untrustedPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(5, [], targetSchema, forwarderBytes)));
  assert(!host.isRegistered(targetSchema), "untrusted install dropped");

  // Now grant trust on the install schema (host-direct, doesn't consume seq).
  host.trustGrant(GENESIS_ALGO_ID, untrustedPk, installId);

  // Replay the same key with seq=1 — strictly less than the prior attempt's
  // seq=5. Without fix the seq table would say last_seen=5 for this key and
  // drop seq=1; with fix the seq table is still empty for this key, so the
  // install succeeds.
  host.dispatch(host.wrapAndEncode(untrustedSk, untrustedPk, CURRENT_VERSION, installId,
    host.encodeInstallPayload(1, [], targetSchema, forwarderBytes)));
  assert(host.isRegistered(targetSchema),
    "fresh install with low seq succeeds — proves untrusted attempt did not pollute lastSeen");

  console.log("  OK\n");
}

// ─── Run ─────────────────────────────────────────────────────────────────

await testFullLifecycle();
await testTrustRevocation();
await testInvalidSignatureDropped();
await testDynamicHandlerAndKernelCall();
await testSizeLimitEnforced();
await testProtectedHandlerNotReplaceable();
await testApproveInstallRejects();
await testApproveInstallAccepts();
await testApproveInstallReceivesWasmHash();
await testNoApproveInstallDropsAll();
await testCapabilityOfHandler();
await testBridgeCapabilityCheckEndToEnd();
await testWrapRejectsInvalidKeySizes();
await testSignatureNestingDepthBounded();
await testTrustRevokeSelectiveByInstaller();
await testBlockFromCallOnDeployerHandler();
await testInvalidActionByteRejected();
await testTrustGrantReplayRejected();
await testTrustGrantOutOfOrderSeqRejected();
await testInstallReplayRejected();
await testRevokeChainCheck();
await testInstallTrustCheckBeforeSeq();
await testPerf10k();

console.log(`\nResults: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
