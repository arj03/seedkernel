// Smoke test: the transport bundle runs as a shell's network over the in-process loopback
// fabric; two nodes complete the AKE and exchange a request and response through it. The
// second half tests the central claim: a node replaces its `_net` claimant while running,
// keeping its channel adapter on the same port, so the protocol can change without a fork.
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { testkit, makeAuthor } from "./testkit.mjs";
// The same assembler the build signs through (scripts/guest-source.mjs), imported instead
// of copied, so these bundles sign exactly the guest production signs.
import { readGuestSource } from "../scripts/guest-source.mjs";
import { TRANSPORT_APP_CONFIG } from "../scripts/transport-config.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

const { loadCrypto, generateKeyPair } = await imp("build/host/crypto-node.js");
const sodium = await loadCrypto();
const { bootShell } = await imp("build/host/shell-core.js");
const { LoopbackChannels } = await imp("tests/loopback-channels.mjs");
const { createSafeRealm } = await imp("build/host/safe-js.js");
const { policyFromJson } = await imp("build/host/policy.js");
const bundleApi = await imp("build/host/bundle.js");
const authorApi = await imp("build/scripts/bundle-author.js");
const { FreshnessMarks, hybridAuthorId, verifyBundle } = bundleApi;
const { authorBundle, guestOpFraming, hybridAuthorKeysFromSeed } = authorApi;
const { ModuleTable } = await imp("build/host/module-table.js");
const TRANSPORT_SERVICE = "_net";
// Every transport change below is one install naming the installed slot (§12.5): the
// node's current link owner, looked up each time because a successful change moves it.
const reinstallTransport = (node, blob, opts) =>
  node.shell.install(blob, { replaces: node.shell.resolve(TRANSPORT_SERVICE), ...opts });
// The app that drives the transport: a request is an app calling the id the transport
// claims (tests/transport-harness.mjs).
const { harnessAppBlob, appRequest, addr, ready, linkedPeers } = await imp("tests/transport-harness.mjs");
const { transportBundleBytes } = await imp("build/host/transport-bundle.js");

const transportBlob = transportBundleBytes();
const currentTransportGuest = readGuestSource(guestOpFraming());
const { ok, summary } = testkit();
// Report-style: a failed check is logged and counted, and the suite keeps going.
const assert = ok;
assert(["encodeManifest", "hybridAuthorKeysFromSeed", "signBundle", "encodeBundleBody", "authorBundle"]
  .every((name) => !(name in bundleApi)), "the runtime bundle entry point has no authoring surface");
// Read from the artifact, since the bundle can be rebuilt with a different key.
const transportVerified = verifyBundle(sodium, transportBlob);
const transportAuthor = Buffer.from(transportVerified.author).toString("hex");
assert(transportVerified.guestSource === currentTransportGuest,
  "the shipped transport contains the canonical generated op-frame source");
// The guest text is part of the signed body, and an editor can save a part with CRLF even
// though the repo checks out LF, so the assembler normalizes; otherwise the same commit
// could sign different bytes depending on who built it.
assert(!currentTransportGuest.includes("\r"), "the assembled transport guest is LF-only, so its signed bytes are the same on every platform");
assert(JSON.stringify(transportVerified.manifest.guest.config) === JSON.stringify(TRANSPORT_APP_CONFIG),
  "the shipped transport manifest signs the guest's complete default configuration");
// The artifact is PQ-signed (§14.1): one hybrid suite, and the author id in a policy is a
// hash of the key set, so both keys are on the verified result.
assert(transportVerified.authorKeys.mlDsa !== undefined,
  "the shipped transport bundle carries the ML-DSA-65 public key of its signing key set");

// Checks the build script's author against `hybridAuthorKeysFromSeed`, the derivation
// every publisher uses. A mismatch would fail no build but silently change this
// artifact's author, invalidating every operator's policy. The seed is per clone,
// gitignored, and written by the build.
const transportSeed = Uint8Array.from(Buffer.from(
  readFileSync(join(root, "transport", "author.key"), "utf8").trim(), "hex"));
const transportKeys = hybridAuthorKeysFromSeed(sodium, transportSeed);
const derivedTransportAuthor = Buffer.from(
  hybridAuthorId(sodium, transportKeys.ed.publicKey, transportKeys.mlDsa.publicKey)).toString("hex");
assert(derivedTransportAuthor === transportAuthor,
  "the shared seed→key-set derivation reproduces the shipped bundle's author id");

// `guestSource` overrides the artifact's guest; the only caller that passes one gives a
// program that cannot compile, so the install fails when the realm starts instead of at
// verify. `guestConfig` is `null` for the one caller signing a transport with no config,
// which fails at the same point.
function transportBundleAt(version, keys, guestSource, guestConfig = TRANSPORT_APP_CONFIG) {
  const guest = guestSource ?? currentTransportGuest;
  const wsWasm = new Uint8Array(readFileSync(join(root, "build/ws.wasm")));
  const mlkemWasm = new Uint8Array(readFileSync(join(root, "browser/mlkem768.wasm")));
  const { blob } = authorBundle(sodium, keys, {
    app: "transport", version,
    // The local service id the transport claims (§12.10), as in the artifact manifest. A
    // `services` claim, reachable by a co-resident guest and by no peer.
    services: [TRANSPORT_SERVICE],
    modules: [{ name: "ws", wasm: wsWasm }, { name: "mlkem", wasm: mlkemWasm }],
    guestSource: guest,
    // The services the transport guest requires, as in the artifact manifest
    // (scripts/build-transport-bundle.mjs). The installer grants `link` only by boot
    // selection or owner replacement (§12.5); it includes inbound delivery (`link/deliver`),
    // since services are declared whole, never by method.
    guestRequires: ["node", "link", "timer"],
    guestConfig: guestConfig ?? undefined,
  });
  return blob;
}

// One app author for both nodes: each loads the echo app, so a request from either
// reaches a handler on the other.
const appAuthor = makeAuthor(sodium);
const appAuthorHex = Buffer.from(appAuthor.id).toString("hex");

// `transport.config` becomes `LOCAL` (§12.6.3).
{
  let source = "";
  const { shell } = await bootShell({
    sodium,
    identity: generateKeyPair(),
    modules: new ModuleTable(),
    freshnessStore: new FreshnessMarks(),
    fs: false,
    transport: {
      config: { linkIdleTimeoutMs: 321, networkKey: "7a".repeat(32) },
      bundle: transportBlob,
    },
    createRealm: async (o) => {
      source = o.source;
      return { call: async () => new Uint8Array(), dispose() {} };
    },
    admit: policyFromJson(JSON.stringify({
      authors: [],
    })),
  });
  const [appConfig, localConfig] = Function(
    source.split("\n").slice(0, 3).join("\n") + "\nreturn [APP, LOCAL];",
  )();
  assert(appConfig.connsPerPeer === TRANSPORT_APP_CONFIG.connsPerPeer,
    "transport defaults arrive from signed APP config");
  assert(localConfig.linkIdleTimeoutMs === 321 && localConfig.networkKey === "7a".repeat(32),
    "bootShell transport.config reaches LOCAL unchanged, including the network key");
  shell.close();
}
/** One request through a node's app handle to `to`, the path a deployment uses. */
async function request(app, to, payload) {
  return appRequest(app, to, payload);
}

async function makeNode(channels, listen, freshnessStore = new FreshnessMarks()) {
  const identity = generateKeyPair();
  const policy = policyFromJson(JSON.stringify({
    authors: [appAuthorHex],
  }));
  const transportOptions = { channels, listen, bundle: transportBlob };
  const transportConfig = {};
  // A test may pause a candidate right after its realm starts, before the shell commits
  // it: its LOCAL config is in place, but the incumbent still owns `_net`, which makes
  // address-book updates during replacement deterministic to test.
  const realmControl = { pauseNext: null };
  // bootShell installs the selected transport at boot; every candidate below replaces
  // its current owner explicitly (§12.5), so each install exercises replacement and the
  // freshness rule, not app admission.
  const { shell, transport } = await bootShell({
    sodium, identity,
    modules: new ModuleTable(),
    freshnessStore,
    fs: false,
    transport: { ...transportOptions, config: transportConfig },
    createRealm: async (o) => {
      const realm = await createSafeRealm(o);
      const pause = realmControl.pauseNext;
      if (pause) { realmControl.pauseNext = null; await pause(); }
      return realm;
    },
    admit: policy,
  });
  const app = await shell.install(harnessAppBlob(appAuthor));
  // This node's key, hex, from the identity created here.
  const peerId = Buffer.from(identity.publicKey).toString("hex");
  return { shell, transport, realmControl, app, peerId };
}

console.log("Test: transport bundle drives two nodes over loopback");

const fabric = new LoopbackChannels();
const listen = [{ label: "tcp", host: "loopback", port: 0 }];
// A per-node view of the shared fabric, not the fabric itself: an upgrade closes the
// outgoing driver, and a whole-fabric close would unbind the other node's listener too.
const a = await makeNode(fabric.view(), listen);
const b = await makeNode(fabric.view(), listen);
const aNet = a.transport;
const bNet = b.transport;
const bId = b.peerId;
const c = await makeNode(fabric.view(), listen);
const cNet = c.transport;
const cId = c.peerId;

console.log("  starting listeners…");
assert(aNet.portOf("tcp") > 0 && bNet.portOf("tcp") > 0 && cNet.portOf("tcp") > 0, "all nodes bound loopback listeners");

// Each node runs the echo app, so the upgrade below can be checked both ways: A dialing
// out through the new transport, and B reaching A.
const bDest = `tcp://loopback:${bNet.portOf("tcp")}`;
await addr(a, bId, bDest);
await ready(a, 2000);
assert((await linkedPeers(a)).includes(bId), "A authenticated B over loopback (AKE ran)");

const resp = await request(b.app, a.peerId, new Uint8Array([1, 2, 3, 4]));
assert(resp.length === 4 && resp[3] === 4, "B's request to A echoed back through the record layer");

// ── The upgrade: swap A's transport while it is running and linked ───────────────
// An update replaces its own complete slot atomically: the claim and host adapter stay
// stable while the realm and its private session state are replaced.
console.log("  upgrading A's transport in place…");
const oldPort = aNet.portOf("tcp");
let candidateConfigured;
const configured = new Promise((resolve) => { candidateConfigured = resolve; });
let publishCandidate;
const publish = new Promise((resolve) => { publishCandidate = resolve; });
a.realmControl.pauseNext = async () => { candidateConfigured(); await publish; };
const replacementKeys = makeAuthor(sodium);
const upgrading = reinstallTransport(a, transportBundleAt(2, replacementKeys));
await configured;
// An address added during replacement goes to whoever owns `_net` right now: still the
// incumbent, since the candidate is not yet committed. The host keeps nothing, so the
// entry dies with that realm; the assertion below checks it is gone, not replayed.
await addr(a, cId, `tcp://loopback:${cNet.portOf("tcp")}`);
publishCandidate();
const upgraded = await upgrading;

assert(Buffer.from(upgraded.author).toString("hex") === Buffer.from(replacementKeys.id).toString("hex") &&
  a.shell.resolve(TRANSPORT_SERVICE) === upgraded.manifest.app,
  "the new author took over the transport claim");
assert(aNet.isClosed === false, "the adapter is neither closed nor leaked by the slot replacement");
assert(aNet.portOf("tcp") === oldPort, "the node stayed on the SAME port its peers hold");

// The cost of the address book living in the guest: neither the peer A was linked to nor
// the one added mid-replacement survives the swap, because both were entries in a realm
// that is gone. A request to either fails on its deadline, like any peer with no address.
let strandedB = true, strandedC = true;
try { await request(a.app, bId, new Uint8Array([9, 9])); strandedB = false; } catch { /* expected */ }
try { await request(a.app, cId, new Uint8Array([7, 8, 9])); strandedC = false; } catch { /* expected */ }
assert(strandedB && strandedC, "the replacement starts with an EMPTY address book — nothing is replayed to it");

// The embedder re-supplies the address and the new guest dials it itself. Live links do
// not survive either (the session keys were private to the outgoing realm), so this
// request reconnects, over the same listener on the same port B already knew.
await addr(a, bId, bDest);
const resp2 = await request(a.app, bId, new Uint8Array([9, 9]));
assert(resp2.length === 2 && resp2[0] === 9, "A reconnects once the embedder re-supplies the address, through the NEW transport");

// The reverse direction over that new link: B reaches A's app through the incoming
// guest, so the replacement handles inbound frames as well as the ones it dialed.
const resp3 = await request(b.app, a.peerId, new Uint8Array([5, 6, 7]));
assert(resp3.length === 3 && resp3[2] === 7, "B reaches A through the new guest, on the unchanged port");

// A downgrade is still refused: installing v2 advanced this (author, app) mark, and the
// transport is checked against it like any other bundle (§12.4).
let refused = false;
try { await reinstallTransport(a, transportBundleAt(1, replacementKeys)); }
catch { refused = true; }
assert(refused, "a lower version from the same author is refused after the upgrade");
assert((await request(a.app, bId, new Uint8Array([4]))).length === 1,
  "…and the refused load left the standing transport serving");

// ── A version that never ran must not consume the claim ──────────────────────────
// Every app's guest starts at install (shell-core.ts), so a v3 that cannot compile fails
// there. If the mark advanced before that, the node could not reinstall the transport it
// had, so the mark is the last step of the install.
const brokenGuest = "const nope = ( ;";
let v3Failed = false;
try { await reinstallTransport(a, transportBundleAt(3, replacementKeys, brokenGuest)); }
catch { v3Failed = true; }
assert(v3Failed, "a v3 whose guest cannot compile fails the load");

let v2Reloaded = true;
try { await reinstallTransport(a, transportBundleAt(2, replacementKeys)); }
catch { v2Reloaded = false; }
assert(v2Reloaded, "the known-good v2 reinstalls after the failed v3 — the mark records only what ran");
assert(a.shell.resolve(TRANSPORT_SERVICE) !== null, "…and the reinstalled bundle holds the transport id again");
// A successful reinstall is a slot replacement like any other, so this realm's address
// book is empty too and the embedder supplies it again. The refused installs above needed
// no such line: nothing was replaced, so the occupant kept its address book.
await addr(a, bId, bDest);
assert((await request(a.app, bId, new Uint8Array([8, 8]))).length === 2,
  "…and the node is back on the network through it");

// ── A transport that signs no bounds is refused, not run unbounded ───────────────
// Every policy value the guest reads bounds a resource, and an absent one does not fail
// the comparison that applies it; it makes it always false, so a frame cap read as
// `undefined` silently disappears. The guest therefore validates its config when the realm
// evaluates, which fails the install.
let noConfigFailed = false;
let noConfigMsg = "";
try { await reinstallTransport(a, transportBundleAt(3, replacementKeys, undefined, null)); }
catch (e) { noConfigFailed = true; noConfigMsg = e.message; }
assert(noConfigFailed && /maxFrameBytes|connsPerPeer|config/.test(noConfigMsg),
  `a transport signing no guest.config fails the load (${noConfigMsg})`);
assert((await request(a.app, bId, new Uint8Array([9]))).length === 1,
  "…and the standing transport is untouched by the refusal");

// Invalid network config must fail before replacing a working transport.
for (const networkKey of [null, 32, [], "", "ab".repeat(31), "ab".repeat(33), "AB".repeat(32), "zz".repeat(32)]) {
  let msg = "";
  try {
    await reinstallTransport(a, transportBundleAt(3, replacementKeys), { localConfig: { networkKey } });
  } catch (e) { msg = e.message; }
  assert(/config networkKey/.test(msg), `invalid network key fails the load (${msg})`);
}
assert((await request(a.app, bId, new Uint8Array([7]))).length === 1,
  "invalid network config leaves the standing transport serving");

// ── A cohort named wrong is a failed load, not a peer that looks down ────────────
// The same rule for another field: a half-length peer key would put an id in the address
// book that no handshake can match, and the only symptom would be a peer that never links,
// indistinguishable from one that is switched off. So the guest checks the shape of
// `LOCAL.peers` when it reads it, and a malformed cohort fails the install. The peer
// grammar and the contact secret's encoding belong to the transport; the CLI passes
// `--peers` through unread.
const PK = "ab".repeat(32);
for (const [what, localConfig] of [
  ["a short peer key", { peers: ["ab".repeat(20) + "@tcp://loopback:1"] }],
  ["a reference with no destination", { peers: [PK] }],
  ["a short contact secret", { peers: [`${PK}.${"cd".repeat(20)}@tcp://loopback:1`] }],
  ["a destination with no port", { peers: [`${PK}@ws://loopback/p`] }],
  ["a port out of range", { peers: [`${PK}@loopback:70000`] }],
  ["an object where a reference belongs", { peers: [{ peerId: PK, dest: "tcp://loopback:1" }] }],
  ["a malformed contact secret", { contactSecret: "not a secret" }],
]) {
  let msg = "";
  try { await reinstallTransport(a, transportBundleAt(3, replacementKeys), { localConfig }); }
  catch (e) { msg = e.message; }
  assert(/config (peers|contactSecret)/.test(msg), `${what} fails the load (${msg || "it loaded"})`);
}
assert((await request(a.app, bId, new Uint8Array([3]))).length === 1,
  "…and those refusals too left the standing transport serving");

// ── A mark that cannot be persisted is a failed load ─────────────────────────────
console.log("  an `_net` claimant whose mark cannot be persisted fails the load…");
{
  let broken = false;
  const store = new FreshnessMarks(null, () => { if (broken) throw new Error("disk full"); });
  const c = await makeNode(fabric.view(), undefined, store);
  assert(c.shell.resolve(TRANSPORT_SERVICE) !== null, "the node stands its transport claimant up normally");

  broken = true;
  let msg = "";
  try { await reinstallTransport(c, transportBundleAt(2, transportKeys)); } catch (e) { msg = e.message; }
  assert(msg.includes("could not be persisted"), `a bundle whose mark cannot be written fails the load (got: ${msg})`);
  assert(msg.includes("disk full"), "…and the original persist error survives the wrap");
  assert(c.shell.resolve(TRANSPORT_SERVICE) === "transport" && store.get(transportVerified.author, "transport") === 1,
    "nothing of the failed load was kept — the claim stayed with the transport that was standing, " +
    "and its mark did not advance");

  // The mark was rolled back, so the retry is a real advance, not a no-op against a store
  // that never got the first one.
  broken = false;
  let reloaded = true;
  try { await reinstallTransport(c, transportBundleAt(2, transportKeys)); } catch { reloaded = false; }
  assert(reloaded, "the retry against a healthy store lands");
  assert(store.get(transportVerified.author, "transport") === 2, "…and the mark it persists is the one the failed load rolled back");
  c.shell.close();
}

a.shell.close();
b.shell.close();
c.shell.close();
summary("transport bundle smoke");
