// Smoke test: the transport bundle stands up as a shell's network over the in-process
// loopback fabric; two nodes complete the AKE and exchange a typed request/response
// through it. The second half is the claim the whole arrangement rests on: a node replaces
// its `_net` claimant while running, with the concrete channel adapter on the same port —
// "the protocol is replaceable without a fork", in practice.
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { testkit, makeAuthor } from "./testkit.mjs";
// The same assembler the build signs through, imported rather than mirrored: these
// bundles must be signed over the byte-for-byte guest production signs, and a second copy
// of the part order here would quietly sign a different program (scripts/guest-source.mjs).
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
const authorApi = await imp("build/host/bundle-author.js");
const { FreshnessMarks, hybridAuthorId, verifyBundle } = bundleApi;
const { authorBundle, hybridAuthorKeysFromSeed } = authorApi;
const { ModuleTable } = await imp("build/host/module-table.js");
const TRANSPORT_SERVICE = "_net";
// The app that drives the transport: there is no host-side request facade left, so a
// request is an app calling the id the transport claims (tests/transport-harness.mjs).
const { harnessAppBlob, appRequest } = await imp("tests/transport-harness.mjs");
const { transportBundleBytes } = await imp("build/host/transport-bundle.js");

const transportBlob = transportBundleBytes();
const { ok, summary } = testkit();
// Report-style: a failed check is logged and counted, and the suite keeps going.
const assert = ok;
assert(["encodeManifest", "hybridAuthorKeysFromSeed", "signManifest", "packBundle", "authorBundle"]
  .every((name) => !(name in bundleApi)), "the runtime bundle entry point has no authoring surface");
// Read out of the artifact rather than restated: a hard-coded author is drift waiting
// to happen, and rebuilding the bundle with a different key is a supported thing to do.
const transportVerified = verifyBundle(sodium, transportBlob);
const transportAuthor = Buffer.from(transportVerified.author).toString("hex");
assert(JSON.stringify(transportVerified.manifest.guest.config) === JSON.stringify(TRANSPORT_APP_CONFIG),
  "the shipped transport manifest signs the guest's complete default configuration");
// The artifact is PQ-signed (§14.1): one hybrid suite, and the id policy pins is a key-set
// hash, so both keys are on the verified result.
assert(transportVerified.authorKeys.mlDsa !== undefined,
  "the shipped transport bundle carries the ML-DSA-65 public key of its signing key set");

// The build script derives the author's key set with its OWN copy of that derivation, so
// this pins it against `hybridAuthorKeysFromSeed` — the one every other publisher calls. A
// drift fails no build but silently re-identifies this artifact's author, invalidating
// every operator's pinned id. The seed is per-clone, gitignored, written by the build.
const transportSeed = Uint8Array.from(Buffer.from(
  readFileSync(join(root, "transport", "author.key"), "utf8").trim(), "hex"));
const transportKeys = hybridAuthorKeysFromSeed(sodium, transportSeed);
const derivedTransportAuthor = Buffer.from(
  hybridAuthorId(sodium, transportKeys.ed.publicKey, transportKeys.mlDsa.publicKey)).toString("hex");
assert(derivedTransportAuthor === transportAuthor,
  "the shared seed→key-set derivation reproduces the shipped bundle's author id");

// `guestSource` overrides the artifact's guest — the only caller that passes one hands in
// a program that cannot compile, to fail the load at the point where the DRIVER stands
// rather than at verify. `guestConfig` is `null` for the one caller signing a transport
// with no config at all, which is refused at the same point and for the same reason.
function transportBundleAt(version, keys, guestSource, guestConfig = TRANSPORT_APP_CONFIG) {
  const guest = guestSource ?? readGuestSource();
  const wsWasm = new Uint8Array(readFileSync(join(root, "build/ws.wasm")));
  const mlkemWasm = new Uint8Array(readFileSync(join(root, "browser/mlkem768.wasm")));
  const { blob } = authorBundle(sodium, keys, {
    app: "transport", version,
    // The local service id the transport claims (§12.10) — mirror of the artifact
    // manifest. A `services` claim, reachable by a co-resident guest and by no peer.
    services: [TRANSPORT_SERVICE],
    modules: [{ name: "ws", wasm: wsWasm }, { name: "mlkem", wasm: mlkemWasm }],
    guestSource: guest,
    // Exactly the services the transport guest holds — a mirror of the artifact manifest
    // (scripts/build-transport-bundle.mjs). `link` is what carries the `link` privilege
    // the admission dispatch reads (§12.5), inbound delivery (`link/deliver`) among its
    // names: the unit declared here is the service, never the method.
    guestRequires: ["node", "link", "timer"],
    guestConfig: guestConfig ?? undefined,
  });
  return blob;
}

// One app author for both nodes: each loads the echo app, so a request from either
// reaches a handler on the other.
const appAuthor = makeAuthor(sodium);
const appAuthorHex = Buffer.from(appAuthor.id).toString("hex");

// bootShell's convenience option is only syntax for this bundle's ordinary LOCAL load
// config. The shell still guards its three node facts against collisions.
{
  let source = "";
  const { shell } = await bootShell({
    sodium,
    identity: generateKeyPair(),
    modules: new ModuleTable(),
    freshnessStore: new FreshnessMarks(),
    fs: false,
    transport: {},
    transportConfig: { requestDeadlineMs: 321, peerId: "operator-cannot-replace-this" },
    transportBundle: transportBlob,
    createRealm: async (o) => {
      source = o.source;
      return { call: async () => new Uint8Array(), dispose() {} };
    },
    admit: policyFromJson(JSON.stringify({
      authors: [transportAuthor], grants: { link: [transportAuthor] },
    })),
  });
  const [appConfig, localConfig] = Function(
    source.split("\n").slice(0, 2).join("\n") + "\nreturn [APP, LOCAL];",
  )();
  assert(appConfig.requestDeadlineMs === TRANSPORT_APP_CONFIG.requestDeadlineMs,
    "transport defaults arrive from signed APP config");
  assert(localConfig.requestDeadlineMs === 321 && /^[0-9a-f]{64}$/.test(localConfig.peerId),
    "bootShell transportConfig reaches LOCAL while host-owned node facts win collisions");
  shell.close();
}
/** One request through a node's app handle to `to` — the path a deployment uses. */
async function request(app, to, payload) {
  return appRequest(app, to, payload);
}

async function makeNode(channels, listen, freshnessStore = new FreshnessMarks()) {
  const identity = generateKeyPair();
  const policy = policyFromJson(JSON.stringify({
    authors: [transportAuthor, appAuthorHex],
    grants: { link: [transportAuthor] },
  }));
  const transportOptions = { channels, listen };
  const transportConfig = { requestDeadlineMs: 800 };
  // A test may pause a candidate right after its realm stands, before the shell publishes
  // it: its LOCAL facts are installed, but the incumbent still owns `_net`, which exposes
  // address-book updates in the replacement window deterministically.
  const realmControl = { pauseNext: null };
  // bootShell owns the adapter but leaves the load to this test — the thing under test,
  // upgrades included. Every
  // candidate below is signed by the shipped blob's own author, so the pin admits them
  // and each load exercises the freshness rule, not the pin.
  const { shell, transport } = await bootShell({
    sodium, identity,
    modules: new ModuleTable(),
    freshnessStore,
    fs: false,
    transport: transportOptions,
    transportLoad: false,
    transportBundle: transportBlob,
    createRealm: async (o) => {
      const realm = await createSafeRealm(o);
      const pause = realmControl.pauseNext;
      if (pause) { realmControl.pauseNext = null; await pause(); }
      return realm;
    },
    admit: policy,
  });
  await shell.loadBundleBlob(transportBlob, { localConfig: transportConfig });
  const app = await shell.loadBundleBlob(harnessAppBlob(appAuthor));
  return { shell, transport, realmControl, app };
}

console.log("Test: transport bundle drives two nodes over loopback");

const fabric = new LoopbackChannels();
const listen = { host: "loopback", port: 0 };
// A per-node VIEW of the shared fabric, not the fabric itself: an upgrade closes the
// outgoing driver, and a whole-fabric close would unbind the other node's listener too.
const a = await makeNode(fabric.view(), listen);
const b = await makeNode(fabric.view(), listen);
const aNet = a.transport;
const bNet = b.transport;
const bId = b.transport.peerId;
const c = await makeNode(fabric.view(), listen);
const cNet = c.transport;
const cId = cNet.peerId;

console.log("  starting listeners…");
await aNet.start();
await bNet.start();
await cNet.start();
assert(aNet.port > 0 && bNet.port > 0 && cNet.port > 0, "all nodes bound loopback listeners");

// Each node runs the echo app, so both directions work — the upgrade below has to be
// checked both ways: A dialing out through the new transport, and B reaching A.
aNet.addPeerAddr(bId, { host: "loopback", port: bNet.port, transport: "tcp" });
await aNet.ready(2000);
assert((await aNet.linkedPeers()).includes(bId), "A authenticated B over loopback (AKE ran)");

const resp = await request(b.app, aNet.peerId, new Uint8Array([1, 2, 3, 4]));
assert(resp.length === 4 && resp[3] === 4, "B's request to A echoed back through the record layer");

// ── The upgrade: swap A's transport while it is running and linked ───────────────
// An update replaces its own complete slot atomically: the claim and host adapter stay
// stable while the realm and its private session state are replaced.
console.log("  upgrading A's transport in place…");
const oldPort = aNet.port;
const oldPeerId = aNet.peerId;
const oldClaimant = a.shell.resolve(TRANSPORT_SERVICE);
let candidateConfigured;
const configured = new Promise((resolve) => { candidateConfigured = resolve; });
let publishCandidate;
const publish = new Promise((resolve) => { publishCandidate = resolve; });
a.realmControl.pauseNext = async () => { candidateConfigured(); await publish; };
const upgrading = a.shell.loadBundleBlob(transportBundleAt(2, transportKeys));
await configured;
// The candidate's `init` facts were not snapped at the pause: this address update lands
// after it, before the handover, while the incumbent still owns `_net`. The address book
// is the NODE's, so it survives the commit iff the host replays it to the published
// claimant; the facts the newcomer received in LOCAL never carried it.
aNet.addPeerAddr(cId, { host: "loopback", port: cNet.port, transport: "tcp" });
publishCandidate();
await upgrading;

assert(a.shell.resolve(TRANSPORT_SERVICE) === oldClaimant, "the update retained its own transport claim");
assert(aNet.isClosed === false, "the adapter is neither closed nor leaked by the slot replacement");
assert(aNet.port === oldPort, "the node stayed on the SAME port its peers hold");
assert(aNet.peerId === oldPeerId, "the node identity is the host's, untouched by the swap");

let racedAddrResp = null;
try { racedAddrResp = await request(a.app, cId, new Uint8Array([7, 8, 9])); } catch { /* assertion below */ }
assert(racedAddrResp?.length === 3 && racedAddrResp[2] === 9,
  "an address added after candidate config but before claim commit is replayed to the replacement");

// Live links do not survive and are not meant to: session keys live in the outgoing
// guest's private memory. What survives is the host's half — the address book — so the
// first request redials and succeeds.
const resp2 = await request(a.app, bId, new Uint8Array([9, 9]));
assert(resp2.length === 2 && resp2[0] === 9, "A reconnects from the re-seeded address book and requests through the NEW transport");

// And the reverse direction: B dials A on the port it already knew, and reaches A's app
// through the incoming guest.
const resp3 = await request(b.app, aNet.peerId, new Uint8Array([5, 6, 7]));
assert(resp3.length === 3 && resp3[2] === 7, "B reaches A on the unchanged port, through the new guest");

// A downgrade is still refused: standing v2 advanced this author's (author, app) mark,
// and the transport answers to that mark like any other bundle (§12.4).
let refused = false;
try { await a.shell.loadBundleBlob(transportBundleAt(1, transportKeys)); }
catch { refused = true; }
assert(refused, "a lower version from the same author is refused after the upgrade");
assert((await request(a.app, bId, new Uint8Array([4]))).length === 1,
  "…and the refused load left the standing transport serving");

// ── A version that never ran must not consume the claim ──────────────────────────
// Every app's guest is STOOD at load (shell-core.ts), so a v3 that cannot compile dies
// there. If the mark advanced on the way in, the node could not reinstall the transport
// it had — rollback bricked by a failed upgrade. So the mark is the last step of the load.
const brokenGuest = "const nope = ( ;";
let v3Failed = false;
try { await a.shell.loadBundleBlob(transportBundleAt(3, transportKeys, brokenGuest)); }
catch { v3Failed = true; }
assert(v3Failed, "a v3 whose guest cannot compile fails the load");

let v2Reloaded = true;
try { await a.shell.loadBundleBlob(transportBundleAt(2, transportKeys)); }
catch { v2Reloaded = false; }
assert(v2Reloaded, "the known-good v2 reinstalls after the failed v3 — the mark records only what ran");
assert(a.shell.resolve(TRANSPORT_SERVICE) !== null, "…and the reinstalled bundle holds the transport id again");
assert((await request(a.app, bId, new Uint8Array([8, 8]))).length === 2,
  "…and the node is back on the network through it");

// ── A transport that signs no bounds is refused, not run unbounded ───────────────
// Every policy value the guest reads bounds a resource, and an absent one does not fail
// the comparison that applies it — it makes that comparison always false, so a frame cap
// read as `undefined` is a cap silently gone rather than a cap set wrong. The guest
// therefore validates its own config at realm evaluation, which is a failed load.
let noConfigFailed = false;
let noConfigMsg = "";
try { await a.shell.loadBundleBlob(transportBundleAt(3, transportKeys, undefined, null)); }
catch (e) { noConfigFailed = true; noConfigMsg = e.message; }
assert(noConfigFailed && /maxFrameBytes|connsPerPeer|config/.test(noConfigMsg),
  `a transport signing no guest.config fails the load (${noConfigMsg})`);
assert((await request(a.app, bId, new Uint8Array([9]))).length === 1,
  "…and the standing transport is untouched by the refusal");

// ── A mark that cannot be persisted is a failed load ─────────────────────────────
console.log("  an `_net` claimant whose mark cannot be persisted fails the load…");
{
  let broken = false;
  class FlakyStore extends FreshnessMarks {
    persist(json) { if (broken) throw new Error("disk full"); super.persist(json); }
  }
  const store = new FlakyStore();
  const c = await makeNode(fabric.view(), undefined, store);
  assert(c.shell.resolve(TRANSPORT_SERVICE) !== null, "the node stands its transport claimant up normally");

  broken = true;
  let msg = "";
  try { await c.shell.loadBundleBlob(transportBundleAt(2, transportKeys)); } catch (e) { msg = e.message; }
  assert(msg.includes("could not be persisted"), `a bundle whose mark cannot be written fails the load (got: ${msg})`);
  assert(msg.includes("disk full"), "…and the original persist error survives the wrap");
  assert(c.shell.resolve(TRANSPORT_SERVICE)?.startsWith(transportAuthor),
    "nothing of the failed load was kept — the claim went back to the transport that was standing, " +
    "rather than the uncommitted bundle serving on");

  // The mark was rolled back, so the retry is a fresh advance and not a no-op against a
  // store that never got the first one.
  broken = false;
  let reloaded = true;
  try { await c.shell.loadBundleBlob(transportBundleAt(2, transportKeys)); } catch { reloaded = false; }
  assert(reloaded, "the retry against a healthy store lands");
  assert(store.get(transportVerified.author, "transport") === 2, "…and the mark it persists is the one the failed load rolled back");
  c.shell.close();
}

a.shell.close();
b.shell.close();
c.shell.close();
summary("transport bundle smoke");
