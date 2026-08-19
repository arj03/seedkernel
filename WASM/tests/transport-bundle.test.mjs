// Smoke test: the transport bundle stands up as a shell's network over the
// in-process loopback fabric; two nodes complete the AKE and exchange a typed
// request/response through it. Everything after boot is the bundle's code.
//
// The second half is the claim the whole arrangement rests on: a node **replaces its
// `_net` claimant while running**, while the concrete channel adapter stays on the same
// port. That is what "the protocol is replaceable without a fork" means in
// practice.
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { testkit, makeAuthor } from "./testkit.mjs";
// The same assembler the build signs through, imported rather than mirrored: these
// bundles must be signed over the byte-for-byte guest production signs, and a second copy
// of the part order here would quietly sign a different program (scripts/guest-source.mjs).
import { readGuestSource } from "../scripts/guest-source.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

const { loadCrypto, generateKeyPair } = await imp("build/host/crypto-node.js");
const sodium = await loadCrypto();
const { createShell } = await imp("build/host/shell-core.js");
const { LoopbackChannels } = await imp("tests/loopback-channels.mjs");
const { createSafeRealm } = await imp("build/host/safe-js.js");
const { policyFromJson } = await imp("build/host/policy.js");
const { FreshnessMarks, signManifest, hybridAuthorId, hybridAuthorKeysFromSeed, packBundle, MANIFEST_FILE, verifyBundle } = await imp("build/host/bundle.js");
const { ModuleTable } = await imp("build/host/module-table.js");
const { TransportHost } = await imp("build/host/transport-host.js");
const { GUEST_ABI_VERSION, NET_PROTOCOL } = await imp("build/core/domains.js");
// The app that drives the transport: there is no host-side request facade left, so a
// request is an app calling the id the transport claims (tests/transport-harness.mjs).
const { harnessAppBlob, appRequest } = await imp("tests/transport-harness.mjs");
const { TRANSPORT_BUNDLE_B64 } = await imp("build/host/transport-bundle.js");

const transportBlob = Uint8Array.from(Buffer.from(TRANSPORT_BUNDLE_B64, "base64"));
const { ok, summary } = testkit();
// Report-style: a failed check is logged and counted, and the suite keeps going.
const assert = ok;
// Read out of the artifact rather than restated: a hard-coded author is drift waiting
// to happen, and rebuilding the bundle with a different key is a supported thing to do.
const transportVerified = verifyBundle(sodium, transportBlob);
const transportAuthor = Buffer.from(transportVerified.author).toString("hex");
// The artifact is PQ-signed (§14.1) — there is one suite and it is hybrid, so the id
// policy pins is a key-set hash and both keys are on the verified result.
assert(transportVerified.authorKeys.mlDsa !== undefined,
  "the shipped transport bundle carries the ML-DSA-65 public key of its signing key set");

// The build script must derive the author's key set with its OWN copy of that derivation,
// since it runs before build/ exists, so this pins the copy against
// `hybridAuthorKeysFromSeed` — the one every other publisher calls. A drift fails no
// build: it silently re-identifies this artifact's author and invalidates every
// operator's pinned id. The seed is per-clone and gitignored, written by the build.
const transportSeed = Uint8Array.from(Buffer.from(
  readFileSync(join(root, "transport", "author.key"), "utf8").trim(), "hex"));
const transportKeys = hybridAuthorKeysFromSeed(sodium, transportSeed);
const derivedTransportAuthor = Buffer.from(
  hybridAuthorId(sodium, transportKeys.ed.publicKey, transportKeys.mlDsa.publicKey)).toString("hex");
assert(derivedTransportAuthor === transportAuthor,
  "the shared seed→key-set derivation reproduces the shipped bundle's author id");

// `guestSource` overrides the artifact's guest — the only caller that passes one hands in
// a program that cannot compile, to fail the load at the point where the DRIVER stands
// rather than at verify.
function transportBundleAt(version, keys, guestSource) {
  const guest = guestSource ?? new Uint8Array(readGuestSource());
  const wsWasm = new Uint8Array(readFileSync(join(root, "build/ws.wasm")));
  const manifest = {
    app: "transport", version,
    modules: [{ name: "ws", hash: Buffer.from(sodium.crypto_generichash(32, wsWasm)).toString("hex") }],
    // The reserved id the transport claims (§12.10) — mirror of the artifact manifest.
    protocols: [NET_PROTOCOL],
    guest: {
      hash: Buffer.from(sodium.crypto_generichash(32, guest)).toString("hex"),
      // Read, never restated: a hardcoded number here would pass a test that the
      // production loader would refuse the moment the seam revved (§12.4).
      abi: GUEST_ABI_VERSION,
      // Exactly the authorities the transport guest holds — a mirror of the artifact
      // manifest (scripts/build-transport-bundle.mjs). `link/*` is what carries the
      // `link` privilege the admission dispatch reads (§12.5).
      requires: [
        "node/sign", "node/verify", "node/random",
        "link/config", "link/open", "link/send", "link/close", "link/stat",
        "timer/arm", "timer/clear",
        "_host",
      ],
    },
  };
  const env = signManifest(sodium, keys, manifest);
  return packBundle({ [MANIFEST_FILE]: env, "guest.js": guest, "ws.wasm": wsWasm });
}

// One app author for both nodes: each loads the echo app, so a request from either
// reaches a handler on the other.
const appAuthor = makeAuthor(sodium);
const appAuthorHex = Buffer.from(appAuthor.id).toString("hex");
const appKey = `${appAuthorHex}:harness`;

/** One request out of `shell`, through its app, to `to` — the path a deployment uses. */
async function request(shell, to, payload) {
  return appRequest(shell, appKey, to, payload);
}

async function makeNode(channels, listen, freshnessStore = new FreshnessMarks()) {
  const identity = generateKeyPair();
  const policy = policyFromJson(JSON.stringify({
    authors: [transportAuthor, appAuthorHex],
    grants: { link: [transportAuthor] },
  }));
  const transport = new TransportHost({ identity, channels, listen, requestDeadlineMs: 800 });
  const shell = createShell({
    platform: {
      sodium, identity,
      modules: new ModuleTable(),
      freshnessStore,
      transportHost: transport,
      createRealm: async (o) => createSafeRealm(o),
    },
    admit: policy,
  });
  await shell.loadBundleBlob(transportBlob);
  await shell.loadBundleBlob(harnessAppBlob(appAuthor));
  return { shell, transport };
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

console.log("  starting listeners…");
await aNet.start();
await bNet.start();
assert(aNet.port > 0 && bNet.port > 0, "both nodes bound loopback listeners");

// Each node runs the echo app, so both directions work — the upgrade below has to be
// checked both ways: A dialing out through the new transport, and B reaching A.
aNet.addPeerAddr(bId, { host: "loopback", port: bNet.port, transport: "tcp" });
await aNet.ready(2000);
assert((await aNet.linkedPeers()).includes(bId), "A authenticated B over loopback (AKE ran)");

const resp = await request(b.shell, aNet.peerId, new Uint8Array([1, 2, 3, 4]));
assert(resp.length === 4 && resp[3] === 4, "B's request to A echoed back through the record layer");

// ── The upgrade: swap A's transport while it is running and linked ───────────────
//
// An update replaces its own complete slot atomically. The claim and host adapter stay
// stable while the realm and its private session state are replaced.
console.log("  upgrading A's transport in place…");
const oldPort = aNet.port;
const oldPeerId = aNet.peerId;
const oldClaimant = a.shell.resolve(NET_PROTOCOL);
await a.shell.loadBundleBlob(transportBundleAt(2, transportKeys));

assert(a.shell.resolve(NET_PROTOCOL) === oldClaimant, "the update retained its own transport claim");
assert(aNet.isClosed === false, "the adapter is neither closed nor leaked by the slot replacement");
assert(aNet.port === oldPort, "the node stayed on the SAME port its peers hold");
assert(aNet.peerId === oldPeerId, "the node identity is the host's, untouched by the swap");

// Live links do not survive and are not meant to: session keys live in the outgoing
// guest's private memory. What survives is the host's half — the address book — so the
// first request redials and succeeds.
const resp2 = await request(a.shell, bId, new Uint8Array([9, 9]));
assert(resp2.length === 2 && resp2[0] === 9, "A reconnects from the re-seeded address book and requests through the NEW transport");

// And the reverse direction: B dials A on the port it already knew, and reaches A's app
// through the incoming guest.
const resp3 = await request(b.shell, aNet.peerId, new Uint8Array([5, 6, 7]));
assert(resp3.length === 3 && resp3[2] === 7, "B reaches A on the unchanged port, through the new guest");

// A downgrade is still refused: standing v2 advanced this author's (author, app) mark,
// and the transport answers to that mark like any other bundle (§12.4).
let refused = false;
try { await a.shell.loadBundleBlob(transportBundleAt(1, transportKeys)); }
catch { refused = true; }
assert(refused, "a lower version from the same author is refused after the upgrade");
assert((await request(a.shell, bId, new Uint8Array([4]))).length === 1,
  "…and the refused load left the standing transport serving");

// ── A version that never ran must not consume the claim ──────────────────────────
// Every app's guest is STOOD at load (shell-core.ts), so a v3 that cannot compile dies
// there. A mark advanced on the way in would leave the node unable to reinstall the
// transport it had: every version an operator can reach would sit below a floor a bundle
// that never executed a line raised — rollback bricked by a failed upgrade. So the mark is
// the last step of the load, after the guest stands.
const brokenGuest = new TextEncoder().encode("const nope = ( ;");
let v3Failed = false;
try { await a.shell.loadBundleBlob(transportBundleAt(3, transportKeys, brokenGuest)); }
catch { v3Failed = true; }
assert(v3Failed, "a v3 whose guest cannot compile fails the load");

let v2Reloaded = true;
try { await a.shell.loadBundleBlob(transportBundleAt(2, transportKeys)); }
catch { v2Reloaded = false; }
assert(v2Reloaded, "the known-good v2 reinstalls after the failed v3 — the mark records only what ran");
assert(a.shell.resolve(NET_PROTOCOL) !== null, "…and the reinstalled bundle holds the transport id again");
assert((await request(a.shell, bId, new Uint8Array([8, 8]))).length === 2,
  "…and the node is back on the network through it");

// ── A mark that cannot be persisted is a failed load ─────────────────────────────
console.log("  an `_net` claimant whose mark cannot be persisted fails the load…");
{
  let broken = false;
  class FlakyStore extends FreshnessMarks {
    persist(json) { if (broken) throw new Error("disk full"); super.persist(json); }
  }
  const store = new FlakyStore();
  const c = await makeNode(fabric.view(), undefined, store);
  assert(c.shell.resolve(NET_PROTOCOL) !== null, "the node stands its `_net` claimant up normally");

  broken = true;
  let msg = "";
  try { await c.shell.loadBundleBlob(transportBundleAt(2, transportKeys)); } catch (e) { msg = e.message; }
  assert(msg.includes("could not be persisted"), `a bundle whose mark cannot be written fails the load (got: ${msg})`);
  assert(msg.includes("disk full"), "…and the original persist error survives the wrap");
  assert(c.shell.resolve(NET_PROTOCOL)?.startsWith(transportAuthor),
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
summary("transport bundle smoke");
