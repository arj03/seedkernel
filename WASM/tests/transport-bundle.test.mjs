// Smoke test: the transport bundle stands up as a shell's network over the
// in-process loopback fabric; two nodes complete the AKE and exchange a typed
// request/response through it. Everything after boot is the bundle's code.
//
// The second half is the claim the whole arrangement rests on: a node **replaces its
// transport while running**, through the explicit transport mount, and comes back on
// the same port. That is what "the protocol is replaceable without a fork" means in
// practice.
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { testkit } from "./testkit.mjs";
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
const { FreshnessMarks, signManifest, packBundle, MANIFEST_FILE, verifyBundle } = await imp("build/host/bundle.js");
const { ModuleTable } = await imp("build/host/module-table.js");
const { GUEST_ABI_VERSION } = await imp("build/core/domains.js");
const { TRANSPORT_BUNDLE_B64 } = await imp("build/host/transport-bundle.js");

const transportBlob = Uint8Array.from(Buffer.from(TRANSPORT_BUNDLE_B64, "base64"));
const { ok, summary } = testkit();
// Report-style: a failed check is logged and counted, and the suite keeps going.
const assert = ok;
// Read out of the artifact rather than restated: a hard-coded author is drift waiting
// to happen, and rebuilding the bundle with a different key is a supported thing to do.
const transportVerified = verifyBundle(sodium, transportBlob);
const transportAuthor = Buffer.from(transportVerified.author).toString("hex");
// The artifact is PQ-signed by default (§14.1): the id policy pins under `0x02` is a
// key-set hash, so a regression to the genesis suite would change every pin silently.
assert(transportVerified.suite === 0x02, "the shipped transport bundle is hybrid-signed (suite 0x02)");
assert(transportVerified.authorKeys.mlDsa !== undefined, "…and carries the ML-DSA-65 public key");

// A SECOND transport, version 2, signed by a different author — the realistic upgrade
// shape, and the one that exercises both admission gates at once: the `mount` grant
// must list the new author, and the freshness floor (which v1 set to 1) must be
// cleared by the new version. Same guest program, because what is under test is the
// swap and not a different protocol.
const upgradeKeys = (() => {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
})();
const upgradeAuthor = Buffer.from(upgradeKeys.publicKey).toString("hex");

// `guestSource` overrides the artifact's guest — the only caller that passes one hands in
// a program that cannot compile, to fail the load at the point where the DRIVER stands
// rather than at verify.
function transportBundleAt(version, keys, guestSource) {
  const guest = guestSource ?? new Uint8Array(readGuestSource());
  const wsWasm = new Uint8Array(readFileSync(join(root, "build/ws.wasm")));
  const manifest = {
    app: "transport", version,
    modules: [{ name: "ws", hash: Buffer.from(sodium.crypto_generichash(32, wsWasm)).toString("hex") }],
    guest: {
      hash: Buffer.from(sodium.crypto_generichash(32, guest)).toString("hex"),
      // Read, never restated: a hardcoded number here would pass a test that the
      // production loader would refuse the moment the seam revved (§12.4).
      abi: GUEST_ABI_VERSION,
      // Exactly the authorities the transport guest (transport/src) holds — mirror of
      // the artifact manifest (scripts/build-transport-bundle.mjs). Its `crypto/*` and its own module name
      // calls are not grants and are not declared. `link/*` + `transport/*` are the two
      // mount halves the admission dispatch reads (§12.5).
      requires: [
        "node/sign", "node/verify", "node/random",
        "link/open", "link/send", "link/close", "link/stat",
        "timer/arm", "timer/clear",
        "transport/deliver", "transport/settle", "transport/link-auth",
        "transport/peer-edge", "transport/ready", "transport/link-down",
      ],
    },
  };
  const env = signManifest(sodium, keys.privateKey, keys.publicKey, manifest);
  return packBundle({ [MANIFEST_FILE]: env, "guest.js": guest, "ws.wasm": wsWasm });
}

async function makeNode(channels, listen) {
  const identity = generateKeyPair();
  const policy = policyFromJson(JSON.stringify({
    authors: [transportAuthor, upgradeAuthor],
    grants: { mount: [transportAuthor, upgradeAuthor] },
  }));
  const shell = createShell({
    platform: {
      sodium, identity,
      table: new ModuleTable(),
      freshnessStore: new FreshnessMarks(),
      channels, listen,
      createRealm: async (o) => createSafeRealm(o),
    },
    admit: policy,
    requestDeadlineMs: 800,
  });
  await shell.loadBundleBlob(transportBlob);
  return shell;
}

console.log("Test: transport bundle drives two nodes over loopback");

const fabric = new LoopbackChannels();
const listen = { host: "loopback", port: 0 };
// A per-node VIEW of the shared fabric, not the fabric itself: an upgrade closes the
// outgoing driver, and a whole-fabric close would unbind the other node's listener too.
const a = await makeNode(fabric.view(), listen);
const b = await makeNode(fabric.view(), listen);
const aNet = a.net;
const bNet = b.net;
const bId = b.transport.peerId;

console.log("  starting listeners…");
await aNet.start();
await bNet.start();
assert(aNet.port > 0 && bNet.port > 0, "both nodes bound loopback listeners");

// Each node echoes whatever the other sends it. Both directions are wired because the
// upgrade below has to be checked both ways: A dialing out through the new transport,
// and B reaching A's re-wired inbound sink.
aNet.onRequest((from, proto, payload) => payload);
bNet.onRequest((from, proto, payload) => payload);
aNet.addPeerAddr(bId, { host: "loopback", port: bNet.port, transport: "tcp" });
await aNet.ready(2000);
assert(aNet.linkedPeers().includes(bId), "A authenticated B over loopback (AKE ran)");

const proto = new TextEncoder().encode("_smoke");
const resp = await bNet.request(aNet.peerId, proto, new Uint8Array([1, 2, 3, 4]));
assert(resp.length === 4 && resp[3] === 4, "B's request to A echoed back through the record layer");

// ── The upgrade: swap A's transport while it is running and linked ───────────────
console.log("  upgrading A's transport in place…");
const oldDriver = a.transport;
const oldPort = aNet.port;
await a.loadBundleBlob(transportBundleAt(2, upgradeKeys));
const aNet2 = a.net;

assert(aNet2 !== oldDriver, "the standing transport was replaced");
// The old driver is CLOSED, not merely dropped: its realm is gone, its links are torn
// down and — the part that would fail loudly on a real socket — its listener is
// released rather than left bound for the life of the process.
assert(oldDriver.isClosed === true, "the outgoing driver was closed, not leaked");
assert(aNet2.port === oldPort, "the node came back on the SAME port its peers hold");
assert(a.net.peerId === aNet.peerId, "the node identity is the host's, untouched by the swap");

// Live links do not survive and are not meant to: session keys live in the outgoing
// guest's private memory. What survives is the host's half — the address book — so the
// first request redials and succeeds.
const resp2 = await a.transport.request(bId, proto, new Uint8Array([9, 9]));
assert(resp2.length === 2 && resp2[0] === 9, "A reconnects from the carried address book and requests through the NEW transport");

// And the reverse direction: B dials A on the port it already knew, and reaches the
// dispatch sink the upgrade re-wired.
const resp3 = await bNet.request(aNet.peerId, proto, new Uint8Array([5, 6, 7]));
assert(resp3.length === 3 && resp3[2] === 7, "B reaches A on the unchanged port, through the re-wired sink");

// A downgrade is still refused: standing v2 advanced this author's (author, app) mark,
// and the mounted transport answers to that mark like any other bundle (§12.4).
let refused = false;
try { await a.loadBundleBlob(transportBundleAt(1, upgradeKeys)); }
catch { refused = true; }
assert(refused, "a lower version from the same author is refused after the upgrade");
assert(a.net === aNet2, "…and the refused load left the standing transport in place");

// ── A version that never ran must not consume the slot ───────────────────────────
// A transport mount's load is not done when its modules bind — it is done when its DRIVER
// STANDS, one step later. A v3 whose guest cannot compile dies at that step. If the mark
// had been advanced on the way in, the node would keep serving the transport it has and
// yet never be able to reinstall it: every version it can reach now sits below a mark
// that a bundle which never executed a line raised. That is rollback bricked by a failed
// upgrade — the exact outcome the downgrade refusals exist to prevent — so the mark is
// deferred until the driver is up (bundle.ts `deferMark`).
const brokenGuest = new TextEncoder().encode("const nope = ( ;");
let v3Failed = false;
try { await a.loadBundleBlob(transportBundleAt(3, upgradeKeys, brokenGuest)); }
catch { v3Failed = true; }
assert(v3Failed, "a v3 whose guest cannot compile fails the load");
assert(a.net === aNet2, "…and the node keeps the transport that was standing");

let v2Reloaded = true;
try { await a.loadBundleBlob(transportBundleAt(2, upgradeKeys)); }
catch { v2Reloaded = false; }
assert(v2Reloaded, "the known-good v2 reinstalls after the failed v3 — the mark records only what loaded");
assert(a.net !== aNet2, "…as a genuinely re-stood driver, not the old one left in place");

a.close();
b.close();
summary("transport bundle smoke");
