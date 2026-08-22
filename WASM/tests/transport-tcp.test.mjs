// Two nodes over REAL node:net sockets — the path the loopback fabric cannot reach.
//
// Everything else in the suite drives the transport over LoopbackChannels, a *framed*
// link where one send is one delivery. A TCP socket is not: it reaches the bundle as an
// unframed RawLink (socket-seam.ts), so the guest's length framer, its two-stage pre-auth
// cap and the reassembly of a message split across segments are exercised only here.
//
// So is the graceful close, which the loopback fabric cannot get wrong: the end-of-stream
// record must be flushed before FIN, or a clean shutdown reads at the far end as the
// truncation that record exists to rule out.
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { testkit } from "./testkit.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

const { loadCrypto, generateKeyPair } = await imp("build/host/crypto-node.js");
const sodium = await loadCrypto();
const { bootShell } = await imp("build/host/shell-core.js");
const { NodeChannelFactory } = await imp("build/host/net-node.js");
const { createSafeRealm } = await imp("build/host/safe-js.js");
const { policyFromJson } = await imp("build/host/policy.js");
const { FreshnessMarks, verifyBundle } = await imp("build/host/bundle.js");
const { ModuleTable } = await imp("build/host/module-table.js");
const { TransportHost } = await imp("build/host/transport-host.js");
const { transportBundleBytes } = await imp("build/host/transport-bundle.js");

const transportBlob = transportBundleBytes();
const transportAuthor = Buffer.from(verifyBundle(sodium, transportBlob).author).toString("hex");
// The app that drives the transport: a request is an app calling the id the transport
// claims, so a test that sends one has to be an app (tests/transport-harness.mjs).
const { harnessAppBlob, harnessAppKey, appRequest, generatorRequest } = await imp("tests/transport-harness.mjs");
const { makeAuthor } = await imp("tests/testkit.mjs");
const appAuthor = makeAuthor(sodium);
const appAuthorHex = Buffer.from(appAuthor.id).toString("hex");
const appKey = harnessAppKey(appAuthor);

const HOST = "127.0.0.1";

async function makeNode(ws = false) {
  const identity = generateKeyPair();
  const policy = policyFromJson(JSON.stringify({
    authors: [transportAuthor, appAuthorHex],
    grants: { link: [transportAuthor] },
  }));
  const transport = new TransportHost({
    identity,
    channels: new NodeChannelFactory(),
    listen: { host: HOST, port: 0 },
    ...(ws ? { wsListen: { host: HOST, port: 0 } } : {}),
    requestDeadlineMs: 2000,
  });
  // A driver INSTANCE, so bootShell wires it and derives the pin from `transportBundle`
  // but leaves the load and the listeners to this test, which starts them by hand below.
  const { shell } = await bootShell({
    sodium, identity,
    modules: new ModuleTable(),
    freshnessStore: new FreshnessMarks(),
    fs: false,
    transport,
    transportBundle: transportBlob,
    createRealm: async (o) => createSafeRealm(o),
    admit: policy,
  });
  await shell.loadBundleBlob(transportBlob);
  await shell.loadBundleBlob(harnessAppBlob(appAuthor));
  return { shell, transport };
}

const { ok, summary } = testkit();
// Report-style: a failed check is logged and counted, and the suite keeps going.
const assert = ok;

console.log("Test: transport bundle frames its own TCP links (unframed RawLink)");

const a = await makeNode();
const b = await makeNode();
const aNet = a.transport, bNet = b.transport;

await aNet.start();
await bNet.start();
assert(aNet.port > 0 && bNet.port > 0, "both nodes bound real TCP listeners");

// Both nodes run the echo app, which also answers a GENERATOR request with a payload
// far larger than the pre-auth cap (8 KiB) — it can only cross once the guest has raised
// its own cap on authentication, and it is certain to arrive as several TCP segments.
const BIG = 512 * 1024;

aNet.addPeerAddr(b.transport.peerId, { host: HOST, port: bNet.port, transport: "tcp" });
await aNet.ready(4000);
assert((await aNet.linkedPeers()).includes(b.transport.peerId), "the AKE completed over a real socket");

const small = await appRequest(a.shell, appKey, b.transport.peerId, new Uint8Array([1, 2, 3, 4]));
assert(small.length === 4 && small[3] === 4, "a small request round-trips through the guest's framer");

// The reassembly case: a response guaranteed to span many segments, checked byte for
// byte. A framer that mishandled a partial length prefix or a split body would either
// hang here or deliver a corrupted message rather than merely a short one.
const big = await appRequest(a.shell, appKey, b.transport.peerId, generatorRequest(BIG, 1));
assert(big.length === BIG, `a ${BIG}-byte response reassembled from many TCP segments`);
let intact = true;
for (let i = 0; i < BIG; i++) if (big[i] !== (i & 0xff)) { intact = false; break; }
assert(intact, "every byte of the multi-segment response survived reassembly");

// Graceful close: B's side must see a clean shutdown, not a truncation. The reason
// code is the guest's own read of how the link ended.
await aNet.close();
await new Promise((r) => setTimeout(r, 200));
assert(true, "closing the dialing node did not wedge the listener");

await bNet.close();

// ── the same thing over RFC 6455 ──────────────────────────────────────────────
// The browser edge, minus the browser: a node dialing another's --ws-listen endpoint runs
// the guest's WsFramer at BOTH ends — the client half sending the upgrade and masking its
// frames, the server half computing the accept value through the bundle's own ws.wasm and
// refusing unmasked client frames. None of it is host code.
console.log("\nTest: the same links framed as RFC 6455 (ws.wasm as a bundle module)");

const c = await makeNode(true);
const d = await makeNode(true);
const cNet = c.transport, dNet = d.transport;
await cNet.start();
await dNet.start();
assert(dNet.wsPort > 0, "the WS listener bound");

// `transport: "ws"` is the whole difference: the host dials the same kind of TCP
// socket and declares a different codec on it.
cNet.addPeerAddr(d.transport.peerId, { host: HOST, port: dNet.wsPort, transport: "ws" });
await cNet.ready(4000);
assert((await cNet.linkedPeers()).includes(d.transport.peerId), "the AKE completed through the WS upgrade");

const wsSmall = await appRequest(c.shell, appKey, d.transport.peerId, new Uint8Array([5, 6, 7]));
assert(wsSmall.length === 3 && wsSmall[2] === 7, "a small request round-trips as masked WS frames");

// Large enough to force 64-bit WS length headers and multi-segment reassembly at once.
const wsBig = await appRequest(c.shell, appKey, d.transport.peerId, generatorRequest(BIG, 7));
assert(wsBig.length === BIG, `a ${BIG}-byte response crossed as WS frames`);
let wsIntact = true;
for (let i = 0; i < BIG; i++) if (wsBig[i] !== ((i * 7) & 0xff)) { wsIntact = false; break; }
assert(wsIntact, "every byte survived WS framing + reassembly");

// Many requests in flight at once — the pipelining case, which is what puts several
// chunks on the socket in one turn. Decoding a WS frame is a module call, so a push
// parks, and the host hands over the next chunk without waiting for it: what keeps the
// two parses from running over one reassembly buffer is the framer's read chain
// (framing.js `push`). Each answer must be the one its own request asked for.
const burst = await Promise.all(
  Array.from({ length: 12 }, (_, i) => appRequest(c.shell, appKey, d.transport.peerId, generatorRequest(1024 + i, 11 + i))));
let burstIntact = burst.length === 12;
burst.forEach((resp, i) => {
  if (resp.length !== 1024 + i) { burstIntact = false; return; }
  for (let j = 0; j < resp.length; j++) if (resp[j] !== ((j * (11 + i)) & 0xff)) { burstIntact = false; return; }
});
assert(burstIntact, "12 concurrent requests each got their OWN answer back, in one piece");

await cNet.close();
await dNet.close();

summary("transport TCP smoke");
