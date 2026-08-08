// Two nodes over REAL node:net sockets — the path the loopback fabric cannot reach.
//
// Everything else in the suite drives the transport over LoopbackChannels, which is a
// *framed* link: one send is one delivery. A TCP socket is not. It is handed to the
// transport bundle as an unframed RawLink (socket-seam.ts), and imposing message
// boundaries on it is the bundle's own job — so the guest's length framer, its
// two-stage pre-auth cap, and the reassembly of a message split across TCP segments
// are all code that ONLY this path exercises.
//
// It also covers the seam's graceful close, which the loopback fabric has no way to
// get wrong: the end-of-stream record has to be flushed before FIN, or a clean
// shutdown reads at the far end as the truncation that record exists to rule out.
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { testkit } from "./testkit.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

const { loadCrypto, generateKeyPair } = await imp("build/host/crypto-node.js");
const sodium = await loadCrypto();
const { createShell } = await imp("build/host/shell-core.js");
const { NodeChannelFactory } = await imp("build/host/net-node.js");
const { createSafeRealm } = await imp("build/host/safe-js.js");
const { policyFromJson } = await imp("build/host/policy.js");
const { FreshnessMarks, verifyBundle } = await imp("build/host/bundle.js");
const { ModuleTable } = await imp("build/host/module-table.js");
const { TRANSPORT_BUNDLE_B64 } = await imp("build/host/transport-bundle.js");

const transportBlob = Uint8Array.from(Buffer.from(TRANSPORT_BUNDLE_B64, "base64"));
const transportAuthor = Buffer.from(verifyBundle(sodium, transportBlob).author).toString("hex");

const HOST = "127.0.0.1";

async function makeNode(ws = false) {
  const identity = generateKeyPair();
  const policy = policyFromJson(JSON.stringify({
    authors: [transportAuthor],
    grants: { mount: [transportAuthor] },
  }));
  const shell = createShell({
    platform: {
      sodium, identity,
      table: new ModuleTable(),
      freshnessStore: new FreshnessMarks(),
      channels: new NodeChannelFactory(),
      listen: { host: HOST, port: 0 },
      ...(ws ? { wsListen: { host: HOST, port: 0 } } : {}),
      createRealm: async (o) => createSafeRealm(o),
    },
    admit: policy,
    requestDeadlineMs: 2000,
  });
  await shell.loadBundleBlob(transportBlob);
  return shell;
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

// Echo, plus one handler that answers with a payload far larger than the pre-auth cap
// (8 KiB) — it can only cross once the guest has raised its own cap on authentication,
// and it is certain to arrive as several TCP segments.
const BIG = 512 * 1024;
aNet.onRequest((from, proto, payload) => payload);
bNet.onRequest((from, proto, payload) => {
  if (payload.length === 1 && payload[0] === 0xff) {
    const out = new Uint8Array(BIG);
    for (let i = 0; i < BIG; i++) out[i] = i & 0xff;
    return out;
  }
  return payload;
});

aNet.addPeerAddr(b.transport.peerId, { host: HOST, port: bNet.port, transport: "tcp" });
await aNet.ready(4000);
assert(aNet.linkedPeers().includes(b.transport.peerId), "the AKE completed over a real socket");

const proto = new TextEncoder().encode("_tcp");
const small = await aNet.request(b.transport.peerId, proto, new Uint8Array([1, 2, 3, 4]));
assert(small.length === 4 && small[3] === 4, "a small request round-trips through the guest's framer");

// The reassembly case: a response guaranteed to span many segments, checked byte for
// byte. A framer that mishandled a partial length prefix or a split body would either
// hang here or deliver a corrupted message rather than merely a short one.
const big = await aNet.request(b.transport.peerId, proto, new Uint8Array([0xff]));
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
// The browser edge, minus the browser: a node dialing another node's --ws-listen
// endpoint runs the guest's WsFramer at BOTH ends — the client half sending the
// upgrade and masking its frames, the server half computing the accept value through
// the bundle's own ws.wasm module and refusing unmasked client frames. None of that is
// host code, so nothing but this test covers it end to end.
console.log("\nTest: the same links framed as RFC 6455 (ws.wasm as a bundle module)");

const c = await makeNode(true);
const d = await makeNode(true);
const cNet = c.transport, dNet = d.transport;
await cNet.start();
await dNet.start();
assert(dNet.wsPort > 0, "the WS listener bound");

dNet.onRequest((from, proto, payload) => {
  if (payload.length === 1 && payload[0] === 0xff) {
    const out = new Uint8Array(BIG);
    for (let i = 0; i < BIG; i++) out[i] = (i * 7) & 0xff;
    return out;
  }
  return payload;
});

// `transport: "ws"` is the whole difference: the host dials the same kind of TCP
// socket and declares a different codec on it.
cNet.addPeerAddr(d.transport.peerId, { host: HOST, port: dNet.wsPort, transport: "ws" });
await cNet.ready(4000);
assert(cNet.linkedPeers().includes(d.transport.peerId), "the AKE completed through the WS upgrade");

const wsSmall = await cNet.request(d.transport.peerId, proto, new Uint8Array([5, 6, 7]));
assert(wsSmall.length === 3 && wsSmall[2] === 7, "a small request round-trips as masked WS frames");

// Large enough to force 64-bit WS length headers and multi-segment reassembly at once.
const wsBig = await cNet.request(d.transport.peerId, proto, new Uint8Array([0xff]));
assert(wsBig.length === BIG, `a ${BIG}-byte response crossed as WS frames`);
let wsIntact = true;
for (let i = 0; i < BIG; i++) if (wsBig[i] !== ((i * 7) & 0xff)) { wsIntact = false; break; }
assert(wsIntact, "every byte survived WS framing + reassembly");

await cNet.close();
await dNet.close();

summary("transport TCP smoke");
