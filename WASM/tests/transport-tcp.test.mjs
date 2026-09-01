// Two nodes over REAL node:net sockets — the path the loopback fabric cannot reach. A TCP
// socket reaches the bundle as an UNframed RawLink (socket-seam.ts), where the loopback
// fabric is a framed link (one send = one delivery), so the guest's length framer, its
// two-stage pre-auth cap and the reassembly of a message split across segments are
// exercised only here — as is the graceful close (the end-of-stream record must flush
// before FIN, or a clean shutdown reads as the truncation that record exists to rule out).
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
const { transportBundleBytes } = await imp("build/host/transport-bundle.js");

const transportBlob = transportBundleBytes();
const transportAuthor = Buffer.from(verifyBundle(sodium, transportBlob).author).toString("hex");
// The app that drives the transport: a request is an app calling the id the transport
// claims, so a test that sends one has to be an app (tests/transport-harness.mjs).
const { harnessAppBlob, appRequest, generatorRequest, addr, ready, linkedPeers } = await imp("tests/transport-harness.mjs");
const { makeAuthor } = await imp("tests/testkit.mjs");
const appAuthor = makeAuthor(sodium);
const appAuthorHex = Buffer.from(appAuthor.id).toString("hex");

const HOST = "127.0.0.1";

async function makeNode(ws = false, extraConfig = {}) {
  const identity = generateKeyPair();
  const policy = policyFromJson(JSON.stringify({
    authors: [transportAuthor, appAuthorHex],
    grants: { link: [transportAuthor] },
  }));
  const transportOptions = {
    channels: new NodeChannelFactory(),
    listen: { host: HOST, port: 0 },
    ...(ws ? { wsListen: { host: HOST, port: 0 } } : {}),
    load: false,
    bundle: transportBlob,
  };
  const transportConfig = { requestDeadlineMs: 2000, ...extraConfig };
  // bootShell owns the adapter but leaves the load and listeners to this test, which
  // starts them by hand below.
  const { shell, transport } = await bootShell({
    sodium, identity,
    modules: new ModuleTable(),
    freshnessStore: new FreshnessMarks(),
    fs: false,
    transport: transportOptions,
    createRealm: async (o) => createSafeRealm(o),
    admit: policy,
  });
  await shell.loadBundleBlob(transportBlob, { localConfig: transportConfig });
  const app = await shell.loadBundleBlob(harnessAppBlob(appAuthor));
  // The node's own channel key, hex. Read off the identity this factory minted rather than
  // asked of the driver: it is the same `toHex(identity.publicKey)` every caller already
  // holds, and the driver has nothing to say about peers any more (core/socket-seam.ts).
  return { shell, transport, app, peerId: Buffer.from(identity.publicKey).toString("hex") };
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

// The listener's port is only known now, so the peer is taught to the running occupant
// rather than named in its load config — the same `addr` op either path ends in.
await addr(a, b.peerId, `tcp://${HOST}:${bNet.port}`);
await ready(a, 4000);
assert((await linkedPeers(a)).includes(b.peerId), "the AKE completed over a real socket");

const small = await appRequest(a.app, b.peerId, new Uint8Array([1, 2, 3, 4]));
assert(small.length === 4 && small[3] === 4, "a small request round-trips through the guest's framer");

// The reassembly case: a response guaranteed to span many segments, checked byte for
// byte. A framer that mishandled a partial length prefix or a split body would either
// hang here or deliver a corrupted message rather than merely a short one.
const big = await appRequest(a.app, b.peerId, generatorRequest(BIG, 1));
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
// the guest's WsFramer at BOTH ends — client half masking its frames, server half computing
// the accept value through the bundle's own ws.wasm and refusing unmasked client frames.
// None of it is host code.
console.log("\nTest: the same links framed as RFC 6455 (ws.wasm as a bundle module)");

const c = await makeNode(true);
const d = await makeNode(true);
const cNet = c.transport, dNet = d.transport;
await cNet.start();
await dNet.start();
assert(dNet.wsPort > 0, "the WS listener bound");

// The `ws://` scheme is the whole difference: the destination string sends the host's
// factory at the same kind of TCP socket, which declares a different codec on it.
await addr(c, d.peerId, `ws://${HOST}:${dNet.wsPort}`);
await ready(c, 4000);
assert((await linkedPeers(c)).includes(d.peerId), "the AKE completed through the WS upgrade");

const wsSmall = await appRequest(c.app, d.peerId, new Uint8Array([5, 6, 7]));
assert(wsSmall.length === 3 && wsSmall[2] === 7, "a small request round-trips as masked WS frames");

// Large enough to force 64-bit WS length headers and multi-segment reassembly at once.
const wsBig = await appRequest(c.app, d.peerId, generatorRequest(BIG, 7));
assert(wsBig.length === BIG, `a ${BIG}-byte response crossed as WS frames`);
let wsIntact = true;
for (let i = 0; i < BIG; i++) if (wsBig[i] !== ((i * 7) & 0xff)) { wsIntact = false; break; }
assert(wsIntact, "every byte survived WS framing + reassembly");

// Many requests in flight at once — the pipelining case, which puts several chunks on the
// socket in one turn. Decoding a WS frame is a module call, so a push parks and the host
// hands over the next chunk without waiting for it: what keeps the two parses from running
// over one reassembly buffer is the framer's read chain (framing.js `push`).
const burst = await Promise.all(
  Array.from({ length: 12 }, (_, i) => appRequest(c.app, d.peerId, generatorRequest(1024 + i, 11 + i))));
let burstIntact = burst.length === 12;
burst.forEach((resp, i) => {
  if (resp.length !== 1024 + i) { burstIntact = false; return; }
  for (let j = 0; j < resp.length; j++) if (resp[j] !== ((j * (11 + i)) & 0xff)) { burstIntact = false; return; }
});
assert(burstIntact, "12 concurrent requests each got their OWN answer back, in one piece");

await cNet.close();
await dNet.close();

// ── a WS upgrade that never lands must still meet its deadline ────────────────
// The codec parks every write until the upgrade completes, and a teardown queued behind
// that park would never run: no close, and the slot and raw link held until the socket
// happened to die on its own. So the peer here does the one thing that defeats every
// other clock — it accepts, says just enough to look alive (which clears the host's own
// pre-speech read deadline), and then stops. Only the guest's handshake deadline is left.
console.log("\nTest: a WS peer that accepts, half-speaks and stalls still meets the deadline");

const { createServer } = await import("node:net");
let stalledClosed = false;
const stalling = createServer((sock) => {
  sock.on("close", () => { stalledClosed = true; });
  sock.on("error", () => { /* the node hangs up on us; that is the point */ });
  sock.resume(); // a paused socket never reads, so it would never see the hang-up either
  // A partial head: never a complete HTTP response, so `upgrade()` keeps returning -1.
  sock.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n");
});
await new Promise((resolve) => stalling.listen(0, HOST, resolve));

const e = await makeNode(false, { handshakeTimeoutMs: 500 });
await e.transport.start();
await addr(e, "00".repeat(32), `ws://${HOST}:${stalling.address().port}`);
// Any send is enough to make the address book dial.
appRequest(e.app, "00".repeat(32), new Uint8Array([1])).catch(() => {});

const deadline = Date.now() + 6000;
while (!stalledClosed && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
assert(stalledClosed, "the handshake deadline closed a link parked on an upgrade that never came");

await e.transport.close();
await new Promise((resolve) => stalling.close(resolve));

summary("transport TCP smoke");
