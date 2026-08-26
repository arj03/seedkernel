// net-rtc.test.mjs — RtcNetwork's untrusted signaling boundary and speculative-entry cap
// (§12.6.1). A signaling endpoint can name arbitrary `from` values in hellos AND in SDP
// offers, and every entry carries an RTCPeerConnection — so decoding precedes policy and
// every path that CREATES an entry answers to the same MAX_UNAUTHED_PEERS bound. Pinned with
// stubs: the browser globals are referenced only inside methods, so net-rtc runs under Node.
// Run after `npm run build`.

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);
const rtc = await imp("build/host/net-rtc.js");
const { RtcChannel, RtcNetwork, RTC_CHUNK_BYTES } = rtc;
import { testkit } from "./testkit.mjs";

const { test, assert, summary } = testkit();

// The cap the transport relay is bound to (net-rtc.ts). A peer with an entry
// already — pre- or post-auth — is never counted against it, so a genuine fleet
// is unconstrained; only NEW speculative entries are.
const MAX_UNAUTHED_PEERS = 256;
const peerId = (n) => String(n).padStart(64, "0");

console.log("\nRtcNetwork signaling boundary and speculative-entry cap (§12.6.1)\n");

await test("net-rtc exports the signaling seam, not a WebSocket relay implementation", async () => {
  assert(!("relaySignaling" in rtc), "the kernel must not ship a rendezvous wire implementation");
});

await test("RtcNetwork validates opaque signaling messages before admitting them", async () => {
  let receive = () => {};
  let admitted = 0;
  let pcs = 0;
  const sent = [];
  const signaling = {
    send(msg) { sent.push(msg); },
    onMessage(cb) { receive = cb; },
    close() {},
  };
  const ownId = peerId(0);
  const net = new RtcNetwork({
    driver: {
      peerId: ownId,
      setPeerHooks() {},
      openLink() { return { linkId: 1, send() {}, close() {} }; },
    },
    signaling,
    admitPeer() { admitted++; return true; },
    peerConnectionFactory: () => {
      pcs++;
      return {
        signalingState: "stable",
        remoteDescription: null,
        addEventListener() {},
        createDataChannel() { return { binaryType: "arraybuffer", send() {}, close() {}, addEventListener() {} }; },
        async setRemoteDescription() {},
        async setLocalDescription() {},
        async addIceCandidate() {},
        close() {},
      };
    },
  });

  const malformed = [
    null,
    "hello",
    [],
    {},
    { type: "hello", from: "not-a-peer" },
    { type: "hello", from: peerId(1), to: 7 },
    { type: "sdp", from: peerId(1) },
    { type: "sdp", from: peerId(1), sdp: { type: "bogus", sdp: "x" } },
    { type: "ice", from: peerId(1) },
    { type: "ice", from: peerId(1), candidate: { candidate: "x", sdpMLineIndex: -1 } },
  ];
  for (const msg of malformed) await receive(msg);
  assert(admitted === 0, `malformed messages must be dropped before policy (got ${admitted})`);
  assert(pcs === 0 && net.peers.size === 0, "malformed messages must not allocate peer connections");

  await receive({ type: "hello", from: peerId(1) });
  assert(admitted === 1 && pcs === 1, "a valid opaque hello must reach policy and create one peer");
  assert(sent.length === 1 && sent[0].type === "hello" && sent[0].to === peerId(1),
    "a valid broadcast hello must receive one directed reply");
  net.close();
});

await test("RtcChannel exposes a length-framed stream and caps physical messages", async () => {
  const listeners = new Map();
  const sent = [];
  const dc = {
    binaryType: "",
    bufferedAmount: 0,
    send(bytes) { sent.push(Uint8Array.from(bytes)); },
    close() {},
    addEventListener(type, cb) { listeners.set(type, cb); },
  };
  const channel = new RtcChannel(dc);
  assert(channel.framing === 1, "RTC bytes must run through the transport's LENGTH framer");
  listeners.get("open")();
  const bytes = new Uint8Array(RTC_CHUNK_BYTES * 2 + 7).fill(0x5a);
  channel.send(bytes);
  assert(sent.length === 3, `a two-chunk-plus-tail write must make 3 messages, got ${sent.length}`);
  assert(sent[0].length === RTC_CHUNK_BYTES && sent[1].length === RTC_CHUNK_BYTES && sent[2].length === 7,
    `physical messages must be capped at ${RTC_CHUNK_BYTES} bytes`);
  assert(sent.every((part) => part.every((byte) => byte === 0x5a)), "chunking must preserve every byte");
  channel.close();
});

await test("RtcChannel fails closed when a chunked write throws after a prefix", async () => {
  const listeners = new Map();
  let writes = 0, closes = 0, failed = 0;
  const dc = {
    binaryType: "",
    bufferedAmount: 0,
    send() {
      writes++;
      if (writes === 2) throw new Error("SCTP buffer full");
    },
    close() { closes++; },
    addEventListener(type, cb) { listeners.set(type, cb); },
  };
  const channel = new RtcChannel(dc);
  channel.onClose(() => { failed++; });
  listeners.get("open")();
  channel.send(new Uint8Array(RTC_CHUNK_BYTES * 2 + 1));
  assert(writes === 2, `the throwing second chunk must stop the write, got ${writes} attempts`);
  assert(closes === 1 && failed === 1, "a partial RTC write must close and fail the channel exactly once");
  channel.send(Uint8Array.of(9));
  assert(writes === 2, "a failed channel must never append bytes after the truncated frame");
});

await test("offers cannot force more than MAX_UNAUTHED_PEERS peer entries", async () => {
  // The old cap applied to the broadcast-hello path only: an offer from an
  // arbitrary `from` created an entry (and an RTCPeerConnection) unconditionally.
  const signaling = { send() {}, onMessage() {}, close() {} };
  const pcs = { n: 0 };
  const driver = {
    peerId: peerId(0),
    setPeerHooks() {},
    openLink() { return { linkId: 1, send() {}, close() {} }; },
  };
  const net = new RtcNetwork({
    driver,
    signaling,
    peerConnectionFactory: () => {
      pcs.n++;
      return {
        signalingState: "stable",
        remoteDescription: null,
        addEventListener() {},
        createDataChannel() { return { binaryType: "arraybuffer", send() {}, close() {}, addEventListener() {} }; },
        async setRemoteDescription() {},
        async setLocalDescription() {},
        async addIceCandidate() {},
        close() {},
      };
    },
  });

  // A flood of offers naming distinct strangers: the 256th entry may be created,
  // the rest must be dropped without allocating a connection.
  const offer = (from) => ({ type: "sdp", from, sdp: { type: "offer", sdp: "x" } });
  for (let i = 1; i <= 300; i++) await net.onSignal(offer(peerId(i)));
  assert(net.peers.size === MAX_UNAUTHED_PEERS,
    `offers must cap peer entries at ${MAX_UNAUTHED_PEERS}, got ${net.peers.size}`);
  assert(pcs.n === MAX_UNAUTHED_PEERS,
    `the connection factory must be reached exactly as many times, got ${pcs.n}`);

  // An entry that already exists is still served — the cap is on creation.
  await net.onSignal(offer(peerId(1)));
  assert(net.peers.size === MAX_UNAUTHED_PEERS, "a repeat offer must not create a second entry");
  assert(pcs.n === MAX_UNAUTHED_PEERS, "a repeat offer must not open a second connection");

  // The hello path answers to the same cap — including DIRECTED hellos, which name
  // us too and could spam a slot just as well as broadcast ones.
  for (let i = 301; i <= 350; i++) {
    await net.onSignal({ type: "hello", from: peerId(i), to: driver.peerId });
  }
  assert(net.peers.size === MAX_UNAUTHED_PEERS, `hellos must not exceed the same cap (got ${net.peers.size})`);
  assert(pcs.n === MAX_UNAUTHED_PEERS, "and no further connections may have been opened");

  net.close();
});

summary("net-rtc signaling boundary and speculative-entry cap");
