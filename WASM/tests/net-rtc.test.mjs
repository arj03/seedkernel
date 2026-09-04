// net-rtc.test.mjs — RtcNetwork's untrusted signaling boundary and speculative-entry cap
// (§12.6.1). A signaling endpoint can name arbitrary `from` values in hellos AND in SDP
// offers, and every entry carries an RTCPeerConnection — so decoding precedes policy and
// every path that CREATES an entry answers to the same MAX_UNESTABLISHED_PEERS bound. Pinned with
// stubs: the browser globals are referenced only inside methods, so net-rtc runs under Node.
// Run after `npm run build`.

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);
const rtc = await imp("build/host/net-rtc.js");
const {
  RtcChannel, RtcNetwork, RTC_CHUNK_BYTES, MAX_UNESTABLISHED_PEERS,
  MAX_SDP_BYTES, MAX_PENDING_ICE_CANDIDATES, MAX_PENDING_ICE_BYTES,
  UNESTABLISHED_PEER_TTL_MS, MAX_QUEUED_SIGNALS, MAX_QUEUED_SIGNAL_BYTES,
} = rtc;
import { testkit } from "./testkit.mjs";

const { test, assert, summary } = testkit();

// The cap the transport relay is bound to (net-rtc.ts). An entry stops counting once its
// peer connection ESTABLISHES — DTLS/ICE completes (`PeerEntry.established`) — not once the
// transport link above it authenticates, so a genuine fleet is unconstrained; only NEW
// speculative entries are.
const peerId = (n) => String(n).padStart(64, "0");
const wire = (msg) => {
  const tag = msg.type === "hello" ? "h"
    : msg.type === "ice" ? "i"
    : msg.sdp.type === "offer" ? "o" : "a";
  const fields = [tag, msg.from, msg.to ?? ""];
  if (msg.type === "hello") return fields.join("\0");
  if (msg.type === "sdp") return [...fields, msg.sdp.sdp].join("\0");
  const c = msg.candidate;
  return [...fields, c.candidate, c.sdpMid ?? "", c.sdpMLineIndex?.toString() ?? "",
    c.usernameFragment ?? ""].join("\0");
};

function stubPeerConnection() {
  const listeners = new Map();
  const pc = {
    signalingState: "stable", connectionState: "new", remoteDescription: null,
    closed: false,
    addEventListener(type, cb) { listeners.set(type, cb); },
    createDataChannel() { return { binaryType: "arraybuffer", send() {}, close() {}, addEventListener() {} }; },
    async setRemoteDescription(sdp) { this.remoteDescription = sdp; },
    async setLocalDescription() {},
    async addIceCandidate() {},
    close() { this.closed = true; },
  };
  return { pc, listeners };
}

console.log("\nRtcNetwork signaling boundary and speculative-entry cap (§12.6.1)\n");

await test("net-rtc exports the signaling seam, not a WebSocket relay implementation", async () => {
  assert(!("relaySignaling" in rtc), "the kernel must not ship a rendezvous wire implementation");
});

await test("RtcNetwork validates encoded signaling strings before admitting them", async () => {
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
    peerId: ownId,
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
    [],
    {},
    "hello",
    wire({ type: "hello", from: "not-a-peer" }),
    wire({ type: "hello", from: peerId(1), to: "not-a-peer" }),
    wire({ type: "sdp", from: peerId(1), sdp: { type: "offer", sdp: "x\0y" } }),
    wire({ type: "ice", from: peerId(1), candidate: { candidate: "x", sdpMLineIndex: -1 } }),
    `h${peerId(1)}trailing`,
    `H${peerId(1)}`,
    `x${peerId(1)}`,
    `i${peerId(1)}00000005x`,
    `i${peerId(1)}ffffffffffffffffffffffffffffffff`,
  ];
  for (const msg of malformed) await receive(msg);
  assert(admitted === 0, `malformed messages must be dropped before policy (got ${admitted})`);
  assert(pcs === 0 && net.peers.size === 0, "malformed messages must not allocate peer connections");

  await receive(wire({ type: "hello", from: peerId(1) }));
  assert(admitted === 1 && pcs === 1, "a valid encoded hello must reach policy and create one peer");
  assert(sent.length === 1 && typeof sent[0] === "string"
      && sent[0] === wire({ type: "hello", from: ownId, to: peerId(1) }),
  "a broadcast hello must receive one byte-exact encoded-string reply");
  net.close();
});

await test("RtcNetwork rejects oversized SDP before policy or WebRTC", async () => {
  let receive = () => {};
  let admitted = 0;
  let pcs = 0;
  const ownId = peerId(0);
  const net = new RtcNetwork({
    peerId: ownId,
    signaling: { send() {}, onMessage(cb) { receive = cb; }, close() {} },
    admitPeer() { admitted++; return true; },
    peerConnectionFactory: () => {
      pcs++;
      return stubPeerConnection().pc;
    },
  });
  const overLimit = "x".repeat(MAX_SDP_BYTES / 2 + 1);
  await receive(wire({ type: "sdp", from: peerId(1), to: ownId, sdp: { type: "offer", sdp: overLimit } }));
  assert(admitted === 0 && pcs === 0 && net.peers.size === 0,
    "oversized SDP must be dropped at decoding, before policy and connection allocation");

  const atLimit = "x".repeat(MAX_SDP_BYTES / 2);
  await receive(wire({ type: "sdp", from: peerId(1), to: ownId, sdp: { type: "offer", sdp: atLimit } }));
  assert(admitted === 1 && pcs === 1 && net.peers.size === 1,
    "SDP at the documented UTF-16 storage ceiling must remain admitted");
  net.close();
});

await test("inbound signaling handlers run in arrival order", async () => {
  let receive = () => {};
  let remoteStartedResolve, releaseRemote;
  const remoteStarted = new Promise((resolve) => { remoteStartedResolve = resolve; });
  const remoteBlocked = new Promise((resolve) => { releaseRemote = resolve; });
  let pcs = 0;
  const ownId = peerId(0);
  const net = new RtcNetwork({
    peerId: ownId,
    signaling: { send() {}, onMessage(cb) { receive = cb; }, close() {} },
    peerConnectionFactory: () => {
      const made = stubPeerConnection();
      pcs++;
      if (pcs === 1) {
        made.pc.setRemoteDescription = async function (sdp) {
          remoteStartedResolve();
          await remoteBlocked;
          this.remoteDescription = sdp;
        };
      }
      return made.pc;
    },
  });
  const offer = receive(wire({
    type: "sdp", from: peerId(1), to: ownId,
    sdp: { type: "offer", sdp: "offer" },
  }));
  await remoteStarted;
  const hello = receive(wire({ type: "hello", from: peerId(2), to: ownId }));
  await Promise.resolve();
  assert(pcs === 1, "a later message must not start while an earlier WebRTC operation is in flight");
  releaseRemote();
  await Promise.all([offer, hello]);
  assert(pcs === 2, "the queued message must run after the earlier handler completes");
  net.close();
});

await test("post-description ICE candidates drain one at a time", async () => {
  let firstStartedResolve, secondStartedResolve, releaseFirst;
  const firstStarted = new Promise((resolve) => { firstStartedResolve = resolve; });
  const secondStarted = new Promise((resolve) => { secondStartedResolve = resolve; });
  const firstBlocked = new Promise((resolve) => { releaseFirst = resolve; });
  let calls = 0, active = 0, maxActive = 0;
  const made = stubPeerConnection();
  made.pc.addIceCandidate = async () => {
    calls++;
    active++;
    maxActive = Math.max(maxActive, active);
    if (calls === 1) {
      firstStartedResolve();
      await firstBlocked;
    } else {
      secondStartedResolve();
    }
    active--;
  };
  const ownId = peerId(0);
  const remote = peerId(1);
  let receive = () => {};
  const net = new RtcNetwork({
    peerId: ownId,
    signaling: { send() {}, onMessage(cb) { receive = cb; }, close() {} },
    peerConnectionFactory: () => made.pc,
  });
  const entry = net.ensurePeer(remote);
  entry.pc.remoteDescription = { type: "offer", sdp: "ready" };

  // Through the inbound boundary, the only way a candidate arrives: one signaling lane
  // serializes every handler, so a drain cannot start while another is mid-candidate and
  // there is no second per-entry lane to keep in step with this one.
  const first = receive(wire({ type: "ice", from: remote, to: ownId, candidate: { candidate: "first" } }));
  const second = receive(wire({ type: "ice", from: remote, to: ownId, candidate: { candidate: "second" } }));
  await firstStarted;
  assert(calls === 1 && maxActive === 1,
    "a later candidate must wait while the preceding addIceCandidate is in flight");
  releaseFirst();
  await secondStarted;
  await Promise.all([first, second]);
  assert(calls === 2 && maxActive === 1, "candidate operations must remain strictly serialized");
  net.close();
});

await test("a duplicate RTC data channel is actively closed", async () => {
  const ownId = peerId(0);
  const remote = peerId(1);
  const made = stubPeerConnection();
  const net = new RtcNetwork({
    peerId: ownId,
    signaling: { send() {}, onMessage() {}, close() {} },
    peerConnectionFactory: () => made.pc,
  });
  let accepted = 0;
  await net.listen(undefined, undefined, () => { accepted++; });
  const channel = () => ({
    binaryType: "", bufferedAmount: 0, closes: 0,
    send() {},
    close() { this.closes++; },
    addEventListener() {},
  });
  const first = channel();
  const duplicate = channel();
  const entry = net.ensurePeer(remote);
  net.bindLink(remote, entry, first, false);
  net.bindLink(remote, entry, duplicate, false);
  assert(accepted === 1, "only the first data channel may be handed to the transport");
  assert(first.closes === 0 && duplicate.closes === 1,
    "the duplicate data channel must be closed instead of left live and unowned");
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
  assert(channel.stream === true, "RTC bytes are a byte duplex the guest must frame itself");
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
  // A dead channel's send() throws rather than silently dropping the write (net-channel.ts
  // BufferedChannel), so the caller — TransportHost's own outbound owner in production —
  // learns immediately rather than believing an admitted write actually left.
  let refused = false;
  try { channel.send(Uint8Array.of(9)); } catch { refused = true; }
  assert(refused, "a failed channel must refuse rather than silently accept a further write");
  assert(writes === 2, "a failed channel must never append bytes after the truncated frame");
});

await test("offers cannot force more than MAX_UNESTABLISHED_PEERS peer entries", async () => {
  // The old cap applied to the broadcast-hello path only: an offer from an
  // arbitrary `from` created an entry (and an RTCPeerConnection) unconditionally.
  const signaling = { send() {}, onMessage() {}, close() {} };
  const pcs = { n: 0 };
  const ownId = peerId(0);
  const net = new RtcNetwork({
    peerId: ownId,
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
  assert(net.peers.size === MAX_UNESTABLISHED_PEERS,
    `offers must cap peer entries at ${MAX_UNESTABLISHED_PEERS}, got ${net.peers.size}`);
  assert(pcs.n === MAX_UNESTABLISHED_PEERS,
    `the connection factory must be reached exactly as many times, got ${pcs.n}`);

  // An entry that already exists is still served — the cap is on creation.
  await net.onSignal(offer(peerId(1)));
  assert(net.peers.size === MAX_UNESTABLISHED_PEERS, "a repeat offer must not create a second entry");
  assert(pcs.n === MAX_UNESTABLISHED_PEERS, "a repeat offer must not open a second connection");

  // The hello path answers to the same cap — including DIRECTED hellos, which name
  // us too and could spam a slot just as well as broadcast ones.
  for (let i = 301; i <= 350; i++) {
    await net.onSignal({ type: "hello", from: peerId(i), to: ownId });
  }
  assert(net.peers.size === MAX_UNESTABLISHED_PEERS, `hellos must not exceed the same cap (got ${net.peers.size})`);
  assert(pcs.n === MAX_UNESTABLISHED_PEERS, "and no further connections may have been opened");

  net.close();
});

await test("pending ICE is normalized and bounded by candidate count", async () => {
  let receive = () => {};
  const made = [];
  const net = new RtcNetwork({
    peerId: peerId(0),
    signaling: { send() {}, onMessage(cb) { receive = cb; }, close() {} },
    peerConnectionFactory: () => {
      const madePc = stubPeerConnection();
      made.push(madePc);
      return madePc.pc;
    },
  });
  const remote = peerId(1);
  await receive(wire({ type: "hello", from: remote, to: peerId(0) }));
  const original = {
    candidate: "candidate:1", sdpMid: "0", sdpMLineIndex: 0,
    usernameFragment: "u", extra: { retained: new Uint8Array(1024) },
  };
  await receive(wire({ type: "ice", from: remote, to: peerId(0), candidate: original }));
  const entry = net.peers.get(remote);
  assert(entry.pendingIce.size === 1, "a valid early candidate must be queued");
  assert(entry.pendingIce.peek() !== original && !("extra" in entry.pendingIce.peek()),
    "the pending queue must retain a normalized candidate, never the signaling object");

  for (let i = 1; i < MAX_PENDING_ICE_CANDIDATES; i++) {
    await receive(wire({ type: "ice", from: remote, to: peerId(0), candidate: { candidate: `candidate:${i}` } }));
  }
  assert(entry.pendingIce.size === MAX_PENDING_ICE_CANDIDATES && !made[0].pc.closed,
    "the exact pending-candidate count ceiling must remain admitted");
  await receive(wire({ type: "ice", from: remote, to: peerId(0), candidate: { candidate: "one-too-many" } }));
  assert(!net.peers.has(remote) && made[0].pc.closed,
    "crossing the pending-candidate count ceiling must release the speculative peer");
  net.close();
});

await test("pending ICE is bounded by aggregate string bytes", async () => {
  let receive = () => {};
  const made = stubPeerConnection();
  const ownId = peerId(0);
  const remote = peerId(1);
  const net = new RtcNetwork({
    peerId: ownId,
    signaling: { send() {}, onMessage(cb) { receive = cb; }, close() {} },
    peerConnectionFactory: () => made.pc,
  });
  await receive(wire({ type: "hello", from: remote, to: ownId }));
  // Candidate accounting uses the worst-case two bytes per JS string code unit.
  const full = "x".repeat(MAX_PENDING_ICE_BYTES / 2);
  await receive(wire({ type: "ice", from: remote, to: ownId, candidate: { candidate: full } }));
  assert(net.peers.get(remote).pendingIceBytes === MAX_PENDING_ICE_BYTES,
    "the exact pending ICE byte ceiling must remain admitted");
  await receive(wire({ type: "ice", from: remote, to: ownId, candidate: { candidate: "x" } }));
  assert(!net.peers.has(remote) && made.pc.closed,
    "crossing the pending ICE byte ceiling must release the speculative peer");
  net.close();
});

await test("an unestablished peer expires on a host-owned deadline", async () => {
  const realSetTimeout = globalThis.setTimeout;
  const realClearTimeout = globalThis.clearTimeout;
  const timers = [];
  globalThis.setTimeout = (fn, ms) => {
    const timer = { fn, ms, cleared: false, unref() {} };
    timers.push(timer);
    return timer;
  };
  globalThis.clearTimeout = (timer) => { timer.cleared = true; };
  let net;
  try {
    const made = stubPeerConnection();
    net = new RtcNetwork({
      peerId: peerId(0),
      signaling: { send() {}, onMessage() {}, close() {} },
      peerConnectionFactory: () => made.pc,
    });
    const remote = peerId(1);
    await net.onSignal({ type: "hello", from: remote, to: peerId(0) });
    assert(timers.length === 1 && timers[0].ms === UNESTABLISHED_PEER_TTL_MS,
      "creating a speculative peer must arm the documented establishment deadline");
    timers[0].fn();
    assert(!net.peers.has(remote) && made.pc.closed,
      "the establishment deadline must close and forget a zombie peer");
  } finally {
    net?.close();
    globalThis.setTimeout = realSetTimeout;
    globalThis.clearTimeout = realClearTimeout;
  }
});

await test("a peer that establishes but never carries a channel expires too", async () => {
  // Establishing leaves the speculative-entry CAP, which is all `established` was ever
  // about. It is not a reason to drop the deadline: the polite side never opens the data
  // channel, so a peer that completes DTLS/ICE and then stays silent arms no channel watch
  // — with the deadline cleared at "connected" nothing would ever reap it, and a relay
  // could hold peer connections without limit outside the cap that counts them.
  const realSetTimeout = globalThis.setTimeout;
  const realClearTimeout = globalThis.clearTimeout;
  const timers = [];
  globalThis.setTimeout = (fn, ms) => {
    const timer = { fn, ms, cleared: false, unref() {} };
    timers.push(timer);
    return timer;
  };
  globalThis.clearTimeout = (timer) => { timer.cleared = true; };
  let net;
  try {
    const made = stubPeerConnection();
    // The factory is resolved once, at construction, so the connection each peer gets is
    // chosen through this cell rather than by reassigning the option.
    let next = made;
    // Ours sorts ABOVE theirs, so this node is the POLITE side and never opens a channel.
    const ownId = peerId(9);
    net = new RtcNetwork({
      peerId: ownId,
      signaling: { send() {}, onMessage() {}, close() {} },
      peerConnectionFactory: () => next.pc,
    });
    await net.listen(undefined, undefined, () => {});
    const remote = peerId(1);
    await net.onSignal({ type: "hello", from: remote, to: ownId });
    const entry = net.peers.get(remote);
    assert(entry && entry.polite && !entry.linked, "the polite side must not open a channel of its own");
    made.pc.connectionState = "connected";
    made.listeners.get("connectionstatechange")();
    assert(entry.established, "a completed DTLS/ICE connection leaves the speculative cap");
    assert(!timers[0].cleared, "leaving the cap must not disarm the entry's deadline");
    timers[0].fn();
    assert(!net.peers.has(remote) && made.pc.closed,
      "an established peer with no data channel must still expire");

    // The control: both facts true is the one state the deadline lets stand.
    const linkedPeer = stubPeerConnection();
    next = linkedPeer;
    const other = peerId(2);
    await net.onSignal({ type: "hello", from: other, to: ownId });
    const liveEntry = net.peers.get(other);
    linkedPeer.pc.connectionState = "connected";
    linkedPeer.listeners.get("connectionstatechange")();
    linkedPeer.listeners.get("datachannel")({
      channel: { binaryType: "arraybuffer", send() {}, close() {}, addEventListener() {} },
    });
    assert(liveEntry.established && liveEntry.linked, "the control peer is established and linked");
    timers[timers.length - 1].fn();
    assert(net.peers.get(other) === liveEntry, "a peer that is both must survive its deadline");
  } finally {
    net?.close();
    globalThis.setTimeout = realSetTimeout;
    globalThis.clearTimeout = realClearTimeout;
  }
});

await test("the signaling lane bounds how many decoded signals may wait on it", async () => {
  // The lane exists to keep a later SDP from overtaking an operation in flight — and a
  // lane is a queue. Nothing else counts it: the per-peer caps are only reached once a
  // message is ACTED on, so without this bound a relay can park unbounded SDP here.
  let deliver = null;
  const signaling = { send() {}, onMessage(cb) { deliver = cb; }, close() {} };
  let admitted = 0;
  let releaseHead;
  const held = new Promise((resolve) => { releaseHead = resolve; });
  const net = new RtcNetwork({
    peerId: peerId(0),
    signaling,
    admitPeer: () => { admitted++; return true; },
    peerConnectionFactory: () => ({
      signalingState: "stable",
      remoteDescription: null,
      addEventListener() {},
      createDataChannel() { return { binaryType: "arraybuffer", send() {}, close() {}, addEventListener() {} }; },
      // The head of the lane parks here, so everything behind it has to wait.
      setRemoteDescription: () => held,
      async setLocalDescription() {},
      async addIceCandidate() {},
      close() {},
    }),
  });
  try {
    // Small offers on purpose: this is the COUNT bound's test, and a maximum-sized one
    // would be stopped by the byte companion first (the test below).
    const big = "s".repeat(64);
    const sent = MAX_QUEUED_SIGNALS + 64;
    for (let i = 1; i <= sent; i++) {
      deliver(wire({ type: "sdp", from: peerId(i), sdp: { type: "offer", sdp: big } }));
    }
    await new Promise((r) => setTimeout(r, 0));
    assert(admitted === 1, `only the head of the lane may run while it is parked, got ${admitted}`);
    releaseHead();
    // Drain: every signal the lane accepted now runs, and nothing more.
    for (let i = 0; i < sent + 8; i++) await new Promise((r) => setTimeout(r, 0));
    assert(admitted <= MAX_QUEUED_SIGNALS + 1,
      `the lane must drop past ${MAX_QUEUED_SIGNALS} waiting signals, ran ${admitted} of ${sent}`);
    assert(admitted < sent, "an unbounded lane would have run every one of them");
  } finally {
    net.close();
  }
});

await test("the signaling lane bounds the BYTES waiting on it, not only the count", async () => {
  // A count alone is half a bound: one relay carries every peer and the per-message caps
  // admit a 256 KiB offer, so MAX_QUEUED_SIGNALS of them would make this lane the largest
  // single allowance on the node — bigger than a confined guest heap.
  let deliver = null;
  let admitted = 0;
  let releaseHead;
  const held = new Promise((resolve) => { releaseHead = resolve; });
  const net = new RtcNetwork({
    peerId: peerId(0),
    signaling: { send() {}, onMessage(cb) { deliver = cb; }, close() {} },
    admitPeer: () => { admitted++; return true; },
    peerConnectionFactory: () => ({
      signalingState: "stable",
      remoteDescription: null,
      addEventListener() {},
      createDataChannel() { return { binaryType: "arraybuffer", send() {}, close() {}, addEventListener() {} }; },
      setRemoteDescription: () => held,
      async setLocalDescription() {},
      async addIceCandidate() {},
      close() {},
    }),
  });
  try {
    const big = "s".repeat(MAX_SDP_BYTES / 2);
    // Worst-case UTF-16 storage of one decoded offer: the description plus the sender id.
    const perSignal = 2 * (big.length + 64);
    const fits = Math.floor(MAX_QUEUED_SIGNAL_BYTES / perSignal);
    const sent = MAX_QUEUED_SIGNALS + 64;
    for (let i = 1; i <= sent; i++) {
      deliver(wire({ type: "sdp", from: peerId(i), sdp: { type: "offer", sdp: big } }));
    }
    releaseHead();
    for (let i = 0; i < sent + 8; i++) await new Promise((r) => setTimeout(r, 0));
    assert(admitted <= fits + 1,
      `the lane must drop past ${MAX_QUEUED_SIGNAL_BYTES} waiting bytes, ran ${admitted} (fits ${fits})`);
    assert(admitted < MAX_QUEUED_SIGNALS,
      "the byte companion must bite before the count does on maximum-sized offers");
  } finally {
    net.close();
  }
});

summary("net-rtc signaling boundary and speculative-entry cap");
