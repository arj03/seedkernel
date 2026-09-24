// net-rtc.test.mjs — WebRTC (§12.7): the host's `rtc:` socket seam, which holds the
// RTCPeerConnection and passes the W3C verbs through as bytes, and the transport bundle's
// side of it — the relay, who offers, the negotiation links and their bounds. The seam is
// pinned with stub peer connections (the platform global is referenced only inside
// `connect`, so it runs under Node); the transport with an in-process relay room and a fake
// WebRTC world whose data channels are loopback pairs. Run after `npm run build`.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { importBuilt, testkit } from "./testkit.mjs";
import {
  makeTransportHost, until, linkedPeers, transportOp, OpArgs, PROTO, generateKeyPair,
} from "./transport-harness.mjs";

const imp = importBuilt(join(dirname(fileURLToPath(import.meta.url)), ".."));
const { RtcChannel, RtcNetwork, RTC_CHUNK_BYTES, RTC_TAG } = await imp("build/services/net-rtc.js");
const { combineChannels } = await imp("build/services/socket-seam.js");

const { test, assert, summary } = testkit();
const enc = new TextEncoder(), dec = new TextDecoder();
const settle = (ms = 50) => new Promise((r) => setTimeout(r, ms));
const msg = (tag, text = "") => {
  const b = enc.encode(text);
  const out = new Uint8Array(1 + b.length);
  out[0] = tag;
  out.set(b, 1);
  return out;
};

// ── the socket seam, over stubs ──────────────────────────────────────────────

/** Listeners by type, several per type as the platform allows. */
function emitter() {
  const on = new Map();
  return {
    addEventListener(type, cb) { (on.get(type) ?? on.set(type, []).get(type)).push(cb); },
    emit(type, ev = {}) { for (const cb of on.get(type) ?? []) cb(ev); },
  };
}

function stubDataChannel(opts) {
  const e = emitter();
  return { ...e, opts, binaryType: "", bufferedAmount: 0, sent: [], closed: false,
    send(b) { this.sent.push(Uint8Array.from(b)); }, close() { this.closed = true; } };
}

function stubPeerConnection() {
  const e = emitter();
  const pc = {
    ...e, calls: [], localDescription: null, connectionState: "new", closed: false, dc: null,
    createDataChannel(label, opts) { this.dc = stubDataChannel(opts); return this.dc; },
    async setLocalDescription() {
      const type = this.calls.some((c) => c[0] === "remote" && c[1] === "offer") ? "answer" : "offer";
      this.calls.push(["local", type]);
      this.localDescription = { type, sdp: `sdp-${type}` };
    },
    async setRemoteDescription(d) { this.calls.push(["remote", d.type, d.sdp]); },
    async addIceCandidate(c) { this.calls.push(["candidate", c]); },
    restartIce() { this.calls.push(["restart"]); },
    close() { this.closed = true; },
  };
  return pc;
}

/** One seam and the links it hands the driver, recorded. */
async function seam() {
  const pcs = [];
  const net = new RtcNetwork({ peerConnectionFactory: () => { const pc = stubPeerConnection(); pcs.push(pc); return pc; } });
  const accepted = [];
  await net.listen([], (channel, arrival) => accepted.push({ channel, arrival }));
  const open = (dest) => {
    const link = net.connect(dest);
    if (!link) return null;
    const up = [];
    let closed = 0;
    link.onData((b) => up.push([b[0], dec.decode(b.subarray(1))]));
    link.onClose(() => { closed++; });
    return { link, up, pc: pcs[pcs.length - 1], closed: () => closed };
  };
  return { net, pcs, accepted, open };
}

console.log("\nWebRTC: the rtc: socket seam (§12.7)\n");

await test("only rtc:offer and rtc:answer route, with an optional JSON configuration", async () => {
  const { net, pcs, open } = await seam();
  for (const dest of ["ws://relay:1/room", "rtc:", "rtc:offerx", "rtc:offer?{bad", "rtc:answer?[1]"]) {
    assert(open(dest) === null, `${dest} must be no route`);
  }
  assert(pcs.length === 0, "an unrouted destination must not allocate a peer connection");
  assert(open("rtc:offer") && open(`rtc:answer?${JSON.stringify({ iceServers: [{ urls: "stun:x" }] })}`),
    "both roles route, with or without a configuration");
  assert(pcs.length === 2 && pcs.every((pc) => pc.dc.opts.negotiated === true && pc.dc.opts.id === 0),
    "every peer connection carries the one pre-agreed data channel, so neither side is the dialer");
  net.close();
  assert(pcs.every((pc) => pc.closed), "closing the factory closes every peer connection");
});

await test("the data link is announced once its channel opens, naming the negotiation link", async () => {
  const { net, accepted, open } = await seam();
  const n = open("rtc:offer");
  await settle(5);
  assert(accepted.length === 0, "no data link before the channel opens");
  n.pc.dc.emit("open");
  assert(accepted.length === 1 && accepted[0].arrival.via === n.link,
    "the open channel is announced with the negotiation link as its via");
  assert(accepted[0].channel.stream === true, "the data link is a byte stream the occupant frames");
  net.close();
});

await test("only the offering side offers; the answering side answers what it is given", async () => {
  const { net, open } = await seam();
  const offerer = open("rtc:offer");
  const answerer = open("rtc:answer");
  offerer.pc.emit("negotiationneeded");
  answerer.pc.emit("negotiationneeded");
  await settle(5);
  assert(offerer.up.length === 1 && offerer.up[0][0] === RTC_TAG.OFFER && offerer.up[0][1] === "sdp-offer",
    "the offering side's negotiationneeded goes up as its local offer");
  assert(answerer.up.length === 0, "the answering side never offers");

  answerer.link.send(msg(RTC_TAG.OFFER, "their-offer"));
  await settle(5);
  assert(answerer.up.length === 1 && answerer.up[0][0] === RTC_TAG.ANSWER, "a remote offer is answered");
  assert(answerer.pc.calls[0][0] === "remote" && answerer.pc.calls[0][2] === "their-offer",
    "the offer reaches the platform verbatim");
  let refused = false;
  try { offerer.link.send(msg(RTC_TAG.OFFER, "x")); } catch { refused = true; }
  assert(refused, "an offer for the offering side is refused, not applied");
  net.close();
});

await test("a candidate gathered before its description goes up after it", async () => {
  const { net, open } = await seam();
  const n = open("rtc:offer");
  const cand = (c) => ({ candidate: { toJSON: () => ({ candidate: c, sdpMid: "0", sdpMLineIndex: 0 }) } });
  n.pc.emit("icecandidate", cand("candidate:early"));
  n.pc.emit("negotiationneeded");
  await settle(5);
  n.pc.emit("icecandidate", cand("candidate:late"));
  assert(n.up.map((u) => u[0]).join() === [RTC_TAG.OFFER, RTC_TAG.CANDIDATE, RTC_TAG.CANDIDATE].join(),
    `the description must lead its candidates, got ${JSON.stringify(n.up)}`);
  assert(n.up[1][1].startsWith("candidate:early\0") && n.up[2][1].startsWith("candidate:late\0"),
    "held candidates keep their order");
  net.close();
});

await test("guest writes apply in order, and what waits is outbound custody", async () => {
  const { net, open } = await seam();
  const n = open("rtc:answer");
  let release;
  const gate = new Promise((r) => { release = r; });
  const setRemote = n.pc.setRemoteDescription;
  n.pc.setRemoteDescription = async function (d) { await gate; return setRemote.call(this, d); };
  const offer = msg(RTC_TAG.OFFER, "o");
  const cand = msg(RTC_TAG.CANDIDATE, "candidate:1\0" + "0\0" + "0\0" + "uf");
  n.link.send(offer);
  n.link.send(cand);
  await settle(5);
  assert(n.pc.calls.length === 0, "a candidate must not overtake the description it belongs to");
  assert(n.link.buffered() === offer.length + cand.length, "unapplied writes are the link's backlog");
  release();
  await settle(5);
  assert(n.pc.calls.map((c) => c[0]).join() === "remote,local,candidate", "applied in the order written");
  assert(n.pc.calls[2][1].sdpMLineIndex === 0 && n.pc.calls[2][1].usernameFragment === "uf",
    "the candidate's fields survive");
  assert(n.link.buffered() === 0, "the backlog drains as the platform answers");
  for (const bad of [msg(RTC_TAG.CANDIDATE, "c\0\0-1\0"), msg(RTC_TAG.CANDIDATE, "only-one-field"), msg(0x7a), new Uint8Array(0)]) {
    let threw = false;
    try { n.link.send(bad); } catch { threw = true; }
    assert(threw, `a malformed write is refused: ${JSON.stringify([...bad])}`);
  }
  n.link.send(msg(RTC_TAG.RESTART));
  assert(n.pc.calls.at(-1)[0] === "restart", "a restart reaches the platform");
  net.close();
});

await test("the connection ending closes both links; closing the negotiation closes the data link", async () => {
  const { net, accepted, open } = await seam();
  const a = open("rtc:offer");
  a.pc.dc.emit("open");
  let dataClosed = 0;
  accepted[0].channel.onClose(() => { dataClosed++; });
  a.pc.connectionState = "failed";
  a.pc.emit("connectionstatechange");
  assert(a.up.at(-1)[0] === RTC_TAG.STATE && a.up.at(-1)[1] === "failed", "the state goes up first");
  assert(a.closed() === 1 && dataClosed === 1 && a.pc.closed, "a failed connection ends both links and the pc");

  const b = open("rtc:answer");
  b.pc.dc.emit("open");
  let bData = 0;
  accepted[1].channel.onClose(() => { bData++; });
  b.link.close();
  assert(bData === 1 && b.pc.closed && b.pc.dc.closed, "a closed negotiation takes its data link down, heard by its owner");
  net.close();
});

await test("RtcChannel exposes a length-framed stream and caps physical messages", async () => {
  const dc = stubDataChannel({});
  const channel = new RtcChannel(dc);
  assert(channel.stream === true, "RTC bytes are a byte duplex the guest must frame itself");
  dc.emit("open");
  const bytes = new Uint8Array(RTC_CHUNK_BYTES * 2 + 7).fill(0x5a);
  channel.send(bytes);
  assert(dc.sent.length === 3, `a two-chunk-plus-tail write must make 3 messages, got ${dc.sent.length}`);
  assert(dc.sent[0].length === RTC_CHUNK_BYTES && dc.sent[1].length === RTC_CHUNK_BYTES && dc.sent[2].length === 7,
    `physical messages must be capped at ${RTC_CHUNK_BYTES} bytes`);
  assert(dc.sent.every((part) => part.every((byte) => byte === 0x5a)), "chunking must preserve every byte");
  channel.close();
});

await test("RtcChannel fails closed when a chunked write throws after a prefix", async () => {
  let writes = 0, closes = 0, failed = 0;
  const dc = stubDataChannel({});
  dc.send = () => { writes++; if (writes === 2) throw new Error("SCTP buffer full"); };
  dc.close = () => { closes++; };
  const channel = new RtcChannel(dc);
  channel.onClose(() => { failed++; });
  dc.emit("open");
  channel.send(new Uint8Array(RTC_CHUNK_BYTES * 2 + 1));
  assert(writes === 2, `the throwing second chunk must stop the write, got ${writes} attempts`);
  assert(closes === 1 && failed === 1, "a partial RTC write must close and fail the channel exactly once");
  let refused = false;
  try { channel.send(Uint8Array.of(9)); } catch { refused = true; }
  assert(refused, "a failed channel must refuse rather than silently accept a further write");
  assert(writes === 2, "a failed channel must never append bytes after the truncated frame");
});

// ── the transport over a relay and a fake WebRTC world ───────────────────────

/** A signaling room: every frame one member sends reaches every other member, verbatim. */
class RelayRoom {
  members = new Set();
  frames = [];
  link() {
    const m = { msg: null, cls: null, dead: false };
    const room = this;
    const link = {
      send(b) {
        room.frames.push(dec.decode(b));
        for (const o of room.members) if (o !== m) queueMicrotask(() => { if (!o.dead) o.msg?.(Uint8Array.from(b)); });
      },
      onData(cb) { m.msg = cb; },
      onClose(cb) { m.cls = cb; },
      close() { m.dead = true; room.members.delete(m); },
      buffered: () => 0,
    };
    m.kill = () => { if (m.dead) return; m.dead = true; room.members.delete(m); m.cls?.(); };
    this.members.add(m);
    return link;
  }
  /** A frame from someone who is not a node: a spoofer, or a stranger. */
  inject(text) { for (const o of this.members) queueMicrotask(() => o.msg?.(enc.encode(text))); }
  factory() {
    return {
      connect: (dest) => (dest.startsWith("ws://relay/") ? this.link() : null),
      listen: async (addrs) => addrs.map(() => 0),
      close() {},
    };
  }
}

/** Peer connections that connect once both descriptions are set, their negotiated data
 *  channels becoming an in-process pair. A description's SDP names its connection. */
class FakeWebRtc {
  pcs = new Map();
  made = [];
  next = 1;
  factory = () => {
    const world = this;
    const e = emitter();
    const id = this.next++;
    const pc = {
      ...e, id, peer: null, closed: false, connectionState: "new", localDescription: null, remote: null, dc: null,
      candidates: [],
      createDataChannel() {
        const d = emitter();
        const dc = { ...d, binaryType: "", bufferedAmount: 0, peer: null, open: false, closed: false,
          send(b) { const p = this.peer; const copy = Uint8Array.from(b).buffer; queueMicrotask(() => { if (p && !p.closed) p.emit("message", { data: copy }); }); },
          close() { if (this.closed) return; this.closed = true; const p = this.peer; queueMicrotask(() => { this.emit("close"); if (p && !p.closed) p.close(); }); } };
        this.dc = dc;
        queueMicrotask(() => e.emit("negotiationneeded"));
        return dc;
      },
      async setLocalDescription() {
        const type = this.remote?.type === "offer" ? "answer" : "offer";
        this.localDescription = { type, sdp: `fake:${id}` };
        queueMicrotask(() => e.emit("icecandidate", { candidate: { toJSON: () => ({ candidate: `candidate:${id}`, sdpMid: "0", sdpMLineIndex: 0 }) } }));
        world.maybeConnect(this);
      },
      async setRemoteDescription(d) {
        this.remote = d;
        this.peer = world.pcs.get(Number(d.sdp.slice(5)));
        world.maybeConnect(this);
      },
      async addIceCandidate(c) { this.candidates.push(c.candidate); },
      restartIce() {},
      close() { if (this.closed) return; this.closed = true; this.dc?.close(); },
    };
    this.pcs.set(id, pc);
    this.made.push(pc);
    return pc;
  };
  maybeConnect(pc) {
    const other = pc.peer;
    if (!other || other.peer !== pc || !pc.localDescription || !other.localDescription || pc.connectionState === "connected") return;
    for (const p of [pc, other]) p.connectionState = "connected";
    pc.dc.peer = other.dc;
    other.dc.peer = pc.dc;
    setTimeout(() => {
      for (const p of [pc, other]) { p.emit("connectionstatechange"); p.dc.emit("open"); }
    }, 5);
  }
}

const relayState = async (node) => (await transportOp(node, new OpArgs("relayState")))[0];
const joinRelay = (node, url) => transportOp(node, new OpArgs("relay").text(url));

/** A node whose sockets are the room and the fake world, and nothing else. */
function rtcNode(room, world, opts = {}) {
  const channels = combineChannels(room.factory(), new RtcNetwork({ peerConnectionFactory: world.factory }));
  return makeTransportHost({ channels, ...opts });
}

await test("two nodes in one room link over WebRTC and carry a request", async (keep) => {
  const room = new RelayRoom(), world = new FakeWebRtc();
  const A = keep(await rtcNode(room, world));
  const B = keep(await rtcNode(room, world));
  assert(await relayState(A) === 0, "no relay before one is joined");
  await joinRelay(A, "ws://relay/room");
  await joinRelay(B, "ws://relay/room");
  assert(await relayState(A) === 1, "the relay link is up once joined");
  await until(async () => (await linkedPeers(A)).includes(B.peerId) && (await linkedPeers(B)).includes(A.peerId),
    4000, "the WebRTC link");
  const resp = await A.request(B.peerId, PROTO, Uint8Array.of(7, 8, 9));
  assert(resp.length === 3 && resp[2] === 9, "a request crosses the data channel");
  assert(world.made.length === 2, `one peer connection per side, got ${world.made.length}`);
  assert(world.made.every((pc) => pc.candidates.length >= 1), "candidates went through the relay and in");
  assert(room.frames.every((f) => f.split("\0").length >= 3), "every relay frame is the NUL-separated wire");
});

await test("a relay that drops is redialed, and a spoofed offer cannot take a live link down", async (keep) => {
  const room = new RelayRoom(), world = new FakeWebRtc();
  const A = keep(await rtcNode(room, world));
  const B = keep(await rtcNode(room, world));
  await joinRelay(A, "ws://relay/room");
  await joinRelay(B, "ws://relay/room");
  await until(async () => (await linkedPeers(A)).includes(B.peerId), 4000, "the WebRTC link");
  // Someone in the room claims to be whichever of the two answers, with a new negotiation.
  const [small, large] = A.peerId < B.peerId ? [A, B] : [B, A];
  room.inject(["o", small.peerId, large.peerId, "00".repeat(8), "fake:999"].join("\0"));
  await settle(100);
  assert((await linkedPeers(large)).includes(small.peerId), "a live link survives a fresh offer in its name");
  assert(world.made.length === 2, "the spoofed offer allocated no peer connection");

  for (const m of [...room.members]) m.kill();
  await until(async () => (await relayState(A)) === 2, 2000, "the dropped relay to read as redialing");
  await until(async () => (await relayState(A)) === 1, 4000, "the relay to be redialed");
});

await test("negotiations are capped, and one that never connects is dropped on its deadline", async (keep) => {
  const room = new RelayRoom();
  // A world where nothing ever connects: descriptions are set and never paired.
  const world = new FakeWebRtc();
  world.maybeConnect = () => {};
  const A = keep(await rtcNode(room, world, { transportConfig: { maxRtcNegotiating: 2, rtcConnectTimeoutMs: 150 } }));
  await joinRelay(A, "ws://relay/room");
  // Strangers larger than A, so A is the side that offers to each.
  for (let i = 0; i < 5; i++) room.inject(["h", "ff".repeat(31) + (16 + i).toString(16), ""].join("\0"));
  await until(() => world.made.length === 2, 2000, "two negotiations");
  await settle(50);
  assert(world.made.length === 2, `the cap bounds the peer connections a room can make us open, got ${world.made.length}`);
  await until(() => world.made.every((pc) => pc.closed), 2000, "the stalled negotiations to be dropped");
});

summary("WebRTC");
