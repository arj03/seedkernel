// The UDP path (§12.7): the host's `udp:` socket seam (services/udp), which finds a path
// between two sockets and runs a reliable stream over it, and the transport bundle's side,
// which offers it before WebRTC. The stream is tested over an in-memory path that loses,
// repeats and reorders; the seam and the transport over real UDP on this machine, with the
// in-process relay (fake-relay.mjs) for signaling. Run after `npm run build`.

import { createSocket } from "node:dgram";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { importBuilt, testkit } from "./testkit.mjs";
import { FakeRelay } from "./fake-relay.mjs";
import {
  makeTransportHost, until, linkedPeers, transportOp, OpArgs, PROTO, generateKeyPair, generatorRequest,
} from "./transport-harness.mjs";

const imp = importBuilt(join(dirname(fileURLToPath(import.meta.url)), ".."));
const { UdpNetwork } = await imp("build/services/udp/net-udp.js");
const { UdpStream } = await imp("build/services/udp/stream.js");
const { bindingRequest, isStun, mappedAddress } = await imp("build/services/udp/stun.js");
const { nodeDatagrams } = await imp("build/services/udp/node.js");
const { RTC_TAG } = await imp("build/services/net-rtc.js");
const { combineChannels } = await imp("build/services/socket-seam.js");

const { test, assert, summary } = testkit();
const enc = new TextEncoder(), dec = new TextDecoder();
const settle = (ms = 50) => new Promise((r) => setTimeout(r, ms));
const CREDIT = 1 << 20;

// ── the stream, over an in-memory path ───────────────────────────────────────

/** Two streams joined by a path that drops `loss` of the packets, sends `dup` of them
 *  twice, and holds `late` of them back 5 ms, behind packets sent after them. `cut()` drops
 *  everything from then on, and a packet larger than `mtu`, which can change, is dropped.
 *  While `held` is an array, what b sends a waits in it, as the acks of a peer whose loop is
 *  held do, and `release()` hands it all to a at once. `largest` is the largest DATA packet
 *  sent from a to b since it was last set to 0, and `toB` counts them. */
function streamPair({ loss = 0, dup = 0, late = 0, mtu = Infinity } = {}) {
  const a = new UdpStream(() => {}), b = new UdpStream(() => {});
  const pair = {
    a, b, dead: false, mtu, largest: 0, toB: 0, held: null,
    cut: () => { pair.dead = true; },
    release: () => { const held = pair.held ?? []; pair.held = null; for (const p of held) a.receive(p); },
  };
  const wire = (to) => (p) => {
    if (to === b && p[0] === 0x64) { pair.largest = Math.max(pair.largest, p.length); pair.toB++; }
    const copies = pair.dead || p.length > pair.mtu || Math.random() < loss ? 0 : Math.random() < dup ? 2 : 1;
    for (let i = 0; i < copies; i++) {
      const bytes = p.slice();
      if (to === a && pair.held) pair.held.push(bytes);
      else if (Math.random() < late) setTimeout(() => to.receive(bytes), 5);
      else setImmediate(() => to.receive(bytes));
    }
  };
  a.start(wire(b), 1);
  b.start(wire(a), 1);
  return pair;
}

/** What a stream's reader is handed, and whether the stream closed under it. */
function reader(stream) {
  const parts = [];
  const r = { length: 0, closed: false, largest: 0, bytes: () => Buffer.concat(parts) };
  stream.onData((b) => { parts.push(Buffer.from(b)); r.length += b.length; r.largest = Math.max(r.largest, b.length); });
  stream.onClose(() => { r.closed = true; });
  return r;
}

/** Write `bytes` in pieces of random size, as the transport's records come. */
function writeInPieces(stream, bytes) {
  for (let at = 0; at < bytes.length;) {
    const n = Math.min(bytes.length - at, 1 + Math.floor(Math.random() * 40_000));
    stream.send(bytes.subarray(at, at + n));
    at += n;
  }
}

console.log("\nUDP: the stream (§12.7)\n");

await test("the stream delivers in order through loss, repeats and reordering, both ways", async () => {
  const { a, b } = streamPair({ loss: 0.05, dup: 0.02, late: 0.02 });
  const toB = randomBytes(1024 * 1024), toA = randomBytes(128 * 1024);
  const atB = reader(b), atA = reader(a);
  writeInPieces(a, toB);
  writeInPieces(b, toA);
  await until(() => atB.length === toB.length && atA.length === toA.length, 30_000, "both directions to arrive");
  assert(atB.bytes().equals(toB) && atA.bytes().equals(toA), "what arrives is what was written, in order");
  await until(() => a.buffered() === 0 && b.buffered() === 0, 5000, "everything to be acked");
  a.close(); b.close();
});

await test("a reader held back stops the sender at its credit, and lets it go again", async () => {
  const { a, b } = streamPair();
  const atB = reader(b);
  b.setReadable(false);
  const data = randomBytes(4 * CREDIT);
  writeInPieces(a, data);
  await settle(300);
  assert(atB.length === 0, "nothing is handed to a reader that is held");
  assert(a.buffered() >= data.length - CREDIT, `the sender keeps what is past the credit, has ${a.buffered()}`);
  b.setReadable(true);
  await until(() => atB.length === data.length, 10_000, "the rest once the reader reads");
  assert(atB.bytes().equals(data), "and in order");
  assert(atB.largest === 256 * 1024, `what was held is handed over in large reads, the largest ${atB.largest}`);
  a.close(); b.close();
});

await test("data the peer stops answering ends the stream well inside the silent path's 30 s", async () => {
  const pair = streamPair();
  const atA = reader(pair.a);
  const t0 = performance.now();
  pair.cut();
  pair.a.send(randomBytes(64 * 1024));
  await until(() => atA.closed, 20_000, "the sender to give up");
  const s = (performance.now() - t0) / 1000;
  assert(s >= 10 && s < 20, `it gives up after the 10 s floor, and before 20 s, at ${s.toFixed(1)} s`);
});

await test("packets grow to 1452 bytes on a path a probe shows carries them, and stay 1200 on one that does not", async () => {
  for (const [mtu, want] of [[Infinity, 1452], [1451, 1200]]) {
    const pair = streamPair({ mtu });
    const atB = reader(pair.b);
    await settle(100);
    const data = randomBytes(512 * 1024);
    writeInPieces(pair.a, data);
    await until(() => atB.length === data.length, 10_000, "the data to arrive");
    assert(atB.bytes().equals(data), "intact");
    assert(pair.largest === want, `on a path carrying ${mtu}, the largest packet is ${want}: ${pair.largest}`);
    pair.a.close(); pair.b.close();
  }
});

await test("a path that stops carrying the larger packets drops back to 1200, splitting what was cut larger", async () => {
  const pair = streamPair({ loss: 0.02, late: 0.02 });
  const atB = reader(pair.b);
  await settle(100);
  const data = randomBytes(2 * CREDIT);
  writeInPieces(pair.a, data);
  await until(() => atB.length > 256 * 1024, 10_000, "the first of it at the larger size");
  pair.mtu = 1451;
  await until(() => atB.length === data.length, 20_000, "the rest at 1200");
  assert(atB.bytes().equals(data), "what was in flight at 1452 arrived intact, split");
  await until(() => pair.a.buffered() === 0, 5000, "everything to be acked");
  pair.largest = 0;
  writeInPieces(pair.a, randomBytes(256 * 1024));
  await until(() => pair.a.buffered() === 0, 10_000, "more to be acked");
  assert(pair.largest === 1200, `the probe after the drop finds 1452 gone, so packets stay 1200: ${pair.largest}`);
  pair.a.close(); pair.b.close();
});

await test("a stall drops packets to 1200 too, and the probe once the peer acks again raises them back", async () => {
  const pair = streamPair();
  const atB = reader(pair.b);
  await settle(100);
  pair.dead = true;
  const data = randomBytes(256 * 1024);
  writeInPieces(pair.a, data);
  await settle(300);
  pair.dead = false;
  await until(() => atB.length === data.length, 20_000, "the data after the stall");
  assert(atB.bytes().equals(data), "intact");
  pair.largest = 0;
  writeInPieces(pair.a, randomBytes(256 * 1024));
  await until(() => pair.a.buffered() === 0, 10_000, "more to be acked");
  assert(pair.largest === 1452, `packets are 1452 again: ${pair.largest}`);
  pair.a.close(); pair.b.close();
});

await test("losses through three probe timeouts start the window over at two packets, and a peer that only stalls keeps it", async () => {
  const burst = {};
  for (const outage of [true, false]) {
    const pair = streamPair();
    const atB = reader(pair.b);
    writeInPieces(pair.a, randomBytes(8 * CREDIT));
    await until(() => atB.length > 2 * CREDIT, 10_000, "the window to open");
    // Nothing gets across for a second, or everything does and only the acks wait.
    if (outage) pair.dead = true; else pair.held = [];
    await settle(1000);
    pair.dead = false;
    pair.held ??= [];
    await until(() => pair.held.length > 0, 10_000, "an ack from b");
    const before = pair.toB;
    pair.release();
    burst[outage ? "outage" : "stall"] = pair.toB - before;
    pair.a.close(); pair.b.close();
  }
  assert(burst.outage <= 2, `after the outage, the first acks let out two packets: ${burst.outage}`);
  assert(burst.stall > 100, `after the stall, the acks let out the window: ${burst.stall}`);
});

await test("a graceful close lets what was written arrive first, then the peer hears the close", async () => {
  const { a, b } = streamPair({ loss: 0.05, late: 0.02 });
  const atB = reader(b);
  const data = randomBytes(256 * 1024);
  writeInPieces(a, data);
  a.close(true);
  let refused = false;
  try { a.send(Uint8Array.of(1)); } catch { refused = true; }
  assert(refused, "nothing is written after a close");
  await until(() => atB.closed, 10_000, "the close to reach the peer");
  assert(atB.length === data.length && atB.bytes().equals(data), "everything written came before it");
});

await test("a hard close reaches the peer at once", async () => {
  const { a, b } = streamPair();
  const atB = reader(b);
  a.send(randomBytes(64 * 1024));
  a.close();
  await until(() => atB.closed, 1000, "the peer to hear it");
});

// ── STUN ─────────────────────────────────────────────────────────────────────

/** A Binding success for `req` naming `host`:`port`, as seedrelay's `--stun` writes one. */
function stunAnswer(req, host, port) {
  const out = Buffer.alloc(32);
  out.writeUInt16BE(0x0101, 0);
  out.writeUInt16BE(12, 2);
  Buffer.from(req).copy(out, 4, 4, 20);
  out.writeUInt16BE(0x0020, 20);
  out.writeUInt16BE(8, 22);
  out[25] = 1;
  out.writeUInt16BE(port ^ 0x2112, 26);
  host.split(".").forEach((o, i) => { out[28 + i] = Number(o) ^ out[4 + i]; });
  return out;
}

console.log("\nUDP: STUN (§12.7)\n");

await test("a Binding answer names the address its server saw, for its own request only", async () => {
  const txn = randomBytes(12);
  const req = bindingRequest(txn);
  assert(req.length === 20 && isStun(req), "a request is a bare 20-byte header");
  const answer = new Uint8Array(stunAnswer(req, "203.0.113.7", 61234));
  assert(mappedAddress(answer, txn) === "203.0.113.7:61234", "the address and port, un-XORed");
  assert(mappedAddress(answer, randomBytes(12)) === null, "an answer to another request is not this one's");
  assert(!isStun(Uint8Array.of(0x64, ...new Uint8Array(30))), "a path's own packet is not STUN");
});

// ── the seam, over real UDP ──────────────────────────────────────────────────

/** A seam whose negotiation messages are recorded as `[tag, text]`. */
async function seam(opts) {
  const net = new UdpNetwork(opts);
  const accepted = [];
  await net.listen([], (channel, arrival) => accepted.push({ channel, arrival }));
  const open = (dest) => {
    const link = net.connect(dest);
    if (!link) return null;
    const up = [];
    link.onData((b) => up.push([b[0], dec.decode(b.subarray(1))]));
    return { link, up };
  };
  return { net, accepted, open };
}

const msg = (tag, text) => Uint8Array.of(tag, ...enc.encode(text));

/** Carry each side's messages to the other, as the transport does, until both have a
 *  data link. */
async function negotiate(A, B, config = "") {
  const offer = A.open(`udp:offer${config}`), answer = B.open(`udp:answer${config}`);
  const carried = [0, 0];
  const carry = () => {
    for (; carried[0] < offer.up.length; carried[0]++) answer.link.send(msg(...offer.up[carried[0]]));
    for (; carried[1] < answer.up.length; carried[1]++) offer.link.send(msg(...answer.up[carried[1]]));
  };
  const timer = setInterval(carry, 5);
  await until(() => A.accepted.length === 1 && B.accepted.length === 1, 5000, "both data links");
  clearInterval(timer);
  return { offer, answer, a: A.accepted[0].channel, b: B.accepted[0].channel };
}

console.log("\nUDP: the udp: socket seam (§12.7)\n");

await test("only udp:offer and udp:answer route, with an optional JSON configuration", async () => {
  const { net, open } = await seam();
  for (const dest of ["rtc:offer", "udp:", "udp:offerx", "udp:offer?{bad", "udp:answer?[1]"])
    assert(open(dest) === null, `${dest} must be no route`);
  assert(open("udp:offer") && open(`udp:answer?${JSON.stringify({ iceServers: [{ urls: "stun:x:9" }] })}`),
    "both roles route, with or without a configuration");
  net.close();
});

await test("two seams punch a path, and its data link carries bytes both ways", async () => {
  const A = await seam(), B = await seam();
  const { offer, answer, a, b } = await negotiate(A, B);
  assert(offer.up[0][0] === RTC_TAG.OFFER && /^[0-9a-f]{16}$/.test(offer.up[0][1]), "the offer is a token");
  assert(answer.up[0][0] === RTC_TAG.ANSWER, "the answer comes first on the answering side");
  assert(offer.up.slice(1).every(([tag, text]) => tag === RTC_TAG.CANDIDATE && /:\d+$/.test(text)),
    "then the candidates, each a host:port");
  assert(A.accepted[0].arrival.via === offer.link && a.stream === true,
    "the data link is a byte stream, announced with its negotiation link as its via");
  const atA = reader(a), atB = reader(b);
  const there = randomBytes(300_000), back = randomBytes(5000);
  a.send(there);
  b.send(back);
  await until(() => atB.length === there.length && atA.length === back.length, 5000, "the bytes");
  assert(atB.bytes().equals(there) && atA.bytes().equals(back), "intact");
  offer.link.close();
  await until(() => atB.closed, 2000, "closing one end's negotiation link to close the other's data link");
  A.net.close(); B.net.close();
});

/** Node's datagrams, with `rebind()` moving the socket to a new port, as a NAT that drops
 *  its mapping does: the peer sees this end arrive from another address. */
function rebindable() {
  let cur, handler;
  return {
    addresses: () => ["127.0.0.1"],
    async bind() {
      cur = await nodeDatagrams.bind();
      const socket = {
        send: (b, port, host) => cur.socket.send(b, port, host),
        onMessage: (cb) => { handler = cb; cur.socket.onMessage(cb); },
        close: () => cur.socket.close(),
      };
      return { port: cur.port, socket };
    },
    async rebind() {
      const old = cur;
      cur = await nodeDatagrams.bind();
      cur.socket.onMessage(handler);
      old.socket.close();
    },
  };
}

await test("a peer that moves to another address keeps its data link, once the new address answers", async () => {
  const moving = rebindable();
  const A = await seam({ datagrams: moving }), B = await seam();
  const { a, b } = await negotiate(A, B);
  const atA = reader(a), atB = reader(b);
  const before = randomBytes(200_000);
  a.send(before);
  await until(() => atB.length === before.length, 5000, "the bytes before the move");
  await moving.rebind();
  // Well inside the 30 s a silent path is given: only a path that moved gets these across.
  const there = randomBytes(300_000), back = randomBytes(300_000);
  a.send(there);
  b.send(back);
  await until(() => atB.length === before.length + there.length && atA.length === back.length, 3000,
    "both directions after the move");
  assert(atB.bytes().equals(Buffer.concat([before, there])) && atA.bytes().equals(back), "intact, and in order");
  assert(!atA.closed && !atB.closed, "neither data link closed");
  A.net.close(); B.net.close();
});

await test("a packet that copies the token from another address draws a challenge, and moves nothing", async () => {
  const A = await seam(), B = await seam();
  const { answer, a, b } = await negotiate(A, B);
  // A stranger that has seen B's token, from a socket that never answers.
  const stranger = createSocket("udp4");
  const challenges = [];
  stranger.on("message", (m) => challenges.push(m));
  await new Promise((r) => stranger.bind(0, "127.0.0.1", r));
  const bPort = Number(answer.up.find(([tag]) => tag === RTC_TAG.CANDIDATE)[1].split(":")[1]);
  const forged = Buffer.concat([Buffer.of(0x00), Buffer.from(answer.up[0][1], "hex"), Buffer.alloc(8)]);
  stranger.send(forged, bPort, "127.0.0.1");
  await until(() => challenges.length > 0, 2000, "B to challenge the stranger's address");
  const atA = reader(a);
  const back = randomBytes(100_000);
  b.send(back);
  await until(() => atA.length === back.length, 3000, "B's bytes, still on the old path");
  assert(atA.bytes().equals(back), "intact");
  stranger.close();
  A.net.close(); B.net.close();
});

await test("a peer's candidates are probed up to a cap, so it cannot aim this node's probes at a crowd", async () => {
  // A platform whose socket records where it sends, and a peer that names 40 candidates.
  const sentTo = new Set();
  const recording = { addresses: () => ["127.0.0.1"], async bind() {
    return { port: 1, socket: { send: (_b, port, host) => sentTo.add(`${host}:${port}`), onMessage() {}, close() {} } };
  } };
  const { net, open } = await seam({ datagrams: recording });
  const answer = open("udp:answer");
  await settle(10);
  answer.link.send(msg(RTC_TAG.OFFER, "00".repeat(8)));
  for (let i = 1; i <= 40; i++) answer.link.send(msg(RTC_TAG.CANDIDATE, `192.0.2.${i}:9`));
  await settle(120);
  assert(sentTo.size === 16, `probes go to 16 addresses, went to ${sentTo.size}`);
  net.close();
});

await test("the address a STUN server sees is a candidate, and a path can be found through it alone", async () => {
  // A server on this machine, which sees each seam at 127.0.0.1, and seams that know no
  // address of their own: the only candidates are what STUN tells them.
  const server = createSocket("udp4");
  let asked = 0;
  server.on("message", (m, from) => { asked++; server.send(stunAnswer(m, from.address, from.port), from.port, from.address); });
  await new Promise((r) => server.bind(0, "127.0.0.1", r));
  const stunOnly = { bind: nodeDatagrams.bind, addresses: () => [] };
  const A = await seam({ datagrams: stunOnly }), B = await seam({ datagrams: stunOnly });
  const config = `?${JSON.stringify({ iceServers: [{ urls: `stun:127.0.0.1:${server.address().port}` }] })}`;
  const { offer, answer } = await negotiate(A, B, config);
  assert(asked >= 2, "each seam asked the server");
  const candidates = [...offer.up, ...answer.up].filter(([tag]) => tag === RTC_TAG.CANDIDATE).map(([, t]) => t);
  assert(candidates.length === 2 && candidates.every((c) => c.startsWith("127.0.0.1:")),
    `one candidate each, the address the server saw, got ${candidates}`);
  A.net.close(); B.net.close();
  server.close();
});

/** An in-memory internet of NATs, in RFC 4787's terms, with a STUN server answering on two
 *  ports at 198.51.100.1, as seedrelay's `--stun` does. A `moderate` NAT keeps one public
 *  port per socket (endpoint-independent mapping); a `strict` one gives each destination a
 *  random public port of the 64,512 above 1023 (endpoint-dependent), as Linux's
 *  `masquerade random` does. Both let in only an address and port a socket has sent to.
 *  Each NAT is a platform, whose machine's own address the world cannot reach, and which
 *  counts the sockets bound and the datagrams sent. */
function natWorld() {
  const STUN_IP = "198.51.100.1", STUN_PORTS = [3478, 3479];
  const nats = new Map();
  const deliver = (fromIp, fromPort, toIp, toPort, bytes) => setImmediate(() => {
    if (toIp === STUN_IP && STUN_PORTS.includes(toPort)) deliver(STUN_IP, toPort, fromIp, fromPort, stunAnswer(bytes, fromIp, fromPort));
    else nats.get(toIp)?.(fromIp, fromPort, toPort, bytes);
  });
  return {
    config: `?${JSON.stringify({ iceServers: STUN_PORTS.map((p) => ({ urls: `stun:${STUN_IP}:${p}` })) })}`,
    nat(kind) {
      const ip = `203.0.113.${nats.size + 1}`;
      const byPublic = new Map(), byKey = new Map();
      let nextPort = 40000;
      nats.set(ip, (fromIp, fromPort, port, bytes) => {
        const m = byPublic.get(port);
        if (m && m.allowed.has(`${fromIp}:${fromPort}`) && !m.socket.closed) m.socket.handler?.(new Uint8Array(bytes), fromIp, fromPort);
      });
      const platform = {
        ip, bound: 0, sent: 0,
        addresses: () => [`10.0.0.${nats.size}`],
        async bind() {
          platform.bound++;
          const own = nextPort++;
          const socket = {
            closed: false, handler: null,
            send(bytes, port, host) {
              if (socket.closed) return;
              platform.sent++;
              const key = kind === "strict" ? `${own}>${host}:${port}` : own;
              let pub = byKey.get(key);
              if (pub === undefined) {
                pub = own;
                if (kind === "strict") do pub = 1024 + Math.floor(Math.random() * 64512); while (byPublic.has(pub));
                byKey.set(key, pub);
                byPublic.set(pub, { socket, allowed: new Set() });
              }
              byPublic.get(pub).allowed.add(`${host}:${port}`);
              deliver(ip, pub, host, port, Uint8Array.from(bytes));
            },
            onMessage(cb) { socket.handler = cb; },
            close() { socket.closed = true; },
          };
          return { port: own, socket };
        },
      };
      return platform;
    },
  };
}

await test("an end whose NAT gives each destination its own port meets a NAT that keeps one, either way round", async () => {
  for (const hardOffers of [true, false]) {
    const world = natWorld();
    const hard = world.nat("strict"), easy = world.nat("moderate");
    const H = await seam({ datagrams: hard }), E = await seam({ datagrams: easy });
    const { offer, answer, a, b } = hardOffers ? await negotiate(H, E, world.config) : await negotiate(E, H, world.config);
    const [atHard, atEasy] = hardOffers ? [offer, answer] : [answer, offer];
    assert(atHard.up.some(([tag, text]) => tag === RTC_TAG.CANDIDATE && text === `${hard.ip}:*`),
      "the hard end, its two STUN answers differing, says so");
    assert(!atEasy.up.some(([, text]) => text.endsWith(":*")), "the easy end does not");
    assert(hard.bound === 257 && easy.bound === 1, `only the hard end opened more sockets, ${hard.bound} and ${easy.bound}`);
    const atA = reader(a), atB = reader(b);
    const there = randomBytes(50_000), back = randomBytes(5000);
    a.send(there);
    b.send(back);
    await until(() => atB.length === there.length && atA.length === back.length, 5000, "the bytes");
    assert(atB.bytes().equals(there) && atA.bytes().equals(back), "intact");
    H.net.close(); E.net.close();
  }
});

await test("two ends that both give each destination their own port stay apart, and spend nothing trying", async () => {
  const world = natWorld();
  const one = world.nat("strict"), two = world.nat("strict");
  const A = await seam({ datagrams: one }), B = await seam({ datagrams: two });
  const offer = A.open(`udp:offer${world.config}`), answer = B.open(`udp:answer${world.config}`);
  const carried = [0, 0];
  const timer = setInterval(() => {
    for (; carried[0] < offer.up.length; carried[0]++) answer.link.send(msg(...offer.up[carried[0]]));
    for (; carried[1] < answer.up.length; carried[1]++) offer.link.send(msg(...answer.up[carried[1]]));
  }, 5);
  await settle(1500);
  clearInterval(timer);
  assert(A.accepted.length === 0 && B.accepted.length === 0, "no path");
  assert(one.bound === 1 && two.bound === 1, "no birthday sockets");
  // The plain punch: a probe each 50 ms to each of a handful of candidates, and no spray.
  assert(one.sent < 300 && two.sent < 300, `no random ports probed, sent ${one.sent} and ${two.sent}`);
  A.net.close(); B.net.close();
});

// ── the transport, over real UDP ─────────────────────────────────────────────

const joinRelay = (node, url) => transportOp(node, new OpArgs("relay").text(url));

/** How `node` reaches each linked peer (`routes`): peer hex to whether the link is direct. */
async function routes(node) {
  const bytes = await transportOp(node, new OpArgs("routes"));
  const out = new Map();
  for (let off = 0; off + 33 <= bytes.length; off += 33)
    out.set(Buffer.from(bytes.slice(off, off + 32)).toString("hex"), bytes[off + 32] === 1);
  return out;
}

/** Nodes in key order, so a test knows which one offers (the smaller key). */
function sortedIdentities(n) {
  return Array.from({ length: n }, () => generateKeyPair())
    .sort((a, b) => Buffer.compare(Buffer.from(a.publicKey), Buffer.from(b.publicKey)));
}

/** Register both on `relay` and link `a` to `b` through it. */
async function relayLink(a, b, origin = "ws://relay") {
  for (const n of [a, b]) await joinRelay(n, origin);
  await transportOp(a, new OpArgs("addr").blob(Buffer.from(b.peerId, "hex")).blob(new Uint8Array(32)).text("relay+" + origin));
  await a.request(b.peerId, PROTO, Uint8Array.of(0));
}

/** A factory that routes nothing and notes what it was asked for. */
function spyChannels(seen) {
  return { connect(dest) { seen.push(dest); return null; }, listen: async (addrs) => addrs.map(() => 0), close() {} };
}

console.log("\nUDP: the transport's move to a UDP path (§12.7)\n");

await test("two nodes linked through the relay move to a UDP path", async (keep) => {
  const relay = new FakeRelay("relay:8080");
  const A = keep(await makeTransportHost({ channels: combineChannels(relay.factory(), new UdpNetwork()) }));
  const B = keep(await makeTransportHost({ channels: combineChannels(relay.factory(), new UdpNetwork()) }));
  await relayLink(A, B, "ws://relay:8080");
  await until(() => relay.splices.length === 1 && relay.splices[0].every((e) => e.dead), 5000, "the splice to be retired");
  const before = relay.spliceBytes;
  const resp = await A.request(B.peerId, PROTO, Uint8Array.of(7, 8, 9));
  assert(resp.length === 3 && resp[2] === 9, "a request crosses the UDP path");
  const big = await B.request(A.peerId, PROTO, generatorRequest(1024 * 1024, 7));
  assert(big.length === 1024 * 1024 && big.every((x, i) => x === ((i * 7) & 255)), "and a large answer, intact");
  assert(relay.spliceBytes === before, "and not the relay");
  assert((await routes(A)).get(B.peerId) === true && (await routes(B)).get(A.peerId) === true,
    "`routes` reads the peer as direct at both ends");
});

await test("a peer with no UDP path declines it, and the offering side offers WebRTC next", async (keep) => {
  const relay = new FakeRelay();
  const [small, large] = sortedIdentities(2);
  const seen = [];
  const A = keep(await makeTransportHost({ identity: small, channels: combineChannels(relay.factory(), new UdpNetwork(), spyChannels(seen)) }));
  const B = keep(await makeTransportHost({ identity: large, channels: relay.factory() }));
  await relayLink(A, B);
  await until(() => seen.some((d) => d.startsWith("rtc:offer")), 3000, "a WebRTC offer after the decline");
  assert(!seen.some((d) => d.startsWith("udp:")), "the UDP offer went to the UDP seam, which routed it");
  assert((await linkedPeers(A)).includes(B.peerId) && (await routes(A)).get(B.peerId) === false,
    "with neither, the relayed link stays");
});

summary("UDP");
