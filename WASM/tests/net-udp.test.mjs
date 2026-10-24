// The UDP path (§12.7): the transport's own (transport/src/udp.js, stream.js), which finds a
// path between two of the host's datagram sockets and runs a reliable stream over it, and
// the host's side, which lends the occupant the sockets and nothing more
// (host/transport-host.ts). The stream and the punch run here as the transport's two parts
// in a realm of their own, over the host's real datagram service, on an in-memory fabric
// that loses, repeats and reorders, or on real UDP on this machine; the transport's move
// to a UDP path runs whole nodes, with the in-process relay (fake-relay.mjs) for
// signaling. Run after `npm run build`.

import vm from "node:vm";
import { createSocket } from "node:dgram";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { importBuilt, testkit } from "./testkit.mjs";
import { FakeRelay } from "./fake-relay.mjs";
import {
  makeTransportHost, until, linkedPeers, transportOp, OpArgs, PROTO, generateKeyPair, generatorRequest, TransportHost,
} from "./transport-harness.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = importBuilt(root);
const { nodeRawDatagrams } = await imp("build/services/datagrams-node.js");
const { forEachDatagram, ipv6Bytes } = await imp("build/services/datagrams.js");
const { guestOpFraming } = await imp("build/scripts/bundle-author.js");
const { RTC_TAG } = await imp("build/services/net-rtc.js");
const { combineChannels } = await imp("build/services/socket-seam.js");

const { test, assert, summary } = testkit();
const enc = new TextEncoder();
const settle = (ms = 50) => new Promise((r) => setTimeout(r, ms));
const CREDIT = 1 << 20, MAX_READ = 256 * 1024;

// ── the transport's UDP parts, in a realm of their own ───────────────────────

/** The parts as the bundle assembles them (scripts/guest-source.mjs), and what the rest of
 *  the transport gives them: the wake and retried calls (core.js), entropy (ake.js), the negotiation tags
 *  (direct.js) and the `datagrams` event. */
const UDP_SOURCE = ["util.js", "stream.js", "udp.js"]
  .map((f) => readFileSync(join(root, "transport", "src", f), "utf8")).join("\n")
  .replace("/* @seedkernel-op-frame */", guestOpFraming()) + `
const host = __host;
const RTC_OFFER = 0x6f, RTC_ANSWER = 0x61, RTC_CANDIDATE = 0x63;
const now = () => performance.now();
let wakeAt = Infinity, wakeTimer;
function wakeBy(at) {
  if (at >= wakeAt) return;
  wakeAt = at;
  clearTimeout(wakeTimer);
  wakeTimer = setTimeout(() => { wakeAt = Infinity; wakeBy(udp.onWake(now())); }, Math.max(0, at - now()));
}
function dueIn(ms) { const at = now() + ms; wakeBy(at); return at; }
function callRetried(name, bytes) { void host.call(name, bytes).catch(() => {}); }
function randomBytes(n) { return host.call("crypto/random", argU32(n)); }
const udp = new Udp();
globalThis.__handle = (input) => {
  const { op, args } = readOp(callerOf(input).body);
  if (op === "datagrams") udp.onDatagrams(new Reader(args));
  return Promise.resolve(EMPTY);
};
globalThis.__open = (offer, iceServers) => udp.open(offer, iceServers);
globalThis.__stop = () => { clearTimeout(wakeTimer); for (const n of [...udp.live]) n.close(); };
`;

/** The pure helpers, from a realm of their own. */
const LIB = vm.createContext({ setTimeout, clearTimeout, performance, __host: null });
vm.runInContext(UDP_SOURCE, LIB);
const { ipv6Text } = LIB;

/** One node's UDP side over `raw`: the transport's parts in a realm, and the host's
 *  datagram service, which they reach as they reach it in the transport (`link/udp*`).
 *  `open(offer, iceServers)` starts a negotiation, its messages up recorded as
 *  `[tag, text]` and its stream as `data` once a path is found. */
function udpRealm(raw = nodeRawDatagrams()) {
  const driver = new TransportHost({ datagrams: raw, suppressLinkLog: true });
  const net = driver.rawNet();
  const ctx = vm.createContext({ setTimeout, clearTimeout, performance });
  ctx.__host = {
    async call(name, payload) {
      const p = new Uint8Array(payload);
      if (name === "link/udpBind") {
        const s = await net.udpBind();
        const a = enc.encode(s.addresses);
        const out = new Uint8Array(6 + a.length);
        new DataView(out.buffer).setUint32(0, s.id);
        out[4] = s.port >> 8; out[5] = s.port & 255;
        out.set(a, 6);
        return out;
      }
      if (name === "link/udpSend") { net.udpSend(p); return new Uint8Array(0); }
      if (name === "link/udpClose") { net.udpClose(new DataView(p.buffer).getUint32(0)); return new Uint8Array(0); }
      if (name === "crypto/random") return new Uint8Array(randomBytes(new DataView(p.buffer).getUint32(0)));
      throw new Error(`no host name ${name}`);
    },
  };
  vm.runInContext(UDP_SOURCE, ctx);
  driver.activate((input) => ctx.__handle(input));
  const accepted = [];
  const open = async (offer, iceServers = []) => {
    const n = await ctx.__open(offer, iceServers);
    if (!n) return null;
    const o = { n, up: [], data: null, get closed() { return n.dead; } };
    n.start({
      up: (tag, text) => o.up.push([tag, text]),
      open: (_id, stream) => { o.data = stream; accepted.push(stream); },
      closed: () => {},
    });
    return o;
  };
  return { accepted, open, close: () => { ctx.__stop(); driver.close(); } };
}

/** Carry each side's messages to the other, as the transport does, until both have a
 *  data link. */
async function negotiate(A, B, iceServers = []) {
  const offer = await A.open(true, iceServers), answer = await B.open(false, iceServers);
  const carried = [0, 0];
  const carry = () => {
    for (; carried[0] < offer.up.length; carried[0]++) answer.n.down(...offer.up[carried[0]]);
    for (; carried[1] < answer.up.length; carried[1]++) offer.n.down(...answer.up[carried[1]]);
  };
  const timer = setInterval(carry, 5);
  await until(() => offer.data && answer.data, 5000, "both data links");
  clearInterval(timer);
  return { offer, answer, a: offer.data, b: answer.data };
}

/** What a stream's reader, the link, is handed. `hold()` keeps it decoding the next read
 *  until `release()`, as a link busy with its records does. */
function reader(stream) {
  const parts = [];
  let go = null;
  const r = {
    length: 0, largest: 0, held: false,
    get closed() { return stream.gone; },
    bytes: () => Buffer.concat(parts),
    hold() { r.held = true; },
    release() { r.held = false; const g = go; go = null; g?.(); },
  };
  stream.reader((b) => {
    parts.push(Buffer.from(b));
    r.length += b.length;
    r.largest = Math.max(r.largest, b.length);
    return r.held ? new Promise((resolve) => { go = resolve; }) : Promise.resolve();
  });
  return r;
}

/** Write `bytes` in pieces of random size, as the link's records come. */
function writeInPieces(stream, bytes) {
  for (let at = 0; at < bytes.length;) {
    const n = Math.min(bytes.length - at, 1 + Math.floor(Math.random() * 40_000));
    stream.send(bytes.subarray(at, at + n));
    at += n;
  }
}

/** Write `bytes` as `writeInPieces` does, holding off while the stream has 8 MiB unacked,
 *  as the link's own outbound bounds do. */
async function writePaced(stream, bytes) {
  for (let at = 0; at < bytes.length; at += CREDIT) {
    while (stream.buffered() > 8 * CREDIT) await settle(5);
    writeInPieces(stream, bytes.subarray(at, at + CREDIT));
  }
}

/** Write `n` as the stream's 48-bit big-endian packet and offset fields. */
const put48 = (p, at, n) => {
  for (let i = 5; i >= 0; i--, n = Math.floor(n / 256)) p[at + i] = n % 256;
};

/** A batch of one datagram, as a platform hands one over: `[n u8][ip n][port u16][len u16][bytes]`. */
function batchOf(host, port, bytes) {
  const ip = host.includes(":") ? ipv6Bytes(host) : Uint8Array.from(host.split("."), Number);
  const out = new Uint8Array(5 + ip.length + bytes.length);
  out[0] = ip.length;
  out.set(ip, 1);
  const at = 1 + ip.length;
  out[at] = port >> 8; out[at + 1] = port & 255;
  out[at + 2] = bytes.length >> 8; out[at + 3] = bytes.length & 255;
  out.set(bytes, at + 4);
  return out;
}

/** One datagram as a send batch carries it: `[socket u32][hostLen u8][host][port u16][len u16][bytes]`. */
function sendOf(id, host, port, bytes) {
  const h = enc.encode(host), out = new Uint8Array(9 + h.length + bytes.length);
  out[0] = id >>> 24; out[1] = (id >>> 16) & 255; out[2] = (id >>> 8) & 255; out[3] = id & 255;
  out[4] = h.length;
  out.set(h, 5);
  const at = 5 + h.length;
  out[at] = port >> 8; out[at + 1] = port & 255;
  out[at + 2] = bytes.length >> 8; out[at + 3] = bytes.length & 255;
  out.set(bytes, at + 4);
  return out;
}

/** Raw datagrams over a platform of `{ addresses() -> string[], bind() -> { port, socket } }`,
 *  each socket `{ send(bytes, port, host), onMessage(cb), close() }`: the shape this file's
 *  fake networks are written in. */
function rawOver(platform) {
  const sockets = new Map();
  let seq = 0;
  return {
    async bind(deliver) {
      const { port, socket } = await platform.bind();
      const id = ++seq;
      sockets.set(id, socket);
      socket.onMessage((bytes, host, from) => deliver(batchOf(host, from, bytes)));
      return { id, port };
    },
    send: (batch) => forEachDatagram(batch, (id, host, port, bytes) => sockets.get(id)?.send(bytes, port, host)),
    close: (id) => { sockets.get(id)?.close(); sockets.delete(id); },
    addresses: () => platform.addresses().join("\n"),
  };
}

/** Node's sockets in that shape, with `addresses` as given. */
function nodePlatform(addresses) {
  const raw = nodeRawDatagrams();
  return {
    addresses,
    async bind() {
      let handler = () => {};
      const { id, port } = await raw.bind((batch) => {
        const b = new Uint8Array(batch);
        for (let at = 0; at < b.length;) {
          const n = b[at], ip = b.subarray(at + 1, at + 1 + n);
          const from = (b[at + 1 + n] << 8) | b[at + 2 + n], len = (b[at + 3 + n] << 8) | b[at + 4 + n];
          handler(b.slice(at + 5 + n, at + 5 + n + len), n === 4 ? ip.join(".") : ipv6Text(ip), from);
          at += 5 + n + len;
        }
      }, 1 << 20);
      return { port, socket: { send: (bytes, p, h) => raw.send(sendOf(id, h, p, bytes)), onMessage: (cb) => { handler = cb; }, close: () => raw.close(id) } };
    },
  };
}

// ── the stream, over an in-memory fabric ─────────────────────────────────────

/** Machines joined by a fabric that drops `loss` of what crosses, sends `dup` of it twice,
 *  and holds `late` of it back 5 ms, behind what was sent after it, or takes `delay` ms
 *  each way. `cut()` drops everything from then on, and a datagram larger than `mtu` is
 *  dropped; both it and `loss` can change. A machine made `toA` is b, and the next
 *  `dropToA` datagrams it sends are dropped. While `held` is an array, what b sends waits
 *  in it, as the acks of a peer whose loop is held do, and `release()` hands it all over at
 *  once. `largest` is the largest DATA packet a sent b since it was last set to 0, `toB`
 *  counts them, and `ackToA` is the size of the last ACK b sent a, `onAck` called with the
 *  credit it grants. */
function fabric({ loss = 0, dup = 0, late = 0, mtu = Infinity, delay = 0 } = {}) {
  const sockets = new Map();
  let nextPort = 40000;
  const f = {
    loss, mtu, dead: false, largest: 0, toB: 0, dropToA: 0, ackToA: 0, held: null,
    cut: () => { f.dead = true; },
    release: () => { const held = f.held ?? []; f.held = null; for (const go of held) go(); },
    machine: (ip, toA) => ({
      addresses: () => [ip],
      async bind() {
        const port = nextPort++;
        const socket = {
          handler: null, closed: false,
          send(bytes, toPort, toHost) {
            if (socket.closed) return;
            const p = Uint8Array.from(bytes);
            if (!toA && p[0] === 0x64) { f.largest = Math.max(f.largest, p.length); f.toB++; }
            if (toA && p[0] === 0x61) { f.ackToA = p.length; f.onAck?.(Buffer.from(p.buffer, p.byteOffset).readUIntBE(9, 6)); }
            if (toA && f.dropToA > 0) { f.dropToA--; return; }
            const copies = f.dead || p.length > f.mtu || Math.random() < f.loss ? 0 : Math.random() < dup ? 2 : 1;
            for (let i = 0; i < copies; i++) {
              const arrive = () => {
                const to = sockets.get(`${toHost}:${toPort}`);
                if (to && !to.closed) to.handler?.(Uint8Array.from(p), ip, port);
              };
              if (toA && f.held) f.held.push(arrive);
              else if (delay > 0) setTimeout(arrive, delay);
              else if (Math.random() < late) setTimeout(arrive, 5);
              else setImmediate(arrive);
            }
          },
          onMessage(cb) { socket.handler = cb; },
          close() { socket.closed = true; },
        };
        sockets.set(`${ip}:${port}`, socket);
        return { port, socket };
      },
    }),
  };
  return f;
}

/** a at 10.0.0.1 and b at 10.0.0.2 on a fabric, with a path negotiated between them. */
async function streamPair(opts) {
  const pair = fabric(opts);
  const A = udpRealm(rawOver(pair.machine("10.0.0.1", false))), B = udpRealm(rawOver(pair.machine("10.0.0.2", true)));
  const { a, b } = await negotiate(A, B);
  pair.close = () => { A.close(); B.close(); };
  return Object.assign(pair, { a, b, A, B });
}

console.log("\nUDP: the stream (§12.7)\n");

await test("the stream delivers in order through loss, repeats and reordering, both ways", async () => {
  const pair = await streamPair({ loss: 0.05, dup: 0.02, late: 0.02 });
  const toB = randomBytes(1024 * 1024), toA = randomBytes(128 * 1024);
  const atB = reader(pair.b), atA = reader(pair.a);
  writeInPieces(pair.a, toB);
  writeInPieces(pair.b, toA);
  await until(() => atB.length === toB.length && atA.length === toA.length, 30_000, "both directions to arrive");
  assert(atB.bytes().equals(toB) && atA.bytes().equals(toA), "what arrives is what was written, in order");
  await until(() => pair.a.buffered() === 0 && pair.b.buffered() === 0, 5000, "everything to be acked");
  pair.close();
});

await test("a reader still decoding stops the sender at its credit, and lets it go again", async () => {
  const pair = await streamPair();
  const atB = reader(pair.b);
  atB.hold();
  const data = randomBytes(4 * CREDIT);
  writeInPieces(pair.a, data);
  await settle(300);
  assert(atB.length <= MAX_READ, `the reader has its first read only, ${atB.length}`);
  assert(pair.a.buffered() >= data.length - CREDIT - MAX_READ,
    `the sender keeps what is past the credit, has ${pair.a.buffered()}`);
  atB.release();
  await until(() => atB.length === data.length, 10_000, "the rest once the reader reads");
  assert(atB.bytes().equals(data), "and in order");
  assert(atB.largest === MAX_READ, `what was held is handed over in large reads, the largest ${atB.largest}`);
  pair.close();
});

await test("a sender held at its credit goes on at once, though the ack that lets it go is lost", async () => {
  const pair = await streamPair();
  const atB = reader(pair.b);
  atB.hold();
  const data = randomBytes(2 * CREDIT);
  writeInPieces(pair.a, data);
  await settle(300);
  pair.dropToA = 1;
  const t0 = performance.now();
  atB.release();
  await until(() => atB.length === data.length, 5000, "the rest, without waiting for a keepalive");
  const ms = performance.now() - t0;
  assert(ms < 1000 && atB.bytes().equals(data), `it arrives in order in ${ms.toFixed(0)} ms`);
  pair.close();
});

await test("a reader slow to decode each read takes a long stream that never drains", async () => {
  const pair = await streamPair();
  const parts = [];
  let length = 0;
  pair.b.reader((bytes) => {
    parts.push(Buffer.from(bytes)); length += bytes.length;
    return new Promise((r) => setTimeout(r, 2));
  });
  const data = randomBytes(24 * CREDIT);
  void writePaced(pair.a, data);
  await until(() => length === data.length || pair.b.gone, 30_000, "all of it");
  assert(!pair.b.gone && Buffer.concat(parts).equals(data), `in order and open, ${length} of ${data.length}`);
  pair.close();
});

await test("a sender held by its credit alone, its reader keeping up, is given more, up to eight credits", async () => {
  // 50 ms a round trip: one credit a round trip is 21 MB/s, which the path beats.
  const pair = await streamPair({ delay: 25 });
  const atB = reader(pair.b);
  let most = 0;
  pair.onAck = (granted) => { most = Math.max(most, granted - atB.length); };
  const data = randomBytes(24 * CREDIT);
  void writePaced(pair.a, data);
  await until(() => atB.length === data.length, 30_000, "all of it");
  assert(atB.bytes().equals(data), "in order");
  assert(most >= 2 * CREDIT && most <= 8 * CREDIT, `the credit grew to ${(most / CREDIT).toFixed(1)} credits`);
  pair.close();
});

await test("acks name only what the sender still waits on, so a lossy stretch leaves them one range", async () => {
  const pair = await streamPair({ loss: 0.05 });
  const atB = reader(pair.b);
  writeInPieces(pair.a, randomBytes(2 * CREDIT));
  await until(() => pair.a.buffered() === 0, 20_000, "the lossy stretch to be acked");
  pair.loss = 0;
  for (const n of [256 * 1024, 64 * 1024]) {
    writeInPieces(pair.a, randomBytes(n));
    await until(() => pair.a.buffered() === 0, 10_000, "more to be acked");
    await settle(200);
  }
  assert(pair.ackToA === 9 + 9 + 12, `the last ack is one range, ${pair.ackToA} bytes`);
  assert(atB.length === 2 * CREDIT + 320 * 1024, "everything arrived");
  pair.close();
});

/** A stranger's socket on this machine, and the port and token of the end that sent
 *  `opened`'s messages, read off its description and first candidate: something that has
 *  seen the token can send that end packets. */
async function stranger(opened) {
  const s = createSocket("udp4");
  const heard = [];
  s.on("message", (m) => heard.push(m));
  await new Promise((r) => s.bind(0, "127.0.0.1", r));
  const port = Number(opened.up.find(([tag]) => tag === RTC_TAG.CANDIDATE)[1].split(":").at(-1));
  const token = Buffer.from(opened.up[0][1], "hex");
  return { s, heard, port, token };
}

await test("chunks past a gap at overlapping offsets end the stream at two credits, not at memory", async () => {
  const A = udpRealm(), B = udpRealm();
  const { offer, a } = await negotiate(A, B);
  const atA = reader(a);
  const x = await stranger(offer);
  // DATA [type][token 8][pn 6][offset 6][floor 6][1400 bytes], well past the next offset.
  const p = Buffer.alloc(27 + 1400);
  p[0] = 0x64;
  x.token.copy(p, 1);
  for (let sent = 1; sent <= 1500 && !atA.closed; sent++) {
    put48(p, 9, 1e6 + sent); put48(p, 15, 10_000 + sent);
    x.s.send(Buffer.from(p), x.port, "127.0.0.1");
    if (sent % 100 === 0) await settle(5);
  }
  await until(() => atA.closed, 3000, "the stream to close at two credits held");
  x.s.close();
  A.close(); B.close();
});

/** A pair whose path has carried data both ways, so each end has measured the round trip
 *  (a negotiated path starts at QUIC's initial 333 ms). */
async function warmPair(opts) {
  const pair = await streamPair(opts);
  reader(pair.a); reader(pair.b);
  pair.a.send(randomBytes(64 * 1024));
  pair.b.send(randomBytes(64 * 1024));
  await until(() => pair.a.buffered() === 0 && pair.b.buffered() === 0, 5000, "the warm-up to be acked");
  return pair;
}

await test("data the peer stops answering ends the stream well inside the silent path's 30 s", async () => {
  const pair = await warmPair();
  const t0 = performance.now();
  pair.cut();
  pair.a.send(randomBytes(64 * 1024));
  await until(() => pair.a.gone, 20_000, "the sender to give up");
  const s = (performance.now() - t0) / 1000;
  // The floor counts from the last packet heard, a moment before the cut.
  assert(s >= 9.5 && s < 20, `it gives up after the 10 s floor, and before 20 s, at ${s.toFixed(1)} s`);
  pair.close();
});

await test("packets grow to 1452 bytes on a path a probe shows carries them, and stay 1200 on one that does not", async () => {
  for (const [mtu, want] of [[Infinity, 1452], [1451, 1200]]) {
    const pair = await streamPair({ mtu });
    const atB = reader(pair.b);
    await settle(100);
    const data = randomBytes(512 * 1024);
    writeInPieces(pair.a, data);
    await until(() => atB.length === data.length, 10_000, "the data to arrive");
    assert(atB.bytes().equals(data), "intact");
    assert(pair.largest === want, `on a path carrying ${mtu}, the largest packet is ${want}: ${pair.largest}`);
    pair.close();
  }
});

await test("a path that stops carrying the larger packets drops back to 1200, splitting what was cut larger", async () => {
  const pair = await streamPair({ loss: 0.02, late: 0.02 });
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
  pair.close();
});

await test("a stall drops packets to 1200 too, and the probe once the peer acks again raises them back", async () => {
  const pair = await streamPair();
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
  pair.close();
});

await test("losses through three probe timeouts start the window over at two packets, and a peer that only stalls keeps it", async () => {
  const burst = {};
  for (const outage of [true, false]) {
    const pair = await streamPair();
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
    // What the held acks let out, in a's next turn: the acks to that are held again.
    pair.held = [];
    await settle(20);
    burst[outage ? "outage" : "stall"] = pair.toB - before;
    pair.close();
  }
  assert(burst.outage <= 4, `after the outage, the first acks let out a couple of packets: ${burst.outage}`);
  assert(burst.stall > 100, `after the stall, the acks let out the window: ${burst.stall}`);
});

await test("a graceful close lets what was written arrive first, then the peer hears the close", async () => {
  const pair = await streamPair({ loss: 0.05, late: 0.02 });
  const atB = reader(pair.b);
  const data = randomBytes(256 * 1024);
  writeInPieces(pair.a, data);
  pair.a.close(true);
  let refused = false;
  try { pair.a.send(Uint8Array.of(1)); } catch { refused = true; }
  assert(refused, "nothing is written after a close");
  await until(() => atB.closed, 10_000, "the close to reach the peer");
  assert(atB.length === data.length && atB.bytes().equals(data), "everything written came before it");
  pair.close();
});

await test("a hard close reaches the peer at once", async () => {
  const pair = await streamPair();
  const atB = reader(pair.b);
  pair.a.send(randomBytes(64 * 1024));
  pair.a.close(false);
  await until(() => atB.closed, 1000, "the peer to hear it");
  pair.close();
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

// ── the punch, over real UDP ─────────────────────────────────────────────────

console.log("\nUDP: finding a path (§12.7)\n");

await test("two ends punch a path, and its stream carries bytes both ways", async () => {
  const A = udpRealm(), B = udpRealm();
  const { offer, answer, a, b } = await negotiate(A, B);
  assert(offer.up[0][0] === RTC_TAG.OFFER && /^[0-9a-f]{16}$/.test(offer.up[0][1]), "the offer is a token");
  assert(answer.up[0][0] === RTC_TAG.ANSWER, "the answer comes first on the answering side");
  assert(offer.up.slice(1).every(([tag, text]) => tag === RTC_TAG.CANDIDATE && /:\d+$/.test(text)),
    "then the candidates, each a host:port");
  const atA = reader(a), atB = reader(b);
  const there = randomBytes(300_000), back = randomBytes(5000);
  a.send(there);
  b.send(back);
  await until(() => atB.length === there.length && atA.length === back.length, 5000, "the bytes");
  assert(atB.bytes().equals(there) && atA.bytes().equals(back), "intact");
  offer.n.close();
  await until(() => atB.closed, 2000, "ending one end's negotiation to close the other's stream");
  A.close(); B.close();
});

await test("an end with no socket from its host has no path, which the transport takes as no route", async () => {
  const A = udpRealm({ ...nodeRawDatagrams(), bind: async () => { throw new Error("no sockets"); } });
  assert(await A.open(true) === null, "the negotiation is refused before it starts");
  A.close();
});

/** Node's sockets, with `rebind()` moving the socket to a new port, as a NAT that drops its
 *  mapping does: the peer sees this end arrive from another address. */
function rebindable() {
  const node = nodePlatform(() => ["127.0.0.1"]);
  let cur, handler;
  return {
    addresses: () => ["127.0.0.1"],
    async bind() {
      cur = await node.bind();
      const socket = {
        send: (b, port, host) => cur.socket.send(b, port, host),
        onMessage: (cb) => { handler = cb; cur.socket.onMessage(cb); },
        close: () => cur.socket.close(),
      };
      return { port: cur.port, socket };
    },
    async rebind() {
      const old = cur;
      cur = await node.bind();
      cur.socket.onMessage(handler);
      old.socket.close();
    },
  };
}

await test("a peer that moves to another address keeps its stream, once the new address answers", async () => {
  const moving = rebindable();
  const A = udpRealm(rawOver(moving)), B = udpRealm();
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
  assert(!atA.closed && !atB.closed, "neither stream closed");
  A.close(); B.close();
});

await test("a packet that copies the token from another address draws a challenge, and moves nothing", async () => {
  const A = udpRealm(), B = udpRealm();
  const { offer, a, b } = await negotiate(A, B);
  // A stranger that has seen A's token, from a socket that never answers. A is the offering
  // end, which challenges at once; the answering end would wait for its path to go quiet.
  const x = await stranger(offer);
  const forged = Buffer.concat([Buffer.of(0x00), x.token, Buffer.alloc(8)]);
  x.s.send(forged, x.port, "127.0.0.1");
  await until(() => x.heard.length > 0, 2000, "A to challenge the stranger's address");
  const atB = reader(b);
  const there = randomBytes(100_000);
  a.send(there);
  await until(() => atB.length === there.length, 3000, "A's bytes, still on the old path");
  assert(atB.bytes().equals(there), "intact");
  x.s.close();
  A.close(); B.close();
});

/** Two machines on two networks, 10.1/16 and 10.2/16, with an address on each, listed in
 *  opposite orders. A datagram leaves from the sender's address on the network it goes to,
 *  as a route picks it, so each end sees the other arrive from the address it sent to. It
 *  takes 20 ms, so each end's own probes are answered before the other's reach it, and the
 *  two take paths on different networks. `moves` counts how often an end's stream packets
 *  change destination: each is its path moving. */
function twoNetworks() {
  const sockets = new Map();
  const moves = { n: 0 };
  let nextPort = 40000;
  const machine = (n, nets) => ({
    addresses: () => nets.map((net) => `10.${net}.0.${n}`),
    async bind() {
      const port = nextPort++;
      let dataTo = null;
      const socket = {
        handler: null, closed: false,
        send(bytes, toPort, toHost) {
          const from = `10.${toHost.split(".")[1]}.0.${n}`, copy = Uint8Array.from(bytes);
          if (copy[0] === 0x64) {
            const to = `${toHost}:${toPort}`;
            if (dataTo !== null && dataTo !== to) moves.n++;
            dataTo = to;
          }
          setTimeout(() => {
            const to = sockets.get(`${toHost}:${toPort}`);
            if (!socket.closed && to && !to.closed) to.handler?.(copy, from, port);
          }, 20);
        },
        onMessage(cb) { socket.handler = cb; },
        close() { socket.closed = true; },
      };
      for (const net of nets) sockets.set(`10.${net}.0.${n}:${port}`, socket);
      return { port, socket };
    },
  });
  return [machine(1, [1, 2]), machine(2, [2, 1]), moves];
}

await test("two ends with two addresses each settle on one path, though each first takes the other's", async () => {
  const [one, two, moves] = twoNetworks();
  const A = udpRealm(rawOver(one)), B = udpRealm(rawOver(two));
  const { a, b } = await negotiate(A, B);
  const atA = reader(a), atB = reader(b);
  const there = randomBytes(500_000), back = randomBytes(500_000);
  a.send(there);
  b.send(back);
  await until(() => atB.length === there.length && atA.length === back.length, 10_000, "the bytes");
  assert(atB.bytes().equals(there) && atA.bytes().equals(back), "intact");
  // One end follows the other's address, once; both following at once swaps them forever.
  assert(moves.n <= 2, `the paths settle, after ${moves.n} moves`);
  A.close(); B.close();
});

/** A platform whose socket records where it sends, as `host port`. */
function recording(sentTo) {
  return {
    addresses: () => ["127.0.0.1"],
    async bind() {
      return { port: 1, socket: { send: (_b, port, host) => sentTo.add(`${host} ${port}`), onMessage() {}, close() {} } };
    },
  };
}

await test("a peer's candidates are probed up to a cap, so it cannot aim this node's probes at a crowd", async () => {
  const sentTo = new Set();
  const A = udpRealm(rawOver(recording(sentTo)));
  const answer = await A.open(false);
  answer.n.down(RTC_TAG.OFFER, "00".repeat(8));
  for (let i = 1; i <= 40; i++) answer.n.down(RTC_TAG.CANDIDATE, `192.0.2.${i}:9`);
  await settle(120);
  assert(sentTo.size === 16, `probes go to 16 addresses, went to ${sentTo.size}`);
  A.close();
});

await test("the address a STUN server sees is a candidate, and a path can be found through it alone", async () => {
  // A server on this machine, which sees each end at 127.0.0.1, and ends that know no
  // address of their own: the only candidates are what STUN tells them.
  const server = createSocket("udp4");
  let asked = 0;
  server.on("message", (m, from) => { asked++; server.send(stunAnswer(m, from.address, from.port), from.port, from.address); });
  await new Promise((r) => server.bind(0, "127.0.0.1", r));
  const A = udpRealm(rawOver(nodePlatform(() => []))), B = udpRealm(rawOver(nodePlatform(() => [])));
  const { offer, answer } = await negotiate(A, B, [{ urls: `stun:127.0.0.1:${server.address().port}` }]);
  assert(asked >= 2, "each end asked the server");
  const candidates = [...offer.up, ...answer.up].filter(([tag]) => tag === RTC_TAG.CANDIDATE).map(([, t]) => t);
  assert(candidates.length === 2 && candidates.every((c) => c.startsWith("127.0.0.1:")),
    `one candidate each, the address the server saw, got ${candidates}`);
  A.close(); B.close();
  server.close();
});

/** An in-memory internet of NATs, in RFC 4787's terms, with a STUN server answering on two
 *  ports at 198.51.100.1, as seedrelay's `--stun` does. A `moderate` NAT keeps one public
 *  port per socket (endpoint-independent mapping); a `strict` one gives each destination a
 *  random public port of the 64,512 above 1023 (endpoint-dependent), as Linux's
 *  `masquerade random` does. Both let in only an address and port a socket has sent to.
 *  Each NAT is a platform, whose machine's own address the world cannot reach, and which
 *  counts the sockets bound and the datagrams sent. With `v6`, the machine also has an IPv6
 *  address, `ip6`, routed end to end with no NAT, behind a firewall that lets in only an
 *  address and port a socket has sent to, as a home router's IPv6 is. */
function natWorld() {
  const STUN_IP = "198.51.100.1", STUN_PORTS = [3478, 3479];
  const nats = new Map(), hosts6 = new Map();
  const deliver = (fromIp, fromPort, toIp, toPort, bytes) => setImmediate(() => {
    if (toIp === STUN_IP && STUN_PORTS.includes(toPort)) deliver(STUN_IP, toPort, fromIp, fromPort, stunAnswer(bytes, fromIp, fromPort));
    else (toIp.includes(":") ? hosts6 : nats).get(toIp)?.(fromIp, fromPort, toPort, bytes);
  });
  return {
    iceServers: STUN_PORTS.map((p) => ({ urls: `stun:${STUN_IP}:${p}` })),
    nat(kind, { v6 = false } = {}) {
      const n = nats.size + 1;
      const ip = `203.0.113.${n}`, ip6 = v6 ? `2001:db8::${n}` : null;
      const byPublic = new Map(), byKey = new Map(), byOwn = new Map();
      let nextPort = 40000;
      nats.set(ip, (fromIp, fromPort, port, bytes) => {
        const m = byPublic.get(port);
        if (m && m.allowed.has(`${fromIp}:${fromPort}`) && !m.socket.closed) m.socket.handler?.(new Uint8Array(bytes), fromIp, fromPort);
      });
      if (ip6) hosts6.set(ip6, (fromIp, fromPort, port, bytes) => {
        const socket = byOwn.get(port);
        if (socket && socket.allowed6.has(`${fromIp}|${fromPort}`) && !socket.closed) socket.handler?.(new Uint8Array(bytes), fromIp, fromPort);
      });
      const platform = {
        ip, ip6, bound: 0, sent: 0,
        addresses: () => [`10.0.0.${n}`, ...(ip6 ? [ip6] : [])],
        async bind() {
          platform.bound++;
          const own = nextPort++;
          const socket = {
            closed: false, handler: null, allowed6: new Set(),
            send(bytes, port, host) {
              if (socket.closed) return;
              platform.sent++;
              if (host.includes(":")) {
                if (!ip6) return;
                socket.allowed6.add(`${host}|${port}`);
                deliver(ip6, own, host, port, Uint8Array.from(bytes));
                return;
              }
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
          byOwn.set(own, socket);
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
    const H = udpRealm(rawOver(hard)), E = udpRealm(rawOver(easy));
    const { offer, answer, a, b } = hardOffers ? await negotiate(H, E, world.iceServers) : await negotiate(E, H, world.iceServers);
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
    H.close(); E.close();
  }
});

await test("two ends that both give each destination their own port stay apart, and spend nothing trying", async () => {
  const world = natWorld();
  const one = world.nat("strict"), two = world.nat("strict");
  const A = udpRealm(rawOver(one)), B = udpRealm(rawOver(two));
  const offer = await A.open(true, world.iceServers), answer = await B.open(false, world.iceServers);
  const carried = [0, 0];
  const timer = setInterval(() => {
    for (; carried[0] < offer.up.length; carried[0]++) answer.n.down(...offer.up[carried[0]]);
    for (; carried[1] < answer.up.length; carried[1]++) offer.n.down(...answer.up[carried[1]]);
  }, 5);
  await settle(1500);
  clearInterval(timer);
  assert(A.accepted.length === 0 && B.accepted.length === 0, "no path");
  assert(one.bound === 1 && two.bound === 1, "no birthday sockets");
  // The plain punch: a probe each 50 ms to each of a handful of candidates, and no spray.
  assert(one.sent < 300 && two.sent < 300, `no random ports probed, sent ${one.sent} and ${two.sent}`);
  A.close(); B.close();
});

await test("two ends behind strict NATs meet over IPv6, through firewalls that let only replies in", async () => {
  const world = natWorld();
  const one = world.nat("strict", { v6: true }), two = world.nat("strict", { v6: true });
  const A = udpRealm(rawOver(one)), B = udpRealm(rawOver(two));
  const { offer, answer, a, b } = await negotiate(A, B, world.iceServers);
  assert(offer.up.some(([tag, text]) => tag === RTC_TAG.CANDIDATE && text === `[${one.ip6}]:40000`) &&
    answer.up.some(([tag, text]) => tag === RTC_TAG.CANDIDATE && text === `[${two.ip6}]:40000`),
    "each end names its IPv6 address, in brackets");
  assert(one.bound === 1 && two.bound === 1, "no birthday sockets: both ends are hard over IPv4");
  const atA = reader(a), atB = reader(b);
  const there = randomBytes(50_000), back = randomBytes(5000);
  a.send(there);
  b.send(back);
  await until(() => atB.length === there.length && atA.length === back.length, 5000, "the bytes");
  assert(atB.bytes().equals(there) && atA.bytes().equals(back), "intact");
  A.close(); B.close();
});

await test("an IPv6 address is written as RFC 5952 writes it, and read from a candidate only in that shape", async () => {
  const bytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
  for (const [hex, text] of [
    ["00000000000000000000000000000000", "::"],
    ["00000000000000000000000000000001", "::1"],
    ["20010db8000000000000000000000001", "2001:db8::1"],
    ["20010db8000000010000000000000001", "2001:db8:0:1::1"],
    ["20010db8000000000001000000000001", "2001:db8::1:0:0:1"],
    ["20010db8000000010001000100010001", "2001:db8:0:1:1:1:1:1"],
    ["fe800000000000000000000000000000", "fe80::"],
  ]) assert(ipv6Text(bytes(hex)) === text, `${hex} is ${text}, got ${ipv6Text(bytes(hex))}`);
  // Against the WHATWG URL serializer, which writes RFC 5952's form, over addresses heavy
  // in zero groups, where the rules bite.
  for (let i = 0; i < 500; i++) {
    const b = new Uint8Array(16);
    for (let g = 0; g < 8; g++) if (Math.random() < 0.4) { b[2 * g] = Math.random() * 256; b[2 * g + 1] = Math.random() * 256; }
    const want = new URL(`http://[${Buffer.from(b).toString("hex").match(/..../g).join(":")}]/`).hostname.slice(1, -1);
    assert(ipv6Text(b) === want, `${want}, got ${ipv6Text(b)}`);
  }
  // The path probes a well-formed IPv6 candidate, and a malformed one ends its negotiation.
  const sentTo = new Set();
  const A = udpRealm(rawOver(recording(sentTo)));
  const good = await A.open(false);
  good.n.down(RTC_TAG.OFFER, "00".repeat(8));
  good.n.down(RTC_TAG.CANDIDATE, "[2001:db8::7]:9");
  for (const bad of ["[2001:db8::7]", "2001:db8::7:9", "[2001:DB8::7]:9", "[fe80::1%eth0]:9", "[1:2:3:4:5:6:7:8:9]:9",
    "[::ffff:1.2.3.4]:9", "[1::2::3]:9", "[12345::]:9", "[::1]:0", "[::1]:65536"]) {
    const refused = await A.open(false);
    refused.n.down(RTC_TAG.OFFER, "00".repeat(8));
    refused.n.down(RTC_TAG.CANDIDATE, bad);
    assert(refused.closed, `${bad} is refused`);
  }
  await settle(80);
  assert(sentTo.has("2001:db8::7 9") && [...sentTo].every((s) => s === "2001:db8::7 9"),
    `probes go to the IPv6 candidate alone, went to ${[...sentTo]}`);
  assert(!good.closed, "the well-formed one stays open");
  A.close();
});

await test("a Node socket is dual-stack: it hears IPv4 and IPv6, and names each sender by its own bytes", async () => {
  const raw = nodeRawDatagrams();
  const heard = [];
  const a = await raw.bind(() => {}, 1 << 16);
  const b = await raw.bind((batch) => {
    const x = new Uint8Array(batch);
    for (let at = 0; at < x.length;) {
      const n = x[at], ip = x.subarray(at + 1, at + 1 + n), port = (x[at + 1 + n] << 8) | x[at + 2 + n];
      const len = (x[at + 3 + n] << 8) | x[at + 4 + n];
      heard.push(`${n === 4 ? ip.join(".") : ipv6Text(ip)} ${port === a.port} ${x[at + 5 + n]}`);
      at += 5 + n + len;
    }
  }, 1 << 16);
  raw.send(sendOf(a.id, "127.0.0.1", b.port, Uint8Array.of(4)));
  raw.send(sendOf(a.id, "::1", b.port, Uint8Array.of(6)));
  await until(() => heard.length === 2, 2000, "both datagrams");
  raw.closeAll();
  assert(heard.sort().join(",") === "127.0.0.1 true 4,::1 true 6", `heard ${heard}`);
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
  const A = keep(await makeTransportHost({ channels: relay.factory(), datagrams: nodeRawDatagrams() }));
  const B = keep(await makeTransportHost({ channels: relay.factory(), datagrams: nodeRawDatagrams() }));
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

await test("over a path that loses, repeats and reorders, the transport's records cross intact", async (keep) => {
  const relay = new FakeRelay("relay:8080");
  const net = fabric({ loss: 0.03, dup: 0.02, late: 0.02 });
  const A = keep(await makeTransportHost({ channels: relay.factory(), datagrams: rawOver(net.machine("10.0.0.1", false)) }));
  const B = keep(await makeTransportHost({ channels: relay.factory(), datagrams: rawOver(net.machine("10.0.0.2", true)) }));
  await relayLink(A, B, "ws://relay:8080");
  await until(async () => (await routes(A)).get(B.peerId) === true && (await routes(B)).get(A.peerId) === true,
    5000, "both to move to the path");
  for (const n of [1024 * 1024, 64 * 1024, 1]) {
    const big = await B.request(A.peerId, PROTO, generatorRequest(n, 11));
    assert(big.length === n && big.every((x, i) => x === ((i * 11) & 255)), `an answer of ${n} bytes, intact`);
  }
});

await test("a peer with no UDP path declines it, and the offering side offers WebRTC next", async (keep) => {
  const relay = new FakeRelay();
  const [small, large] = sortedIdentities(2);
  const seen = [];
  const A = keep(await makeTransportHost({ identity: small, channels: combineChannels(relay.factory(), spyChannels(seen)), datagrams: nodeRawDatagrams() }));
  const B = keep(await makeTransportHost({ identity: large, channels: relay.factory() }));
  await relayLink(A, B);
  await until(() => seen.some((d) => d.startsWith("rtc:offer")), 3000, "a WebRTC offer after the decline");
  assert(!seen.some((d) => d.startsWith("udp:")), "the UDP offer never reached the host's sockets");
  assert((await linkedPeers(A)).includes(B.peerId) && (await routes(A)).get(B.peerId) === false,
    "with neither, the relayed link stays");
});

summary("UDP");
