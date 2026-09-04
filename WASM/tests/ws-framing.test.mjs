// ws-framing.test.mjs — unit tests for the RFC 6455 STATE MACHINE in transport/src/framing.js
// (`WsFramer`): fragment reassembly, control-frame interleaving, the pre-auth frame cap,
// and the read/write serialization `push`/`enqueue` provide over an async, per-frame module
// call. fuzz_ws_test.go covers ws.wasm's stateless per-frame codec (one call in, one call
// out); nothing there exercises state carried ACROSS calls, which is everything this file
// is about.
//
// `WsFramer` is guest code with no module boundary of its own — it shares a scope with
// util.js (transport/src/util.js) and reads `host`, `N_WS`, `maxFrameBytes`, `randomBytes`
// as free variables normally supplied by ake.js and the realm. Rather than reimplement
// those, this loads the REAL util.js + framing.js source into a vm context and supplies
// just those four names, with `host.call` bridged to the real ws.wasm the transport bundle
// ships — so a change to either file's contract shows up here without being restated.
import vm from "node:vm";
import { randomBytes as nodeRandomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { testkit } from "./testkit.mjs";

const { ok, assertEqual, note, summary } = testkit({ verbose: false });

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// ── the real ws.wasm, called exactly as framing.js's `wsCall` calls it: raw request in,
// UNPARSED response out (status byte included) — framing.js reads that status itself. ────
const wasmBytes = new Uint8Array(readFileSync(join(root, "build/ws.wasm")));
const wsInst = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes), {
  env: { abort: () => { throw new Error("ws.wasm abort"); }, seed: () => Date.now(), trace: () => {} },
});
const wsScratch = wsInst.exports.scratch.value;
function wsRawCall(req) {
  new Uint8Array(wsInst.exports.memory.buffer, wsScratch, req.length).set(req);
  const len = wsInst.exports.handle(req.length);
  if (len <= 0) return new Uint8Array(0);
  return new Uint8Array(wsInst.exports.memory.buffer, wsScratch, len).slice();
}

/** Decode one whole frame with the same module, independent of any `WsFramer` under test —
 *  the oracle for what landed in a captured `put` sink. */
function decodeFrame(frame, expectMasked) {
  const req = new Uint8Array(2 + frame.length);
  req[0] = 2; req[1] = expectMasked ? 1 : 0; // WS_OP_DECODE_ONE
  req.set(frame, 2);
  const r = wsRawCall(req);
  if (r.length === 0 || r[0] !== 1) return null;
  const payloadLen = ((r[6] << 24) | (r[7] << 16) | (r[8] << 8) | r[9]) >>> 0;
  return { fin: (r[1] & 0x80) !== 0, opcode: r[1] & 0x0f, payload: r.slice(10, 10 + payloadLen) };
}

// ── stand up the real WsFramer, in the same lexical scope util.js gives it in production ──
const TEST_MAX_FRAME_BYTES = 1 << 20; // the post-`raiseCap` ceiling; distinct from the 8 KiB pre-auth one

const guestSrc =
  readFileSync(join(root, "transport/src/util.js"), "utf8") + "\n" +
  readFileSync(join(root, "transport/src/framing.js"), "utf8") + "\n" +
  `globalThis.__wsTestExports = {
    WsFramer, ByteParts,
    WS_OP_CONT, WS_OP_BINARY, WS_OP_CLOSE, WS_OP_PING, WS_OP_PONG,
    MAX_HANDSHAKE_FRAME_BYTES, MAX_WS_HANDSHAKE,
  };`;

function newSandbox() {
  const sandbox = {
    Uint8Array, TextEncoder, TextDecoder, Promise, RegExp, console,
    host: { call: (id, req) => {
      if (id !== "ws") throw new Error(`ws-framing harness: unexpected host.call id ${id}`);
      return Promise.resolve(wsRawCall(req));
    } },
    N_WS: "ws",
    maxFrameBytes: TEST_MAX_FRAME_BYTES,
    randomBytes: async (n) => nodeRandomBytes(n),
  };
  vm.createContext(sandbox);
  new vm.Script(guestSrc, { filename: "ws-framing-harness.js" }).runInContext(sandbox);
  return sandbox.__wsTestExports;
}

const WS = newSandbox();

/** A `WsFramer` plus the bytes it wrote, in write order. */
function makeFramer(client, authority = "") {
  const outbox = [];
  const framer = new WS.WsFramer((bytes) => { outbox.push(bytes); return true; }, client, authority);
  return { framer, outbox };
}

/** Mint one raw, correctly masked client frame — a byte-factory only; this instance's own
 *  handshake machinery (`prepared`) runs and writes into a throwaway sink, which `.frame()`
 *  does not depend on. */
function frameFactory() {
  return makeFramer(true).framer;
}

/** Force a fragment START (`opEncode` always sets FIN=1); flipping the bit post-encode is
 *  safe because masking only XORs the payload. */
function withFin(frame, fin) {
  const b = frame.slice();
  b[0] = (b[0] & 0x7f) | (fin ? 0x80 : 0);
  return b;
}

function concat(parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/** A fresh, already-upgraded SERVER framer — the role that reads a stranger's masked
 *  frames, which is what fuzz_ws_test.go cannot exercise (it drives the codec once, not a
 *  live connection). */
async function serverAfterUpgrade() {
  const { framer, outbox } = makeFramer(false);
  const enc = new TextEncoder();
  const head = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
  const delivered = [];
  const opened = await framer.push(enc.encode(head), (p) => delivered.push(p));
  ok(opened === true, "handshake head alone: push resolves true (more may come)");
  ok(outbox.length === 1 && /^HTTP\/1\.1 101/.test(new TextDecoder().decode(outbox[0])), "server answered the upgrade");
  delivered.length = 0;
  outbox.length = 0; // the upgrade response itself is not part of what a test below is checking
  return { framer, outbox, delivered };
}

async function run() {
  const client = frameFactory();
  const payload = (n, seed = 0) => Uint8Array.from({ length: n }, (_, i) => (i + seed) & 0xff);

  // ── structured frame sequences ────────────────────────────────────────────────────────

  {
    const { framer, delivered } = await serverAfterUpgrade();
    const a = payload(50, 1), b = payload(60, 2);
    const part1 = withFin(await client.frame(WS.WS_OP_BINARY, a), false);
    const part2 = await client.frame(WS.WS_OP_CONT, b); // CONT is always the final fragment here, fin=1 already
    const r = await framer.push(concat([part1, part2]), (p) => delivered.push(p));
    ok(r === true, "fragmented binary + continuation: link stays open");
    ok(delivered.length === 1 && bytesEq(delivered[0], concat([a, b])), "reassembled payload is fragment 1 || fragment 2");
  }

  {
    const { framer, outbox, delivered } = await serverAfterUpgrade();
    const a = payload(20, 3), b = payload(20, 4), pingBody = payload(5, 9);
    const part1 = withFin(await client.frame(WS.WS_OP_BINARY, a), false);
    const ping = await client.frame(WS.WS_OP_PING, pingBody);
    const part2 = await client.frame(WS.WS_OP_CONT, b);
    const r = await framer.push(concat([part1, ping, part2]), (p) => delivered.push(p));
    ok(r === true, "ping between fragments: link stays open");
    const pong = decodeFrame(outbox[0], false);
    ok(pong && pong.opcode === WS.WS_OP_PONG && bytesEq(pong.payload, pingBody), "the ping was answered with a matching pong, mid-fragmentation");
    ok(delivered.length === 1 && bytesEq(delivered[0], concat([a, b])), "fragmentation still reassembled correctly around the ping");
  }

  {
    const { framer, delivered } = await serverAfterUpgrade();
    const orphan = await client.frame(WS.WS_OP_CONT, payload(10));
    const r = await framer.push(orphan, (p) => delivered.push(p));
    ok(r === false, "an orphan continuation frame closes the link");
    ok(delivered.length === 0, "nothing was delivered for it");
  }

  {
    // A second data frame preempting an open fragment, both as another fragment START
    // (fin=false) and as a whole message (fin=true) — RFC 6455 §5.4 forbids either.
    for (const secondFin of [false, true]) {
      const { framer, delivered } = await serverAfterUpgrade();
      const part1 = withFin(await client.frame(WS.WS_OP_BINARY, payload(10)), false);
      const secondRaw = await client.frame(WS.WS_OP_BINARY, payload(10, 5));
      const second = withFin(secondRaw, secondFin);
      const r = await framer.push(concat([part1, second]), (p) => delivered.push(p));
      ok(r === false, `a second data frame (fin=${secondFin}) during fragmentation closes the link`);
      ok(delivered.length === 0, "the in-flight fragment was never delivered");
    }
  }

  {
    // Individually small, but their sum crosses the (pre-`raiseCap`) 8 KiB cap once
    // reassembled — the cumulative `fragBytes` check, not the per-frame one.
    const { framer, delivered } = await serverAfterUpgrade();
    const half = WS.MAX_HANDSHAKE_FRAME_BYTES / 2 + 100;
    const part1 = withFin(await client.frame(WS.WS_OP_BINARY, payload(half, 1)), false);
    const part2 = await client.frame(WS.WS_OP_CONT, payload(half, 2));
    const r = await framer.push(concat([part1, part2]), (p) => delivered.push(p));
    ok(r === false, `two ${half}-byte fragments (sum > ${WS.MAX_HANDSHAKE_FRAME_BYTES}) close the link even though neither frame alone does`);
    ok(delivered.length === 0, "the over-cap message was never delivered");
  }

  // ── exact boundaries ──────────────────────────────────────────────────────────────────

  for (const n of [125, 126, 65535, 65536]) {
    const { framer, delivered } = await serverAfterUpgrade();
    framer.raiseCap(); // the 65535/65536 cases exceed the 8 KiB pre-auth cap; this is a post-auth boundary
    const frame = await client.frame(WS.WS_OP_BINARY, payload(n, 7));
    // Dribble the frame in two pieces split exactly one byte into the length field, so the
    // header-not-yet-buffered path (`frameLength()` returning -1) is hit at the boundary
    // itself, not just well clear of it.
    const cut = Math.min(3, frame.length - 1);
    const r1 = await framer.push(frame.subarray(0, cut), (p) => delivered.push(p));
    ok(r1 === true, `${n}-byte payload: a partial header waits rather than erroring`);
    const r2 = await framer.push(frame.subarray(cut), (p) => delivered.push(p));
    ok(r2 === true && delivered.length === 1 && delivered[0].length === n, `${n}-byte payload round-trips whole, split across the length-field boundary`);
  }

  {
    // The pre-auth cap itself: total wire bytes (header + 4-byte client mask + payload)
    // exactly at the cap must pass; one byte over must close the link. Both payload sizes
    // use the 4-byte header form (>= 126), so the arithmetic is just `cap - 4 - 4`.
    const okLen = WS.MAX_HANDSHAKE_FRAME_BYTES - 4 - 4;
    const overLen = okLen + 1;
    {
      const { framer, delivered } = await serverAfterUpgrade();
      const frame = await client.frame(WS.WS_OP_BINARY, payload(okLen));
      assertEqual(frame.length, WS.MAX_HANDSHAKE_FRAME_BYTES, "sanity: this frame is exactly the cap");
      const r = await framer.push(frame, (p) => delivered.push(p));
      ok(r === true && delivered.length === 1, "a frame exactly at the pre-auth cap is accepted");
    }
    {
      const { framer, delivered } = await serverAfterUpgrade();
      const frame = await client.frame(WS.WS_OP_BINARY, payload(overLen));
      const r = await framer.push(frame, (p) => delivered.push(p));
      ok(r === false && delivered.length === 0, "one byte over the pre-auth cap closes the link");
    }
  }

  // ── the handshake head's own rolling scan (`WsFramer.scanHead`) ──────────────────────

  {
    // The terminator dribbled one byte per push exercises the exact property a resumable
    // scan exists for: each push only extends the rolling window, it never rescans bytes
    // an earlier push already saw.
    const { framer, outbox } = makeFramer(false);
    const enc = new TextEncoder();
    const head = enc.encode("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
    let allTrue = true;
    for (let i = 0; i < head.length; i++) {
      const r = await framer.push(head.subarray(i, i + 1), () => {});
      if (r !== true) allTrue = false;
    }
    ok(allTrue, "a head dribbled one byte at a time never errors before the terminator lands");
    ok(outbox.length === 1 && /^HTTP\/1\.1 101/.test(new TextDecoder().decode(outbox[0])), "and the upgrade still completed, byte by byte");
  }

  {
    // The cap is exact: a head totaling MAX_WS_HANDSHAKE bytes (terminator included) is
    // accepted, one byte more is refused. Padded with a harmless header so the upgrade can
    // actually succeed at the boundary, not just fail to be refused for the wrong reason.
    const enc = new TextEncoder();
    const headerBlock = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";
    const padPrefix = "X-Pad: ", padSuffix = "\r\n\r\n"; // padSuffix carries the one blank-line terminator
    for (const total of [WS.MAX_WS_HANDSHAKE, WS.MAX_WS_HANDSHAKE + 1]) {
      const filler = total - headerBlock.length - padPrefix.length - padSuffix.length;
      const head = enc.encode(headerBlock + padPrefix + "x".repeat(filler) + padSuffix);
      assertEqual(head.length, total, "sanity: constructed head is exactly the intended length");
      const { framer, outbox } = makeFramer(false);
      const r = await framer.push(head, () => {});
      if (total === WS.MAX_WS_HANDSHAKE) {
        ok(r === true && outbox.length === 1, `a head totaling exactly MAX_WS_HANDSHAKE (${WS.MAX_WS_HANDSHAKE}) upgrades, not refused for size alone`);
      } else {
        ok(r === false, "a head one byte over MAX_WS_HANDSHAKE closes the link");
      }
    }
  }

  {
    // A single oversized chunk with no terminator anywhere in it must be refused without
    // buffering all of it first — the exact gap the review called out in the old
    // "scan fully, then check length" shape.
    const { framer } = makeFramer(false);
    const oversized = new Uint8Array(WS.MAX_WS_HANDSHAKE + 4096).fill(0x41); // no CRLFCRLF at all
    const r = await framer.push(oversized, () => {});
    ok(r === false, "one oversized chunk with no terminator is refused in a single push");
  }

  // ── read serialization: several pushes queued before any is awaited ─────────────────

  {
    const N = 8;
    const frames = [];
    for (let i = 0; i < N; i++) frames.push(await client.frame(WS.WS_OP_BINARY, payload(30 + i, i)));

    const seqDelivered = [];
    {
      const { framer } = await serverAfterUpgrade();
      for (const f of frames) await framer.push(f, (p) => seqDelivered.push(p));
    }

    const concDelivered = [];
    {
      const { framer } = await serverAfterUpgrade();
      // Fire every push before awaiting ANY of them — the case the docstring on
      // `WsFramer.push` claims is safe because of the `this.reads` chain, and the one a
      // probe that always awaits before its next push can never exercise.
      const pending = frames.map((f) => framer.push(f, (p) => concDelivered.push(p)));
      const results = await Promise.all(pending);
      ok(results.every((r) => r === true), "every queued push still resolved true");
    }

    ok(concDelivered.length === N, `all ${N} concurrently-queued pushes delivered`);
    ok(seqDelivered.length === concDelivered.length &&
      seqDelivered.every((p, i) => bytesEq(p, concDelivered[i])),
      "delivery order under unawaited concurrent pushes matches strictly sequential pushes");
  }

  {
    // Same property, but each frame arrives as several small, unawaited chunks — stresses
    // `ByteParts` reassembly and the read chain at once, which a whole-frame-per-push test
    // cannot: a chunk boundary can now land mid-header or mid-payload of ANY frame, for
    // frames whose parse is still in flight from an earlier, un-awaited push.
    const N = 6;
    const CHUNK = 7;
    const frames = [];
    for (let i = 0; i < N; i++) frames.push(await client.frame(WS.WS_OP_BINARY, payload(90 + i * 3, i + 1)));
    const whole = concat(frames);
    const chunks = [];
    for (let off = 0; off < whole.length; off += CHUNK) chunks.push(whole.subarray(off, off + CHUNK));

    const delivered = [];
    const { framer } = await serverAfterUpgrade();
    const pending = chunks.map((c) => framer.push(c, (p) => delivered.push(p)));
    const results = await Promise.all(pending);
    ok(results.every((r) => r === true), "every dribbled, unawaited chunk push resolved true");
    ok(delivered.length === N && frames.every((f, i) => {
      const want = decodeFrame(f, true);
      return bytesEq(delivered[i], want.payload);
    }), "dribbled-and-concurrent chunks still reassembled into the right frames, in order");
  }

  // ── write serialization: several enqueues queued before any is awaited ──────────────

  {
    const N = 8;
    // Server role: its constructor has no async handshake side effect of its own (unlike
    // the client role, whose `prepared` writes a GET request straight to `put`, outside the
    // `writes` chain), so `outbox` holds exactly what `enqueue` wrote, in the order it wrote.
    const { framer, outbox } = makeFramer(false);
    const payloads = Array.from({ length: N }, (_, i) => payload(15 + i, i + 100));
    const pending = payloads.map((p) => framer.enqueue(WS.WS_OP_BINARY, p));
    await Promise.all(pending);
    ok(outbox.length === N, `all ${N} concurrently-queued enqueues wrote a frame`);
    const decoded = outbox.map((f) => decodeFrame(f, false)); // server frames are unmasked
    ok(decoded.every((d, i) => d && bytesEq(d.payload, payloads[i])),
      "write order under unawaited concurrent enqueues matches call order, not module-call completion order");
  }

  summary("ws framing: fragmentation, cap, and read/write serialization");
}

function bytesEq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

await run();
