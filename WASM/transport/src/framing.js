// Link framing. The codec depends on whether the link is a stream and on the destination
// or listener (§12.1).

/** Pre-auth frame cap, with room for the ML-KEM-768 encapsulation key (1184 B). */
const MAX_HANDSHAKE_FRAME_BYTES = 8 * 1024;

// ── byte assembly ─────────────────────────────────────────────────────────────

/** Below this, a framer's pieces gather into one accumulator. */
const MERGE_BELOW = 8 * 1024;

/** A length-prefixed link is writable immediately; there is no negotiation. */
class LengthFramer {
  constructor(put) {
    this.put = put;
    this.parts = new Pieces(MERGE_BELOW);
    this.cap = MAX_HANDSHAKE_FRAME_BYTES;
  }

  send(msg) {
    const out = new Uint8Array(4 + msg.length);
    writeU32BE(out, 0, msg.length);
    out.set(msg, 4);
    return this.put(out);
  }

  raiseCap() { this.cap = maxFrameBytes; }

  /** Drop what is buffered: the link refused its peer and reads nothing more (ake.js `stall`). */
  discard() { this.parts = new Pieces(MERGE_BELOW); }

  /** Feed inbound bytes, delivering each whole message. Returns false for an over-cap
   *  frame, true when waiting for more; before the cap is raised, a promise of either
   *  (`parse`). */
  push(chunk, deliver) {
    this.parts.push(chunk);
    return this.parse(deliver);
  }

  /** Until the cap is raised, one message at a time, since handling it may raise the cap
   *  (ake.js `becomeAuthed`) before the next frame in the same read is measured. */
  parse(deliver) {
    for (;;) {
      if (this.parts.bytes < 4) return true;
      const p = this.parts;
      const len = ((p.byteAt(0) << 24) | (p.byteAt(1) << 16) | (p.byteAt(2) << 8) | p.byteAt(3)) >>> 0;
      if (len > this.cap) return false;
      if (this.parts.bytes < 4 + len) return true;
      this.parts.take(4);
      const step = deliver(this.parts.takeCopy(len));
      if (this.cap !== maxFrameBytes) return Promise.resolve(step).then(() => this.parse(deliver));
    }
  }
}

// ── RFC 6455, for the browser edge ────────────────────────────────────────────
//
// For browsers, which cannot open raw TCP. Both ends run this one class. Headers are read
// and written here; the per-byte work (masking, the accept value) runs in this bundle's
// `ws.wasm`, so a frame that is not masked, every one a server sends, never reaches it.
const WS_OP_MASK = 1, WS_OP_ACCEPT = 2, WS_OP_BASE64 = 3;
const WS_OP_CONT = 0x0, WS_OP_BINARY = 0x2, WS_OP_CLOSE = 0x8, WS_OP_PING = 0x9, WS_OP_PONG = 0xa;
/** RFC 6455 status 1000 (normal closure), big-endian, as a close-frame payload. */
const WS_CLOSE_NORMAL = new Uint8Array([0x03, 0xe8]);
/** An HTTP upgrade head is tiny; anything larger is not one. */
const MAX_WS_HANDSHAKE = 16 * 1024;

/** Call this bundle's ws.wasm (§12.2). */
function wsCall(req) {
  return host.call(N_WS, req);
}

// A client masks every frame under a fresh four-byte key (RFC 6455 §5.3). The keys come
// out of one block of host entropy at a time: a host round trip per frame for four bytes
// costs more than framing it. A key the block has is handed over at once; only a refill
// waits.
const MASK_POOL_BYTES = 1024;
let maskPool = EMPTY;
let maskAt = 0;
function maskKey() {
  if (maskAt + 4 <= maskPool.length) {
    maskAt += 4;
    return maskPool.subarray(maskAt - 4, maskAt);
  }
  return randomBytes(MASK_POOL_BYTES).then((pool) => {
    maskPool = pool;
    maskAt = 4;
    return pool.subarray(0, 4);
  });
}

/** One frame with FIN set (RFC 6455 §5.2), in the shortest length form. With a `key` it is
 *  a masking request for ws.wasm, `[WS_OP_MASK][frame]` with the payload still clear. */
function wsFrame(opcode, payload, key) {
  const n = payload.length, ext = n < 126 ? 0 : n < 65536 ? 2 : 8;
  const at = key ? 1 : 0, head = 2 + ext + (key ? 4 : 0);
  const out = new Uint8Array(at + head + n);
  out[at] = 0x80 | opcode;
  out[at + 1] = (key ? 0x80 : 0) | (ext === 0 ? n : ext === 2 ? 126 : 127);
  if (ext === 2) writeU16BE(out, at + 2, n);
  else if (ext === 8) writeU32BE(out, at + 6, n);
  out.set(payload, at + head);
  if (!key) return out;
  out[0] = WS_OP_MASK;
  out.set(key, at + head - 4);
  return out;
}

/** The next frame's header, read off the front of `p` without consuming it: `{ fin,
 *  opcode, head, len }`, with `head` counting the key, once its bytes are there, null
 *  before, false for a frame RFC 6455 refuses or a payload over `cap`. A server reads
 *  masked frames and a client unmasked ones; a control frame is whole and at most 125
 *  bytes, a close's never 1; a length takes its shortest form. */
function wsHead(p, masked, cap) {
  if (p.bytes < 2) return null;
  const b0 = p.byteAt(0), b1 = p.byteAt(1);
  const fin = (b0 & 0x80) !== 0, opcode = b0 & 0x0f;
  let len = b1 & 0x7f, head = 2;
  if ((b0 & 0x70) !== 0 || ((b1 & 0x80) !== 0) !== masked) return false;
  if (opcode > WS_OP_BINARY && (opcode < WS_OP_CLOSE || opcode > WS_OP_PONG)) return false;
  if (opcode >= WS_OP_CLOSE && (!fin || len > 125 || (opcode === WS_OP_CLOSE && len === 1))) return false;
  if (len === 126) {
    if (p.bytes < 4) return null;
    len = (p.byteAt(2) << 8) | p.byteAt(3);
    if (len < 126) return false;
    head = 4;
  } else if (len === 127) {
    if (p.bytes < 10) return null;
    // Any bit in the high half is over any cap.
    if ((p.byteAt(2) | p.byteAt(3) | p.byteAt(4) | p.byteAt(5)) !== 0) return false;
    len = ((p.byteAt(6) << 24) | (p.byteAt(7) << 16) | (p.byteAt(8) << 8) | p.byteAt(9)) >>> 0;
    if (len < 65536) return false;
    head = 10;
  }
  if (len > cap) return false;
  return { fin, opcode, head: head + (masked ? 4 : 0), len };
}

class WsFramer {
  /** `authority` and `path` are the dialed target, for the client's request. */
  constructor(put, weDialed, authority, path = "/") {
    this.put = put;
    this.client = weDialed;
    this.cap = MAX_HANDSHAKE_FRAME_BYTES;
    this.parts = new Pieces(MERGE_BELOW);      // inbound: handshake head, then frames
    this.open = false;
    // `send` waits on this until the upgrade completes, or fails with it (`abort`, §12.6).
    this.opened = new Promise((resolve, reject) => {
      this.resolveOpen = resolve;
      this.rejectOpen = reject;
    });
    this.opened.catch(() => {}); // no unhandled rejection when nothing was waiting
    // Rolling scan state for the HTTP head terminator (`scanHead`).
    this.headLen = 0;
    this.h0 = -1; this.h1 = -1; this.h2 = -1; this.h3 = -1;
    this.fragOpcode = -1;
    this.frags = [];
    this.fragBytes = 0;
    // Writes and reads each run on a chain, so async module calls never reorder bytes:
    // the record layer counts nonces.
    this.writes = Promise.resolve();
    this.reads = Promise.resolve();
    if (this.client) {
      // The client's GET, built with two module calls; `upgrade` awaits it.
      this.prepared = (async () => {
        const r = await wsCall(concatBytes([Uint8Array.of(WS_OP_BASE64), await randomBytes(16)]));
        this.key = utf8Decode(r);
        this.expectAccept = utf8Decode(await wsCall(concatBytes([Uint8Array.of(WS_OP_ACCEPT), r])));
        this.put(utf8Encode(
          "GET " + path + " HTTP/1.1\r\nHost: " + authority + "\r\n" +
          "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
          "Sec-WebSocket-Key: " + this.key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"));
      })();
      this.prepared.catch(() => {});
    } else {
      this.prepared = Promise.resolve();
    }
  }

  raiseCap() { this.cap = maxFrameBytes; }

  /** Drop what is buffered: the link refused its peer and reads nothing more (ake.js `stall`). */
  discard() { this.parts = new Pieces(MERGE_BELOW); this.frags = []; this.fragBytes = 0; }

  /** One frame, or a promise of it when ws.wasm masks it: every frame a client sends. */
  frame(opcode, payload) {
    if (!this.client) return wsFrame(opcode, payload, null);
    const key = maskKey();
    return key instanceof Uint8Array
      ? wsCall(wsFrame(opcode, payload, key))
      : key.then((k) => wsCall(wsFrame(opcode, payload, k)));
  }

  /** Frame one message and put it, in order, on the write chain. */
  enqueue(opcode, payload) {
    return this.writes = this.writes.then(() => this.frame(opcode, payload)).then((f) => this.put(f));
  }

  send(msg) {
    if (this.open) return this.enqueue(WS_OP_BINARY, msg);
    return this.opened.then(() => this.enqueue(WS_OP_BINARY, msg));
  }

  /** A close frame, after the end-of-stream record on the same chain. None before the
   *  upgrade, where it would be garbage. */
  goodbye() {
    return this.open ? this.enqueue(WS_OP_CLOSE, WS_CLOSE_NORMAL) : Promise.resolve();
  }

  /** Terminal: no upgrade will complete, so fail whatever is waiting on it. */
  abort() {
    this.rejectOpen(new Error("ws: link closed before the upgrade completed"));
  }

  /** One chunk in, parsed on the read chain so two parses never overlap. */
  push(chunk, deliver) {
    const done = this.reads.then(() => this.read(chunk, deliver));
    this.reads = done.catch(() => {});
    return done;
  }

  async read(chunk, deliver) {
    if (!this.open) {
      const sep = this.scanHead(chunk);
      if (sep === -2) return false; // no terminator within the head's own ceiling
      this.parts.push(chunk);
      if (sep < 0) return true;
      let consumed;
      try { consumed = await this.upgrade(sep); } catch { return false; }
      this.parts.take(consumed);
      this.open = true;
      this.resolveOpen();
    } else {
      this.parts.push(chunk);
    }
    try { return await this.frames(deliver); } catch { return false; }
  }

  /** Extend the rolling `\r\n\r\n` scan over one pre-open chunk. Returns the terminator's
   *  offset in the stream, -1 if not found yet, or -2 past MAX_WS_HANDSHAKE. */
  scanHead(chunk) {
    let h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, n = this.headLen, found = -1;
    for (let i = 0; i < chunk.length; i++) {
      h0 = h1; h1 = h2; h2 = h3; h3 = chunk[i];
      n++;
      const matched = h0 === 13 && h1 === 10 && h2 === 13 && h3 === 10;
      if (matched || n > MAX_WS_HANDSHAKE) {
        found = matched && n <= MAX_WS_HANDSHAKE ? n - 4 : -2;
        break;
      }
    }
    this.h0 = h0; this.h1 = h1; this.h2 = h2; this.h3 = h3; this.headLen = n;
    return found;
  }

  /** Read (client) or answer (server) the opening handshake, `sep` bytes into the buffered
   *  head (from `scanHead`). Returns the bytes consumed. Throws on a refusal. */
  async upgrade(sep) {
    await this.prepared;
    const head = utf8Decode(this.parts.peek(sep));
    if (this.client) {
      // Sec-WebSocket-Accept is case-significant base64.
      if (!/HTTP\/1\.1 101/.test(head) || headerValue(head, "sec-websocket-accept") !== this.expectAccept) {
        throw new Error("ws: upgrade refused");
      }
      return sep + 4;
    }
    const key = headerValue(head, "sec-websocket-key");
    if (!key) throw new Error("ws: missing Sec-WebSocket-Key");
    const accept = utf8Decode(await wsCall(concatBytes([Uint8Array.of(WS_OP_ACCEPT), utf8Encode(key)])));
    this.put(utf8Encode(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
      "Sec-WebSocket-Accept: " + accept + "\r\n\r\n"));
    return sep + 4;
  }

  /** Parse whatever frames are complete. Until the cap is raised, each message is handled
   *  before the next frame is measured (`dispatch`). */
  async frames(deliver) {
    for (;;) {
      // A server expects masked frames, a client unmasked.
      const h = wsHead(this.parts, !this.client, this.cap);
      if (h === null) return true;
      if (h === false) return false;
      if (this.parts.bytes < h.head + h.len) return true;
      const { fin, opcode } = h;
      let payload;
      if (this.client) {
        this.parts.take(h.head);
        payload = this.parts.takeCopy(h.len);
      } else {
        // Taken with room for the request's op byte in front. A view of the answer is
        // safe: each call returns a fresh buffer.
        const req = this.parts.takeCopy(h.head + h.len, 1);
        req[0] = WS_OP_MASK;
        payload = (await wsCall(req)).subarray(h.head);
      }
      if (opcode === WS_OP_CONT) {
        if (this.fragOpcode < 0) return false;
        this.fragBytes += payload.length;
        if (this.fragBytes > this.cap) return false;
        this.frags.push(payload);
        if (fin) {
          const msg = concatBytes(this.frags);
          const first = this.fragOpcode;
          this.fragOpcode = -1; this.frags = []; this.fragBytes = 0;
          if (!(await this.dispatch(first, msg, deliver))) return false;
        }
      } else if (!fin) {
        // The first fragment of a data message (`wsHead` refuses fragmented control).
        if (this.fragOpcode >= 0) return false;
        this.fragOpcode = opcode;
        this.frags = [payload];
        this.fragBytes = payload.length;
      } else {
        // A data frame may not preempt an in-flight fragmented message; control frames
        // interleave freely (RFC 6455 §5.4).
        if (opcode < 0x8 && this.fragOpcode >= 0) return false;
        if (!(await this.dispatch(opcode, payload, deliver))) return false;
      }
    }
  }

  async dispatch(opcode, payload, deliver) {
    if (opcode === WS_OP_BINARY) {
      const step = deliver(payload);
      // Handling it may raise the cap (see LengthFramer `parse`).
      if (this.cap !== maxFrameBytes) await step;
    } else if (opcode === WS_OP_PING) await this.enqueue(WS_OP_PONG, payload);
    else if (opcode === WS_OP_CLOSE) return false;
    return true;
  }
}

/** Case-insensitively read a header value from an HTTP head. `name` is a literal header
 *  name, used in the pattern as is. A blank value does not match; the lookahead keeps the
 *  lazy group from returning leading whitespace. */
function headerValue(head, name) {
  const m = new RegExp("^" + name + ":[ \\t]*(?![ \\t])(.+?)[ \\t]*$", "im").exec(head);
  return m ? m[1] : null;
}

/** The listener label that means WebSocket (`--listen ws=host:port`); others use length
 *  framing. */
const LISTENER_WS = "ws";

/** The codec for a link that writes through `put` (ake.js `hostChannel`). */
function makeFramer(stream, put, dest, listener) {
  if (!stream) return null;
  if (dest) {
    const ws = /^wss?:\/\/([^/]+)(\/\S*)?$/i.exec(dest);
    if (ws) return new WsFramer(put, true, ws[1], ws[2] ?? "/");
    return new LengthFramer(put);
  }
  if (listener === LISTENER_WS) return new WsFramer(put, false, "");
  return new LengthFramer(put);
}
