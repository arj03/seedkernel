// Link framing. The codec follows the stream shape and the destination or listener (§12.1).

/** Pre-auth frame cap, with room for the ML-KEM-768 encapsulation key (1184 B). */
const MAX_HANDSHAKE_FRAME_BYTES = 8 * 1024;

// ── inbound byte assembly ─────────────────────────────────────────────────────
//
// Slices arrive arbitrarily small. The first small one is borrowed; a second starts a
// doubling accumulator, so a dribbled frame costs linear copies.
const MERGE_BELOW = 8 * 1024;

class ByteParts {
  constructor() {
    this.parts = [];   // inbound slices, not yet parsed
    this.head = 0;     // index of the first live slice
    this.length = 0;   // live bytes across all slices
    this.tail = -1;    // index of the growable accumulator in `parts`, or -1 for none
    this.tailOwned = false; // borrowed slices may have spare capacity we must not write
  }
  push(chunk) {
    if (chunk.length === 0) return;
    this.length += chunk.length;
    // A large slice is kept as it arrived and ends the accumulator.
    if (chunk.length >= MERGE_BELOW) { this.parts.push(chunk); this.tail = -1; return; }
    if (this.tail < 0) {
      this.tail = this.parts.length;
      this.tailOwned = false;
      this.parts.push(chunk);
      return;
    }
    const cur = this.parts[this.tail];
    if (this.tailOwned && chunk.length <= cur.buffer.byteLength - cur.byteOffset - cur.length) {
      const grown = new Uint8Array(cur.buffer, cur.byteOffset, cur.length + chunk.length);
      grown.set(chunk, cur.length);
      this.parts[this.tail] = grown;
      return;
    }
    const want = cur.length + chunk.length;
    const buf = new Uint8Array(Math.max(MERGE_BELOW, want * 2));
    buf.set(cur, 0);
    buf.set(chunk, cur.length);
    this.parts[this.tail] = buf.subarray(0, want);
    this.tailOwned = true;
  }
  /** Copy up to `n` bytes from the front without consuming them. */
  peek(n) {
    const out = new Uint8Array(Math.min(n, this.length));
    let off = 0;
    for (let i = this.head; i < this.parts.length && off < out.length; i++) {
      const p = this.parts[i];
      const take = Math.min(p.length, out.length - off);
      out.set(p.subarray(0, take), off);
      off += take;
    }
    return out;
  }
  /** The i-th live byte, without copying; callers check `length` first. */
  byteAt(i) {
    for (let k = this.head; k < this.parts.length; k++) {
      const p = this.parts[k];
      if (i < p.length) return p[i];
      i -= p.length;
    }
    return 0;
  }
  /** Consume exactly `n` bytes from the front, as one buffer with `prefix` free bytes in
   *  front for the caller to fill. */
  take(n, prefix = 0) {
    const out = new Uint8Array(prefix + n);
    const end = prefix + n;
    let off = prefix;
    while (off < end) {
      const p = this.parts[this.head];
      const need = end - off;
      if (p.length <= need) { out.set(p, off); off += p.length; this.parts[this.head] = null; this.head++; }
      else { out.set(p.subarray(0, need), off); this.parts[this.head] = p.subarray(need); off = end; }
    }
    this.length -= n;
    // Once consumed from, the accumulator's capacity is no longer ours to append into.
    if (this.tail >= 0 && this.tail <= this.head) this.tail = -1;
    // Drop the consumed slices once they outnumber the live ones.
    if (this.head >= 8 && this.head * 2 >= this.parts.length) {
      this.parts = this.parts.slice(this.head);
      if (this.tail >= 0) this.tail -= this.head;
      this.head = 0;
    }
    return out;
  }
}

/** A length-prefixed link is writable from birth — there is no negotiation. */
class LengthFramer {
  constructor(put) {
    this.put = put;
    this.parts = new ByteParts();
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
  discard() { this.parts = new ByteParts(); }

  /** Feed inbound bytes, delivering each whole message. False for an over-cap frame, true
   *  when waiting for more; before the cap is raised, a promise of either (`parse`). */
  push(chunk, deliver) {
    this.parts.push(chunk);
    return this.parse(deliver);
  }

  /** Until the cap is raised, one message at a time: its step may raise the cap (ake.js
   *  `becomeAuthed`) before the next frame in the same read is measured. */
  parse(deliver) {
    for (;;) {
      if (this.parts.length < 4) return true;
      const p = this.parts;
      const len = ((p.byteAt(0) << 24) | (p.byteAt(1) << 16) | (p.byteAt(2) << 8) | p.byteAt(3)) >>> 0;
      if (len > this.cap) return false;
      if (this.parts.length < 4 + len) return true;
      const step = deliver(this.parts.take(4 + len).subarray(4));
      if (this.cap !== maxFrameBytes) return Promise.resolve(step).then(() => this.parse(deliver));
    }
  }
}

// ── RFC 6455, for the browser edge ────────────────────────────────────────────
//
// For browsers, which cannot open raw TCP. Both ends run this one class; every byte
// transform (encode, decode, the accept value) runs in this bundle's `ws.wasm`.
const WS_OP_ENCODE = 1, WS_OP_DECODE_ONE = 2, WS_OP_ACCEPT = 3, WS_OP_BASE64 = 4;
const WS_OP_CONT = 0x0, WS_OP_BINARY = 0x2, WS_OP_CLOSE = 0x8, WS_OP_PING = 0x9, WS_OP_PONG = 0xa;
/** RFC 6455 status 1000 (normal closure), big-endian, as a close-frame payload. */
const WS_CLOSE_NORMAL = new Uint8Array([0x03, 0xe8]);
/** An HTTP upgrade head is tiny; anything larger is not one. */
const MAX_WS_HANDSHAKE = 16 * 1024;

/** Call this bundle's ws.wasm (§12.2). */
function wsCall(req) {
  return host.call(N_WS, req);
}

class WsFramer {
  /** `authority` and `path` are the dialed target, for the client's request. */
  constructor(put, weDialed, authority, path = "/") {
    this.put = put;
    this.client = weDialed;
    this.cap = MAX_HANDSHAKE_FRAME_BYTES;
    this.parts = new ByteParts();      // inbound: handshake head, then frames
    this.open = false;
    // `send` parks here until the upgrade completes, or fails with it (`abort`, §12.6).
    this.opened = new Promise((resolve, reject) => {
      this.resolveOpen = resolve;
      this.rejectOpen = reject;
    });
    this.opened.catch(() => {}); // no unhandled rejection when nothing was parked
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
  discard() { this.parts = new ByteParts(); this.frags = []; this.fragBytes = 0; }

  async mask() { return this.client ? await randomBytes(4) : null; }

  async frame(opcode, payload) {
    const m = await this.mask();
    const req = new Uint8Array(3 + (m ? 4 : 0) + payload.length);
    req[0] = WS_OP_ENCODE;
    req[1] = opcode & 0x0f;
    req[2] = m ? 1 : 0;
    if (m) req.set(m, 3);
    req.set(payload, 3 + (m ? 4 : 0));
    return wsCall(req);
  }

  /** Frame one message and put it, in order, on the write chain. */
  enqueue(opcode, payload) {
    return this.writes = this.writes.then(() => this.frame(opcode, payload)).then((f) => this.put(f));
  }

  async send(msg) {
    await this.opened;
    await this.enqueue(WS_OP_BINARY, msg);
  }

  /** A close frame, after the end-of-stream record on the same chain. None before the
   *  upgrade, where it would be garbage. */
  goodbye() {
    return this.open ? this.enqueue(WS_OP_CLOSE, WS_CLOSE_NORMAL) : Promise.resolve();
  }

  /** Terminal: no upgrade will complete, so fail whatever parked on it. */
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
    let h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, n = this.headLen;
    for (let i = 0; i < chunk.length; i++) {
      h0 = h1; h1 = h2; h2 = h3; h3 = chunk[i];
      n++;
      const matched = h0 === 13 && h1 === 10 && h2 === 13 && h3 === 10;
      if (matched || n > MAX_WS_HANDSHAKE) {
        this.h0 = h0; this.h1 = h1; this.h2 = h2; this.h3 = h3; this.headLen = n;
        return matched && n <= MAX_WS_HANDSHAKE ? n - 4 : -2;
      }
    }
    this.h0 = h0; this.h1 = h1; this.h2 = h2; this.h3 = h3; this.headLen = n;
    return -1;
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

  /** Parse whatever frames are complete. Until the cap is raised, each message's step runs
   *  before the next frame is measured (`dispatch`). */
  async frames(deliver) {
    for (;;) {
      const total = this.frameLength();
      if (total < 0) return true;
      if (total === Infinity) return false;
      if (this.parts.length < total) return true;
      // Taken with room for the two-byte request header in front.
      const req = this.parts.take(total, 2);
      req[0] = WS_OP_DECODE_ONE;
      req[1] = this.client ? 0 : 1; // a server expects masked frames, a client unmasked
      const r = await wsCall(req);
      // Anything but 1 is a protocol violation.
      if (r[0] !== 1) return false;
      const fin = (r[1] & 0x80) !== 0;
      const opcode = r[1] & 0x0f;
      // A view: each call answers a fresh buffer.
      const payload = r.subarray(10, 10 + readU32BE(r, 6));
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
        // The first fragment of a data message (the module refuses fragmented control).
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
      // This step may raise the cap (LengthFramer `parse`).
      if (this.cap !== maxFrameBytes) await step;
    } else if (opcode === WS_OP_PING) await this.enqueue(WS_OP_PONG, payload);
    else if (opcode === WS_OP_CLOSE) return false;
    return true;
  }

  /** The next frame's total length from its unvalidated header: -1 if not yet known,
   *  Infinity once its payload is over the cap. Validation is the module's. */
  frameLength() {
    const p = this.parts;
    if (p.length < 2) return -1;
    const b1 = p.byteAt(1);
    const masked = (b1 & 0x80) !== 0;
    const len7 = b1 & 0x7f;
    let headerLen = 2, payloadLen = len7;
    if (len7 === 126) {
      if (p.length < 4) return -1;
      headerLen = 4;
      payloadLen = (p.byteAt(2) << 8) | p.byteAt(3);
    } else if (len7 === 127) {
      if (p.length < 10) return -1;
      // Any bit in the high half is over any cap.
      if ((p.byteAt(2) | p.byteAt(3) | p.byteAt(4) | p.byteAt(5)) !== 0) return Infinity;
      headerLen = 10;
      payloadLen = ((p.byteAt(6) << 24) | (p.byteAt(7) << 16)
        | (p.byteAt(8) << 8) | p.byteAt(9)) >>> 0;
    }
    if (payloadLen > this.cap) return Infinity;
    return headerLen + (masked ? 4 : 0) + payloadLen;
  }
}

/** Case-insensitively pull a header value out of an HTTP head. A blank value does not
 *  match; the lookahead stops the lazy group returning a leading space as the value. */
function headerValue(head, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp("^" + escaped + ":[ \\t]*(?![ \\t])(.+?)[ \\t]*$", "im").exec(head);
  return m ? m[1] : null;
}

/** The listener label read as WebSocket (`--listen ws=host:port`); others are length framing. */
const LISTENER_WS = "ws";

function makeFramer(stream, linkId, dest, listener) {
  const put = (bytes) => netLinkSend(linkId, bytes);
  if (!stream) return null;
  if (dest) {
    const ws = /^wss?:\/\/([^/]+)(\/\S*)?$/i.exec(dest);
    if (ws) return new WsFramer(put, true, ws[1], ws[2] ?? "/");
    return new LengthFramer(put);
  }
  if (listener === LISTENER_WS) return new WsFramer(put, false, "");
  return new LengthFramer(put);
}
