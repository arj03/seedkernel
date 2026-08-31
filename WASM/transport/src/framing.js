// Guest-owned framing. Codec derives from stream shape plus destination/listener metadata
// (§12.1).

/** Pre-auth frame cap. 8 KiB leaves room for the suite's ML-KEM-768 encapsulation
 *  key (1184 B); unlike the platform ceiling, this is transport-bundle content. */
const MAX_HANDSHAKE_FRAME_BYTES = 8 * 1024;

// ── inbound byte assembly ─────────────────────────────────────────────────────
//
// A link message arrives in arbitrarily small slices. Merge slices below MERGE_BELOW
// into a doubling buffer, so a dribbled frame costs linear copies, not quadratic.
const MERGE_BELOW = 8 * 1024;

class ByteParts {
  constructor() {
    this.parts = [];   // inbound slices, not yet parsed
    this.head = 0;     // index of the first live slice
    this.length = 0;   // live bytes across all slices
    this.tail = -1;    // index of the growable accumulator in `parts`, or -1 for none
  }
  push(chunk) {
    if (chunk.length === 0) return;
    this.length += chunk.length;
    // A slice big enough to carry its own overhead is kept as it arrived and ends the
    // accumulator: no copy on the path that matters.
    if (chunk.length >= MERGE_BELOW) { this.parts.push(chunk); this.tail = -1; return; }
    if (this.tail < 0) {
      const buf = new Uint8Array(MERGE_BELOW);
      buf.set(chunk, 0);
      this.tail = this.parts.length;
      this.parts.push(buf.subarray(0, chunk.length));
      return;
    }
    const cur = this.parts[this.tail];
    if (chunk.length <= cur.buffer.byteLength - cur.byteOffset - cur.length) {
      const grown = new Uint8Array(cur.buffer, cur.byteOffset, cur.length + chunk.length);
      grown.set(chunk, cur.length);
      this.parts[this.tail] = grown;
      return;
    }
    const want = cur.length + chunk.length;
    const buf = new Uint8Array(want * 2); // doubling is what makes the copying amortized
    buf.set(cur, 0);
    buf.set(chunk, cur.length);
    this.parts[this.tail] = buf.subarray(0, want);
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
  /** Consume exactly `n` bytes from the front, as one buffer. */
  take(n) {
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const p = this.parts[this.head];
      const need = n - off;
      if (p.length <= need) { out.set(p, off); off += p.length; this.parts[this.head] = null; this.head++; }
      else { out.set(p.subarray(0, need), off); this.parts[this.head] = p.subarray(need); off = n; }
    }
    this.length -= n;
    // The accumulator stops accumulating once its start is consumed from: the capacity
    // behind it is no longer ours to append into.
    if (this.tail >= 0 && this.tail <= this.head) this.tail = -1;
    // Drop the consumed slices once they outnumber the live ones.
    if (this.head >= 8 && this.head * 2 >= this.parts.length) {
      this.parts = this.parts.slice(this.head);
      if (this.tail >= 0) this.tail -= this.head;
      this.head = 0;
    }
    return out;
  }
  /** Byte offset of the first `\r\n\r\n`, or -1 when not present yet. */
  findHeadEnd() {
    let b0 = -1, b1 = -1, b2 = -1, b3 = -1, off = 0;
    for (let i = this.head; i < this.parts.length; i++) {
      const p = this.parts[i];
      for (let j = 0; j < p.length; j++) {
        b0 = b1; b1 = b2; b2 = b3; b3 = p[j];
        if (b0 === 13 && b1 === 10 && b2 === 13 && b3 === 10) return off - 3;
        off++;
      }
    }
    return -1;
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

  /** Feed inbound bytes, delivering each whole message. Returns false when the peer
   *  declared an over-cap frame — a protocol violation the caller answers by tearing
   *  the link down, never by growing the buffer. */
  push(chunk, deliver) {
    this.parts.push(chunk);
    for (;;) {
      if (this.parts.length < 4) return true;
      const len = readU32BE(this.parts.peek(4), 0);
      if (len > this.cap) return false;
      if (this.parts.length < 4 + len) return true;
      deliver(this.parts.take(4 + len).subarray(4));
    }
  }
}

// ── RFC 6455, for the browser edge ────────────────────────────────────────────
//
// WebSocket exists here only because browsers cannot open raw TCP: an HTTP upgrade,
// then length-delimited frames, masked client→server and not server→client. Both ends
// run this one class. Every byte transform — encode, single-frame decode, the SHA-1 +
// base64 accept value — runs in `ws.wasm`, a module of this bundle.
const WS_OP_ENCODE = 1, WS_OP_DECODE_ONE = 2, WS_OP_ACCEPT = 3, WS_OP_BASE64 = 4;
const WS_OP_CONT = 0x0, WS_OP_BINARY = 0x2, WS_OP_CLOSE = 0x8, WS_OP_PING = 0x9, WS_OP_PONG = 0xa;
/** RFC 6455 status 1000 (normal closure), big-endian, as a close-frame payload. */
const WS_CLOSE_NORMAL = new Uint8Array([0x03, 0xe8]);
/** An HTTP upgrade head is tiny; anything larger is not one. */
const MAX_WS_HANDSHAKE = 16 * 1024;

/** Run this bundle's own ws.wasm — an ordinary `host.call`. An empty answer is the
 *  module's failure signal (§4). Every seam call answers a Promise; `host.call` is
 *  already one, so nothing to normalize here. */
function wsCall(req) {
  return host.call(N_WS, req).then((out) => {
    if (!out || out.length === 0) throw new Error("ws: module error");
    return out;
  });
}

class WsFramer {
  /** `authority` is the `host:port` this link was dialed at, for the client's Host
   *  header — empty on the accepting side, which never sends one. */
  constructor(put, weDialed, authority) {
    this.put = put;
    this.client = weDialed;
    this.cap = MAX_HANDSHAKE_FRAME_BYTES;
    this.parts = new ByteParts();      // inbound: handshake head, then frames
    this.open = false;
    this.opened = new Promise((resolve) => { this.resolveOpen = resolve; });
    this.fragOpcode = -1;
    this.frags = [];
    this.fragBytes = 0;
    // Outbound order: every wire write is a link in this chain, so an async module
    // call can never let a later frame overtake an earlier one — the record layer
    // above relies on the byte order.
    this.writes = Promise.resolve();
    // Inbound order, for the same reason: the record layer counts nonces, so a message
    // delivered out of order is a decrypt failure and a dead link.
    this.reads = Promise.resolve();
    if (this.client) {
      // The upgrade head needs two module calls, so it is computed on a later turn,
      // ahead of anything queued behind it. `prepared` is what upgrade() awaits; it
      // rejects there if the module could not produce a key — a client that never wrote
      // its GET must abort rather than wait out the idle clock. The bare catch only keeps
      // a link torn down before anyone awaits it from reporting an unhandled rejection.
      this.prepared = (async () => {
        const r = await wsCall(concatBytes([Uint8Array.of(WS_OP_BASE64), await randomBytes(16)]));
        this.key = utf8Decode(r);
        this.expectAccept = utf8Decode(await wsCall(concatBytes([Uint8Array.of(WS_OP_ACCEPT), r])));
        this.put(utf8Encode(
          "GET / HTTP/1.1\r\nHost: " + authority + "\r\n" +
          "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
          "Sec-WebSocket-Key: " + this.key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"));
      })();
      this.prepared.catch(() => {});
    } else {
      this.prepared = Promise.resolve();
    }
  }

  raiseCap() { this.cap = maxFrameBytes; }

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

  /** Append one write to the wire chain: frame the message, then put it — in order,
   *  when its module call answers. */
  enqueue(opcode, payload) {
    return this.writes = this.writes.then(() => this.frame(opcode, payload)).then((f) => this.put(f));
  }

  async send(msg) {
    await this.opened;
    await this.enqueue(WS_OP_BINARY, msg);
  }

  /** The close frame rides the same byte stream after the end-of-stream record just
   *  written, so it cannot overtake it — the ordering that record depends on. */
  goodbye() {
    return this.enqueue(WS_OP_CLOSE, WS_CLOSE_NORMAL);
  }

  /** One chunk in, in arrival order. The parse itself is `read` below; this is the chain
   *  that keeps two parses from running at once, which matters twice: `frames()` takes a
   *  frame before awaiting its decode, so a second parser would read the frame after it;
   *  and `raiseCap()` lands only when msg4 is delivered, so a second parser would measure
   *  a frame riding the same segment against the pre-auth cap. */
  push(chunk, deliver) {
    const done = this.reads.then(() => this.read(chunk, deliver));
    this.reads = done.catch(() => {});
    return done;
  }

  async read(chunk, deliver) {
    this.parts.push(chunk);
    if (!this.open) {
      let consumed;
      try { consumed = await this.upgrade(); } catch { return false; }
      if (consumed < 0) return this.parts.length <= MAX_WS_HANDSHAKE;
      this.parts.take(consumed);
      this.open = true;
      this.resolveOpen();
    }
    try { return await this.frames(deliver); } catch { return false; }
  }

  /** Read (client) or answer (server) the opening handshake. Returns the bytes
   *  consumed, or -1 when the head is not complete yet. Throws on a refusal. */
  async upgrade() {
    await this.prepared;
    const sep = this.parts.findHeadEnd();
    if (sep < 0) return -1;
    const head = utf8Decode(this.parts.peek(sep));
    if (this.client) {
      // Sec-WebSocket-Accept is base64 and case-significant — compare it byte for byte
      // rather than lowercasing both sides.
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

  /** Parse whatever frames are complete. Delivery is per frame rather than per chunk:
   *  delivering msg4 raises the cap, and an application frame riding the same TCP
   *  segment must be measured against the raised cap, not the pre-auth one. */
  async frames(deliver) {
    for (;;) {
      const total = this.frameLength();
      if (total < 0) return true;
      if (total > this.cap) return false;
      if (this.parts.length < total) return true;
      const whole = this.parts.take(total);
      const req = new Uint8Array(2 + whole.length);
      req[0] = WS_OP_DECODE_ONE;
      req[1] = this.client ? 0 : 1; // a server expects masked frames, a client unmasked
      req.set(whole, 2);
      const r = await wsCall(req);
      // The module saw exactly one whole frame; anything but "frame" (1) is a protocol
      // violation — bad mask direction, a fragmented control frame, a bad length.
      if (r[0] !== 1) return false;
      const fin = (r[1] & 0x80) !== 0;
      const opcode = r[1] & 0x0f;
      const payload = r.slice(10, 10 + readU32BE(r, 6));
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
    if (opcode === WS_OP_BINARY) deliver(payload);
    else if (opcode === WS_OP_PING) await this.enqueue(WS_OP_PONG, payload);
    else if (opcode === WS_OP_CLOSE) return false;
    return true;
  }

  /** Total byte length of the next frame, from the (unvalidated) header — or -1 when
   *  too few bytes are buffered to know yet. All real validation is the module's; this
   *  only sizes the wait. */
  frameLength() {
    if (this.parts.length < 2) return -1;
    const b = this.parts.peek(10);
    const masked = (b[1] & 0x80) !== 0;
    const len7 = b[1] & 0x7f;
    let headerLen = 2, payloadLen = len7;
    if (len7 === 126) {
      if (this.parts.length < 4) return -1;
      headerLen = 4;
      payloadLen = (b[2] << 8) | b[3];
    } else if (len7 === 127) {
      if (this.parts.length < 10) return -1;
      if (readU32BE(b, 2) !== 0) return 0x7fffffff; // > 4 GiB: over any cap
      headerLen = 10;
      payloadLen = readU32BE(b, 6);
    }
    return headerLen + (masked ? 4 : 0) + payloadLen;
  }
}

/** Case-insensitively pull a header value out of an HTTP head. */
function headerValue(head, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp("^" + escaped + ":[ \\t]*(.+?)[ \\t]*$", "im").exec(head);
  return m ? m[1] : null;
}

/** Must match `LISTENER.WS` in core/socket-seam.ts. */
const LISTENER_WS = "ws";

function makeFramer(stream, linkId, dest, listener) {
  const put = (bytes) => netLinkSend(linkId, bytes);
  if (!stream) return null;
  if (dest) {
    // The socket factory already accepted the destination; framing needs only its codec
    // and, for WebSocket, the HTTP Host value.
    const ws = /^wss?:\/\/([^/]+)/i.exec(dest);
    if (ws) return new WsFramer(put, true, ws[1]);
    return new LengthFramer(put);
  }
  // Unlabelled platform dials, such as RTC, use length framing.
  if (listener === LISTENER_WS) return new WsFramer(put, false, "");
  return new LengthFramer(put);
}
