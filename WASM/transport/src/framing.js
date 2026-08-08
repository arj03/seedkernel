// ============================================================================
// transport/src/framing.js — the wire framing for links the platform did not
// frame. A browser WebSocket and an RTCDataChannel arrive with message
// boundaries already on them; a TCP socket does not. Where the platform
// supplies none, imposing them is OURS — framing is content by the end-to-end
// argument (it is a state machine over whole messages, and an endpoint can do
// it), so a host that framed on our behalf would be holding a piece of the
// protocol that a replacement bundle could not replace. The host hands over
// bytes; what a message *is* is decided here.
//
//   [len u32 BE][bytes]   one link message per record.
//
// The cap is two-stage and both numbers come from the host at init. Pre-auth it
// is the small handshake bound: a stranger who knows only host:port must not be
// able to reserve megabytes by declaring a frame and then dribbling the body.
// It rises to the full frame cap at exactly the moment the peer becomes a
// known, admitted identity.
// ============================================================================

// ── inbound byte assembly ─────────────────────────────────────────────────────
//
// A link message may arrive in arbitrary slices, and the slices can be arbitrarily
// small. The old arrangement joined every new slice onto one buffer, which made a
// peer that dribbles a full-size frame one byte at a time cost a quadratic number of
// copies — a CPU-exhaustion budget no frame-size cap controls. The parser instead
// keeps the slices it was handed and copies only when a whole message is complete:
// once per frame, bounded by the cap that already governs the frame.
class ByteParts {
  constructor() {
    this.parts = [];   // inbound slices, not yet parsed
    this.head = 0;     // index of the first live slice
    this.length = 0;   // live bytes across all slices
  }
  push(chunk) {
    if (chunk.length > 0) { this.parts.push(chunk); this.length += chunk.length; }
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
      if (p.length <= need) { out.set(p, off); off += p.length; this.head++; }
      else { out.set(p.subarray(0, need), off); this.parts[this.head] = p.subarray(need); off = n; }
    }
    this.length -= n;
    // Drop the consumed slices once they outnumber the live ones — a long dribble
    // must not grow the array without bound.
    if (this.head >= 8 && this.head * 2 >= this.parts.length) {
      this.parts = this.parts.slice(this.head);
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
    this.cap = maxHandshakeFrameBytes;
  }

  send(msg) {
    const out = new Uint8Array(4 + msg.length);
    writeU32BE(out, 0, msg.length);
    out.set(msg, 4);
    this.put(out);
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
// WebSocket exists here only because browsers cannot open raw TCP, so it is a wire
// codec over a raw socket and nothing more: an HTTP upgrade, then length-delimited
// frames with a masking rule that depends on which end you are. Both ends run this
// one class; they differ in who speaks first and in whether frames are masked
// (client→server must be, server→client must not).
//
// Every byte transform runs in `ws.wasm`, a module of THIS bundle reached by logical
// name — the encode, the single-frame decode, the SHA-1 + base64 of the accept value.
// Holding it as a module rather than as host code is what makes the framing content:
// it arrives through the one install path, signed by the same author as this program,
// and a fix to either half is one bundle rollout.
const WS_OP_ENCODE = 1, WS_OP_DECODE_ONE = 2, WS_OP_ACCEPT = 3, WS_OP_BASE64 = 4;
const WS_OP_CONT = 0x0, WS_OP_BINARY = 0x2, WS_OP_CLOSE = 0x8, WS_OP_PING = 0x9, WS_OP_PONG = 0xa;
/** RFC 6455 status 1000 (normal closure), big-endian, as a close-frame payload. */
const WS_CLOSE_NORMAL = new Uint8Array([0x03, 0xe8]);
/** An HTTP upgrade head is tiny; anything larger is not one. */
const MAX_WS_HANDSHAKE = 16 * 1024;

/** Run this bundle's own ws.wasm — an ordinary `host.call`, like every other name this
 *  program uses. An empty answer is the module's failure signal (§4). */
function wsCall(req) {
  const out = host.call(N_WS, req);
  if (out.length === 0) throw new Error("ws: module error");
  return out;
}

class WsFramer {
  /** `authority` is the `host:port` this link was dialed at, for the client's Host
   *  header — empty on the accepting side, which never sends one. */
  constructor(put, weDialed, authority) {
    this.put = put;
    this.client = weDialed;
    this.cap = maxHandshakeFrameBytes;
    this.parts = new ByteParts();      // inbound: handshake head, then frames
    this.queue = [];                   // outbound, until the upgrade completes
    this.open = false;
    this.fragOpcode = -1;
    this.frags = [];
    this.fragBytes = 0;
    if (this.client) {
      const r = wsCall(concatBytes([Uint8Array.of(WS_OP_BASE64), randomBytes(16)]));
      this.key = utf8Decode(r);
      this.expectAccept = utf8Decode(wsCall(concatBytes([Uint8Array.of(WS_OP_ACCEPT), r])));
      this.put(utf8Encode(
        "GET / HTTP/1.1\r\nHost: " + authority + "\r\n" +
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
        "Sec-WebSocket-Key: " + this.key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"));
    }
  }

  raiseCap() { this.cap = maxFrameBytes; }

  mask() { return this.client ? randomBytes(4) : null; }

  frame(opcode, payload) {
    const m = this.mask();
    const req = new Uint8Array(3 + (m ? 4 : 0) + payload.length);
    req[0] = WS_OP_ENCODE;
    req[1] = opcode & 0x0f;
    req[2] = m ? 1 : 0;
    if (m) req.set(m, 3);
    req.set(payload, 3 + (m ? 4 : 0));
    return wsCall(req);
  }

  send(msg) {
    // The transport emits its HELLO the moment the link exists — before the upgrade
    // has finished — so frames queue until the channel opens.
    if (!this.open) { this.queue.push(msg); return; }
    this.put(this.frame(WS_OP_BINARY, msg));
  }

  /** The close frame rides the same byte stream as the end-of-stream record just
   *  written, so it cannot overtake it — which is the ordering that record depends on. */
  goodbye() {
    if (this.open) { try { this.put(this.frame(WS_OP_CLOSE, WS_CLOSE_NORMAL)); } catch { /* gone */ } }
  }

  push(chunk, deliver) {
    this.parts.push(chunk);
    if (!this.open) {
      let consumed;
      try { consumed = this.upgrade(); } catch { return false; }
      if (consumed < 0) return this.parts.length <= MAX_WS_HANDSHAKE;
      this.parts.take(consumed);
      this.open = true;
      for (const m of this.queue) this.put(this.frame(WS_OP_BINARY, m));
      this.queue = [];
    }
    try { return this.frames(deliver); } catch { return false; }
  }

  /** Read (client) or answer (server) the opening handshake. Returns the bytes
   *  consumed, or -1 when the head is not complete yet. Throws on a refusal. */
  upgrade() {
    const sep = this.parts.findHeadEnd();
    if (sep < 0) return -1;
    const head = utf8Decode(this.parts.peek(sep));
    if (this.client) {
      // Sec-WebSocket-Accept is base64 and case-significant, so compare the exact
      // header value byte for byte rather than lowercasing both sides.
      if (!/HTTP\/1\.1 101/.test(head) || headerValue(head, "sec-websocket-accept") !== this.expectAccept) {
        throw new Error("ws: upgrade refused");
      }
      return sep + 4;
    }
    const key = headerValue(head, "sec-websocket-key");
    if (!key) throw new Error("ws: missing Sec-WebSocket-Key");
    const accept = utf8Decode(wsCall(concatBytes([Uint8Array.of(WS_OP_ACCEPT), utf8Encode(key)])));
    this.put(utf8Encode(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
      "Sec-WebSocket-Accept: " + accept + "\r\n\r\n"));
    return sep + 4;
  }

  /** Parse whatever frames are complete. Delivery is per frame rather than per chunk:
   *  delivering msg4 raises the cap, and an application frame riding the same TCP
   *  segment must be measured against the raised cap, not the pre-auth one. */
  frames(deliver) {
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
      const r = wsCall(req);
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
          if (!this.dispatch(first, msg, deliver)) return false;
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
        if (!this.dispatch(opcode, payload, deliver)) return false;
      }
    }
  }

  dispatch(opcode, payload, deliver) {
    if (opcode === WS_OP_BINARY) deliver(payload);
    else if (opcode === WS_OP_PING) this.put(this.frame(WS_OP_PONG, payload));
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

/** How a link is framed, as the host declares it at open. The host knows only because
 *  it dialed the address; what to DO about it is entirely here. */
const FRAMING_PLATFORM = 0, FRAMING_LENGTH = 1, FRAMING_WS_CLIENT = 2, FRAMING_WS_SERVER = 3;

function makeFramer(framing, linkId, weDialed, authority) {
  const put = (bytes) => netLinkSend(linkId, bytes);
  if (framing === FRAMING_LENGTH) return new LengthFramer(put);
  if (framing === FRAMING_WS_CLIENT) return new WsFramer(put, true, authority || "");
  if (framing === FRAMING_WS_SERVER) return new WsFramer(put, false, "");
  return null; // FRAMING_PLATFORM: the transport under us already has boundaries
}
