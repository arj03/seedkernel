// Byte, hex and UTF-8 helpers and the seam's argument codec. First in the concatenation,
// so its "use strict" starts the signed program.

"use strict";

// ── byte helpers (no TextEncoder/TextDecoder in a zero-authority realm) ───────

/** The shared empty answer. */
const EMPTY = new Uint8Array(0);

function concatBytes(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function writeU32BE(out, off, v) {
  out[off] = v >>> 24; out[off + 1] = (v >>> 16) & 0xff; out[off + 2] = (v >>> 8) & 0xff; out[off + 3] = v & 0xff;
}
function readU32BE(b, off) { return ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0; }
function writeU16BE(out, off, v) { out[off] = v >>> 8; out[off + 1] = v & 0xff; }
function readU16BE(b, off) { return (b[off] << 8) | b[off + 1]; }
/** A 48-bit field, as a safe integer. Spelled out, as the stream's every packet carries
 *  three: QuickJS pays for each call and for `2 ** 32`, which it does not fold. */
function writeU48BE(out, off, v) {
  const hi = (v / 4294967296) >>> 0;
  out[off] = hi >>> 8; out[off + 1] = hi & 0xff;
  out[off + 2] = v >>> 24; out[off + 3] = (v >>> 16) & 0xff; out[off + 4] = (v >>> 8) & 0xff; out[off + 5] = v & 0xff;
}
function readU48BE(b, off) {
  return ((b[off] << 8) | b[off + 1]) * 4294967296 + (((b[off + 2] << 24) | (b[off + 3] << 16) | (b[off + 4] << 8) | b[off + 5]) >>> 0);
}

const HEX = "0123456789abcdef";
const HEX_BYTE = Array.from({ length: 256 }, (_, i) => HEX[i >> 4] + HEX[i & 15]);
function toHex(b) {
  let s = "", i = 0;
  // Four bytes per append: QuickJS pays per append, and this runs on every record.
  for (; i + 4 <= b.length; i += 4)
    s += HEX_BYTE[b[i]] + HEX_BYTE[b[i + 1]] + HEX_BYTE[b[i + 2]] + HEX_BYTE[b[i + 3]];
  for (; i < b.length; i++) s += HEX_BYTE[b[i]];
  return s;
}
/** Nibble value plus one per ASCII code, so 0 and `undefined` both mean "not hex". */
const NIBBLE = new Uint8Array(128);
for (let i = 0; i < 16; i++) {
  NIBBLE[HEX.charCodeAt(i)] = i + 1;
  NIBBLE["0123456789ABCDEF".charCodeAt(i)] = i + 1;
}
function fromHex(s) {
  const n = s.length / 2, out = new Uint8Array(n);
  for (let i = 0, j = 0; i < n; i++, j += 2) {
    const hi = NIBBLE[s.charCodeAt(j)], lo = NIBBLE[s.charCodeAt(j + 1)];
    out[i] = hi && lo ? ((hi - 1) << 4) | (lo - 1) : 0;
  }
  return out;
}

/** Lexicographic byte-array compare (-1 / 0 / 1). */
function bytesCompare(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

// utf8Encode and utf8Decode come with the op-frame prelude (bundle-author.ts `guestOpFraming`).

// ── outbound argument encoding ────────────────────────────────────────────────

function argU32(v) {
  const b = new Uint8Array(4);
  writeU32BE(b, 0, v);
  return b;
}
/** `[u32 fields][u8 fields][raw tail]`, in each op's fixed order. */
function args(u32s, u8s, tail) {
  const parts = [];
  for (const v of u32s) parts.push(argU32(v));
  if (u8s.length) parts.push(Uint8Array.from(u8s));
  if (tail) parts.push(tail);
  return concatBytes(parts);
}

// ── inbound argument decoding ─────────────────────────────────────────────────

// Each op reads its own fixed field order: u32 BE, u8, and blobs as `[len u32 BE][bytes]`.
// The host's writer is `OpArgs` (host/op-frame.ts).
function Reader(b) {
  this.b = b;
  this.off = 0;
}
Reader.prototype.u8 = function () { return this.b[this.off++]; };
Reader.prototype.u32 = function () {
  const v = readU32BE(this.b, this.off);
  this.off += 4;
  return v;
};
Reader.prototype.blob = function () {
  const n = this.u32();
  const s = this.b.subarray(this.off, this.off + n);
  this.off += n;
  return s;
};
/** A blob that must be a 32-byte peer id; `op` names the op that refuses anything else. */
Reader.prototype.peer = function (op) {
  const b = this.blob();
  if (b.length !== PK_LEN) throw new Error("transport: " + op + " needs a 32-byte peer id");
  return b;
};
/** Whether an optional trailing field follows. */
Reader.prototype.more = function () { return this.off < this.b.length; };

// ── byte queue ────────────────────────────────────────────────────────────────

/** Bytes in pieces, taken from the front: what arrived and is not yet parsed or read, and
 *  what was written and is not yet sent. A head index and an offset into the front piece,
 *  not `shift` or `subarray`, which would go quadratic over a credit of tiny datagrams; a
 *  consumed slot is cleared, so it frees. Pieces under `mergeBelow` gather into a doubling
 *  accumulator: the first is borrowed and a second starts it, so a frame arriving in tiny
 *  slices costs linear copying. */
class Pieces {
  constructor(mergeBelow = 0) {
    this.list = [];
    this.head = 0;
    this.at = 0; // where in the front piece the next byte is
    this.bytes = 0;
    this.mergeBelow = mergeBelow;
    this.tail = -1;         // index of the growable accumulator in `list`, or -1 for none
    this.tailOwned = false; // a borrowed piece's spare capacity must not be written
  }

  get slices() { return this.list.length - this.head; }

  push(piece) {
    if (piece.length === 0) return;
    this.bytes += piece.length;
    // A large piece is kept as it arrived and ends the accumulator.
    if (piece.length >= this.mergeBelow) { this.list.push(piece); this.tail = -1; return; }
    if (this.tail < 0) {
      this.tail = this.list.length;
      this.tailOwned = false;
      this.list.push(piece);
      return;
    }
    const cur = this.list[this.tail];
    if (this.tailOwned && piece.length <= cur.buffer.byteLength - cur.byteOffset - cur.length) {
      const grown = new Uint8Array(cur.buffer, cur.byteOffset, cur.length + piece.length);
      grown.set(piece, cur.length);
      this.list[this.tail] = grown;
      return;
    }
    const want = cur.length + piece.length;
    const buf = new Uint8Array(Math.max(this.mergeBelow, want * 2));
    buf.set(cur, 0);
    buf.set(piece, cur.length);
    this.list[this.tail] = buf.subarray(0, want);
    this.tailOwned = true;
  }

  shift() {
    if (this.tail === this.head) this.tail = -1;
    this.list[this.head++] = null;
    this.at = 0;
    if (this.head >= 1024 && this.head * 2 >= this.list.length) {
      this.list = this.list.slice(this.head);
      if (this.tail >= 0) this.tail -= this.head;
      this.head = 0;
    }
  }

  /** Copy up to `n` bytes from the front without consuming them. */
  peek(n) {
    const out = new Uint8Array(Math.min(n, this.bytes));
    for (let i = this.head, from = this.at, off = 0; off < out.length; i++, from = 0) {
      const p = this.list[i];
      const k = Math.min(p.length - from, out.length - off);
      out.set(p.subarray(from, from + k), off);
      off += k;
    }
    return out;
  }

  /** The i-th live byte, without copying; callers check `bytes` first. */
  byteAt(i) {
    i += this.at;
    for (let k = this.head; k < this.list.length; k++) {
      const p = this.list[k];
      if (i < p.length) return p[i];
      i -= p.length;
    }
    return 0;
  }

  /** The next `n` bytes, of the `bytes` there are: a view of the piece they sit in, or a
   *  copy across pieces. */
  take(n) { return this.consume(n, undefined, 0); }

  /** The next `n` bytes as a buffer the caller owns, with `prefix` free bytes in front for
   *  it to fill. A framer's frames take this, since the pieces it was handed are borrowed. */
  takeCopy(n, prefix = 0) { return this.consume(n, new Uint8Array(prefix + n), prefix); }

  consume(n, out, prefix) {
    this.bytes -= n;
    for (let got = 0; got < n;) {
      const piece = this.list[this.head], k = Math.min(piece.length - this.at, n - got);
      if (k === n && out === undefined) out = piece.subarray(this.at, this.at + k);
      else (out ??= new Uint8Array(n)).set(piece.subarray(this.at, this.at + k), prefix + got);
      got += k;
      this.at += k;
      if (this.at === piece.length) this.shift();
    }
    return out;
  }
}

// ── the caller prefix and op envelope, UTF-8, and `Fifo` ────────────────────
// Injected from the host's own sources by scripts/guest-source.mjs; assembly fails without it.
/* @seedkernel-op-frame */
