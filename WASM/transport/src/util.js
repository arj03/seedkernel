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

// utf8Encode and utf8Decode come with the op-frame prelude (op-frame.ts `guestOpFraming`).

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
// The host's writer is `OpArgs` (services/op-frame.ts).
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
/** Whether an optional trailing field follows. */
Reader.prototype.more = function () { return this.off < this.b.length; };

// ── the caller prefix and op envelope ───────────────────────────────────────
// Injected from services/op-frame.ts by scripts/guest-source.mjs; assembly fails without it.
/* @seedkernel-op-frame */
