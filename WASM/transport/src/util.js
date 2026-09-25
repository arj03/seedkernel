// Byte, hex and UTF-8 helpers and the seam's argument codec; pure transforms. First in
// the concatenation, so its "use strict" leads the signed program.

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

/** Lexicographic byte-array compare (−1 / 0 / 1). */
function bytesCompare(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

/** UTF-8 as TextEncoder writes it: a surrogate pair is one four-byte sequence, a lone
 *  surrogate U+FFFD. */
function utf8Encode(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdfff) {
      const lo = s.charCodeAt(i + 1);
      if (c < 0xdc00 && lo >= 0xdc00 && lo <= 0xdfff) { c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00); i++; }
      else c = 0xfffd;
    }
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}

function utf8Decode(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const c = b[i];
    if (c < 0x80) s += String.fromCharCode(c);
    else if ((c & 0xe0) === 0xc0) { s += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63)); i += 1; }
    else if ((c & 0xf0) === 0xe0) { s += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63)); i += 2; }
    else {
      const cp = (((c & 7) << 18) | ((b[i + 1] & 63) << 12) | ((b[i + 2] & 63) << 6) | (b[i + 3] & 63)) - 0x10000;
      s += String.fromCharCode(0xd800 | (cp >> 10), 0xdc00 | (cp & 0x3ff));
      i += 3;
    }
  }
  return s;
}

// ── outbound argument encoding ────────────────────────────────────────────────

function argU32(v) {
  const b = new Uint8Array(4);
  writeU32BE(b, 0, v);
  return b;
}
/** `[u32 fields][u8 fields][raw tail]` — each op's own fixed order. */
function args(u32s, u8s, tail) {
  const parts = [];
  for (const v of u32s) parts.push(argU32(v));
  if (u8s.length) parts.push(Uint8Array.from(u8s));
  if (tail) parts.push(tail);
  return concatBytes(parts);
}

// ── inbound argument decoding ─────────────────────────────────────────────────

// Each op reads its own fixed field order: u32 BE, u8, and blobs as `[len u32 BE][bytes]`.
// The host's twin is transport-host.ts `Args`.
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

// ── the caller prefix and op envelope ───────────────────────────────────────
// Injected from services/op-frame.ts by scripts/guest-source.mjs; assembly fails without it.
/* @seedkernel-op-frame */
