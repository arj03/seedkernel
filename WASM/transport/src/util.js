// ============================================================================
// transport/src/util.js — byte helpers, hex, utf8 and the seam's argument codec
// for the rest of the transport guest program. Pure transforms only: no host
// calls, no state.
//
// Leads the concatenation (scripts/build-transport-bundle.mjs), so its
// "use strict" is the first statement of the signed program.
// ============================================================================

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
function toHex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) { s += HEX[b[i] >>> 4] + HEX[b[i] & 15]; }
  return s;
}
function fromHex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

/** Lexicographic byte-array compare (−1 / 0 / 1). */
function bytesCompare(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

/** UTF-8, not CESU-8: a surrogate PAIR is one four-byte sequence. The other end of this
 *  seam is the platform's TextEncoder/TextDecoder, so encoding the halves separately would
 *  make an astral `dest` read back as a different string on the host side. A lone surrogate
 *  becomes U+FFFD, which is what TextEncoder does with one. */
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

// Each op declares its own fixed field order — u32 BE, u8, and length-prefixed blobs
// (`[len u32 BE][bytes]`, an empty blob being length 0). No tag byte: the op NAME leads
// the payload (`readOp`) and is the whole discriminator. The host twin is
// transport-host.ts's `Args`; a field written and not read desyncs the whole payload.
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
// Injected from host/op-frame.ts by scripts/guest-source.mjs. Keeping a marker here makes
// omission fail during assembly instead of producing a signed guest with missing globals.
/* @seedkernel-op-frame */
