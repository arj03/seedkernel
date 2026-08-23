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

function utf8Encode(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}

function utf8Decode(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const c = b[i];
    if (c < 0x80) s += String.fromCharCode(c);
    else if ((c & 0xe0) === 0xc0) { s += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63)); i++; }
    else { s += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63)); i += 2; }
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
// (`[len u32 BE][bytes]`, an empty blob being length 0). There is no tag byte: the op's
// name leads the payload (`readOp`, after the 32-byte caller id) and is the whole
// discriminator. The host twin is transport-host.ts's `Args`; a field written and not
// read desyncs the whole payload.
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

// ── the caller prefix and the op envelope ──────────────────────────────────────
//
// The kernel's inbound shape is `handle([caller 32][body …])`: attribution only. What
// this program does with the bytes after the caller is ITS format, so the helpers HERE
// are this bundle's own spellings (the host twin, transport-host.ts, is content paired
// with this bundle like the wire codec) — not a kernel ABI. The op is a NAME, never a
// tag byte: collapsing many events onto one call must not smuggle in a number two sides
// have to agree on, so an unimplemented op fails loud.

/** The three kinds of caller, told apart by those 32 bytes and nothing else:
 *  the HOST proper (`[0x00 × 32]`, platform events and loopbacks), a fired TIMER
 *  (`[0x01][0x00 × 31]`, the host's own re-entry for a deadline this program armed),
 *  and an APP (its app key, derived host-side from the admitted manifest, exactly as an
 *  inbound frame carries the authenticated sender's key). */
function callerOf(arg) {
  const caller = arg.subarray(0, 32);
  let fromHost = true;
  let fromTimer = false;
  for (let i = 0; i < 32; i++) {
    if (caller[i] !== 0) { fromHost = false; if (i === 0 && caller[i] === 1) fromTimer = true; break; }
  }
  return { fromHost, fromTimer, caller, body: arg.subarray(32) };
}

/** `[opLen u8][op ascii][args …]` — this bundle's one envelope. Malformed framing
 *  throws rather than yielding a truncated name that would then read as an
 *  unimplemented op. */
function readOp(body) {
  const n = body.length > 0 ? body[0] : -1;
  if (n < 0 || body.length < 1 + n) throw new Error("transport: malformed op envelope");
  let op = "";
  for (let i = 0; i < n; i++) op += String.fromCharCode(body[1 + i]);
  return { op, args: body.subarray(1 + n) };
}

/** The same, written — an app's or the host's payload, handed over as-is. */
function writeOp(op, args) {
  const out = new Uint8Array(1 + op.length + args.length);
  out[0] = op.length;
  for (let i = 0; i < op.length; i++) out[1 + i] = op.charCodeAt(i) & 0xff;
  out.set(args, 1 + op.length);
  return out;
}
