// Named-op envelope for the host's raw-link event ABI, and optional application framing.
// Event names live in services/domains.ts; their byte layouts are in §12.2.
// bundle-author.ts's `guestOpFraming` serializes the three functions below into
// import-free guests, and the transport build injects that source before signing, so they
// must reference nothing outside themselves, not even this file's imports. The type system
// cannot check that; `testGeneratedOpFrame` (tests/bundle-install.test.mjs) runs the
// emitted source to catch a free variable, so a new code path here needs a case there.
import { writeU32BE, enc } from "./util.js";

/** Split a `handle` argument: `[caller 32][body ...]`. The host id is all zeros, checked
 *  over all 32 bytes, since a caller id can be ground to match any short prefix. */
export function callerOf(arg: Uint8Array): { fromHost: boolean; caller: Uint8Array; body: Uint8Array } {
  const caller = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) {
    if (caller[i] !== 0) fromHost = false;
  }
  return { fromHost, caller, body: arg.subarray(32) };
}

/** Read `[opLen u8][op ascii][args ...]`: required for link events, optional for apps. */
export function readOp(body: Uint8Array): { op: string; args: Uint8Array } {
  const n = body.length > 0 ? body[0] : -1;
  if (n < 0 || body.length < 1 + n) throw new Error("op-frame: malformed op envelope");
  let op = "";
  for (let i = 0; i < n; i++) op += String.fromCharCode(body[1 + i]);
  return { op, args: body.subarray(1 + n) };
}

/** Write `[opLen u8][op ascii][args ...]`: required for link events, optional for apps. */
export function writeOp(op: string, args: Uint8Array): Uint8Array {
  if (op.length < 1 || op.length > 255)
    throw new Error(`op-frame: op name ${JSON.stringify(op)} must be 1..255 bytes`);
  const out = new Uint8Array(1 + op.length + args.length);
  out[0] = op.length;
  for (let i = 0; i < op.length; i++) {
    const c = op.charCodeAt(i);
    if (c > 0x7f) throw new Error(`op-frame: op name ${JSON.stringify(op)} must be ASCII`);
    out[1 + i] = c;
  }
  out.set(args, 1 + op.length);
  return out;
}

// ── op arguments ──────────────────────────────────────────────────────────────
//
// The op's fields after the envelope, in the order the op defines. The reading side is
// `Reader` (transport/src/util.js); a field written here and not read there misaligns
// everything after it. Used by the socket driver and by anyone building an op for
// `Shell.call`, so both use one encoder.

/** Cached `[opLen u8][op]`, which would otherwise be rebuilt per socket read. Sharing is
 *  safe since nothing mutates a header. */
const OP_HEADERS = new Map<string, Uint8Array>();
function opHeader(op: string): Uint8Array {
  let h = OP_HEADERS.get(op);
  if (h === undefined) {
    h = writeOp(op, new Uint8Array(0));
    OP_HEADERS.set(op, h);
  }
  return h;
}

/** One op's payload. The op is named in the constructor so `build()` writes the whole
 *  envelope, attribution prefix included, in one pass instead of copying the payload
 *  again behind a header. */
export class OpArgs {
  readonly op: string;
  private readonly parts: Uint8Array[] = [];
  private len = 0;
  constructor(op: string) {
    this.op = op;
    this.raw(opHeader(op));
  }
  u8(v: number): this {
    const b = new Uint8Array(1);
    b[0] = v;
    return this.raw(b);
  }
  u32(v: number): this {
    const b = new Uint8Array(4);
    writeU32BE(b, 0, v);
    return this.raw(b);
  }
  /** `[len u32 BE][bytes]`; an empty blob is length 0. */
  blob(b: Uint8Array): this {
    const h = new Uint8Array(4);
    writeU32BE(h, 0, b.length);
    return this.raw(h).raw(b);
  }
  /** A UTF-8 string as a blob. */
  text(s: string): this { return this.blob(enc.encode(s)); }
  private raw(b: Uint8Array): this { this.parts.push(b); this.len += b.length; return this; }
  /** The whole thing as one buffer. `prefix` (the host's 32-byte caller id) is written in
   *  front of the envelope, so a socket read is copied once here instead of again when a
   *  prefix is added later. */
  build(prefix?: Uint8Array): Uint8Array {
    const head = prefix ? prefix.length : 0;
    const out = new Uint8Array(head + this.len);
    if (prefix) out.set(prefix, 0);
    let off = head;
    for (const p of this.parts) { out.set(p, off); off += p.length; }
    return out;
  }
}
