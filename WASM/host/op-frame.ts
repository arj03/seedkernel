// Named-op envelope shared by clients and guest code. The kernel ABI ends at `[caller 32]`;
// driver event names live in core/domains.ts (§12.2).
// The three functions below are serialized by bundle-author.ts's `guestOpFraming` for
// import-free guests, and the transport assembler injects that source before signing — so
// they must reference nothing outside themselves, not even this file's imports. The type
// system does not say so: run.mjs's `testGeneratedOpFrame` EXECUTES the emitted source, and
// that is what catches a free variable — a new code path here needs a case there.
import { writeU32BE, enc } from "../core/util.js";

/** Split a `handle` argument: `[caller 32][body …]`. The host id is all-zero, matched
 *  over the whole 32 bytes — an app key is grindable, so a prefix test is unsafe. */
export function callerOf(arg: Uint8Array): { fromHost: boolean; caller: Uint8Array; body: Uint8Array } {
  const caller = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) {
    if (caller[i] !== 0) fromHost = false;
  }
  return { fromHost, caller, body: arg.subarray(32) };
}

/** Read the optional `[opLen u8][op ascii][args …]` client convention. */
export function readOp(body: Uint8Array): { op: string; args: Uint8Array } {
  const n = body.length > 0 ? body[0] : -1;
  if (n < 0 || body.length < 1 + n) throw new Error("op-frame: malformed op envelope");
  let op = "";
  for (let i = 0; i < n; i++) op += String.fromCharCode(body[1 + i]);
  return { op, args: body.subarray(1 + n) };
}

/** Write the optional `[opLen u8][op ascii][args …]` client convention. */
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
// The op's fields after the envelope above, in the order the op declares. Reader twin is
// `Reader` (transport/src/util.js); a field written here and not read there desyncs the
// payload rather than degrading quietly. Shared by the socket driver and by anyone
// composing an op for `Shell.call`, so the two ends cannot drift.

/** Memoized `[opLen u8][op]`: rebuilt once per socket read otherwise. Sharing is safe —
 *  nothing mutates a header. */
const OP_HEADERS = new Map<string, Uint8Array>();
function opHeader(op: string): Uint8Array {
  let h = OP_HEADERS.get(op);
  if (h === undefined) {
    h = writeOp(op, new Uint8Array(0));
    OP_HEADERS.set(op, h);
  }
  return h;
}

/** One op's payload. The op is named in the constructor so `build()` emits the whole
 *  envelope in one pass, rather than copying every payload again behind its header. */
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
  build(): Uint8Array {
    const out = new Uint8Array(this.len);
    let off = 0;
    for (const p of this.parts) { out.set(p, off); off += p.length; }
    return out;
  }
}
