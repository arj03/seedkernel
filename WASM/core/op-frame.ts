// op-frame — the one definition of the app-facing loopback envelope: `[caller 32]` split
// by `callerOf`, `[opLen u8][op][args]` by `readOp`/`writeOp`, with `guestOpFraming()`
// emitting the same three as a flat block bundle tooling can inline. CONTENT, never ABI
// (§12.2): the kernel's own guest preamble does not include it, and the host never
// interprets it.

/** Split a `handle` argument: `[caller 32][body …]`. The host id is all-zero, matched
 *  over the WHOLE 32 bytes — an app key is a hash of facts its author picks, so a prefix
 *  test is a name an app can grind its way into (§12.2). */
export function callerOf(arg: Uint8Array): { fromHost: boolean; caller: Uint8Array; body: Uint8Array } {
  const caller = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) {
    if (caller[i] !== 0) fromHost = false;
  }
  return { fromHost, caller, body: arg.subarray(32) };
}

/** `[opLen u8][op ascii][args …]` read back. Malformed framing throws rather than
 *  yielding a truncated name that would read as an unimplemented op. */
export function readOp(body: Uint8Array): { op: string; args: Uint8Array } {
  const n = body.length > 0 ? body[0] : -1;
  if (n < 0 || body.length < 1 + n) throw new Error("op-frame: malformed op envelope");
  let op = "";
  for (let i = 0; i < n; i++) op += String.fromCharCode(body[1 + i]);
  return { op, args: body.subarray(1 + n) };
}

/** The same, written. The op is a NAME, never a tag byte, ASCII 1..255 — checked
 *  rather than truncated, because the one-byte length and UTF-16 counting would
 *  otherwise go out silently different. */
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

/** The above three as a flat guest-source block: `"use strict"`-safe, no imports — ready
 *  to prepend to a bundle's guest source by its build tooling. */
export function guestOpFraming(): string {
  return `
// op-frame: the app's own loopback framing (seedkernel core/op-frame.ts) - inlined by
// bundle tooling, content not ABI: after the kernel's 32-byte caller id it is the
// callee's format. The kernel never reads any of it.
const callerOf = (arg) => {
  const caller = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) {
    if (caller[i] !== 0) fromHost = false;
  }
  return { fromHost, caller, body: arg.subarray(32) };
};
const readOp = (body) => {
  const n = body.length > 0 ? body[0] : -1;
  if (n < 0 || body.length < 1 + n) throw new Error("op-frame: malformed op envelope");
  let op = "";
  for (let i = 0; i < n; i++) op += String.fromCharCode(body[1 + i]);
  return { op, args: body.subarray(1 + n) };
};
const writeOp = (op, args) => {
  if (op.length < 1 || op.length > 255) throw new Error("op-frame: op name must be 1..255 bytes");
  const out = new Uint8Array(1 + op.length + args.length);
  out[0] = op.length;
  for (let i = 0; i < op.length; i++) {
    const c = op.charCodeAt(i);
    if (c > 127) throw new Error("op-frame: op name must be ASCII");
    out[1 + i] = c;
  }
  out.set(args, 1 + op.length);
  return out;
};
`;
}
