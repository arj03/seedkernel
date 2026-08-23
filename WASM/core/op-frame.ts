// op-frame — the ONE definition of the app-facing loopback envelope: `[caller 32]`
// split by `callerOf`, and `[opLen u8][op][args]` read/written by `readOp`/`writeOp`,
// with the flat guest-source block `guestOpFraming()` bundle tooling can inline.
//
// CONTENT, never ABI: the kernel's own guest preamble does not include this, the host
// does not interpret it, and nothing here moves `GUEST_ABI_VERSION`. A callee defines
// what the bytes after the kernel's 32-byte caller id mean (§12.2), and choosing the
// op-led envelope below is simply the common spelling — an app that prefers its own
// framing is free not to use it. The functions here are mirrors of the inlined block,
// for host-side callers of the same app's guest; the definition lives in this one file.

/** Split a `handle` argument: `[caller 32][body …]`. The kernel's inbound shape is
 *  attribution only — 32 zero bytes are the host's own id, anything else is the
 *  authenticated sender's key. */
export function callerOf(arg: Uint8Array): { fromHost: boolean; caller: Uint8Array; body: Uint8Array } {
  const caller = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) { if (caller[i] !== 0) { fromHost = false; break; } }
  return { fromHost, caller, body: arg.subarray(32) };
}

/** `[opLen u8][op ascii][args …]` read back. Malformed framing throws rather than
 *  yielding a truncated name that would then read as an unimplemented op. */
export function readOp(body: Uint8Array): { op: string; args: Uint8Array } {
  const n = body.length > 0 ? body[0] : -1;
  if (n < 0 || body.length < 1 + n) throw new Error("op-frame: malformed op envelope");
  let op = "";
  for (let i = 0; i < n; i++) op += String.fromCharCode(body[1 + i]);
  return { op, args: body.subarray(1 + n) };
}

/** The same, written. The op is a NAME, never a tag byte: an op a guest does not
 *  implement then fails by name rather than landing on a neighbouring case. */
export function writeOp(op: string, args: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + op.length + args.length);
  out[0] = op.length;
  for (let i = 0; i < op.length; i++) out[1 + i] = op.charCodeAt(i) & 0xff;
  out.set(args, 1 + op.length);
  return out;
}

/** The above three as a flat guest-source block: `"use strict"`-safe, no imports, no
 *  side effects beyond the declarations — ready to prepend to a bundle's guest source
 *  by its build tooling. The kernel never injects it; the app owns what it means. */
export function guestOpFraming(): string {
  return `
// op-frame: the app's own loopback framing (seedkernel core/op-frame.ts) - inlined by
// bundle tooling, content not ABI: after the kernel's 32-byte caller id it is the
// callee's format. The kernel never reads any of it.
const callerOf = (arg) => {
  const caller = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) { if (caller[i] !== 0) { fromHost = false; break; } }
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
  const out = new Uint8Array(1 + op.length + args.length);
  out[0] = op.length;
  for (let i = 0; i < op.length; i++) out[1 + i] = op.charCodeAt(i) & 255;
  out.set(args, 1 + op.length);
  return out;
};
`;
}
