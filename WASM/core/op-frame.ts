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
 *  attribution only, and two kinds of caller are told apart by those 32 bytes and
 *  nothing else:
 *
 *  - the HOST proper, `[0x00 × 32]` — a loopback the host wrote, whose body is an op
 *    envelope this app composed for itself. A fired deadline re-enters this way too,
 *    naming a `timer` op (`[id u32]`) exactly as any other host event does, so a guest
 *    declaring `timer/*` tells one from an ordinary loopback by the op name it reads,
 *    never by a second caller id;
 *  - an APP or a peer, anything else — its app key, or the authenticated sender's.
 *
 *  The host id is matched over the WHOLE 32 bytes. An app key is a hash of facts its
 *  author picks, so a prefix test is a name an app can grind its way into. */
export function callerOf(arg: Uint8Array): { fromHost: boolean; caller: Uint8Array; body: Uint8Array } {
  const caller = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) {
    if (caller[i] !== 0) fromHost = false;
  }
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
 *  implement then fails by name rather than landing on a neighbouring case.
 *
 *  ASCII, 1..255 bytes, checked rather than truncated: the length is ONE byte and the
 *  reader counts bytes where `String.prototype.length` counts UTF-16 units, so a name
 *  that is too long or not ASCII would go out as a silently different frame — and an
 *  operator's `--op` is exactly where such a name comes from. */
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

/** The above three as a flat guest-source block: `"use strict"`-safe, no imports, no
 *  side effects beyond the declarations — ready to prepend to a bundle's guest source
 *  by its build tooling. The kernel never injects it; the app owns what it means. */
export function guestOpFraming(): string {
  return `
// op-frame: the app's own loopback framing (seedkernel core/op-frame.ts) - inlined by
// bundle tooling, content not ABI: after the kernel's 32-byte caller id it is the
// callee's format. The kernel never reads any of it.
//
// Two kinds of caller, over the WHOLE 32 bytes (a prefix test is a name an app can grind
// its way into): the HOST proper [00 x 32] - whose body is an op envelope, a fired
// deadline included, naming "timer" like any other host event - and anything else, an
// app key or an authenticated peer.
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
