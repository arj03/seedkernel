// op-frame — the optional client-side named-op envelope, as an importable module.
// Clients and the operator CLI compose it; dispatch, timers, and the guest seam never
// interpret it, because the kernel ABI ends after `[caller 32]`.
//
// This module is runtime — it is vendored into browser shells. The same three functions
// exist as flat guest source in host/bundle-author.ts `guestOpFraming`, which a build
// tool inlines into signed guest source and which stays offline for that reason.
// Change one and change the other — `tests/run.mjs` fails the pair if they disagree.

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
