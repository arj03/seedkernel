// Reusable scaffolding for dynamic WASM handlers (README §3.2).
//
// Every handler that wants to receive signed envelopes, look up the signer,
// and forward an event to another schema ends up writing the same five things:
//   - a scratch + private memory layout
//   - a configure() entry point that lets the host plant the route name — the
//     one name the WASM cannot know, because only the deployer picks it
//   - a kernel.call to `signature.signer` to get the message's signer
//   - a kernel.call to a route name that delivers the event onward
//   - careful staging in private memory so kernel.call's scratch overwrite
//     doesn't clobber the input or the in-progress outbound buffer
//
// This module factors all of that out. App handlers import the primitives,
// re-export `configure`, allocate their own `scratch` + `priv` (so the host
// reads `scratch` as the handler's own Global export), and write only
// their `handle()` entry point.
//
// "Route" is the helper's name for the downstream schema this handler hands
// events to. Whether the receiver is a host-side JS bridge, another dynamic
// WASM handler, or a bridge that performs I/O is the deployer's choice and
// the helper does not need to care — kernel.call is uniform across all of
// them.
//
// Memory layout note: the helper reserves the first `PRIV_USER_OFF` bytes
// of private memory for its own bookkeeping (the route name). Apps may use
// everything from `PRIV_USER_OFF` onward.

@external("kernel", "call")
declare function kernelCall(
  schemaPtr: i32, schemaLen: i32,
  payloadPtr: i32, payloadLen: i32
): i32;

export const PK_LEN: i32 = 32;             // Ed25519
export const MAX_SCHEMA_BYTES: i32 = 64;   // SHA-3-256 = 32, leaves headroom

const ROUTE_OFF: i32 = 0;
export const PRIV_USER_OFF: i32 = MAX_SCHEMA_BYTES; // 64

// The §6.5 signer-query handler's name, baked in: the literal-ASCII bootstrap
// name `"seedkernel.bootstrap.v1:" + "signature.signer"` (§5.1). Bootstrap names
// are plain ASCII rather than genesis-hash-derived, so the helper builds the
// byte-identical name itself — exactly as the signature module builds its suite
// slot names (§6.4) — and reaches the query with a plain kernel.call. Nothing for
// the host to plant, so loadTopSignerPubkey works with no configuration at all.
const SIGNER_NAME: Uint8Array = ascii("seedkernel.bootstrap.v1:signature.signer");

function ascii(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) as u8;
  return out;
}

let scratchPtr: i32 = 0;
let privPtr: i32 = 0;
let routeLen: i32 = 0;

/** Register the app's scratch + private memory regions with the helper.
 *  Call this once from the app's top-level init, AFTER allocating both
 *  buffers. The helper does not allocate its own buffers — the app owns
 *  them so the host's `scratch` global export points at the app's memory. */
export function init(scratch: i32, priv: i32): void {
  scratchPtr = scratch;
  privPtr = priv;
}

/** WASM handler `configure(input_len)` export. The host invokes this once
 *  via `KernelHost.callDynamicExport` after install with payload:
 *      [route_schema_len u8][route_schema ..]
 *  The route name is the host bridge that `forwardToHost` will call into —
 *  the deployer's choice, so it is the one name the WASM cannot bake in
 *  itself. (The signer-query name is literal ASCII and is baked in above.)
 *
 *  Apps re-export this directly:
 *      export { configure } from "../seedkernel/handler"; */
export function configure(input_len: i32): void {
  let p = scratchPtr;
  const end = scratchPtr + input_len;
  if (p >= end) return;
  const rLen = load<u8>(p) as i32; p++;
  if (rLen <= 0 || rLen > MAX_SCHEMA_BYTES || p + rLen > end) return;
  memory.copy(privPtr + ROUTE_OFF, p, rLen);
  routeLen = rLen;
}

/** True once the route name has been planted by configure(). Apps should
 *  early-return from handle() until this is true. */
export function isConfigured(): bool {
  return routeLen > 0;
}

/** Query `signature.signer` for the current message's signer stack and
 *  return a pointer into scratch at the **top** (innermost, last-pushed)
 *  signer's pubkey, or -1 on failure. Needs no configure() — the query's
 *  name is baked in (SIGNER_NAME).
 *
 *  Wire format of the response (README §6.5):
 *      [count u8] [algo u16 BE][pk_len u16 BE][pk ..]*   in push order —
 *      outermost first, top signer LAST.
 *
 *  Only Ed25519 (pk_len == PK_LEN) is accepted; anything else yields -1.
 *  Bounds-check every step so a truncated / malformed response never
 *  reads past the kernel.call return length.
 *
 *  IMPORTANT: this clobbers scratch with the response. Callers must have
 *  staged any input bytes they still need elsewhere (typically in priv)
 *  before calling. */
export function loadTopSignerPubkey(): i32 {
  const respLen = kernelCall(SIGNER_NAME.dataStart as i32, SIGNER_NAME.length, scratchPtr, 0);
  if (respLen <= 0) return -1;
  const count = load<u8>(scratchPtr) as i32;
  if (count == 0) return -1;

  // Walk each [algo u16][pk_len u16][pk ..] entry to find the LAST one.
  // Header per entry = 4 bytes; bounds checks defend against a malformed
  // or truncated response.
  let o: i32 = 1;            // skip count byte
  let pkPtr: i32 = -1;
  let pkLen: i32 = 0;
  for (let i: i32 = 0; i < count; i++) {
    if (o + 4 > respLen) return -1;
    o += 2;                  // skip algo
    pkLen = ((load<u8>(scratchPtr + o) as i32) << 8) |
            (load<u8>(scratchPtr + o + 1) as i32);
    o += 2;
    if (pkLen <= 0 || o + pkLen > respLen) return -1;
    pkPtr = scratchPtr + o;
    o += pkLen;
  }
  // Only the top signer's algorithm matters for this helper. Apps that need
  // multi-algorithm awareness can read the signer stack directly.
  if (pkLen != PK_LEN) return -1;
  return pkPtr;
}

/** Forward a rendered event to the host-side route schema (the JS bridge
 *  the deployer registered for this app). `payloadPtr`/`payloadLen` may
 *  point anywhere in the WASM's memory — typically into priv, since
 *  scratch is unreliable across calls. The host's response (if any) is
 *  written to scratch and the i32 return value is the response length. */
export function forwardToHost(payloadPtr: i32, payloadLen: i32): i32 {
  if (routeLen == 0) return -1;
  return kernelCall(privPtr + ROUTE_OFF, routeLen, payloadPtr, payloadLen);
}
