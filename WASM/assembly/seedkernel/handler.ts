// Shared scaffolding for pure-transform WASM handlers (README §3.2, §4).
//
// A handler is a PURE TRANSFORM. It exports `memory`, a `scratch` global, and
// `handle(input_len)`. The host stages the input bytes at `scratch`, calls
// `handle`, and reads the response back from `scratch[0..ret]`. Handlers import
// nothing — no kernel.call, no signer query, no caller stack. The kernel is a
// named table of pure transforms; the orchestrator (the host shell, or a
// zero-authority guest — README §12) does all I/O, routing, and authorization.
//
// This module holds only the memory-layout constants app modules share. There is
// no longer any `configure`/route machinery: a transform receives everything it
// needs in its input and returns everything it produces in its output.

/** Ed25519 public key length — the sender identity the orchestrator prepends to
 *  a message before handing it to the transform. */
export const PK_LEN: i32 = 32;

/** Offset in a handler's private memory that app bookkeeping may start at. The
 *  helper reserves nothing anymore, so this is 0 — kept as a named constant so
 *  app modules read intent, not a bare literal. */
export const PRIV_USER_OFF: i32 = 0;
