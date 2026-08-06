// Shared scaffolding for pure-transform WASM modules (README §3.2, §4).
//
// NOTE: nothing inside this repo imports this file. Its only consumer today is
// seedchat, which reaches it as `seedkernel-wasm/assembly/seedkernel/handler`.
// (seed store's modules predate it and declare their own layout.) It is not dead
// code: it is the guest half of the module ABI, published for the same reason
// the bundle format is — an ABI that apps fork is an ABI that drifts. The path
// keeps its `handler` filename because it is public surface: moving or renaming
// it is a breaking change to consumers.
//
// A module is a PURE TRANSFORM. It exports `memory`, a `scratch` global, and
// `handle(input_len)`. The host stages the input bytes at `scratch`, calls
// `handle`, and reads the response back from `scratch[0..ret]`. Modules import
// nothing — no host seam, no signer query, no caller stack. The host holds a
// named table of pure transforms; the orchestrator (the host shell, or a
// zero-authority guest — README §12) does all I/O, routing, and authorization.
//
// This module holds only the memory-layout constants app modules share. There is
// no longer any `configure`/route machinery: a transform receives everything it
// needs in its input and returns everything it produces in its output.

/** Ed25519 public key length — the sender identity the orchestrator prepends to
 *  a message before handing it to the transform. */
export const PK_LEN: i32 = 32;

/** Offset in a module's private memory that app bookkeeping may start at. The
 *  helper reserves nothing anymore, so this is 0 — kept as a named constant so
 *  app modules read intent, not a bare literal. */
export const PRIV_USER_OFF: i32 = 0;
