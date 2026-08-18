// Shared scaffolding for pure-transform WASM modules (README §3.2, §4).
//
// Nothing in this repo imports it — its consumer is seedchat, as
// `seedkernel-wasm/assembly/seedkernel/handler` — but it is not dead code: it is the guest
// half of the module ABI, published for the same reason the bundle format is. The filename
// is public surface, so renaming it breaks consumers.
//
// A module is a PURE TRANSFORM: it exports `memory`, a `scratch` global and
// `handle(input_len)`, and imports nothing. The host stages input at `scratch`, calls
// `handle`, and reads the response from `scratch[0..ret]`; all I/O, routing and
// authorization are the orchestrator's (§12).
//
// What is left here is the memory-layout constants app modules share — a transform receives
// everything it needs in its input and returns everything it produces in its output.

/** Ed25519 public key length — the sender identity the orchestrator prepends to
 *  a message before handing it to the transform. */
export const PK_LEN: i32 = 32;

/** Offset in a module's private memory that app bookkeeping may start at. This helper
 *  reserves nothing, so it is 0 — named so app modules read intent, not a literal. */
export const PRIV_USER_OFF: i32 = 0;
