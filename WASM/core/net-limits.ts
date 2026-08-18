// The inbound flood bounds — core, because they belong to whoever holds the file
// descriptor (README §12.6, §16.1).
//
// **Why these are not in the transport bundle.** The bundle's framers apply the check, on
// sight of an over-cap declaration and before the body it announces is allocated — but a
// host that imported its own flood bound from the module it is bounding would be taking
// the bounded party's word for the bound. So the numbers live here and the module learns
// them at init. Not because the bundle is untrusted, but because a limit protecting a
// resource must be declared by whoever owns the resource, so replacing the transport
// cannot silently replace the bound. (MAX_QUEUE_BYTES is the same rule pointed the other
// way and correctly stays in the bundle: it bounds the module's own memory.)
//
// Nothing here is negotiated or per-suite: both caps apply identically on TCP, WebSocket
// and WebRTC, so a frame that crosses one crosses the other.
/** Hard cap on one link frame, matching §16.1. Checked against the declared length —
 *  the TCP length prefix, the WS frame header — before the body is buffered.
 *
 *  Chosen against what actually crosses a link: the transport does not fragment, so one
 *  application message is one frame, and 2 MiB is twice the largest thing anything here
 *  produces. The headroom is not free — it is a *pre-allocation* bound, so it is what a
 *  peer can make a node reserve from a single length prefix, and `ws.wasm` stages a whole
 *  frame in a scratch region it allocates at module init, in every shell that loads the
 *  transport bundle.
 *
 *  Raising it again means rebuilding ws.wasm (assembly/ws/abi.ts); forget, and
 *  `tests/transport.test.mjs` says so by name rather than a WS link tearing down on the
 *  first big frame while TCP carries it. Lowering one host's cap needs no rebuild
 *  (`TransportHostOptions.maxFrameBytes`). */
export const MAX_FRAME_BYTES = 2 * 1024 * 1024; // 2 MiB
/** The frame cap that applies BEFORE a link authenticates.
 *
 *  Applying MAX_FRAME_BYTES to an unauthenticated peer is a memory-exhaustion hole: a
 *  stranger who knows only host:port declares a full-size frame, dribbles the body, and
 *  holds that much memory — times the half-open budget. No handshake message is anywhere
 *  near it, so nothing legitimate needs the headroom until the link authenticates, which
 *  is when the bundle raises its own framers to the full cap.
 *
 *  **8 KiB rather than 512** because an ML-KEM-768 encapsulation key is 1,184 bytes: with
 *  `ml-kem-768` in the primitive catalog, a 512-byte cap would be the one remaining reason
 *  a PQ handshake still needed a core rev (§14.1). 8 KiB still caps pre-authentication
 *  buffering at 8 MiB against the 1,024 unverified half-open budget. */
export const MAX_HANDSHAKE_FRAME_BYTES = 8 * 1024;
