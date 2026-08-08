// The inbound flood bounds — core, because they belong to whoever holds the file
// descriptor (README §12.6, §16.1).
//
// **Why these are not in the transport bundle.** Whoever imposes the boundaries applies
// the check — the transport bundle's framers (transport/src/framing.js), which refuse an
// over-cap declaration on sight, before the body it announces is ever allocated. But a
// host that imported its own flood bound from the module it is bounding would be taking
// the bounded party's word for the bound. So the numbers live here, in the core, and the
// module learns them at init rather than the other way round.
//
// The distinction is not "the transport bundle is untrusted" — a transport admitted at
// boot is trusted exactly as much as host code. It is that a limit protecting a resource
// must be declared by whoever owns the resource, so that replacing the transport cannot
// silently replace the bound. MAX_QUEUE_BYTES is the other side of the same rule and
// correctly stays in the bundle: it bounds the transport's *own* pre-auth send queue,
// which is the module's memory to spend.
//
// Nothing here is negotiated and nothing is per-suite. Both caps apply identically on
// TCP, WebSocket and WebRTC, so a frame that crosses one crosses the other.
/** Hard cap on one link frame, matching §16.1. Checked against the declared length —
 *  the TCP length prefix, the WS frame header — before the body is buffered.
 *
 *  **2 MiB, and the number is chosen against what actually crosses a link, not against
 *  what a frame could theoretically be.** The transport does not fragment: one
 *  application message is one frame, so this is the largest message a node can send. The
 *  only app on it batches at 1 MiB and stores 256 KiB blocks, and the bundle's own
 *  pre-auth send budget (`MAX_QUEUE_BYTES`) is 1 MiB — so 2 MiB is twice the largest
 *  thing anything here produces. It was 16 MiB, which nothing approached.
 *
 *  Two reasons the headroom was not free. It is a *pre-allocation* bound, so it is also
 *  what a peer can make a node reserve from a single length prefix; and `ws.wasm` must be
 *  able to stage a whole frame in its scratch region, which it allocates at module init —
 *  and, riding in the transport bundle, it is instantiated in every shell, so the cap was
 *  costing ~17 MB of linear memory per node whether or not that node ever spoke
 *  WebSocket. Raising this again means rebuilding ws.wasm (assembly/ws/abi.ts) — forget
 *  and `tests/transport.test.mjs` says so by name, rather than a WS link tearing down on
 *  the first big frame while TCP carries it. Lowering a single host's cap needs no
 *  rebuild, and `TransportHostOptions.maxFrameBytes` already allows it. */
export const MAX_FRAME_BYTES = 2 * 1024 * 1024; // 2 MiB
/** The frame cap that applies BEFORE a link authenticates.
 *
 *  MAX_FRAME_BYTES bounds what an *application* frame may be, and applying it to an
 *  unauthenticated peer is a memory-exhaustion hole: a stranger who knows only host:port
 *  declares a full-size frame, dribbles the body, and holds that much of our memory —
 *  times the half-open budget, which is gigabytes for the price of opening sockets. No
 *  handshake message is anywhere near it (the largest is 113 bytes including the tag), so
 *  nothing legitimate needs the headroom until the link is authenticated.
 *
 *  The transport bundle raises its own framers to MAX_FRAME_BYTES at exactly the moment
 *  the peer becomes a known, admitted identity. Both numbers stay the host's; what the
 *  module chooses is only when the transition happens.
 *
 *  **8 KiB rather than 512, and the difference is the post-quantum migration §14.1 puts
 *  on a clock.** An ML-KEM-768 encapsulation key is 1,184 bytes, so 512 would be a second
 *  lock on the same door: with `ml-kem-768` in the primitive catalog, a 512-byte cap is
 *  the one remaining reason a PQ handshake would still need a core rev — the bound
 *  refusing the message the catalog just made expressible. 8 KiB still does the job it
 *  exists for, capping *pre-authentication* buffering at 8 MiB against the 1,024
 *  unverified half-open budget, without deciding which suites are expressible. */
export const MAX_HANDSHAKE_FRAME_BYTES = 8 * 1024;
