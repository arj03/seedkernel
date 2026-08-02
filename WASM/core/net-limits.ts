// The inbound flood bounds — core, because they belong to whoever holds the file
// descriptor (README §12.6, §16.1).
//
// **Why these are not in net-link.ts.** The check is already in the right place: the
// socket seams (net-node.ts, net-ws.ts, net-rtc.ts) test the declared length against the
// cap *before* buffering, so an over-cap frame is refused without its bytes ever being
// allocated. Only the declaration was on the wrong side of the line. net-link.ts is the
// AKE and record layer, which becomes an ordinary signed bundle — and a host that
// imported its own flood bound from the module it is bounding would be taking the
// bounded party's word for the bound. So the numbers live here, in the core, and the
// module imports them rather than the other way round.
//
// The distinction is not "net-link is untrusted" — a transport admitted at boot is
// trusted exactly as much as host code. It is that a limit protecting a resource must be
// declared by whoever owns the resource, so that replacing the transport cannot silently
// replace the bound. MAX_QUEUE_BYTES is the other side of the same rule and correctly
// stays in net-link.ts: it bounds PeerLink's *own* pre-auth send queue, which is the
// module's memory to spend.
//
// Nothing here is negotiated and nothing is per-suite. Both caps apply identically on
// TCP, WebSocket and WebRTC, so a frame that crosses one crosses the other.
/** Hard cap on one link frame, matching §16.1. Enforced by the socket seams on the
 *  length prefix (TCP) or frame length (WS) before buffering. */
export const MAX_FRAME_BYTES = 16 * 1024 * 1024; // 16 MiB
/** The frame cap that applies BEFORE a link authenticates.
 *
 *  MAX_FRAME_BYTES bounds what an *application* frame may be, and applying it to an
 *  unauthenticated peer was a memory-exhaustion hole: a stranger who knows only
 *  host:port could declare a 16 MiB frame, dribble the body, and hold that much of our
 *  memory — times the half-open budget, which is gigabytes for the price of opening
 *  sockets. No handshake message is anywhere near it (the largest is 113 bytes including
 *  the tag), so nothing legitimate needs the headroom until the link is authenticated.
 *
 *  Raised to MAX_FRAME_BYTES by the transport bundle through `NET_LINK_CAP` at exactly
 *  the moment the peer becomes a known, admitted identity — the one transition the
 *  module is allowed to ask for, and the host still owns both numbers.
 *
 *  **8 KiB rather than the 512 this started at, and the difference is the post-quantum
 *  migration §14.1 puts on a clock.** An ML-KEM-768 encapsulation key is 1,184 bytes, so
 *  512 was a second lock on the same door: with `ml-kem-768` now in the primitive
 *  catalog, a 512-byte cap would have been the one remaining reason a PQ handshake still
 *  needed a core rev — the socket seam would have refused the message the catalog had
 *  just made expressible. The bound still does its job — it exists to cap *pre-authentication*
 *  buffering, and 8 KiB against the 1,024 unverified half-open budget is 8 MiB, bounded
 *  and small — while no longer deciding which suites are expressible. */
export const MAX_HANDSHAKE_FRAME_BYTES = 8 * 1024;
