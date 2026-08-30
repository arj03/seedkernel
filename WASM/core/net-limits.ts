// Inbound flood bound (§12.6.2, §16.1). Host-owned; the bundle learns it at init.
/** Hard cap on one link frame, checked against the declared length before buffering. */
export const MAX_FRAME_BYTES = 2 * 1024 * 1024; // 2 MiB

/** Inbound bytes the driver will HOLD for one link whose adapter cannot be paused at the
 *  platform — a browser WebSocket and an RTCDataChannel both deliver whatever arrives, so
 *  "paused" can only mean held above the socket. It is the peer's in-flight window while
 *  one read occupies the serialized realm: eight more frames behind the one being worked
 *  on. Past it the peer is outrunning the realm, and the link fails rather than the driver
 *  growing a queue on its behalf. A socket that CAN be paused holds nothing here.
 *
 *  The window is what a pipelining peer really runs at, not a guess: seedstore's holder
 *  ingest bench (1 MiB batched STOREs against a zero-latency fabric, the hardest case there
 *  is — no wire to pace the sender) peaks at ~6 MiB of hold, so this leaves ~2.5× headroom.
 *  Only a link with no platform pushback holds anything at all, which in practice means a
 *  browser edge's handful of peers rather than a node's whole link table. */
export const MAX_INBOUND_HOLD_BYTES = 8 * MAX_FRAME_BYTES;

/** The same hold, as a COUNT. A byte bound alone lets a peer sending one-byte messages
 *  turn that window into millions of held slices, which cost far more than their bytes —
 *  so the two bounds meet at roughly a kilobyte per slice, and a peer below that is
 *  bounded by this one. A stream adapter's slices are orders of magnitude larger. */
export const MAX_INBOUND_HOLD_SLICES = 4096;

/** Live raw sockets one host holds at once. The native accept path also receives this
 *  value so it can refuse before allocating a channel's goroutines and read buffer. */
export const DEFAULT_MAX_RAW_LINKS = 4096;

/** How long a gracefully closed TCP socket may linger while queued bytes flush. */
export const TCP_LINGER_MS = 5_000;
