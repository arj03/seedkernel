// Inbound flood bound (§12.6.2, §16.1). Host-owned; the bundle learns it at init.
/** Hard cap on one link frame, checked against the declared length before buffering. */
export const MAX_FRAME_BYTES = 2 * 1024 * 1024; // 2 MiB

/** Aggregate inbound bytes one driver admits across dispatched and held reads. A browser
 *  WebSocket and an RTCDataChannel cannot be paused, while a pausable socket still owns one
 *  dispatched read until the serialized realm releases it; both therefore reserve from the
 *  same driver-wide window before a read crosses into the realm, instead of multiplying
 *  host memory by the raw-link ceiling. Native applies the window a SECOND time to reads
 *  staged toward QuickJS, so the two overlap and that target's real bound is 2× (§12.6);
 *  there a full window stalls the reader goroutine, here it fails the arriving link.
 *
 *  The window is what a pipelining peer really runs at, not a guess: seedstore's holder
 *  ingest bench (1 MiB batched STOREs against a zero-latency fabric, the hardest case there
 *  is — no wire to pace the sender) peaks at ~6 MiB of hold, so this leaves ~2.5× headroom.
 *  The value is eight maximum-sized frames, shared by the entire transport realm. */
export const MAX_INBOUND_HOLD_BYTES = 8 * MAX_FRAME_BYTES;

/** Driver-wide count companion to `MAX_INBOUND_HOLD_BYTES`. A byte bound alone lets peers
 *  sending one-byte messages turn that window into millions of queued realm invocations
 *  and held slices, which cost far more than their bytes. */
export const MAX_INBOUND_HOLD_SLICES = 4096;

/** Bytes one socket adapter may retain for writes that have not reached the wire. The
 *  transport may have many authenticated producers (local requests and peer responses),
 *  so observing backlog for stall clocks is not enough: the adapter that owns the queue
 *  fails the link before accepting a write past this ceiling. */
export const MAX_OUTBOUND_QUEUE_BYTES = 8 * MAX_FRAME_BYTES;

/** Count companion to `MAX_OUTBOUND_QUEUE_BYTES`. Tiny writes otherwise fit millions of
 *  queue nodes inside the byte window while spending much more host memory in metadata. */
export const MAX_OUTBOUND_QUEUE_SLICES = 4096;

/** Parent allowance shared by every link in one network driver. Per-link ceilings alone
 * multiply by `DEFAULT_MAX_RAW_LINKS`; this bounds the process-facing aggregate instead. */
export const MAX_NODE_OUTBOUND_QUEUE_BYTES = 4 * MAX_OUTBOUND_QUEUE_BYTES;
export const MAX_NODE_OUTBOUND_QUEUE_SLICES = 4 * MAX_OUTBOUND_QUEUE_SLICES;

/** Live raw sockets one host holds at once. The native accept path also receives this
 *  value so it can refuse before allocating a channel's goroutines and read buffer. */
export const DEFAULT_MAX_RAW_LINKS = 4096;

/** How long a gracefully closed TCP socket may linger while queued bytes flush. */
export const TCP_LINGER_MS = 5_000;
