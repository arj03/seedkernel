// Driver bounds (§12.6). Host-owned: the socket side of a link, never its framing.
/** Hard cap on one read handed to the link occupant, refused before it is copied into a
 *  realm. A platform-framed transport's frame cap must fit under it. The unit the windows
 *  below are sized in. */
export const MAX_LINK_READ_BYTES = 2 * 1024 * 1024; // 2 MiB

/** Inbound bytes one driver admits across dispatched and held reads, driver-wide rather
 *  than per link. Native applies it again to reads staged toward QuickJS, so its bound is
 *  2× (§12.6); there a full window stalls the reader, here it fails the arriving link.
 *  Seedstore's holder ingest bench, the worst case, peaks at ~6 MiB. */
export const MAX_INBOUND_HOLD_BYTES = 8 * MAX_LINK_READ_BYTES;

/** Count companion to `MAX_INBOUND_HOLD_BYTES`, against floods of tiny reads. */
export const MAX_INBOUND_HOLD_SLICES = 4096;

/** Bytes one link may retain for writes not yet on the wire; a write past it fails the
 *  link. */
export const MAX_OUTBOUND_QUEUE_BYTES = 8 * MAX_LINK_READ_BYTES;

/** Count companion to `MAX_OUTBOUND_QUEUE_BYTES`, against floods of tiny writes. */
export const MAX_OUTBOUND_QUEUE_SLICES = 4096;

/** Outbound allowance shared by every link in one driver, so per-link ceilings do not
 *  multiply by `DEFAULT_MAX_RAW_LINKS`. */
export const MAX_NODE_OUTBOUND_QUEUE_BYTES = 4 * MAX_OUTBOUND_QUEUE_BYTES;
export const MAX_NODE_OUTBOUND_QUEUE_SLICES = 4 * MAX_OUTBOUND_QUEUE_SLICES;

/** Live raw sockets one host holds; native also refuses at accept with it. */
export const DEFAULT_MAX_RAW_LINKS = 4096;

/** How long a gracefully closed TCP socket may linger while queued bytes flush. */
export const TCP_LINGER_MS = 5_000;
