// Inbound flood bound (§12.6.2, §16.1). Host-owned; the bundle learns it at init.
/** Hard cap on one link frame, checked against the declared length before buffering. */
export const MAX_FRAME_BYTES = 2 * 1024 * 1024; // 2 MiB

/** Live raw sockets one host holds at once. The native accept path also receives this
 *  value so it can refuse before allocating a channel's goroutines and read buffer. */
export const DEFAULT_MAX_RAW_LINKS = 4096;

/** How long a gracefully closed TCP socket may linger while queued bytes flush. */
export const TCP_LINGER_MS = 5_000;
