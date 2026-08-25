// Inbound flood bound (§12.6.2, §16.1). Host-owned; the bundle learns it at init.
/** Hard cap on one link frame, checked against the declared length before buffering. */
export const MAX_FRAME_BYTES = 2 * 1024 * 1024; // 2 MiB
