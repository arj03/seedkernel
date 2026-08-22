// Inbound flood bounds (§12.6.2, §16.1). Host-owned; the bundle learns them at init.
/** Hard cap on one link frame, checked against the declared length before buffering. */
export const MAX_FRAME_BYTES = 2 * 1024 * 1024; // 2 MiB
/** Pre-auth frame cap, raised to MAX_FRAME_BYTES on authentication. 8 KiB so an
 *  ML-KEM-768 encapsulation key (1184 B) fits without a core rev. */
export const MAX_HANDSHAKE_FRAME_BYTES = 8 * 1024;
