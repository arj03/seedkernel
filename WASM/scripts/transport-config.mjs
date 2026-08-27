// Defaults owned by the signed transport program. The build writes this object into
// manifest.guest.config, so changing one changes the signed artifact rather than the
// generic host that happens to load it.
import { MAX_FRAME_BYTES } from "../build/core/net-limits.js";

export const TRANSPORT_APP_CONFIG = Object.freeze({
  connsPerPeer: 1,
  maxHalfOpenUnverified: 1024,
  maxHalfOpenPerSource: 8,
  maxHalfOpenVerified: 256,
  maxAuthedLinks: 256,
  maxFrameBytes: MAX_FRAME_BYTES,
  requestDeadlineMs: 10_000,
  linkIdleTimeoutMs: 300_000,
  admitPeers: Object.freeze([]),
  // The dialing side's whole handshake deadline.
  handshakeTimeoutMs: 10_000,
  // The shorter clock an accept runs until a msg1 opens under the contact secret.
  unverifiedTimeoutMs: 2_000,
  // Frames per direction between key ratchets.
  rekeyAfterFrames: 1 << 24,
});
