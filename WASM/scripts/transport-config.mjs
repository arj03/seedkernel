// Defaults owned by the signed transport program. The build writes this object into
// manifest.guest.config, so changing one changes the signed artifact rather than the
// generic host that happens to load it.
import { MAX_FRAME_BYTES } from "../build/core/net-limits.js";

/** The local service id this composition claims under `services`: a co-resident guest's and
 *  the host's to reach, no peer's. This program's own choice with no kernel semantics, which
 *  is why it is emitted beside the blob rather than known to the loader. */
export const TRANSPORT_SERVICE = "_net";

export const TRANSPORT_APP_CONFIG = Object.freeze({
  connsPerPeer: 1,
  maxHalfOpenUnverified: 1024,
  maxHalfOpenPerSource: 8,
  maxHalfOpenVerified: 256,
  maxAuthedLinks: 256,
  maxFrameBytes: MAX_FRAME_BYTES,
  maxPreAuthQueueSlices: 4096,
  linkIdleTimeoutMs: 300_000,
  admitPeers: Object.freeze([]),
  // Peers this program dials, as `{ peerId, dest, contactSecret? }` in hex. Empty by
  // default because a cohort is a DEPLOYMENT's fact, not an author's — an installation
  // names it in `LOCAL`, and does so again for a replacement transport, whose address book
  // starts empty like every other part of a fresh realm (§12.10).
  peers: Object.freeze([]),
  // The dialing side's whole handshake deadline.
  handshakeTimeoutMs: 10_000,
  // The shorter clock an accept runs until a msg1 opens under the contact secret.
  unverifiedTimeoutMs: 2_000,
  // Frames per direction between key ratchets.
  rekeyAfterFrames: 1 << 24,
});
