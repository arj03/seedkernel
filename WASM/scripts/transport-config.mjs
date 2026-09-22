// Defaults owned by the signed transport program. The build writes this object into
// manifest.guest.config, so changing one changes the signed artifact rather than the
// generic host that happens to load it.

/** The local service id this composition claims under `services`: a co-resident guest's and
 *  the host's to reach, no peer's. This program's own choice with no host semantics, which
 *  is why it is emitted beside the blob rather than known to the host. */
export const TRANSPORT_SERVICE = "_net";

/** This program's largest frame, and so its largest application message. ws.wasm stages a
 *  whole frame in its compiled scratch, and on a platform-framed link one message carries
 *  one frame, so it must fit the host's MAX_LINK_READ_BYTES (both: tests/transport.test.mjs). */
export const MAX_FRAME_BYTES = 2 * 1024 * 1024;

export const TRANSPORT_APP_CONFIG = Object.freeze({
  connsPerPeer: 1,
  maxHalfOpenUnverified: 1024,
  maxHalfOpenPerSource: 8,
  maxHalfOpenVerified: 256,
  maxAuthedLinks: 256,
  maxFrameBytes: MAX_FRAME_BYTES,
  maxPreAuthQueueSlices: 4096,
  linkIdleTimeoutMs: 300_000,
  // How long one open correlation waits for its peer before the transport gives up on it.
  // A deployment whose invocation deadline is shorter than this should say so: an app can
  // only route around a silent holder while it still has segment left. Otherwise its host
  // deadline wins and this timer cleans the transport's correlation afterwards (§16.1).
  requestTimeoutMs: 10_000,
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
