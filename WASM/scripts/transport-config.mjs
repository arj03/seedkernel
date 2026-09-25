// The transport's signed defaults, written into manifest.guest.config.

/** The local service id this bundle claims under `services`; the host gives it no meaning. */
export const TRANSPORT_SERVICE = "_net";

/** The largest frame, and so the largest application message. It must fit ws.wasm's
 *  scratch and the host's MAX_LINK_READ_BYTES (tests/transport.test.mjs). */
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
  // How long a correlation waits for its peer. Set it below the invocation deadline for an
  // app to have time to try another holder (§16.1).
  requestTimeoutMs: 10_000,
  admitPeers: Object.freeze([]),
  // Peers to dial, as `pk[.secret]@dest` (core.js `peerRef`). A deployment's fact, so set
  // in LOCAL (§12.10).
  peers: Object.freeze([]),
  // The dialing side's whole handshake deadline.
  handshakeTimeoutMs: 10_000,
  // The shorter clock an accept runs until a msg1 opens under the contact secret.
  unverifiedTimeoutMs: 2_000,
  // Frames per direction between key ratchets.
  rekeyAfterFrames: 1 << 24,
  // WebRTC (rtc.js): negotiations at once without an authenticated link, and how long one
  // may take to open its data channel.
  maxRtcNegotiating: 256,
  rtcConnectTimeoutMs: 30_000,
  // STUN/TURN servers (RTCConfiguration.iceServers). Empty means LAN only.
  iceServers: Object.freeze([]),
});
