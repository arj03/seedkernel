// BrowserWebRtcDirectNetwork — the browser backend of WebRtcDirectNetwork. All the
// link plumbing lives in WebRtcDirectNetworkBase (shared with the node fabric); this
// class supplies only the platform dial. A browser cannot bind a UDP port, so it is
// dial-only (no listener): it reaches console `serveDirect` nodes by their token with
// NO signaling relay — it fabricates each console's answer locally from the token's
// certhash, so no answer travels back — then PeerLink proves identity in-channel.
//
// Browser-only (uses the platform RTCPeerConnection / RTCDataChannel); like net-rtc.ts
// it touches those globals only inside openChannel(), never at module scope, so
// importing this module under Node (e.g. for type-checking) stays safe. The node-side
// WebRtcDirectNetwork (werift) is the tested parity reference.

import { WebRtcDirectNetworkBase, type WebRtcDirectBaseOptions, type OpenedChannel } from "./webrtc-direct-net.js";
import { RtcChannel } from "./net-rtc.js";
import {
  parseDialToken, certhashToFingerprint, fabricateAnswerSdp, randomUfrag,
} from "./webrtc-direct-sdp.js";

export interface BrowserWebRtcDirectNetworkOptions extends WebRtcDirectBaseOptions {
  /** ICE servers (STUN/TURN) for dialing a console across NAT. For a console on the
   *  same LAN, host candidates connect without it. */
  rtcConfig?: RTCConfiguration;
}

export class BrowserWebRtcDirectNetwork extends WebRtcDirectNetworkBase {
  constructor(private readonly opts: BrowserWebRtcDirectNetworkOptions) {
    super(opts);
  }

  // Dial with the platform RTCPeerConnection: build an offer, fabricate the console's
  // answer from the token's certhash, set it — ICE + DTLS then bring the channel up
  // with no relay. Wrapping the channel in RtcChannel here (it subscribes immediately)
  // means the console's HELLO is not missed once the base adopts it into PeerLink.
  protected async openChannel(token: string): Promise<OpenedChannel> {
    const t = parseDialToken(token);
    const pc = new RTCPeerConnection(this.opts.rtcConfig ?? {});
    const dc = pc.createDataChannel("seedkernel", { ordered: true });
    const channel = new RtcChannel(dc);
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    const ufrag = randomUfrag();
    const answer = fabricateAnswerSdp(pc.localDescription!.sdp, {
      ufrag, fingerprint: certhashToFingerprint(t.certhash), host: t.host, port: t.port,
    });
    await pc.setRemoteDescription({ type: "answer", sdp: answer });
    return { channel, close: () => { try { pc.close(); } catch { /* already gone */ } } };
  }
}
