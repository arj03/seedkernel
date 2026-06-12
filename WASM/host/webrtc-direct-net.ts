// Shared link management for relay-less WebRTC-Direct Networks (browser-safe — no
// node, no werift imports). Both the console fabric (host/webrtc-direct.ts, werift
// dialer + single-port listener) and the browser fabric (host/webrtc-direct-browser.ts,
// native RTCPeerConnection, dial-only) are the SAME `Network`: identical link maps,
// PeerLink adoption, promotion, routing, and teardown. They differ only in how a
// dial produces a channel (and whether the node also listens) — so that platform
// part is the one abstract method `openChannel` (plus `acceptInbound` for a node
// listener). This is the WebRtcDirect analogue of RtcNetwork's `peerConnectionFactory`
// seam: one class of plumbing, two thin backends, no duplicated Network logic.

import type { Network, PeerId } from "./net.js";
import { PeerLink, type RawChannel, type Identity, type TransportCrypto } from "./net-link.js";
import { parseDialToken } from "./webrtc-direct-sdp.js";
import { toHex } from "./util.js";

/** A platform-dialed channel: the PeerLink-ready RawChannel, a teardown for any
 *  owning connection object (e.g. an RTCPeerConnection), and — when the channel
 *  opens asynchronously after the call returns — an `opened` promise whose
 *  rejection means the connection failed to come up. */
export interface OpenedChannel {
  channel: RawChannel;
  close: () => void;
  opened?: Promise<void>;
}

export interface WebRtcDirectBaseOptions {
  identity: Identity;
  sodium: TransportCrypto;
  /** Roster gate applied after the in-channel AUTH proves identity — an off-roster
   *  peer is dropped even once the handshake completes (trustworthy decision). */
  admit?: (peerId: PeerId) => boolean;
  onPeerUp?: (peerId: PeerId) => void;
  onPeerDown?: (peerId: PeerId) => void;
}

export abstract class WebRtcDirectNetworkBase implements Network {
  /** Diagnostics, mirroring the other Networks. */
  framesDelivered = 0;

  protected readonly ownId: PeerId;
  private sink: ((from: PeerId, frame: Uint8Array) => void) | null = null;
  private readonly links = new Map<PeerId, PeerLink>();   // authenticated, routable
  private readonly pending = new Set<PeerLink>();          // adopted, pre-auth
  // Teardown for a channel's owning connection (e.g. the dial-side RTCPeerConnection):
  // closing the PeerLink shuts the data channel but not the connection, whose timers
  // we also want gone — so run it when the link is forgotten or the network closes.
  private readonly closers = new Map<PeerLink, () => void>();

  constructor(protected readonly baseOpts: WebRtcDirectBaseOptions) {
    this.ownId = toHex(baseOpts.identity.publicKey);
  }

  /** Open a data channel to the token's node, wrapped as a PeerLink-ready RawChannel.
   *  The node backend dials with werift; the browser backend with the platform
   *  RTCPeerConnection. */
  protected abstract openChannel(token: string, timeoutMs: number): Promise<OpenedChannel>;

  /** Dial a token and resolve once the link authenticates (rejects on timeout or a
   *  failed connection). The peer is then routable and onPeerUp has fired. */
  async dial(token: string, timeoutMs = 15000): Promise<PeerId> {
    const t = parseDialToken(token);
    const { channel, close, opened } = await this.openChannel(token, timeoutMs);
    return await new Promise<PeerId>((resolve, reject) => {
      const timer = setTimeout(() => { this.forget(link); reject(new Error("webrtc-direct dial: auth timeout")); }, timeoutMs);
      const link = this.adopt(channel, true, t.peerId, close, (pid) => { clearTimeout(timer); resolve(pid); });
      opened?.catch((e) => { clearTimeout(timer); this.forget(link); reject(e); });
    });
  }

  /** Adopt an inbound channel (a node listener calls this for each accepted dialer). */
  protected acceptInbound(channel: RawChannel, close?: () => void): void {
    this.adopt(channel, false, undefined, close);
  }

  // Wrap a RawChannel in PeerLink and track it until it authenticates. `onUp` fires
  // (in addition to onPeerUp) on auth, so dial() can resolve with the peer id.
  private adopt(
    channel: RawChannel, weDialed: boolean, expectPeerId: PeerId | undefined,
    close: (() => void) | undefined, onUp?: (peerId: PeerId) => void,
  ): PeerLink {
    const link = new PeerLink({
      channel, identity: this.baseOpts.identity, sodium: this.baseOpts.sodium,
      weDialed, expectPeerId,
      onAuth: (pid, l) => { this.promote(pid, l); onUp?.(pid); },
      onFrame: (pid, frame) => this.deliver(pid, frame),
      onClose: (l) => this.forget(l),
    });
    this.pending.add(link);
    if (close) this.closers.set(link, close);
    return link;
  }

  // ── Network interface ──────────────────────────────────────────────────────
  register(peerId: PeerId, sink: (from: PeerId, frame: Uint8Array) => void): void {
    if (peerId !== this.ownId) throw new Error("WebRtcDirectNetwork is bound to one identity");
    this.sink = sink;
  }
  unregister(peerId: PeerId): void {
    if (peerId !== this.ownId) return;
    this.sink = null;
    this.close();
  }
  send(_from: PeerId, to: PeerId, frame: Uint8Array): void {
    // Dropped if there is no authenticated link, exactly as the other Networks drop
    // to an unknown peer; the Transport's timeout copes.
    this.links.get(to)?.send(frame);
  }

  /** The peers we currently hold an authenticated link to (for cohort / UI). */
  linkedPeers(): PeerId[] { return [...this.links.keys()]; }

  close(): void {
    for (const l of this.links.values()) l.close();
    for (const l of this.pending) l.close();
    for (const teardown of this.closers.values()) { try { teardown(); } catch { /* ignore */ } }
    this.links.clear();
    this.pending.clear();
    this.closers.clear();
    this.stopListener();
  }

  /** Subclass hook: tear down a node listener on close (no-op for dial-only). */
  protected stopListener(): void {}

  // ── link lifecycle ───────────────────────────────────────────────────────────
  private promote(peerId: PeerId, link: PeerLink): void {
    this.pending.delete(link);
    if (this.baseOpts.admit && !this.baseOpts.admit(peerId)) { link.close(); return; }
    const existing = this.links.get(peerId);
    if (existing && existing !== link) existing.close(); // a re-dial replaces the old link
    this.links.set(peerId, link);
    this.baseOpts.onPeerUp?.(peerId);
  }

  private deliver(peerId: PeerId, frame: Uint8Array): void {
    if (!this.sink || peerId === this.ownId) return;
    this.framesDelivered++;
    this.sink(peerId, frame); // PeerLink only delivers post-auth, tagged with the authenticated id
  }

  private forget(link: PeerLink): void {
    this.pending.delete(link);
    for (const [pid, l] of this.links) {
      if (l === link) { this.links.delete(pid); this.baseOpts.onPeerDown?.(pid); }
    }
    const teardown = this.closers.get(link);
    if (teardown) { this.closers.delete(link); try { teardown(); } catch { /* ignore */ } }
  }
}
