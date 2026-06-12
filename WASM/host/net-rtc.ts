// WebRTC as a first-class Network (README §13.6: net.send is "addressed unicast
// to a peer over its data channel"; net.ts notes "a WebRTC/data-channel … satisfies
// the same interface"). This is the real-P2P fabric: peers reach each other
// directly over RTCDataChannels — the relay is only a signaling rendezvous and can
// be killed once channels are up — so there is no server in the data path.
//
// The layering is identical to net-node.ts, only the bottom swaps:
//   Transport (unchanged) → RtcNetwork → PeerLink (unchanged identity handshake)
//                                          → RtcChannel (this file) → RTCDataChannel
// Transport rides on top untouched, so storage's coordinator/holder get P2P for
// free; an app that only wants fire-and-forget (chat) consumes the Network's
// send() directly. One ordered, binary data channel per peer carries everything.
//
// Identity: PeerLink runs its HELLO/AUTH challenge *inside* the channel, proving
// each end holds the kernel private key for the pubkey it claims. That subsumes
// the SDP-fingerprint signing chat-shell.js does at the signaling layer — and is
// stronger, because it is continuous channel binding rather than a one-shot SDP
// assertion: a MITM relay can splice SDP and bring up DTLS to itself, but it can
// never complete AUTH without the peer's private key, so the link never
// authenticates and never delivers a byte.
//
// This module is browser-native (it uses the platform RTCPeerConnection /
// RTCDataChannel / WebSocket). A Node/Bun console peer joins the same mesh by
// passing a werift-backed `peerConnectionFactory` (./net-rtc-node
// `weriftPeerConnectionFactory`) behind the same RtcChannel / Signaling —
// everything above the channel is untouched, the same "swap the connection, keep
// the stack" move net-node.ts documents for the engine build. (werift, pure-TS, is
// used rather than the native node-datachannel, which segfaults under Bun.) The
// browser globals are referenced only inside RtcNetwork / relaySignaling, never at
// module scope, so importing this module under Node (e.g. to unit-test RtcChannel)
// is safe.

import type { Network, PeerId } from "./net.js";
import { PeerLink, type RawChannel, type Identity, type TransportCrypto } from "./net-link.js";
import { toHex } from "./util.js";

// ── RawChannel over one RTCDataChannel ────────────────────────────────────────
// An RTCDataChannel is already an ordered, whole-message binary pipe (WebRTC does
// framing + ordering), so this is a thin adapter. Its one job beyond shuffling
// bytes: buffer sends issued before the channel reaches "open", because PeerLink
// emits its HELLO the instant it is constructed — the same pre-open queueing the
// WS channel does in net-node.ts.
export class RtcChannel implements RawChannel {
  private onMsg: ((b: Uint8Array) => void) | null = null;
  private onCls: (() => void) | null = null;
  private readonly pending: Uint8Array[] = [];
  private dead = false;

  constructor(private readonly dc: RTCDataChannel) {
    dc.binaryType = "arraybuffer";
    dc.addEventListener("message", (ev: MessageEvent) => {
      // String frames are not ours (a host may multiplex renegotiation signaling
      // over the same channel — see chat-shell.js); only binary frames are
      // PeerLink messages.
      if (!this.dead && typeof ev.data !== "string") this.onMsg?.(new Uint8Array(ev.data as ArrayBuffer));
    });
    dc.addEventListener("open", () => {
      // The DOM types RTCDataChannel.send as requiring an ArrayBuffer-backed view
      // (not SharedArrayBuffer). PeerLink frames are always plain Uint8Arrays over
      // a real ArrayBuffer, so the narrowing cast is sound.
      for (const b of this.pending) dc.send(b as Uint8Array<ArrayBuffer>);
      this.pending.length = 0;
    });
    dc.addEventListener("close", () => this.fail());
    dc.addEventListener("error", () => this.fail());
  }

  send(bytes: Uint8Array): void {
    if (this.dead) return;
    if (this.dc.readyState === "open") this.dc.send(bytes as Uint8Array<ArrayBuffer>);
    else this.pending.push(bytes);
  }
  onMessage(cb: (b: Uint8Array) => void): void { this.onMsg = cb; }
  onClose(cb: () => void): void { this.onCls = cb; }
  close(): void { if (!this.dead) { this.dead = true; try { this.dc.close(); } catch { /* already gone */ } } }

  // Failure teardown notifies onClose so the owning PeerLink is forgotten from the
  // routing maps (see net-node.ts TcpChannel.fail for why this must always fire).
  private fail(): void { if (!this.dead) { this.dead = true; this.onCls?.(); } }
}

// ── Signaling: a pluggable rendezvous for the SDP/ICE exchange ─────────────────
// The relay (scripts/relay.mjs) satisfies this unchanged: it broadcasts JSON
// `{type, from, to}` messages within a room. Any rendezvous that delivers those
// works — a DHT, gossip, even a shared channel between two already-connected peers
// for renegotiation. We deliberately do NOT carry an SDP-fingerprint signature
// here; PeerLink proves identity in-channel (see header).
export interface Signaling {
  send(msg: unknown): void;
  onMessage(cb: (msg: SignalMsg) => void): void;
  close(): void;
}

interface SignalMsg {
  type: "hello" | "sdp" | "ice";
  from: PeerId;
  to?: PeerId;
  sdp?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
}

export interface RtcNetworkOptions {
  identity: Identity;
  sodium: TransportCrypto;
  signaling: Signaling;
  /** ICE servers (STUN/TURN). For LAN/localhost a public STUN list is enough. */
  rtcConfig?: RTCConfiguration;
  /** Factory for the underlying RTCPeerConnection. Defaults to the platform
   *  global, which is what a browser tab uses. A Node/Bun *console* node passes a
   *  werift-backed factory (./net-rtc-node `weriftPeerConnectionFactory`) so this
   *  exact RtcNetwork / RtcChannel / PeerLink stack runs off-browser — "swap the
   *  connection, keep the stack", the same move net-node.ts documents for TCP. It
   *  is referenced only inside ensurePeer(), never at module scope, so importing
   *  this module under Node without a factory stays safe. */
  peerConnectionFactory?: (config?: RTCConfiguration) => RTCPeerConnection;
  /** Optional roster gate: which peers we are willing to link with (e.g. a storage
   *  cohort). Applied to signaling and at authentication, so an off-roster peer
   *  never gets a connection or a frame. Default: admit everyone in the room. */
  admit?: (peerId: PeerId) => boolean;
  /** Called when a peer's link authenticates / drops. The storage demo uses these
   *  to mirror the live mesh into a StorageNode's cohort (addPeer/removePeer). */
  onPeerUp?: (peerId: PeerId) => void;
  onPeerDown?: (peerId: PeerId) => void;
}

// Cap on speculative (unauthenticated) peer entries the relay can force us to
// allocate by spamming `hello`s with arbitrary `from` values. Authenticated peers
// do not count, so genuine fleet size is unconstrained (mirrors chat-shell.js's
// MAX_UNAUTHED_PEERS). 256 is comfortable headroom for a churn storm.
const MAX_UNAUTHED_PEERS = 256;

interface PeerEntry {
  pc: RTCPeerConnection;
  link: PeerLink | null;     // wraps the data channel once it exists
  authed: boolean;
  polite: boolean;
  makingOffer: boolean;
  pendingIce: RTCIceCandidateInit[];
}

export class RtcNetwork implements Network {
  /** Diagnostics, mirroring LoopbackNetwork / NodeNetwork. */
  framesDelivered = 0;

  private readonly opts: RtcNetworkOptions;
  private readonly ownId: PeerId;
  private sink: ((from: PeerId, frame: Uint8Array) => void) | null = null;
  private readonly links = new Map<PeerId, PeerLink>();  // authenticated, routable
  private readonly peers = new Map<PeerId, PeerEntry>(); // all (pre- and post-auth)

  constructor(opts: RtcNetworkOptions) {
    this.opts = opts;
    this.ownId = toHex(opts.identity.publicKey);
    opts.signaling.onMessage((m) => this.onSignal(m));
  }

  // ── Network interface ────────────────────────────────────────────────────────
  register(peerId: PeerId, sink: (from: PeerId, frame: Uint8Array) => void): void {
    if (peerId !== this.ownId) throw new Error("RtcNetwork is bound to one identity");
    this.sink = sink; // Transport registers its frame sink here (net.ts)
  }
  unregister(peerId: PeerId): void {
    if (peerId !== this.ownId) return;
    this.sink = null;
    this.close();
  }
  send(_from: PeerId, to: PeerId, frame: Uint8Array): void {
    // Links form through signaling/discovery, not lazily on first send. A frame to
    // a peer with no authenticated link is dropped, exactly as Loopback/NodeNetwork
    // drop to an unknown peer; the Transport's timeout copes with the fallout.
    this.links.get(to)?.send(frame);
  }

  /** Announce ourselves into the room so present peers begin the WebRTC dance.
   *  Call once after registering the sink (or constructing a StorageNode/Transport
   *  over this network). */
  join(): void { this.opts.signaling.send({ type: "hello", from: this.ownId }); }

  /** The peers we currently hold an authenticated link to (for broadcast / UI). */
  linkedPeers(): PeerId[] { return [...this.links.keys()]; }

  /** Tear down every connection, link, and the signaling channel. */
  close(): void {
    for (const l of this.links.values()) l.close();
    for (const e of this.peers.values()) { try { e.pc.close(); } catch { /* ignore */ } }
    this.links.clear();
    this.peers.clear();
    this.opts.signaling.close();
  }

  // ── per-peer connection (perfect negotiation, adapted from chat-shell.js) ─────
  private ensurePeer(peerId: PeerId): PeerEntry {
    const existing = this.peers.get(peerId);
    if (existing) return existing;
    const makePc = this.opts.peerConnectionFactory ?? ((cfg?: RTCConfiguration) => new RTCPeerConnection(cfg));
    const pc = makePc(this.opts.rtcConfig);
    const e: PeerEntry = { pc, link: null, authed: false, polite: this.ownId > peerId, makingOffer: false, pendingIce: [] };
    this.peers.set(peerId, e);

    pc.addEventListener("icecandidate", (ev) => {
      if (ev.candidate) this.opts.signaling.send({ type: "ice", from: this.ownId, to: peerId, candidate: ev.candidate.toJSON() });
    });
    pc.addEventListener("negotiationneeded", async () => {
      // Single entry point for offers — fires when the impolite side creates the
      // data channel. Implicit setLocalDescription() picks offer vs answer.
      try {
        e.makingOffer = true;
        await pc.setLocalDescription();
        this.opts.signaling.send({ type: "sdp", from: this.ownId, to: peerId, sdp: pc.localDescription ?? undefined });
      } catch { /* renegotiation failed; ICE restart / next hello recovers */ }
      finally { e.makingOffer = false; }
    });
    // The polite side receives the channel the impolite side opened.
    pc.addEventListener("datachannel", (ev) => this.bindLink(peerId, e, ev.channel, /*weDialed*/ false));
    pc.addEventListener("connectionstatechange", () => {
      if (pc.connectionState === "failed" || pc.connectionState === "closed") this.forget(peerId);
    });
    return e;
  }

  // The impolite side opens the single ordered binary channel; the polite side gets
  // it via ondatachannel. Exactly one channel per pair, so there is no double-
  // connect to resolve (unlike NodeNetwork's TCP dial race).
  private dialChannel(peerId: PeerId, e: PeerEntry): void {
    if (e.polite || e.link) return;
    this.bindLink(peerId, e, e.pc.createDataChannel("seedkernel", { ordered: true }), /*weDialed*/ true);
  }

  private bindLink(peerId: PeerId, e: PeerEntry, dc: RTCDataChannel, weDialed: boolean): void {
    if (e.link) return; // already bound (a renegotiation re-fired ondatachannel)
    e.link = new PeerLink({
      channel: new RtcChannel(dc),
      identity: this.opts.identity,
      sodium: this.opts.sodium,
      weDialed,
      expectPeerId: peerId, // PeerLink pins the far key to who signaling said it is
      onAuth: (pid, l) => this.promote(pid, l, e),
      onFrame: (pid, frame) => this.deliver(pid, frame),
      onClose: () => this.forget(peerId),
    });
  }

  private promote(peerId: PeerId, link: PeerLink, e: PeerEntry): void {
    // Final gate: even a peer that finished the WebRTC + PeerLink handshake is
    // dropped if it is not on the roster. Identity is now proven, so this is a
    // trustworthy decision.
    if (this.opts.admit && !this.opts.admit(peerId)) { link.close(); return; }
    e.authed = true;
    this.links.set(peerId, link);
    this.opts.onPeerUp?.(peerId);
  }

  private deliver(peerId: PeerId, frame: Uint8Array): void {
    if (!this.sink || peerId === this.ownId) return;
    this.framesDelivered++;
    this.sink(peerId, frame); // PeerLink only delivers post-auth, tagged with the authenticated id
  }

  private forget(peerId: PeerId): void {
    const had = this.links.delete(peerId);
    const e = this.peers.get(peerId);
    if (e) { try { e.pc.close(); } catch { /* ignore */ } this.peers.delete(peerId); }
    if (had) this.opts.onPeerDown?.(peerId);
  }

  // ── signaling handlers: hello / sdp / ice (perfect negotiation) ───────────────
  private async onSignal(msg: SignalMsg): Promise<void> {
    if (!msg || typeof msg !== "object") return;
    if (msg.from === this.ownId || (msg.to && msg.to !== this.ownId)) return;
    if (this.opts.admit && !this.opts.admit(msg.from)) return; // ignore off-roster peers
    try {
      if (msg.type === "hello") await this.onHello(msg);
      else if (msg.type === "sdp") await this.onSdp(msg);
      else if (msg.type === "ice") await this.onIce(msg);
    } catch { /* a malformed signal must not crash the network */ }
  }

  private async onHello(msg: SignalMsg): Promise<void> {
    const broadcast = !msg.to;
    // A speculative entry that never authenticated is a zombie; on a fresh
    // broadcast hello, replace it (the peer reloaded). Bound how many such
    // unauthenticated entries the relay can force us to hold.
    if (broadcast) {
      const existing = this.peers.get(msg.from);
      if (existing && !existing.authed) this.forget(msg.from);
      let unauthed = 0;
      for (const e of this.peers.values()) if (!e.authed) unauthed++;
      if (!this.peers.has(msg.from) && unauthed >= MAX_UNAUTHED_PEERS) return;
    }
    const e = this.ensurePeer(msg.from);
    // Reply to a broadcast once (directed), so the peer learns we're here; never
    // reply to a directed hello, or the two bounce forever.
    if (broadcast) this.opts.signaling.send({ type: "hello", from: this.ownId, to: msg.from });
    this.dialChannel(msg.from, e); // impolite side opens the channel
  }

  private async onSdp(msg: SignalMsg): Promise<void> {
    if (!msg.sdp) return;
    // Only an offer may create a peer; a stray answer for an unknown peer is dropped.
    const e = msg.sdp.type === "offer" ? this.ensurePeer(msg.from) : this.peers.get(msg.from);
    if (!e) return;
    // Glare: an offer arriving while we are also offering (or mid-renegotiation) is
    // a collision. The polite side yields (setRemoteDescription rolls back its own
    // offer implicitly); the impolite side ignores the incoming one.
    const collision = msg.sdp.type === "offer" && (e.makingOffer || e.pc.signalingState !== "stable");
    if (!e.polite && collision) return;
    await e.pc.setRemoteDescription(msg.sdp);
    for (const c of e.pendingIce.splice(0)) { try { await e.pc.addIceCandidate(c); } catch { /* stray post-rollback */ } }
    if (msg.sdp.type === "offer") {
      await e.pc.setLocalDescription();
      this.opts.signaling.send({ type: "sdp", from: this.ownId, to: msg.from, sdp: e.pc.localDescription ?? undefined });
    }
  }

  private async onIce(msg: SignalMsg): Promise<void> {
    const e = this.peers.get(msg.from);
    if (!e || !msg.candidate) return;
    // Candidates can arrive before the remote description is set; queue them until
    // setRemoteDescription has run, then flush (see onSdp).
    if (e.pc.remoteDescription) { try { await e.pc.addIceCandidate(msg.candidate); } catch { /* ignore */ } }
    else e.pendingIce.push(msg.candidate);
  }
}

// ── a Signaling over the relay WebSocket (scripts/relay.mjs) ───────────────────
// Connect to ws://host:port/<room>; the relay broadcasts every JSON frame to the
// other clients in the same room. Browser-native (uses the platform WebSocket).
export function relaySignaling(url: string): Signaling {
  const ws = new WebSocket(url);
  let cb: (m: SignalMsg) => void = () => {};
  const outbox: string[] = [];
  ws.addEventListener("open", () => { for (const s of outbox) ws.send(s); outbox.length = 0; });
  ws.addEventListener("message", (ev: MessageEvent) => {
    if (typeof ev.data !== "string") return;
    let m: SignalMsg;
    try { m = JSON.parse(ev.data); } catch { return; }
    cb(m);
  });
  return {
    send(msg) {
      const s = JSON.stringify(msg);
      if (ws.readyState === WebSocket.OPEN) ws.send(s); else outbox.push(s);
    },
    onMessage(fn) { cb = fn; },
    close() { try { ws.close(); } catch { /* ignore */ } },
  };
}
