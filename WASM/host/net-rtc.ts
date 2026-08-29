// The WebRTC socket seam (README §12.6): peers reach each other directly over
// RTCDataChannels, so the relay is only a signaling rendezvous and there is no server in
// the data path. This file manages RTCPeerConnections and signaling and hands each data
// channel to the driver as a `ChannelFactory`; everything above — the handshake, the
// record layer, the routing — is the transport bundle's, identical to the TCP path.
//
// Raw I/O only. Anything a peer connection can carry BESIDES bytes (live audio/video)
// belongs to the app, which subclasses RtcNetwork and works against the PeerEntry `pc`.
//
// Identity is proved by the transport's AUTH challenge INSIDE the channel, not by an
// SDP-fingerprint assertion: a MITM relay can splice SDP and bring up DTLS to itself, but it
// can never complete AUTH without the peer's private key, so the link never authenticates.
//
// Browser-native, but the platform globals are referenced only inside RtcNetwork, so importing
// this under Node is safe — a console peer joins the same mesh by passing its own
// `peerConnectionFactory`. Signaling is likewise supplied behind the seam below: the kernel
// owes the driver a byte duplex, not a particular ICE/DTLS stack or rendezvous protocol.
import { MessageChannel } from "./net-channel.js";
import { type Arrival, type ChannelFactory, type RawLink } from "../core/socket-seam.js";
import { isHex64 } from "../core/util.js";

/** One peer connection and everything the negotiation state machine hangs off it.
 *  Exported because it is the seam an app subclass works against — see the note on media
 *  above. */
export interface PeerEntry {
  pc: RTCPeerConnection;
  /** Whether this entry's data channel is already bound to a RawLink — guards against a
   *  renegotiation re-firing `ondatachannel` and handing the driver a second channel for
   *  the same peer. */
  linked: boolean;
  /** Whether the underlying peer connection has completed DTLS/ICE (`connectionState`
   *  reached "connected"). This is what `admitNewPeer`'s speculative-entry cap asks: a
   *  connection this far along cost a real handshake, not just a relayed `hello`, so it no
   *  longer counts against the cap — regardless of whether the transport above it has
   *  authenticated. */
  established: boolean;
  polite: boolean;
  makingOffer: boolean;
  pendingIce: RTCIceCandidateInit[];
}


export interface Signaling {
    send(msg: unknown): void;
    /** Deliver one implementation-defined inbound message. RtcNetwork owns decoding its
     *  private protocol; a signaling adapter need only transport opaque values. */
    onMessage(cb: (msg: unknown) => void): void;
    close(): void;
}

/** Every signaling message names its sender, and a directed one its recipient, by channel
 *  public key in lowercase hex — this file's own vocabulary. Nothing below it deals in
 *  peers: a socket seam takes destinations, not identities (core/socket-seam.ts). */
interface SignalBase {
    from: string;
    to?: string;
}

type HelloSignal = SignalBase & { type: "hello" };
type SdpSignal = SignalBase & {
    type: "sdp";
    sdp: RTCSessionDescriptionInit & { type: "offer" | "answer" };
};
type IceSignal = SignalBase & { type: "ice"; candidate: RTCIceCandidateInit };
type SignalMsg = HelloSignal | SdpSignal | IceSignal;

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSessionDescription(value: unknown): value is SdpSignal["sdp"] {
    return isRecord(value)
        && (value.type === "offer" || value.type === "answer")
        && typeof value.sdp === "string";
}

function isIceCandidate(value: unknown): value is RTCIceCandidateInit {
    if (!isRecord(value) || typeof value.candidate !== "string") return false;
    return (value.sdpMid === undefined || value.sdpMid === null || typeof value.sdpMid === "string")
        && (value.sdpMLineIndex === undefined || value.sdpMLineIndex === null
            || (typeof value.sdpMLineIndex === "number" && Number.isInteger(value.sdpMLineIndex)
                && value.sdpMLineIndex >= 0 && value.sdpMLineIndex <= 0xffff))
        && (value.usernameFragment === undefined || value.usernameFragment === null
            || typeof value.usernameFragment === "string");
}

/** Decode the kernel's private negotiation protocol at the untrusted signaling boundary. */
function signalMsg(value: unknown): SignalMsg | undefined {
    if (!isRecord(value) || typeof value.from !== "string" || !isHex64(value.from))
        return undefined;
    if (value.to !== undefined && (typeof value.to !== "string" || !isHex64(value.to)))
        return undefined;
    const base: SignalBase = value.to === undefined
        ? { from: value.from }
        : { from: value.from, to: value.to };
    if (value.type === "hello") return { type: "hello", ...base };
    if (value.type === "sdp" && isSessionDescription(value.sdp))
        return { type: "sdp", ...base, sdp: value.sdp };
    if (value.type === "ice" && isIceCandidate(value.candidate))
        return { type: "ice", ...base, candidate: value.candidate };
    return undefined;
}

export interface RtcNetworkOptions {
    /** This node's own channel public key, hex — the negotiation needs it for the
     *  polite/impolite tie-break and for its own `hello`s. Cannot come from a driver: this
     *  factory is constructed BEFORE the driver, since `bootShell` builds the
     *  `TransportHost` from `transport.channels`. */
    peerId: string;
    signaling: Signaling;
    /** ICE servers (STUN/TURN). For LAN/localhost a public STUN list is enough. */
    rtcConfig?: RTCConfiguration;
    /** Factory for the underlying RTCPeerConnection. Defaults to the platform global; a
     *  Node/Bun console node supplies its own (a pure-JS WebRTC library wrapped to the
     *  W3C surface used here) so this exact stack runs off-browser. */
    peerConnectionFactory?: (config?: RTCConfiguration) => RTCPeerConnection;
    /** Optional peer allowlist, applied to SIGNALING messages. Absent (the default)
     *  admits every peer to the rendezvous; the in-channel peer lint (the
     *  driver's, run on a signature-verified id) is separate and always on. */
    admitPeer?: (peerId: string) => boolean;
}

// Keep physical data-channel messages below the conservative cross-browser ceiling while
// exposing an ordered byte stream to the transport. Its existing bounded length framer
// restores record boundaries, so storage can coalesce several blocks per encrypted record
// without asking WebRTC to carry that record as one message.
export const RTC_CHUNK_BYTES = 48 * 1024;
export class RtcChannel extends MessageChannel {
  /** Exposes chunked RTC messages as a byte stream, preserving large writes. */
  readonly stream = true;
  constructor(dc: RTCDataChannel) { super(dc); }
  protected override write(bytes: Uint8Array): void {
    for (let off = 0; off < bytes.length; off += RTC_CHUNK_BYTES) {
      super.write(bytes.subarray(off, Math.min(bytes.length, off + RTC_CHUNK_BYTES)));
    }
  }
}
// Cap on speculative peer entries the relay can force us to allocate by spamming `hello`s
// with arbitrary `from` values. An entry stops being speculative once its peer connection
// establishes (PeerEntry.established) — that cost a real DTLS/ICE handshake, not just a
// relayed `hello` — so a genuine fleet is unconstrained. What keeps the escaped side of
// that line bounded is `bindLink`'s channel watch: an entry that establishes but never
// carries an authenticated link loses its data channel to the transport's own deadline,
// and the entry with it.
const MAX_UNESTABLISHED_PEERS = 256;
export class RtcNetwork implements ChannelFactory {
    opts;
    private readonly ownId: string;
    private onAccept: ((channel: RawLink, arrival?: Arrival) => void) | null = null;
    readonly peers = new Map<string, PeerEntry>(); // all (pre- and post-establish)
    private readonly makePc: (config?: RTCConfiguration) => RTCPeerConnection;
    constructor(opts: RtcNetworkOptions) {
        this.opts = opts;
        this.ownId = opts.peerId;
        // Resolved once per network rather than per ensurePeer, so the browser global is
        // only touched where it exists.
        this.makePc = opts.peerConnectionFactory ?? ((cfg) => new RTCPeerConnection(cfg));
        opts.signaling.onMessage((m) => this.onSignal(m));
    }
    // ── ChannelFactory interface ─────────────────────────────────────────────────
    /** A browser binds no port; every RTC link arrives through signaling. `connect` is
     *  deliberately absent (socket-seam.ts `ChannelFactory`): RTC peers come from
     *  signaling, never from an address. */
    async listen(
        _tcp: { host: string; port: number } | undefined,
        _ws: { host: string; port: number } | undefined,
        onAccept: (channel: RawLink, arrival?: Arrival) => void,
    ): Promise<{ port: number; wsPort: number }> {
        this.onAccept = onAccept;
        return { port: 0, wsPort: 0 };
    }
    // ── Network interface ────────────────────────────────────────────────────────
    /** Announce ourselves into the room so present peers begin the WebRTC dance.
     *  Call once after registering the sink (or constructing a StorageNode/Transport
     *  over this network). */
    join(): void { this.sendSignal({ type: "hello", from: this.ownId }); }
    /** Tear down every connection and the signaling channel. The transport's links
     *  die with their channels. */
    close(): void {
        for (const e of this.peers.values()) {
            try {
                e.pc.close();
            }
            catch { /* ignore */ }
        }
        this.peers.clear();
        this.opts.signaling.close();
    }
    // ── per-peer connection (perfect negotiation) ───────────────────────────────────
    /** Whether a NEW (not yet established) peer entry may be created. The relay can force
     *  speculative entries by naming arbitrary peers in hellos AND in offers, so every path
     *  that would CREATE one answers to the same cap. */
    private admitNewPeer(): boolean {
        let unestablished = 0;
        for (const e of this.peers.values()) if (!e.established) unestablished++;
        return unestablished < MAX_UNESTABLISHED_PEERS;
    }
    ensurePeer(peerId: string): PeerEntry {
        const existing = this.peers.get(peerId);
        if (existing)
            return existing;
        const pc = this.makePc(this.opts.rtcConfig);
        const e: PeerEntry = { pc, linked: false, established: false, polite: this.ownId > peerId, makingOffer: false, pendingIce: [] };
        this.peers.set(peerId, e);
        pc.addEventListener("icecandidate", (ev) => {
            if (ev.candidate)
                this.sendSignal({ type: "ice", from: this.ownId, to: peerId, candidate: ev.candidate.toJSON() });
        });
        pc.addEventListener("negotiationneeded", async () => {
            // Single entry point for offers — fires when the impolite side creates the
            // data channel. Implicit setLocalDescription() picks offer vs answer.
            try {
                e.makingOffer = true;
                await pc.setLocalDescription();
                const sdp = pc.localDescription;
                if (isSessionDescription(sdp))
                    this.sendSignal({ type: "sdp", from: this.ownId, to: peerId, sdp });
            }
            catch { /* renegotiation failed; ICE restart / next hello recovers */ }
            finally {
                e.makingOffer = false;
            }
        });
        // The polite side receives the channel the impolite side opened.
        pc.addEventListener("datachannel", (ev) => this.bindLink(peerId, e, ev.channel, /*weDialed*/ false));
        pc.addEventListener("connectionstatechange", () => {
            const s = pc.connectionState;
            if (s === "connected") {
                // A completed DTLS/ICE connection is no longer a speculative entry the
                // relay conjured for free (admitNewPeer). Whether the transport ABOVE it
                // authenticates is that guest's business from here — this file's watch
                // ends at the peer connection.
                e.established = true;
            }
            else if (s === "disconnected") {
                // A transient path failure (network blip, NAT rebind): restartIce()
                // schedules negotiationneeded with fresh credentials and the link recovers
                // without a teardown. Only "failed"/"closed" are terminal.
                try {
                    pc.restartIce();
                }
                catch { /* nothing to restart */ }
            }
            else if (s === "failed" || s === "closed") {
                this.forget(peerId);
            }
        });
        return e;
    }
    // The impolite side opens the single ordered binary channel; the polite side gets
    // it via ondatachannel. Exactly one channel per pair, so there is no double-
    // connect to resolve (unlike TCP's dial race).
    dialChannel(peerId: string, e: PeerEntry) {
        if (e.polite || e.linked)
            return;
        this.bindLink(peerId, e, e.pc.createDataChannel("seedkernel", { ordered: true }), /*weDialed*/ true);
    }
    /** Hand the data channel to the driver as a RawLink. The link's fate — whether it
     *  authenticates, and when it dies — is entirely the transport guest's from here; what
     *  this file still owns is the CHANNEL, so it watches the one event that says the
     *  channel is gone.
     *
     *  That watch is what bounds the entry table. A `hello` costs a peer connection, and
     *  `admitNewPeer` stops counting an entry once DTLS/ICE establishes — cheap enough that
     *  a relay naming fabricated peers could otherwise allocate without limit. It cannot,
     *  because the transport above tears an unauthenticated link down on its own deadline
     *  (`unverifiedTimeoutMs`), the driver closes the channel, and the entry goes with it.
     *
     *  A channel with nowhere to go is not bound at all: the driver has not started its
     *  listeners yet, so the negotiation must be free to hand this peer over again rather
     *  than sit marked `linked` forever. */
    bindLink(peerId: string, e: PeerEntry, dc: RTCDataChannel, weDialed: boolean) {
        if (e.linked)
            return; // already bound (a renegotiation re-fired ondatachannel)
        const accept = this.onAccept;
        if (!accept) {
            try { dc.close(); } catch { /* ignore */ }
            return;
        }
        // One data channel per peer connection and it is never re-bound, so the channel
        // going away is terminal for this entry — exactly what the link's old onClose said.
        dc.addEventListener("close", () => this.forget(peerId));
        dc.addEventListener("error", () => this.forget(peerId));
        e.linked = true;
        // Signaling-created links have no listener; arrival records the selected dialer.
        accept(new RtcChannel(dc), { weDialed, expectPeerId: peerId });
    }
    forget(peerId: string) {
        const e = this.peers.get(peerId);
        if (!e)
            return;
        try {
            e.pc.close();
        }
        catch { /* ignore */ }
        this.peers.delete(peerId);
    }
    // ── signaling handlers: hello / sdp / ice (perfect negotiation) ───────────────
    private sendSignal(msg: SignalMsg): void { this.opts.signaling.send(msg); }
    private async onSignal(value: unknown) {
        try {
            const msg = signalMsg(value);
            if (!msg || msg.from === this.ownId || (msg.to && msg.to !== this.ownId))
                return;
            if (this.opts.admitPeer && !this.opts.admitPeer(msg.from))
                return; // ignore peers outside the signaling allowlist
            if (msg.type === "hello")
                await this.onHello(msg);
            else if (msg.type === "sdp")
                await this.onSdp(msg);
            else if (msg.type === "ice")
                await this.onIce(msg);
        }
        catch { /* a malformed signal must not crash the network */ }
    }
    private async onHello(msg: HelloSignal) {
        const broadcast = !msg.to;
        // A speculative entry that never established is a zombie; a fresh broadcast
        // hello means the peer reloaded, so replace it.
        if (broadcast) {
            const existing = this.peers.get(msg.from);
            if (existing && !existing.established)
                this.forget(msg.from);
        }
        // The cap is on CREATION, whatever shape the hello took: a directed hello
        // names us too, so it can spam a slot just as well as a broadcast one.
        if (!this.peers.has(msg.from) && !this.admitNewPeer())
            return;
        const e = this.ensurePeer(msg.from);
        // Reply to a broadcast once (directed), so the peer learns we're here; never
        // reply to a directed hello, or the two bounce forever.
        if (broadcast)
            this.sendSignal({ type: "hello", from: this.ownId, to: msg.from });
        this.dialChannel(msg.from, e); // impolite side opens the channel
    }
    private async onSdp(msg: SdpSignal) {
        // Only an offer may create a peer; a stray answer for an unknown one is dropped.
        // An offer clears the same speculative-entry cap a hello does — the relay can name
        // arbitrary `from` values in offers too, and each entry costs a connection.
        const e = msg.sdp.type === "offer"
            ? (this.peers.get(msg.from) ?? (this.admitNewPeer() ? this.ensurePeer(msg.from) : undefined))
            : this.peers.get(msg.from);
        if (!e)
            return;
        // Glare: an offer arriving while we are also offering (or mid-renegotiation) is
        // a collision. The polite side yields (setRemoteDescription rolls back its own
        // offer implicitly); the impolite side ignores the incoming one.
        const collision = msg.sdp.type === "offer" && (e.makingOffer || e.pc.signalingState !== "stable");
        if (!e.polite && collision)
            return;
        await e.pc.setRemoteDescription(msg.sdp);
        for (const c of e.pendingIce.splice(0)) {
            try {
                await e.pc.addIceCandidate(c);
            }
            catch { /* stray post-rollback */ }
        }
        if (msg.sdp.type === "offer") {
            await e.pc.setLocalDescription();
            const sdp = e.pc.localDescription;
            if (isSessionDescription(sdp))
                this.sendSignal({ type: "sdp", from: this.ownId, to: msg.from, sdp });
        }
    }
    private async onIce(msg: IceSignal) {
        const e = this.peers.get(msg.from);
        if (!e || !msg.candidate)
            return;
        // Candidates can arrive before the remote description is set; queue them until
        // setRemoteDescription has run, then flush (see onSdp).
        if (e.pc.remoteDescription) {
            try {
                await e.pc.addIceCandidate(msg.candidate);
            }
            catch { /* ignore */ }
        }
        else
            e.pendingIce.push(msg.candidate);
    }
}
