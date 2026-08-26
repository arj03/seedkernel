// The WebRTC socket seam (README §12.6): peers reach each other directly over
// RTCDataChannels, so the relay is only a signaling rendezvous and there is no server in
// the data path. This file manages RTCPeerConnections and signaling and hands each data
// channel to the driver's `openLink()`; everything above — the handshake, the record layer,
// the routing — is the transport bundle's, identical to the TCP path.
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
// owes openLink a byte duplex, not a particular ICE/DTLS stack or rendezvous protocol.
import { MessageChannel, SingleIdentityNetwork } from "./net-channel.js";
import { FRAMING, type PeerId } from "../core/socket-seam.js";
import { isHex64 } from "../core/util.js";
import type { TransportHost, LinkHandle } from "./transport-host.js";

/** One peer connection and everything the negotiation state machine hangs off it.
 *  Exported because it is the seam an app subclass works against — see the note on media
 *  above. */
export interface PeerEntry {
  pc: RTCPeerConnection;
  link: LinkHandle | null;
  authed: boolean;
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

interface SignalBase {
    from: PeerId;
    to?: PeerId;
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
    /** The platform's concrete channel adapter. It holds the node identity, the network
     *  key, the contact secret and the peer lint; this file only manages connections. */
    driver: TransportHost;
    /** Resolve a peer's contact secret when dialing it. Signaling already names the
     *  peer, so it can carry the credential too. */
    peerContactFor?: (peerId: PeerId) => Uint8Array | undefined;
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
    admitPeer?: (peerId: PeerId) => boolean;
    /** Called when a peer's link authenticates / drops. The storage demo uses these
     *  to mirror the live mesh into a StorageNode's cohort (addPeer/removePeer). */
    onPeerUp?: (peerId: PeerId) => void;
    onPeerDown?: (peerId: PeerId) => void;
}

// Keep physical data-channel messages below the conservative cross-browser ceiling while
// exposing an ordered byte stream to the transport. Its existing bounded length framer
// restores record boundaries, so storage can coalesce several blocks per encrypted record
// without asking WebRTC to carry that record as one message.
export const RTC_CHUNK_BYTES = 48 * 1024;
export class RtcChannel extends MessageChannel {
  override readonly framing = FRAMING.LENGTH;
  constructor(dc: RTCDataChannel) { super(dc); }
  protected override write(bytes: Uint8Array): void {
    for (let off = 0; off < bytes.length; off += RTC_CHUNK_BYTES) {
      super.write(bytes.subarray(off, Math.min(bytes.length, off + RTC_CHUNK_BYTES)));
    }
  }
}
// Cap on speculative (unauthenticated) peer entries the relay can force us to allocate by
// spamming `hello`s with arbitrary `from` values. Authenticated peers do not count, so a
// genuine fleet is unconstrained.
const MAX_UNAUTHED_PEERS = 256;
export class RtcNetwork extends SingleIdentityNetwork {
    opts;
    readonly peers = new Map<PeerId, PeerEntry>(); // all (pre- and post-auth)
    private readonly makePc: (config?: RTCConfiguration) => RTCPeerConnection;
    constructor(opts: RtcNetworkOptions) {
        super(opts.driver, { onPeerUp: opts.onPeerUp, onPeerDown: opts.onPeerDown });
        this.opts = opts;
        // Resolved once per network rather than per ensurePeer, so the browser global is
        // only touched where it exists.
        this.makePc = opts.peerConnectionFactory ?? ((cfg) => new RTCPeerConnection(cfg));
        opts.signaling.onMessage((m) => this.onSignal(m));
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
    /** Whether a NEW (pre-auth) peer entry may be created. The relay can force speculative
     *  entries by naming arbitrary peers in hellos AND in offers, so every path that would
     *  CREATE one answers to the same cap. */
    private admitNewPeer(): boolean {
        let unauthed = 0;
        for (const e of this.peers.values()) if (!e.authed) unauthed++;
        return unauthed < MAX_UNAUTHED_PEERS;
    }
    ensurePeer(peerId: PeerId): PeerEntry {
        const existing = this.peers.get(peerId);
        if (existing)
            return existing;
        const pc = this.makePc(this.opts.rtcConfig);
        const e: PeerEntry = { pc, link: null, authed: false, polite: this.ownId > peerId, makingOffer: false, pendingIce: [] };
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
            if (s === "disconnected") {
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
    dialChannel(peerId: PeerId, e: PeerEntry) {
        if (e.polite || e.link)
            return;
        this.bindLink(peerId, e, e.pc.createDataChannel("seedkernel", { ordered: true }), /*weDialed*/ true);
    }
    bindLink(peerId: PeerId, e: PeerEntry, dc: RTCDataChannel, weDialed: boolean) {
        if (e.link)
            return; // already bound (a renegotiation re-fired ondatachannel)
        const handle = this.driver.openLink({
            channel: new RtcChannel(dc),
            weDialed,
            // Dialing gates on THEIR secret; accepting gates on OURS — and the driver
            // seals an accept by itself, reading its contact secret at announce time, so
            // nothing is supplied here for a link we did not dial.
            contactSecret: weDialed ? this.opts.peerContactFor?.(peerId) : undefined,
            expectPeerId: peerId, // the transport pins the far key to who signaling said it is
            onAuth: () => { e.authed = true; this.peerUp(peerId); },
            onClose: () => { this.peerDown(peerId); this.forget(peerId); },
        });
        e.link = handle;
    }
    forget(peerId: PeerId) {
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
        // A speculative entry that never authenticated is a zombie; a fresh broadcast
        // hello means the peer reloaded, so replace it.
        if (broadcast) {
            const existing = this.peers.get(msg.from);
            if (existing && !existing.authed)
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
