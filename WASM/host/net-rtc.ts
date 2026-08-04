// WebRTC as a first-class Network (README §12.6: net.send is "addressed unicast
// to a peer over its data channel"). This is the real-P2P fabric: peers reach each
// other directly over RTCDataChannels — the relay is only a signaling rendezvous
// and can be killed once channels are up — so there is no server in the data path.
//
// The transport itself — the identity handshake, the record layer, the routing —
// runs in the transport bundle's guest program, driven by the shared TransportHost
// (transport-host.ts). This file is what remains of the old RtcNetwork: the
// WebRTC socket seam. It manages RTCPeerConnections and signaling; each data
// channel is handed to the driver's openLink(), and everything above is the
// bundle's, identical to the TCP path with only the bottom swapped.
//
// Identity: the transport runs its HELLO/AUTH challenge *inside* the channel,
// proving each end holds the kernel private key for the pubkey it claims. That
// subsumes the SDP-fingerprint signing chat-shell.js does at the signaling layer —
// and is stronger, because it is continuous channel binding rather than a one-shot
// SDP assertion: a MITM relay can splice SDP and bring up DTLS to itself, but it
// can never complete AUTH without the peer's private key, so the link never
// authenticates and never delivers a byte.
//
// This module is browser-native (it uses the platform RTCPeerConnection /
// RTCDataChannel / WebSocket). A Node/Bun console peer joins the same mesh by
// passing a werift-backed `peerConnectionFactory` (./net-rtc-node
// `weriftPeerConnectionFactory`) behind the same RtcChannel / Signaling —
// everything above the channel is untouched, the same "swap the connection, keep
// the stack" move net-node.ts documents for the engine build. The browser globals
// are referenced only inside RtcNetwork / relaySignaling, never at module scope,
// so importing this module under Node (e.g. to unit-test RtcChannel) is safe.
import { MessageChannel, SingleIdentityNetwork } from "./net-channel.js";
import { type PeerId } from "../core/net.js";
import type { TransportHost, LinkHandle } from "./transport-host.js";

/** One peer connection and everything the negotiation state machine hangs off it. */
interface PeerEntry {
  pc: RTCPeerConnection;
  link: LinkHandle | null;
  authed: boolean;
  polite: boolean;
  makingOffer: boolean;
  pendingIce: RTCIceCandidateInit[];
  callSenders: RTCRtpSender[] | null;
}


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
    /** The transport driver — the shell's `net` once the transport bundle is
     *  admitted. It holds the node identity, the network key, the contact secret
     *  and the whitelist gate; this file only manages connections. */
    driver: TransportHost;
    /** Resolve a peer's contact secret when dialing it. Signaling already names the
     *  peer, so it can carry the credential too. */
    peerContactFor?: (peerId: PeerId) => Uint8Array | undefined;
    signaling: Signaling;
    /** ICE servers (STUN/TURN). For LAN/localhost a public STUN list is enough. */
    rtcConfig?: RTCConfiguration;
    /** Factory for the underlying RTCPeerConnection. Defaults to the platform
     *  global, which is what a browser tab uses. A Node/Bun *console* node passes a
     *  werift-backed factory (./net-rtc-node `weriftPeerConnectionFactory`) so this
     *  exact stack runs off-browser — "swap the connection, keep the stack", the
     *  same move net-node.ts documents for TCP. Referenced only inside ensurePeer(),
     *  never at module scope, so importing this module under Node without a factory
     *  stays safe. */
    peerConnectionFactory?: (config?: RTCConfiguration) => RTCPeerConnection;
    /** Optional peer whitelist, applied to SIGNALING messages. Absent (the default)
     *  admits every peer to the rendezvous; the in-channel whitelist gate (the
     *  driver's, run on a signature-verified id) is separate and always on. */
    admitPeer?: (peerId: PeerId) => boolean;
    /** Called when a peer's link authenticates / drops. The storage demo uses these
     *  to mirror the live mesh into a StorageNode's cohort (addPeer/removePeer). */
    onPeerUp?: (peerId: PeerId) => void;
    onPeerDown?: (peerId: PeerId) => void;
    /** A remote media track arrived from a peer. Audio/video calls ride the same
     *  RTCPeerConnection as the data channel, so an app that wants live media (the
     *  chat demo's call feature) supplies this and attaches the track to a per-peer
     *  tile; an app that only moves bytes omits it and never negotiates media. */
    onTrack?: (peerId: PeerId, track: MediaStreamTrack) => void;
}

// ── RawLink over one RTCDataChannel ────────────────────────────────────────
// An RTCDataChannel is already an ordered, whole-message binary pipe (WebRTC does
// framing + ordering), so this is a thin adapter over MessageChannel (net-channel.ts) —
// with the same pre-open send buffer the transport needs because it emits its HELLO
// the instant a link is constructed.
export class RtcChannel extends MessageChannel {
  constructor(dc: RTCDataChannel) { super(dc); }
}
// Cap on speculative (unauthenticated) peer entries the relay can force us to
// allocate by spamming `hello`s with arbitrary `from` values. Authenticated peers
// do not count, so genuine fleet size is unconstrained (mirrors chat-shell.js's
// MAX_UNAUTHED_PEERS). 256 is comfortable headroom for a churn storm.
const MAX_UNAUTHED_PEERS = 256;
export class RtcNetwork extends SingleIdentityNetwork {
    opts;
    readonly peers = new Map<PeerId, PeerEntry>(); // all (pre- and post-auth)
    private readonly makePc: (config?: RTCConfiguration) => RTCPeerConnection;
    // Local media tracks to publish to every peer (now and as new ones connect).
    // Empty unless the app started a call via addLocalTrack().
    private readonly localTracks: { track: MediaStreamTrack; stream: MediaStream }[] = [];
    constructor(opts: RtcNetworkOptions) {
        super(opts.driver, { onPeerUp: opts.onPeerUp, onPeerDown: opts.onPeerDown });
        this.opts = opts;
        // The peer-connection factory is fixed per network; defaulting to the platform
        // global here (not per ensurePeer) keeps a browser tab's RTCPeerConnection the
        // default and a werift-backed one the Node/Bun path.
        this.makePc = opts.peerConnectionFactory ?? ((cfg) => new RTCPeerConnection(cfg));
        // Cohort edges come from the driver's router (the transport bundle's).
        opts.signaling.onMessage((m) => this.onSignal(m));
    }
    // ── Network interface ────────────────────────────────────────────────────────
    /** Announce ourselves into the room so present peers begin the WebRTC dance.
     *  Call once after registering the sink (or constructing a StorageNode/Transport
     *  over this network). */
    join(): void { this.opts.signaling.send({ type: "hello", from: this.ownId }); }
    // ── live media (audio/video) ──────────────────────────────────────────────────
    // Calls ride the same RTCPeerConnections as the data channel. addTrack triggers
    // negotiationneeded, and the offer it produces flows through the same perfect-
    // negotiation path the data channel uses — no separate signaling.
    /** Publish a local track to every connected peer, and to any peer that connects
     *  later (the track set is remembered until removeLocalTracks()). Idempotent per
     *  (peer, track), so adding audio then video is two safe calls. */
    addLocalTrack(track: MediaStreamTrack, stream: MediaStream): void {
        this.localTracks.push({ track, stream });
        for (const e of this.peers.values())
            this.addLocalTracksTo(e);
    }
    /** Stop publishing media (hang up): remove every track we added and forget the
     *  set, so future peers get no media. Renegotiation happens automatically. */
    removeLocalTracks(): void {
        this.localTracks.length = 0;
        for (const e of this.peers.values()) {
            if (!e.callSenders)
                continue;
            for (const sender of e.callSenders) {
                try {
                    e.pc.removeTrack(sender);
                }
                catch { /* already gone */ }
            }
            e.callSenders = null;
        }
    }
    // Add any not-yet-published local tracks to one connected peer. Skips peers that
    // are not yet "connected" (a track added mid-handshake fights perfect negotiation);
    // the connectionstatechange handler calls back here when they reach "connected".
    addLocalTracksTo(e: PeerEntry) {
        if (this.localTracks.length === 0 || e.pc.connectionState !== "connected")
            return;
        if (!e.callSenders)
            e.callSenders = [];
        for (const { track, stream } of this.localTracks) {
            if (e.callSenders.some((s: RTCRtpSender) => s.track === track))
                continue; // already on this pc
            try {
                e.callSenders.push(e.pc.addTrack(track, stream));
            }
            catch { /* ignore */ }
        }
    }
    /** Kick an ICE restart on every peer. Call on a network-change event (the browser
     *  going online, an interface flip) so recovery starts at once instead of waiting
     *  out ICE keepalive timeouts. Each restart's offer rides the signaling channel —
     *  so the relay must still be reachable for this to complete. */
    restartAllIce(): void {
        for (const e of this.peers.values()) {
            try {
                e.pc.restartIce();
            }
            catch { /* ignore */ }
        }
    }
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
    // ── per-peer connection (perfect negotiation, adapted from chat-shell.js) ─────
    ensurePeer(peerId: PeerId) {
        const existing = this.peers.get(peerId);
        if (existing)
            return existing;
        const pc = this.makePc(this.opts.rtcConfig);
        const e = { pc, link: null, authed: false, polite: this.ownId > peerId, makingOffer: false, pendingIce: [] as RTCIceCandidateInit[], callSenders: null };
        this.peers.set(peerId, e);
        pc.addEventListener("icecandidate", (ev) => {
            if (ev.candidate)
                this.opts.signaling.send({ type: "ice", from: this.ownId, to: peerId, candidate: ev.candidate.toJSON() });
        });
        pc.addEventListener("negotiationneeded", async () => {
            // Single entry point for offers — fires when the impolite side creates the
            // data channel. Implicit setLocalDescription() picks offer vs answer.
            try {
                e.makingOffer = true;
                await pc.setLocalDescription();
                this.opts.signaling.send({ type: "sdp", from: this.ownId, to: peerId, sdp: pc.localDescription ?? undefined });
            }
            catch { /* renegotiation failed; ICE restart / next hello recovers */ }
            finally {
                e.makingOffer = false;
            }
        });
        // The polite side receives the channel the impolite side opened.
        pc.addEventListener("datachannel", (ev) => this.bindLink(peerId, e, ev.channel, /*weDialed*/ false));
        // A remote track means the peer is sending us media; hand it to the app.
        pc.addEventListener("track", (ev) => this.opts.onTrack?.(peerId, ev.track));
        pc.addEventListener("connectionstatechange", () => {
            const s = pc.connectionState;
            if (s === "connected") {
                // Publish any in-progress call tracks to a peer that just finished its
                // handshake. Doing it here (not at ensurePeer time) keeps clear of the
                // perfect-negotiation window — the renegotiation offer rides cleanly.
                this.addLocalTracksTo(e);
            }
            else if (s === "disconnected") {
                // A transient path failure (network blip, NAT rebind). restartIce()
                // schedules negotiationneeded with fresh ICE credentials; the existing
                // handler ships the offer over signaling and the link recovers without
                // a full teardown. Only "failed"/"closed" are terminal.
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
            // Dialing gates on THEIR secret; accepting gates on ours (the driver's).
            contactSecret: weDialed ? this.opts.peerContactFor?.(peerId) : undefined,
            expectPeerId: peerId, // the transport pins the far key to who signaling said it is
            onAuth: () => { e.authed = true; },
            onClose: () => this.forget(peerId),
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
    async onSignal(msg: SignalMsg) {
        if (!msg || typeof msg !== "object")
            return;
        if (msg.from === this.ownId || (msg.to && msg.to !== this.ownId))
            return;
        if (this.opts.admitPeer && !this.opts.admitPeer(msg.from))
            return; // ignore non-whitelisted peers
        try {
            if (msg.type === "hello")
                await this.onHello(msg);
            else if (msg.type === "sdp")
                await this.onSdp(msg);
            else if (msg.type === "ice")
                await this.onIce(msg);
        }
        catch { /* a malformed signal must not crash the network */ }
    }
    async onHello(msg: SignalMsg) {
        const broadcast = !msg.to;
        // A speculative entry that never authenticated is a zombie; on a fresh
        // broadcast hello, replace it (the peer reloaded). Bound how many such
        // unauthenticated entries the relay can force us to hold.
        if (broadcast) {
            const existing = this.peers.get(msg.from);
            if (existing && !existing.authed)
                this.forget(msg.from);
            let unauthed = 0;
            for (const e of this.peers.values())
                if (!e.authed)
                    unauthed++;
            if (!this.peers.has(msg.from) && unauthed >= MAX_UNAUTHED_PEERS)
                return;
        }
        const e = this.ensurePeer(msg.from);
        // Reply to a broadcast once (directed), so the peer learns we're here; never
        // reply to a directed hello, or the two bounce forever.
        if (broadcast)
            this.opts.signaling.send({ type: "hello", from: this.ownId, to: msg.from });
        this.dialChannel(msg.from, e); // impolite side opens the channel
    }
    async onSdp(msg: SignalMsg) {
        if (!msg.sdp)
            return;
        // Only an offer may create a peer; a stray answer for an unknown peer is dropped.
        const e = msg.sdp.type === "offer" ? this.ensurePeer(msg.from) : this.peers.get(msg.from);
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
            this.opts.signaling.send({ type: "sdp", from: this.ownId, to: msg.from, sdp: e.pc.localDescription ?? undefined });
        }
    }
    async onIce(msg: SignalMsg) {
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
// ── a Signaling over the relay WebSocket (seedchat's scripts/relay.mjs) ────────
// Connect to ws://host:port/<room>; the relay broadcasts every JSON frame to the
// other clients in the same room. Browser-native (uses the platform WebSocket).
export function relaySignaling(url: string): Signaling {
    const ws = new WebSocket(url);
    let cb: (msg: SignalMsg) => void = () => { };
    const outbox: string[] = [];
    ws.addEventListener("open", () => { for (const s of outbox)
        ws.send(s); outbox.length = 0; });
    ws.addEventListener("message", (ev) => {
        if (typeof ev.data !== "string")
            return;
        let m;
        try {
            m = JSON.parse(ev.data);
        }
        catch {
            return;
        }
        cb(m);
    });
    return {
        send(msg: unknown) {
            const s = JSON.stringify(msg);
            if (ws.readyState === WebSocket.OPEN)
                ws.send(s);
            else
                outbox.push(s);
        },
        onMessage(fn: (msg: SignalMsg) => void) { cb = fn; },
        close() { try {
            ws.close();
        }
        catch { /* ignore */ } },
    };
}
