// The WebRTC socket seam (README §12.6): peers reach each other directly over
// RTCDataChannels, so the relay is only a signaling rendezvous and there is no server in
// the data path. This file manages RTCPeerConnections and signaling and hands each data
// channel to the driver's `openLink()`; everything above — the handshake, the record layer,
// the routing — is the transport bundle's, identical to the TCP path.
//
// Raw I/O only. Anything a peer connection can carry BESIDES bytes (live audio/video)
// belongs to the app, which subclasses RtcNetwork and works against the PeerEntry `pc`;
// media never enters the runtime.
//
// Identity is proved by the transport's AUTH challenge INSIDE the channel, not by an
// SDP-fingerprint assertion at the signaling layer: a MITM relay can splice SDP and bring
// up DTLS to itself, but it can never complete AUTH without the peer's private key, so the
// link never authenticates and never delivers a byte.
//
// Browser-native, but the globals are referenced only inside RtcNetwork / relaySignaling,
// so importing this under Node is safe — a console peer joins the same mesh with a
// werift-backed `peerConnectionFactory` (./net-rtc-node).
import { MessageChannel, SingleIdentityNetwork } from "./net-channel.js";
import { type PeerId } from "../core/socket-seam.js";
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
     *  and the peer lint; this file only manages connections. */
    driver: TransportHost;
    /** Resolve a peer's contact secret when dialing it. Signaling already names the
     *  peer, so it can carry the credential too. */
    peerContactFor?: (peerId: PeerId) => Uint8Array | undefined;
    signaling: Signaling;
    /** ICE servers (STUN/TURN). For LAN/localhost a public STUN list is enough. */
    rtcConfig?: RTCConfiguration;
    /** Factory for the underlying RTCPeerConnection. Defaults to the platform global; a
     *  Node/Bun console node passes a werift-backed one (./net-rtc-node) so this exact
     *  stack runs off-browser. */
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

// An RTCDataChannel is already an ordered, whole-message binary pipe, so this is a thin
// adapter over MessageChannel (net-channel.ts) — including its pre-open send buffer, which
// the transport needs because it emits its HELLO the instant a link is constructed.
export class RtcChannel extends MessageChannel {
  constructor(dc: RTCDataChannel) { super(dc); }
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
    join(): void { this.opts.signaling.send({ type: "hello", from: this.ownId }); }
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
            // Dialing gates on THEIR secret; accepting gates on ours (the driver's).
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
    async onSignal(msg: SignalMsg) {
        if (!msg || typeof msg !== "object")
            return;
        if (msg.from === this.ownId || (msg.to && msg.to !== this.ownId))
            return;
        if (this.opts.admitPeer && !this.opts.admitPeer(msg.from))
            return; // ignore peers outside the signaling allowlist
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
            this.opts.signaling.send({ type: "hello", from: this.ownId, to: msg.from });
        this.dialChannel(msg.from, e); // impolite side opens the channel
    }
    async onSdp(msg: SignalMsg) {
        if (!msg.sdp)
            return;
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
