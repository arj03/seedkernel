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
  /** Worst-case UTF-16 storage retained by queued or in-flight candidate strings. */
  pendingIceBytes: number;
  /** The one host-owned deadline every entry gets. An entry that has not both established
   *  AND bound its data channel when it fires is forgotten — two conditions rather than
   *  one, because either alone leaves a hole: a peer that never completes ICE is the
   *  speculative entry `admitNewPeer` counts, while a peer that completes ICE and then
   *  simply never opens a channel escapes that count (`established`) and has nothing else
   *  to reap it (`bindLink`'s channel watch never arms). */
  establishmentTimer: ReturnType<typeof setTimeout> | null;
}


export interface Signaling {
    /** Carry one opaque encoded negotiation message. A relay adapter transports this
     *  string verbatim; it never owns or interprets JavaScript message objects. */
    send(message: string): void;
    onMessage(cb: (message: string) => void): void;
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
    sdp: RTCSessionDescriptionInit & { type: "offer" | "answer"; sdp: string };
};
type IceSignal = SignalBase & {
    type: "ice";
    candidate: RTCIceCandidateInit & { candidate: string };
};
type SignalMsg = HelloSignal | SdpSignal | IceSignal;

/** Copy the platform description into the private signaling vocabulary. */
function sessionDescription(value: RTCSessionDescriptionInit | null): SdpSignal["sdp"] | undefined {
    if (!value || (value.type !== "offer" && value.type !== "answer")
        || typeof value.sdp !== "string") return undefined;
    return { type: value.type, sdp: value.sdp };
}

/** Conservative retained storage for candidate strings. JS engines may store strings as
 *  UTF-16, so charging two bytes per code unit avoids allocating an encoding just to
 *  measure untrusted signaling input and never understates its host-memory cost. */
function iceCandidateBytes(candidate: RTCIceCandidateInit): number {
    return utf16Bytes(candidate.candidate)
        + utf16Bytes(candidate.sdpMid)
        + utf16Bytes(candidate.usernameFragment);
}

function utf16Bytes(value: string | null | undefined): number {
    return value === undefined || value === null ? 0 : value.length * 2;
}

/** Retained storage for one decoded signal waiting on the lane, in the same currency. The
 *  peer ids are fixed-width but charged with the rest: what the queue holds is the whole
 *  message, and an owner that counts only the interesting field is an owner with a gap. */
function signalBytes(msg: SignalMsg): number {
    const ids = utf16Bytes(msg.from) + utf16Bytes(msg.to);
    if (msg.type === "sdp") return ids + utf16Bytes(msg.sdp.sdp);
    if (msg.type === "ice") return ids + iceCandidateBytes(msg.candidate);
    return ids;
}

// The private negotiation frame (§12.6), NUL-separated: tag | from | to-or-empty | payload,
// tags h/o/a/i, an absent ICE scalar empty. Not JSON — a relay broadcasts the string
// verbatim and parses nothing. NUL is outside SDP's and ICE's grammar, so a stray one can
// only change the field COUNT, which every branch below pins exactly: a malformed frame is
// refused, never reinterpreted as a different field.
function encodeSignal(msg: SignalMsg): string {
    const tag = msg.type === "hello" ? "h"
        : msg.type === "ice" ? "i"
        : msg.sdp.type === "offer" ? "o" : "a";
    const fields = [tag, msg.from, msg.to ?? ""];
    if (msg.type === "hello") return fields.join("\0");
    if (msg.type === "sdp") return [...fields, msg.sdp.sdp].join("\0");
    const c = msg.candidate;
    return [...fields, c.candidate, c.sdpMid ?? "", c.sdpMLineIndex?.toString() ?? "",
        c.usernameFragment ?? ""].join("\0");
}

/** Decode one private negotiation frame at the untrusted signaling boundary. */
function signalMsg(wire: string): SignalMsg | undefined {
    if (typeof wire !== "string" || wire.length > MAX_SIGNAL_CHARS)
        return undefined;
    const parts = wire.split("\0");
    if (parts.length < 3) return undefined;
    const [tag, from, directed] = parts;
    if (!isHex64(from) || (directed !== "" && !isHex64(directed))) return undefined;
    const base: SignalBase = directed === "" ? { from } : { from, to: directed };
    if (tag === "h") return parts.length === 3 ? { type: "hello", ...base } : undefined;
    if (tag === "o" || tag === "a") {
        const sdp = parts[3];
        return parts.length === 4 && sdp.length <= MAX_SDP_BYTES / 2
            ? { type: "sdp", ...base, sdp: { type: tag === "o" ? "offer" : "answer", sdp } }
            : undefined;
    }
    if (tag !== "i" || parts.length !== 7) return undefined;
    const line = parts[5] === "" ? undefined : Number(parts[5]);
    if (line !== undefined && (!Number.isInteger(line) || line < 0 || line > 0xffff
        || String(line) !== parts[5])) return undefined;
    const candidate: IceSignal["candidate"] = { candidate: parts[3] };
    if (parts[4] !== "") candidate.sdpMid = parts[4];
    if (line !== undefined) candidate.sdpMLineIndex = line;
    if (parts[6] !== "") candidate.usernameFragment = parts[6];
    return iceCandidateBytes(candidate) <= MAX_PENDING_ICE_BYTES
        ? { type: "ice", ...base, candidate } : undefined;
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
export const MAX_UNESTABLISHED_PEERS = 256;
/** Maximum retained UTF-16 storage for one inbound SDP string. */
export const MAX_SDP_BYTES = 256 * 1024;
/** Count and byte bounds for candidate work retained per peer. */
export const MAX_PENDING_ICE_CANDIDATES = 256;
export const MAX_PENDING_ICE_BYTES = 256 * 1024;
/** Refuse a frame by LENGTH before splitting it, so a relay cannot make us allocate the
 *  parts array first: the widest text either payload cap allows, plus this grammar's fixed
 *  overhead — tag, two peer ids, six separators, sdpMLineIndex's widest decimal. */
const MAX_SIGNAL_CHARS = Math.max(MAX_SDP_BYTES, MAX_PENDING_ICE_BYTES) / 2 + 1 + 64 + 64 + 5 + 6;
/** A relayed hello/offer that never becomes a live link cannot retain a peer forever. */
export const UNESTABLISHED_PEER_TTL_MS = 30_000;
/** Inbound signals waiting on the ordered lane, each retaining its decoded message. One
 *  relay carries every peer, so overflow DROPS the newcomer rather than tearing anything
 *  down: a dropped signal costs one redial, a failed channel costs every peer on it. */
export const MAX_QUEUED_SIGNALS = 256;
/** Byte companion to `MAX_QUEUED_SIGNALS`, in the same conservative UTF-16 currency as
 *  `iceCandidateBytes`. A count alone is half a bound here for the reason it is everywhere
 *  else in this runtime: the per-message caps above admit a 256 KiB offer, so 256 of them
 *  would make this lane the largest single allowance on the node. Sized for what a real
 *  rendezvous queues — a fleet's worth of few-KiB offers and answers — so the pairing bites
 *  only on the shape nobody sends honestly. Overflow drops the newcomer, as the count does. */
export const MAX_QUEUED_SIGNAL_BYTES = 4 * 1024 * 1024;
export class RtcNetwork implements ChannelFactory {
    opts;
    private readonly ownId: string;
    private onAccept: ((channel: RawLink, arrival?: Arrival) => void) | null = null;
    readonly peers = new Map<string, PeerEntry>(); // all (pre- and post-establish)
    private readonly makePc: (config?: RTCConfiguration) => RTCPeerConnection;
    /** One ordered lane for the signaling state machine. Promise-returning WebRTC methods
     *  may yield, but a later SDP/ICE message must not overtake the operation in flight. */
    private signalTail: Promise<void> = Promise.resolve();
    private queuedSignals = 0;
    private queuedSignalBytes = 0;
    private closed = false;
    constructor(opts: RtcNetworkOptions) {
        if (!isHex64(opts.peerId)) throw new Error("rtc: peerId must be 64 lowercase hex characters");
        this.opts = opts;
        this.ownId = opts.peerId;
        // Resolved once per network rather than per ensurePeer, so the browser global is
        // only touched where it exists.
        this.makePc = opts.peerConnectionFactory ?? ((cfg) => new RTCPeerConnection(cfg));
        opts.signaling.onMessage((m) => this.enqueueSignal(m));
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
        if (this.closed)
            return;
        this.closed = true;
        for (const peerId of [...this.peers.keys()]) this.forget(peerId);
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
        const e: PeerEntry = {
            pc, linked: false, established: false, polite: this.ownId > peerId,
            makingOffer: false, pendingIce: [], pendingIceBytes: 0, establishmentTimer: null,
        };
        this.peers.set(peerId, e);
        e.establishmentTimer = setTimeout(() => {
            if (this.peers.get(peerId) !== e) return;
            e.establishmentTimer = null; // it has fired; nothing left for forget() to clear
            if (!(e.established && e.linked)) this.forget(peerId);
        }, UNESTABLISHED_PEER_TTL_MS);
        // A speculative browser connection should expire, but the deadline alone must not
        // keep a Node console process alive.
        (e.establishmentTimer as ReturnType<typeof setTimeout> & { unref?: () => void }).unref?.();
        pc.addEventListener("icecandidate", (ev) => {
            const c = ev.candidate?.toJSON();
            if (this.peers.get(peerId) === e && typeof c?.candidate === "string")
                this.sendSignal({ type: "ice", from: this.ownId, to: peerId, candidate: {
                    candidate: c.candidate, sdpMid: c.sdpMid, sdpMLineIndex: c.sdpMLineIndex,
                    usernameFragment: c.usernameFragment,
                } });
        });
        pc.addEventListener("negotiationneeded", async () => {
            // Single entry point for offers — fires when the impolite side creates the
            // data channel. Implicit setLocalDescription() picks offer vs answer.
            try {
                if (this.peers.get(peerId) !== e)
                    return;
                e.makingOffer = true;
                await pc.setLocalDescription();
                const sdp = sessionDescription(pc.localDescription);
                if (this.peers.get(peerId) === e && sdp)
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
            if (this.peers.get(peerId) !== e)
                return;
            const s = pc.connectionState;
            if (s === "connected") {
                // A completed DTLS/ICE connection is no longer a speculative entry the
                // relay conjured for free (admitNewPeer). Whether the transport ABOVE it
                // authenticates is that guest's business from here — this file's watch
                // ends at the peer connection. The deadline is NOT cleared here: leaving
                // the cap is not the same as being a live link, and a connection that
                // establishes and then never carries a channel would otherwise have
                // nothing left to reap it. The one timer decides, once, on both facts.
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
                this.forget(peerId, e);
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
     *  That watch is what reaps a LINKED entry: the transport above tears an
     *  unauthenticated link down on its own deadline (`unverifiedTimeoutMs`), the driver
     *  closes the channel, and the entry goes with it. It says nothing about an entry that
     *  never got a channel — the polite side never opens one, so a peer that completes
     *  DTLS/ICE and then stays silent arms no watch here at all. That case is the
     *  entry's own `establishmentTimer`, which is why it survives establishment.
     *
     *  A channel with nowhere to go is not bound at all: the driver has not started its
     *  listeners yet, so the negotiation must be free to hand this peer over again rather
     *  than sit marked `linked` forever. */
    bindLink(peerId: string, e: PeerEntry, dc: RTCDataChannel, weDialed: boolean) {
        // A late event from a replaced connection, or a renegotiation that presents a
        // second channel, must not leak a live SCTP stream or bind it to the new entry.
        if (this.closed || this.peers.get(peerId) !== e || e.linked) {
            try { dc.close(); } catch { /* already gone */ }
            return;
        }
        const accept = this.onAccept;
        if (!accept) {
            try { dc.close(); } catch { /* ignore */ }
            return;
        }
        // One data channel per peer connection and it is never re-bound, so the channel
        // going away is terminal for this entry — exactly what the link's old onClose said.
        dc.addEventListener("close", () => this.forget(peerId, e));
        dc.addEventListener("error", () => this.forget(peerId, e));
        e.linked = true;
        // Signaling-created links have no listener; arrival records the selected dialer.
        accept(new RtcChannel(dc), { weDialed, expectPeerId: peerId });
    }
    forget(peerId: string, expected?: PeerEntry) {
        const e = this.peers.get(peerId);
        if (!e || (expected && e !== expected))
            return;
        if (e.establishmentTimer !== null) {
            clearTimeout(e.establishmentTimer);
            e.establishmentTimer = null;
        }
        e.pendingIce.length = 0;
        e.pendingIceBytes = 0;
        try {
            e.pc.close();
        }
        catch { /* ignore */ }
        this.peers.delete(peerId);
    }
    // ── signaling handlers: hello / sdp / ice (perfect negotiation) ───────────────
    private sendSignal(msg: SignalMsg): void {
        if (!this.closed)
            this.opts.signaling.send(encodeSignal(msg));
    }
    /** Append one inbound message to the signaling lane, bounded by `MAX_QUEUED_SIGNALS`:
     *  a lane is a queue, and a queue nobody counts is the hole this whole layer closes.
     *  Returning this promise is useful to synchronous/test adapters; production adapters
     *  may ignore it. Keep a recovered tail so one unexpected rejection cannot permanently
     *  poison the lane. */
    private enqueueSignal(wire: string): Promise<void> {
        // Decode synchronously so an adapter-owned string is never captured by
        // the promise lane while an earlier WebRTC operation is still in flight.
        let msg: SignalMsg | undefined;
        try { msg = signalMsg(wire); }
        catch { return Promise.resolve(); }
        if (!msg || this.closed || this.queuedSignals >= MAX_QUEUED_SIGNALS)
            return Promise.resolve();
        const bytes = signalBytes(msg);
        if (bytes > MAX_QUEUED_SIGNAL_BYTES - this.queuedSignalBytes)
            return Promise.resolve();
        this.queuedSignals++;
        this.queuedSignalBytes += bytes;
        const run = this.signalTail.then(() => {
            this.queuedSignals--;
            this.queuedSignalBytes -= bytes;
            return this.onSignal(msg);
        });
        this.signalTail = run.catch(() => { /* onSignal already contains the boundary */ });
        return run;
    }
    /** Act on one already-decoded signal. Decoding happens once, at the boundary above. */
    private async onSignal(msg: SignalMsg) {
        try {
            if (this.closed || msg.from === this.ownId || (msg.to && msg.to !== this.ownId))
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
        if (this.closed || this.peers.get(msg.from) !== e)
            return;
        await this.drainIce(msg.from, e);
        if (this.closed || this.peers.get(msg.from) !== e)
            return;
        if (msg.sdp.type === "offer") {
            await e.pc.setLocalDescription();
            const sdp = sessionDescription(e.pc.localDescription);
            if (this.peers.get(msg.from) === e && sdp)
                this.sendSignal({ type: "sdp", from: this.ownId, to: msg.from, sdp });
        }
    }
    private async onIce(msg: IceSignal) {
        const e = this.peers.get(msg.from);
        if (!e || !msg.candidate)
            return;
        // One queue for both phases: before SDP it waits, after SDP the lane below drains
        // it — so a direct caller cannot enter addIceCandidate outside the meter.
        const candidateBytes = iceCandidateBytes(msg.candidate);
        if (e.pendingIce.length >= MAX_PENDING_ICE_CANDIDATES
            || candidateBytes > MAX_PENDING_ICE_BYTES - e.pendingIceBytes) {
            // The sender has made this negotiation unusable; tear it down instead of
            // retaining an ever-growing pre-description or post-description backlog.
            this.forget(msg.from, e);
            return;
        }
        e.pendingIce.push(msg.candidate);
        e.pendingIceBytes += candidateBytes;
        if (e.pc.remoteDescription)
            await this.drainIce(msg.from, e);
    }
    /** Feed the queue to WebRTC oldest first, the candidate at index zero staying charged
     *  while the platform owns the in-flight promise. No lane of its own: every caller
     *  reaches here from `onSignal`, which the signaling lane already runs one at a time,
     *  so a second drain cannot begin while this one is between candidates. */
    private async drainIce(peerId: string, e: PeerEntry): Promise<void> {
        while (!this.closed && this.peers.get(peerId) === e
            && e.pc.remoteDescription && e.pendingIce.length > 0) {
            const candidate = e.pendingIce[0];
            const candidateBytes = iceCandidateBytes(candidate);
            try {
                await e.pc.addIceCandidate(candidate);
            }
            catch { /* stale after rollback, or rejected by the platform */ }
            // forget() may have cleared the queue while the platform operation yielded.
            if (e.pendingIce[0] === candidate) {
                e.pendingIce.shift();
                e.pendingIceBytes -= candidateBytes;
            }
        }
    }
}
