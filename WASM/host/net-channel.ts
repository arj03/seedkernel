// net-channel.ts — shared plumbing for the host socket adapters. Two families of
// duplication live here once:
//
// 1. RawLink adapters over an already-ordered binary transport: WsChannel (net-ws,
//    a browser WebSocket) and RtcChannel (net-rtc, an RTCDataChannel). Every one of
//    them delivers whole messages, so this base is FRAMING.PLATFORM; a byte duplex
//    (a raw socket, handed to the transport bundle to frame itself) has no boundaries
//    to buffer per message and does not come through here.
//    The onData/onClose sinks, the `dead` flag, the pre-open send buffer (PeerLink
//    emits HELLO before the transport is writable), and the close/fail teardown are
//    written once here; a subclass only wires its transport's events to
//    open()/deliver()/fail() and says how to write bytes and tear the transport down.
//
// 2. The single-identity Network facade both RtcNetwork and WsNetwork present over
//    the same TransportHost driver: the endpoint() identity guard, the framesDelivered
//    mirror, and the linkedPeers() cohort query.
//
// Host code, not core: it defines no seam. `RawLink` — the shape it satisfies — is the
// core seam (socket-seam.ts), and this is one convenience for the two host adapters
// that implement it against a platform object. A target with its own message transport
// is free to satisfy RawLink without ever touching this file.
import { FRAMING } from "../core/socket-seam.js";
import type { Endpoint, PeerId } from "../core/net.js";
import type { TransportHost } from "./transport-host.js";

export abstract class BufferedChannel {
    /** Every subclass here wraps a transport that already has message boundaries. */
    readonly framing = FRAMING.PLATFORM;
    protected onMsg: ((bytes: Uint8Array) => void) | null = null;
    protected onCls: (() => void) | null = null;
    private readonly pending: Uint8Array[] = [];
    protected opened = false;
    protected dead = false;
    private pendingBytes = 0;
    protected abstract write(bytes: Uint8Array): void;
    protected abstract stop(graceful: boolean): void;
    /** Bytes this transport is still holding — its own socket backlog, which only the
     *  subclass can name (`writableLength`, `bufferedAmount`, …). Default 0 for a
     *  transport that cannot say; `buffered()` still reports the pre-open queue. */
    protected backlog(): number { return 0; }
    /** Written-but-not-yet-on-the-wire bytes: the pre-open queue plus the transport's
     *  own backlog. Feeds the transport bundle's stall clock (socket-seam.ts). */
    buffered(): number { return this.pendingBytes + this.backlog(); }
    send(bytes: Uint8Array): void {
        if (this.dead)
            return;
        if (this.opened)
            this.write(bytes);
        else {
            this.pending.push(bytes);
            this.pendingBytes += bytes.length;
        }
    }
    onData(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; }
    onClose(cb: () => void): void { this.onCls = cb; }
    close(graceful = false): void {
        if (this.dead)
            return;
        this.dead = true;
        try {
            this.stop(graceful);
        }
        catch { /* already gone */ }
    }
    /** The transport became writable — drain the pre-open buffer. Idempotent, so a
     *  transport writable from birth (a socket that buffers its own writes) calls it
     *  straight from its ctor. */
    protected open(): void {
        if (this.opened)
            return;
        this.opened = true;
        for (const b of this.pending)
            this.write(b);
        this.pending.length = 0;
        this.pendingBytes = 0;
    }
    /** A whole message arrived. */
    protected deliver(bytes: Uint8Array): void { if (!this.dead)
        this.onMsg?.(bytes); }
    /** The transport failed/closed: mark dead and notify onClose once. close() sets
     *  `dead` first, so a deliberate close never re-enters here — but a failure on a
     *  live channel must reach onClose, or the PeerLink is never forgotten and the peer
     *  is blackholed until restart. */
    protected fail(): void {
        if (this.dead)
            return;
        this.dead = true;
        try {
            this.stop(false);
        }
        catch { /* already gone */ }
        this.onCls?.();
    }
}

/** The minimal view of a message-oriented transport that MessageChannel wraps: a
 *  browser WebSocket and an RTCDataChannel (browser or the werift facade in
 *  net-rtc-node) both deliver whole ordered binary messages and expose
 *  binaryType/bufferedAmount. */
export interface MessageTransport {
    binaryType: string;
    /** Bytes queued but not yet on the wire — the stall clock's progress signal
     *  (socket-seam.ts `RawLink.buffered`). Optional: not every transport-shaped
     *  object in a test double reports it. */
    bufferedAmount?: number;
    /** The send accepted by every real transport here (DOM WebSocket and
     *  RTCDataChannel both take any of these shapes; werift takes a Uint8Array). */
    send(data: string | ArrayBufferView | ArrayBuffer | Blob): void;
    close(): void;
    addEventListener(type: "open" | "close" | "error", cb: () => void): void;
    addEventListener(type: "message", cb: (ev: { data: unknown }) => void): void;
}

/** RawLink over any whole-message binary transport: WsChannel (net-ws) and
 *  RtcChannel (net-rtc) are both this class — the transport's own event wiring is
 *  identical, so it is written once here. A string frame is never ours (a host may
 *  multiplex renegotiation signaling over the same channel); only binary frames are
 *  transport messages. */
export class MessageChannel extends BufferedChannel {
    constructor(private readonly t: MessageTransport) {
        super();
        t.binaryType = "arraybuffer";
        t.addEventListener("message", (ev) => {
            if (typeof ev.data !== "string")
                this.deliver(new Uint8Array(ev.data as ArrayBuffer));
        });
        t.addEventListener("open", () => this.open());
        t.addEventListener("close", () => this.fail());
        t.addEventListener("error", () => this.fail());
    }
    protected write(bytes: Uint8Array): void { this.t.send(bytes); }
    /** The transport's own send backlog. */
    protected backlog(): number { return this.t.bufferedAmount ?? 0; }
    // Both real transports drain their queued frames before going away, so a
    // graceful stop needs nothing extra here.
    protected stop(_graceful: boolean): void { this.t.close(); }
}

/** The driver-facade half of a host Network: RtcNetwork and WsNetwork are both a
 *  single-identity fabric over one TransportHost — they vend exactly their own
 *  endpoint, mirror the driver's framesDelivered diagnostic, and delegate the
 *  linkedPeers() cohort query. */
export abstract class SingleIdentityNetwork {
    protected readonly driver: TransportHost;
    protected readonly ownId: PeerId;
    constructor(driver: TransportHost, hooks: { onPeerUp?: (peerId: PeerId) => void; onPeerDown?: (peerId: PeerId) => void }) {
        this.driver = driver;
        this.ownId = driver.peerId;
        driver.setPeerHooks({ onPeerUp: hooks.onPeerUp, onPeerDown: hooks.onPeerDown });
    }
    /** Frames delivered to the app side — the driver's diagnostic mirror. */
    get framesDelivered(): number { return this.driver.framesDelivered; }
    /** A single-identity fabric: it vends exactly one endpoint, its own. */
    endpoint(id: PeerId): Endpoint {
        if (id !== this.ownId)
            throw new Error(`${this.constructor.name} is bound to one identity`);
        return this.driver.endpoint(id);
    }
    /** The peers we currently hold at least one authenticated link to (for UI / cohort). */
    linkedPeers(): PeerId[] { return this.driver.linkedPeers(); }
    abstract close(): void;
}
