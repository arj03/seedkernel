// net-channel.ts — shared plumbing for the RawLink adapters that wrap an
// already-ordered binary transport: WsChannel (net-ws, a browser WebSocket) and
// RtcChannel (net-rtc, an RTCDataChannel). Every one of them delivers whole messages,
// so this base is FRAMING.PLATFORM; a byte duplex (a raw socket, handed to the
// transport bundle to frame itself) has no boundaries to buffer per message and does
// not come through here.
// The onData/onClose sinks, the `dead` flag, the pre-open send buffer (PeerLink
// emits HELLO before the transport is writable), and the close/fail teardown are
// written once here; a subclass only wires its transport's events to
// open()/deliver()/fail() and says how to write bytes and tear the transport down.
//
// Host code, not core: it defines no seam. `RawLink` — the shape it satisfies — is the
// core seam (socket-seam.ts), and this is one convenience for the two host adapters
// that implement it against a platform object. A target with its own message transport
// is free to satisfy RawLink without ever touching this file.
import { FRAMING } from "../core/socket-seam.js";

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
