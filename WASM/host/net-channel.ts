
/** Platform adapter with a natural pre-open buffer. Admission belongs to the enclosing
 * link owner (`TransportHost`); this class retains accepted bytes and reports them. */

export abstract class BufferedChannel {
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
            throw new Error("socket: link is closed");
        if (this.opened) {
            try {
                this.write(bytes);
            }
            catch {
                // A message may have been split into several physical writes. Once any
                // write fails, the byte stream cannot safely continue after that prefix.
                this.fail();
            }
        }
        else {
            this.pending.push(bytes);
            this.pendingBytes += bytes.length;
        }
    }
    /** Release the pre-open queue. Every path out of the buffering state ends here or in
     *  `open()`, so a channel that dies before it opened does not hold its backlog until
     *  the object itself is dropped. */
    private dropPending(): void {
        this.pending.length = 0;
        this.pendingBytes = 0;
    }
    onData(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; }
    onClose(cb: () => void): void { this.onCls = cb; }
    close(graceful = false): void {
        if (this.dead)
            return;
        this.dead = true;
        this.dropPending();
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
        try {
            for (const b of this.pending)
                this.write(b);
        }
        catch {
            this.fail();
            return;
        }
        this.dropPending();
    }
    /** A whole message arrived. */
    protected deliver(bytes: Uint8Array): void { if (!this.dead)
        this.onMsg?.(bytes); }
    /** The transport failed/closed: mark dead and notify onClose once. `close()` sets `dead`
     *  first, so a deliberate close never re-enters here — but a failure on a live channel
     *  must reach onClose, or the link is never forgotten and the peer is blackholed. */
    protected fail(): void {
        if (this.dead)
            return;
        this.dead = true;
        this.dropPending();
        try {
            this.stop(false);
        }
        catch { /* already gone */ }
        this.onCls?.();
    }
}

/** The minimal view of a message-oriented transport that MessageChannel wraps: a
 *  browser WebSocket and an RTCDataChannel both deliver whole ordered binary
 *  messages and expose binaryType/bufferedAmount. It is the whole contract a
 *  console peer's own peer-connection implementation has to satisfy. */
export interface MessageTransport {
    binaryType: string;
    /** Bytes queued but not yet on the wire — the stall clock's progress signal
     *  (socket-seam.ts `RawLink.buffered`). Optional: not every transport-shaped
     *  object in a test double reports it. */
    bufferedAmount?: number;
    /** The send accepted by every real transport here (DOM WebSocket and
     *  RTCDataChannel both take any of these shapes; an off-browser data channel
     *  may accept only a Uint8Array, which is what this class always sends). */
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
    protected write(bytes: Uint8Array): void {
        this.t.send(bytes);
    }
    /** The transport's own send backlog. */
    protected backlog(): number { return this.t.bufferedAmount ?? 0; }
    // Both real transports drain their queued frames before going away, so a
    // graceful stop needs nothing extra here.
    protected stop(_graceful: boolean): void {
        this.t.close();
    }
}
