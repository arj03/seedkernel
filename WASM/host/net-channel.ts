/** Platform adapter with a natural pre-open buffer. Admission belongs to the enclosing
 * link owner (`TransportHost`); this class retains accepted bytes and reports them. */

/** The minimal view of a message-oriented transport that MessageChannel wraps: a
 *  browser WebSocket and an RTCDataChannel both deliver whole ordered binary
 *  messages and expose binaryType/bufferedAmount. It is the whole contract a
 *  console peer's own peer-connection implementation has to satisfy. */
export interface MessageTransport {
  binaryType: string;
  /** Bytes queued but not yet on the wire — the host owner's custody signal
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

/** RawLink over any whole-message binary transport: a WebSocket (net-ws) and RtcChannel
 *  (net-rtc) are both this class — the transport's own event wiring is identical, so it is
 *  written once here. A string frame is never ours (a host may multiplex renegotiation
 *  signaling over the same channel); only binary frames are transport messages. */
export class MessageChannel {
  private onMsg: ((bytes: Uint8Array) => void) | null = null;
  private onCls: (() => void) | null = null;
  private readonly pending: Uint8Array[] = [];
  private opened = false;
  protected dead = false;
  private pendingBytes = 0;

  constructor(private readonly t: MessageTransport) {
    t.binaryType = "arraybuffer";
    t.addEventListener("message", (ev) => {
      if (typeof ev.data !== "string" && !this.dead)
        this.onMsg?.(new Uint8Array(ev.data as ArrayBuffer));
    });
    t.addEventListener("open", () => this.open());
    t.addEventListener("close", () => this.fail());
    t.addEventListener("error", () => this.fail());
  }
  /** Written-but-not-yet-on-the-wire bytes: the pre-open queue plus the platform
     *  transport's own send backlog. Feeds the host's outbound custody owner
     *  (socket-seam.ts). */
  buffered(): number { return this.pendingBytes + (this.t.bufferedAmount ?? 0); }
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
  /** One physical write. Overridable so a transport with a message-size ceiling
     *  (RtcChannel) can split it while everything above still sees whole writes. */
  protected write(bytes: Uint8Array): void { this.t.send(bytes); }
  /** Release the pre-open queue. Every path out of the buffering state ends here or in
     *  `open()`, so a channel that dies before it opened does not hold its backlog until
     *  the object itself is dropped. */
  private dropPending(): void {
    this.pending.length = 0;
    this.pendingBytes = 0;
  }
  onData(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; }
  onClose(cb: () => void): void { this.onCls = cb; }
  close(_graceful = false): void {
    if (this.dead)
      return;
    this.dead = true;
    this.dropPending();
    // Both real transports drain their queued frames before going away, so a graceful
    // stop needs nothing extra here.
    try {
      this.t.close();
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
  /** The transport failed/closed: mark dead and notify onClose once. `close()` sets `dead`
     *  first, so a deliberate close never re-enters here — but a failure on a live channel
     *  must reach onClose, or the link is never forgotten and the peer is blackholed. */
  protected fail(): void {
    if (this.dead)
      return;
    this.dead = true;
    this.dropPending();
    try {
      this.t.close();
    }
    catch { /* already gone */ }
    this.onCls?.();
  }
}
