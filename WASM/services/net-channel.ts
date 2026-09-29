/** Platform adapter with a pre-open buffer. Admission is the link owner's job
 * (`TransportHost`); this class holds accepted bytes and reports them. */

/** The part of a message-oriented transport that MessageChannel uses. A browser
 *  WebSocket and an RTCDataChannel both deliver whole ordered binary messages and expose
 *  binaryType and bufferedAmount. This is all a console peer's own peer-connection
 *  implementation has to provide. */
export interface MessageTransport {
  binaryType: string;
  /** Bytes queued but not yet on the wire, which the host uses for outbound accounting
   *  (socket-seam.ts `RawLink.buffered`). Optional, since some test doubles omit it. */
  bufferedAmount?: number;
  /** This class only sends bytes, so that is all it requires; a DOM WebSocket or
   *  RTCDataChannel accepts more, an off-browser data channel may not. A view instead of
   *  `Uint8Array`, because the DOM lib types RTCDataChannel's as
   *  `ArrayBufferView<ArrayBuffer>`, which a `Uint8Array<ArrayBufferLike>` does not match. */
  send(data: ArrayBufferView): void;
  close(): void;
  addEventListener(type: "open" | "close" | "error", cb: () => void): void;
  addEventListener(type: "message", cb: (ev: { data: unknown }) => void): void;
}

/** RawLink over any whole-message binary transport. WebSocket (net-ws) and RtcChannel
 *  (net-rtc) both use it, since their event wiring is identical. The seam carries bytes,
 *  so only binary frames are delivered; a string frame is dropped. */
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
      if (typeof ev.data !== "string" && !this.dead) this.onMsg?.(new Uint8Array(ev.data as ArrayBuffer));
    });
    t.addEventListener("open", () => this.open());
    t.addEventListener("close", () => this.fail());
    t.addEventListener("error", () => this.fail());
  }
  /** Bytes written but not yet on the wire: the pre-open queue plus the transport's own
   *  send backlog. Used for the host's outbound accounting (socket-seam.ts). */
  buffered(): number { return this.pendingBytes + (this.t.bufferedAmount ?? 0); }
  send(bytes: Uint8Array): void {
    if (this.dead) throw new Error("socket: link is closed");
    if (this.opened) {
      try {
        this.write(bytes);
      } catch {
        // A message may have been split into several physical writes. Once one fails,
        // the stream cannot safely continue after the part already written.
        this.fail();
      }
    } else {
      this.pending.push(bytes);
      this.pendingBytes += bytes.length;
    }
  }
  /** One physical write. Overridable so a transport with a message-size ceiling
   *  (RtcChannel) can split it while everything above still sees whole writes. */
  protected write(bytes: Uint8Array): void { this.t.send(bytes); }
  /** Release the pre-open queue, so a channel that dies before opening does not hold its
   *  backlog until the object is collected. */
  private dropPending(): void {
    this.pending.length = 0;
    this.pendingBytes = 0;
  }
  onData(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; }
  onClose(cb: () => void): void { this.onCls = cb; }
  close(_graceful = false): void {
    if (this.dead) return;
    this.dead = true;
    this.dropPending();
    // Both real transports drain their queued frames before going away, so a graceful
    // stop needs nothing extra here.
    try {
      this.t.close();
    } catch { /* already gone */ }
  }
  /** The transport became writable: flush the pre-open buffer. Idempotent, so a transport
   *  that is writable immediately (a socket that buffers its own writes) can call it from
   *  its constructor. */
  protected open(): void {
    if (this.opened) return;
    this.opened = true;
    try {
      for (const b of this.pending) this.write(b);
    } catch {
      this.fail();
      return;
    }
    this.dropPending();
  }
  /** The transport failed or closed: mark it dead and notify onClose once. `close()` sets
   *  `dead` first, so a local close does not come through here, but a failure on a live
   *  channel must reach onClose or the link is never removed. */
  protected fail(): void {
    if (this.dead) return;
    this.close();
    this.onCls?.();
  }
}
