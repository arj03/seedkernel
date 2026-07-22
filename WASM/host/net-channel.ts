// net-channel.ts — shared plumbing for the RawChannel adapters that wrap an
// already-ordered binary transport: TcpChannel (net-node, length-prefix framed),
// WsChannel (net-ws, a browser WebSocket), RtcChannel (net-rtc, an RTCDataChannel).
// The onMessage/onClose sinks, the `dead` flag, the pre-open send buffer (PeerLink
// emits HELLO before the transport is writable), and the close/fail teardown are
// written once here; a subclass only wires its transport's events to
// open()/deliver()/fail() and says how to write bytes and tear the transport down.
// (net-frame.ts's WsChannelBase is the sibling base for the RFC 6455 codec channels.)

import type { RawChannel } from "./net-link.js";

export abstract class BufferedChannel implements RawChannel {
  protected onMsg: ((bytes: Uint8Array) => void) | null = null;
  protected onCls: (() => void) | null = null;
  private readonly pending: Uint8Array[] = [];
  private opened = false;
  protected dead = false;

  protected abstract write(bytes: Uint8Array): void; // put bytes on the open transport
  protected abstract stop(): void;                    // tear it down (may throw; guarded)

  send(bytes: Uint8Array): void {
    if (this.dead) return;
    if (this.opened) this.write(bytes); else this.pending.push(bytes);
  }
  onMessage(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; }
  onClose(cb: () => void): void { this.onCls = cb; }
  close(): void { if (!this.dead) { this.dead = true; try { this.stop(); } catch { /* already gone */ } } }

  /** The transport became writable — drain the pre-open buffer. Idempotent, so a
   *  transport writable from birth (a socket that buffers its own writes) calls it
   *  straight from its ctor. */
  protected open(): void {
    if (this.opened) return;
    this.opened = true;
    for (const b of this.pending) this.write(b);
    this.pending.length = 0;
  }
  /** A whole message arrived. */
  protected deliver(bytes: Uint8Array): void { if (!this.dead) this.onMsg?.(bytes); }
  /** The transport failed/closed: mark dead and notify onClose once. close() sets
   *  `dead` first, so a deliberate close never re-enters here — but a failure on a
   *  live channel must reach onClose, or the PeerLink is never forgotten and the peer
   *  is blackholed until restart. */
  protected fail(): void {
    if (this.dead) return;
    this.dead = true;
    try { this.stop(); } catch { /* already gone */ }
    this.onCls?.();
  }
}
