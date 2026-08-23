// loopback-channels.mjs — the in-process socket fabric the transport tests run over.
// Test infrastructure, so it stays out of the shared bundle every target ships: tests
// drive the transport through this ChannelFactory the way a node drives real sockets.

import { FRAMING } from "../build/core/socket-seam.js";

/** One end of an in-process socket pair. Delivery is asynchronous (a microtask),
 *  mirroring a real socket; closing one end fires the other's onClose — the close
 *  semantics of BufferedChannel's fail() path on a real channel. */
class LoopbackChannel {
  /** A socket pair with `send` as the boundary: one send is one delivery. */
  framing = FRAMING.PLATFORM;
  peer = null;
  msg = null;
  cls = null;
  dead = false;
  remoteAddr;

  constructor(remoteAddr) {
    this.remoteAddr = remoteAddr;
  }

  static pair(remoteAddr) {
    const a = new LoopbackChannel(remoteAddr);
    const b = new LoopbackChannel(remoteAddr);
    a.peer = b;
    b.peer = a;
    return [a, b];
  }

  send(bytes) {
    if (this.dead) return;
    const p = this.peer;
    queueMicrotask(() => { if (p && !p.dead) p.msg?.(bytes); });
  }
  onData(cb) { this.msg = cb; }
  onClose(cb) { this.cls = cb; }
  close() {
    if (this.dead) return;
    this.dead = true;
    const p = this.peer;
    queueMicrotask(() => { if (p && !p.dead) p.cls?.(); });
  }
  /** The far end went away / this end failed: notify our own onClose (the
   *  BufferedChannel.fail() path — how a socket reports being cut). */
  kill() {
    if (this.dead) return;
    this.dead = true;
    this.cls?.();
  }
}

/** In-process socket fabric for the transport driver. The fabric is SHARED by every
 *  driver in a process (like a real network), so closing one driver only clears its
 *  own listeners — a per-node `view()` handles that. */
export class LoopbackChannels {
  listeners = new Map();
  nextPort = 10000;

  /** The bound ports (set by a driver's start()). */
  port = 0;
  wsPort = 0;

  async listen(tcp, ws, onAccept) {
    let port = 0, wsPort = 0;
    if (tcp) { port = this.bind(tcp.port, onAccept); }
    if (ws) { wsPort = this.bind(ws.port, onAccept); }
    this.port = port;
    this.wsPort = wsPort;
    return { port, wsPort };
  }

  bind(requested, onAccept) {
    const port = requested > 0 ? requested : this.nextPort++;
    if (this.listeners.has(port)) throw new Error("LoopbackChannels: port already bound");
    this.listeners.set(port, onAccept);
    return port;
  }

  connect(addr) {
    const onAccept = this.listeners.get(addr.port);
    if (!onAccept) {
      // A dial to a dead port: the channel fails immediately on the DIAL side
      // (mirroring ECONNREFUSED → the socket's error/close events), so the
      // transport forgets the link instead of holding it until the deadline.
      const [dial] = LoopbackChannel.pair(addr.host);
      queueMicrotask(() => dial.kill());
      return dial;
    }
    // The address's host is the "far end" both sides see — it is what the
    // half-open limiter buckets accepts by (the per-source cap; §12.6.1).
    const [dial, accepted] = LoopbackChannel.pair(addr.host);
    queueMicrotask(() => onAccept(accepted));
    return dial;
  }

  close() {
    this.listeners.clear();
  }

  /** A per-node view of this fabric: it dials and listens through the same registry, but
   *  its `close` unbinds only the ports *it* bound — the whole-fabric `close` above is
   *  right only for teardown. (An in-place transport upgrade re-binds the driver's port,
   *  which on the shared object would unbind every other node.) */
  view() {
    const fabric = this;
    const mine = [];
    return {
      connect: (addr) => fabric.connect(addr),
      async listen(tcp, ws, onAccept) {
        const r = await fabric.listen(tcp, ws, onAccept);
        if (r.port) mine.push(r.port);
        if (r.wsPort) mine.push(r.wsPort);
        return r;
      },
      close() {
        for (const p of mine.splice(0)) fabric.unbind(p);
      },
    };
  }

  /** Release one bound port. The per-node `view()` is the only caller — the fabric's
   *  own `close` drops everything. */
  unbind(port) {
    this.listeners.delete(port);
  }
}
