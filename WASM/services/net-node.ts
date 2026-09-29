// The Node platform's socket seam: a `ChannelFactory` (services/socket-seam.ts) that opens
// node:net sockets and wraps them as RawLinks. The handshake, link routing and
// request/response layer run in the transport bundle's guest, driven by TransportHost.
//
// Every listener carries the same byte stream; the transport bundle chooses framing from
// the destination or the listener's label (§12.1).
import { createServer as createTcpServer, connect as tcpConnect, type Server as TcpServer, type Socket } from "node:net";

import { errMessage } from "./util.js";
import { type Arrival, type ListenAddress, type RawLink } from "./socket-seam.js";
import { TCP_LINGER_MS } from "./net-limits.js";
import { parseDest } from "./peer-addr.js";

// node:net buffers pre-connect writes, so the link is immediately writable.
function nodeRawStream(socket: Socket): RawLink {
  return {
    stream: true,
    // The peer's IP, only for the per-source half-open cap (§12.6.2): unauthenticated and
    // never an identity. Read now because `socket.remoteAddress` is undefined once the
    // socket is destroyed, and the limiter must release the bucket it took.
    remoteAddr: socket.remoteAddress ?? undefined,
    send: (bytes: Uint8Array) => { socket.write(bytes); },
    // Pass a plain Uint8Array view: the driver copies when it holds a read, and its
    // slice() must copy as Uint8Array's does, not alias as Buffer's does.
    onData: (cb: (chunk: Uint8Array) => void) => {
      socket.on("data", (chunk: Uint8Array) => cb(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)));
    },
    setReadable: (enabled) => { if (enabled) socket.resume(); else socket.pause(); },
    // error and close both mean "gone"; the caller's teardown is idempotent.
    onClose: (cb: () => void) => { socket.on("close", cb); socket.on("error", cb); },
    // A graceful close must flush: `destroy()` drops the write buffer, losing the
    // end-of-stream record the transport just wrote, so the peer sees a clean shutdown as
    // a truncation. `end()` writes the queued bytes then sends FIN; the linger timer
    // covers a peer that never closes its side.
    close: (graceful?: boolean) => {
      if (!graceful) { socket.destroy(); return; }
      try {
        socket.end();
        const t = setTimeout(() => socket.destroy(), TCP_LINGER_MS);
        t.unref?.();
      } catch { socket.destroy(); }
    },
    buffered: () => socket.writableLength,
  };
}

function listenOn(server: TcpServer, opt: ListenAddress): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    // Removed after bind. Left in place, it would swallow the first later error (reject
    // on a settled promise is silent, and `once` then unregisters it), and the second
    // would reach a server with no `error` listener, which ends the process.
    server.once("error", reject);
    server.listen(opt.port, opt.host, () => {
      server.removeListener("error", reject);
      const a = server.address() as { port: number } | null;
      const port = a && typeof a === "object" ? a.port : 0;
      // An error on a listening server is a failed accept (EMFILE and the like). The
      // connection is lost but the listener is fine, so log it and keep going.
      server.on("error", (err) => {
        console.error(`[net] accept on ${opt.host}:${port}: ${errMessage(err)}`);
      });
      resolve(port);
    });
  });
}

// The node:net ChannelFactory: every socket the transport driver opens or accepts is
// created here, as a RawLink.
export class NodeChannelFactory {
  private readonly servers: TcpServer[] = [];
  /** Takes no crypto: the transport bundle makes the WebSocket client key and frame masks
   *  itself, with entropy from `crypto/random`. */
  constructor() {}
  /** Dial TCP-backed destinations; `wss://` is unsupported because this factory has no TLS. */
  connect(dest: string): RawLink | null {
    const d = parseDest(dest);
    if (!d || d.scheme === "wss") return null;
    return nodeRawStream(tcpConnect(d.port, d.host));
  }
  /** One TCP server per address; every socket it accepts carries that listener's label. */
  listen(
    addrs: readonly ListenAddress[],
    onAccept: (channel: RawLink, arrival?: Arrival) => void,
  ): Promise<number[]> {
    return Promise.all(addrs.map((a) => {
      const server = createTcpServer((s) => onAccept(nodeRawStream(s), { listener: a.label }));
      this.servers.push(server);
      return listenOn(server, a);
    }));
  }
  close(): void {
    for (const server of this.servers.splice(0)) server.close();
  }
}
