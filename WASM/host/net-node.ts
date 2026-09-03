// The Node platform binding for the TCP/WS socket seam: a `ChannelFactory`
// (core/socket-seam.ts) that opens node:net sockets and wraps them as RawLinks, and
// nothing else. The handshake, link routing and request/response layer run in the transport
// bundle's guest, driven by TransportHost.
//
// TCP and WebSocket listeners expose the same byte stream; the transport bundle selects
// framing from the destination or listener label (§12.1).
import { createServer as createTcpServer, connect as tcpConnect, type Server as TcpServer, type Socket } from "node:net";

import { errMessage } from "../core/util.js";
import { LISTENER, type Arrival, type ListenAddress, type RawLink } from "../core/socket-seam.js";
import { TCP_LINGER_MS } from "../core/net-limits.js";
import { parseDest } from "./peer-addr.js";

// node:net buffers pre-connect writes, so the link is immediately writable.
function nodeRawStream(socket: Socket): RawLink {
  return {
    stream: true,
    // The peer's IP, for the per-source half-open cap only (§12.6.2) — unauthenticated
    // and never an identity. Captured now because `socket.remoteAddress` reads undefined
    // once destroyed, and the limiter must release the bucket it took.
    remoteAddr: socket.remoteAddress ?? undefined,
    send: (bytes: Uint8Array) => { socket.write(bytes); },
    onData: (cb: (chunk: Uint8Array) => void) => { socket.on("data", (chunk: Uint8Array) => cb(new Uint8Array(chunk))); },
    setReadable: (enabled) => { if (enabled) socket.resume(); else socket.pause(); },
    // error and close both mean "gone"; the caller's teardown is idempotent.
    onClose: (cb: () => void) => { socket.on("close", cb); socket.on("error", cb); },
    // A graceful stop must FLUSH: `destroy()` drops the write buffer, so the
    // end-of-stream record the transport just wrote is discarded and the peer reads a
    // clean shutdown as a truncation. `end()` writes the queued bytes then FINs; the
    // linger timer is the backstop for a peer that never FINs back.
    close: (graceful?: boolean) => {
      if (!graceful) { socket.destroy(); return; }
      try {
        socket.end();
        const t = setTimeout(() => socket.destroy(), TCP_LINGER_MS);
        t.unref?.();
      }
      catch { socket.destroy(); }
    },
    buffered: () => socket.writableLength,
  };
}
function listenOn(server: TcpServer, opt: ListenAddress): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    // Detached below, because `reject` on a settled promise is silent AND `once`
    // unregisters it: left armed, it eats the first post-bind error and leaves the
    // second to reach a server with no `error` listener, which ends the process.
    server.once("error", reject);
    server.listen(opt.port, opt.host, () => {
      server.removeListener("error", reject);
      const a = server.address() as { port: number } | null;
      const port = a && typeof a === "object" ? a.port : 0;
      // A LISTENING server's error is an accept that failed (EMFILE and friends).
      // The connection is lost, the listener is not: report and stay up.
      server.on("error", (err) => {
        console.error(`[net] accept on ${opt.host}:${port}: ${errMessage(err)}`);
      });
      resolve(port);
    });
  });
}
// The node:net ChannelFactory: every socket the transport driver opens or accepts is
// created here, behind the RawLink shape.
export class NodeChannelFactory {
  private tcpServer: TcpServer | null = null;
  private wsServer: TcpServer | null = null;
  /** Takes no crypto: the WebSocket client key and the frame masks are the transport
     *  bundle's, which reaches entropy through `node/random` like any other authority. */
  constructor() {}
  /** Dial TCP-backed destinations; `wss://` is unsupported because this factory has no TLS. */
  connect(dest: string): RawLink | null {
    const d = parseDest(dest);
    if (!d || d.scheme === "wss") return null;
    return nodeRawStream(tcpConnect(d.port, d.host));
  }
  async listen(tcp: ListenAddress | undefined, ws: ListenAddress | undefined, onAccept: (channel: RawLink, arrival?: Arrival) => void): Promise<{
    port: number;
    wsPort: number;
  }> {
    let port = 0, wsPort = 0;
    const tasks: Promise<void>[] = [];
    if (tcp) {
      const server = createTcpServer((s) => onAccept(nodeRawStream(s), { listener: LISTENER.TCP }));
      this.tcpServer = server;
      tasks.push(listenOn(server, tcp).then((p) => { port = p; }));
    }
    if (ws) {
      const server = createTcpServer((s) => onAccept(nodeRawStream(s), { listener: LISTENER.WS }));
      this.wsServer = server;
      tasks.push(listenOn(server, ws).then((p) => { wsPort = p; }));
    }
    await Promise.all(tasks);
    return { port, wsPort };
  }
  close(): void {
    this.tcpServer?.close();
    this.tcpServer = null;
    this.wsServer?.close();
    this.wsServer = null;
  }
}
