// The Node platform binding for the routing core (net-route.ts) — node↔node over
// TCP and browser↔node over WebSocket. It implements ChannelFactory: it knows how
// to open node:net sockets and wrap them as RawChannels, and nothing else. The
// routing, the PeerLink handshake, and the double-connect rule live in
// NodeNetworkCore and are shared with every other target (the engine build swaps
// this file for a factory over its native __net binding).
//
// WebSocket exists only because browsers cannot speak raw TCP, so it is handled as
// a wire codec *over a raw TCP listener*: the RFC 6455 opening handshake and
// framing run in ws.wasm (ws-codec.ts), identically on Node and Bun — no
// dependency on node:http and no Bun-native fast path, one WS code path everywhere.

import { createServer as createTcpServer, connect as tcpConnect, type Server as TcpServer, type Socket } from "node:net";

import { NodeNetworkCore, type ChannelFactory, type PeerAddr } from "./net-route.js";
import { MAX_FRAME_BYTES, type RawChannel, type Identity, type TransportCrypto } from "./net-link.js";
import { WsServerChannel, WsClientChannel, type RawByteStream } from "./net-frame.js";
import { installWasmWsBackend } from "./ws/ws-wasm-backend.js";
import { writeU32BE, readU32BE, ByteQueue } from "./util.js";

export { parsePeerSpec } from "./net-route.js";
export type { PeerAddr } from "./net-route.js";

// The WS codec (net-frame.ts) runs over the WebAssembly ws.wasm on this target.
installWasmWsBackend();

// One wire-visible frame cap for both node↔node transports (§13.6, §17.1): the
// TCP length prefix is checked against it before the body is buffered, and the WS
// codec caps identically, so a frame that crosses one crosses the other.

export interface NodeNetworkOptions {
  identity: Identity;
  sodium: TransportCrypto;
  /** TCP listener for node↔node peers. Port 0 binds an ephemeral port. */
  listen?: { host: string; port: number };
  /** WebSocket listener for browser↔node peers. Port 0 binds an ephemeral port. */
  wsListen?: { host: string; port: number };
}

// ── RawChannel: length-prefixed frames over a TCP socket ──────────────────────
//   [len u32 BE][bytes]   one PeerLink message per record.
class TcpChannel implements RawChannel {
  private onMsg: ((bytes: Uint8Array) => void) | null = null;
  private onCls: (() => void) | null = null;
  private readonly q = new ByteQueue();
  private dead = false;

  constructor(private readonly socket: Socket) {
    socket.on("data", (chunk: Buffer) => this.onData(new Uint8Array(chunk)));
    socket.on("close", () => this.fail());
    socket.on("error", () => this.fail());
  }

  send(bytes: Uint8Array): void {
    if (this.dead) return;
    const out = new Uint8Array(4 + bytes.length);
    writeU32BE(out, 0, bytes.length);
    out.set(bytes, 4);
    this.socket.write(out);
  }
  onMessage(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; }
  onClose(cb: () => void): void { this.onCls = cb; }
  close(): void { if (!this.dead) { this.dead = true; this.socket.destroy(); } }

  /** Failure teardown: destroy the socket AND notify onClose. close() (the
   *  deliberate path) sets `dead` first, so a fail() that follows it stays
   *  silent — but an error/'close' event on a live channel must always reach
   *  onClose, or the owning PeerLink is never forgotten from the routing maps
   *  and the peer is blackholed until restart. */
  private fail(): void {
    if (this.dead) return;
    this.dead = true;
    this.socket.destroy();
    this.onCls?.();
  }

  private onData(chunk: Uint8Array): void {
    if (this.dead) return;
    this.q.push(chunk);
    for (;;) {
      const head = this.q.peek(4);
      if (!head) break;
      const len = readU32BE(head, 0);
      if (len > MAX_FRAME_BYTES) { this.fail(); return; }
      if (this.q.length < 4 + len) break;
      this.q.drop(4);
      this.onMsg?.(this.q.take(len)!);
    }
  }
}

// ── RawByteStream over a node:net socket ──────────────────────────────────────
// The transport the shared WS codec (net-frame.ts) runs on: raw bytes in/out, no
// framing. node:net buffers writes issued before connect, so the WS client's
// upgrade request can be written the moment the channel is constructed.
function nodeRawStream(socket: Socket): RawByteStream {
  return {
    write: (bytes) => { socket.write(bytes); },
    onData: (cb) => { socket.on("data", (chunk: Buffer) => cb(new Uint8Array(chunk))); },
    // error and close both mean "gone"; WsChannelBase.fail() is idempotent.
    onClose: (cb) => { socket.on("close", cb); socket.on("error", cb); },
    close: () => { socket.destroy(); },
  };
}

function listenOn(server: TcpServer, opt: { host: string; port: number }): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opt.port, opt.host, () => {
      const a = server.address();
      resolve(a && typeof a === "object" ? a.port : 0);
    });
  });
}

// The node:net / ws.wasm ChannelFactory: every socket the routing core opens or
// accepts is created here, behind the RawChannel shape.
class NodeChannelFactory implements ChannelFactory {
  private tcpServer: TcpServer | null = null;
  private wsServer: TcpServer | null = null;

  constructor(private readonly sodium: TransportCrypto) {}

  connect(addr: PeerAddr): RawChannel {
    return addr.transport === "ws"
      ? new WsClientChannel(nodeRawStream(tcpConnect(addr.port, addr.host)), addr.host, addr.port, this.sodium)
      : new TcpChannel(tcpConnect(addr.port, addr.host));
  }

  async listen(
    tcp: { host: string; port: number } | undefined,
    ws: { host: string; port: number } | undefined,
    onAccept: (channel: RawChannel) => void,
  ): Promise<{ port: number; wsPort: number }> {
    let port = 0, wsPort = 0;
    const tasks: Promise<void>[] = [];
    if (tcp) {
      const server = createTcpServer((socket) => onAccept(new TcpChannel(socket)));
      this.tcpServer = server;
      tasks.push(listenOn(server, tcp).then((p) => { port = p; }));
    }
    if (ws) {
      const server = createTcpServer((socket) => onAccept(new WsServerChannel(nodeRawStream(socket))));
      this.wsServer = server;
      tasks.push(listenOn(server, ws).then((p) => { wsPort = p; }));
    }
    await Promise.all(tasks);
    return { port, wsPort };
  }

  close(): void {
    this.tcpServer?.close(); this.tcpServer = null;
    this.wsServer?.close(); this.wsServer = null;
  }
}

/** The real Network for a server node: the shared routing core wired to the
 *  node:net socket binding. Construction is unchanged for callers. */
export class NodeNetwork extends NodeNetworkCore {
  constructor(opts: NodeNetworkOptions) {
    super({ ...opts, channels: new NodeChannelFactory(opts.sodium) });
  }
}
