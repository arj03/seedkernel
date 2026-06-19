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
import { type RawChannel, type Identity, type TransportCrypto } from "./net-link.js";
import { WsParser, encodeFrame, wsAcceptKey, wsClientKey, WS_OPCODES } from "./ws/ws-codec.js";
import { writeU32BE, readU32BE, ByteQueue } from "./util.js";

export { parsePeerSpec } from "./net-route.js";
export type { PeerAddr } from "./net-route.js";

const MAX_TCP_MESSAGE = 16 * 1024 * 1024; // matches the WS frame cap
const MAX_WS_HANDSHAKE = 16 * 1024;       // an HTTP upgrade request is tiny

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
      if (len > MAX_TCP_MESSAGE) { this.fail(); return; }
      if (this.q.length < 4 + len) break;
      this.q.drop(4);
      this.onMsg?.(this.q.take(len)!);
    }
  }
}

// ── RawChannel: WebSocket over raw TCP (RFC 6455 framing in ws.wasm) ──────────
// One base drives both directions of the connection; the subclasses differ only
// in who speaks first in the HTTP opening handshake and in masking (client→
// server frames are masked, server→client unmasked). No node:http and no
// Bun-native server, so Node and Bun share one path.
abstract class WsChannelBase implements RawChannel {
  private onMsg: ((bytes: Uint8Array) => void) | null = null;
  private onCls: (() => void) | null = null;
  private readonly parser: WsParser;
  private open = false;
  private dead = false;
  private handshake = new Uint8Array(0);
  // PeerLink emits its HELLO the moment the link is created — before the
  // opening handshake has finished — so frames queue until the channel opens.
  private readonly pending: Uint8Array[] = [];
  protected socket!: Socket;

  constructor(expectMasked: boolean) {
    this.parser = new WsParser(expectMasked);
  }

  /** Wire up socket events; the subclass calls this from its constructor. */
  protected attach(socket: Socket): void {
    this.socket = socket;
    socket.on("data", (chunk: Buffer) => this.onData(new Uint8Array(chunk)));
    socket.on("close", () => this.fail());
    socket.on("error", () => this.fail());
  }

  /** The frame mask: 4 CSPRNG bytes on the client side (RFC 6455 §5.3 requires
   *  it to be unpredictable), null on the server side (unmasked). */
  protected abstract mask(): Uint8Array | null;

  /** Drive the HTTP opening handshake from the bytes buffered so far. Returns
   *  the byte length of the consumed handshake head once the channel is open,
   *  or -1 to wait for more bytes; throws to fail the channel. */
  protected abstract tryHandshake(buf: Uint8Array): number;

  send(bytes: Uint8Array): void {
    if (this.dead) return;
    if (!this.open) { this.pending.push(bytes); return; }
    this.socket.write(encodeFrame(WS_OPCODES.OP_BINARY, bytes, this.mask()));
  }
  onMessage(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; }
  onClose(cb: () => void): void { this.onCls = cb; }
  close(): void { if (!this.dead) { this.dead = true; this.socket.destroy(); } }

  // Failure teardown: destroy + notify (see TcpChannel.fail for why onClose
  // must fire here).
  private fail(): void { if (this.dead) return; this.dead = true; this.socket.destroy(); this.onCls?.(); }

  private onData(chunk: Uint8Array): void {
    if (this.dead) return;
    if (!this.open) {
      const merged = new Uint8Array(this.handshake.length + chunk.length);
      merged.set(this.handshake, 0); merged.set(chunk, this.handshake.length);
      this.handshake = merged;
      let consumed: number;
      try { consumed = this.tryHandshake(this.handshake); }
      catch { this.fail(); return; }
      // wait for the rest of the head, but never hoard unbounded bytes
      if (consumed < 0) { if (this.handshake.length > MAX_WS_HANDSHAKE) this.fail(); return; }
      this.open = true;
      for (const b of this.pending) this.socket.write(encodeFrame(WS_OPCODES.OP_BINARY, b, this.mask()));
      this.pending.length = 0;
      const rest = this.handshake.subarray(consumed);
      this.handshake = new Uint8Array(0);
      if (rest.length) this.feedFrames(rest);
      return;
    }
    this.feedFrames(chunk);
  }

  private feedFrames(chunk: Uint8Array): void {
    let frames;
    try { frames = this.parser.push(chunk); }
    catch { this.fail(); return; }
    for (const f of frames) {
      if (f.opcode === WS_OPCODES.OP_BINARY) this.onMsg?.(f.payload);
      else if (f.opcode === WS_OPCODES.OP_PING) this.socket.write(encodeFrame(WS_OPCODES.OP_PONG, f.payload, this.mask()));
      else if (f.opcode === WS_OPCODES.OP_CLOSE) { this.fail(); return; }
    }
  }
}

// The connection the *server* accepted: read the client's HTTP upgrade request,
// reply 101 with the computed accept, then expect masked frames.
class WsServerChannel extends WsChannelBase {
  constructor(socket: Socket) {
    super(true); // client frames are masked
    this.attach(socket);
  }

  protected mask(): Uint8Array | null { return null; }

  protected tryHandshake(buf: Uint8Array): number {
    const sep = indexOfCRLFCRLF(buf);
    if (sep < 0) return -1;
    const header = new TextDecoder().decode(buf.subarray(0, sep));
    const key = headerValue(header, "sec-websocket-key");
    if (!key) throw new Error("ws: missing Sec-WebSocket-Key");
    this.socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${wsAcceptKey(key)}\r\n\r\n`,
    );
    return sep + 4;
  }
}

// The connection we *dial out* (node-side client). The browser uses platform
// WebSocket; this exists so a Node peer can reach a node's WS endpoint (and so
// the WS path is exercised end-to-end in tests).
class WsClientChannel extends WsChannelBase {
  private readonly expectAccept: string;

  constructor(host: string, port: number, private readonly sodium: TransportCrypto) {
    super(false); // server frames are unmasked
    const { key, expectAccept } = wsClientKey(sodium.randombytes_buf(16));
    this.expectAccept = expectAccept;
    this.attach(tcpConnect(port, host, () => {
      this.socket.write(
        `GET / HTTP/1.1\r\nHost: ${host}:${port}\r\n` +
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
        `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
      );
    }));
  }

  protected mask(): Uint8Array { return this.sodium.randombytes_buf(4); }

  protected tryHandshake(buf: Uint8Array): number {
    const sep = indexOfCRLFCRLF(buf);
    if (sep < 0) return -1;
    const header = new TextDecoder().decode(buf.subarray(0, sep));
    // Sec-WebSocket-Accept is base64 (case-significant), so extract the exact
    // header value and compare byte-for-byte rather than via a lowercased
    // substring match — robust to header whitespace and avoids case folding the
    // base64 on both sides.
    if (!/HTTP\/1\.1 101/.test(header) || headerValue(header, "sec-websocket-accept") !== this.expectAccept) {
      throw new Error("ws: upgrade refused");
    }
    return sep + 4;
  }
}

function indexOfCRLFCRLF(b: Uint8Array): number {
  for (let i = 0; i + 3 < b.length; i++) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
  }
  return -1;
}

/** Case-insensitively pull a header value out of an HTTP request head. */
function headerValue(head: string, name: string): string | null {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`^${escaped}:[ \\t]*(.+?)[ \\t]*$`, "im");
  const m = re.exec(head);
  return m ? m[1] : null;
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
      ? new WsClientChannel(addr.host, addr.port, this.sodium)
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
      const server = createTcpServer((socket) => onAccept(new WsServerChannel(socket)));
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
