// The real Network (README §13.6) for a server node — node↔node over TCP and
// browser↔node over WebSocket. It satisfies the same Network interface the
// Transport/cohort/coordinator drive, so nothing above it changes; only the
// fabric underneath is new.
//
// Two transports, one routing table:
//   node ↔ node     length-prefixed frames over TCP (connect/listen)
//   browser ↔ node  RFC 6455 WebSocket over TCP (the browser uses platform
//                   WebSocket; this side speaks the wire format via ws-frame.ts)
//
// WebSocket exists only because browsers cannot speak raw TCP, so it is handled
// as a wire codec *over a raw TCP listener*: we do the RFC 6455 opening
// handshake and framing ourselves, identically on Node and Bun. There is no
// dependency on node:http (whose Bun upgrade socket silently swallowed the 101
// write) and no Bun-native fast path — one WS code path everywhere
// (the runtime split).
//
// Every connection — inbound or outbound, TCP or WS — is wrapped in a RawChannel
// and handed to a PeerLink, which performs the identity handshake and only then
// becomes routable. A frame received on a link is delivered to the registered
// sink tagged with the link's *authenticated* peerId, never a value off the wire.
//
// This module is the Node reference: it uses node:net. The engine build swaps it
// for its native TCP binding behind the same RawChannel shape; PeerLink, the
// routing, and the handshake are untouched.

import { createServer as createTcpServer, connect as tcpConnect, type Server as TcpServer, type Socket } from "node:net";

import type { Network, PeerId } from "./net.js";
import { PeerLink, bytesCompare, type RawChannel, type Identity, type TransportCrypto } from "./net-link.js";
import { WsParser, encodeFrame, wsAcceptKey, wsClientKey, WS_OPCODES } from "./ws/ws-codec.js";
import { toHex, fromHex, writeU32BE, readU32BE, ByteQueue } from "./util.js";

const MAX_TCP_MESSAGE = 16 * 1024 * 1024; // matches the WS frame cap
const MAX_WS_HANDSHAKE = 16 * 1024;       // an HTTP upgrade request is tiny

export interface PeerAddr {
  host: string;
  port: number;
  transport: "tcp" | "ws";
}

export interface NodeNetworkOptions {
  identity: Identity;
  sodium: TransportCrypto;
  /** TCP listener for node↔node peers. Port 0 binds an ephemeral port. */
  listen?: { host: string; port: number };
  /** WebSocket listener for browser↔node peers. Port 0 binds an ephemeral port. */
  wsListen?: { host: string; port: number };
}

export class NodeNetwork implements Network {
  /** Diagnostics for tests, mirroring LoopbackNetwork. */
  framesDelivered = 0;
  framesSent = 0;
  /** Bound ports, valid after start() (ephemeral when requested with port 0). */
  port = 0;
  wsPort = 0;

  private readonly identity: Identity;
  private readonly sodium: TransportCrypto;
  private readonly ownId: PeerId;
  private sink: ((from: PeerId, frame: Uint8Array) => void) | null = null;

  private readonly links = new Map<PeerId, PeerLink>();      // authenticated, routable
  private readonly connecting = new Map<PeerId, PeerLink>(); // outbound, pre-auth
  private readonly inbound = new Set<PeerLink>();            // accepted, pre-auth
  private readonly addrs = new Map<PeerId, PeerAddr>();      // how to reach a peer
  private readonly authWaiters = new Set<() => void>();      // ready() callers

  private tcpServer: TcpServer | null = null;
  private wsServer: TcpServer | null = null;
  private readonly listenOpt?: { host: string; port: number };
  private readonly wsListenOpt?: { host: string; port: number };

  constructor(opts: NodeNetworkOptions) {
    this.identity = opts.identity;
    this.sodium = opts.sodium;
    this.ownId = toHex(opts.identity.publicKey);
    this.listenOpt = opts.listen;
    this.wsListenOpt = opts.wsListen;
  }

  // ── Network interface ──────────────────────────────────────────────────────
  register(peerId: PeerId, sink: (from: PeerId, frame: Uint8Array) => void): void {
    if (peerId !== this.ownId) throw new Error("NodeNetwork is bound to one identity");
    this.sink = sink;
  }

  unregister(peerId: PeerId): void {
    if (peerId !== this.ownId) return;
    this.sink = null;
    this.close();
  }

  send(_from: PeerId, to: PeerId, frame: Uint8Array): void {
    if (to === this.ownId) return;
    this.framesSent++;
    let link = this.links.get(to) ?? this.connecting.get(to) ?? this.dial(to);
    if (link) link.send(frame);
    // No link and no address → silently dropped, exactly as LoopbackNetwork drops
    // a frame to an unknown peer; the Transport's timeout handles the fallout.
  }

  // ── teach the network how to reach a peer ──────────────────────────────────
  addPeerAddr(peerId: PeerId, addr: PeerAddr): void {
    this.addrs.set(peerId, addr);
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────
  /** Bind the configured listeners. Resolves once ports are known. */
  async start(): Promise<void> {
    const tasks: Promise<void>[] = [];
    if (this.listenOpt) {
      const server = createTcpServer((socket) => this.accept(new TcpChannel(socket)));
      this.tcpServer = server;
      tasks.push(this.listenOn(server, this.listenOpt, (p) => { this.port = p; }));
    }
    if (this.wsListenOpt) {
      // WebSocket on a raw TCP listener: each socket does its own RFC 6455
      // handshake + framing (WsServerChannel) — one path on Node and Bun.
      const server = createTcpServer((socket) => this.accept(new WsServerChannel(socket)));
      this.wsServer = server;
      tasks.push(this.listenOn(server, this.wsListenOpt, (p) => { this.wsPort = p; }));
    }
    await Promise.all(tasks);
  }

  private listenOn(server: TcpServer, opt: { host: string; port: number }, setPort: (p: number) => void): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(opt.port, opt.host, () => {
        const a = server.address();
        if (a && typeof a === "object") setPort(a.port);
        resolve();
      });
    });
  }

  /** Dial every known peer address and resolve once each is authenticated (or
   *  the deadline passes — links also form lazily on first send). Resolution is
   *  event-driven off promote(), not polled, so an all-up cohort resolves the
   *  moment its last handshake lands. */
  async ready(timeoutMs = 5000): Promise<void> {
    const targets = [...this.addrs.keys()].filter((p) => p !== this.ownId);
    for (const p of targets) if (!this.links.has(p)) this.dial(p);
    const allUp = (): boolean => targets.every((p) => this.links.has(p));
    if (allUp()) return;
    await new Promise<void>((resolve) => {
      const done = (): void => { clearTimeout(timer); this.authWaiters.delete(check); resolve(); };
      const check = (): void => { if (allUp()) done(); };
      const timer = setTimeout(done, timeoutMs);
      this.authWaiters.add(check);
    });
  }

  /** Tear down every connection and listener. */
  close(): void {
    for (const l of this.links.values()) l.close();
    for (const l of this.connecting.values()) l.close();
    for (const l of this.inbound) l.close();
    this.links.clear();
    this.connecting.clear();
    this.inbound.clear();
    this.tcpServer?.close(); this.tcpServer = null;
    this.wsServer?.close(); this.wsServer = null;
  }

  // ── link management ────────────────────────────────────────────────────────
  private dial(peerId: PeerId): PeerLink | null {
    const addr = this.addrs.get(peerId);
    if (!addr) return null;
    const channel = addr.transport === "ws"
      ? new WsClientChannel(addr.host, addr.port, this.sodium)
      : new TcpChannel(tcpConnect(addr.port, addr.host));
    const link = new PeerLink({
      channel, identity: this.identity, sodium: this.sodium,
      weDialed: true, expectPeerId: peerId,
      onAuth: (pid, l) => this.promote(pid, l),
      onFrame: (pid, frame) => this.deliver(pid, frame),
      onClose: (l) => this.forget(l),
    });
    this.connecting.set(peerId, link);
    return link;
  }

  private accept(channel: RawChannel): void {
    const link = new PeerLink({
      channel, identity: this.identity, sodium: this.sodium,
      weDialed: false,
      onAuth: (pid, l) => this.promote(pid, l),
      onFrame: (pid, frame) => this.deliver(pid, frame),
      onClose: (l) => this.forget(l),
    });
    this.inbound.add(link);
  }

  /** A link finished its handshake: install it as the routable link for its
   *  peer, resolving a double-connect by a rule both ends compute identically. */
  private promote(peerId: PeerId, link: PeerLink): void {
    this.inbound.delete(link);
    if (this.connecting.get(peerId) === link) this.connecting.delete(peerId);
    const existing = this.links.get(peerId);
    if (existing && existing !== link) {
      // Two connections to the same peer (each dialed the other). Keep the one
      // whose *dialer* holds the smaller pubkey — a deterministic choice both
      // ends agree on, so exactly one survives.
      if (this.canonicalKeep(link)) { existing.close(); this.links.set(peerId, link); }
      else { link.close(); }
    } else {
      this.links.set(peerId, link);
    }
    for (const w of [...this.authWaiters]) w();
  }

  private canonicalKeep(link: PeerLink): boolean {
    const peer = link.peerPubkey!;
    const mine = this.identity.publicKey;
    const dialer = link.weDialed ? mine : peer;
    const smaller = bytesCompare(mine, peer) <= 0 ? mine : peer;
    return bytesCompare(dialer, smaller) === 0;
  }

  private deliver(peerId: PeerId, frame: Uint8Array): void {
    if (!this.sink || peerId === this.ownId) return;
    this.framesDelivered++;
    this.sink(peerId, frame);
  }

  private forget(link: PeerLink): void {
    this.inbound.delete(link);
    // Scan by value rather than keying off link.peerId: an outbound dial is
    // registered in `connecting` under the *target* peerId before the peer's
    // HELLO ever arrives (link.peerId is still ""), so a dial that dies pre-
    // handshake (ECONNREFUSED, expectPeerId mismatch) must still be removed —
    // otherwise send() returns the dead link forever and never redials.
    for (const [pid, l] of this.connecting) if (l === link) this.connecting.delete(pid);
    for (const [pid, l] of this.links) if (l === link) this.links.delete(pid);
  }
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

/** Parse a `--peers` entry: `<pubkeyhex>@<host>:<port>`. */
export function parsePeerSpec(spec: string, transport: "tcp" | "ws"): { peerId: PeerId; addr: PeerAddr } {
  const at = spec.indexOf("@");
  if (at < 0) throw new Error(`bad peer spec (want pk@host:port): ${spec}`);
  const peerId = spec.slice(0, at).toLowerCase();
  if (peerId.length !== 64 || /[^0-9a-f]/.test(peerId)) throw new Error(`bad peer pubkey hex: ${spec}`);
  const hostPort = spec.slice(at + 1);
  const colon = hostPort.lastIndexOf(":");
  if (colon < 0) throw new Error(`bad peer host:port: ${spec}`);
  const host = hostPort.slice(0, colon);
  const port = Number(hostPort.slice(colon + 1));
  if (!Number.isInteger(port) || port <= 0) throw new Error(`bad peer port: ${spec}`);
  // Validate the pubkey is real hex by round-tripping (throws on garbage).
  fromHex(peerId);
  return { peerId, addr: { host, port, transport } };
}
