// Shared WebSocket channel: RFC 6455 over a raw byte stream, presented as the
// RawChannel (whole-message duplex) the routing core consumes. WebSocket exists
// only because browsers cannot speak raw TCP, so it is a *wire codec over a raw
// socket* — the opening handshake and framing (ws.wasm, via ws-codec.ts) run
// identically on every target. This file is target-agnostic: it drives a
// RawByteStream (write/onData/onClose/close) that each target backs with its own
// socket — node:net on the Node target, the Go __net raw channel on the engine —
// so the WS code path is written once, not re-derived per target.
//
// One base drives both ends; they differ only in who speaks first in the opening
// handshake and in masking (client→server frames are masked, server→client
// unmasked). PeerLink emits its HELLO the moment the link is created — before the
// handshake finishes — so frames queue until the channel opens.

import { encodeFrame, wsAcceptKey, wsClientKey, WsParser, WS_OPCODES } from "./ws/ws-codec.js";
import { type RawChannel, type TransportCrypto } from "./net-link.js";

const MAX_WS_HANDSHAKE = 16 * 1024; // an HTTP upgrade request is tiny

/** A raw byte duplex (no framing): the transport under the WS codec. Each target
 *  adapts its socket to this shape; the WS channel does the RFC 6455 framing on
 *  top. Writes issued before the underlying socket connects must buffer (the
 *  client sends its upgrade request immediately), mirroring node:net. */
export interface RawByteStream {
  write(bytes: Uint8Array): void;
  onData(cb: (chunk: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  close(): void;
}

const utf8 = new TextEncoder();

abstract class WsChannelBase implements RawChannel {
  private onMsg: ((bytes: Uint8Array) => void) | null = null;
  private onCls: (() => void) | null = null;
  private readonly parser: WsParser;
  private opened = false;
  private dead = false;
  private handshake = new Uint8Array(0);
  private readonly pending: Uint8Array[] = [];

  constructor(protected readonly stream: RawByteStream, expectMasked: boolean) {
    this.parser = new WsParser(expectMasked);
    stream.onData((chunk) => this.onData(chunk));
    stream.onClose(() => this.fail());
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
    if (!this.opened) { this.pending.push(bytes); return; }
    this.stream.write(encodeFrame(WS_OPCODES.OP_BINARY, bytes, this.mask()));
  }
  onMessage(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; }
  onClose(cb: () => void): void { this.onCls = cb; }
  close(): void { if (!this.dead) { this.dead = true; this.stream.close(); } }

  // Failure teardown: close the stream AND notify onClose. close() (the
  // deliberate path) sets `dead` first, so a fail() that follows it stays silent
  // — but an error on a live channel must always reach onClose, or the owning
  // PeerLink is never forgotten from the routing maps and the peer is blackholed.
  private fail(): void { if (this.dead) return; this.dead = true; this.stream.close(); this.onCls?.(); }

  private onData(chunk: Uint8Array): void {
    if (this.dead) return;
    if (!this.opened) {
      const merged = new Uint8Array(this.handshake.length + chunk.length);
      merged.set(this.handshake, 0); merged.set(chunk, this.handshake.length);
      this.handshake = merged;
      let consumed: number;
      try { consumed = this.tryHandshake(this.handshake); }
      catch { this.fail(); return; }
      // wait for the rest of the head, but never hoard unbounded bytes
      if (consumed < 0) { if (this.handshake.length > MAX_WS_HANDSHAKE) this.fail(); return; }
      this.opened = true;
      for (const b of this.pending) this.stream.write(encodeFrame(WS_OPCODES.OP_BINARY, b, this.mask()));
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
      else if (f.opcode === WS_OPCODES.OP_PING) this.stream.write(encodeFrame(WS_OPCODES.OP_PONG, f.payload, this.mask()));
      else if (f.opcode === WS_OPCODES.OP_CLOSE) { this.fail(); return; }
    }
  }
}

// The connection the *server* accepted: read the client's HTTP upgrade request,
// reply 101 with the computed accept, then expect masked frames.
export class WsServerChannel extends WsChannelBase {
  constructor(stream: RawByteStream) {
    super(stream, true); // client frames are masked
  }

  protected mask(): Uint8Array | null { return null; }

  protected tryHandshake(buf: Uint8Array): number {
    const sep = indexOfCRLFCRLF(buf);
    if (sep < 0) return -1;
    const header = new TextDecoder().decode(buf.subarray(0, sep));
    const key = headerValue(header, "sec-websocket-key");
    if (!key) throw new Error("ws: missing Sec-WebSocket-Key");
    this.stream.write(utf8.encode(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${wsAcceptKey(key)}\r\n\r\n`,
    ));
    return sep + 4;
  }
}

// The connection we *dial out* (e.g. a Node peer reaching a node's WS endpoint, or
// the engine dialing one). The browser uses its platform WebSocket instead. The
// upgrade request is written immediately; the RawByteStream buffers it until the
// socket connects.
export class WsClientChannel extends WsChannelBase {
  private readonly expectAccept: string;

  constructor(stream: RawByteStream, host: string, port: number, private readonly sodium: TransportCrypto) {
    super(stream, false); // server frames are unmasked
    const { key, expectAccept } = wsClientKey(sodium.randombytes_buf(16));
    this.expectAccept = expectAccept;
    stream.write(utf8.encode(
      `GET / HTTP/1.1\r\nHost: ${host}:${port}\r\n` +
      "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
      `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
    ));
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
