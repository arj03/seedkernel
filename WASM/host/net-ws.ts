// The browser end of the socket seam (README §12.6): a `ChannelFactory` that dials
// platform WebSockets. A browser cannot open raw TCP, and WebRTC (net-rtc.ts) needs a
// signaling relay plus STUN; when a node is directly reachable, the simplest path is a
// WebSocket straight at its --ws-listen endpoint.
//
// The peer this factory dials is named by `link/open`, out of the address book the
// transport GUEST holds — so which peers, when, and how many times are all its signed
// policy (`connsPerPeer`), not this file's. Everything above the socket — the handshake,
// the record layer, the routing — is the transport bundle's, identical to the TCP path.
// The WebSocket global is touched only inside `connect` (or an injected factory), so
// importing it where WebSocket is absent is safe.
import type { ChannelFactory, RawLink } from "../core/socket-seam.js";
import { MessageChannel } from "./net-channel.js";
import { parseDest } from "./peer-addr.js";

/** The minimal structural view of the platform WebSocket that WsChannel uses — so
 *  this module type-checks without committing to a DOM lib and accepts any
 *  conforming implementation (the browser global, Bun's, or a test double). */
export interface WsLike {
  binaryType: string;
  /** Bytes queued but not yet on the wire — the stall clock's progress signal
   *  (socket-seam.ts `RawLink.buffered`). Optional: not every WebSocket-shaped
   *  object in a test double reports it. */
  bufferedAmount?: number;
  send(data: Uint8Array): void;
  close(): void;
  addEventListener(type: "open" | "close" | "error", cb: () => void): void;
  addEventListener(type: "message", cb: (ev: { data: unknown }) => void): void;
}

// A WebSocket delivers whole binary messages in order, so this is a thin adapter over
// MessageChannel (net-channel.ts) — including its pre-open send buffer, which the transport
// needs because it emits its HELLO the instant a link is constructed.
export class WsChannel extends MessageChannel {
  constructor(ws: WsLike) { super(ws); }
}

export interface WsNetworkOptions {
  /** Open a WebSocket to `url`. Defaults to the platform global. */
  webSocketFactory?: (url: string) => WsLike;
}

export class WsNetwork implements ChannelFactory {
  private readonly mkWs: (url: string) => WsLike;

  constructor(opts: WsNetworkOptions = {}) {
    this.mkWs = opts.webSocketFactory
      ?? ((url: string) => new (globalThis as unknown as { WebSocket: new (u: string) => WsLike }).WebSocket(url));
  }

  /** A destination is already a URL a browser `WebSocket` takes — `wss://` is how a
   *  deployment asks for TLS, and the path is what a peer behind a reverse proxy answers on.
   *  It is still parsed rather than passed through, so a malformed one reads "no route"
   *  instead of reaching the platform as a URL to throw on, and `tcp://` — a real
   *  destination that no browser can open — reads the same. */
  connect(dest: string): RawLink | null {
    const d = parseDest(dest);
    if (!d || d.scheme === "tcp") return null;
    return new WsChannel(this.mkWs(`${d.scheme}://${d.host}:${d.port}${d.path ?? ""}`));
  }

  /** A browser binds nothing: every inbound link here is dialed by the far end at us as
   *  a client, never accepted by this factory. */
  async listen(
    _tcp: { host: string; port: number } | undefined,
    _ws: { host: string; port: number } | undefined,
    _onAccept: (channel: RawLink) => void,
  ): Promise<{ port: number; wsPort: number }> {
    return { port: 0, wsPort: 0 };
  }

  /** Nothing to release: the driver closes the channels it holds. */
  close(): void { /* no listeners, no owned sockets */ }
}
