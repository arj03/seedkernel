// The browser end of the socket seam (README §12.6): a `ChannelFactory` that dials
// platform WebSockets. A browser cannot open raw TCP, and WebRTC (net-rtc.ts) needs a
// signaling relay plus STUN; when a node is directly reachable, the simplest path is a
// WebSocket straight at its --ws-listen endpoint.
//
// The peer this factory dials comes from the driver's address book (`addPeerAddr`), fed
// by `link/open` — so the guest decides when and how many times to dial. `connsPerPeer`
// is the transport bundle's signed policy now, not this file's. Everything above the
// socket — the handshake, the record layer, the routing — is the transport bundle's,
// identical to the TCP path. The WebSocket global is touched only inside `connect` (or an
// injected factory), so importing it where WebSocket is absent is safe.
import type { ChannelFactory, PeerAddr, RawLink } from "../core/socket-seam.js";
import { MessageChannel } from "./net-channel.js";

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

/** The whole URL back out of the address (`peer-addr.ts` `parsePeerSpec` put it there). A
 *  host carrying an explicit `wss://` is how a deployment asks for TLS, a bare host
 *  defaults to `ws://`, and the path is what a peer behind a reverse proxy answers on. */
function wsUrl(addr: PeerAddr): string {
  const origin = (addr.host.includes("://") ? addr.host : "ws://" + addr.host) + ":" + addr.port;
  return origin + (addr.path ?? "");
}

export class WsNetwork implements ChannelFactory {
  private readonly mkWs: (url: string) => WsLike;

  constructor(opts: WsNetworkOptions = {}) {
    this.mkWs = opts.webSocketFactory
      ?? ((url: string) => new (globalThis as unknown as { WebSocket: new (u: string) => WsLike }).WebSocket(url));
  }

  connect(addr: PeerAddr): RawLink {
    return new WsChannel(this.mkWs(wsUrl(addr)));
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
