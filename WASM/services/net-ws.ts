// The browser end of the socket seam (README §12.6): a `ChannelFactory` that dials
// platform WebSockets. A browser cannot open raw TCP, and WebRTC (net-rtc.ts) needs a
// signaling relay plus STUN; when a node is directly reachable, the simplest path is a
// WebSocket straight at a listener whose label its transport reads as WebSocket.
//
// Every destination this factory dials is named by `link/open` — a peer out of the address
// book the transport GUEST holds, or the relay its WebRTC signaling rides — so what, when,
// and how many times are all its signed policy, not this file's. Everything above the
// socket — the handshake, the record layer, the routing — is the transport bundle's.
// The WebSocket global is touched only inside `connect` (or an injected factory), so
// importing it where WebSocket is absent is safe.
import type { ChannelFactory, ListenAddress, RawLink } from "./socket-seam.js";
import { MessageChannel, type MessageTransport } from "./net-channel.js";
import { parseDest } from "./peer-addr.js";

export interface WsNetworkOptions {
  /** Open a WebSocket to `url`. Defaults to the platform global; any object meeting
   *  `MessageTransport` (Bun's WebSocket, a test double) is accepted. */
  webSocketFactory?: (url: string) => MessageTransport;
}

export class WsNetwork implements ChannelFactory {
  private readonly mkWs: (url: string) => MessageTransport;

  constructor(opts: WsNetworkOptions = {}) {
    this.mkWs = opts.webSocketFactory
      ?? ((url: string) => new (globalThis as unknown as { WebSocket: new (u: string) => MessageTransport }).WebSocket(url));
  }

  /** A destination is already a URL a browser `WebSocket` takes — `wss://` is how a
   *  deployment asks for TLS, and the path is what a peer behind a reverse proxy answers on.
   *  It is still parsed rather than passed through, so a malformed one reads "no route"
   *  instead of reaching the platform as a URL to throw on, and `tcp://` — a real
   *  destination that no browser can open — reads the same. */
  connect(dest: string): RawLink | null {
    const d = parseDest(dest);
    if (!d || d.scheme === "tcp") return null;
    // A WebSocket delivers whole binary messages in order, so `MessageChannel`
    // (net-channel.ts) is the adapter unchanged — including its pre-open send buffer, which
    // the transport needs because it emits its HELLO the instant a link is constructed.
    return new MessageChannel(this.mkWs(`${d.scheme}://${d.host}:${d.port}${d.path ?? ""}`));
  }

  /** A browser binds nothing: every inbound link here is dialed by the far end at us as
   *  a client, never accepted by this factory. */
  async listen(addrs: readonly ListenAddress[]): Promise<number[]> {
    return addrs.map(() => 0);
  }

  /** Nothing to release: the driver closes the channels it holds. */
  close(): void { /* no listeners, no owned sockets */ }
}
