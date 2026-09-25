// The browser end of the socket seam (§12.6): a `ChannelFactory` that dials platform
// WebSockets, for a directly reachable node. What to dial and when is the transport's.
// The WebSocket global is touched only inside `connect`, so importing this is safe where
// it is absent.
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

  /** Parsed rather than passed through, so a malformed destination or `tcp://` reads
   *  "no route" instead of a platform throw. */
  connect(dest: string): RawLink | null {
    const d = parseDest(dest);
    if (!d || d.scheme === "tcp") return null;
    // Whole messages in order, so `MessageChannel` fits unchanged, pre-open buffer included.
    return new MessageChannel(this.mkWs(`${d.scheme}://${d.host}:${d.port}${d.path ?? ""}`));
  }

  /** A browser binds nothing. */
  async listen(addrs: readonly ListenAddress[]): Promise<number[]> {
    return addrs.map(() => 0);
  }

  /** Nothing to release: the driver closes the channels it holds. */
  close(): void { /* no listeners, no owned sockets */ }
}
