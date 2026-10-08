// The browser's socket seam (§12.6): a `ChannelFactory` that dials platform WebSockets to
// a directly reachable node. The transport decides what to dial and when. The WebSocket
// global is used only inside `connect`, so importing this is safe where it is absent.
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

  /** Parsed instead of passed through, so a malformed destination or `tcp://` gives
   *  "no route" instead of a platform error. */
  connect(dest: string): RawLink | null {
    const d = parseDest(dest);
    if (!d || d.scheme === "tcp") return null;
    // `parseDest` hands back an IPv6 host bare, and a URL wants its brackets.
    const host = d.host.includes(":") ? `[${d.host}]` : d.host;
    // Whole messages in order, so `MessageChannel` fits unchanged, pre-open buffer included.
    return new MessageChannel(this.mkWs(`${d.scheme}://${host}:${d.port}${d.path ?? ""}`));
  }

  /** A browser binds nothing. */
  async listen(addrs: readonly ListenAddress[]): Promise<number[]> {
    return addrs.map(() => 0);
  }

  /** Nothing to release: the driver closes the channels it holds. */
  close(): void { /* no listeners, no owned sockets */ }
}
