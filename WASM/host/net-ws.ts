// The browser↔node edge over a plain WebSocket. A browser cannot open raw TCP, and WebRTC
// (net-rtc.ts) needs a signaling relay plus STUN; when a node is directly reachable, the
// simplest path is a WebSocket straight at its --ws-listen endpoint.
//
// The browser end of the socket seam and nothing more: it opens platform WebSockets and
// hands them to the driver's `openLink()`. Everything above — the handshake, the record
// layer, the routing — is the transport bundle's, identical to the TCP path. The WebSocket
// global is touched only inside a dial (or an injected factory), so importing it where
// WebSocket is absent is safe.
import type { PeerId } from "../core/socket-seam.js";
import { MessageChannel, SingleIdentityNetwork } from "./net-channel.js";
import { parsePeerRef } from "./peer-addr.js";
import type { TransportHost, LinkHandle } from "./transport-host.js";

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
  /** The platform's concrete channel adapter. It holds the node identity, the network key,
   *  the contact secret and the peer lint; this file only opens sockets. */
  driver: TransportHost;
  /** Open a WebSocket to `url`. Defaults to the platform global. */
  webSocketFactory?: (url: string) => WsLike;
  /** Called when a peer's link authenticates / drops. */
  onPeerUp?: (peerId: PeerId) => void;
  onPeerDown?: (peerId: PeerId) => void;
  /** How many parallel connections to open per peer (default 1). A bulk transfer stripes
   *  its frames across them — each its own link and record session — so a high-RTT link a
   *  single TCP flow cannot fill is filled by N. The peer must accept multiple inbound
   *  links for this to take effect. */
  connsPerPeer?: number;
}

export class WsNetwork extends SingleIdentityNetwork {
  private readonly mkWs: (url: string) => WsLike;
  private readonly conns: number;
  private readonly dialing = new Map<PeerId, LinkHandle[]>(); // every link we have dialed to a peer

  constructor(private readonly opts: WsNetworkOptions) {
    super(opts.driver, { onPeerUp: opts.onPeerUp, onPeerDown: opts.onPeerDown });
    this.mkWs = opts.webSocketFactory
      ?? ((url: string) => new (globalThis as unknown as { WebSocket: new (u: string) => WsLike }).WebSocket(url));
    this.conns = Math.max(1, Math.floor(opts.connsPerPeer ?? 1));
  }

  // ── Network interface ──────────────────────────────────────────────────────────

  /** Dial a cohort peer given `pubkey@host:port` (or `pubkey@ws://host:port[/path]`,
   *  `wss://…` for TLS). The link authenticates in-channel, pinned to the declared
   *  `pubkey`, and onPeerUp fires once it does. An idempotent top-up: it opens only the
   *  shortfall to connsPerPeer, and returns the parsed peer id either way. */
  connect(spec: string): PeerId {
    const { peerId, contactSecret, url } = parseWsPeer(spec);
    if (peerId === this.ownId) return peerId;
    // `dialing` holds every live link dialed to this peer, pre- and post-auth, so its
    // length is the current outbound flow count.
    let arr = this.dialing.get(peerId);
    if (!arr) {
      arr = [];
      this.dialing.set(peerId, arr);
    }
    for (let i = arr.length; i < this.conns; i++) {
      const handle: LinkHandle = this.driver.openLink({
        channel: new WsChannel(this.mkWs(url)),
        weDialed: true,
        expectPeerId: peerId, // pin the far key to the address we dialed
        // DIALING gates on THEIR secret, from the peer spec: passing ours would seal msg1
        // under a secret the peer has never seen, so every dial would draw silence.
        contactSecret,
        onAuth: () => this.peerUp(peerId),
        onClose: () => { this.peerDown(peerId); this.forget(peerId, handle); },
      });
      arr.push(handle);
    }
    return peerId;
  }

  /** Tear down every link and the driver's channels. */
  close(): void {
    const pending: LinkHandle[] = [];
    for (const arr of this.dialing.values()) for (const l of arr) pending.push(l);
    this.dialing.clear();
    for (const l of pending) l.close();
  }

  // A link died, or the peer lint declined it: drop it from the outbound pool. The router
  // bookkeeping is the guest's.
  private forget(peerId: PeerId, handle: LinkHandle): void {
    const dl = this.dialing.get(peerId);
    if (dl) {
      const i = dl.indexOf(handle);
      if (i >= 0) dl.splice(i, 1);
      if (dl.length === 0) this.dialing.delete(peerId);
    }
  }
}

/** Parse a `pubkey@host:port` (or `pubkey@ws://host:port[/path]`) cohort peer spec
 *  into the peer id + the WebSocket URL to dial. A bare host:port defaults to the
 *  ws:// scheme; pass wss:// explicitly for TLS.
 *
 *  Who the peer is comes from `parsePeerRef` (peer-addr.ts), the one place that grammar is
 *  written; this edge's address form being a URL is the only reason a second entry point
 *  exists. */
export function parseWsPeer(spec: string): { peerId: PeerId; contactSecret?: Uint8Array; url: string } {
  const { peerId, contactSecret, location } = parsePeerRef(spec);
  const url = (location.startsWith("ws://") || location.startsWith("wss://")) ? location : "ws://" + location;
  return { peerId, contactSecret, url };
}
