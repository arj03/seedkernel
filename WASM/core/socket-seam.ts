// Socket-side types for raw I/O (§12.1, §12.6). Codec/AKE/routing live in the
// transport bundle. A link states its `framing`; the guest branches on it.

/** One link as the platform hands it to the driver. States its `framing`; guest branches. */
export interface RawLink {
  send(bytes: Uint8Array): void;
  /** Inbound bytes. `framing` says what one call means: a whole message, or an arbitrary
   *  slice of a stream with no boundary implied. */
  onData(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  /** Tear the link down. `graceful` asks the transport to flush already-written bytes;
   *  the guest passes true only after writing its end-of-stream record. */
  close(graceful?: boolean): void;
  /** Bytes written but not yet on the wire — what distinguishes a slow exchange from a
   *  stalled one; the bundle's stall clock polls this (link/stat) rather than timing from
   *  queue. Optional: a transport that cannot say leaves the clock a plain deadline. */
  buffered?(): number;
  /** Optional transport-supplied identifier for the far end (an IP, say), used only to
   *  bucket the per-source half-open cap — enforced in the transport bundle. NEVER an
   *  identity. */
  readonly remoteAddr?: string;
  /** How this link is framed: `FRAMING.PLATFORM` when the transport already has message
   *  boundaries, else which wire codec the bundle must run over the byte duplex. */
  readonly framing: Framing;
  /** The `host:port` this link was dialed at — the one thing a wire codec needs that only
   *  the address knows. Set on dialed WS links and nowhere else, never a route the bundle
   *  could dial for itself. */
  readonly authority?: string;
  /** Whether THIS end opened the connection. Default false — a link the platform hands
   *  over is an accept unless it says otherwise, and only the dialing side speaks
   *  unprompted (§12.6.2). Set by a factory that dials on its own initiative: WebRTC,
   *  where the polite/impolite tie-break decides who opens the channel. A link the guest
   *  asked for (`link/open`) is a dial by construction and states nothing here. */
  readonly weDialed?: boolean;
  /** Who this end expects to find, lowercase hex — the handshake is refused if the far
   *  end proves a different key. Meaningful only with `weDialed`, and only from a factory
   *  that chose the peer itself (signaling named it); a guest dial pins the key it looked
   *  the address up under. */
  readonly expectPeerId?: PeerId;
}

/** The wire codecs a link can need, as the host declares one at open (§12.1). A closed set
 *  of *codecs*, not a description of the socket: the host says only which codec the bundle
 *  already knows applies here. */
export const FRAMING = {
  /** The transport already delivers whole messages; the bundle frames nothing. */
  PLATFORM: 0,
  /** `[len u32 BE][bytes]` over a byte duplex — node↔node TCP. */
  LENGTH: 1,
  /** RFC 6455, this end being the one that dialed (masks its frames, sends the upgrade). */
  WS_CLIENT: 2,
  /** RFC 6455, this end having accepted (answers the upgrade, expects masked frames). */
  WS_SERVER: 3,
} as const;
export type Framing = (typeof FRAMING)[keyof typeof FRAMING];

/** WHO a peer is: its 32-byte channel public key, lowercase hex — the one identity the
 *  address book is keyed on and the one every attributed frame names, and all the host has
 *  left to say about a peer, the transport being a guest. */
export type PeerId = string;

/** How a peer is reachable (README §12.6). The optional contact secret is THE PEER's,
 *  which is what makes an address a credential rather than merely a location. */
export interface PeerAddr {
  host: string;
  port: number;
  transport: "tcp" | "ws";
  contactSecret?: Uint8Array;
  /** The request target a WS peer answers on, when it is not the root — a deployment
   *  behind a reverse proxy is reached at a path, and the browser's `WebSocket` takes the
   *  whole URL. Carried on the address because that is the only place that knows it; a
   *  target whose codec cannot name a request target ignores it. */
  path?: string;
}

/** How the routing core opens sockets — the one platform seam. A target supplies
 *  TCP/WS dialing and listening behind the RawLink shape; everything above is
 *  the transport bundle's shared code (driven by the host). */
export interface ChannelFactory {
  /** Dial a peer; returns a RawLink that connects in the background. Absent for a factory
   *  that only ever accepts (WebRTC, whose peers arrive through signaling rather than from
   *  an address) — the driver answers `link/open` "no route" for it. */
  connect?(addr: PeerAddr): RawLink;
  /** Bind the requested listeners, invoking onAccept(channel) for each inbound
 *  connection; resolves with the bound ports (0 where not listening). */
  listen(
    tcp: { host: string; port: number } | undefined,
    ws: { host: string; port: number } | undefined,
    onAccept: (channel: RawLink) => void,
  ): Promise<{ port: number; wsPort: number }>;
  /** Stop the listeners. Open channels are closed by the core. */
  close(): void;
}
