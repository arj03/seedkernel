// Raw socket ABI (§12.1). Framing and routing belong to the transport bundle.

export interface RawLink {
  send(bytes: Uint8Array): void;
  /** One message, or an arbitrary slice when `stream` is true. */
  onData(cb: (bytes: Uint8Array) => void): void;
  /** Stop/start inbound delivery around one serialized transport-realm turn. Optional;
   * TransportHost gives adapters without platform backpressure one fallback message. */
  setReadable?(enabled: boolean): void;
  onClose(cb: () => void): void;
  /** `graceful` permits flushing queued writes. */
  close(graceful?: boolean): void;
  /** Bytes awaiting transmission: the only release signal `LinkOutboundOwner`
   *  (transport-host.ts) has as writes leave this adapter, read
   *  as a SUFFIX of the writes it admitted — an adapter draining out of send order would
   *  retire the wrong slices. Omit it only when nothing is retained past `send`; omitting
   *  it while really buffering grows the link's charge to the ceiling with an empty
   *  socket. Implemented, it must answer — one that throws fails its link rather than
   *  reading as "holding nothing". */
  buffered?(): number;
  /** Unauthenticated key for per-source limits; never a peer identity. */
  readonly remoteAddr?: string;
  /** Whether `onData` delivers arbitrary byte-stream slices. */
  readonly stream?: boolean;
}

/** Metadata for a platform-opened socket. Guest-opened links have none. */
export interface Arrival {
  /** Opaque listener label used by the bundle to select framing. */
  readonly listener?: string;
  /** Set for platform-initiated dials such as WebRTC. */
  readonly weDialed?: boolean;
  /** Expected peer identity for a platform-initiated dial. */
  readonly expectPeerId?: string;
}

/** Standard listener labels interpreted by the transport bundle. */
export const LISTENER = { TCP: "tcp", WS: "ws" } as const;

/** Where a listener binds: a host and a port, with port 0 meaning "ask the OS". One shape
 *  from the operator's `--listen`/`--ws-listen` through the node config and the driver
 *  down to this seam, so a bind address cannot mean one thing at one end of that chain and
 *  something else at the other. Not a destination: dialing takes a STRING whose scheme the
 *  factory interprets (`connect`, peer-addr.ts `parseDest`). */
export interface ListenAddress {
  host: string;
  port: number;
}

export interface ChannelFactory {
  connect?(dest: string): RawLink | null;
  listen(
    tcp: ListenAddress | undefined,
    ws: ListenAddress | undefined,
    onAccept: (channel: RawLink, arrival?: Arrival) => void,
  ): Promise<{ port: number; wsPort: number }>;
  /** Stop the listeners. Open channels are closed by the core. */
  close(): void;
}
