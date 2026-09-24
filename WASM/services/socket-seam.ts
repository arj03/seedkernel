// Raw socket ABI (§12.1). Framing, routing and every peer-shaped decision belong to the
// transport bundle.

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

/** Metadata for a platform-opened link. Guest-opened links have none. */
export interface Arrival {
  /** The label of the listener that accepted it, passed to the occupant unread. */
  readonly listener?: string;
  /** The link this one arrived through — a WebRTC data channel names the negotiation link
   *  the occupant opened for it. The driver passes the id; what it means is the occupant's. */
  readonly via?: RawLink;
}

/** Where a listener binds: a label, a host and a port, with port 0 meaning "ask the OS".
 *  The label reaches the occupant with every link the listener accepts, unread here, so
 *  what a listener is for — which codec it speaks — is the transport's to decide. Not a
 *  destination: dialing takes a STRING whose scheme the factory interprets (`connect`,
 *  peer-addr.ts `parseDest`). */
export interface ListenAddress {
  label: string;
  host: string;
  port: number;
}

export interface ChannelFactory {
  connect?(dest: string): RawLink | null;
  /** Bind each address this factory can bind and hand every platform-opened link to
   *  `onAccept`. Answers the bound port of each address, in order: 0 for one it does not
   *  bind. A factory that binds nothing still gets the sink — a WebRTC data channel is
   *  platform-opened too. */
  listen(
    addrs: readonly ListenAddress[],
    onAccept: (channel: RawLink, arrival?: Arrival) => void,
  ): Promise<number[]>;
  /** Stop the listeners. Open channels are closed by the core. */
  close(): void;
}

/** Several factories as one: a destination goes to the first that routes it, and every
 *  factory gets the addresses and the accept sink. How a browser node reaches a WebRTC
 *  relay over a WebSocket and its peers over data channels. */
export function combineChannels(...factories: ChannelFactory[]): ChannelFactory {
  return {
    connect(dest) {
      for (const f of factories) {
        const link = f.connect?.(dest) ?? null;
        if (link) return link;
      }
      return null;
    },
    async listen(addrs, onAccept) {
      const bound = await Promise.all(factories.map((f) => f.listen(addrs, onAccept)));
      return addrs.map((_, i) => bound.reduce((port, b) => port || (b[i] ?? 0), 0));
    },
    close() { for (const f of factories) f.close(); },
  };
}
