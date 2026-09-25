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
  /** Bytes awaiting transmission, drained in send order: the only release signal
   *  `LinkOutboundOwner` has. Omit only when nothing is retained past `send`. A throw
   *  fails the link. */
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
  /** The link this one arrived through (a data channel's negotiation link). */
  readonly via?: RawLink;
}

/** Where a listener binds; port 0 asks the OS. The label reaches the occupant with every
 *  accepted link, so which codec a listener speaks is the transport's to decide. */
export interface ListenAddress {
  label: string;
  host: string;
  port: number;
}

export interface ChannelFactory {
  connect?(dest: string): RawLink | null;
  /** Bind what this factory can and hand every platform-opened link to `onAccept`.
   *  Answers each address's bound port in order, 0 for one it does not bind. */
  listen(
    addrs: readonly ListenAddress[],
    onAccept: (channel: RawLink, arrival?: Arrival) => void,
  ): Promise<number[]>;
  /** Stop the listeners. Open channels are closed by the core. */
  close(): void;
}

/** Several factories as one: a destination goes to the first that routes it; every
 *  factory gets the addresses and the accept sink. */
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
