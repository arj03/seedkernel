// Raw socket ABI (§12.1). Framing and routing belong to the transport bundle.

export interface RawLink {
  send(bytes: Uint8Array): void;
  /** One message, or an arbitrary slice when `stream` is true. */
  onData(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  /** `graceful` permits flushing queued writes. */
  close(graceful?: boolean): void;
  /** Bytes awaiting transmission, used for stall detection. */
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

export interface ChannelFactory {
  connect?(dest: string): RawLink | null;
  listen(
    tcp: { host: string; port: number } | undefined,
    ws: { host: string; port: number } | undefined,
    onAccept: (channel: RawLink, arrival?: Arrival) => void,
  ): Promise<{ port: number; wsPort: number }>;
  /** Stop the listeners. Open channels are closed by the core. */
  close(): void;
}
