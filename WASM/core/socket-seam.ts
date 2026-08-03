// socket-seam.ts — the socket-side types shared by the host's raw-I/O layers
// after the transport itself moved into the signed transport bundle
// (§12.6).
//
// What these types describe is the CORE seam (README §12.1, §12.6): whole bytes
// to and from an opaque peer over an already-ordered channel, plus the flood
// limits that must sit with whoever holds the descriptor. Everything structural
// above them — the AKE, the record layer, link routing, the request/response
// layer — now lives in the transport bundle's guest program, driven through
// host/transport-host.ts. This file is what remains: the shapes the socket
// adapters (net-node, net-ws, net-rtc, net-frame, net-channel) still compile
// against, and the identity/crypto shapes the driver passes through.

import { fromHex } from "./util.js";
import type { PeerId } from "./net.js";

/** A peer identity — the node's kernel ed25519 keypair (README §12.6). */
export interface Identity {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** The narrow libsodium surface the channel handshake needs: sign/verify the
 *  handshake transcript, an ephemeral X25519 key exchange, a KDF (BLAKE2b) for
 *  the session keys, ChaCha20-Poly1305 for the record layer, and a CSPRNG for
 *  nonces. Any libsodium build satisfies it structurally, so the seam need not
 *  depend on a specific sodium type. */
export interface TransportCrypto {
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  crypto_box_keypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_scalarmult(sk: Uint8Array, pk: Uint8Array): Uint8Array;
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  crypto_aead_chacha20poly1305_ietf_encrypt(
    message: Uint8Array, additional_data: Uint8Array | null, secret_nonce: Uint8Array | null,
    public_nonce: Uint8Array, key: Uint8Array,
  ): Uint8Array;
  crypto_aead_chacha20poly1305_ietf_decrypt(
    secret_nonce: Uint8Array | null, ciphertext: Uint8Array, additional_data: Uint8Array | null,
    public_nonce: Uint8Array, key: Uint8Array,
  ): Uint8Array;
  randombytes_buf(length: number): Uint8Array;
}

/** A bidirectional channel that delivers whole messages atomically. The transport
 *  bundle never sees one of these: the driver (transport-host.ts) wires a channel
 *  to the guest by a host-supplied link id, and bytes cross as events/actions. */
export interface RawChannel {
  send(bytes: Uint8Array): void;
  onMessage(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  /** Tear the channel down. `graceful` asks the transport to flush already-written
 *  bytes first; the guest passes true only after writing its end-of-stream record,
 *  because a transport that discards that write turns a clean close into exactly
 *  the truncation the record exists to rule out. */
  close(graceful?: boolean): void;
  /** Raise this channel's inbound frame cap from MAX_HANDSHAKE_FRAME_BYTES to
 *  MAX_FRAME_BYTES. The guest asks for it once, on authentication. Optional
 *  because a transport with its own message boundaries (an RTCDataChannel) has
 *  nothing to reassemble and so nothing to bound. */
  allowLargeFrames?(): void;
  /** Bytes written to this channel that the transport has NOT yet put on the wire.
 *  The one thing that distinguishes a slow exchange from a stalled one: a request
 *  whose bytes are still draining is progressing, however long it is taking, while
 *  one whose backlog has not moved is waiting on the far end. The transport
 *  bundle's stall clock polls it (NET_LINK_STAT) instead of timing an exchange from
 *  the moment it was *queued*, which measured our own upload and cancelled healthy
 *  requests under backpressure. Optional: a transport that cannot say returns
 *  nothing and the clock falls back to a plain deadline. */
  buffered?(): number;
  /** Optional transport-supplied identifier for the far end (an IP, say), used
 *  only to bucket the per-source half-open cap — enforced in the transport
 *  bundle. Optional because not every transport has one. NEVER an identity. */
  readonly remoteAddr?: string;
}

/** A raw byte duplex (no framing): the transport under the WS codec. Each target
 *  adapts its socket to this shape (net-frame.ts's WsChannelBase does the RFC 6455
 *  framing on top). */
export interface RawByteStream {
  write(bytes: Uint8Array): void;
  onData(cb: (chunk: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  close(): void;
  /** Written-but-unsent bytes, if this stream's backend can say — the same progress
   *  signal `RawChannel.buffered` reports, one layer down. */
  buffered?(): number;
}

/** How a peer is reachable (README §12.6). The optional contact secret is THE
 *  PEER's, which is what makes an address a credential rather than merely a
 *  location. */
export interface PeerAddr {
  host: string;
  port: number;
  transport: "tcp" | "ws";
  contactSecret?: Uint8Array;
}

/** How the routing core opens sockets — the one platform seam. A target supplies
 *  TCP/WS dialing and listening behind the RawChannel shape; everything above is
 *  the transport bundle's shared code (driven by the host). */
export interface ChannelFactory {
  /** Dial a peer; returns a RawChannel that connects in the background. */
  connect(addr: PeerAddr): RawChannel;
  /** Bind the requested listeners, invoking onAccept(channel) for each inbound
 *  connection; resolves with the bound ports (0 where not listening). */
  listen(
    tcp: { host: string; port: number } | undefined,
    ws: { host: string; port: number } | undefined,
    onAccept: (channel: RawChannel) => void,
  ): Promise<{ port: number; wsPort: number }>;
  /** Stop the listeners. Open channels are closed by the core. */
  close(): void;
}

// ── peer-spec parsing ─────────────────────────────────────────────────────────

/** Parse a `pk[.secret]@host:port` peer spec into the peer id + address to dial.
 *  Here rather than with the driver because what it produces is a `PeerAddr` — a core
 *  type — and a target parses its own `--peer` flags long before any transport stands.
 *  `pk` names WHO lives there and keys the address book; the optional `.secret`
 *  is THAT PEER's contact secret, which is what makes the address a credential. */
export function parsePeerSpec(spec: string, transport: "tcp" | "ws"): { peerId: PeerId; addr: PeerAddr } {
  const at = spec.indexOf("@");
  if (at < 0) throw new Error(`bad peer spec (want pk[.secret]@host:port): ${spec}`);
  const idPart = spec.slice(0, at).toLowerCase();
  const dot = idPart.indexOf(".");
  const peerId = dot < 0 ? idPart : idPart.slice(0, dot);
  if (peerId.length !== 64 || /[^0-9a-f]/.test(peerId)) throw new Error(`bad peer pubkey hex: ${spec}`);
  let contactSecret: Uint8Array | undefined;
  if (dot >= 0) {
    const hex = idPart.slice(dot + 1);
    if (hex.length !== 64 || /[^0-9a-f]/.test(hex)) {
      throw new Error(`bad peer contact secret hex (want 32 bytes): ${spec}`);
    }
    contactSecret = fromHex(hex);
  }
  const hostPort = spec.slice(at + 1);
  const colon = hostPort.lastIndexOf(":");
  if (colon < 0) throw new Error(`bad peer host:port: ${spec}`);
  const host = hostPort.slice(0, colon);
  const port = Number(hostPort.slice(colon + 1));
  if (!Number.isInteger(port) || port <= 0) throw new Error(`bad peer port: ${spec}`);
  return { peerId, addr: { host, port, transport, contactSecret } };
}
