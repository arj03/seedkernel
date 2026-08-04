// socket-seam.ts — the socket-side types shared by the host's raw-I/O layers.
//
// What these types describe is the CORE seam (README §12.1, §12.6): bytes to and from
// an opaque link over an already-ordered channel. Everything structural above them —
// the wire codec, the AKE, the record layer, link routing, the request/response layer
// — is the transport bundle's guest program, driven through host/transport-host.ts.
// This file is the shapes the socket adapters (net-node, net-ws, net-rtc, net-channel)
// compile against, and the identity/crypto shapes the driver passes through.

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

/** One link, as the platform hands it to the driver. The transport bundle never sees
 *  the object: the driver (transport-host.ts) wires it to the guest by a host-supplied
 *  link id, and bytes cross as events/actions.
 *
 *  **Some platform transports have message boundaries and some do not.** A browser
 *  WebSocket and an RTCDataChannel arrive already framed; a TCP socket is a byte duplex
 *  whose boundaries are the transport's to impose. A seam that presented one shape
 *  would not remove that difference, only hide it — and it could hide it only by
 *  framing in the host, which is content living below the seam. So the link states its
 *  `framing` and the guest branches on it. */
export interface RawLink {
  send(bytes: Uint8Array): void;
  /** Inbound bytes. `framing` says what one call means: a whole message, or an
   *  arbitrary slice of a stream with no boundary implied. */
  onData(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  /** Tear the link down. `graceful` asks the transport to flush already-written bytes
 *  first; the guest passes true only after writing its end-of-stream record, because a
 *  transport that discards that write turns a clean close into exactly the truncation
 *  the record exists to rule out. */
  close(graceful?: boolean): void;
  /** Bytes written to this link that the transport has NOT yet put on the wire.
 *  The one thing that distinguishes a slow exchange from a stalled one: a request whose
 *  bytes are still draining is progressing, however long it is taking, while one whose
 *  backlog has not moved is waiting on the far end. The transport bundle's stall clock
 *  polls it (NET_LINK_STAT) rather than timing an exchange from the moment it was
 *  *queued*, which would measure our own upload and cancel healthy requests under
 *  backpressure. Optional: a transport that cannot say returns nothing and the clock
 *  falls back to a plain deadline. */
  buffered?(): number;
  /** Optional transport-supplied identifier for the far end (an IP, say), used only to
 *  bucket the per-source half-open cap — enforced in the transport bundle. Optional
 *  because not every transport has one. NEVER an identity. */
  readonly remoteAddr?: string;
  /** How this link is framed — `FRAMING.PLATFORM` when the transport under it already
   *  has message boundaries (a browser WebSocket, an RTCDataChannel), otherwise which
   *  wire codec the transport bundle must run over the byte duplex. The host knows only
   *  because it dialed the address; what to DO about it is entirely the bundle's. */
  readonly framing: Framing;
  /** The `host:port` this link was dialed at — the one thing a wire codec needs that
   *  only the address knows (a WebSocket client's `Host` header). Set on dialed WS
   *  links and nowhere else: it is the authority of a link the host has ALREADY opened,
   *  never a route the bundle could dial for itself. */
  readonly authority?: string;
}

/** The wire codecs a link can need, as the host declares one at open (§12.1).
 *
 *  This is the whole of what the platform says about framing, and it is deliberately a
 *  closed set of *codecs* rather than a description of the socket: the host is not
 *  telling the bundle what the transport is, it is telling it which of the codecs it
 *  already knows applies here. Adding one is a bundle change plus one constant. */
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
 *  TCP/WS dialing and listening behind the RawLink shape; everything above is
 *  the transport bundle's shared code (driven by the host). */
export interface ChannelFactory {
  /** Dial a peer; returns a RawLink that connects in the background. */
  connect(addr: PeerAddr): RawLink;
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
