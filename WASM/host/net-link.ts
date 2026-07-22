// Channel identity binding + forward-secret record layer (README §12.6). A real
// socket carries no trustworthy "from" field, so before a connection is allowed
// to deliver frames it runs a mutual challenge/response that proves each end
// holds the kernel private key for the public key it claims, and — in the same
// exchange — agrees an ephemeral session key. From then on every frame is an
// authenticated, encrypted record attributed to that authenticated identity,
// never to anything inside the frame. This is the node↔node analogue of
// chat-shell.js pinning each data-channel to a kernel pk and dropping envelopes
// signed by anyone else.
//
// PeerLink is transport-agnostic: it drives any RawChannel that delivers whole
// messages (TCP gets message framing from a length prefix; WebSocket already has
// message boundaries). Three short message types ride the channel:
//   HELLO = suite(1) ‖ pubkey(32) ‖ nonce(32) ‖ eph(32)  sent by both ends immediately
//   AUTH  = sign(transcript)(64)                         binds both halves entire
//   FRAME = ChaCha20-Poly1305 record                     only after both authenticate
//
// `eph` is a fresh ephemeral X25519 public key, generated per connection. AUTH
// signs the whole transcript — DOMAIN_CHANNEL ‖ the two (suite ‖ pubkey ‖ nonce ‖ eph)
// halves in a canonical order — not just the peer's nonce. Signing the nonce alone would
// make a node a signing oracle: an attacker could relay a victim's outstanding
// nonce as its own HELLO, collect the node's signature, and replay it on another
// connection to impersonate the node. Binding both identities, both nonces, and
// both ephemeral keys ties every signature to the single exchange that produced
// it, so a harvested one verifies nowhere else — and, because the signature
// covers `eph`, it authenticates the key exchange itself (a SIGMA-style AKE).
//
// Once both AUTHs verify, each end computes the ephemeral–ephemeral DH and derives
// two directional ChaCha20-Poly1305 keys from it and the transcript hash. The
// canonical lo/hi ordering assigns the directions, so both ends agree without
// negotiation. Every post-AUTH FRAME is then an AEAD record under the sending
// direction's key with an implicit monotonic counter as the nonce (never
// transmitted) and strict counter enforcement on receive — individually
// authenticated, confidential, replay-protected, and forward-secret because the
// DH keys are ephemeral. The identity Ed25519 key stays signing-only and never
// takes a DH role.

import { concatBytes, toHex, writeU32BE } from "./util.js";
import { DOMAIN_CHANNEL, SUITE_CHANNEL_GENESIS } from "./domains.js";

/** A peer identity — the node's kernel ed25519 keypair (README §12.6). */
export interface Identity {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** The narrow libsodium surface the channel handshake needs: sign/verify the
 *  handshake transcript, an ephemeral X25519 key exchange, a KDF (BLAKE2b) for
 *  the session keys, ChaCha20-Poly1305 for the record layer, and a CSPRNG for
 *  nonces. Any libsodium build satisfies it structurally, so the transport need
 *  not depend on a specific sodium type. */
export interface TransportCrypto {
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  crypto_box_keypair(): { publicKey: Uint8Array; privateKey: Uint8Array };
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

/** A bidirectional channel that delivers whole messages atomically. */
export interface RawChannel {
  send(bytes: Uint8Array): void;
  onMessage(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  close(): void;
}

const MSG_HELLO = 1, MSG_AUTH = 2, MSG_FRAME = 3;
// Cipher-suite id — the first byte of HELLO and of each transcript half; see domains.ts
// for why it exists and why it is not negotiated. A link speaks exactly one suite: an
// unrecognised id closes the connection, and because the byte sits inside the signed
// transcript, an in-path attacker who flips it only makes the two ends sign different
// bytes, so both AUTHs fail. The suite is chosen by the endpoints, never forced by the
// network (§12.6, §14.1).
const SUITE_LEN = 1;
const PK_LEN = 32, NONCE_LEN = 32, EPH_LEN = 32, SIG_LEN = 64;
const OFF_PK = SUITE_LEN, OFF_NONCE = OFF_PK + PK_LEN, OFF_EPH = OFF_NONCE + NONCE_LEN;
const HELLO_LEN = OFF_EPH + EPH_LEN;
const KEY_LEN = 32, NPUB_LEN = 12, TAG_LEN = 16;
// Directional session-key labels (README §12.6): the `lo` end encrypts with
// k_lo→hi and decrypts with k_hi→lo; the `hi` end mirrors. Distinct constants so
// the two directions never share a key.
const LABEL_LO2HI = new TextEncoder().encode("seedkernel-session-lo->hi-v1\0");
const LABEL_HI2LO = new TextEncoder().encode("seedkernel-session-hi->lo-v1\0");
// Hard cap on one link frame, matching §16.1; the transports enforce it on the
// length prefix (TCP) / frame length (WS) before buffering. Exported so every
// transport caps identically — a frame that crosses one crosses the other.
export const MAX_FRAME_BYTES = 16 * 1024 * 1024; // 16 MiB
// The largest *plaintext* frame send() accepts. Sealing wraps a frame in the 1-byte
// MSG_FRAME tag plus the 16-byte Poly1305 tag, and MAX_FRAME_BYTES is enforced on that
// framed record at the receiver — so a plaintext frame within 17 bytes of the wire cap
// would seal to an over-cap record and be rejected on the receiver's length prefix,
// tearing the whole link down (and every request in flight on it) instead of failing
// gracefully. send() refuses anything above this budget. Exported so callers can size
// payloads against the plaintext limit rather than the wire one.
export const MAX_PLAINTEXT_FRAME_BYTES = MAX_FRAME_BYTES - 1 - TAG_LEN;
// Total bytes of frames buffered while the handshake completes. Sends past it drop the
// oldest — a byte bound rather than a frame count, so a flood of small frames can't
// silently balloon the buffer. Drop-oldest always keeps the newest frame, so a single
// large frame (up to MAX_PLAINTEXT_FRAME_BYTES) can transiently sit above this bound; the
// guarantee is only that a peer which never authenticates cannot make us hoard unbounded
// memory, not that the buffer is a hard ceiling.
const MAX_QUEUE_BYTES = 1024 * 1024; // 1 MiB

export interface PeerLinkOptions {
  channel: RawChannel;
  identity: Identity;
  sodium: TransportCrypto;
  /** true if we opened the connection (outbound dial), false if we accepted it. */
  weDialed: boolean;
  /** For an outbound dial, the peerId we expect to reach — the handshake is
   *  rejected if the far end presents a different key (no silent re-pointing). */
  expectPeerId?: string;
  onAuth: (peerId: string, link: PeerLink) => void;
  onFrame: (peerId: string, frame: Uint8Array) => void;
  onClose: (link: PeerLink) => void;
}

export class PeerLink {
  readonly weDialed: boolean;
  peerPubkey: Uint8Array | null = null;
  peerId = "";
  authed = false;

  private readonly opts: PeerLinkOptions;
  private readonly ch: RawChannel;
  private readonly sodium: TransportCrypto;
  private readonly myNonce: Uint8Array;
  private readonly myEph: { publicKey: Uint8Array; privateKey: Uint8Array };
  private readonly queue: Uint8Array[] = [];
  private queuedBytes = 0;
  private peerEph: Uint8Array | null = null;
  /** The peer's HELLO body, verbatim — it *is* their transcript half (see myHalf). */
  private peerHello: Uint8Array | null = null;
  private closed = false;
  // Directional record-layer state, set once the session key is derived (onAuth).
  private sendKey: Uint8Array | null = null;
  private recvKey: Uint8Array | null = null;
  private sendCtr = 0;
  private recvCtr = 0;

  constructor(opts: PeerLinkOptions) {
    this.opts = opts;
    this.ch = opts.channel;
    this.sodium = opts.sodium;
    this.weDialed = opts.weDialed;
    this.myNonce = opts.sodium.randombytes_buf(NONCE_LEN);
    this.myEph = opts.sodium.crypto_box_keypair();
    this.ch.onMessage((m) => this.onMessage(m));
    this.ch.onClose(() => this.onChannelClose());
    this.sendHello();
  }

  /** Queue (pre-auth) or send (post-auth, as an AEAD record) a Network frame. */
  send(frame: Uint8Array): void {
    if (this.closed) return;
    // Refuse a frame that would seal to an over-cap wire record (plaintext + MSG_FRAME
    // byte + AEAD tag > MAX_FRAME_BYTES) rather than send it: the receiver would reject
    // the record on its length prefix and tear the link down. Dropping it here degrades
    // to a single request timing out instead of killing every request on the link.
    if (frame.length > MAX_PLAINTEXT_FRAME_BYTES) return;
    if (this.authed) { this.ch.send(this.tag(MSG_FRAME, this.seal(frame))); return; }
    this.queue.push(frame);
    this.queuedBytes += frame.length;
    // Byte-bounded pre-auth buffer: drop the oldest until we are back under the
    // cap (but always keep the frame just queued).
    while (this.queuedBytes > MAX_QUEUE_BYTES && this.queue.length > 1) {
      this.queuedBytes -= this.queue.shift()!.length;
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.ch.close();
  }

  // ── handshake ────────────────────────────────────────────────────────────
  private tag(type: number, payload: Uint8Array): Uint8Array {
    const out = new Uint8Array(1 + payload.length);
    out[0] = type;
    out.set(payload, 1);
    return out;
  }

  private sendHello(): void {
    this.ch.send(this.tag(MSG_HELLO, this.myHalf()));
  }

  /** My half of the transcript — `suite ‖ pubkey ‖ nonce ‖ eph`.
   *
   *  This is *exactly* the HELLO body: the bytes we put on the wire and the bytes we
   *  sign are one construction, so they cannot drift apart. That equality is what makes
   *  the suite byte load-bearing rather than decorative — everything a peer declares
   *  about the handshake is, by construction, inside what both ends sign. */
  private myHalf(): Uint8Array {
    const h = new Uint8Array(HELLO_LEN);
    h[0] = SUITE_CHANNEL_GENESIS;
    h.set(this.opts.identity.publicKey.subarray(0, PK_LEN), OFF_PK);
    h.set(this.myNonce, OFF_NONCE);
    h.set(this.myEph.publicKey.subarray(0, EPH_LEN), OFF_EPH);
    return h;
  }

  /** The peer's half — their HELLO body verbatim, kept rather than reassembled from
   *  parsed fields so we sign the bytes they actually sent. Requires onHello to have run. */
  private peerHalf(): Uint8Array {
    return this.peerHello!;
  }

  /** The bytes both ends sign and verify: DOMAIN_CHANNEL followed by the two halves
   *  ordered by their bytes so both ends derive an identical transcript regardless
   *  of who dialed. */
  private transcript(): Uint8Array {
    const mine = this.myHalf(), theirs = this.peerHalf();
    const [lo, hi] = bytesCompare(mine, theirs) <= 0 ? [mine, theirs] : [theirs, mine];
    return concatBytes([DOMAIN_CHANNEL, lo, hi]);
  }

  private onMessage(m: Uint8Array): void {
    if (this.closed || m.length < 1) return;
    const type = m[0];
    const body = m.subarray(1);
    if (type === MSG_HELLO) this.onHello(body);
    else if (type === MSG_AUTH) this.onAuth(body);
    else if (type === MSG_FRAME) this.onRecord(body);
  }

  private onHello(body: Uint8Array): void {
    // Exact length, not a minimum: for a given suite the HELLO width is fixed, so a
    // longer body is malformed rather than forward-compatible. Accepting a tail would
    // be the dangerous kind of extension point — trailing bytes that ride along
    // *outside* what the transcript covers, and so outside what AUTH signs. Extensions
    // belong in a new suite, whose bytes are covered like every other field.
    if (this.peerPubkey || body.length !== HELLO_LEN) { this.close(); return; }
    // Suite first: a different suite means different field widths below, so parsing
    // before checking would be reading another format's bytes at this one's offsets.
    if (body[0] !== SUITE_CHANNEL_GENESIS) { this.close(); return; }
    const pubkey = body.slice(OFF_PK, OFF_PK + PK_LEN);
    // Reflection guard: a peer presenting OUR own kernel key is either our own HELLO
    // echoed back or an attacker replaying it. Because the transcript is canonically
    // ordered, both ends sign identical AUTH bytes, so echoing our HELLO+AUTH would
    // otherwise let the connection "authenticate" as our own identity and install a link
    // to ourselves in the routing tables (visible to linkedPeers()/cohort logic).
    // expectPeerId only guards the dialing side; a node never links to itself — drop it.
    if (bytesCompare(pubkey, this.opts.identity.publicKey.subarray(0, PK_LEN)) === 0) { this.close(); return; }
    const peerEph = body.slice(OFF_EPH, OFF_EPH + EPH_LEN);
    const peerId = toHex(pubkey);
    if (this.opts.expectPeerId && peerId !== this.opts.expectPeerId) { this.close(); return; }
    this.peerPubkey = pubkey;
    this.peerEph = peerEph;
    this.peerHello = body.slice(0, HELLO_LEN);
    this.peerId = peerId;
    // Authenticate over the full transcript — both pubkeys, both nonces, both
    // ephemeral keys — so this signature is bound to this exchange (and this key
    // exchange) and cannot be replayed on another.
    const sig = this.sodium.crypto_sign_detached(this.transcript(), this.opts.identity.privateKey);
    this.ch.send(this.tag(MSG_AUTH, sig));
  }

  private onAuth(sig: Uint8Array): void {
    if (this.authed || !this.peerPubkey || !this.peerEph || sig.length < SIG_LEN) { this.close(); return; }
    let ok = false;
    try { ok = this.sodium.crypto_sign_verify_detached(sig.slice(0, SIG_LEN), this.transcript(), this.peerPubkey); }
    catch { ok = false; }
    if (!ok) { this.close(); return; }
    // A malformed/low-order ephemeral key makes the DH throw; treat that as a
    // failed handshake rather than letting it escape the message callback.
    try { this.deriveSession(); } catch { this.close(); return; }
    this.authed = true;
    this.opts.onAuth(this.peerId, this);
    // onAuth may have torn this link down synchronously: the promote() double-connect
    // tie-break calls link.close() on the loser from inside this callback. Don't seal and
    // send the queue onto a now-closed channel — bail; the frames route over the surviving
    // link on the next send (this link's queue dies with it).
    if (this.closed) return;
    for (const f of this.queue) this.ch.send(this.tag(MSG_FRAME, this.seal(f)));
    this.queue.length = 0;
    this.queuedBytes = 0;
  }

  /** Compute the ephemeral–ephemeral DH and derive the two directional session
   *  keys from it and the transcript hash (README §12.6). The canonical lo/hi
   *  ordering picks which key encrypts and which decrypts. */
  private deriveSession(): void {
    const dh = this.sodium.crypto_scalarmult(this.myEph.privateKey, this.peerEph!);
    const th = this.sodium.crypto_generichash(32, this.transcript(), null);
    const kdf = (label: Uint8Array): Uint8Array =>
      this.sodium.crypto_generichash(KEY_LEN, concatBytes([dh, th, label]), null);
    const kLoHi = kdf(LABEL_LO2HI), kHiLo = kdf(LABEL_HI2LO);
    const iAmLo = bytesCompare(this.myHalf(), this.peerHalf()) <= 0;
    this.sendKey = iAmLo ? kLoHi : kHiLo;
    this.recvKey = iAmLo ? kHiLo : kLoHi;
  }

  /** A 12-byte ChaCha20-Poly1305-IETF nonce from an implicit monotonic counter.
   *  Never transmitted — each direction reconstructs it from its own counter. */
  private static nonce(ctr: number): Uint8Array {
    const n = new Uint8Array(NPUB_LEN);
    writeU32BE(n, 4, Math.floor(ctr / 0x100000000));
    writeU32BE(n, 8, ctr >>> 0);
    return n;
  }

  /** Encrypt a plaintext frame into an AEAD record under the send key + counter. */
  private seal(frame: Uint8Array): Uint8Array {
    const ct = this.sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      frame, null, null, PeerLink.nonce(this.sendCtr), this.sendKey!,
    );
    this.sendCtr++;
    return ct;
  }

  /** Decrypt and deliver a post-auth record; any failure (bad tag, wrong
   *  counter, pre-auth) tears the link down — strict per-direction ordering. */
  private onRecord(body: Uint8Array): void {
    if (!this.authed || !this.recvKey || body.length < TAG_LEN) { this.close(); return; }
    let plain: Uint8Array;
    try {
      // No defensive copy: the channel hands each message its own buffer, and decrypt
      // consumes `body` synchronously (copying into the wasm heap / native Go), so
      // nothing aliases it afterwards.
      plain = this.sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
        null, body, null, PeerLink.nonce(this.recvCtr), this.recvKey,
      );
    } catch { this.close(); return; }
    this.recvCtr++;
    this.opts.onFrame(this.peerId, plain);
  }

  private onChannelClose(): void {
    if (this.closed) return;
    this.closed = true;
    this.opts.onClose(this);
  }
}

/** Lexicographic compare of two byte arrays (-1 / 0 / 1). */
export function bytesCompare(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}
