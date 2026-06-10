// Channel identity binding (README §13.6). A real socket carries no trustworthy
// "from" field, so before a connection is allowed to deliver frames it runs a
// mutual challenge/response that proves each end holds the kernel private key
// for the public key it claims. From then on every frame is attributed to that
// authenticated identity — never to anything inside the frame. This is the
// node↔node analogue of chat-shell.js pinning each data-channel to a kernel pk
// and dropping envelopes signed by anyone else.
//
// PeerLink is transport-agnostic: it drives any RawChannel that delivers whole
// messages (TCP gets message framing from a length prefix; WebSocket already has
// message boundaries). Three short message types ride the channel:
//   HELLO = pubkey(32) ‖ nonce(32)         sent by both ends immediately
//   AUTH  = sign(transcript)(64)           binds both pubkeys + both nonces
//   FRAME = the opaque Network frame        only after both ends authenticate
//
// AUTH signs the whole transcript — DOMAIN ‖ the two (pubkey ‖ nonce) pairs in a
// canonical order — not just the peer's nonce. Signing the nonce alone would make a
// node a signing oracle: an attacker could relay a victim's outstanding nonce as its
// own HELLO, collect the node's signature, and replay it on another connection to
// impersonate the node. Binding both identities and both nonces ties every signature
// to the single exchange that produced it, so a harvested one verifies nowhere else.

import { toHex } from "./util.js";

/** A peer identity — the node's kernel ed25519 keypair (README §13.6). */
export interface Identity {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** The narrow libsodium surface the channel handshake needs: sign/verify the
 *  handshake transcript and a CSPRNG for nonces. Any libsodium build satisfies it
 *  structurally, so the transport need not depend on a specific sodium type. */
export interface TransportCrypto {
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
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
const PK_LEN = 32, NONCE_LEN = 32, SIG_LEN = 64;
const DOMAIN = new TextEncoder().encode("seedkernel-channel-id-v1\0");
// Cap on frames buffered while the handshake completes. Sends past it drop the
// oldest — a peer that never authenticates cannot make us hoard memory.
const MAX_QUEUE = 256;

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
  private readonly queue: Uint8Array[] = [];
  private peerNonce: Uint8Array | null = null;
  private closed = false;

  constructor(opts: PeerLinkOptions) {
    this.opts = opts;
    this.ch = opts.channel;
    this.sodium = opts.sodium;
    this.weDialed = opts.weDialed;
    this.myNonce = opts.sodium.randombytes_buf(NONCE_LEN);
    this.ch.onMessage((m) => this.onMessage(m));
    this.ch.onClose(() => this.onChannelClose());
    this.sendHello();
  }

  /** Queue (pre-auth) or send (post-auth) a Network frame to this peer. */
  send(frame: Uint8Array): void {
    if (this.closed) return;
    if (this.authed) { this.ch.send(this.tag(MSG_FRAME, frame)); return; }
    if (this.queue.length >= MAX_QUEUE) this.queue.shift();
    this.queue.push(frame);
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
    const hello = new Uint8Array(PK_LEN + NONCE_LEN);
    hello.set(this.opts.identity.publicKey.subarray(0, PK_LEN), 0);
    hello.set(this.myNonce, PK_LEN);
    this.ch.send(this.tag(MSG_HELLO, hello));
  }

  /** The bytes both ends sign and verify: DOMAIN followed by each side's
   *  (pubkey ‖ nonce) block, the two ordered by their bytes so both ends derive an
   *  identical transcript regardless of who dialed. Requires peerPubkey/peerNonce. */
  private transcript(): Uint8Array {
    const mine = new Uint8Array(PK_LEN + NONCE_LEN);
    mine.set(this.opts.identity.publicKey.subarray(0, PK_LEN), 0);
    mine.set(this.myNonce, PK_LEN);
    const theirs = new Uint8Array(PK_LEN + NONCE_LEN);
    theirs.set(this.peerPubkey!, 0);
    theirs.set(this.peerNonce!, PK_LEN);
    const [lo, hi] = bytesCompare(mine, theirs) <= 0 ? [mine, theirs] : [theirs, mine];
    const msg = new Uint8Array(DOMAIN.length + lo.length + hi.length);
    msg.set(DOMAIN, 0);
    msg.set(lo, DOMAIN.length);
    msg.set(hi, DOMAIN.length + lo.length);
    return msg;
  }

  private onMessage(m: Uint8Array): void {
    if (this.closed || m.length < 1) return;
    const type = m[0];
    const body = m.subarray(1);
    if (type === MSG_HELLO) this.onHello(body);
    else if (type === MSG_AUTH) this.onAuth(body);
    else if (type === MSG_FRAME) { if (this.authed) this.opts.onFrame(this.peerId, body.slice()); }
  }

  private onHello(body: Uint8Array): void {
    if (this.peerPubkey || body.length < PK_LEN + NONCE_LEN) { this.close(); return; }
    const pubkey = body.slice(0, PK_LEN);
    const peerNonce = body.slice(PK_LEN, PK_LEN + NONCE_LEN);
    const peerId = toHex(pubkey);
    if (this.opts.expectPeerId && peerId !== this.opts.expectPeerId) { this.close(); return; }
    this.peerPubkey = pubkey;
    this.peerNonce = peerNonce;
    this.peerId = peerId;
    // Authenticate over the full transcript — both pubkeys, both nonces — so this
    // signature is bound to this exchange and cannot be replayed on another.
    const sig = this.sodium.crypto_sign_detached(this.transcript(), this.opts.identity.privateKey);
    this.ch.send(this.tag(MSG_AUTH, sig));
  }

  private onAuth(sig: Uint8Array): void {
    if (this.authed || !this.peerPubkey || !this.peerNonce || sig.length < SIG_LEN) { this.close(); return; }
    let ok = false;
    try { ok = this.sodium.crypto_sign_verify_detached(sig.slice(0, SIG_LEN), this.transcript(), this.peerPubkey); }
    catch { ok = false; }
    if (!ok) { this.close(); return; }
    this.authed = true;
    this.opts.onAuth(this.peerId, this);
    for (const f of this.queue) this.ch.send(this.tag(MSG_FRAME, f));
    this.queue.length = 0;
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
