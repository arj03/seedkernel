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
// message boundaries). Four handshake messages ride the channel, then records:
//
//   msg1  i→r  MSG_HELLO  suite(1) ‖ eph_i(32) ‖ seal(k1; nonce_i)
//   msg2  r→i  MSG_AUTH             eph_r(32) ‖ seal(k2; nonce_r)
//   msg3  i→r  MSG_AUTH                         seal(k3; id_i ‖ sig_i)
//   msg4  r→i  MSG_AUTH                         seal(k4; id_r ‖ sig_r)
//   FRAME      MSG_FRAME  ChaCha20-Poly1305 record   only after authentication
//
// NEITHER IDENTITY APPEARS IN CLEARTEXT, and the ORDER OF THE IDENTITIES is the
// design. Only a dialer speaks unprompted; an accepting node stays silent until a
// msg1 opens under the deployment's contact secret, so a stranger who opens a socket
// learns nothing — a node that answered would be a directory service, and one TCP
// connect would enumerate it. The caller then names itself at msg3, BEFORE the
// receiver has said anything about itself, so a caller the receiver declines
// (`admitPeer`) is turned away without learning whether the identity it dialed is
// even here.
//
// That ordering costs a second round trip and is worth it. At msg1 the only key in
// existence is long-term, so an identity sent that early would be sealed under a key
// that lives for years — anyone seizing the node later could decrypt every recorded
// msg1 and recover every peer that ever dialed it. Waiting for the
// ephemeral-ephemeral secret `ee` makes concealment forward-secret for both ends. A
// handshake runs once per connection; the exchange it protects does not.
//
// Both early messages carry a seal keyed by the contact secret, so neither side reveals
// an identity to a non-member: msg1 proves the caller belongs, msg2 proves the
// answerer does. Each side then signs root ‖ transcript-so-far ‖ its own
// id, so a signature is bound to the one exchange that produced it and a harvested
// one verifies nowhere else (a SIGMA-style AKE, with the identity commitment
// explicit). Session keys come from `ee` and the contact secret over the full
// transcript; roles are explicit, so directions need no canonical byte-sort.
//
// Every post-handshake FRAME is an AEAD record under the sending direction's key
// with an implicit (epoch, counter) nonce (never transmitted) and strict
// enforcement on receive — individually authenticated, confidential,
// replay-protected, and forward-secret because the DH keys are ephemeral. The
// identity Ed25519 key stays signing-only and never takes a DH role: the handshake
// needs no long-term DH key at all, so there is none to publish or convert.
//
// ── Hardening (§12.6.1) ──────────────────────────────────────────────────────
// Four properties this layer did not previously hold, each closed here:
//
//  1. EXACT LENGTHS EVERYWHERE. onHello already rejected a HELLO that was not
//     exactly HELLO_LEN, because trailing bytes would ride outside what the
//     transcript covers and so outside what AUTH signs. onAuth accepted `>= 64`
//     and truncated. Both are now exact — the argument was always general.
//
//  2. NO SILENT COUNTER SATURATION, AND A REKEY. The record nonce used to be
//     derived from a JS number, which is exact only below 2^53 and then stops
//     advancing — repeating a nonce under a live key, which for ChaCha20-Poly1305
//     is keystream reuse plus a reused Poly1305 one-time key. The counter is now
//     a (epoch, ctr) pair of u32s, and each direction ratchets its key every
//     REKEY_AFTER_FRAMES frames, so no float arithmetic touches the nonce path and
//     the ceiling is enforced rather than assumed. The ratchet also buys what a
//     fixed session key cannot: intra-session forward secrecy. These links are
//     deliberately long-lived (connsPerPeer parallel flows, re-dialled on loss), and
//     without it a session-key compromise decrypts every frame the link ever
//     carried. It is deterministic and count-triggered — never a negotiated message
//     — so §12.6's "exactly one post-handshake frame type, no plane split, no
//     downgrade seam" still holds, and it is safe precisely because the channel is
//     strictly ordered and any decrypt failure closes the link, so the two ends
//     cannot drift.
//
//  3. UNAUTHENTICATED LOAD IS BOUNDED. A half-open link used to cost an X25519
//     keypair, an Ed25519 signature per inbound HELLO, and a transport buffer, with
//     no deadline and no global cap. There is now a deadline on every link (uniform
//     across transports, which is why it lives here and not in each one) and an
//     injectable HalfOpenLimiter. §12.6.2 took this further once refusals became
//     silent and the budgets had to carry real weight: key material is generated
//     only after a peer proves roster membership, the budgets are split so an
//     outside flood cannot crowd out members, a full budget evicts the oldest
//     rather than refusing the newest, and an unproven connection gets a shorter
//     deadline than a proven one. The pre-signature `admitPubkey` filter that first
//     landed here is gone — it answered membership questions to anyone who could
//     open a socket; see `admitPeer` below.
//
//  4. A CLEAN CLOSE IS DISTINGUISHABLE FROM A CUT ONE. The record layer had no end
//     of stream, so truncation was indistinguishable from a clean FIN — and with
//     FLAG_NO_REPLY sends there is not even a pending request to time out, so a
//     dropped tail was perfectly silent. An empty plaintext is now reserved as an
//     authenticated end-of-stream marker: it rides the one post-handshake frame type
//     (no second tag, so §12.6's "no plane split, no downgrade seam" still holds),
//     send() refuses empty application frames to keep the reservation total, and it
//     is consumed by onRecord rather than delivered to onFrame.
//
//     Two things make it mean something. First, ONLY close() emits it; every failure
//     path uses abort(), which is silent. Otherwise an attacker who injects one junk
//     record into A→B makes B tear down AND hand A a genuine farewell — no forgery
//     needed, just a victim induced to say goodbye at a moment of the attacker's
//     choosing. Second, a graceful close asks the transport to FLUSH: a TCP socket
//     destroyed rather than ended discards the record it was just handed, so the
//     receiver reads a clean shutdown as a truncation and the whole mechanism is a
//     no-op on the transport most likely to carry it.
//
//  5. TEARDOWN ALWAYS NOTIFIES. This was a leak, not a hardening: close() marked
//     the link closed and called ch.close(), but BufferedChannel.close() sets `dead`
//     without firing onCls (deliberately — a self-close should not re-enter fail()),
//     so opts.onClose never ran and the transport never dropped the link from its
//     pre-auth bookkeeping. Every self-closing path — reflection guard, bad suite,
//     length mismatch, expectPeerId mismatch, failed AUTH, low-order ephemeral,
//     decrypt failure — leaked its entry in net-route's `inbound` Set, permanently
//     and without holding a socket. Both teardown paths now funnel through finish(),
//     which notifies exactly once.
//
// A sixth item is deliberately NOT addressed here: both long-term public keys ride
// in cleartext in HELLO, so a passive observer learns both node identities. Hiding
// them requires deriving a key before sending an identity, which a single
// simultaneous flight cannot do — it is the price of the 1-RTT symmetry that makes
// `weDialed` a routing detail rather than a cryptographic role. Recorded as a trade
// in §12.6.1, not closed here.

import { concatBytes, toHex, writeU32BE } from "./util.js";
import { DOMAIN_CHANNEL, SUITE_CHANNEL_CONCEALED } from "./domains.js";

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

/** A bidirectional channel that delivers whole messages atomically. */
export interface RawChannel {
  send(bytes: Uint8Array): void;
  onMessage(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  /** Tear the channel down. `graceful` asks the transport to flush already-written
   *  bytes first; PeerLink passes true only after writing its end-of-stream record,
   *  because a transport that discards that write turns a clean close into exactly
   *  the truncation the record exists to rule out. */
  close(graceful?: boolean): void;
  /** Raise this channel's inbound frame cap from MAX_HANDSHAKE_FRAME_BYTES to
   *  MAX_FRAME_BYTES. PeerLink calls it once, on authentication. Optional because a
   *  transport with its own message boundaries (an RTCDataChannel) has nothing to
   *  reassemble and so nothing to bound. */
  allowLargeFrames?(): void;
  /** Optional transport-supplied identifier for the far end (an IP, say), used
   *  only to bucket the per-source half-open cap. Optional because not every
   *  transport has one: an RTCDataChannel is reached through signaling, and the
   *  WS codec sees a byte stream rather than a socket. Where it is absent only
   *  the global cap applies. It is NEVER an identity — it is unauthenticated and
   *  spoofable, and nothing but the limiter may read it. */
  readonly remoteAddr?: string;
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
const KEY_LEN = 32, NPUB_LEN = 12, TAG_LEN = 16;

/** Per-suite wire parameters. A suite id is not a version to negotiate — it makes the
 *  format SELF-DESCRIBING, so a later suite may change every field width and old and new
 *  stay unambiguous (§14.1). Keeping the widths in one table is what makes the PQ suite
 *  a table entry rather than a rewrite.
 *
 *  What 0x03 (X25519 + ML-KEM-768 hybrid) will change here: msg1 gains the initiator's
 *  KEM encapsulation key and msg2 the responder's ciphertext, so both grow by ~1.1 KB.
 *  What it will NOT change: node addresses (no long-term DH key is published, so a KEM
 *  never enters an address), the identity keypair, the transcript chain, the signature
 *  preimages, the contact-secret mix, or the record layer. The KEM secret joins `ee` in the
 *  key schedule and displaces nothing —  *  `deriveKeys` already takes a LIST of shared secrets, so a KEM secret joins the list
 *  rather than displacing anything. See §12.6.2 §11. */
export interface SuiteParams {
  /** Exact wire length of each handshake message, tag byte excluded. */
  msg1Len: number; msg2Len: number; msg3Len: number; msg4Len: number;
}

export const SUITE_PARAMS: Readonly<Record<number, SuiteParams>> = {
  [SUITE_CHANNEL_CONCEALED]: {
    msg1Len: SUITE_LEN + EPH_LEN + NONCE_LEN + TAG_LEN, //  81
    msg2Len: EPH_LEN + NONCE_LEN + TAG_LEN,             //  80
    msg3Len: PK_LEN + SIG_LEN + TAG_LEN,                // 112
    msg4Len: PK_LEN + SIG_LEN + TAG_LEN,                // 112
  },
};

const P = SUITE_PARAMS[SUITE_CHANNEL_CONCEALED];
const M1_LEN = P.msg1Len, M2_LEN = P.msg2Len, M3_LEN = P.msg3Len, M4_LEN = P.msg4Len;

/** The all-zero AEAD nonce used for each handshake seal. Safe because every handshake
 *  key is used exactly once, for exactly one message: k_probe, k_r and k_i are each
 *  derived from a fresh transcript hash and never encrypt a second time. */
const ZERO_NPUB = new Uint8Array(NPUB_LEN);
// Directional session-key labels: the initiator encrypts with i->r and decrypts with
// r->i; the responder mirrors. Distinct constants so the two directions never share a
// key. Roles are explicit under 0x02, so the canonical lo/hi byte-sort that 0x01 needed
// in order to agree on directions without a role is gone with it.
// Ratchet label — third member of the same family, same discipline (distinct literal,
// versioned, trailing NUL so no member is a prefix of another). It separates the
// one-way key update from the two key-derivation labels, so a ratcheted key can never
// collide with a freshly derived one.
const LABEL_REKEY = new TextEncoder().encode("seedkernel-session-rekey-v1\0");
// Suite 0x02 labels — same family, same discipline (distinct literal, versioned,
// trailing NUL so no member is a prefix of another). Four stages, four keys, none of
// which may collide with another or with a 0x01 session key.
const LABEL_PROBE = new TextEncoder().encode("seedkernel-c-probe-v1\0");
const LABEL_M2 = new TextEncoder().encode("seedkernel-c-msg2-v1\0");
const LABEL_M3 = new TextEncoder().encode("seedkernel-c-msg3-v1\0");
const LABEL_M4 = new TextEncoder().encode("seedkernel-c-msg4-v1\0");
const LABEL_I2R = new TextEncoder().encode("seedkernel-session-i->r-v1\0");
const LABEL_R2I = new TextEncoder().encode("seedkernel-session-r->i-v1\0");
// Hard cap on one link frame, matching §16.1; the transports enforce it on the
// length prefix (TCP) / frame length (WS) before buffering. Exported so every
// transport caps identically — a frame that crosses one crosses the other.
export const MAX_FRAME_BYTES = 16 * 1024 * 1024; // 16 MiB

/** The frame cap that applies BEFORE a link authenticates.
 *
 *  MAX_FRAME_BYTES bounds what an *application* frame may be, and applying it to an
 *  unauthenticated peer was a memory-exhaustion hole: a stranger who knows only
 *  host:port could declare a 16 MiB frame, dribble the body, and hold that much of our
 *  memory — times the half-open budget, which is gigabytes for the price of opening
 *  sockets. No handshake message is anywhere near it (the largest is 113 bytes including
 *  the tag), so nothing legitimate needs the headroom until the link is authenticated.
 *
 *  The cap is raised by PeerLink via RawChannel.allowLargeFrames() at exactly the moment
 *  the peer becomes a known, admitted identity. */
export const MAX_HANDSHAKE_FRAME_BYTES = 512;
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
// memory, not that the buffer is a hard ceiling. Note this budget is only reachable on
// links WE dialed: a transport routes frames to a peer, and an accepted link has no peer
// id to route to until it authenticates.
const MAX_QUEUE_BYTES = 1024 * 1024; // 1 MiB

/** Frames per direction before the key ratchets. 2^24 keeps `ctr` a u32 by a wide
 *  margin and makes the ratchet frequent enough that a session-key compromise
 *  exposes a bounded window, while staying rare enough that the extra BLAKE2b is
 *  noise against the per-frame AEAD. */
export const REKEY_AFTER_FRAMES = 1 << 24; // 16,777,216
/** Ratchets per direction before the link is retired. Reaching it means ~2^40
 *  frames on one direction; the link has done its work and a fresh handshake costs
 *  one round trip. The ceiling is enforced, not assumed — that is the whole point. */
export const REJECT_AFTER_EPOCHS = 1 << 16; // 65,536
/** How long a link may stay half-open before it is closed. A peer that connects and
 *  never speaks used to cost a PeerLink indefinitely. */
export const HANDSHAKE_TIMEOUT_MS = 10_000;

/** How long an ACCEPTED connection has to prove roster membership — that is, to send a
 *  msg1 that opens — before it is dropped.
 *
 *  Much shorter than the full handshake deadline, because it covers one message from a
 *  peer that has already completed a TCP connect, not a four-message exchange. Until
 *  that message opens, a connection is a stranger holding a socket, and a stranger
 *  should not be able to hold one for ten seconds.
 *
 *  It leaks nothing. To observe the longer deadline you must send a msg1 that opens,
 *  which requires the contact secret — and such a peer gets msg2 back immediately anyway, so
 *  the timing tells it nothing it did not already know. */
export const UNVERIFIED_TIMEOUT_MS = 2_000;
/** Default concurrent half-open links a HalfOpenLimiter admits, in total and from
 *  any one source. Deliberately small: a half-open link is pure cost until it
 *  authenticates, and a legitimate peer completes in one round trip. */
/** Budget for connections that have NOT yet proved roster membership. Generous, because
 *  since the ephemeral keypair is deferred (see PeerLink's constructor) such a
 *  connection costs a socket and a timer and no cryptography at all. */
export const MAX_HALF_OPEN_UNVERIFIED = 1024;
/** Budget for connections that HAVE proved membership and are mid-handshake. A separate
 *  pool, which is the whole point: a flood from outside the roster exhausts the
 *  unverified budget and cannot touch this one, so members keep getting in. */
export const MAX_HALF_OPEN_VERIFIED = 256;
export const MAX_HALF_OPEN_PER_SOURCE = 8;

/** A global bound on concurrent half-open links, shared by every transport in a host.
 *
 *  It is a constructor-injected object rather than a module singleton for the reason
 *  everything else here is injected: a per-host bound that hides in module state is
 *  neither testable nor composable, and "global" has to mean global *to a host*, not
 *  to a process that might run several. A host makes one and passes it to every
 *  transport it stands up; transports that share one share the cap.
 *
 *  A slot is taken before any key material is generated and released the moment the
 *  link authenticates (it is no longer half-open) or dies — whichever comes first. */
/** The stand-in used when no contact secret is configured — secret to no one, and a
 *  domain separator rather than a gate. A node on this value is *open*: it answers msg1
 *  from anyone. See PeerLinkOptions.contactSecret for exactly what that costs. */
export const OPEN_CONTACT = new Uint8Array(32).fill(0);

/** The network key of the public network — the value a node uses when none is set.
 *  Published, and meant to be: it is a name, not a secret. */
export const PUBLIC_NETWORK = new Uint8Array(32).fill(0);

/** Which budget a half-open link is drawing on. A link starts `unverified` and is
 *  promoted the moment its first message opens under the contact secret. */
export type LinkTier = "unverified" | "verified";

/** A reservation. Held by the PeerLink that took it and handed back on teardown; the
 *  limiter may also evict it (see acquire). Release is idempotent per slot, which is
 *  what lets an eviction and the evicted link's own teardown both run safely. */
export interface HalfOpenSlot {
  readonly source?: string;
  tier: LinkTier;
  released: boolean;
  /** Tear down the link holding this slot. Called only by the limiter, on eviction. */
  readonly evict: () => void;
}

export class HalfOpenLimiter {
  private unverifiedCount = 0;
  private verifiedCount = 0;
  private nextId = 0;
  private readonly perSource = new Map<string, number>();
  /** Live unverified slots in arrival order — a Map iterates by insertion, so the first
   *  key is the oldest. That ordering is the eviction policy. */
  private readonly waiting = new Map<number, HalfOpenSlot>();
  /** Live verified slots in promotion order — same eviction policy, one tier up. */
  private readonly promoting = new Map<number, HalfOpenSlot>();

  constructor(
    private readonly maxUnverified: number = MAX_HALF_OPEN_UNVERIFIED,
    private readonly maxPerSource: number = MAX_HALF_OPEN_PER_SOURCE,
    private readonly maxVerified: number = MAX_HALF_OPEN_VERIFIED,
  ) {}

  /** Reserve an unverified slot, EVICTING THE OLDEST UNVERIFIED CONNECTION if the
   *  budget is full. Returns null only when the per-source cap is met.
   *
   *  Refusing instead of evicting is what made the budget a denial-of-service weapon
   *  rather than a defence: a flood saturates the pool, and every member that arrives
   *  afterwards is turned away at the door — before it can send the one message that
   *  would have proved it belonged. Promotion cannot help a connection that was never
   *  accepted. Evicting inverts it. A member occupies an unverified slot for exactly one
   *  round trip before promoting out, while a stranger sits there until its deadline, so
   *  the oldest unverified connection is overwhelmingly likely to be a stranger making
   *  no progress. An attacker must now cycle the ENTIRE budget faster than a member
   *  completes one round trip, rather than merely filling it once.
   *
   *  The per-source cap is deliberately NOT evictable: one address hitting its own limit
   *  must be refused, never allowed to push another address out. With the cap at 8 and
   *  the budget at 1024, saturation needs 128 distinct sources. */
  acquire(source: string | undefined, evict: () => void): HalfOpenSlot | null {
    if (source !== undefined && (this.perSource.get(source) ?? 0) >= this.maxPerSource) return null;
    if (this.unverifiedCount >= this.maxUnverified) {
      const oldest = this.waiting.keys().next();
      if (oldest.done) return null; // budget is zero; nothing to make room with
      const victim = this.waiting.get(oldest.value)!;
      // Drop the bookkeeping BEFORE tearing the victim down: its own teardown will call
      // release(), and the slot's `released` flag is what keeps that from double-counting.
      this.waiting.delete(oldest.value);
      this.forget(victim);
      try { victim.evict(); } catch { /* already gone */ }
    }
    const slot: HalfOpenSlot = { source, tier: "unverified", released: false, evict };
    if (source !== undefined) this.perSource.set(source, (this.perSource.get(source) ?? 0) + 1);
    this.unverifiedCount++;
    this.waiting.set(this.nextId++, slot);
    return slot;
  }

  /** Move a slot to the verified budget, once its link has proved roster membership.
   *  False if the verified budget is full, in which case the caller must refuse.
   *
   *  A stranger can only ever occupy the unverified budget, and a member leaves it on
   *  its very first message — so no volume of connections from outside the roster can
   *  keep members from handshaking. The per-source count does not move: it bounds one
   *  address across both tiers. */
  promote(slot: HalfOpenSlot): boolean {
    if (slot.released || slot.tier === "verified") return true;
    if (this.verifiedCount >= this.maxVerified) {
      // Same failure the unverified budget had, one tier up: refusing here would let
      // anyone holding our contact secret saturate this budget and lock every other
      // member out of the handshake. A verified slot belongs to a peer that produced the
      // secret but has NOT yet proved an identity, so the oldest one is still the least
      // likely to be making progress — evict it and take its place.
      const oldest = this.promoting.keys().next();
      if (oldest.done) return false;
      const victim = this.promoting.get(oldest.value)!;
      this.promoting.delete(oldest.value);
      this.forget(victim);
      try { victim.evict(); } catch { /* already gone */ }
    }
    for (const [id, s] of this.waiting) if (s === slot) { this.waiting.delete(id); break; }
    if (this.unverifiedCount > 0) this.unverifiedCount--;
    this.verifiedCount++;
    slot.tier = "verified";
    this.promoting.set(this.nextId++, slot);
    return true;
  }

  /** Give a slot back. Idempotent, so an eviction and the evicted link's own teardown
   *  can both run without letting the budget drift open. */
  release(slot: HalfOpenSlot): void {
    if (slot.released) return;
    const book = slot.tier === "verified" ? this.promoting : this.waiting;
    for (const [id, s] of book) if (s === slot) { book.delete(id); break; }
    this.forget(slot);
  }

  private forget(slot: HalfOpenSlot): void {
    if (slot.released) return;
    slot.released = true;
    if (slot.tier === "verified") { if (this.verifiedCount > 0) this.verifiedCount--; }
    else if (this.unverifiedCount > 0) this.unverifiedCount--;
    if (slot.source === undefined) return;
    const n = this.perSource.get(slot.source);
    if (n === undefined) return;
    if (n <= 1) this.perSource.delete(slot.source); else this.perSource.set(slot.source, n - 1);
  }

  /** Outstanding in each budget — diagnostics and test hooks. */
  get unverified(): number { return this.unverifiedCount; }
  get verified(): number { return this.verifiedCount; }

  /** Half-open links currently outstanding — a diagnostic and a test hook. */
  get outstanding(): number { return this.unverifiedCount + this.verifiedCount; }
}

export interface PeerLinkOptions {
  channel: RawChannel;
  identity: Identity;
  sodium: TransportCrypto;
  /** true if we opened the connection (outbound dial), false if we accepted it. */
  weDialed: boolean;
  /** For an outbound dial, the peerId we expect to reach — the handshake is
   *  rejected if the far end presents a different key (no silent re-pointing). */
  expectPeerId?: string;
  /** OPTIONAL per-node contact secret — 32 bytes of full entropy, distributed with the
   *  node's address. **On an accepting link this is OUR OWN secret; on a dial it is the
   *  PEER's**, taken from the address we are dialing. Absent, OPEN_CONTACT substitutes
   *  and the node is open.
   *
   *  PER NODE, NOT PER DEPLOYMENT AND NOT PER PAIR, and both halves of that are
   *  deliberate. A deployment-wide value (Secret Handshake's network key, Noise's
   *  `psk0` with a group key) means one compromised node re-keys the fleet — the blast
   *  radius is the whole network for the leak of any member. Per-node contains it: X's
   *  secret leaks, X rotates and re-issues its own address, nobody else moves. Per-PAIR
   *  would be tighter still but is unusable here, for the reason the Noise spec gives
   *  for preferring `psk1` over `psk0` on patterns that transmit the initiator's static:
   *  a pairwise secret cannot be selected by the responder until it knows who is calling,
   *  and at msg1 it does not. The secret that gates the first message can only be one the
   *  receiver can identify on its own — its own.
   *
   *  IT IS NOT WHAT CONCEALS THE IDENTITIES. With four messages the ORDERING does that:
   *  the caller names itself at msg3 and the receiver only answers at msg4, so a caller
   *  the receiver declines never learns who it reached, secret or no secret. Both
   *  identities ride keys derived from the ephemeral-ephemeral secret either way. Setting
   *  this buys three narrower things:
   *
   *  1. A STRANGER COSTS NO ASYMMETRIC CRYPTO. The main one. Answering msg1 needs an
   *     ephemeral keypair and a scalarmult, so without a gate every inbound connection
   *     buys both from us — and the two-tier half-open budget is built on "msg1 opened"
   *     being a cheap proof worth promoting on. Open, the posture is an ordinary
   *     authenticated protocol's: a stranger costs a keygen, a scalarmult, an AEAD open
   *     and an Ed25519 verify, bounded by the connection caps rather than by a filter.
   *  2. The CALLER's identity is protected from an ACTIVE attacker, not merely a passive
   *     one. Open, anyone who can answer at an address the caller dials collects that
   *     caller's identity at msg3 — the standard Noise XX limitation (its identity-hiding
   *     grade for the initiator drops from 8 to 2, "sent to an anonymous responder"), and
   *     pinning expectPeerId does NOT help, since msg3 goes out before msg4 is checked.
   *     With a secret, harvesting requires already holding the address as a credential.
   *  3. Active probing draws silence rather than a msg2, so "a node speaks this protocol
   *     here" stops being observable. Identity was never observable either way.
   *
   *  WHY A SECRET AND NOT THE PEER'S PUBLIC KEY. An earlier revision gated msg1 on a
   *  published long-term X25519 key — which is WireGuard's `mac1` and Noise's `XK`. That
   *  is weaker on both counts the Noise spec names: the value ships in the address, so it
   *  gates nothing an address holder lacks; and a public value can be trial-checked
   *  against candidates (identity-hiding grade 3, "a passive attacker can check candidates
   *  for the responder's private key"). Noise §14 states the rule directly — if the
   *  parties want to authenticate with a shared secret, it should be a PSK, not a public
   *  key. Hence a secret, and hence no second long-term key to publish or convert.
   *
   *  Mixed at msg1 together with the initiator's ephemeral, per Noise's PSK validity rule
   *  (a PSK-derived key must be randomized by a self-chosen ephemeral before it encrypts
   *  anything), and into every later key by construction — see kdf(). */
  contactSecret?: Uint8Array;
  /** OPTIONAL network key: which network this node belongs to. Defaults to
   *  PUBLIC_NETWORK.
   *
   *  IT IS AN ISOLATION BOUNDARY, NOT A GATE, and that distinction is the whole reason
   *  it is separate from contactSecret above. Its job is to make two networks that share
   *  infrastructure — a staging fleet and a production one, say — structurally unable to
   *  reach each other, so that a stale address, a copied config or a mistyped host can
   *  never cross the boundary. Nodes on different network keys cannot complete a
   *  handshake with each other under any circumstances, including deliberate ones. That
   *  is the same job Secret Handshake's network key does, and it is a job a per-node
   *  contact secret cannot do: contact secrets are handed out per relationship, so they
   *  say nothing about which network a node belongs to.
   *
   *  Because it is a boundary rather than a secret, its blast radius on disclosure is
   *  small — an attacker who learns it can address the network, which is exactly what
   *  every member can already do, and still cannot draw a response from any node whose
   *  contact secret it lacks. It is fine to treat a network key as public. Do not treat
   *  it as access control: that is what contactSecret and admitPeer are for.
   *
   *  It is applied as Noise calls it, a PROLOGUE: the transcript is seeded with it, so
   *  every derived key and every signature preimage on one network differs from those on
   *  another. A cross-network handshake therefore fails at the first message rather than
   *  somewhere later and more confusingly, and a signature harvested on one network is
   *  not even a well-formed candidate on another. */
  networkKey?: Uint8Array;
  /** Bounds concurrent half-open links across every transport that shares it. When
   *  omitted the link is unbounded, which is right for a link the host itself dialed
   *  and wrong for anything it accepted. */
  limiter?: HalfOpenLimiter;
  /** Optional roster gate on the peer's identity, consulted once that identity has
   *  been decrypted AND its signature verified — never on a claimed key.
   *
   *  It replaces the pre-signature `admitPubkey` filter, and the move is the point. A
   *  filter that runs on a claimed key answers a question for anyone who can open a
   *  socket: name a key, watch whether the response differs, and you have tested roster
   *  membership without holding any private key at all. On a roster that tracks a
   *  social graph, that IS the graph. Here the check runs after decryption, and a
   *  refusal is silent (see stall), so an off-roster peer, a peer with the wrong static
   *  key, and a peer that sent nothing are indistinguishable from outside.
   *
   *  The DoS work the old filter was doing is done better by the opening message: it
   *  costs one X25519 and one Poly1305 to reject a stranger, less than the Ed25519
   *  verify the filter was there to avoid, and it is a proof rather than a claim.
   *
   *  Not the authoritative gate — LinkRouter.promote still runs. */
  admitPeer?: (peerId: string) => boolean;
  /** Override the half-open deadline (ms). 0 disables it; use only in tests. */
  handshakeTimeoutMs?: number;
  /** Frames per direction between key ratchets. Defaults to REKEY_AFTER_FRAMES.
   *
   *  DEPLOYMENT-WIDE CONSTANT, NOT A PER-CONNECTION KNOB. The ratchet is
   *  deterministic and never announced — that is what keeps it inside the single
   *  post-handshake frame type — so two ends that disagree ratchet at different
   *  points and every frame after the first boundary fails to decrypt, tearing the
   *  link down. It is settable because a deployment may want a tighter window (and
   *  because the boundary is otherwise unreachable in a test), on the same terms as
   *  the suite byte: chosen once, identical everywhere, never negotiated. */
  rekeyAfterFrames?: number;
  onAuth: (peerId: string, link: PeerLink) => void;
  onFrame: (peerId: string, frame: Uint8Array) => void;
  onClose: (link: PeerLink) => void;
}

export class PeerLink {
  readonly weDialed: boolean;
  peerPubkey: Uint8Array | null = null;
  peerId = "";
  authed = false;
  /** True once the peer's authenticated end-of-stream record arrived. Distinguishes
   *  a clean shutdown from a truncation: an in-path attacker can cut a connection,
   *  but cannot forge this record. Read it from onClose. */
  peerSaidGoodbye = false;

  private readonly opts: PeerLinkOptions;
  private readonly ch: RawChannel;
  private readonly sodium: TransportCrypto;
  /** Our nonce and ephemeral keypair. Null until needed — see ensureKeys. */
  private myNonce: Uint8Array | null = null;
  private myEph: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
  private readonly queue: Uint8Array[] = [];
  private queuedBytes = 0;
  private peerEph: Uint8Array | null = null;
  private closed = false;
  /** onClose fires exactly once, from whichever teardown path runs first. */
  private notified = false;
  /** We initiated this teardown (rather than the transport dying under us). */
  private closedLocally = false;
  /** We tore this link down because something was WRONG post-authentication — a
   *  decrypt failure, a record that cannot be one. Distinct from closedLocally: a
   *  deliberate shutdown and a defensive one are the same action but not the same
   *  event, and only the second is worth an alarm. */
  private aborted = false;
  /** Whether this link still holds a limiter slot, so release() runs once. */
  /** Our half-open reservation, or null if we hold none. */
  private slot: HalfOpenSlot | null = null;
  private readonly source?: string;
  private deadline: ReturnType<typeof setTimeout> | null = null;
  // Directional record-layer state, set once the session key is derived (onAuth).
  // Each direction carries its own (epoch, ctr): ctr counts frames within an epoch
  // and resets on ratchet, epoch counts ratchets. Both are u32 and both are bounded,
  // so the nonce is built from integers that cannot silently saturate.
  private sendKey: Uint8Array | null = null;
  private recvKey: Uint8Array | null = null;
  private sendEpoch = 0;
  private sendCtr = 0;
  private recvEpoch = 0;
  private recvCtr = 0;
  private readonly rekeyAfter: number;
  // ── suite 0x02 handshake state (§12.6.2) ──────────────────────────────────
  private readonly contactSecret: Uint8Array;
  /** DOMAIN_CHANNEL bound to our network key — the root of every transcript and every
   *  signature preimage on this link. See PeerLinkOptions.networkKey. */
  private readonly root: Uint8Array;
  /** Running transcript hash. h1 after msg1, h2 once the responder ephemeral is known,
   *  h3 after msg2, h4 after msg3 — each stage folding in exactly the bytes that went
   *  on the wire, so the signed transcript and the wire cannot drift. */
  private th: Uint8Array | null = null;
  private ee: Uint8Array | null = null;

  constructor(opts: PeerLinkOptions) {
    this.opts = opts;
    this.ch = opts.channel;
    this.sodium = opts.sodium;
    this.weDialed = opts.weDialed;
    this.source = opts.channel.remoteAddr;
    this.rekeyAfter = opts.rekeyAfterFrames ?? REKEY_AFTER_FRAMES;
    this.contactSecret = opts.contactSecret ?? OPEN_CONTACT;
    this.root = opts.sodium.crypto_generichash(
      KEY_LEN, concatBytes([DOMAIN_CHANNEL, opts.networkKey ?? PUBLIC_NETWORK]), null,
    );

    // Take a half-open slot BEFORE generating any key material — the point of the cap
    // is that a refused connection costs a map lookup, not a keypair.
    // Take a half-open slot BEFORE generating any key material — the point of the cap
    // is that a refused connection costs a map lookup, not a keypair.
    this.slot = opts.limiter ? opts.limiter.acquire(this.source, () => this.abort()) : null;
    if (opts.limiter && !this.slot) {
      this.closed = true;
      // Defer the teardown: the caller does not hold this reference yet, so notifying
      // synchronously from the constructor would run its bookkeeping (`inbound.add`,
      // `dialing.push`) *after* the removal that was meant to undo it, leaving exactly
      // the leak this class now takes care to avoid.
      queueMicrotask(() => { try { this.ch.close(false); } catch { /* already gone */ } this.finish(); });
      return;
    }
    this.ch.onMessage((m) => this.onMessage(m));
    this.ch.onClose(() => this.onChannelClose());

    // WHO SPEAKS FIRST IS THE WHOLE QUESTION (§12.6.2 §2.1). A node that emits its
    // identity unprompted to anyone who opens a socket is a directory service, and one
    // TCP connect enumerates it — cheaper and more reliable than any traffic analysis.
    // So only a dialer speaks from the constructor, and an accepting link says nothing
    // at all until a message arrives proving the sender already knew our static key.
    // KEY MATERIAL IS NOT GENERATED HERE ON THE ACCEPTING SIDE. A responder needs an
    // ephemeral only to build msg2, which it will not build until a msg1 has opened
    // under the contact secret — so a stranger who connects and then sends garbage, or
    // nothing at all, costs a socket and a timer and NO cryptography. Generating the
    // keypair on accept made every inbound TCP connection buy an X25519 keygen from us
    // for free, which is the cheapest flood there is. The dialer needs both immediately,
    // because msg1 carries them.
    if (this.weDialed) {
      this.ensureKeys();
      this.armDeadline(opts.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS);
      this.sendMsg1();
    } else {
      // A stranger gets the short leash; it lengthens when msg1 opens.
      this.armDeadline(opts.handshakeTimeoutMs ?? UNVERIFIED_TIMEOUT_MS);
    }
  }

  /** Generate our nonce and ephemeral keypair, once. */
  private ensureKeys(): void {
    if (this.myEph) return;
    this.myNonce = this.sodium.randombytes_buf(NONCE_LEN);
    this.myEph = this.sodium.crypto_box_keypair();
  }

  private armDeadline(ms: number): void {
    this.clearDeadline();
    if (ms > 0) this.deadline = setTimeout(() => { if (!this.authed) this.abort(); }, ms);
  }

  /** Queue (pre-auth) or send (post-auth, as an AEAD record) a Network frame. */
  send(frame: Uint8Array): void {
    if (this.closed) return;
    // Refuse a frame that would seal to an over-cap wire record (plaintext + MSG_FRAME
    // byte + AEAD tag > MAX_FRAME_BYTES) rather than send it: the receiver would reject
    // the record on its length prefix and tear the link down. Dropping it here degrades
    // to a single request timing out instead of killing every request on the link.
    if (frame.length > MAX_PLAINTEXT_FRAME_BYTES) return;
    // An empty record is reserved for the authenticated end-of-stream marker (see
    // close()), so an empty application frame would be read by the far end as a
    // goodbye. Nothing above this layer produces one — a Transport frame always
    // carries at least a kind byte — so refusing it costs nothing and keeps the
    // reservation total.
    if (frame.length === 0) return;
    if (this.authed) {
      // The epoch ceiling is checked here rather than inside seal() so that reaching it
      // retires the link instead of producing a record under a repeated nonce. Retirement
      // is an intentional shutdown, so it goes through close() and announces itself: the
      // peer should redial, not conclude it was cut. close() can still spend one nonce at
      // exactly REJECT_AFTER_EPOCHS — the ceiling is a policy bound (2^16) far below the
      // u32 the nonce field actually holds, so the farewell record is unique by
      // construction like every other.
      if (this.sendEpoch >= REJECT_AFTER_EPOCHS) { this.close(); return; }
      this.ch.send(this.tag(MSG_FRAME, this.seal(frame)));
      return;
    }
    this.queue.push(frame);
    this.queuedBytes += frame.length;
    // Byte-bounded pre-auth buffer: drop the oldest until we are back under the
    // cap (but always keep the frame just queued).
    while (this.queuedBytes > MAX_QUEUE_BYTES && this.queue.length > 1) {
      this.queuedBytes -= this.queue.shift()!.length;
    }
  }

  /** Shut the link down deliberately, announcing the end of the stream so the far
   *  end can tell this from a cut connection.
   *
   *  ONLY FOR AN INTENTIONAL SHUTDOWN. Everything that tears a link down because
   *  something went wrong must use abort() — see the note there for why the
   *  distinction is a security property and not tidiness. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.closedLocally = true;
    // Say goodbye first, while the send key still exists (teardown wipes it). Skipped
    // when the peer said it first — that would be answering a farewell into a dying
    // socket — and when the send direction has no nonce left to spend.
    let saidGoodbye = false;
    if (this.authed && !this.peerSaidGoodbye && this.sendEpoch <= REJECT_AFTER_EPOCHS) {
      try {
        this.ch.send(this.tag(MSG_FRAME, this.seal(new Uint8Array(0))));
        saidGoodbye = true;
      } catch { /* the transport is already gone; nothing to say */ }
    }
    this.teardown();
    // Flush only when there is something to flush: a graceful transport close costs a
    // FIN handshake (and, on TCP, a linger timer) that a link with nothing left to say
    // has no reason to pay for.
    try { this.ch.close(saidGoodbye); } catch { /* already gone */ }
    this.finish();
  }

  /** Tear the link down WITHOUT announcing an end of stream.
   *
   *  Every failure path uses this, and the distinction is load-bearing. close() emits
   *  an authenticated end-of-stream record; if a failure path emitted one too, then an
   *  in-path attacker who injects a single junk record into A→B would make B tear the
   *  link down AND hand B's genuine, correctly-signed farewell to A — so A would read
   *  an attacker-chosen moment as a clean shutdown. The attacker never has to forge the
   *  record; they induce the victim to emit a real one. Keeping failures silent is what
   *  makes "the peer said goodbye" mean "the peer chose to stop" rather than merely
   *  "the peer stopped".
   *
   *  `defensive` marks a post-authentication protocol failure (bad tag, impossible
   *  record) as opposed to an ordinary handshake washout, so closeReason can tell an
   *  attack or a corruption apart from a peer that simply never completed. */
  abort(defensive = false): void {
    if (this.closed) return;
    this.closed = true;
    this.closedLocally = true;
    if (defensive) this.aborted = true;
    this.teardown();
    try { this.ch.close(false); } catch { /* already gone */ }
    this.finish();
  }

  /** How this link ended. Read it from onClose.
   *
   *  - `open`      — still live.
   *  - `handshake` — died before authenticating; nothing was ever carried.
   *  - `clean`     — the peer's authenticated end-of-stream record arrived.
   *  - `aborted`   — WE tore it down post-auth because a record was bad. Attack or
   *                  corruption; the one value that deserves an alarm.
   *  - `local`     — we shut it down on purpose (tie-break, roster change, shutdown).
   *  - `truncated` — authenticated, then the transport died with no goodbye. The
   *                  stream was cut; anything the peer had left to send is missing. */
  get closeReason(): "open" | "handshake" | "clean" | "aborted" | "local" | "truncated" {
    if (!this.closed) return "open";
    if (!this.authed) return "handshake";
    if (this.peerSaidGoodbye) return "clean";
    if (this.aborted) return "aborted";
    if (this.closedLocally) return "local";
    return "truncated";
  }

  /** True only when the peer's stream was CUT: authenticated, ended by the far side,
   *  and no end-of-stream record.
   *
   *  Note what is excluded. A shutdown we initiated reports `local`, not a truncation —
   *  we do not normally get a goodbye back (close() deliberately does not answer one),
   *  so testing `!peerSaidGoodbye` alone would flag every deliberate close, including
   *  the double-connect tie-break that fires on any parallel dial. That would be an
   *  alarm on a routine event, which is the fastest way to teach an operator to ignore
   *  the alarm. */
  wasTruncated(): boolean { return this.closeReason === "truncated"; }

  // ── handshake ────────────────────────────────────────────────────────────
  private tag(type: number, payload: Uint8Array): Uint8Array {
    const out = new Uint8Array(1 + payload.length);
    out[0] = type;
    out.set(payload, 1);
    return out;
  }

  private onMessage(m: Uint8Array): void {
    if (this.closed || m.length < 1) return;
    const type = m[0];
    const body = m.subarray(1);
    if (type === MSG_HELLO) this.onMsg1(body);
    else if (type === MSG_AUTH) {
      // Which of the three sealed messages this is follows from our role and how far
      // the exchange has got: the initiator reads msg2 then msg4, the responder msg3.
      if (!this.weDialed) this.onMsg3(body);
      else if (!this.peerEph) this.onMsg2(body);
      else this.onMsg4(body);
    } else if (type === MSG_FRAME) this.onRecord(body);
    else this.stall();
  }

  /** Refuse WITHOUT saying so (§12.6.2 §6.5).
   *
   *  Tearing the link down here would answer a question: an immediate close tells a
   *  prober "I am a seedkernel node and that is not my key", which is exactly the
   *  oracle suite 0x02 exists to remove. Doing nothing leaves the handshake deadline to
   *  expire, so an unauthorised peer sees what it would see from a port that is not
   *  listening. Every 0x02 refusal — wrong static key, bad signature, off-roster
   *  identity, malformed message — funnels here so they are indistinguishable from each
   *  other and from silence.
   *
   *  THIS IS LOAD-BEARING AND LOOKS LIKE A BUG. It is not missing error handling; do
   *  not "fix" it into an abort(). The cost is a socket and a timer per junk
   *  connection, which is what HalfOpenLimiter bounds. */
  private stall(): void { /* deliberately nothing — see above */ }

  /** Shared post-authentication bookkeeping for both suites. */
  private becomeAuthed(): void {
    this.authed = true;
    // No longer half-open: give the slot back and stop the deadline before handing
    // control to onAuth, which may run arbitrary transport bookkeeping.
    this.releaseSlot();
    this.clearDeadline();
    // The peer is now a verified, admitted identity, so it may send application frames
    // at full size. Until this point the transport reassembles under the much smaller
    // handshake cap — see MAX_HANDSHAKE_FRAME_BYTES.
    try { this.ch.allowLargeFrames?.(); } catch { /* transport without a cap to raise */ }
    this.opts.onAuth(this.peerId, this);
    // onAuth may have torn this link down synchronously: the promote() double-connect
    // tie-break calls link.close() on the loser from inside this callback. Don't seal
    // and send the queue onto a now-closed channel.
    if (this.closed) return;
    for (const f of this.queue) this.ch.send(this.tag(MSG_FRAME, this.seal(f)));
    this.queue.length = 0;
    this.queuedBytes = 0;
  }

  // ── the concealed-identity handshake (§12.6.2) ─────────────────────────────
  //
  // Four messages, and the ORDER OF THE IDENTITIES is the design:
  //
  //   msg1  i→r  [suite][eph_i][seal(k1; nonce_i)]        roster proof, no identity
  //   msg2  r→i  [eph_r][seal(k2; nonce_r)]               roster proof, STILL no identity
  //   msg3  i→r  [seal(k3; id_i ‖ sig_i)]                 the dialer names itself first
  //   msg4  r→i  [seal(k4; id_r ‖ sig_r)]                 the receiver answers, or not
  //
  // The receiver learns who is calling BEFORE it says who it is, so a caller that fails
  // the whitelist is turned away having learned nothing — not even that the address is
  // live with the identity the caller expected. That is the property the whole design
  // is for, and it is why this costs two round trips rather than one: at msg1 the only
  // key that exists is long-term, so an identity sent that early would be sealed under
  // a key that lives for years and could be recovered by anyone who seizes the node
  // later. Waiting for the ephemeral-ephemeral secret makes concealment forward-secret
  // for both ends. One extra round trip, once per connection, buys that.
  //
  // Both early messages carry a seal keyed by the contact secret, so neither side reveals
  // an identity to a non-member: msg1 proves the caller is one, msg2 proves the
  // answerer is. Everything past that rides `ee`, which dies with the connection.
  //
  // The initiator authenticates at msg4 (2 RTT); the responder authenticates at msg3
  // and may carry application data alongside msg4 (1.5 RTT).

  /** BLAKE2b-256 over the concatenation — the one system hash (§5.1), used for both
   *  the transcript chain and the key schedule. */
  private h(...parts: Uint8Array[]): Uint8Array {
    return this.sodium.crypto_generichash(KEY_LEN, concatBytes(parts), null);
  }

  /** Every handshake key comes through here, so the contact secret is mixed into all of
   *  them by construction — there is no path that derives a key without it. */
  private kdf(ikm: Uint8Array[], ctx: Uint8Array, label: Uint8Array): Uint8Array {
    return this.sodium.crypto_generichash(
      KEY_LEN, concatBytes([...ikm, this.contactSecret, ctx, label]), null,
    );
  }

  private sealZero(key: Uint8Array, plain: Uint8Array): Uint8Array {
    const ct = this.sodium.crypto_aead_chacha20poly1305_ietf_encrypt(plain, null, null, ZERO_NPUB, key);
    key.fill(0);
    return ct;
  }
  private openZero(key: Uint8Array, ct: Uint8Array): Uint8Array {
    try { return this.sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ct, null, ZERO_NPUB, key); }
    finally { key.fill(0); }
  }

  /** The key gating msg1. Derived from the contact secret and the initiator's ephemeral
   *  alone — there is no shared secret yet, and deliberately no identity to protect. */
  private probeKey(suiteByte: Uint8Array, ephI: Uint8Array): Uint8Array {
    return this.kdf([], this.h(this.root, suiteByte, ephI), LABEL_PROBE);
  }

  private signIdentity(th: Uint8Array): { id: Uint8Array; sig: Uint8Array } {
    const id = this.opts.identity.publicKey.subarray(0, PK_LEN);
    const sig = this.sodium.crypto_sign_detached(
      concatBytes([this.root, th, id]), this.opts.identity.privateKey,
    );
    return { id, sig };
  }

  /** Open an identity message and verify its signature against the transcript it
   *  claims. Returns null on any failure, so every caller refuses the same way. */
  private openIdentity(key: Uint8Array, ct: Uint8Array, th: Uint8Array): Uint8Array | null {
    let plain: Uint8Array;
    try { plain = this.openZero(key, ct); } catch { return null; }
    const id = plain.slice(0, PK_LEN);
    const sig = plain.slice(PK_LEN, PK_LEN + SIG_LEN);
    try {
      if (!this.sodium.crypto_sign_verify_detached(sig, concatBytes([this.root, th, id]), id)) return null;
    } catch { return null; }
    // A peer presenting OUR identity is our own traffic reflected, or a replay of it.
    if (bytesCompare(id, this.opts.identity.publicKey.subarray(0, PK_LEN)) === 0) return null;
    return id;
  }

  // msg1 ─ initiator opens. No identity: see the note at the top of this block.
  private sendMsg1(): void {
    const suiteByte = new Uint8Array([SUITE_CHANNEL_CONCEALED]);
    const eph = this.myEph!.publicKey.subarray(0, EPH_LEN);
    const w1 = concatBytes([suiteByte, eph, this.sealZero(this.probeKey(suiteByte, eph), this.myNonce!)]);
    this.th = this.h(this.root, w1);
    this.ch.send(this.tag(MSG_HELLO, w1));
  }

  // msg1 at the responder. Failure past the length check is SILENT: a caller that
  // cannot produce this seal is not a member, and telling it so is the enumeration
  // this design closes.
  private onMsg1(w1: Uint8Array): void {
    // Suite first — another suite means other field widths below, so parsing before
    // checking would be reading one format at another's offsets. Exact length, not a
    // minimum: a trailing byte would ride outside the transcript, and so outside what
    // both signatures cover. Extensions belong in a new suite.
    if (this.peerEph || this.weDialed || w1.length !== M1_LEN) { this.stall(); return; }
    if (w1[0] !== SUITE_CHANNEL_CONCEALED) { this.stall(); return; }
    const ephI = w1.slice(SUITE_LEN, SUITE_LEN + EPH_LEN);
    try {
      // With a contact secret configured this is a proof of membership, and NOTHING is spent
      // before it: no keypair, no scalarmult, no promotion, so a caller who cannot produce
      // it costs us a hash and a Poly1305 verify. Without one it is only a format check
      // that anyone can satisfy — the identities stay concealed regardless (that is the
      // message ordering's job, not this seal's), but the cheap filter in front of the
      // keypair below is gone. See PeerLinkOptions.contactSecret.
      this.openZero(this.probeKey(w1.slice(0, SUITE_LEN), ephI), w1.slice(SUITE_LEN + EPH_LEN));
    } catch { this.stall(); return; }

    // Proved. Move off the contended budget before doing the expensive work, so a flood
    // of strangers cannot crowd out the members queued behind them.
    if (this.slot && this.opts.limiter && !this.opts.limiter.promote(this.slot)) { this.stall(); return; }
    this.armDeadline(this.opts.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS);
    this.ensureKeys();
    try { this.ee = this.sodium.crypto_scalarmult(this.myEph!.privateKey, ephI); }
    catch { this.stall(); return; }
    this.peerEph = ephI;

    const h1 = this.h(this.root, w1);
    const w2 = concatBytes([
      this.myEph!.publicKey.subarray(0, EPH_LEN),
      this.sealZero(this.kdf([this.ee], h1, LABEL_M2), this.myNonce!),
    ]);
    this.th = this.h(h1, w2);
    this.ch.send(this.tag(MSG_AUTH, w2));
  }

  // msg2 at the initiator. Still no identity in flight. Opening it proves the answerer
  // holds the contact secret, which is what lets us name ourselves next.
  private onMsg2(w2: Uint8Array): void {
    if (this.authed || this.peerEph || !this.th || w2.length !== M2_LEN) { this.stall(); return; }
    const ephR = w2.slice(0, EPH_LEN);
    let ee: Uint8Array;
    try {
      ee = this.sodium.crypto_scalarmult(this.myEph!.privateKey, ephR);
      this.openZero(this.kdf([ee], this.th, LABEL_M2), w2.slice(EPH_LEN));
    } catch { this.stall(); return; }
    this.ee = ee; this.peerEph = ephR;

    const h2 = this.h(this.th, w2);
    const { id, sig } = this.signIdentity(h2);
    const w3 = this.sealZero(this.kdf([ee], h2, LABEL_M3), concatBytes([id, sig]));
    this.th = this.h(h2, w3);
    this.ch.send(this.tag(MSG_AUTH, w3));
  }

  // msg3 at the responder: the caller names itself, and this is where we decide.
  // The whitelist runs here — after decryption and signature, never on a claimed key —
  // and a refusal is silence, so being turned away is indistinguishable from a msg3
  // that simply never arrived. Nothing about us has gone out yet.
  private onMsg3(w3: Uint8Array): void {
    if (this.authed || !this.peerEph || !this.th || !this.ee || w3.length !== M3_LEN) { this.stall(); return; }
    const idI = this.openIdentity(this.kdf([this.ee], this.th, LABEL_M3), w3, this.th);
    if (!idI) { this.stall(); return; }
    const peerId = toHex(idI);
    if (this.opts.admitPeer && !this.opts.admitPeer(peerId)) { this.stall(); return; }
    this.peerPubkey = idI; this.peerId = peerId;

    const h3 = this.h(this.th, w3);
    const { id, sig } = this.signIdentity(h3);
    const w4 = this.sealZero(this.kdf([this.ee], h3, LABEL_M4), concatBytes([id, sig]));
    this.th = this.h(h3, w4);
    try { this.deriveConcealedSession(); } catch { this.stall(); return; }
    this.ch.send(this.tag(MSG_AUTH, w4));
    this.becomeAuthed();
  }

  // msg4 at the initiator: the answerer finally names itself, and we check it is who
  // we dialed. A mismatch here is a local fault, not a probe to hide from — we already
  // revealed ourselves at msg3 — so it aborts rather than stalls.
  private onMsg4(w4: Uint8Array): void {
    if (this.authed || !this.peerEph || !this.th || !this.ee || w4.length !== M4_LEN) { this.stall(); return; }
    const idR = this.openIdentity(this.kdf([this.ee], this.th, LABEL_M4), w4, this.th);
    if (!idR) { this.stall(); return; }
    const peerId = toHex(idR);
    if (this.opts.expectPeerId && peerId !== this.opts.expectPeerId) { this.abort(); return; }
    this.peerPubkey = idR; this.peerId = peerId;
    this.th = this.h(this.th, w4);
    try { this.deriveConcealedSession(); } catch { this.abort(); return; }
    this.becomeAuthed();
  }

  /** Directional session keys. Roles are explicit, so the canonical lo/hi byte-sort
   *  that a symmetric handshake needs in order to agree on directions has nothing left
   *  to do: the initiator sends under i->r and receives under r->i, responder mirrors.
   *
   *  Only `ee` and the contact secret feed this. There is deliberately no long-term DH
   *  term: `ee` dies with the connection, so a node seized later recovers nothing from
   *  a recording, and the contact secret — which never appears on the wire — is the floor
   *  if an ephemeral RNG turns out to be broken. */
  private deriveConcealedSession(): void {
    const kI2R = this.kdf([this.ee!], this.th!, LABEL_I2R);
    const kR2I = this.kdf([this.ee!], this.th!, LABEL_R2I);
    this.sendKey = this.weDialed ? kI2R : kR2I;
    this.recvKey = this.weDialed ? kR2I : kI2R;
    this.ee!.fill(0);
    this.ee = null;
  }


  /** A 12-byte ChaCha20-Poly1305-IETF nonce from the implicit (epoch, counter) pair.
   *  Never transmitted — each direction reconstructs it from its own state.
   *
   *  Both components are u32 and both are bounded (ctr < REKEY_AFTER_FRAMES, epoch <
   *  REJECT_AFTER_EPOCHS), so this is exact integer arithmetic throughout. The previous
   *  form derived the high word from a JS number via Math.floor(ctr / 2^32), which is
   *  exact only below 2^53 and then stops advancing — saturating rather than wrapping,
   *  and so repeating a nonce under a live key. Uniqueness now holds by construction:
   *  ctr is unique within an epoch, epoch is unique within a key's life, and the key
   *  changes whenever epoch does. */
  private static nonce(epoch: number, ctr: number): Uint8Array {
    const n = new Uint8Array(NPUB_LEN);
    writeU32BE(n, 0, epoch);
    // bytes 4..8 stay zero — reserved, and keeping them so leaves the epoch-0 nonce
    // byte-identical to the counter-only form this replaces.
    writeU32BE(n, 8, ctr);
    return n;
  }

  /** One-way key update. A ratcheted key cannot be run backwards to recover the key
   *  that produced it, which is what bounds how much of a session a compromised key
   *  discloses. */
  private ratchet(k: Uint8Array): Uint8Array {
    const next = this.sodium.crypto_generichash(KEY_LEN, concatBytes([k, LABEL_REKEY]), null);
    k.fill(0);
    return next;
  }

  /** Encrypt a plaintext frame into an AEAD record under the send key + counter,
   *  then advance — ratcheting the direction's key at the epoch boundary. */
  private seal(frame: Uint8Array): Uint8Array {
    const ct = this.sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      frame, null, null, PeerLink.nonce(this.sendEpoch, this.sendCtr), this.sendKey!,
    );
    if (++this.sendCtr >= this.rekeyAfter) {
      this.sendKey = this.ratchet(this.sendKey!);
      this.sendEpoch++;
      this.sendCtr = 0;
    }
    return ct;
  }

  /** Decrypt and deliver a post-auth record; any failure (bad tag, wrong
   *  counter, pre-auth) tears the link down — strict per-direction ordering. */
  private onRecord(body: Uint8Array): void {
    if (!this.authed || !this.recvKey || body.length < TAG_LEN) { this.abort(this.authed); return; }
    if (this.recvEpoch >= REJECT_AFTER_EPOCHS) { this.abort(); return; }
    let plain: Uint8Array;
    try {
      // No defensive copy: the channel hands each message its own buffer, and decrypt
      // consumes `body` synchronously (copying into the wasm heap / native Go), so
      // nothing aliases it afterwards.
      plain = this.sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
        null, body, null, PeerLink.nonce(this.recvEpoch, this.recvCtr), this.recvKey,
      );
    } catch { this.abort(/*defensive*/ true); return; }
    // Advance only on success — a failed decrypt must never move the counter, or an
    // attacker who injects one junk record desynchronises the direction and every
    // subsequent genuine frame fails. (The failure path closes the link anyway; the
    // ordering is what makes that a policy rather than the only thing saving us.)
    if (++this.recvCtr >= this.rekeyAfter) {
      this.recvKey = this.ratchet(this.recvKey!);
      this.recvEpoch++;
      this.recvCtr = 0;
    }
    // The reserved empty record: an authenticated end-of-stream. It rides the one
    // post-handshake frame type rather than introducing a second, so §12.6's "no plane
    // split, no downgrade seam" still holds — and because it is authenticated, an
    // in-path attacker can cut a connection but cannot fabricate a clean ending.
    if (plain.length === 0) { this.peerSaidGoodbye = true; this.close(); return; }
    this.opts.onFrame(this.peerId, plain);
  }

  private onChannelClose(): void {
    if (this.notified) return;
    this.closed = true;
    this.teardown();
    this.finish();
  }

  // ── teardown ─────────────────────────────────────────────────────────────
  // Both paths (self-close and transport-close) release the same resources and
  // notify exactly once. Splitting them was the bug: BufferedChannel.close() marks
  // itself dead WITHOUT firing onCls — deliberately, so a self-close does not
  // re-enter fail() — which meant a link that closed itself never reached
  // opts.onClose, and every transport kept it in its pre-auth bookkeeping forever.

  private clearDeadline(): void {
    if (this.deadline !== null) { clearTimeout(this.deadline); this.deadline = null; }
  }

  private releaseSlot(): void {
    if (!this.slot) return;
    const slot = this.slot;
    this.slot = null;
    this.opts.limiter?.release(slot);
  }

  private teardown(): void {
    this.clearDeadline();
    this.releaseSlot();
    this.queue.length = 0;
    this.queuedBytes = 0;
    this.sendKey?.fill(0);
    this.recvKey?.fill(0);
    this.sendKey = null;
    this.recvKey = null;
    // Handshake secrets, if we died mid-flight (deriveConcealedSession wipes them on
    // the success path).
    this.ee?.fill(0);
    this.ee = null;
  }

  private finish(): void {
    if (this.notified) return;
    this.notified = true;
    this.opts.onClose(this);
  }
}

/** Lexicographic compare of two byte arrays (-1 / 0 / 1). */
export function bytesCompare(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}
