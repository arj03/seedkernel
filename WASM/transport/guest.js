// ============================================================================
// The transport bundle guest — the channel handshake (AKE + forward-secret
// record layer, ex net-link.ts), the authenticated link router (ex link-router.ts),
// the link bookkeeping (ex net-route.ts NodeNetworkCore) and the request/response
// layer (ex net.ts) — as the zero-authority JS program of a signed bundle claiming
// `role: "transport"`.
//
// Why this exists as a bundle at all (§12.6): the wire
// behaviour of a seedkernel node — what the AKE signs, which suite byte it speaks,
// how records are framed, how links are routed — is *content* (replaceable state
// machines over whole messages), and a signed bundle is the mechanism this runtime
// already has for shipping replaceable code. The host keeps only what has no
// endpoint substitute: the sockets, the flood caps, the node key, the entropy
// source. Everything here is state machines.
//
// What the host supplies (the seam):
//
//   - `host.crypto(name, bytes)` — the PRIMITIVE seam: one op over a flat catalog of
//     opaque names, none of which is a capability, because a function of its arguments
//     grants nothing. What this program uses, declared in its manifest's
//     `guest.primitives` so a host that lacks one refuses the bundle at load:
//       "blake2b-256"                  bytes -> 32B         (transcript, KDF, root)
//       "ed25519/verify"               [pk 32][sig 64][msg] -> [ok u8]   (peer AUTH)
//       "chacha20poly1305-ietf/seal"   [npub 12][key 32][msg] -> ct      (record layer)
//       "chacha20poly1305-ietf/open"   [npub 12][key 32][ct] -> [ok u8][pt]
//       "x25519/dh"                    [sk 32][pk 32] -> [ok u8][x 32]   (ephemeral DH,
//                                        and against the base point, the pubkey too)
//
//     Changing suite is changing these names. It costs this file and a host that
//     already carries the primitive — no op number, no ABI rev, no new grant.
//
//   - `host.call(op, bytes)` — the AUTHORITIES the manifest declares in `caps`, which
//     is the whole of what this program is granted:
//       SIGN   (2)  msg -> 64B sig. The host prefixes `DOMAIN_channel ‖ networkKey`
//                   from THIS bundle's slot and signs the opaque suffix with the node's
//                   channel key, which never enters this module. It does not read the
//                   suffix — the domain separation is the guarantee, so no transcript
//                   shape is pinned into the host and no op signs raw bytes.
//       RANDOM (4)  [n u32 BE] -> n random bytes            (nonces, ephemeral secrets)
//       CLOCK  (14) -> now ms (u64 BE)                      (stall clocks)
//
//     `rawnet` — the platform's whole contribution to the network: bytes over an
//     opaque link id, opened and closed. `timer` — deadlines, because a
//     zero-authority realm has no setTimeout. `transport` — where this program
//     reports its structured OUTPUT (an attributed peer, a protocol id, a
//     correlation), which every app then reaches through the ordinary `net` domain.
//
//     The whitelist gate is deliberately NOT ours to apply. It is host policy over the
//     attribution this program reports (NET_LINK_AUTH answers with the verdict, and
//     the host has already closed the channel on a refusal); a gate this program
//     applied to itself would be one a hostile occupant of the slot would simply skip.
//
//   - entrypoints, invoked synchronously by name — `linkBytes`, `timer`, `request`
//     and the rest below. This is the SAME mechanism an app's holder `handle` is
//     invoked through: there is no second host↔module ABI, no event tag space, and
//     an entrypoint this program does not register fails loud by name rather than
//     desyncing a decoder.
//
// The node key stays out of this module in the strongest sense: there is no op
// that signs arbitrary bytes — SIGN is scoped by the slot the host admitted this
// bundle into, so a compromised transport can neither forge app signatures nor
// sign for another network.
//
// Channels are host handles keyed by a link id the HOST minted — the kernel table
// holds one instance per name (§3.1), so all link state lives in this module's
// heap, keyed by that id.
//
// This file is hand-maintained single-source content: it is signed into the
// bundle, so it must be self-contained (no imports) and must match the seam
// below exactly. The host twin of this contract lives in host/transport-host.ts.
// ============================================================================

"use strict";

// ── byte helpers (no TextEncoder/TextDecoder in a zero-authority realm) ───────

function concatBytes(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function writeU32BE(out, off, v) {
  out[off] = v >>> 24; out[off + 1] = (v >>> 16) & 0xff; out[off + 2] = (v >>> 8) & 0xff; out[off + 3] = v & 0xff;
}
function readU32BE(b, off) { return ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0; }

const HEX = "0123456789abcdef";
function toHex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) { s += HEX[b[i] >>> 4] + HEX[b[i] & 15]; }
  return s;
}
function fromHex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

/** Lexicographic byte-array compare (−1 / 0 / 1). */
function bytesCompare(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

function utf8Encode(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}

function utf8Decode(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const c = b[i];
    if (c < 0x80) s += String.fromCharCode(c);
    else if ((c & 0xe0) === 0xc0) { s += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63)); i++; }
    else { s += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63)); i += 2; }
  }
  return s;
}

// ── capability op ids (must match cap-bridge's CAP) ───────────────────────────

// Authorities only — a primitive has no op number, it has a name (see below).
const OP_SIGN = 2;
const OP_RANDOM = 4;
const OP_CLOCK = 14;

// The raw net capability: bytes over an opaque link id, opened and closed. This is
// the whole of what the platform contributes — there is no peer here, no framing and
// no attribution, because those are state machines and state machines are ours.
const OP_LINK_OPEN = 15;
const OP_LINK_SEND = 16;
const OP_LINK_CLOSE = 17;
const OP_LINK_CAP = 18;

// The platform's event loop.
const OP_TIMER_ARM = 19;
const OP_TIMER_CLEAR = 20;

// What this program PROVIDES back — the structured face the platform does not have.
const OP_DELIVER = 21;
const OP_SETTLE = 22;
const OP_LINK_AUTH = 23;
const OP_PEER_EDGE = 24;
const OP_READY = 25;
const OP_LINK_DOWN = 26;

// The primitives this program asks for by name, through the one CAP_CRYPTO op. These
// are the strings the manifest's `guest.primitives` declares, so a host that cannot
// serve one refuses the bundle at load rather than failing here.
const P_HASH = "blake2b-256";
const P_VERIFY = "ed25519/verify";
const P_SEAL = "chacha20poly1305-ietf/seal";
const P_OPEN = "chacha20poly1305-ietf/open";
const P_DH = "x25519/dh";

// The X25519 base point. `x25519/dh(sk, BASEPOINT)` is the public-key derivation, so
// the catalog needs no keygen entry and the ephemeral secret comes from RANDOM — which
// keeps the entropy grant where it belongs and the catalog purely functional.
const X25519_BASEPOINT = new Uint8Array([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

// Kinds of link, as the host's `linkOpen` declares them: 0 = the routing core's own
// (an accepted socket; dial/accept bookkeeping and the half-open limiter apply);
// 1 = a host-managed transport (WebRTC / browser WS) that opened the socket itself
// and handed it over (openLink). A CORE link we DIALED never arrives this way — we
// open those ourselves through OP_LINK_OPEN and already know everything about them.
const LINK_CORE = 0;
const LINK_OPEN = 1;

// Link close-reason codes (OP_LINK_DOWN's u8) — mirror Link.closeReason.
const REASON_OPEN = 0, REASON_HANDSHAKE = 1, REASON_CLEAN = 2, REASON_ABORTED = 3,
      REASON_LOCAL = 4, REASON_TRUNCATED = 5;

function reasonCode(link) {
  const r = link.closeReason;
  return r === "handshake" ? REASON_HANDSHAKE : r === "clean" ? REASON_CLEAN
    : r === "aborted" ? REASON_ABORTED : r === "local" ? REASON_LOCAL
    : r === "truncated" ? REASON_TRUNCATED : REASON_OPEN;
}

// ── channel handshake constants (ex net-link.ts §12.6) ───────────────────────

const MSG_HELLO = 1, MSG_AUTH = 2, MSG_FRAME = 3;
const SUITE_CHANNEL_CONCEALED = 0x02;
const SUITE_LEN = 1, PK_LEN = 32, NONCE_LEN = 32, EPH_LEN = 32, SIG_LEN = 64;
const KEY_LEN = 32, NPUB_LEN = 12, TAG_LEN = 16;
const M1_LEN = SUITE_LEN + EPH_LEN + NONCE_LEN + TAG_LEN; //  81
const M2_LEN = EPH_LEN + NONCE_LEN + TAG_LEN;             //  80
const M3_LEN = PK_LEN + SIG_LEN + TAG_LEN;                // 112
const M4_LEN = PK_LEN + SIG_LEN + TAG_LEN;                // 112

// The one suite this transport speaks. A suite byte is not negotiated: it makes
// the wire self-describing, and because it sits inside every signed transcript
// half, an in-path attacker who flips it only makes the two ends sign different
// bytes (domains.ts / §12.6, §14.1).
const SUITE_BYTE = new Uint8Array([SUITE_CHANNEL_CONCEALED]);

const ZERO_NPUB = new Uint8Array(NPUB_LEN);

// Directional session-key labels and the ratchet label — the same family
// discipline as every domain prefix: distinct literals, versioned, trailing NUL
// so no member is a prefix of another. The host never sees them; they are this
// bundle's wire contract, and two endpoints that disagree fail at first decrypt.
const LABEL_REKEY = utf8Encode("seedkernel-session-rekey-v1\0");
const LABEL_PROBE = utf8Encode("seedkernel-c-probe-v1\0");
const LABEL_M2 = utf8Encode("seedkernel-c-msg2-v1\0");
const LABEL_M3 = utf8Encode("seedkernel-c-msg3-v1\0");
const LABEL_M4 = utf8Encode("seedkernel-c-msg4-v1\0");
const LABEL_I2R = utf8Encode("seedkernel-session-i->r-v1\0");
const LABEL_R2I = utf8Encode("seedkernel-session-r->i-v1\0");

const DOMAIN_CHANNEL = utf8Encode("seedkernel-channel-id-v1\0");

// Per-suite wire lengths (ex SUITE_PARAMS). A later suite changes these and the
// byte it is keyed by; the host never reads them.
const REKEY_AFTER_FRAMES = 1 << 24;  // frames per direction before the key ratchets
const REJECT_AFTER_EPOCHS = 1 << 16; // ratchets per direction before the link retires
const HANDSHAKE_TIMEOUT_MS = 10_000;
const UNVERIFIED_TIMEOUT_MS = 2_000;
const MAX_QUEUE_BYTES = 1024 * 1024; // pre-auth send buffer byte budget (drop-oldest)

// ── per-host state, set by EVT_INIT ───────────────────────────────────────────

let ownPk = null;          // 32B node channel public key
let ownId = "";            // its hex — the peer id
let networkKey = null;     // 32B
let contactSecret = null;  // 32B — OUR inbound gate (zeros = open)
// What the host PREPENDS to everything the SIGN op signs for this slot:
// `DOMAIN_channel ‖ networkKey`, chosen from the slot this bundle was admitted into
// and never from anything said here (cap-bridge `transportSignScope`). The host
// prefixes and does not parse, so reconstructing the prefix to VERIFY a peer's
// transcript signature is this program's job — it is the one thing about signing the
// two sides have to agree on, and getting it wrong is a handshake that never
// completes rather than one that completes wrongly.
let signPrefix = null;
let timeoutMs = 200;
let connsPerPeer = 1;
let maxStallWindows = 50;
// The HOST's flood cap, learned at INIT — this module never declares the number
// that bounds it (net-limits.ts stays core); it only sizes its own send budget
// against it.
let maxFrameBytes = 16 * 1024 * 1024;
let maxUnverified = 1024, maxPerSource = 8, maxVerified = 256;

// The one router and the one request/response layer per host instance.
let router = null;
let reqres = null;
let core = null;

// Timers this module asked the host to arm — host events carry the id back.
let nextTimerId = 1;
const timers = new Map();

// Deferred teardowns (see Link constructor): flushed after the current event.
const deferQueue = [];

// Host-managed (openLink) links by id — the pre-auth ones are in no pool.
const openLinks = new Map();

// ── the seam helpers ──────────────────────────────────────────────────────────

function hash() {
  const parts = [...arguments];
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return host.crypto(P_HASH, out);
}
function verify(pk, sig, msg) {
  let len = pk.length + sig.length + msg.length;
  const out = new Uint8Array(len);
  out.set(pk, 0); out.set(sig, pk.length); out.set(msg, pk.length + sig.length);
  return host.crypto(P_VERIFY, out)[0] === 1;
}
function randomBytes(n) {
  const req = new Uint8Array(4);
  writeU32BE(req, 0, n);
  return host.call(OP_RANDOM, req);
}
function aeadEnc(key, npub, msg) {
  const out = new Uint8Array(npub.length + key.length + msg.length);
  out.set(npub, 0); out.set(key, npub.length); out.set(msg, npub.length + key.length);
  return host.crypto(P_SEAL, out);
}
function aeadDec(key, npub, ct) {
  const out = new Uint8Array(npub.length + key.length + ct.length);
  out.set(npub, 0); out.set(key, npub.length); out.set(ct, npub.length + key.length);
  const r = host.crypto(P_OPEN, out);
  return r[0] === 1 ? { ok: true, pt: r.subarray(1) } : { ok: false, pt: null };
}
function scalarmult(sk, pk) {
  const out = new Uint8Array(64);
  out.set(sk, 0); out.set(pk, 32);
  const r = host.crypto(P_DH, out);
  return r[0] === 1 ? { ok: true, x: r.subarray(1) } : { ok: false, x: null };
}
/** An ephemeral X25519 pair: entropy from the host (an authority), the public half
 *  derived with the same DH primitive against the base point (a pure transform). */
function boxKeypair() {
  const sk = randomBytes(32);
  const r = scalarmult(sk, X25519_BASEPOINT);
  if (!r.ok) throw new Error("transport: ephemeral keygen failed");
  return { publicKey: r.x, privateKey: sk };
}
/** Ask the host to sign a handshake transcript. The host prefixes
 *  `DOMAIN_channel ‖ networkKey` — chosen from THIS bundle's slot, not from anything
 *  said here — and signs the opaque suffix with the node's channel key, which never
 *  enters this program. There is no op that signs raw bytes, and the prefix is what
 *  makes a transcript signature unusable as app data (and vice versa). */
function channelSign(root, th, id) {
  const out = new Uint8Array(96);
  out.set(root, 0); out.set(th, 32); out.set(id, 64);
  return { ok: true, sig: host.call(OP_SIGN, out) };
}
function clockNow() {
  const r = host.call(OP_CLOCK, new Uint8Array(0));
  return readU32BE(r, 0) * 0x100000000 + readU32BE(r, 4);
}

// ── calling out: the ops, each one argument-encoded and issued immediately ────
//
// There is no action buffer and no batch. An earlier revision accumulated orders
// into a `[count u8][action …]` response the host decoded after the entrypoint
// returned; that was a second host↔module ABI, and every one of these calls is now
// an ordinary `host.call` through the one seam (§12.2).
//
// The one rule the arrangement rests on is the host's: NO OP RE-ENTERS THIS REALM.
// A socket write does not deliver during the write, a fired timer arrives on its own
// turn, and an inbound request is answered through the `respond` entrypoint rather
// than as OP_DELIVER's return value — so nothing below can call back into a frame
// that is still on the stack.

function argU32(v) {
  const b = new Uint8Array(4);
  writeU32BE(b, 0, v);
  return b;
}
/** `[u32 fields][u8 fields][raw tail]` — each op's own fixed order. */
function args(u32s, u8s, tail) {
  const parts = [];
  for (const v of u32s) parts.push(argU32(v));
  if (u8s.length) parts.push(Uint8Array.from(u8s));
  if (tail) parts.push(tail);
  return concatBytes(parts);
}

/** Open a link to an opaque destination (the peer's channel key); 0 ⇒ no route. */
function netLinkOpen(destBytes) { return readU32BE(host.call(OP_LINK_OPEN, destBytes), 0); }
function netLinkSend(linkId, bytes) { host.call(OP_LINK_SEND, args([linkId], [], bytes)); }
function netLinkClose(linkId, graceful) { host.call(OP_LINK_CLOSE, args([linkId], [graceful ? 1 : 0])); }
function netLinkCap(linkId) { host.call(OP_LINK_CAP, args([linkId], [])); }

function netDeliver(corr, noReply, fromBytes, proto, payload) {
  const head = new Uint8Array(1 + proto.length);
  head[0] = proto.length;
  head.set(proto, 1);
  host.call(OP_DELIVER, args([corr], [noReply ? 1 : 0], concatBytes([fromBytes, head, payload])));
}
function netSettle(corr, ok, payload) { host.call(OP_SETTLE, args([corr], [ok ? 1 : 0], payload)); }
/** Ask the host's WHITELIST whether this peer may link. Asked at the FIRST point the
 *  peer is known and — critically — before this end has revealed anything about
 *  itself: msg3 when accepting, msg4 when dialing. `conceal` tells the host a refusal
 *  must be silent, which is true exactly when we have not yet sent our identity.
 *  The gate is the host's because a predicate we applied to ourselves would gate
 *  nothing; the ORDER is ours, and it is what keeps a refusal from being an oracle. */
function netLinkAuth(linkId, peerBytes, conceal) {
  return host.call(OP_LINK_AUTH, args([linkId], [conceal ? 1 : 0], peerBytes))[0] === 1;
}
function netPeerEdge(up, peerBytes) { host.call(OP_PEER_EDGE, args([], [up ? 1 : 0], peerBytes)); }
function netReady(ok) { host.call(OP_READY, args([], [ok ? 1 : 0])); }
function netLinkDown(linkId, reason) { host.call(OP_LINK_DOWN, args([linkId], [reason])); }

// ── timers ────────────────────────────────────────────────────────────────────

function armTimer(ms, fn) {
  const id = nextTimerId++;
  timers.set(id, fn);
  host.call(OP_TIMER_ARM, args([id, Math.max(1, Math.floor(ms))], []));
  return id;
}
function clearTimer(id) {
  if (timers.delete(id)) host.call(OP_TIMER_CLEAR, args([id], []));
}
function fireTimer(id) {
  const fn = timers.get(id);
  if (fn) { timers.delete(id); fn(); }
}
function clearAllTimers() {
  for (const id of [...timers.keys()]) host.call(OP_TIMER_CLEAR, args([id], []));
  timers.clear();
}

// ── the link (PeerLink port, ex net-link.ts) ─────────────────────────────────

// A link is bound to one host-managed channel, addressed by the HOST-SUPPLIED
// link id — the table holds one instance per name (§3.1), so all session state
// lives here, keyed by that id.
class Link {
  constructor(spec) {
    this.linkId = spec.linkId;
    this.weDialed = spec.weDialed;
    this.expectPeerId = spec.expectPeerId;   // 32B or null
    this.source = spec.source;               // remoteAddr for the limiter, if any
    this.onAuth = spec.onAuth;
    this.onFrame = spec.onFrame;
    this.onClose = spec.onClose;
    this.handshakeTimeoutMs = spec.handshakeTimeoutMs;
    this.rekeyAfter = spec.rekeyAfterFrames || REKEY_AFTER_FRAMES;
    // Dialing: the secret gating the far end is THEIRS, carried by the address;
    // accepting: OURS. (net-link.ts §12.6.3)
    this.contactSecret = spec.dialSecret || contactSecret;
    this.root = hash(DOMAIN_CHANNEL, spec.networkKey || networkKey);

    this.peerPubkey = null;
    this.peerId = "";
    this.authed = false;
    this.peerSaidGoodbye = false;
    this.myNonce = null;
    this.myEph = null;
    this.queue = [];
    this.queuedBytes = 0;
    this.peerEph = null;
    this.closed = false;
    this.notified = false;
    this.closedLocally = false;
    this.aborted = false;
    this.slot = null;
    this.deadline = null;
    this.sendKey = null;
    this.recvKey = null;
    this.sendEpoch = 0;
    this.sendCtr = 0;
    this.recvEpoch = 0;
    this.recvCtr = 0;
    this.th = null;
    this.ee = null;

    // Half-open slot BEFORE any key material (the cap's point: a refused
    // connection costs a map lookup, not a keypair). Deferring the teardown of
    // an over-budget link keeps the constructor from notifying synchronously —
    // the caller's bookkeeping (core.accept etc.) runs after construction, so a
    // synchronous onClose would undo what it has not yet done (the
    // queueMicrotask of net-link.ts, here a post-event flush).
    if (spec.limiter) {
      this.slot = spec.limiter.acquire(this.source, () => this.abort());
      if (!this.slot) {
        this.closed = true;
        deferQueue.push(() => {
          try { netLinkClose(this.linkId, false); } catch { /* already gone */ }
          this.finish();
        });
        return;
      }
    }

    // Only a dialer speaks unprompted; an accepting link says nothing until a
    // msg1 opens under the contact secret — and a responder generates no key
    // material before that proof (net-link.ts §12.6.2).
    if (this.weDialed) {
      this.ensureKeys();
      this.armDeadline(this.handshakeTimeoutMs || HANDSHAKE_TIMEOUT_MS);
      this.sendMsg1();
    } else {
      this.armDeadline(this.handshakeTimeoutMs || UNVERIFIED_TIMEOUT_MS);
    }
  }

  ensureKeys() {
    if (this.myEph) return;
    this.myNonce = randomBytes(NONCE_LEN);
    this.myEph = boxKeypair();
  }

  armDeadline(ms) {
    this.clearDeadline();
    if (ms > 0) {
      this.deadline = armTimer(ms, () => { if (!this.authed) this.abort(); });
    }
  }

  clearDeadline() {
    if (this.deadline !== null) { clearTimer(this.deadline); this.deadline = null; }
  }

  // Queue (pre-auth) or send (post-auth, as an AEAD record) a frame.
  send(frame) {
    if (this.closed) return;
    // Refuse a frame that would seal to an over-cap wire record — the receiver
    // would reject it on its length prefix and tear the whole link down. The
    // cap itself is the host's (learned at INIT).
    if (frame.length > maxFrameBytes - 1 - TAG_LEN) return;
    // An empty record is the authenticated end-of-stream marker — never an
    // application frame.
    if (frame.length === 0) return;
    if (this.authed) {
      if (this.sendEpoch >= REJECT_AFTER_EPOCHS) { this.close(); return; }
      netLinkSend(this.linkId, this.tag(MSG_FRAME, this.seal(frame)));
      return;
    }
    this.queue.push(frame);
    this.queuedBytes += frame.length;
    while (this.queuedBytes > MAX_QUEUE_BYTES && this.queue.length > 1) {
      this.queuedBytes -= this.queue.shift().length;
    }
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.closedLocally = true;
    let saidGoodbye = false;
    if (this.authed && !this.peerSaidGoodbye && this.sendEpoch <= REJECT_AFTER_EPOCHS) {
      try {
        netLinkSend(this.linkId, this.tag(MSG_FRAME, this.seal(new Uint8Array(0))));
        saidGoodbye = true;
      } catch { /* the channel is already gone */ }
    }
    this.teardown();
    try { netLinkClose(this.linkId, saidGoodbye); } catch { /* already gone */ }
    this.finish();
  }

  // Every failure path uses abort(), never close(): only close() emits the
  // authenticated end-of-stream record, so "the peer said goodbye" always means
  // "the peer chose to stop" (net-link.ts hardening 4).
  abort(defensive) {
    if (this.closed) return;
    this.closed = true;
    this.closedLocally = true;
    if (defensive) this.aborted = true;
    this.teardown();
    try { netLinkClose(this.linkId, false); } catch { /* already gone */ }
    this.finish();
  }

  get closeReason() {
    if (!this.closed) return "open";
    if (!this.authed) return "handshake";
    if (this.peerSaidGoodbye) return "clean";
    if (this.aborted) return "aborted";
    if (this.closedLocally) return "local";
    return "truncated";
  }

  wasTruncated() { return this.closeReason === "truncated"; }

  // ── handshake ───────────────────────────────────────────────────────────────

  tag(type, payload) {
    const out = new Uint8Array(1 + payload.length);
    out[0] = type;
    out.set(payload, 1);
    return out;
  }

  onMessage(m) {
    if (this.closed || m.length < 1) return;
    const type = m[0];
    const body = m.subarray(1);
    if (type === MSG_HELLO) this.onMsg1(body);
    else if (type === MSG_AUTH) {
      // Which sealed message this is follows from our role and progress:
      // the initiator reads msg2 then msg4, the responder msg3.
      if (!this.weDialed) this.onMsg3(body);
      else if (!this.peerEph) this.onMsg2(body);
      else this.onMsg4(body);
    } else if (type === MSG_FRAME) this.onRecord(body);
    else this.stall();
  }

  // Refuse WITHOUT saying so — every suite-0x02 refusal funnels here so refusals
  // are indistinguishable from each other and from silence (net-link.ts §12.6.2).
  stall() { /* deliberately nothing */ }

  becomeAuthed() {
    this.authed = true;
    this.releaseSlot();
    this.clearDeadline();
    try { netLinkCap(this.linkId); } catch { /* no cap to raise */ }
    this.onAuth(this.peerId, this);
    if (this.closed) return; // onAuth may have torn us down (the tie-break)
    for (const f of this.queue) netLinkSend(this.linkId, this.tag(MSG_FRAME, this.seal(f)));
    this.queue.length = 0;
    this.queuedBytes = 0;
  }

  // ── the concealed-identity handshake (suite 0x02, §12.6.2) ──────────────────

  // BLAKE2b-256 over the concatenation — the one system hash.
  h() {
    return hash(...arguments);
  }

  // Every handshake key comes through here, so the contact secret is mixed into
  // all of them by construction.
  kdf(ikm, ctx, label) {
    const parts = [];
    for (const p of ikm) parts.push(p);
    parts.push(this.contactSecret, ctx, label);
    return this.h(...parts);
  }

  sealZero(key, plain) {
    const ct = aeadEnc(key, ZERO_NPUB, plain);
    key.fill(0);
    return ct;
  }
  openZero(key, ct) {
    try { return aeadDec(key, ZERO_NPUB, ct); }
    finally { key.fill(0); }
  }

  probeKey(suiteByte, ephI) {
    return this.kdf([], this.h(this.root, suiteByte, ephI), LABEL_PROBE);
  }

  signIdentity(th) {
    // The node key never enters this module: the host signs
    // `root ‖ th ‖ id` with the channel key after checking both (CHANNEL_SIGN).
    const r = channelSign(this.root, th, ownPk);
    if (!r.ok) { this.abort(); return null; } // the host refused the preimage — local fault
    return { id: ownPk, sig: r.sig };
  }

  openIdentity(key, ct, th) {
    const r = this.openZero(key, ct);
    if (!r.ok) return null;
    const plain = r.pt;
    const id = plain.slice(0, PK_LEN);
    const sig = plain.slice(PK_LEN, PK_LEN + SIG_LEN);
    if (!verify(id, sig, concatBytes([signPrefix, this.root, th, id]))) return null;
    if (bytesCompare(id, ownPk) === 0) return null; // our own traffic reflected
    return id;
  }

  sendMsg1() {
    const eph = this.myEph.publicKey.subarray(0, EPH_LEN);
    const w1 = concatBytes([SUITE_BYTE, eph, this.sealZero(this.probeKey(SUITE_BYTE, eph), this.myNonce)]);
    this.th = this.h(this.root, w1);
    netLinkSend(this.linkId, this.tag(MSG_HELLO, w1));
  }

  onMsg1(w1) {
    if (this.peerEph || this.weDialed || w1.length !== M1_LEN) { this.stall(); return; }
    if (w1[0] !== SUITE_CHANNEL_CONCEALED) { this.stall(); return; }
    const ephI = w1.slice(SUITE_LEN, SUITE_LEN + EPH_LEN);
    const probe = this.openZero(this.probeKey(w1.slice(0, SUITE_LEN), ephI), w1.slice(SUITE_LEN + EPH_LEN));
    if (!probe.ok) { this.stall(); return; }
    // Proved: move off the contended budget before the expensive work.
    if (this.slot && this.slot.limiter && !this.slot.limiter.promote(this.slot)) { this.stall(); return; }
    this.armDeadline(this.handshakeTimeoutMs || HANDSHAKE_TIMEOUT_MS);
    this.ensureKeys();
    const dh = scalarmult(this.myEph.privateKey, ephI);
    if (!dh.ok) { this.stall(); return; }
    this.ee = dh.x;
    this.peerEph = ephI;

    const h1 = this.h(this.root, w1);
    const w2 = concatBytes([
      this.myEph.publicKey.subarray(0, EPH_LEN),
      this.sealZero(this.kdf([this.ee], h1, LABEL_M2), this.myNonce),
    ]);
    this.th = this.h(h1, w2);
    netLinkSend(this.linkId, this.tag(MSG_AUTH, w2));
  }

  onMsg2(w2) {
    if (this.authed || this.peerEph || !this.th || w2.length !== M2_LEN) { this.stall(); return; }
    const ephR = w2.slice(0, EPH_LEN);
    const dh = scalarmult(this.myEph.privateKey, ephR);
    if (!dh.ok) { this.stall(); return; }
    const r = this.openZero(this.kdf([dh.x], this.th, LABEL_M2), w2.slice(EPH_LEN));
    if (!r.ok) { this.stall(); return; }
    this.ee = dh.x; this.peerEph = ephR;

    const h2 = this.h(this.th, w2);
    const si = this.signIdentity(h2);
    if (!si) return;
    const w3 = this.sealZero(this.kdf([this.ee], h2, LABEL_M3), concatBytes([si.id, si.sig]));
    this.th = this.h(h2, w3);
    netLinkSend(this.linkId, this.tag(MSG_AUTH, w3));
  }

  onMsg3(w3) {
    if (this.authed || !this.peerEph || !this.th || !this.ee || w3.length !== M3_LEN) { this.stall(); return; }
    const idI = this.openIdentity(this.kdf([this.ee], this.th, LABEL_M3), w3, this.th);
    if (!idI) { this.stall(); return; }
    const peerId = toHex(idI);
    // The whitelist gate runs HERE — after decryption and signature, never on a claimed
    // key, and before msg4 puts our identity and signature on the wire. A refusal is
    // silence, so being turned away is indistinguishable from a msg3 that simply never
    // arrived, and the caller learns nothing about who lives at this address. Nothing
    // about us has gone out yet, and that is the whole point of the second round trip
    // (§12.6.2, CHANNEL §10 invariant 5). Asking at becomeAuthed() instead would be one
    // message too late.
    if (!netLinkAuth(this.linkId, idI, true)) { this.stall(); return; }
    this.peerPubkey = idI; this.peerId = peerId;

    const h3 = this.h(this.th, w3);
    const si = this.signIdentity(h3);
    if (!si) return;
    const w4 = this.sealZero(this.kdf([this.ee], h3, LABEL_M4), concatBytes([si.id, si.sig]));
    this.th = this.h(h3, w4);
    try { this.deriveConcealedSession(); } catch { this.stall(); return; }
    netLinkSend(this.linkId, this.tag(MSG_AUTH, w4));
    this.becomeAuthed();
  }

  onMsg4(w4) {
    if (this.authed || !this.peerEph || !this.th || !this.ee || w4.length !== M4_LEN) { this.stall(); return; }
    const idR = this.openIdentity(this.kdf([this.ee], this.th, LABEL_M4), w4, this.th);
    if (!idR) { this.stall(); return; }
    const peerId = toHex(idR);
    // A mismatch here is a local fault, not a probe to hide from — we already
    // revealed ourselves at msg3 — so it aborts rather than stalls.
    if (this.expectPeerId && peerId !== toHex(this.expectPeerId)) { this.abort(); return; }
    // Our own whitelist gate, on the end that dialed. Not concealed: we named ourselves at
    // msg3, so there is nothing left to hide from this peer and an abort is honest.
    if (!netLinkAuth(this.linkId, idR, false)) { this.abort(true); return; }
    this.peerPubkey = idR; this.peerId = peerId;
    this.th = this.h(this.th, w4);
    try { this.deriveConcealedSession(); } catch { this.abort(); return; }
    this.becomeAuthed();
  }

  deriveConcealedSession() {
    const kI2R = this.kdf([this.ee], this.th, LABEL_I2R);
    const kR2I = this.kdf([this.ee], this.th, LABEL_R2I);
    this.sendKey = this.weDialed ? kI2R : kR2I;
    this.recvKey = this.weDialed ? kR2I : kI2R;
    this.ee.fill(0);
    this.ee = null;
  }

  // A 12-byte nonce from the implicit (epoch, counter) pair — never transmitted.
  nonce(epoch, ctr) {
    const n = new Uint8Array(NPUB_LEN);
    writeU32BE(n, 0, epoch);
    writeU32BE(n, 8, ctr);
    return n;
  }

  ratchet(k) {
    const next = this.h(k, LABEL_REKEY);
    k.fill(0);
    return next;
  }

  seal(frame) {
    const ct = aeadEnc(this.sendKey, this.nonce(this.sendEpoch, this.sendCtr), frame);
    if (++this.sendCtr >= this.rekeyAfter) {
      this.sendKey = this.ratchet(this.sendKey);
      this.sendEpoch++;
      this.sendCtr = 0;
    }
    return ct;
  }

  onRecord(body) {
    if (!this.authed || !this.recvKey || body.length < TAG_LEN) { this.abort(this.authed); return; }
    if (this.recvEpoch >= REJECT_AFTER_EPOCHS) { this.abort(); return; }
    const r = aeadDec(this.recvKey, this.nonce(this.recvEpoch, this.recvCtr), body);
    if (!r.ok) { this.abort(true); return; }
    // Advance only on success — a failed decrypt must never move the counter.
    if (++this.recvCtr >= this.rekeyAfter) {
      this.recvKey = this.ratchet(this.recvKey);
      this.recvEpoch++;
      this.recvCtr = 0;
    }
    // The reserved empty record: an authenticated end-of-stream.
    if (r.pt.length === 0) { this.peerSaidGoodbye = true; this.close(); return; }
    this.onFrame(this.peerId, r.pt);
  }

  onChannelClosed() {
    if (this.notified) return;
    this.closed = true;
    this.teardown();
    this.finish();
  }

  // ── teardown ────────────────────────────────────────────────────────────────

  teardown() {
    this.clearDeadline();
    this.releaseSlot();
    this.queue.length = 0;
    this.queuedBytes = 0;
    if (this.sendKey) this.sendKey.fill(0);
    if (this.recvKey) this.recvKey.fill(0);
    this.sendKey = null;
    this.recvKey = null;
    if (this.ee) this.ee.fill(0);
    this.ee = null;
  }

  releaseSlot() {
    if (!this.slot) return;
    const slot = this.slot;
    this.slot = null;
    slot.limiter.release(slot);
  }

  finish() {
    if (this.notified) return;
    this.notified = true;
    this.onClose(this);
  }
}

// The half-open limiter (ex net-link.ts HalfOpenLimiter). The budgets come from
// EVT_INIT — a module does not declare the numbers that bound it either.
class HalfOpenLimiter {
  constructor(maxUnverified, maxPerSource, maxVerified) {
    this.maxUnverified = maxUnverified;
    this.maxPerSource = maxPerSource;
    this.maxVerified = maxVerified;
    this.unverifiedCount = 0;
    this.verifiedCount = 0;
    this.nextId = 0;
    this.perSource = new Map();
    this.waiting = new Map();    // insertion order is the eviction policy
    this.promoting = new Map();
  }

  acquire(source, evict) {
    if (source !== undefined && (this.perSource.get(source) || 0) >= this.maxPerSource) return null;
    if (this.unverifiedCount >= this.maxUnverified) {
      const oldest = this.waiting.keys().next();
      if (oldest.done) return null;
      const victim = this.waiting.get(oldest.value);
      this.waiting.delete(oldest.value);
      this.forget(victim);
      try { victim.evict(); } catch { /* already gone */ }
    }
    const slot = { source, tier: "unverified", released: false, evict, limiter: this };
    if (source !== undefined) this.perSource.set(source, (this.perSource.get(source) || 0) + 1);
    this.unverifiedCount++;
    this.waiting.set(this.nextId++, slot);
    return slot;
  }

  promote(slot) {
    if (slot.released || slot.tier === "verified") return true;
    if (this.verifiedCount >= this.maxVerified) {
      const oldest = this.promoting.keys().next();
      if (oldest.done) return false;
      const victim = this.promoting.get(oldest.value);
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

  release(slot) {
    if (slot.released) return;
    const book = slot.tier === "verified" ? this.promoting : this.waiting;
    for (const [id, s] of book) if (s === slot) { book.delete(id); break; }
    this.forget(slot);
  }

  forget(slot) {
    if (slot.released) return;
    slot.released = true;
    if (slot.tier === "verified") { if (this.verifiedCount > 0) this.verifiedCount--; }
    else if (this.unverifiedCount > 0) this.unverifiedCount--;
    if (slot.source === undefined) return;
    const n = this.perSource.get(slot.source);
    if (n === undefined) return;
    if (n <= 1) this.perSource.delete(slot.source); else this.perSource.set(slot.source, n - 1);
  }

  get outstanding() { return this.unverifiedCount + this.verifiedCount; }
}

// ── the router (ex link-router.ts) ────────────────────────────────────────────

class Router {
  constructor(ownPubkey, ownId) {
    this.ownPubkey = ownPubkey;
    this.ownId = ownId;
    this.links = new Map();      // peerId → Link[] (authenticated, routable)
    this.rr = new Map();         // peerId → round-robin cursor
    this.sink = null;            // the request/response layer's frame intake
    this.framesDelivered = 0;
    this.onPeerUp = () => {};
    this.onPeerDown = () => {};
  }

  linkedPeers() { return [...this.links.keys()]; }
  linkCount(peerId) { const a = this.links.get(peerId); return a ? a.length : 0; }

  send(to, frame) {
    const pool = this.links.get(to);
    if (!pool || pool.length === 0) return false;
    const i = (this.rr.get(to) || 0) % pool.length;
    this.rr.set(to, i + 1);
    pool[i].send(frame);
    return true;
  }

  // Install a freshly-authenticated link: the double-connect tie-break and the up edge
  // on a peer's first link. Returns false — the link closed — when it lost the tie-break.
  //
  // The whitelist gate is NOT here. It is the host's policy, and a gate this program is
  // asked to apply to itself is one a hostile occupant of this slot simply skips; the
  // driver enforces it on the attribution this program reports (LINK_AUTH / PEER_UP),
  // where it cannot be bypassed.
  promote(peerId, link) {
    const pool = this.links.get(peerId) || [];
    const wasEmpty = pool.length === 0;
    let rival = null;
    for (const l of pool) if (l.weDialed !== link.weDialed) { rival = l; break; }
    if (rival) {
      if (!this.canonicalKeep(link)) { link.close(); return false; }
      // Splice the rival out BEFORE closing it: close() reaches the transport's
      // forget() → remove() synchronously, which would otherwise splice the very
      // array we are editing (link-router.ts promote).
      pool.splice(pool.indexOf(rival), 1);
      this.links.set(peerId, pool);
      rival.close();
    }
    pool.push(link);
    this.links.set(peerId, pool);
    if (wasEmpty) this.onPeerUp(peerId);
    return true;
  }

  // Keep the link whose *dialer* is the lexicographically smaller identity.
  canonicalKeep(link) {
    const peer = link.peerPubkey, mine = this.ownPubkey;
    const dialer = link.weDialed ? mine : peer;
    const smaller = bytesCompare(mine, peer) <= 0 ? mine : peer;
    return bytesCompare(dialer, smaller) === 0;
  }

  deliver(peerId, frame) {
    if (!this.sink || peerId === this.ownId) return;
    this.framesDelivered++;
    this.sink(peerId, frame);
  }

  remove(link) {
    for (const [pid, pool] of this.links) {
      const i = pool.indexOf(link);
      if (i < 0) continue;
      pool.splice(i, 1);
      if (pool.length === 0) { this.links.delete(pid); this.rr.delete(pid); this.onPeerDown(pid); }
      return true;
    }
    return false;
  }

  closeAll() {
    const all = [];
    for (const pool of this.links.values()) for (const l of pool) all.push(l);
    this.links.clear();
    this.rr.clear();
    for (const l of all) l.close();
  }
}

// ── the request/response layer (ex net.ts Transport) ──────────────────────────

// The event-driven twin of net.ts's Promise-based Transport: the HOST holds the
// promises (keyed by the corr it assigned) and this layer holds the wire state —
// correlation, the silence-based stall clock, the response binding — driven by
// host timer events. `to`/`from` are hex peer ids; proto is opaque bytes.
class ReqRes {
  constructor() {
    this.pending = new Map();   // corr → {to, issuedAt, deadline}
    this.lastFrameAt = new Map();
    this.timers = new Map();    // corr → timerId
  }

  attach(sendFrame, now) {
    this.sendFrame = sendFrame;
    this.now = now;
  }

  request(corr, to, proto, payload, noReply) {
    const frame = this.buildReq(corr, noReply, proto, payload);
    if (!noReply) {
      // A noReply send carries corr 0 and never resolves — the host keeps no
      // promise for it, so nothing here is parked on its behalf.
      const issuedAt = this.now();
      const deadline = issuedAt + timeoutMs * maxStallWindows;
      this.pending.set(corr, { to, issuedAt, deadline });
      const check = () => {
        const p = this.pending.get(corr);
        if (!p) return;
        this.timers.delete(corr);
        const now = this.now();
        const last = Math.max(p.issuedAt, this.lastFrameAt.get(to) || 0);
        const remaining = last + timeoutMs - now;
        if (remaining > 0 && now < p.deadline) {
          this.timers.set(corr, armTimer(Math.min(remaining, p.deadline - now), check));
          return;
        }
        this.pending.delete(corr);
        netSettle(corr, false, utf8Encode("net.send: " + (remaining > 0 ? "backstop" : "timeout") + " to " + to.slice(0, 8)));
      };
      this.timers.set(corr, armTimer(timeoutMs, check));
    }
    this.sendFrame(to, frame);
  }

  buildReq(corr, noReply, proto, payload) {
    const frame = new Uint8Array(1 + 4 + 1 + proto.length + payload.length);
    frame[0] = noReply ? 0x80 : 0; // KIND_REQ | FLAG_NO_REPLY
    writeU32BE(frame, 1, corr);
    frame[5] = proto.length;
    frame.set(proto, 6);
    frame.set(payload, 6 + proto.length);
    return frame;
  }

  onFrame(from, frame) {
    this.lastFrameAt.set(from, this.now());
    // A response is `[1][corr u32][payload]`, so an EMPTY response is exactly five
    // bytes — the shortest legal frame. Requiring six here dropped it, and since a
    // request nobody is bound to answers empty by contract, that made "no app serves
    // this protocol" indistinguishable from an unreachable peer: the caller waited out
    // its stall clock instead of being told nothing was there. The six-byte floor is
    // the REQUEST branch's (it needs the protocol-id length at offset 5) and is
    // checked there.
    if (frame.length < 5) return;
    const kind = frame[0];
    const noReply = !!(kind & 0x80);
    const corr = readU32BE(frame, 1);
    if ((kind & 1) === 1) {
      // res = [1][corr u32][payload]
      const p = this.pending.get(corr);
      if (!p || p.to !== from) return; // response bound to the peer it went to
      this.pending.delete(corr);
      const t = this.timers.get(corr);
      if (t) { clearTimer(t); this.timers.delete(corr); }
      netSettle(corr, true, frame.slice(5));
      return;
    }
    if ((kind & 1) === 0) {
      if (frame.length < 6) return; // no room for the protocol-id length byte
      const idLen = frame[5];
      if (frame.length < 6 + idLen) return;
      const proto = frame.slice(6, 6 + idLen);
      const payload = frame.slice(6 + idLen);
      netDeliver(corr, noReply, fromHex(from), proto, payload);
    }
  }

  // The response to a DELIVER'd request, addressed back to `from`. noReply runs
  // the host's handler but skips the wire response.
  respond(corr, noReply, from, payload) {
    if (noReply) return;
    const body = payload || new Uint8Array(0);
    const frame = new Uint8Array(5 + body.length);
    frame[0] = 1; // KIND_RES
    writeU32BE(frame, 1, corr);
    frame.set(body, 5);
    this.sendFrame(from, frame);
  }

  close() {
    for (const t of this.timers.values()) clearTimer(t);
    this.timers.clear();
    this.pending.clear();
    this.lastFrameAt.clear();
  }
}

// ── the routing core (ex net-route.ts NodeNetworkCore) ────────────────────────

class Core {
  constructor() {
    this.connecting = new Map(); // peerId → Link[] (outbound, pre-auth)
    this.inbound = new Set();    // accepted, pre-auth
    this.addrs = new Map();      // peerId → 32B contact secret (or null = open)
    this.framesSent = 0;
    this.readyWaiter = null;     // {check, timer}
    this.halfOpen = new HalfOpenLimiter(maxUnverified, maxPerSource, maxVerified);
  }

  static push(m, peerId, link) {
    const a = m.get(peerId); if (a) a.push(link); else m.set(peerId, [link]);
  }
  static drop(m, peerId, link) {
    const a = m.get(peerId); if (!a) return false;
    const i = a.indexOf(link); if (i < 0) return false;
    a.splice(i, 1);
    if (a.length === 0) m.delete(peerId);
    return true;
  }

  addAddr(peerBytes, secret) {
    this.addrs.set(toHex(peerBytes), secret.length > 0 ? secret : null);
  }

  // Top a dialed peer up to connsPerPeer outbound links. `NET_LINK_OPEN` is the raw
  // capability and it answers immediately with the link id (or 0 for no route), so
  // the link lands in `connecting` before this returns — there is no in-flight dial
  // window any more, and with it went the queue of frames that used to wait one out.
  dial(peerId) {
    if (!this.addrs.has(peerId)) return;
    const have = router.linkCount(peerId) + (this.connecting.get(peerId) || []).length;
    for (let n = have; n < connsPerPeer; n++) {
      const linkId = netLinkOpen(fromHex(peerId));
      if (linkId === 0) return; // no route — a fabric with nowhere to send drops the frame
      this.openLink({
        linkId,
        weDialed: true,
        expectPeerId: fromHex(peerId),
        dialSecret: this.addrs.get(peerId),
        limiter: null,
        dialedPeerId: peerId,
      });
    }
  }

  // An inbound (accepted) channel, or a link we just dialed.
  openLink(spec) {
    const link = new Link({
      linkId: spec.linkId,
      weDialed: spec.weDialed,
      expectPeerId: spec.expectPeerId,
      dialSecret: spec.dialSecret,
      source: spec.source,
      limiter: spec.limiter,
      handshakeTimeoutMs: spec.handshakeTimeoutMs,
      rekeyAfterFrames: spec.rekeyAfterFrames,
      onAuth: (pid, l) => this.onAuth(pid, l),
      onFrame: (pid, frame) => router.deliver(pid, frame),
      onClose: (l) => this.forget(l),
    });
    if (spec.weDialed) Core.push(this.connecting, spec.dialedPeerId, link);
    else this.inbound.add(link);
    return link;
  }

  onAuth(peerId, link) {
    this.inbound.delete(link);
    Core.drop(this.connecting, peerId, link);
    // The whitelist already answered, at msg3 or msg4 — a link that reaches auth is one
    // the host admitted, so a refused peer never appears on a cohort edge it would
    // immediately have to be taken off again. All that is left here is routing.
    router.promote(peerId, link);
  }

  forget(link) {
    this.inbound.delete(link);
    for (const pid of [...this.connecting.keys()]) {
      if (Core.drop(this.connecting, pid, link)) break;
    }
    router.remove(link);
  }

  sendFrame(to, frame) {
    if (to === ownId) return;
    this.framesSent++;
    if (router.send(to, frame)) return;
    let pool = this.connecting.get(to);
    // Dialing lands the link synchronously now, so the frame goes straight into its
    // pre-auth queue. (No address → dropped, exactly as a fabric with no route drops
    // a frame.)
    if (!pool || pool.length === 0) { this.dial(to); pool = this.connecting.get(to); }
    if (!pool || pool.length === 0) return;
    pool[0].send(frame);
  }

  // Resolve once every known peer is authenticated (or the deadline passes) —
  // event-driven off the router's up edge, like net-route.ts.
  ready(timeoutMs) {
    const targets = [...this.addrs.keys()].filter((p) => p !== ownId);
    for (const p of targets) this.dial(p);
    const allUp = () => targets.every((p) => router.linkCount(p) >= 1);
    if (allUp()) { netReady(true); return; }
    this.readyWaiter = { check: allUp, timer: armTimer(timeoutMs, () => {
      this.readyWaiter = null;
      netReady(allUp());
    }) };
  }

  checkReady() {
    if (this.readyWaiter && this.readyWaiter.check()) {
      clearTimer(this.readyWaiter.timer);
      this.readyWaiter = null;
      netReady(true);
    }
  }

  close() {
    if (this.readyWaiter) { clearTimer(this.readyWaiter.timer); this.readyWaiter = null; }
    const pending = [];
    for (const arr of this.connecting.values()) for (const l of arr) pending.push(l);
    for (const l of this.inbound) pending.push(l);
    this.connecting.clear();
    this.inbound.clear();
    router.closeAll();
    for (const l of pending) l.close();
  }
}

// ── init ──────────────────────────────────────────────────────────────────────

function init(cfg) {
  ownPk = cfg.ownPk;
  ownId = toHex(ownPk);
  networkKey = cfg.networkKey;
  signPrefix = concatBytes([DOMAIN_CHANNEL, networkKey]);
  contactSecret = cfg.contactSecret;
  timeoutMs = cfg.timeoutMs;
  connsPerPeer = Math.max(1, Math.floor(cfg.connsPerPeer || 1));
  maxFrameBytes = cfg.maxFrameBytes;
  maxStallWindows = cfg.maxStallWindows;
  maxUnverified = cfg.maxUnverified;
  maxPerSource = cfg.maxPerSource;
  maxVerified = cfg.maxVerified;

  router = new Router(ownPk, ownId);
  reqres = new ReqRes();
  core = new Core();
  reqres.attach((to, frame) => core.sendFrame(to, frame), clockNow);
  router.sink = (from, frame) => reqres.onFrame(from, frame);
  router.onPeerUp = (peerId) => {
    core.checkReady();
    netPeerEdge(true, fromHex(peerId));
  };
  router.onPeerDown = (peerId) => netPeerEdge(false, fromHex(peerId));
}

// ── argument decoding ─────────────────────────────────────────────────────────

// Each entrypoint below declares its own fixed field order: u32 BE fields, then u8
// fields, then length-prefixed blobs (`[len u32 BE][bytes]`, an empty blob being
// length 0). There is no tag byte and no shared union — the entrypoint's NAME is the
// discriminator, and it is the realm's, so there is no tag space to keep in step and
// no unknown-tag case a decoder could desync on. The host twin is transport-host.ts's
// `Args`.
function Reader(b) {
  this.b = b;
  this.off = 0;
}
Reader.prototype.u8 = function () { return this.b[this.off++]; };
Reader.prototype.u32 = function () {
  const v = readU32BE(this.b, this.off);
  this.off += 4;
  return v;
};
Reader.prototype.blob = function () {
  const n = this.u32();
  const s = this.b.subarray(this.off, this.off + n);
  this.off += n;
  return s;
};

/** Every core link, wherever it currently sits: authenticated ones live in the
 *  router's pools, pre-auth ones in the core's connecting/inbound tables, and a
 *  host-managed one in `openLinks`. */
function findLink(linkId) {
  const open = openLinks.get(linkId);
  if (open) return open;
  for (const pool of router.links.values()) {
    for (const link of pool) if (link.linkId === linkId) return link;
  }
  for (const arr of core.connecting.values()) {
    for (const link of arr) if (link.linkId === linkId) return link;
  }
  for (const link of core.inbound) if (link.linkId === linkId) return link;
  return null;
}

// ── the entrypoints ───────────────────────────────────────────────────────────
//
// The host invokes each of these synchronously by name, exactly as it invokes an
// app's holder `handle`. They answer by calling ops back out (above), not by
// returning a payload — so every one returns the same empty bytes, and a reader
// looking for what an entrypoint DOES looks at what it calls.
//
// A deferred teardown (Link's over-budget path) is flushed at the end of whichever
// entrypoint provoked it, so a link's bookkeeping is never undone by an onClose that
// ran before its caller finished.

const NOTHING = new Uint8Array(0);

function entry(name, fn) {
  register(name, (argBytes) => {
    fn(new Reader(argBytes));
    const deferred = deferQueue.splice(0);
    for (const f of deferred) { try { f(); } catch { /* teardown of a gone link */ } }
    return NOTHING;
  });
}

/** The one config turn: who we are, which network, and the budgets — including the
 *  HOST's flood cap, which this module learns rather than declares. */
entry("init", (r) => {
  init({
    ownPk: r.blob(), networkKey: r.blob(), contactSecret: r.blob(),
    timeoutMs: r.u32(), connsPerPeer: r.u32(),
    maxUnverified: r.u32(), maxPerSource: r.u32(), maxVerified: r.u32(),
    maxFrameBytes: r.u32(), maxStallWindows: r.u32(),
  });
});

/** A link the HOST opened: an accepted socket (kind CORE), or one a host-managed
 *  transport handed over (kind OPEN, either direction). A core link we dialed never
 *  arrives here — `Core.dial` opens those itself through the raw capability. */
entry("linkOpen", (r) => {
  const linkId = r.u32();
  const weDialed = r.u8() === 1;
  const kind = r.u8();
  const handshakeTimeoutMs = r.u32();
  const rekeyAfterFrames = r.u32();
  const expectPeerId = r.blob();
  const dialSecret = r.blob();
  const source = r.blob();
  const spec = {
    linkId, weDialed,
    expectPeerId: expectPeerId.length > 0 ? expectPeerId.slice() : null,
    dialSecret: dialSecret.length > 0 ? dialSecret.slice() : null,
    source: source.length > 0 ? utf8Decode(source) : undefined,
    handshakeTimeoutMs: handshakeTimeoutMs > 0 ? handshakeTimeoutMs : undefined,
    rekeyAfterFrames: rekeyAfterFrames > 0 ? rekeyAfterFrames : undefined,
    limiter: null,
  };
  if (kind === LINK_CORE) {
    // Only an accept spends half-open budget; a dial is our own decision to make.
    spec.limiter = weDialed ? null : core.halfOpen;
    spec.dialedPeerId = weDialed ? toHex(expectPeerId) : null;
    core.openLink(spec);
    return;
  }
  // A host-managed transport (WebRTC / browser WS): the socket is the caller's;
  // auth goes to the shared router, and the host tracks the link by its id.
  const link = new Link(Object.assign({}, spec, {
    onAuth: (peerId, l) => {
      // The host's whitelist answered at msg3/msg4; what is left is ours — the
      // double-connect tie-break.
      if (!router.promote(peerId, l)) l.close();
    },
    onFrame: (peerId, frame) => router.deliver(peerId, frame),
    onClose: () => {
      openLinks.delete(linkId);
      router.remove(link);
      netLinkDown(linkId, reasonCode(link));
    },
  }));
  openLinks.set(linkId, link);
});

entry("linkBytes", (r) => {
  const link = findLink(r.u32());
  if (link) link.onMessage(r.blob());
});

entry("linkClosed", (r) => {
  const link = findLink(r.u32());
  if (link) link.onChannelClosed();
});

entry("timer", (r) => { fireTimer(r.u32()); });

/** An app wants a typed request sent. The host holds the promise under `corr` and
 *  this side holds the wire state; the stall clock is a host-armed timer. */
entry("request", (r) => {
  const corr = r.u32();
  const noReply = r.u8() === 1;
  const to = r.blob();
  const proto = r.blob().slice();
  const payload = r.blob().slice();
  reqres.request(corr, toHex(to), proto, payload, noReply);
});

/** The raw Endpoint face: one whole frame to one peer, no correlation. */
entry("sendFrame", (r) => {
  const to = r.blob();
  core.sendFrame(toHex(to), r.blob().slice());
});

/** The answer to a NET_DELIVER, on a later turn than the delivery itself — which is
 *  what lets the app-side handler be asynchronous, and what keeps an op from
 *  re-entering a guest frame that is still on the stack. */
entry("respond", (r) => {
  const corr = r.u32();
  const noReply = r.u8() === 1;
  const from = r.blob();
  reqres.respond(corr, noReply, toHex(from), r.blob().slice());
});

entry("addr", (r) => {
  const peer = r.blob();
  core.addAddr(peer, r.blob());
});

entry("ready", (r) => { core.ready(r.u32()); });

// There is no `shutdown` entrypoint, deliberately. Teardown releases the sockets and the
// timers, and both are the HOST's — it closes them itself (transport-host.ts `close`)
// rather than asking the occupant, because it owns the descriptor and a wedged occupant
// must not be able to refuse. What is left is this realm's own heap, which dies with the
// realm. An entrypoint whose only effect would be tidying memory about to be freed is one
// more thing to keep in step for nothing.

// ── the host-managed link handle (openLink's LinkHandle) ──────────────────────

entry("linkSend", (r) => {
  const link = findLink(r.u32());
  if (link) link.send(r.blob().slice());
});

entry("linkClose", (r) => {
  const link = findLink(r.u32());
  if (link) link.close();
});
