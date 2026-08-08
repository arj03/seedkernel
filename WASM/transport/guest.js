// ============================================================================
// The transport bundle guest — the channel handshake (AKE + forward-secret
// record layer, ex net-link.ts), the authenticated link router (ex link-router.ts),
// the link bookkeeping (ex net-route.ts NodeNetworkCore) and the request/response
// layer (ex net.ts) — as the zero-authority JS program of a signed bundle claiming
// the shell's explicit transport mount.
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
//   - `host.call(name, bytes)` — ONE seam, addressed by name (§12.2). What this
//     program uses, declared in its manifest's `guest.requires` — the names a host
//     that cannot serve them refuses the bundle by, at load:
//       "crypto/blake2b-256"               bytes -> 32B      (transcript, KDF, root)
//       "crypto/chacha20poly1305-ietf/seal" [npub 12][key 32][msg] -> ct      (record layer)
//       "crypto/chacha20poly1305-ietf/open" [npub 12][key 32][ct] -> [ok u8][pt]
//       "crypto/x25519/dh"                 [sk 32][pk 32] -> [ok u8][x 32]   (ephemeral DH,
//                                        and against the base point, the pubkey too)
//
//     Changing suite is changing these names. It costs this file and a host that
//     already carries the primitive — no op number, no ABI rev, no new grant.
//
//     The AUTHORITIES the manifest's `requires` grants — the whole of what this
//     program holds, by EXACT name (README §12.2):
//       "node/sign"   msg -> 64B sig. The host prefixes `DOMAIN_channel ‖ networkKey`
//                     from THIS bundle's admission point and signs the opaque suffix with the node's
//                     channel key, which never enters this module. It does not read the
//                     suffix — the domain separation is the guarantee, so no transcript
//                     shape is pinned into the host and no call signs raw bytes.
//       "node/verify" [pk 32][sig 64][msg] -> [ok u8]. The SAME scope, host-applied:
//                     verifies a peer's transcript signature under the caller-named key
//                     without this module ever reconstructing the prefix it was made
//                     under — the one side of signing the two ends have to agree on is
//                     the host's, never this program's.
//       "node/random" [n u32 BE] -> n random bytes            (nonces, ephemeral secrets)
//
//     `link` — the platform's whole contribution to the network: bytes over an opaque
//     link id, opened and closed. `timer` — deadlines, because a zero-authority realm
//     has no setTimeout. `transport` — where this program reports its structured
//     OUTPUT (an attributed peer, a protocol id, a correlation), which every app then
//     reaches through the ordinary `net` domain. Its own ws.wasm is NOT here: a bare
//     name is a primitive — the bundle's own code, ungated like `crypto` (§12.1) — so
//     no grant is needed to name it.
//
//     The whitelist gate is deliberately NOT ours to apply. It is host policy over the
//     attribution this program reports (transport/link-auth answers with the verdict,
//     and the host has already closed the channel on a refusal); a gate this program
//     applied to itself would be one a hostile transport would simply skip.
//
//   - entrypoints, invoked synchronously by name — `linkBytes`, `timer`, `request`
//     and the rest below. This is the SAME mechanism an app's holder `handle` is
//     invoked through: there is no second host↔module ABI, no event tag space, and
//     an entrypoint this program does not register fails loud by name rather than
//     desyncing a decoder.
//
// The node key stays out of this module in the strongest sense: there is no call
// that signs arbitrary bytes — node/sign is scoped by the point the host admitted this
// bundle into, so a compromised transport can neither forge app signatures nor
// sign for another network. Its verification twin is equally scope-bound: node/verify
// answers only under this mount's own scope, so this program checks a peer's
// transcript signature without holding the domain tag it was made under.
//
// Channels are host handles keyed by a link id the HOST minted — the module table
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

// ── capability names (must match the cap-bridge's dispatch table) ─────────────

// Authorities only — a primitive has no name of its own beyond `crypto/<name>` (see
// below).
const N_SIGN = "node/sign";
const N_VERIFY = "node/verify";
const N_RANDOM = "node/random";
/** This bundle's own RFC 6455 codec, by the logical name its manifest declares. A bare
 *  name — no `/` — is what makes it a module rather than a host name (§12.2), and it is
 *  ungated for the same reason `crypto/*` is: it is this bundle's own verified code. */
const N_WS = "ws";

// The raw net capability: bytes over an opaque link id, opened and closed. This is
// the whole of what the platform contributes — there is no peer here, no framing and
// no attribution, because those are state machines and state machines are ours.
const N_LINK_OPEN = "link/open";
const N_LINK_SEND = "link/send";
const N_LINK_CLOSE = "link/close";
// A READ of a link's unsent backlog — the only way this program can tell a slow
// exchange from a stalled one, since everything else it sees is its own bookkeeping.
const N_LINK_STAT = "link/stat";

// The platform's event loop.
const N_TIMER_ARM = "timer/arm";
const N_TIMER_CLEAR = "timer/clear";

// What this program PROVIDES back — the structured face the platform does not have.
const N_DELIVER = "transport/deliver";
const N_SETTLE = "transport/settle";
const N_LINK_AUTH = "transport/link-auth";
const N_PEER_EDGE = "transport/peer-edge";
const N_READY = "transport/ready";
const N_LINK_DOWN = "transport/link-down";

// The primitives this program asks for by name, through the `crypto/` prefix — the
// full names as the manifest's `guest.requires` declares them, so a host that cannot
// serve one refuses the bundle at load rather than failing here.
const P_HASH = "crypto/blake2b-256";
const P_SEAL = "crypto/chacha20poly1305-ietf/seal";
const P_OPEN = "crypto/chacha20poly1305-ietf/open";
const P_DH = "crypto/x25519/dh";

// The X25519 base point. `crypto/x25519/dh(sk, BASEPOINT)` is the public-key
// derivation, so the catalog needs no keygen entry and the ephemeral secret comes from
// node/random — which keeps the entropy grant where it belongs and the catalog purely
// functional.
const X25519_BASEPOINT = new Uint8Array([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

// Kinds of link, as the host's `linkOpen` declares them: 0 = the routing core's own
// (an accepted socket; dial/accept bookkeeping and the half-open limiter apply);
// 1 = a host-managed transport (WebRTC / browser WS) that opened the socket itself
// and handed it over (openLink). A CORE link we DIALED never arrives this way — we
// open those ourselves through link/open and already know everything about them.
const LINK_CORE = 0;
const LINK_OPEN = 1;

// Link close-reason codes (transport/link-down's u8) — mirror Link.closeReason.
const REASON_OPEN = 0, REASON_HANDSHAKE = 1, REASON_CLEAN = 2, REASON_ABORTED = 3,
      REASON_LOCAL = 4, REASON_TRUNCATED = 5;

function reasonCode(link) {
  const r = link.closeReason;
  return r === "handshake" ? REASON_HANDSHAKE : r === "clean" ? REASON_CLEAN
    : r === "aborted" ? REASON_ABORTED : r === "local" ? REASON_LOCAL
    : r === "truncated" ? REASON_TRUNCATED : REASON_OPEN;
}

// ── channel handshake constants (ex net-link.ts §12.6) ───────────────────────

const SUITE_CHANNEL_CONCEALED = 0x02;
const SUITE_LEN = 1, PK_LEN = 32, NONCE_LEN = 32, EPH_LEN = 32, SIG_LEN = 64;
const KEY_LEN = 32, NPUB_LEN = 12, TAG_LEN = 16;
const M1_LEN = SUITE_LEN + EPH_LEN + NONCE_LEN + TAG_LEN; //  81
const M2_LEN = EPH_LEN + NONCE_LEN + TAG_LEN;             //  80
const M3_LEN = PK_LEN + SIG_LEN + TAG_LEN;                // 112
const M4_LEN = PK_LEN + SIG_LEN + TAG_LEN;                // 112

// The one suite this transport speaks, and the bundle's own number: a channel suite
// is read by the AKE, which is entirely this program, so it lives here rather than in
// the host's core (§14.1 — the manifest suite is the host's for the opposite reason,
// the loader reads it before anything is trusted). The cleartext-identity genesis
// suite 0x01 was removed rather than disabled, because a node accepting both would
// have the concealment of neither.
//
// A suite byte is not negotiated: it makes the wire self-describing, and because it
// sits inside every signed transcript half, an in-path attacker who flips it only
// makes the two ends sign different bytes (§12.6, §14.1).
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

// The channel-id domain tag, for the session ROOT derivation only (Link: root =
// blake2b(DOMAIN_channel ‖ networkKey)) — the KDF's domain separator, this bundle's
// own wire contract like the LABEL_* strings above. It is NOT the sign-prefix domain:
// that half of signing is the host's (transportSignScope) and this program never
// reconstructs it — node/verify applies it for us.
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
let connsPerPeer = 1;
// The HOST's flood cap, learned at INIT — this module never declares the number
// that bounds it (net-limits.ts stays core); it only sizes its own send budget
// against it. The literal is the value INIT overwrites, never a second declaration.
let maxFrameBytes = 2 * 1024 * 1024;
// The pre-auth cap, learned at init from the same place. Enforced HERE rather than by
// the host, because on an unframed link the host has no frames to measure — it holds a
// byte duplex and we are the ones imposing boundaries on it. The number is still the
// host's: whoever owns the resource declares the bound, whoever parses applies it.
let maxHandshakeFrameBytes = 8 * 1024;
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
  return host.call(P_HASH, out);
}
function verify(pk, sig, msg) {
  let len = pk.length + sig.length + msg.length;
  const out = new Uint8Array(len);
  out.set(pk, 0); out.set(sig, pk.length); out.set(msg, pk.length + sig.length);
  return host.call(N_VERIFY, out)[0] === 1;
}
function randomBytes(n) {
  const req = new Uint8Array(4);
  writeU32BE(req, 0, n);
  return host.call(N_RANDOM, req);
}
function aeadEnc(key, npub, msg) {
  const out = new Uint8Array(npub.length + key.length + msg.length);
  out.set(npub, 0); out.set(key, npub.length); out.set(msg, npub.length + key.length);
  return host.call(P_SEAL, out);
}
function aeadDec(key, npub, ct) {
  const out = new Uint8Array(npub.length + key.length + ct.length);
  out.set(npub, 0); out.set(key, npub.length); out.set(ct, npub.length + key.length);
  const r = host.call(P_OPEN, out);
  return r[0] === 1 ? { ok: true, pt: r.subarray(1) } : { ok: false, pt: null };
}
function scalarmult(sk, pk) {
  const out = new Uint8Array(64);
  out.set(sk, 0); out.set(pk, 32);
  const r = host.call(P_DH, out);
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
 *  `DOMAIN_channel ‖ networkKey` — chosen from THIS bundle's admission point, not from anything
 *  said here — and signs the opaque suffix with the node's channel key, which never
 *  enters this program. There is no call that signs raw bytes, and the prefix is what
 *  makes a transcript signature unusable as app data (and vice versa). The peer side
 *  of the same transcript is checked with node/verify under the identical prefix. */
function channelSign(root, th, id) {
  const out = new Uint8Array(96);
  out.set(root, 0); out.set(th, 32); out.set(id, 64);
  return { ok: true, sig: host.call(N_SIGN, out) };
}

// ── calling out: the ops, each one argument-encoded and issued immediately ────
//
// There is no action buffer and no batch. Accumulating orders into a response the host
// decodes after the entrypoint returns would be a second host↔module ABI; every one of
// these calls is an ordinary `host.call` through the one seam (§12.2).
//
// The one rule the arrangement rests on is the host's: NO OP RE-ENTERS THIS REALM.
// A socket write does not deliver during the write, a fired timer arrives on its own
// turn, and an inbound request is answered through the `respond` entrypoint rather
// than as transport/deliver's return value — so nothing below can call back into a frame
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
function netLinkOpen(destBytes) {
  const r = host.call(N_LINK_OPEN, destBytes);
  const authLen = readU32BE(r, 5);
  return {
    linkId: readU32BE(r, 0),
    framing: r[4],
    authority: authLen > 0 ? utf8Decode(r.subarray(9, 9 + authLen)) : "",
  };
}
function netLinkSend(linkId, bytes) { host.call(N_LINK_SEND, args([linkId], [], bytes)); }
function netLinkClose(linkId, graceful) { host.call(N_LINK_CLOSE, args([linkId], [graceful ? 1 : 0])); }
/** Bytes handed to this link that are not yet on the wire. 0 for a link that is gone
 *  or a channel that cannot say — both read as "nothing queued", which leaves the
 *  stall clock to the deadline alone. */
function netLinkBuffered(linkId) { return readU32BE(host.call(N_LINK_STAT, args([linkId], [])), 0); }

function netDeliver(corr, noReply, fromBytes, proto, payload) {
  const head = new Uint8Array(1 + proto.length);
  head[0] = proto.length;
  head.set(proto, 1);
  host.call(N_DELIVER, args([corr], [noReply ? 1 : 0], concatBytes([fromBytes, head, payload])));
}
function netSettle(corr, ok, payload) { host.call(N_SETTLE, args([corr], [ok ? 1 : 0], payload)); }
/** Ask the host's WHITELIST whether this peer may link. Asked at the FIRST point the
 *  peer is known and — critically — before this end has revealed anything about
 *  itself: msg3 when accepting, msg4 when dialing. `conceal` tells the host a refusal
 *  must be silent, which is true exactly when we have not yet sent our identity.
 *  The gate is the host's because a predicate we applied to ourselves would gate
 *  nothing; the ORDER is ours, and it is what keeps a refusal from being an oracle. */
function netLinkAuth(linkId, peerBytes, conceal) {
  return host.call(N_LINK_AUTH, args([linkId], [conceal ? 1 : 0], peerBytes))[0] === 1;
}
function netPeerEdge(up, peerBytes) { host.call(N_PEER_EDGE, args([], [up ? 1 : 0], peerBytes)); }
function netReady(ok) { host.call(N_READY, args([], [ok ? 1 : 0])); }
function netLinkDown(linkId, reason) { host.call(N_LINK_DOWN, args([linkId], [reason])); }

// ── timers ────────────────────────────────────────────────────────────────────

function armTimer(ms, fn) {
  const id = nextTimerId++;
  timers.set(id, fn);
  host.call(N_TIMER_ARM, args([id, Math.max(1, Math.floor(ms))], []));
  return id;
}
function clearTimer(id) {
  if (timers.delete(id)) host.call(N_TIMER_CLEAR, args([id], []));
}
function fireTimer(id) {
  const fn = timers.get(id);
  if (fn) { timers.delete(id); fn(); }
}

// ── the link (PeerLink port, ex net-link.ts) ─────────────────────────────────

// A link is bound to one host-managed channel, addressed by the HOST-SUPPLIED
// link id — the table holds one instance per name (§3.1), so all session state
// lives here, keyed by that id.
// ── wire framing, for links the platform did not frame ────────────────────────
//
// A browser WebSocket and an RTCDataChannel arrive with message boundaries already
// on them; a TCP socket does not. Where the platform supplies none, imposing them is
// OURS — framing is content by the end-to-end argument (it is a state machine over
// whole messages, and an endpoint can do it), so a host that framed on our behalf
// would be holding a piece of the protocol that a replacement bundle could not
// replace. The host hands over bytes; what a message *is* is decided here.
//
//   [len u32 BE][bytes]   one link message per record.
//
// The cap is two-stage and both numbers come from the host at init. Pre-auth it is
// the small handshake bound: a stranger who knows only host:port must not be able to
// reserve megabytes by declaring a frame and then dribbling the body. It rises to the
// full frame cap at exactly the moment the peer becomes a known, admitted identity.
// ── inbound byte assembly ─────────────────────────────────────────────────────
//
// A link message may arrive in arbitrary slices, and the slices can be arbitrarily
// small. The old arrangement joined every new slice onto one buffer, which made a
// peer that dribbles a full-size frame one byte at a time cost a quadratic number of
// copies — a CPU-exhaustion budget no frame-size cap controls. The parser instead
// keeps the slices it was handed and copies only when a whole message is complete:
// once per frame, bounded by the cap that already governs the frame.
class ByteParts {
  constructor() {
    this.parts = [];   // inbound slices, not yet parsed
    this.head = 0;     // index of the first live slice
    this.length = 0;   // live bytes across all slices
  }
  push(chunk) {
    if (chunk.length > 0) { this.parts.push(chunk); this.length += chunk.length; }
  }
  /** Copy up to `n` bytes from the front without consuming them. */
  peek(n) {
    const out = new Uint8Array(Math.min(n, this.length));
    let off = 0;
    for (let i = this.head; i < this.parts.length && off < out.length; i++) {
      const p = this.parts[i];
      const take = Math.min(p.length, out.length - off);
      out.set(p.subarray(0, take), off);
      off += take;
    }
    return out;
  }
  /** Consume exactly `n` bytes from the front, as one buffer. */
  take(n) {
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const p = this.parts[this.head];
      const need = n - off;
      if (p.length <= need) { out.set(p, off); off += p.length; this.head++; }
      else { out.set(p.subarray(0, need), off); this.parts[this.head] = p.subarray(need); off = n; }
    }
    this.length -= n;
    // Drop the consumed slices once they outnumber the live ones — a long dribble
    // must not grow the array without bound.
    if (this.head >= 8 && this.head * 2 >= this.parts.length) {
      this.parts = this.parts.slice(this.head);
      this.head = 0;
    }
    return out;
  }
  /** Byte offset of the first `\r\n\r\n`, or -1 when not present yet. */
  findHeadEnd() {
    let b0 = -1, b1 = -1, b2 = -1, b3 = -1, off = 0;
    for (let i = this.head; i < this.parts.length; i++) {
      const p = this.parts[i];
      for (let j = 0; j < p.length; j++) {
        b0 = b1; b1 = b2; b2 = b3; b3 = p[j];
        if (b0 === 13 && b1 === 10 && b2 === 13 && b3 === 10) return off - 3;
        off++;
      }
    }
    return -1;
  }
}

/** A length-prefixed link is writable from birth — there is no negotiation. */
class LengthFramer {
  constructor(put) {
    this.put = put;
    this.parts = new ByteParts();
    this.cap = maxHandshakeFrameBytes;
  }

  send(msg) {
    const out = new Uint8Array(4 + msg.length);
    writeU32BE(out, 0, msg.length);
    out.set(msg, 4);
    this.put(out);
  }

  raiseCap() { this.cap = maxFrameBytes; }

  /** Feed inbound bytes, delivering each whole message. Returns false when the peer
   *  declared an over-cap frame — a protocol violation the caller answers by tearing
   *  the link down, never by growing the buffer. */
  push(chunk, deliver) {
    this.parts.push(chunk);
    for (;;) {
      if (this.parts.length < 4) return true;
      const len = readU32BE(this.parts.peek(4), 0);
      if (len > this.cap) return false;
      if (this.parts.length < 4 + len) return true;
      deliver(this.parts.take(4 + len).subarray(4));
    }
  }
}

// ── RFC 6455, for the browser edge ────────────────────────────────────────────
//
// WebSocket exists here only because browsers cannot open raw TCP, so it is a wire
// codec over a raw socket and nothing more: an HTTP upgrade, then length-delimited
// frames with a masking rule that depends on which end you are. Both ends run this
// one class; they differ in who speaks first and in whether frames are masked
// (client→server must be, server→client must not).
//
// Every byte transform runs in `ws.wasm`, a module of THIS bundle reached by logical
// name — the encode, the single-frame decode, the SHA-1 + base64 of the accept value.
// Holding it as a module rather than as host code is what makes the framing content:
// it arrives through the one install path, signed by the same author as this program,
// and a fix to either half is one bundle rollout.
const WS_OP_ENCODE = 1, WS_OP_DECODE_ONE = 2, WS_OP_ACCEPT = 3, WS_OP_BASE64 = 4;
const WS_OP_CONT = 0x0, WS_OP_BINARY = 0x2, WS_OP_CLOSE = 0x8, WS_OP_PING = 0x9, WS_OP_PONG = 0xa;
/** RFC 6455 status 1000 (normal closure), big-endian, as a close-frame payload. */
const WS_CLOSE_NORMAL = new Uint8Array([0x03, 0xe8]);
/** An HTTP upgrade head is tiny; anything larger is not one. */
const MAX_WS_HANDSHAKE = 16 * 1024;

/** Run this bundle's own ws.wasm — an ordinary `host.call`, like every other name this
 *  program uses. An empty answer is the module's failure signal (§4). */
function wsCall(req) {
  const out = host.call(N_WS, req);
  if (out.length === 0) throw new Error("ws: module error");
  return out;
}

class WsFramer {
  /** `authority` is the `host:port` this link was dialed at, for the client's Host
   *  header — empty on the accepting side, which never sends one. */
  constructor(put, weDialed, authority) {
    this.put = put;
    this.client = weDialed;
    this.cap = maxHandshakeFrameBytes;
    this.parts = new ByteParts();      // inbound: handshake head, then frames
    this.queue = [];                   // outbound, until the upgrade completes
    this.open = false;
    this.fragOpcode = -1;
    this.frags = [];
    this.fragBytes = 0;
    if (this.client) {
      const r = wsCall(concatBytes([Uint8Array.of(WS_OP_BASE64), randomBytes(16)]));
      this.key = utf8Decode(r);
      this.expectAccept = utf8Decode(wsCall(concatBytes([Uint8Array.of(WS_OP_ACCEPT), r])));
      this.put(utf8Encode(
        "GET / HTTP/1.1\r\nHost: " + authority + "\r\n" +
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
        "Sec-WebSocket-Key: " + this.key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"));
    }
  }

  raiseCap() { this.cap = maxFrameBytes; }

  mask() { return this.client ? randomBytes(4) : null; }

  frame(opcode, payload) {
    const m = this.mask();
    const req = new Uint8Array(3 + (m ? 4 : 0) + payload.length);
    req[0] = WS_OP_ENCODE;
    req[1] = opcode & 0x0f;
    req[2] = m ? 1 : 0;
    if (m) req.set(m, 3);
    req.set(payload, 3 + (m ? 4 : 0));
    return wsCall(req);
  }

  send(msg) {
    // The transport emits its HELLO the moment the link exists — before the upgrade
    // has finished — so frames queue until the channel opens.
    if (!this.open) { this.queue.push(msg); return; }
    this.put(this.frame(WS_OP_BINARY, msg));
  }

  /** The close frame rides the same byte stream as the end-of-stream record just
   *  written, so it cannot overtake it — which is the ordering that record depends on. */
  goodbye() {
    if (this.open) { try { this.put(this.frame(WS_OP_CLOSE, WS_CLOSE_NORMAL)); } catch { /* gone */ } }
  }

  push(chunk, deliver) {
    this.parts.push(chunk);
    if (!this.open) {
      let consumed;
      try { consumed = this.upgrade(); } catch { return false; }
      if (consumed < 0) return this.parts.length <= MAX_WS_HANDSHAKE;
      this.parts.take(consumed);
      this.open = true;
      for (const m of this.queue) this.put(this.frame(WS_OP_BINARY, m));
      this.queue = [];
    }
    try { return this.frames(deliver); } catch { return false; }
  }

  /** Read (client) or answer (server) the opening handshake. Returns the bytes
   *  consumed, or -1 when the head is not complete yet. Throws on a refusal. */
  upgrade() {
    const sep = this.parts.findHeadEnd();
    if (sep < 0) return -1;
    const head = utf8Decode(this.parts.peek(sep));
    if (this.client) {
      // Sec-WebSocket-Accept is base64 and case-significant, so compare the exact
      // header value byte for byte rather than lowercasing both sides.
      if (!/HTTP\/1\.1 101/.test(head) || headerValue(head, "sec-websocket-accept") !== this.expectAccept) {
        throw new Error("ws: upgrade refused");
      }
      return sep + 4;
    }
    const key = headerValue(head, "sec-websocket-key");
    if (!key) throw new Error("ws: missing Sec-WebSocket-Key");
    const accept = utf8Decode(wsCall(concatBytes([Uint8Array.of(WS_OP_ACCEPT), utf8Encode(key)])));
    this.put(utf8Encode(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
      "Sec-WebSocket-Accept: " + accept + "\r\n\r\n"));
    return sep + 4;
  }

  /** Parse whatever frames are complete. Delivery is per frame rather than per chunk:
   *  delivering msg4 raises the cap, and an application frame riding the same TCP
   *  segment must be measured against the raised cap, not the pre-auth one. */
  frames(deliver) {
    for (;;) {
      const total = this.frameLength();
      if (total < 0) return true;
      if (total > this.cap) return false;
      if (this.parts.length < total) return true;
      const whole = this.parts.take(total);
      const req = new Uint8Array(2 + whole.length);
      req[0] = WS_OP_DECODE_ONE;
      req[1] = this.client ? 0 : 1; // a server expects masked frames, a client unmasked
      req.set(whole, 2);
      const r = wsCall(req);
      // The module saw exactly one whole frame; anything but "frame" (1) is a protocol
      // violation — bad mask direction, a fragmented control frame, a bad length.
      if (r[0] !== 1) return false;
      const fin = (r[1] & 0x80) !== 0;
      const opcode = r[1] & 0x0f;
      const payload = r.slice(10, 10 + readU32BE(r, 6));
      if (opcode === WS_OP_CONT) {
        if (this.fragOpcode < 0) return false;
        this.fragBytes += payload.length;
        if (this.fragBytes > this.cap) return false;
        this.frags.push(payload);
        if (fin) {
          const msg = concatBytes(this.frags);
          const first = this.fragOpcode;
          this.fragOpcode = -1; this.frags = []; this.fragBytes = 0;
          if (!this.dispatch(first, msg, deliver)) return false;
        }
      } else if (!fin) {
        // The first fragment of a data message (the module refuses fragmented control).
        if (this.fragOpcode >= 0) return false;
        this.fragOpcode = opcode;
        this.frags = [payload];
        this.fragBytes = payload.length;
      } else {
        // A data frame may not preempt an in-flight fragmented message; control frames
        // interleave freely (RFC 6455 §5.4).
        if (opcode < 0x8 && this.fragOpcode >= 0) return false;
        if (!this.dispatch(opcode, payload, deliver)) return false;
      }
    }
  }

  dispatch(opcode, payload, deliver) {
    if (opcode === WS_OP_BINARY) deliver(payload);
    else if (opcode === WS_OP_PING) this.put(this.frame(WS_OP_PONG, payload));
    else if (opcode === WS_OP_CLOSE) return false;
    return true;
  }

  /** Total byte length of the next frame, from the (unvalidated) header — or -1 when
   *  too few bytes are buffered to know yet. All real validation is the module's; this
   *  only sizes the wait. */
  frameLength() {
    if (this.parts.length < 2) return -1;
    const b = this.parts.peek(10);
    const masked = (b[1] & 0x80) !== 0;
    const len7 = b[1] & 0x7f;
    let headerLen = 2, payloadLen = len7;
    if (len7 === 126) {
      if (this.parts.length < 4) return -1;
      headerLen = 4;
      payloadLen = (b[2] << 8) | b[3];
    } else if (len7 === 127) {
      if (this.parts.length < 10) return -1;
      if (readU32BE(b, 2) !== 0) return 0x7fffffff; // > 4 GiB: over any cap
      headerLen = 10;
      payloadLen = readU32BE(b, 6);
    }
    return headerLen + (masked ? 4 : 0) + payloadLen;
  }
}

/** Case-insensitively pull a header value out of an HTTP head. */
function headerValue(head, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp("^" + escaped + ":[ \\t]*(.+?)[ \\t]*$", "im").exec(head);
  return m ? m[1] : null;
}

/** How a link is framed, as the host declares it at open. The host knows only because
 *  it dialed the address; what to DO about it is entirely here. */
const FRAMING_PLATFORM = 0, FRAMING_LENGTH = 1, FRAMING_WS_CLIENT = 2, FRAMING_WS_SERVER = 3;

function makeFramer(framing, linkId, weDialed, authority) {
  const put = (bytes) => netLinkSend(linkId, bytes);
  if (framing === FRAMING_LENGTH) return new LengthFramer(put);
  if (framing === FRAMING_WS_CLIENT) return new WsFramer(put, true, authority || "");
  if (framing === FRAMING_WS_SERVER) return new WsFramer(put, false, "");
  return null; // FRAMING_PLATFORM: the transport under us already has boundaries
}

class Link {
  constructor(spec) {
    this.linkId = spec.linkId;
    // How this link is framed. PLATFORM means the transport under us already has
    // message boundaries (a browser WebSocket, an RTCDataChannel) and the host still
    // owns its cap; anything else is a byte duplex we frame ourselves.
    this.framer = makeFramer(spec.framing, spec.linkId, spec.weDialed, spec.authority);
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
    if (frame.length > maxFrameBytes - TAG_LEN) return;
    // An empty record is the authenticated end-of-stream marker — never an
    // application frame.
    if (frame.length === 0) return;
    if (this.authed) {
      if (this.sendEpoch >= REJECT_AFTER_EPOCHS) { this.close(); return; }
      this.wire(this.seal(frame));
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
        this.wire(this.seal(new Uint8Array(0)));
        // A codec with its own end-of-stream signal says it too, on the same byte
        // stream and after our record, so the peer reads one clean shutdown.
        if (this.framer && this.framer.goodbye) this.framer.goodbye();
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

  // ── handshake ───────────────────────────────────────────────────────────────

  /** Put one link message on the wire, framing it first where the platform gave us
   *  no boundaries of its own. */
  wire(msg) {
    if (this.framer) this.framer.send(msg);
    else netLinkSend(this.linkId, msg);
  }

  /** Inbound bytes from the host: a whole message on a framed link, an arbitrary
   *  slice on an unframed one. An over-cap declaration is a protocol violation, so it
   *  is a defensive abort — no goodbye record, nothing said. */
  onWire(bytes) {
    if (!this.framer) { this.onMessage(bytes); return; }
    if (!this.framer.push(bytes, (m) => this.onMessage(m))) this.abort(true);
  }

  /** Route one whole link message. A message is a bare body, and which one it is
   *  follows from our role and how far the exchange has got: we dialed, so msg2 then
   *  msg4; we accepted, so msg1 then msg3; authenticated, so a record. Our progress
   *  is ours, so the sender chooses nothing here — every message has exactly one
   *  destination, the handler checks its exact width, and a post-auth body goes to
   *  the AEAD, which fails closed. Delivery is in order, as the record layer's
   *  implicit counter requires of every seam beneath us. */
  onMessage(m) {
    if (this.closed) return;
    if (this.authed) this.onRecord(m);
    else if (this.weDialed) this.peerEph ? this.onMsg4(m) : this.onMsg2(m);
    else this.peerEph ? this.onMsg3(m) : this.onMsg1(m);
  }

  // Refuse WITHOUT saying so — every suite-0x02 refusal funnels here so refusals
  // are indistinguishable from each other and from silence (net-link.ts §12.6.2).
  stall() { /* deliberately nothing */ }

  becomeAuthed() {
    this.authed = true;
    this.releaseSlot();
    this.clearDeadline();
    // A known, admitted identity may send full-size frames; a stranger may not. On a
    // platform-framed link there is no reassembly buffer of ours to bound.
    if (this.framer) this.framer.raiseCap();
    this.onAuth(this.peerId, this);
    if (this.closed) return; // onAuth may have torn us down (the tie-break)
    for (const f of this.queue) this.wire(this.seal(f));
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
    // Scoped verify, host-applied: node/verify checks `DOMAIN_channel ‖ networkKey ‖
    // root ‖ th ‖ id` under `id` — the same scope this node signs its own identity
    // under — so the preimage the two ends must agree on is the host's, never
    // reconstructed here.
    if (!verify(id, sig, concatBytes([this.root, th, id]))) return null;
    if (bytesCompare(id, ownPk) === 0) return null; // our own traffic reflected
    return id;
  }

  sendMsg1() {
    const eph = this.myEph.publicKey.subarray(0, EPH_LEN);
    const w1 = concatBytes([SUITE_BYTE, eph, this.sealZero(this.probeKey(SUITE_BYTE, eph), this.myNonce)]);
    this.th = this.h(this.root, w1);
    this.wire(w1);
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
    this.wire(w2);
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
    this.wire(w3);
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
    this.wire(w4);
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

  // Reached only on an authenticated link, where a body that will not open is corruption
  // or injection either way and the link goes down. This is the one receive path that
  // speaks: concealment is owed to strangers, and this peer proved who it is.
  onRecord(body) {
    if (!this.recvKey || body.length < TAG_LEN) { this.abort(true); return; }
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
}

// ── the router (ex link-router.ts) ────────────────────────────────────────────

class Router {
  constructor(ownPubkey, ownId) {
    this.ownPubkey = ownPubkey;
    this.ownId = ownId;
    this.links = new Map();      // peerId → Link[] (authenticated, routable)
    this.rr = new Map();         // peerId → round-robin cursor
    this.sink = null;            // the request/response layer's frame intake
    this.onPeerUp = () => {};
    this.onPeerDown = () => {};
  }

  linkCount(peerId) { const a = this.links.get(peerId); return a ? a.length : 0; }
  /** This peer's routable links, for the stall clock's backlog read. Empty for a peer
   *  still dialing — whose frames sit in the pre-auth pool instead (Core.sendFrame),
   *  where a handshake that never completes is the half-open deadline's business, not
   *  this one's. */
  linksTo(peerId) { return this.links.get(peerId) || []; }

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
// correlation, the response binding, one deadline per request — driven by host timer
// events. `to`/`from` are hex peer ids; proto is opaque bytes.
//
// The deadline arrives WITH each request rather than being inferred here, and that is
// the whole of the timing policy. This layer cannot tell a 200-byte control message
// from a 4 MB block, so anything it computed would be a guess. Re-arming a silence
// window whenever ANY frame arrived from the peer, under an absolute backstop, makes a
// request's lifetime depend on unrelated traffic to the same peer — a chatty request
// keeps a stalled one alive, and a quiet-but-progressing transfer dies. The caller
// knows what it sent; it says so (`request` entrypoint).
//
// The deadline is a STALL clock, not a budget for the whole exchange. Arming it at
// enqueue and letting it expire measured our OWN upload: a request whose bytes are
// still draining out of a backpressured socket has not been answered late, it has not
// finished being asked. A 50 MB PUT across two holders queued ~42 MB behind four
// sockets and every request in the window was cancelled at 5 s while the wire was
// working perfectly — the holders were blamed for our backlog.
//
// So on expiry this asks whether OUR OWN REQUEST is still going out, and only gives up
// if it is not. Two numbers say it, both from bytes rather than from traffic:
//
//   flushed = sent − buffered   bytes for this peer that actually left (monotone)
//   owed                        `sent` at the moment this request was handed over
//
// A link is FIFO, so `flushed ≥ owed` means precisely "this request's last byte is on
// the wire". Until then the exchange has not begun — we are still asking — and an
// expiry that finds `flushed` moving re-arms. After that the clock is a pure silence
// window and settles on schedule.
//
// Bounding the re-arm by `owed` is what keeps this from being the old silence window
// under a new name. Progress measured per PEER would let unrelated frames to the same
// peer keep a request alive — a chatty caller resurrecting a stalled request, exactly
// the flaw that got the previous design deleted. Later frames raise `sent`, never this
// request's `owed`, so nothing another request does can extend this one past its own
// transmission.
class ReqRes {
  constructor() {
    this.pending = new Map();   // corr → {to}
    this.timers = new Map();    // corr → timerId
    this.sent = new Map();      // peerId → bytes handed to its links, ever
  }

  /** Count bytes on their way to a peer — the numerator of the progress measure. */
  note(to, n) { this.sent.set(to, (this.sent.get(to) || 0) + n); }

  /** Bytes of ours that have actually left for this peer: everything handed over,
   *  less what its links are still holding. Monotone non-decreasing while the wire
   *  moves, flat while it does not. */
  flushed(to) {
    let buffered = 0;
    for (const link of router.linksTo(to)) buffered += netLinkBuffered(link.linkId);
    return (this.sent.get(to) || 0) - buffered;
  }

  /** Arm one request's stall clock. `owed` is `sent` including this request's own
   *  frame — the point at which it has finished being asked. */
  armStall(corr, to, deadlineMs, owed) {
    // The baseline is taken on the FIRST expiry, not here. A frame handed over while the
    // peer is still being dialled routes through the pre-auth pool, where there is no
    // link to read a backlog from — so a baseline taken now would be `sent` with nothing
    // subtracted, an over-estimate no later reading could ever beat, and every such
    // request would settle on its first tick however hard the wire was working. One
    // deadline of grace to find the link is the cost, and it is bounded by `owed` like
    // everything else here.
    let mark = null;
    const tick = () => {
      this.timers.delete(corr);
      if (!this.pending.has(corr)) return;
      const now = this.flushed(to);
      // Still going out, and moving: we have not finished asking, so nothing here is
      // late. Anything else — drained (the peer owes us an answer) or not moving (the
      // wire is stuck) — settles.
      if (now < owed && (mark === null || now > mark)) {
        mark = now;
        this.timers.set(corr, armTimer(deadlineMs, tick));
        return;
      }
      this.pending.delete(corr);
      netSettle(corr, false, utf8Encode("net.send: timeout to " + to.slice(0, 8)));
    };
    this.timers.set(corr, armTimer(deadlineMs, tick));
  }

  attach(sendFrame) {
    this.sendFrame = sendFrame;
  }

  request(corr, to, proto, payload, noReply, deadlineMs) {
    const frame = this.buildReq(corr, noReply, proto, payload);
    if (!noReply) {
      // A noReply send carries corr 0 and never resolves — the host keeps no
      // promise for it, so nothing here is parked on its behalf.
      this.pending.set(corr, { to });
    }
    // Count the frame BEFORE it is handed over, so the first stall check cannot read a
    // `flushed` that already includes bytes this request has not yet contributed.
    this.note(to, frame.length);
    const owed = this.sent.get(to);
    this.sendFrame(to, frame);
    if (!noReply) this.armStall(corr, to, deadlineMs, owed);
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
    // A response is `[1][corr u32][payload]`, so an EMPTY response is exactly five
    // bytes — the shortest legal frame. Requiring six here dropped it, and since a
    // request nobody is bound to answers empty by contract, that made "no app serves
    // this protocol" indistinguishable from an unreachable peer: the caller waited out
    // its whole deadline instead of being told nothing was there. The six-byte floor is
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
  }
}

// ── the routing core (ex net-route.ts NodeNetworkCore) ────────────────────────

class Core {
  constructor() {
    this.connecting = new Map(); // peerId → Link[] (outbound, pre-auth)
    this.inbound = new Set();    // accepted, pre-auth
    this.addrs = new Map();      // peerId → 32B contact secret (or null = open)
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

  // Top a dialed peer up to connsPerPeer outbound links. `link/open` is the raw
  // capability and it answers immediately with the link id (or 0 for no route), so the
  // link lands in `connecting` before this returns — there is no in-flight dial window,
  // and so no queue of frames waiting one out.
  dial(peerId) {
    if (!this.addrs.has(peerId)) return;
    const have = router.linkCount(peerId) + (this.connecting.get(peerId) || []).length;
    for (let n = have; n < connsPerPeer; n++) {
      const { linkId, framing, authority } = netLinkOpen(fromHex(peerId));
      if (linkId === 0) return; // no route — a fabric with nowhere to send drops the frame
      this.openLink({
        linkId,
        framing,
        authority,
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
      framing: spec.framing,
      authority: spec.authority,
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
  contactSecret = cfg.contactSecret;
  connsPerPeer = Math.max(1, Math.floor(cfg.connsPerPeer || 1));
  maxFrameBytes = cfg.maxFrameBytes;
  maxHandshakeFrameBytes = cfg.maxHandshakeFrameBytes;
  maxUnverified = cfg.maxUnverified;
  maxPerSource = cfg.maxPerSource;
  maxVerified = cfg.maxVerified;

  router = new Router(ownPk, ownId);
  reqres = new ReqRes();
  core = new Core();
  reqres.attach((to, frame) => core.sendFrame(to, frame));
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
 *  HOST's flood cap, which this module learns rather than declares.
 *
 *  There is no request-timing config here. A deadline is per request, not per node, so
 *  it rides on `request` instead — which is also what leaves the host's default in one
 *  place (transport-host.ts) rather than mirrored on both sides of the seam. */
entry("init", (r) => {
  init({
    ownPk: r.blob(), networkKey: r.blob(), contactSecret: r.blob(),
    connsPerPeer: r.u32(),
    maxUnverified: r.u32(), maxPerSource: r.u32(), maxVerified: r.u32(),
    maxFrameBytes: r.u32(),
    maxHandshakeFrameBytes: r.u32(),
  });
});

/** A link the HOST opened: an accepted socket (kind CORE), or one a host-managed
 *  transport handed over (kind OPEN, either direction). A core link we dialed never
 *  arrives here — `Core.dial` opens those itself through the raw capability. */
entry("linkOpen", (r) => {
  const linkId = r.u32();
  const weDialed = r.u8() === 1;
  const kind = r.u8();
  const framing = r.u8();
  const authority = r.blob();
  const handshakeTimeoutMs = r.u32();
  const rekeyAfterFrames = r.u32();
  const expectPeerId = r.blob();
  const dialSecret = r.blob();
  const source = r.blob();
  const spec = {
    linkId, weDialed, framing,
    authority: authority.length > 0 ? utf8Decode(authority) : "",
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
  if (link) link.onWire(r.blob());
});

entry("linkClosed", (r) => {
  const link = findLink(r.u32());
  if (link) link.onChannelClosed();
});

entry("timer", (r) => { fireTimer(r.u32()); });

/** An app wants a typed request sent. The host holds the promise under `corr` and
 *  this side holds the wire state; the stall clock is a host-armed timer. */
/** One request out. `deadlineMs` is the CALLER's — how long this particular exchange
 *  may take before it settles as unreachable — resolved host-side against its default
 *  and always concrete by the time it arrives here (§12.6). Ignored for a noReply send,
 *  which nothing is waiting on. */
entry("request", (r) => {
  const corr = r.u32();
  const noReply = r.u8() === 1;
  const deadlineMs = r.u32();
  const to = r.blob();
  const proto = r.blob().slice();
  const payload = r.blob().slice();
  reqres.request(corr, toHex(to), proto, payload, noReply, deadlineMs);
});

/** The raw Endpoint face: one whole frame to one peer, no correlation. */
entry("sendFrame", (r) => {
  const to = r.blob();
  core.sendFrame(toHex(to), r.blob().slice());
});

/** The answer to a transport/deliver, on a later turn than the delivery itself — which is
 *  what lets the app-side handler be asynchronous, and what keeps a call from
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
