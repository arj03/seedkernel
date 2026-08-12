// ============================================================================
// The transport bundle guest — the channel handshake (AKE + forward-secret
// record layer, ex net-link.ts), the authenticated link router (ex link-router.ts),
// the link bookkeeping (ex net-route.ts NodeNetworkCore) and the request/response
// layer (ex net.ts) — as the zero-authority JS program of a signed bundle claiming
// the shell's explicit transport slot.
//
// The program is split across transport/src/{util,ake,framing,router,core}.js —
// pure helpers, the AKE and record layer, the wire framers, the routers, and the
// core/init/entrypoints — and CONCATENATED in that fixed order by
// scripts/build-transport-bundle.mjs into the single guest.js the manifest
// hashes and the loader runs. The parts share one scope, so dependencies between
// them are runtime ones only (never a top-level reference to a later part).
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
//     `link/*` — the platform's whole contribution to the network: bytes over an opaque
//     link id, opened and closed. `timer/*` — deadlines, because a zero-authority realm
//     has no setTimeout. `_host` — the shell's own reserved id, for the two edges where
//     the host holds the other end. Its own ws.wasm is NOT here: a bare name is a
//     primitive — the bundle's own code, ungated like `crypto` (§12.1) — so no grant is
//     needed to name it.
//
//     There is no `transport` domain and no `net` domain. What this program provides
//     back is not a host name at all: the manifest claims the reserved id `_net`
//     (§12.10), and an app reaching the network CALLS that id, exactly as an inbound
//     frame reaches an app by the id it claims. The host's whole part is attribution —
//     it prepends the caller's key — and resolution.
//
//   - one entrypoint, `handle`, invoked exactly as an app's is. The op travels as a
//     length-prefixed NAME in the payload rather than a tag byte, so there is still no
//     number two sides must agree on and an op this program does not implement fails
//     loud by name rather than desyncing a decoder. (`timer` is the second entrypoint,
//     and it is every guest's, not this program's.)
//
// The node key stays out of this module in the strongest sense: there is no call
// that signs arbitrary bytes — node/sign is scoped by the point the host admitted this
// bundle into, so a compromised transport can neither forge app signatures nor
// sign for another network. Its verification twin is equally scope-bound: node/verify
// answers only under this transport's own scope, so this program checks a peer's
// transcript signature without holding the domain tag it was made under.
//
// Channels are host handles keyed by a link id the HOST minted — the module table
// holds one instance per name (§3.1), so all link state lives in this module's
// heap, keyed by that id.
//
// These parts are hand-maintained single-source content: they are signed into the
// bundle, so they must stay self-contained (no imports) and must match the seam
// below exactly. The host twin of this contract lives in host/transport-host.ts.
// ============================================================================

// ── capability names (must match the guest seam's dispatch table) ─────────────

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

// The SHELL's own reserved id (§12.10) — the one thing this program calls that is not a
// host authority. It is a cross-realm call like any other: the shell answers it rather
// than routing it, and it carries only the two edges where the host genuinely holds the
// other end (an inbound request, which reaches the app claiming the protocol; and the
// fate of a link the host handed us through openLink).
//
// What this program PROVIDES back is NOT here, because it is not something it calls: the
// transport claims `_net`, and an app reaching the network calls that. The answer is what
// `handle` returns.
const N_HOST = "_host";

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
// turn, and a cross-realm call runs its callee on a LATER turn by construction — so
// nothing below can call back into a frame that is still on the stack.
//
// The corollary, and the reason this program never uses `await`: an answer that arrives
// through this realm cannot be awaited from inside it, because the invocation carrying it
// would queue behind the frame doing the awaiting (realm-queue.ts). So an inbound request
// is dispatched with `.then`, not awaited, and an app's send is answered with `defer()`.

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

/** Call the shell's own protocol by op name — the preamble's `writeOp` (guest-seam.ts)
 *  frames it, the same envelope every other call in this system carries. The host
 *  prepends OUR id on the way in, so there is nothing here to identify ourselves with. */
function hostCall(op, tail) {
  return host.call(N_HOST, writeOp(op, tail));
}

/** Hand an inbound request to whichever app claims its protocol id, and resolve with
 *  that app's answer. NOT awaited by any caller inside this realm — see the note above.
 *
 *  Delivery and the reply are ONE call: the answer is the app's own `handle` return
 *  value, on a later turn, which is exactly the shape an asynchronous app handler needs
 *  and what a separate reply entrypoint would only have simulated. */
function hostDeliver(fromBytes, proto, payload) {
  const head = new Uint8Array(1 + proto.length);
  head[0] = proto.length;
  head.set(proto, 1);
  return hostCall("deliver", concatBytes([fromBytes, head, payload]));
}
/** A link the HOST handed us (openLink) authenticated, or tore down. Relayed so whoever
 *  passed the channel in learns its fate; a core link the guest dialed or accepted is
 *  nobody's business but ours. */
function hostLinkAuth(linkId, peerBytes) { hostCall("link-auth", args([linkId], [], peerBytes)); }
function hostLinkDown(linkId, reason) { hostCall("link-down", args([linkId], [reason])); }

/** The peer LINT (§12.6): is this peer on the operator's list? Asked at the FIRST point
 *  the peer is known and — critically — before this end has revealed anything about
 *  itself: msg3 when accepting, msg4 when dialing. `conceal` says a refusal must be
 *  silent, which is true exactly when we have not yet sent our identity, and it is what
 *  keeps a refusal from being an oracle (§12.6.2).
 *
 *  **It is a lint and it lives here, which is a correction rather than a relaxation.**
 *  The host used to hold it, on the argument that a predicate we applied to ourselves
 *  would gate nothing against a hostile occupant of this slot. True — but the host was
 *  checking a key WE supplied, so it gated nothing against a hostile occupant either: one
 *  would simply supply a key that passes, or forge an attribution with no link at all.
 *  What the check actually catches is a buggy transport or an unlisted peer, and both are
 *  ours. What holds against a hostile transport is unchanged and was always the real answer:
 *  it reaches no authority but `link/*`. */
function admits(peerBytes) {
  if (admitPeers === null) return true;
  return admitPeers.has(toHex(peerBytes));
}

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
    // The peer lint runs HERE — after decryption and signature, never on a claimed
    // key, and before msg4 puts our identity and signature on the wire. A refusal is
    // silence, so being turned away is indistinguishable from a msg3 that simply never
    // arrived, and the caller learns nothing about who lives at this address. Nothing
    // about us has gone out yet, and that is the whole point of the second round trip
    // (§12.6.2, CHANNEL §10 invariant 5). Asking at becomeAuthed() instead would be one
    // message too late.
    if (!admits(idI)) { this.stall(); return; }
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
    // The peer lint, on the end that dialed. Not concealed: we named ourselves at
    // msg3, so there is nothing left to hide from this peer and an abort is honest.
    if (!admits(idR)) { this.abort(true); return; }
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
