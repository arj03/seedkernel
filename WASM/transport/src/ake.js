// ============================================================================
// The transport bundle guest — the channel handshake (AKE + forward-secret record
// layer), the authenticated link router, the link bookkeeping and the
// request/response layer — as the zero-authority JS program of a signed bundle
// reaching the raw-link capability and claiming `_net` (§12.6). The host keeps only what has no
// endpoint substitute: the sockets, the flood caps, the node key, the entropy
// source. Everything here is state machines.
//
// The program is split across transport/src/{util,ake,framing,router,core}.js and
// CONCATENATED in that fixed order by scripts/build-transport-bundle.mjs into the
// single guest.js the manifest hashes and the loader runs. The parts share one
// scope, so a reference to a later part must be a runtime one, never top-level.
//
// The seam is one `host.call(name, bytes)` (§12.2), and the names below are
// declared in the manifest's `guest.requires` — a host that cannot serve one
// refuses the bundle at load. Primitives (pure transforms):
//
//   "crypto/blake2b-256"                bytes -> 32B                (transcript, KDF, root)
//   "crypto/chacha20poly1305-ietf/seal" [npub 12][key 32][msg] -> ct    (record layer)
//   "crypto/chacha20poly1305-ietf/open" [npub 12][key 32][ct] -> [ok u8][pt]
//   "crypto/x25519/dh"                  [sk 32][pk 32] -> [ok u8][x 32] (also the
//                                       pubkey, against the base point)
//
// Changing suite is changing these names: no op number, no ABI rev, no new grant.
// Authorities — the whole of what this program holds:
//
//   "link/sign"   msg -> 64B sig, under this slot's network scope (`DOMAIN_link_scope ‖
//                 networkKey`) — the one thing this name ever signs under, wired only
//                 because this bundle reaches `link`. The host never reads the suffix,
//                 and the channel format tag is part of msg below, so no handshake shape
//                 is pinned into the host and no call signs raw bytes.
//   "link/verify" [pk 32][sig 64][msg] -> [ok u8], under the SAME network scope — so
//                 this program checks a peer's transcript signature without holding the
//                 scope it was made under.
//   "node/random" [n u32 BE] -> n bytes            (nonces, ephemeral secrets)
//   `link/*`      bytes over an opaque link id, opened and closed
//   `timer/*`     deadlines, since a zero-authority realm has no setTimeout
//   "route/deliver" generic submission to an exact local claim
//   "link/authenticated", "link/down" reports to this raw-link binding's owner
//
// Its own ws.wasm needs no grant: a bare name is a primitive, ungated like `crypto`
// (§12.1). What the program provides back is the reserved id `_net` it CLAIMS
// (§12.10), reached by an app calling it, with the host contributing attribution and
// resolution only. One entrypoint, `handle`, invoked exactly as an app's is; the op
// travels as a length-prefixed name in the payload, so an unimplemented op fails loud
// rather than desyncing a decoder. (`timer` is every guest's, not this program's.)
// Channels are host handles keyed by a HOST-minted link id, so all link state lives in
// this module's heap. These parts are signed into the bundle: no imports, and they
// must match the seam exactly — the host twin is host/transport-host.ts.
// ============================================================================

// ── capability names (must match the guest seam's dispatch table) ─────────────

const N_SIGN = "link/sign";
const N_VERIFY = "link/verify";
const N_RANDOM = "node/random";
/** This bundle's own RFC 6455 codec, by the logical name its manifest declares. A bare
 *  name — no `/` — is what makes it a module rather than a host name (§12.2). */
const N_WS = "ws";

const N_LINK_CONFIG = "link/config";
const N_LINK_OPEN = "link/open";
const N_LINK_SEND = "link/send";
const N_LINK_CLOSE = "link/close";
// A READ of a link's unsent backlog — the only way this program can tell a slow
// exchange from a stalled one, since everything else it sees is its own bookkeeping.
const N_LINK_STAT = "link/stat";
const N_LINK_AUTHENTICATED = "link/authenticated";
const N_LINK_DOWN = "link/down";
const N_ROUTE_DELIVER = "route/deliver";

const N_TIMER_ARM = "timer/arm";
const N_TIMER_CLEAR = "timer/clear";

const P_HASH = "crypto/blake2b-256";
const P_SEAL = "crypto/chacha20poly1305-ietf/seal";
const P_OPEN = "crypto/chacha20poly1305-ietf/open";
const P_DH = "crypto/x25519/dh";

// The X25519 base point: `crypto/x25519/dh(sk, BASEPOINT)` is the public-key
// derivation, so the catalog needs no keygen entry (and stays purely functional) while
// the ephemeral secret comes from node/random.
const X25519_BASEPOINT = new Uint8Array([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

// Kinds of link, as the host's `linkOpen` declares them: 0 = the routing core's own
// (an accepted socket; dial/accept bookkeeping and the half-open limiter apply);
// 1 = a host-managed transport (WebRTC / browser WS) that opened the socket itself and
// handed it over. A core link we DIALED never arrives this way.
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

// ── channel handshake constants (§12.6) ──────────────────────────────────────

const SUITE_CHANNEL_CONCEALED = 0x03;
const SUITE_LEN = 1, PK_LEN = 32, NONCE_LEN = 32, EPH_LEN = 32, SIG_LEN = 64;
const KEY_LEN = 32, NPUB_LEN = 12, TAG_LEN = 16;
const M1_LEN = SUITE_LEN + EPH_LEN + NONCE_LEN + TAG_LEN; //  81
const M2_LEN = EPH_LEN + NONCE_LEN + TAG_LEN;             //  80
const M3_LEN = PK_LEN + SIG_LEN + TAG_LEN;                // 112
const M4_LEN = PK_LEN + SIG_LEN + TAG_LEN;                // 112

// The one suite this transport speaks, and the bundle's own number: a channel suite is
// read by the AKE, which is entirely this program, so it lives here rather than in the
// host's core (§14.1 — the manifest suite is the host's for the opposite reason, the
// loader reads it before anything is trusted).
//
// A suite byte is not negotiated: it makes the wire self-describing, and because it
// sits inside every signed transcript half, an in-path attacker who flips it only makes
// the two ends sign different bytes (§12.6, §14.1).
//
// `0x03` moved the channel's format tag out of the host's signing prefix and into the
// identity payload this program assembles (`channelIdentityMessage`), which changes what
// both ends sign. It is a new byte for the reason every suite change is: a node that
// speaks the old preimage must fail at msg1, by a suite it does not know, rather than
// authenticate its way to a signature mismatch it cannot explain. 0x02 was removed, not
// disabled — a node accepting both would take the concealment of the weaker one.
const SUITE_BYTE = new Uint8Array([SUITE_CHANNEL_CONCEALED]);

const ZERO_NPUB = new Uint8Array(NPUB_LEN);

// Directional session-key labels and the ratchet label — same family discipline as
// every domain prefix: distinct, versioned, trailing NUL so no member is a prefix of
// another. This bundle's wire contract, never seen by the host.
const LABEL_REKEY = utf8Encode("seedkernel-session-rekey-v1\0");
const LABEL_PROBE = utf8Encode("seedkernel-c-probe-v1\0");
const LABEL_M2 = utf8Encode("seedkernel-c-msg2-v1\0");
const LABEL_M3 = utf8Encode("seedkernel-c-msg3-v1\0");
const LABEL_M4 = utf8Encode("seedkernel-c-msg4-v1\0");
const LABEL_I2R = utf8Encode("seedkernel-session-i->r-v1\0");
const LABEL_R2I = utf8Encode("seedkernel-session-r->i-v1\0");

// This channel format tag seeds the session root AND prefixes every identity-signature
// payload below. It is transport CONTENT, not a kernel signing domain — which is what lets
// this program change its handshake format in a bundle update: the host contributes only
// the opaque scope it chose for this slot (`DOMAIN_link_scope ‖ networkKey`) and reads
// nothing inside.
const DOMAIN_CHANNEL = utf8Encode("seedkernel-channel-id-v1\0");

// Per-suite wire lengths. A later suite changes these and the byte it is keyed by; the
// host never reads them.
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
  // The argument buffer held a COPY of the private scalar. Erasing the key on the
  // link (Link.clearEphemeral) is worth nothing if the call that used it leaves a
  // second copy on the heap for a memory-image attacker to find.
  out.fill(0);
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
/** Assemble the channel's tagged identity-signature format. The host treats this whole
 *  value as an opaque suffix, while still prefixing the scope it chose for this slot. */
function channelIdentityMessage(root, th, id) {
  return concatBytes([DOMAIN_CHANNEL, root, th, id]);
}
/** Ask the host to sign a tagged handshake transcript, under `DOMAIN_link_scope ‖
 *  networkKey` (the prefix is the host's, unconditional for this name) with the node's
 *  channel key, which never enters this program.
 *
 *  `link/sign` THROWS when the bundle does not reach the authority (guest-seam.ts), so
 *  the `{ok}` shape is a real status: catching here lets the caller abort the link
 *  rather than unwind out of a frame-delivery callback and leave the socket open until
 *  it times out. Same idiom as `scalarmult` and `openZero`. */
function channelSign(root, th, id) {
  try {
    return { ok: true, sig: host.call(N_SIGN, channelIdentityMessage(root, th, id)) };
  } catch {
    return { ok: false, sig: null };
  }
}

// ── calling out: the ops, each one argument-encoded and issued immediately ────
//
// There is no action buffer and no batch — accumulating orders into a response the host
// decodes afterwards would be a second host↔module ABI. Every call below is an ordinary
// `host.call` through the one seam (§12.2).
//
// The arrangement rests on the host's rule that NO OP RE-ENTERS THIS REALM, so nothing
// below can call back into a frame still on the stack. The corollary, and why this
// program never uses `await`: an answer arriving through this realm cannot be awaited
// from inside it, since the invocation carrying it would queue behind the frame doing
// the awaiting (realm-queue.ts). So an inbound request is dispatched with `.then`, and
// an app's send is answered with `defer()`.

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
function netConfig() { return host.call(N_LINK_CONFIG, new Uint8Array(0)); }
function netLinkClose(linkId, graceful) { host.call(N_LINK_CLOSE, args([linkId], [graceful ? 1 : 0])); }
/** Bytes handed to this link that are not yet on the wire. 0 for a link that is gone
 *  or a channel that cannot say — both read as "nothing queued", which leaves the
 *  stall clock to the deadline alone. */
function netLinkBuffered(linkId) { return readU32BE(host.call(N_LINK_STAT, args([linkId], [])), 0); }

/** Hand an inbound request to whichever app claims its protocol id, and resolve with
 *  that app's answer. NOT awaited by any caller inside this realm — see the note above.
 *
 *  Delivery and the reply are ONE call: the answer is the app's own `handle` return
 *  value on a later turn, which is what an asynchronous app handler needs. */
function hostDeliver(fromBytes, proto, payload) {
  const attrLen = new Uint8Array(4);
  writeU32BE(attrLen, 0, fromBytes.length);
  return host.call(N_ROUTE_DELIVER, concatBytes([
    Uint8Array.of(proto.length), proto, attrLen, fromBytes, payload,
  ]));
}
/** A link the HOST handed us (openLink) authenticated, or tore down. Relayed so whoever
 *  passed the channel in learns its fate; a core link the guest dialed or accepted is
 *  nobody's business but ours. */
function hostLinkAuth(linkId, peerBytes) { host.call(N_LINK_AUTHENTICATED, args([linkId], [], peerBytes)); }
function hostLinkDown(linkId, reason) { host.call(N_LINK_DOWN, args([linkId], [reason])); }

/** The peer LINT (§12.6): is this peer on the operator's list? Asked at the FIRST point
 *  the peer is known and — critically — before this end has revealed anything about
 *  itself: msg3 when accepting, msg4 when dialing. `conceal` says a refusal must be
 *  silent, which is true exactly when we have not yet sent our identity, and it is what
 *  keeps a refusal from being an oracle (§12.6.2).
 *
 *  A LINT, not a gate: what it catches is a buggy transport or an unlisted peer, both
 *  ours. Held host-side it would gate nothing either, since the key it checked would be
 *  one we supplied. What holds against a hostile occupant of this slot is that it
 *  reaches no authority but `link/*`. */
function admits(peerBytes) {
  if (admitPeers === null) return true;
  return admitPeers.has(toHex(peerBytes));
}

// ── timers ────────────────────────────────────────────────────────────────────

// `timer/arm` is the host's table and the host's cap (DEFAULT_MAX_LIVE_TIMERS), so a
// realm that has spent it gets a THROW here rather than a return code. The entry is
// dropped again before the throw escapes: a caller that retries must not accumulate
// callbacks for deadlines the host never armed and will never fire back.
function armTimer(ms, fn) {
  const id = nextTimerId++;
  timers.set(id, fn);
  try {
    host.call(N_TIMER_ARM, args([id, Math.max(1, Math.floor(ms))], []));
  } catch (e) {
    timers.delete(id);
    throw e;
  }
  return id;
}
function clearTimer(id) {
  if (timers.delete(id)) host.call(N_TIMER_CLEAR, args([id], []));
}
function fireTimer(id) {
  const fn = timers.get(id);
  if (fn) { timers.delete(id); fn(); }
}

// ── the link ─────────────────────────────────────────────────────────────────

// One host-managed channel, addressed by the HOST-SUPPLIED link id. All session state
// lives in this heap, keyed by that id.

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
    // accepting: OURS (§12.6.3).
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
    this.idle = null;         // the post-auth idle clock (armIdle)
    this.sawTraffic = false;  // ...and whether anything crossed since it last ticked
    this.sendKey = null;
    this.recvKey = null;
    this.sendEpoch = 0;
    this.sendCtr = 0;
    this.recvEpoch = 0;
    this.recvCtr = 0;
    this.th = null;
    this.ee = null;

    // Half-open slot BEFORE any key material — the cap's point is that a refused
    // connection costs a map lookup, not a keypair. Teardown of an over-budget link is
    // deferred so the constructor never notifies synchronously (see deferTeardown).
    if (spec.limiter) {
      this.slot = spec.limiter.acquire(this.source, () => this.abort());
      if (!this.slot) {
        this.deferTeardown();
        return;
      }
    }

    // Only a dialer speaks unprompted; an accepting link says nothing until a msg1
    // opens under the contact secret, and a responder generates no key material before
    // that proof (§12.6.2).
    //
    // Everything from here on can THROW: `armDeadline` crosses to the host, and
    // `timer/arm` refuses once the realm's live-timer table is full — a cap a
    // CO-RESIDENT app can reach on its own. A throw escaping the constructor would leave
    // the slot acquired and the host channel open with no Link built to close either, so
    // an app sitting on the timer cap would make every inbound connection a permanent
    // leak. Hence the same deferred teardown the refused slot takes.
    try {
      if (this.weDialed) {
        this.ensureKeys();
        this.armDeadline(this.handshakeTimeoutMs || HANDSHAKE_TIMEOUT_MS);
        this.sendMsg1();
      } else {
        this.armDeadline(this.handshakeTimeoutMs || UNVERIFIED_TIMEOUT_MS);
      }
    } catch {
      // The slot first and on its own: it is the resource with a hard cap and releasing
      // it touches nothing outside this module, whereas the rest of the tidying crosses
      // to the host again and so may fail again. A failure to tidy must not cost the
      // slot, nor the close and notify below.
      this.releaseSlot();
      try { this.teardown(); } catch { /* the host has evidently lost the timer anyway */ }
      this.deferTeardown();
    }
  }

  /** Close the host channel and notify, but AFTER the current event: the caller's
   *  bookkeeping (core.openLink's pools, entry("openLink")'s `openLinks`) runs once the
   *  constructor returns, so a synchronous onClose would undo what it has not yet
   *  done. */
  deferTeardown() {
    this.closed = true;
    this.closedLocally = true;
    deferQueue.push(() => {
      try { netLinkClose(this.linkId, false); } catch { /* already gone */ }
      this.finish();
    });
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

  /** The post-auth idle clock, which the handshake deadline hands over to: a peer that
   *  opens links and then goes quiet is the cheapest way to spend our budget of sockets,
   *  slots and sessions. Retired with the authenticated goodbye, since that is a
   *  deliberate shutdown and the address book redials on the next send.
   *
   *  Two ticks rather than a timestamp, because a zero-authority realm has no clock —
   *  "idle" is "a whole window passed with nothing seen", so the effective window is
   *  between one and two `linkIdleTimeoutMs`. */
  armIdle() {
    if (linkIdleTimeoutMs <= 0) return;
    this.sawTraffic = false;
    this.idle = armTimer(linkIdleTimeoutMs, () => {
      this.idle = null;
      if (this.closed || !this.authed) return;
      if (!this.sawTraffic) { this.close(); return; }
      this.armIdle();
    });
  }

  clearIdle() {
    if (this.idle !== null) { clearTimer(this.idle); this.idle = null; }
  }

  // Queue (pre-auth) or send (post-auth, as an AEAD record) a frame.
  send(frame) {
    if (this.closed) return;
    // Refuse a frame that would seal to an over-cap wire record: the receiver would
    // reject it on its length prefix and tear the link down. The cap is the host's,
    // learned at INIT.
    if (frame.length > maxFrameBytes - TAG_LEN) return;
    // An empty record is the authenticated end-of-stream marker, never app data.
    if (frame.length === 0) return;
    if (this.authed) {
      if (this.sendEpoch >= REJECT_AFTER_EPOCHS) { this.close(); return; }
      this.sawTraffic = true;
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
    // The goodbye records above are QUEUED, not yet on the wire — the module calls
    // framing them answer on a later turn. Closing only once the framer's last write has
    // landed is what makes the peer read a clean shutdown rather than a truncation.
    const flushed = (this.framer && this.framer.flush ? this.framer.flush() : Promise.resolve()).catch(() => {});
    void flushed.then(() => {
      try { netLinkClose(this.linkId, saidGoodbye); } catch { /* already gone */ }
      this.finish();
    });
  }

  // Every failure path uses abort(), never close(): only close() emits the
  // authenticated end-of-stream record, so "the peer said goodbye" always means "the
  // peer chose to stop".
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

  /** Inbound bytes from the host: a whole message on a framed link, an arbitrary slice
   *  on an unframed one. An over-cap declaration is a protocol violation, so it is a
   *  defensive abort — nothing said.
   *
   *  A framed link's push is async, so the abort decision lands on a later turn and the
   *  host does not wait for it before handing over the next chunk. Delivery stays in the
   *  order the record layer's counter requires because the framer's own read chain
   *  (framing.js, `push`) parses one chunk at a time; `closed` gates what a delivery
   *  arriving after an abort can still reach. */
  onWire(bytes) {
    if (!this.framer) {
      // A platform-framed link (browser WebSocket, RTCDataChannel) arrives with message
      // boundaries already on it, so there is no reassembly buffer of ours to bound —
      // but the two-stage cap is about how much a peer may make us HOLD, not about who
      // framed it. Without this, one huge message takes the realm down.
      if (bytes.length > (this.authed ? maxFrameBytes : maxHandshakeFrameBytes)) { this.abort(true); return; }
      this.onMessage(bytes);
      return;
    }
    // A Promise on a framed link (its decode runs in the bundle's ws module, whose
    // answer crosses an isolate since ABI 6), a plain boolean on a length-framed one.
    void Promise.resolve(this.framer.push(bytes, (m) => this.onMessage(m))).then(
      (ok) => { if (!ok) this.abort(true); },
      () => { this.abort(true); },
    );
  }

  /** Route one whole link message. A message is a bare body, and which one it is follows
   *  from our role and how far the exchange has got — so the sender chooses nothing:
   *  every message has exactly one destination, the handler checks its exact width, and a
   *  post-auth body goes to the AEAD, which fails closed. */
  onMessage(m) {
    if (this.closed) return;
    if (this.authed) this.onRecord(m);
    else if (this.weDialed) this.peerEph ? this.onMsg4(m) : this.onMsg2(m);
    else this.peerEph ? this.onMsg3(m) : this.onMsg1(m);
  }

  // Refuse WITHOUT saying so — every refusal funnels here, so they are
  // indistinguishable from each other and from silence (§12.6.2).
  stall() { /* deliberately nothing */ }

  becomeAuthed() {
    this.authed = true;
    // The slot is NOT released — it moves to the authed tier and is held until the link
    // dies. Released, the budget would bound only how many peers are GETTING IN at once:
    // past the door anyone able to complete a handshake could open links without limit,
    // each with its own framer, keys, timers and buffers.
    if (this.slot && !this.slot.limiter.hold(this.slot)) { this.abort(); return; }
    this.clearDeadline();
    this.armIdle();
    // A known, admitted identity may send full-size frames; a stranger may not. A
    // platform-framed link has no framer to raise — for it, `authed` (set above) is what
    // raises the cap, in onWire.
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
    // The channel tag and `root ‖ th ‖ id` are the opaque suffix; the host reads none of
    // it and prefixes with this slot's network scope, `DOMAIN_link_scope ‖ networkKey` —
    // which is why the network binding survives a transport that lies about its own root.
    const r = channelSign(this.root, th, ownPk);
    // The seam refused: no `link/sign` grant. Our own misconfiguration, never anything
    // the peer did, so it aborts — a stall would claim this address went quiet, which is
    // a different fact.
    if (!r.ok) { this.abort(); return null; }
    return { id: ownPk, sig: r.sig };
  }

  openIdentity(key, ct, th) {
    const r = this.openZero(key, ct);
    if (!r.ok) return null;
    const plain = r.pt;
    const id = plain.slice(0, PK_LEN);
    const sig = plain.slice(PK_LEN, PK_LEN + SIG_LEN);
    // link/verify applies the same host-owned scope this node signs under, so the preimage
    // the two ends must agree on is the host's for its prefix half. The channel's format
    // tag is ours, so the two ends reconstruct that half here.
    if (!verify(id, sig, channelIdentityMessage(this.root, th, id))) return null;
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
    // The peer lint runs HERE: after decryption and signature, never on a claimed key,
    // and before msg4 puts our identity on the wire. A refusal is silence, so being
    // turned away is indistinguishable from a msg3 that never arrived — the whole point
    // of the second round trip (§12.6.2). At becomeAuthed() it would be one message
    // too late.
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
    // Every input that produced the session can now only be used to RE-derive it, which
    // is the point at which forward secrecy is either real or a claim (clearEphemeral).
    this.clearEphemeral();
  }

  /** Erase the handshake's private material: the X25519 ephemeral SECRET, the shared
   *  point it produced, and our nonce.
   *
   *  Forward secrecy is a property of what is IN MEMORY, not of what is on the wire: an
   *  attacker who reads this process (a core dump, a swapped page) and finds the
   *  ephemeral secret recomputes `ee` against the peer's public ephemeral, re-runs the
   *  KDF over the transcript, and decrypts every record the link carried.
   *
   *  Called at both ends of the handshake's life — the moment the session keys exist
   *  (the common case), and again at teardown, which covers a link that DIED
   *  mid-handshake and is exactly when the material is otherwise still live. `myEph` is
   *  dropped rather than only zeroed, or `ensureKeys` would see an all-zero secret as a
   *  key it had already generated.
   *
   *  This cannot promise the engine kept no copy (a GC that moved the buffer), only that
   *  no live reference holds the plaintext key. */
  clearEphemeral() {
    if (this.myEph) {
      this.myEph.privateKey.fill(0); // the secret half only — the public one was on the wire
      this.myEph = null;
    }
    if (this.myNonce) { this.myNonce.fill(0); this.myNonce = null; }
    if (this.ee) { this.ee.fill(0); this.ee = null; }
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
  // or injection either way. The one receive path that SPEAKS: concealment is owed to
  // strangers, and this peer proved who it is.
  onRecord(body) {
    // Framed links have already been measured; this is the platform-framed one's floor,
    // stated where the record layer can see it.
    if (!this.recvKey || body.length < TAG_LEN || body.length > maxFrameBytes) { this.abort(true); return; }
    if (this.recvEpoch >= REJECT_AFTER_EPOCHS) { this.abort(); return; }
    const r = aeadDec(this.recvKey, this.nonce(this.recvEpoch, this.recvCtr), body);
    if (!r.ok) { this.abort(true); return; }
    this.sawTraffic = true;
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
    this.clearIdle();
    this.releaseSlot();
    this.queue.length = 0;
    this.queuedBytes = 0;
    if (this.sendKey) this.sendKey.fill(0);
    if (this.recvKey) this.recvKey.fill(0);
    this.sendKey = null;
    this.recvKey = null;
    // The link torn down mid-handshake is exactly the case where the ephemeral secret
    // and the nonce are still live (clearEphemeral).
    this.clearEphemeral();
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
