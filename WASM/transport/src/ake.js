// Transport bundle guest: AKE, record layer, link router, request/response (§12.6).

const N_SIGN = "node/sign";
const N_VERIFY = "node/verify";
const N_RANDOM = "node/random";
// Read from the host so it matches `node/sign` (§12.2).
const N_IDENTITY = "node/identity";
/** This bundle's own RFC 6455 codec, by the logical name its manifest declares. A bare
 *  name — no `/` — is what makes it a module rather than a host name (§12.2). */
const N_WS = "ws";
/** ML-KEM is bundle content, not a host primitive. */
const N_MLKEM = "mlkem";

const N_LINK_OPEN = "link/open";
const N_LINK_SEND = "link/send";
const N_LINK_CLOSE = "link/close";
// A READ of a link's unsent backlog — the only way this program can tell a slow
// exchange from a stalled one, since everything else it sees is its own bookkeeping.
const N_LINK_STAT = "link/stat";
// The one link name that carries something IN rather than out: a request this program
// decoded off a link, handed to the host's claim routing.
const N_LINK_DELIVER = "link/deliver";

const N_TIMER_ARM = "timer/arm";
const N_TIMER_CLEAR = "timer/clear";

const P_HASH = "crypto/blake2b-256";
const P_SEAL = "crypto/chacha20poly1305-ietf/seal";
const P_OPEN = "crypto/chacha20poly1305-ietf/open";
const P_DH = "crypto/x25519/dh";

// The X25519 base point: `dh(sk, BASEPOINT)` IS the public-key derivation, so the
// the residual host transform needs no keygen entry while the secret comes from node/random.
const X25519_BASEPOINT = new Uint8Array([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

// Why a link went down, returned from the driver's `linkClosed` event. The event already
// names the link, so the return carries no link id and cannot speak about another socket.
// This is the ONE thing the host cannot work out for itself: it sees a descriptor close,
// while whether that was a farewell, a defensive abort or a cut stream is a fact only the
// end holding the session keys ever had.
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
const KEM_PK_LEN = 1184, KEM_SK_LEN = 2400, KEM_CT_LEN = 1088, KEM_SS_LEN = 32;
const M1_LEN = SUITE_LEN + EPH_LEN + KEM_PK_LEN + NONCE_LEN + TAG_LEN; // 1265
const M2_LEN = EPH_LEN + KEM_CT_LEN + NONCE_LEN + TAG_LEN;             // 1168
const M3_LEN = PK_LEN + SIG_LEN + TAG_LEN;                // 112
const M4_LEN = PK_LEN + SIG_LEN + TAG_LEN;                // 112

// The one suite this transport speaks, and the bundle's own number: a channel suite is
// read by the AKE, which is entirely this program, so it lives here rather than in the
// host's core (§14.1). Not negotiated: it makes the wire self-describing, and because it
// sits inside every signed transcript half, an in-path attacker who flips it only makes
// the two ends sign different bytes (§12.6).
const SUITE_BYTE = new Uint8Array([SUITE_CHANNEL_CONCEALED]);

const ZERO_NPUB = new Uint8Array(NPUB_LEN);

// Directional session-key labels and the ratchet label — distinct, versioned, trailing NUL.
const LABEL_REKEY = utf8Encode("seedkernel-session-rekey-v1\0");
const LABEL_PROBE = utf8Encode("seedkernel-c-probe-v1\0");
const LABEL_M2 = utf8Encode("seedkernel-c-msg2-v1\0");
const LABEL_M3 = utf8Encode("seedkernel-c-msg3-v1\0");
const LABEL_M4 = utf8Encode("seedkernel-c-msg4-v1\0");
const LABEL_I2R = utf8Encode("seedkernel-session-i->r-v1\0");
const LABEL_R2I = utf8Encode("seedkernel-session-r->i-v1\0");

// This channel format tag seeds the session root and prefixes every identity-signature
// payload. Transport CONTENT, not a kernel signing domain — which is how a bundle update
// changes the handshake format: the host supplies only the opaque scope. (§12.6.2b)
const DOMAIN_CHANNEL = utf8Encode("seedkernel-channel-id-v1\0");

// Per-suite policy constants, keyed by the suite byte; the host never reads them.
const REJECT_AFTER_EPOCHS = 1 << 16; // ratchets per direction before the link retires
const MAX_QUEUE_BYTES = 1024 * 1024; // pre-auth send buffer byte budget (drop-oldest)

// ── the seam helpers ──────────────────────────────────────────────────────────
//
// EVERY seam name answers a Promise now — there is no sync/async line to fall on the
// wrong side of — so every helper is `async` and its callers await it. The cost is a
// few microtasks per call; the transforms themselves still run inline in the host.

async function hash() {
  const parts = [...arguments];
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return host.call(P_HASH, out);
}
async function verify(pk, sig, msg) {
  let len = pk.length + sig.length + msg.length;
  const out = new Uint8Array(len);
  out.set(pk, 0); out.set(sig, pk.length); out.set(msg, pk.length + sig.length);
  const r = await host.call(N_VERIFY, out);
  return r[0] === 1;
}
async function randomBytes(n) {
  const req = new Uint8Array(4);
  writeU32BE(req, 0, n);
  return host.call(N_RANDOM, req);
}
async function aeadEnc(key, npub, msg) {
  const out = new Uint8Array(npub.length + key.length + msg.length);
  out.set(npub, 0); out.set(key, npub.length); out.set(msg, npub.length + key.length);
  return host.call(P_SEAL, out);
}
async function aeadDec(key, npub, ct) {
  const out = new Uint8Array(npub.length + key.length + ct.length);
  out.set(npub, 0); out.set(key, npub.length); out.set(ct, npub.length + key.length);
  const r = await host.call(P_OPEN, out);
  return r[0] === 1 ? { ok: true, pt: r.subarray(1) } : { ok: false, pt: null };
}
async function scalarmult(sk, pk) {
  const out = new Uint8Array(64);
  out.set(sk, 0); out.set(pk, 32);
  const r = await host.call(P_DH, out);
  // The buffer held a COPY of the private scalar; zero it, or the call leaves a second
  // copy on the heap for a memory-image attacker to find.
  out.fill(0);
  return r[0] === 1 ? { ok: true, x: r.subarray(1) } : { ok: false, x: null };
}
/** An ephemeral X25519 pair: entropy from the host, the public half through the current
 *  host transform against the base point. */
async function boxKeypair() {
  const sk = await randomBytes(32);
  const r = await scalarmult(sk, X25519_BASEPOINT);
  if (!r.ok) throw new Error("transport: ephemeral keygen failed");
  return { publicKey: r.x, privateKey: sk };
}
async function kemKeypair(seed) {
  const req = concatBytes([Uint8Array.of(0), seed]);
  let r;
  try {
    r = await host.call(N_MLKEM, req);
  } finally {
    req.fill(0);
    seed.fill(0);
  }
  if (r.length !== KEM_PK_LEN + KEM_SK_LEN) {
    r.fill(0);
    throw new Error("transport: ML-KEM keygen failed");
  }
  const pair = { publicKey: r.slice(0, KEM_PK_LEN), privateKey: r.slice(KEM_PK_LEN) };
  r.fill(0);
  return pair;
}
async function kemEncaps(pk, coins) {
  const req = concatBytes([Uint8Array.of(1), pk, coins]);
  let r;
  try {
    r = await host.call(N_MLKEM, req);
  } finally {
    req.fill(0);
    coins.fill(0);
  }
  const result = r.length === 1 + KEM_CT_LEN + KEM_SS_LEN && r[0] === 1
    ? { ok: true, ciphertext: r.slice(1, 1 + KEM_CT_LEN), sharedSecret: r.slice(1 + KEM_CT_LEN) }
    : { ok: false, ciphertext: null, sharedSecret: null };
  r.fill(0);
  return result;
}
async function kemDecaps(sk, ct) {
  const req = concatBytes([Uint8Array.of(2), sk, ct]);
  let r;
  try {
    r = await host.call(N_MLKEM, req);
  } finally {
    req.fill(0);
  }
  const result = r.length === 1 + KEM_SS_LEN && r[0] === 1
    ? { ok: true, sharedSecret: r.slice(1) }
    : { ok: false, sharedSecret: null };
  r.fill(0);
  return result;
}
/** The channel's tagged identity-signature format — the host's slot scope, prefixed by
 *  the HOST, wraps this whole value as an opaque suffix. */
function channelIdentityMessage(root, th, id) {
  return concatBytes([DOMAIN_CHANNEL, root, th, id]);
}
/** Ask the host to sign under `DOMAIN_link_scope ‖ networkKey` with the node's channel
 *  key, which never enters this program. `node/sign` REJECTS when the authority is not
 *  reached, so the `{ok}` shape is a real status: catching here lets the caller abort the
 *  link rather than unwind out of a frame-delivery callback. */
async function channelSign(root, th, id) {
  try {
    return { ok: true, sig: await host.call(N_SIGN, channelIdentityMessage(root, th, id)) };
  } catch {
    return { ok: false, sig: null };
  }
}

// ── calling out: the ops, each one argument-encoded and issued immediately ────
//
// No action buffer and no batch — accumulating orders would be a second host↔module ABI.
// The arrangement rests on the host's rule that no op re-enters this realm, so nothing
// below can call back into a frame still on the stack. Every name answers on a later
// microtask now, so callers `await`; an inbound request is dispatched with `.then`, and
// an app's send is answered with `defer()`.

/** Open a link to an opaque destination — the string this program's own address book holds
 *  for a peer, which only the host's socket factory takes apart. 0 ⇒ no route: this node
 *  cannot reach that destination, and the caller treats it as a fabric dropping a frame. */
async function netLinkOpen(dest) {
  const r = await host.call(N_LINK_OPEN, utf8Encode(dest));
  // Destination selects the codec (§12.1).
  return { linkId: readU32BE(r, 0), stream: r[4] === 1 };
}
/** Fire-and-forget wire ops: a link/send cannot answer anything worth having (the
 *  channel drops silently when the link is gone either way), so their rejections are
 *  swallowed here rather than left to surface as unhandled rejections. */
function netLinkSend(linkId, bytes) { void host.call(N_LINK_SEND, args([linkId], [], bytes)).catch(() => {}); }
function netLinkClose(linkId, graceful) { void host.call(N_LINK_CLOSE, args([linkId], [graceful ? 1 : 0])).catch(() => {}); }
/** Bytes handed to this link that are not yet on the wire. 0 for a link that is gone
 *  or a channel that cannot say — both read as "nothing queued", which leaves the
 *  stall clock to the deadline alone. */
async function netLinkBuffered(linkId) { return readU32BE(await host.call(N_LINK_STAT, args([linkId], [])), 0); }

/** Hand ONE request this program decoded to the host's claim routing:
 *  `[claimLen u8][claim][attribution 32][payload]`, answered with the claimant's bytes
 *  (empty both for a claim no peer may reach and for a handler that failed — one fact at
 *  this boundary). Symmetric with an outbound `send` and under the same `link` privilege
 *  as every other name here: it selects no link, and this program chose all three fields.
 *
 *  One request per call, so the payload simply runs to the end. It is the caller's job to
 *  FIRE this and return from the event that decoded the request — the answer is another
 *  turn of this realm, so awaiting it inside that event would hold the realm against it. */
function netLinkDeliver(claim, attribution, payload) {
  return host.call(N_LINK_DELIVER, concatBytes([Uint8Array.of(claim.length), claim, attribution, payload]));
}

/** Peer lint (§12.6): asked at msg3 when accepting, msg4 when dialing — before this
 *  end has revealed anything. A lint, not a gate: a hostile occupant still reaches
 *  only `link/*`. */
function admits(peerBytes) {
  if (admitPeers === null) return true;
  return admitPeers.has(toHex(peerBytes));
}

// ── timers ────────────────────────────────────────────────────────────────────

// `timer/arm` is the host's table and the host's cap (DEFAULT_MAX_LIVE_TIMERS). The arm
// lands on a later microtask now, so the id returns immediately and a REFUSAL (the cap)
// drops the entry instead of throwing to the armer — the tables stay honest, and the
// deadline that never fires reads as a stall to whichever clock armed it.
function armTimer(ms, fn) {
  const id = nextTimerId++;
  timers.set(id, fn);
  // The kernel stores and returns the tail opaquely. This transport owns the event's
  // `timer` name and framing just as it owns every other byte after the caller id.
  void host.call(N_TIMER_ARM, args(
    [id, Math.max(1, Math.floor(ms))], [], writeOp("timer", argU32(id)),
  )).catch(() => {
    timers.delete(id);
  });
  return id;
}
function clearTimer(id) {
  if (timers.delete(id)) void host.call(N_TIMER_CLEAR, args([id], [])).catch(() => {});
}
function fireTimer(id) {
  const fn = timers.get(id);
  if (fn) { timers.delete(id); fn(); }
}

// ── the link ─────────────────────────────────────────────────────────────────

// One host-managed channel, addressed by the host-supplied link id. All session state
// lives in this heap, keyed by that id.

class Link {
  constructor(spec) {
    this.linkId = spec.linkId;
    // Framing derives from stream shape and route metadata (§12.1).
    this.framer = makeFramer(spec.stream, spec.linkId, spec.dest, spec.listener);
    this.weDialed = spec.weDialed;
    this.expectPeerId = spec.expectPeerId;   // 32B or null
    this.source = spec.source;               // remoteAddr for the limiter, if any
    this.onAuth = spec.onAuth;
    this.onFrame = spec.onFrame;
    this.onClose = spec.onClose;
    this.rekeyAfter = rekeyAfterFrames;
    // Address-book dials use the peer's secret; platform-opened links use our live secret
    // (§12.6.3).
    this.contactSecret = spec.linkSecret || contactSecret;
    this.root = null; // set by the boot chain below — every seam call is async now

    this.peerPubkey = null;
    this.peerId = "";
    this.authed = false;
    this.peerSaidGoodbye = false;
    this.myNonce = null;
    this.myEph = null;
    this.myKem = null;
    this.kemSecret = null;
    this.queue = [];
    this.queuedBytes = 0;
    this.outboundQueuedBytes = 0;
    this.outboundQueuedSlices = 0;
    this.peerEph = null;
    this.closed = false;
    this.stalled = false;
    this.notified = false;
    // How this link ended, for `closeReason`: whether WE tore it down, and whether the
    // teardown was defensive (a peer did something wrong) rather than merely our own
    // decision. Both are set once, on the way down, and read once by `linkClosed`.
    this.closedLocally = false;
    this.aborted = false;
    this.slot = null;
    this.deadline = null;
    this.idle = null;         // the post-auth idle clock (armIdle)
    this.sawTraffic = false;  // whether anything crossed since it last ticked
    this.sendKey = null;
    this.recvKey = null;
    this.sendEpoch = 0;
    this.sendCtr = 0;
    this.recvEpoch = 0;
    this.recvCtr = 0;
    this.th = null;
    this.ee = null;

    // One work chain per link. Every seam call answers a Promise now, so a handshake
    // step spans microtasks; serializing ALL of a link's processing through one chain
    // keeps two steps from interleaving mid-handshake and keeps arrival order (the
    // record layer counts nonces). The chain STARTS as the boot sequence.
    this.work = Promise.resolve();

    // Half-open slot BEFORE any key material — a refused connection costs a map lookup,
    // not a keypair. Teardown of an over-budget link is deferred (see deferTeardown).
    if (spec.limiter) {
      this.slot = spec.limiter.acquire(this.source, () => this.abort());
      if (!this.slot) {
        this.deferTeardown();
        return;
      }
    }

    // Only a dialer speaks unprompted; an accepting link says nothing until a msg1 opens
    // under the contact secret (§12.6.2).
    //
    // Everything here runs async now, so the constructor's old try/catch becomes the
    // boot chain's rejection arm — same deferred teardown the refused slot takes: the
    // slot first and on its own, then the timer table, then the notify-on-later-turn.
    const networkKeyBytes = spec.networkKey || networkKey;
    this.work = (async () => {
      this.root = await hash(DOMAIN_CHANNEL, networkKeyBytes);
      if (this.weDialed) {
        await this.ensureKeys();
        this.armDeadline(handshakeTimeoutMs);
        await this.sendMsg1();
      } else {
        this.armDeadline(unverifiedTimeoutMs);
      }
    })();
    this.work.catch(() => {
      this.releaseSlot();
      try { this.teardown(); } catch { /* the host has evidently lost the timer anyway */ }
      this.deferTeardown();
    });
  }

  /** Run `fn` as the next step of this link's one work chain. The returned promise
   *  settles with fn's own outcome; the CHAIN swallows it so one failed step never
   *  wedges the ones behind it. */
  enqueue(fn) {
    const done = this.work.then(fn);
    this.work = done.catch(() => {});
    return done;
  }

  /** Close the host channel and notify, but AFTER the current event: the caller's
   *  bookkeeping (core.openLink's connecting/inbound pools) runs once the constructor
   *  returns. */
  deferTeardown() {
    this.closed = true;
    this.closedLocally = true;
    deferQueue.push(() => {
      try { netLinkClose(this.linkId, false); } catch { /* already gone */ }
      this.finish();
    });
  }

  async ensureKeys() {
    if (!this.myNonce) this.myNonce = await randomBytes(NONCE_LEN);
    if (!this.myEph) this.myEph = await boxKeypair();
    // Only the initiator publishes an encapsulation key. The responder creates its KEM
    // state by encapsulating that key after the contact-secret probe has opened.
    if (this.weDialed && !this.myKem) this.myKem = await kemKeypair(await randomBytes(64));
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
   *  opens links and goes quiet is the cheapest way to spend our budget of sockets and
   *  slots. Retired with the authenticated goodbye.
   *
   *  Two ticks rather than a timestamp: a zero-authority realm has no clock, so "idle"
   *  is "a whole window passed with nothing seen" — the effective window is one to two
   *  `linkIdleTimeoutMs`. */
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
    // reject it on the length prefix and tear the link down. The cap is the host's.
    if (frame.length > maxFrameBytes - TAG_LEN) return;
    // An empty record is the authenticated end-of-stream marker, never app data.
    if (frame.length === 0) return;
    if (this.authed) {
      if (this.sendEpoch >= REJECT_AFTER_EPOCHS) { this.close(); return; }
      if (this.outboundQueuedSlices >= maxOutboundQueueSlices
          || frame.length > maxOutboundQueueBytes - this.outboundQueuedBytes) {
        // Dropping one record would desynchronise the ordered stream. Fail the link and let
        // every already-queued send observe `closed` instead of doing more crypto work.
        this.abort();
        return;
      }
      this.sawTraffic = true;
      // Sealed and wired through the one work chain, so records leave in send order.
      this.outboundQueuedSlices++;
      this.outboundQueuedBytes += frame.length;
      void this.enqueue(async () => {
        try {
          if (this.closed) return;
          this.wire(await this.seal(frame));
        } finally {
          this.outboundQueuedSlices--;
          this.outboundQueuedBytes -= frame.length;
        }
      });
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
    // The goodbye rides the same work chain as everything else, so it cannot overtake
    // a record still being sealed and cannot race teardown's key-zeroing.
    void this.enqueue(async () => {
      let saidGoodbye = false;
      if (this.authed && !this.peerSaidGoodbye && this.sendEpoch <= REJECT_AFTER_EPOCHS && this.sendKey) {
        try {
          this.wire(await this.seal(new Uint8Array(0)));
          // A codec with its own end-of-stream signal says it too, on the same byte
          // stream after our record, so the peer reads one clean shutdown.
          if (this.framer && this.framer.goodbye) this.framer.goodbye();
          saidGoodbye = true;
        } catch { /* the channel is already gone */ }
      }
      this.teardown();
      // The goodbye record is QUEUED, not yet on the wire; only closing once the framer's
      // last write has landed lets the peer read a clean shutdown, not a truncation.
      const flushed = (this.framer && this.framer.flush ? this.framer.flush() : Promise.resolve()).catch(() => {});
      await flushed;
      netLinkClose(this.linkId, saidGoodbye);
      this.finish();
    });
  }

  // Every failure path uses abort(), never close(): only close() emits the authenticated
  // end-of-stream record, so "the peer said goodbye" means "the peer chose to stop".
  abort(defensive) {
    if (this.closed) return;
    this.closed = true;
    this.closedLocally = true;
    if (defensive) this.aborted = true;
    // Behind the chain like close(), so an in-flight step finishes before its keys are
    // zeroed under it.
    void this.enqueue(async () => {
      this.teardown();
      netLinkClose(this.linkId, false);
      this.finish();
    });
  }

  /** Why this link ended, as the occupant alone can say it. `handshake` is a link that
   *  never got there; `clean` is the peer's own end-of-stream record; `aborted` is a
   *  teardown a peer PROVOKED (a forged record, a refused identity, an over-cap frame);
   *  `local` is our own deliberate shutdown; `truncated` is a stream that just stopped.
   *  The split matters: defining a truncation as `authed && !peerSaidGoodbye` would flag
   *  every deliberate close we make, and an attacker who could induce a farewell could
   *  make an arbitrary cut look like a clean shutdown to the far end. */
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

  /** Inbound bytes. Over-cap is a defensive abort. Every step rides the link's one work
   *  chain, so handshake steps cannot interleave and arrival order holds. Answers when
   *  this READ has been decoded — a request it carried is already on its way to the host
   *  under its own `link/deliver` call, and is deliberately not waited for here. */
  onWire(bytes) {
    // A concealed refusal is terminal for this exchange. The socket stays silent until
    // its already-armed deadline retires it, but subsequent reads do not reparse frames or
    // repeat proof/KEM work.
    if (this.closed || this.stalled) return Promise.resolve();
    if (!this.framer) {
      // A platform-framed link (browser WebSocket, RTCDataChannel) arrives with message
      // boundaries already on it — but the two-stage cap is about how much a peer may
      // make us HOLD, not about who framed it. Without this, one huge message takes the
      // realm down.
      if (bytes.length > (this.authed ? maxFrameBytes : MAX_HANDSHAKE_FRAME_BYTES)) { this.abort(true); return Promise.resolve(); }
      return this.enqueue(() => this.onMessage(bytes));
    }
    // Steps collected as PROMISES, in arrival order: a length-framed chunk's parse loop
    // fires `deliver` synchronously and does not await it, so finishing the read means
    // waiting on every step through Promise.all rather than counting pushes.
    const out = [];
    const deliver = (m) => { out.push(this.enqueue(() => this.onMessage(m))); };
    try {
      const ok = this.framer.push(bytes, deliver);
      return Promise.resolve(ok).then(
        (good) => {
          if (!good) { this.abort(true); return; }
          return Promise.all(out).then(() => {});
        },
        () => { this.abort(true); },
      );
    } catch {
      this.abort(true);
      return Promise.resolve();
    }
  }

  /** Route one whole link message. A message is a bare body — the sender chooses
   *  nothing: which one it is follows from our role and how far the exchange got, each
   *  handler checks its exact width, and a post-auth body goes to the AEAD, which fails
   *  closed (see §12.6). Answers when the step is done; nothing rides the value. */
  onMessage(m) {
    // Several complete frames can share one stream read and are enqueued before the first
    // is processed. Re-check here so a refusal by the first cheaply consumes the rest.
    if (this.closed || this.stalled) return Promise.resolve();
    const step = this.authed
      ? this.onRecord(m)
      : this.weDialed
        ? (this.peerEph ? this.onMsg4(m) : this.onMsg2(m))
        : (this.peerEph ? this.onMsg3(m) : this.onMsg1(m));
    return Promise.resolve(step).catch(() => { this.abort(true); });
  }

  // Refuse WITHOUT saying so — every refusal funnels here, so they are
  // indistinguishable from each other and from silence (§12.6.2). Terminal: what was
  // wrong was the PEER's, and nothing it can send on this connection changes that.
  stall() {
    if (this.stalled) return;
    this.stalled = true;
    // The timer and half-open slot remain live: silence must still cost the sender a slot
    // until the normal deadline. Private handshake material has no further use, though.
    this.clearEphemeral();
  }

  // Refuse the same way, but for OUR contention rather than anything the peer did, so the
  // exchange is not terminal: a caller that arrived while the verified budget was full may
  // try again on this connection before its deadline retires it. Indistinguishable on the
  // wire — both are silence — and a retry costs one AEAD open, the same as a fresh dial.
  stallBusy() { /* deliberately nothing */ }

  async becomeAuthed() {
    this.authed = true;
    // The slot is NOT released — it moves to the authed tier and is held until the link
    // dies, so the budget bounds how many peers may be IN rather than how many got in.
    if (this.slot && !this.slot.limiter.hold(this.slot)) { this.abort(); return; }
    this.clearDeadline();
    this.armIdle();
    // A known, admitted identity may send full-size frames; a platform-framed link has
    // no framer to raise — for it, `authed` is what raises the cap, in onWire.
    if (this.framer) this.framer.raiseCap();
    this.onAuth(this.peerId, this);
    if (this.closed) return; // onAuth may have torn us down (the tie-break)
    const flush = this.queue;
    this.queue = [];
    this.queuedBytes = 0;
    for (const f of flush) this.wire(await this.seal(f));
  }

  // ── the concealed-identity handshake (suite 0x03, §12.6.2) ──────────────────

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

  async sealZero(key, plain) {
    const ct = await aeadEnc(key, ZERO_NPUB, plain);
    key.fill(0);
    return ct;
  }
  async openZero(key, ct) {
    try { return await aeadDec(key, ZERO_NPUB, ct); }
    finally { key.fill(0); }
  }

  async probeKey(suiteByte, ephI, kemPkI) {
    return this.kdf([], await this.h(this.root, suiteByte, ephI, kemPkI), LABEL_PROBE);
  }

  async signIdentity(th) {
    // The channel tag and `root ‖ th ‖ id` are the opaque suffix; the host reads none of
    // it and prefixes this slot's network scope — which is why the network binding
    // survives a transport that lies about its own root.
    const r = await channelSign(this.root, th, ownPk);
    // The seam refused: our own misconfiguration, never the peer's doing, so it aborts —
    // a stall would claim this address went quiet, which is a different fact.
    if (!r.ok) { this.abort(); return null; }
    return { id: ownPk, sig: r.sig };
  }

  async openIdentity(key, ct, th) {
    const r = await this.openZero(key, ct);
    if (!r.ok) return null;
    const plain = r.pt;
    const id = plain.slice(0, PK_LEN);
    const sig = plain.slice(PK_LEN, PK_LEN + SIG_LEN);
    // node/verify applies the same host-owned scope this node signs under, so the
    // preimage the two ends must agree on is the host's for its prefix half. The channel
    // format tag is ours, so the two ends reconstruct that half here.
    if (!(await verify(id, sig, channelIdentityMessage(this.root, th, id)))) return null;
    if (bytesCompare(id, ownPk) === 0) return null; // our own traffic reflected
    return id;
  }

  async sendMsg1() {
    const eph = this.myEph.publicKey.subarray(0, EPH_LEN);
    const kemPk = this.myKem.publicKey;
    const w1 = concatBytes([SUITE_BYTE, eph, kemPk,
      await this.sealZero(await this.probeKey(SUITE_BYTE, eph, kemPk), this.myNonce)]);
    this.th = await this.h(this.root, w1);
    this.wire(w1);
  }

  async onMsg1(w1) {
    if (this.peerEph || this.weDialed || w1.length !== M1_LEN) { this.stall(); return; }
    if (w1[0] !== SUITE_CHANNEL_CONCEALED) { this.stall(); return; }
    const ephI = w1.slice(SUITE_LEN, SUITE_LEN + EPH_LEN);
    const kemPkI = w1.slice(SUITE_LEN + EPH_LEN, SUITE_LEN + EPH_LEN + KEM_PK_LEN);
    const probe = await this.openZero(
      await this.probeKey(w1.slice(0, SUITE_LEN), ephI, kemPkI),
      w1.slice(SUITE_LEN + EPH_LEN + KEM_PK_LEN));
    if (!probe.ok) { this.stall(); return; }
    // Proved: move off the contended budget before the expensive work.
    if (this.slot && this.slot.limiter && !this.slot.limiter.promote(this.slot)) { this.stallBusy(); return; }
    this.armDeadline(handshakeTimeoutMs);
    await this.ensureKeys();
    const dh = await scalarmult(this.myEph.privateKey, ephI);
    if (!dh.ok) { this.stall(); return; }
    const kem = await kemEncaps(kemPkI, await randomBytes(32));
    if (!kem.ok) { this.stall(); return; }
    this.ee = dh.x;
    this.kemSecret = kem.sharedSecret;
    this.peerEph = ephI;

    const h1 = await this.h(this.root, w1);
    const w2 = concatBytes([
      this.myEph.publicKey.subarray(0, EPH_LEN),
      kem.ciphertext,
      await this.sealZero(await this.kdf([this.ee, this.kemSecret], h1, LABEL_M2), this.myNonce),
    ]);
    this.th = await this.h(h1, w2);
    this.wire(w2);
  }

  async onMsg2(w2) {
    if (this.authed || this.peerEph || !this.th || w2.length !== M2_LEN) { this.stall(); return; }
    const ephR = w2.slice(0, EPH_LEN);
    const kemCt = w2.slice(EPH_LEN, EPH_LEN + KEM_CT_LEN);
    const dh = await scalarmult(this.myEph.privateKey, ephR);
    if (!dh.ok) { this.stall(); return; }
    const kem = await kemDecaps(this.myKem.privateKey, kemCt);
    if (!kem.ok) { this.stall(); return; }
    const r = await this.openZero(
      await this.kdf([dh.x, kem.sharedSecret], this.th, LABEL_M2),
      w2.slice(EPH_LEN + KEM_CT_LEN));
    if (!r.ok) { this.stall(); return; }
    this.ee = dh.x; this.kemSecret = kem.sharedSecret; this.peerEph = ephR;

    const h2 = await this.h(this.th, w2);
    const si = await this.signIdentity(h2);
    if (!si) return;
    const w3 = await this.sealZero(await this.kdf([this.ee, this.kemSecret], h2, LABEL_M3), concatBytes([si.id, si.sig]));
    this.th = await this.h(h2, w3);
    this.wire(w3);
  }

  async onMsg3(w3) {
    if (this.authed || !this.peerEph || !this.th || !this.ee || w3.length !== M3_LEN) { this.stall(); return; }
    const idI = await this.openIdentity(await this.kdf([this.ee, this.kemSecret], this.th, LABEL_M3), w3, this.th);
    if (!idI) { this.stall(); return; }
    const peerId = toHex(idI);
    // The peer lint runs HERE: after decryption and signature, never on a claimed key,
    // and before msg4 puts our identity on the wire. A refusal is silence, so being
    // turned away is indistinguishable from a msg3 that never arrived (§12.6.2).
    if (!admits(idI)) { this.stall(); return; }
    this.peerPubkey = idI; this.peerId = peerId;

    const h3 = await this.h(this.th, w3);
    const si = await this.signIdentity(h3);
    if (!si) return;
    const w4 = await this.sealZero(await this.kdf([this.ee, this.kemSecret], h3, LABEL_M4), concatBytes([si.id, si.sig]));
    this.th = await this.h(h3, w4);
    try { await this.deriveConcealedSession(); } catch { this.stall(); return; }
    this.wire(w4);
    await this.becomeAuthed();
  }

  async onMsg4(w4) {
    if (this.authed || !this.peerEph || !this.th || !this.ee || w4.length !== M4_LEN) { this.stall(); return; }
    const idR = await this.openIdentity(await this.kdf([this.ee, this.kemSecret], this.th, LABEL_M4), w4, this.th);
    if (!idR) { this.stall(); return; }
    const peerId = toHex(idR);
    // A mismatch here is a local fault, not a probe to hide from — we already revealed
    // ourselves at msg3 — so it aborts rather than stalls.
    if (this.expectPeerId && peerId !== toHex(this.expectPeerId)) { this.abort(); return; }
    // The peer lint, on the end that dialed. Not concealed: we named ourselves at
    // msg3, so an abort here is honest rather than a probe.
    if (!admits(idR)) { this.abort(true); return; }
    this.peerPubkey = idR; this.peerId = peerId;
    this.th = await this.h(this.th, w4);
    try { await this.deriveConcealedSession(); } catch { this.abort(); return; }
    await this.becomeAuthed();
  }

  async deriveConcealedSession() {
    const kI2R = await this.kdf([this.ee, this.kemSecret], this.th, LABEL_I2R);
    const kR2I = await this.kdf([this.ee, this.kemSecret], this.th, LABEL_R2I);
    this.sendKey = this.weDialed ? kI2R : kR2I;
    this.recvKey = this.weDialed ? kR2I : kI2R;
    // Every input that produced the session can now only be used to RE-derive it — the
    // point at which forward secrecy is either real or a claim (clearEphemeral).
    this.clearEphemeral();
  }

  /** Zero and drop the handshake's private material (ephemeral secret, `ee`, nonce).
   *  Called when session keys exist and again at teardown. `myEph` is dropped, not only
   *  zeroed — `ensureKeys` would treat an all-zero secret as already generated. */
  clearEphemeral() {
    if (this.myEph) {
      this.myEph.privateKey.fill(0); // the secret half only — the public one was on the wire
      this.myEph = null;
    }
    if (this.myKem) {
      this.myKem.privateKey.fill(0);
      this.myKem = null;
    }
    if (this.myNonce) { this.myNonce.fill(0); this.myNonce = null; }
    if (this.ee) { this.ee.fill(0); this.ee = null; }
    if (this.kemSecret) { this.kemSecret.fill(0); this.kemSecret = null; }
  }

  // A 12-byte nonce from the implicit (epoch, counter) pair — never transmitted.
  nonce(epoch, ctr) {
    const n = new Uint8Array(NPUB_LEN);
    writeU32BE(n, 0, epoch);
    writeU32BE(n, 8, ctr);
    return n;
  }

  async ratchet(k) {
    const next = await this.h(k, LABEL_REKEY);
    k.fill(0);
    return next;
  }

  async seal(frame) {
    const ct = await aeadEnc(this.sendKey, this.nonce(this.sendEpoch, this.sendCtr), frame);
    if (++this.sendCtr >= this.rekeyAfter) {
      this.sendKey = await this.ratchet(this.sendKey);
      this.sendEpoch++;
      this.sendCtr = 0;
    }
    return ct;
  }

  // Reached only on an authenticated link, where a body that will not open is corruption
  // or injection either way. The one receive path that SPEAKS: concealment is owed to
  // strangers, and this peer proved who it is.
  async onRecord(body) {
    // Framed links were measured on arrival; this is the platform-framed link's floor.
    if (!this.recvKey || body.length < TAG_LEN || body.length > maxFrameBytes) { this.abort(true); return; }
    if (this.recvEpoch >= REJECT_AFTER_EPOCHS) { this.abort(); return; }
    const r = await aeadDec(this.recvKey, this.nonce(this.recvEpoch, this.recvCtr), body);
    if (!r.ok) { this.abort(true); return; }
    this.sawTraffic = true;
    // Advance only on success — a failed decrypt must never move the counter.
    if (++this.recvCtr >= this.rekeyAfter) {
      this.recvKey = await this.ratchet(this.recvKey);
      this.recvEpoch++;
      this.recvCtr = 0;
    }
    // The reserved empty record: an authenticated end-of-stream.
    if (r.pt.length === 0) { this.peerSaidGoodbye = true; this.close(); return; }
    // Not awaited, and nothing to await: a request goes to the host as its own call, and
    // this link's next record must not queue behind whoever answers it.
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
