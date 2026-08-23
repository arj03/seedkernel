// Transport bundle guest: AKE, record layer, link router, request/response (§12.6).

const N_SIGN = "node/sign";
const N_VERIFY = "node/verify";
const N_RANDOM = "node/random";
/** This bundle's own RFC 6455 codec, by the logical name its manifest declares. A bare
 *  name — no `/` — is what makes it a module rather than a host name (§12.2). */
const N_WS = "ws";

const N_LINK_OPEN = "link/open";
const N_LINK_SEND = "link/send";
const N_LINK_CLOSE = "link/close";
// A READ of a link's unsent backlog — the only way this program can tell a slow
// exchange from a stalled one, since everything else it sees is its own bookkeeping.
const N_LINK_STAT = "link/stat";
const N_LINK_AUTHENTICATED = "link/authenticated";
const N_LINK_DOWN = "link/down";

const N_TIMER_ARM = "timer/arm";
const N_TIMER_CLEAR = "timer/clear";

const P_HASH = "crypto/blake2b-256";
const P_SEAL = "crypto/chacha20poly1305-ietf/seal";
const P_OPEN = "crypto/chacha20poly1305-ietf/open";
const P_DH = "crypto/x25519/dh";

// The X25519 base point: `dh(sk, BASEPOINT)` IS the public-key derivation, so the
// catalog needs no keygen entry while the secret comes from node/random.
const X25519_BASEPOINT = new Uint8Array([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

// Link kinds as the host's `linkOpen` declares them: 0 = an accepted socket (half-open
// limiter applies), 1 = a host-managed transport that opened the socket itself.
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
  // The buffer held a COPY of the private scalar; zero it, or the call leaves a second
  // copy on the heap for a memory-image attacker to find.
  out.fill(0);
  return r[0] === 1 ? { ok: true, x: r.subarray(1) } : { ok: false, x: null };
}
/** An ephemeral X25519 pair: entropy from the host, the public half through the DH
 *  primitive against the base point. */
function boxKeypair() {
  const sk = randomBytes(32);
  const r = scalarmult(sk, X25519_BASEPOINT);
  if (!r.ok) throw new Error("transport: ephemeral keygen failed");
  return { publicKey: r.x, privateKey: sk };
}
/** The channel's tagged identity-signature format — the host's slot scope, prefixed by
 *  the HOST, wraps this whole value as an opaque suffix. */
function channelIdentityMessage(root, th, id) {
  return concatBytes([DOMAIN_CHANNEL, root, th, id]);
}
/** Ask the host to sign under `DOMAIN_link_scope ‖ networkKey` with the node's channel
 *  key, which never enters this program. `node/sign` THROWS when the authority is not
 *  reached, so the `{ok}` shape is a real status: catching here lets the caller abort the
 *  link rather than unwind out of a frame-delivery callback. */
function channelSign(root, th, id) {
  try {
    return { ok: true, sig: host.call(N_SIGN, channelIdentityMessage(root, th, id)) };
  } catch {
    return { ok: false, sig: null };
  }
}

// ── calling out: the ops, each one argument-encoded and issued immediately ────
//
// No action buffer and no batch — accumulating orders would be a second host↔module ABI.
// The arrangement rests on the host's rule that no op re-enters this realm, so nothing
// below can call back into a frame still on the stack. Hence no `await`: an inbound
// request is dispatched with `.then`, and an app's send is answered with `defer()`.

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

/** A link the HOST handed us (openLink) changed state — relayed so whoever passed the
 *  channel in learns its fate. A core link's fate is ours alone. */
function hostLinkAuth(linkId, peerBytes) { host.call(N_LINK_AUTHENTICATED, args([linkId], [], peerBytes)); }
function hostLinkDown(linkId, reason) { host.call(N_LINK_DOWN, args([linkId], [reason])); }

/** One linkBytes invocation's delivery return: `[count u32]` then that many records
 *  from the request/response layer (`ReqRes.onFrame`), each one
 *  `[noReply u8][corr u32][claimLen u8][claim][attrLen u32][attribution][payloadLen u32][payload]`,
 *  or null when this frame decoded to nothing deliverable — a host reads any non-empty
 *  return as a frame, so the empty case is a real signal. Several records is the
 *  ordinary case, which is why every field is length-prefixed. */
function packDeliveries(records) {
  if (!records || records.length === 0) return null;
  const head = new Uint8Array(4);
  writeU32BE(head, 0, records.length);
  return concatBytes([head, ...records]);
}

/** Peer lint (§12.6): asked at msg3 when accepting, msg4 when dialing — before this
 *  end has revealed anything. A lint, not a gate: a hostile occupant still reaches
 *  only `link/*`. */
function admits(peerBytes) {
  if (admitPeers === null) return true;
  return admitPeers.has(toHex(peerBytes));
}

// ── timers ────────────────────────────────────────────────────────────────────

// `timer/arm` is the host's table and the host's cap (DEFAULT_MAX_LIVE_TIMERS), so a
// realm that has spent it gets a THROW here. The entry is dropped before the throw
// escapes so a retrying caller does not accumulate callbacks for an unarmed deadline.
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

// One host-managed channel, addressed by the host-supplied link id. All session state
// lives in this heap, keyed by that id.

class Link {
  constructor(spec) {
    this.linkId = spec.linkId;
    // PLATFORM means the transport under us already has message boundaries (a browser
    // WebSocket, an RTCDataChannel); anything else is a byte duplex we frame ourselves.
    this.framer = makeFramer(spec.framing, spec.linkId, spec.weDialed, spec.authority);
    this.weDialed = spec.weDialed;
    this.expectPeerId = spec.expectPeerId;   // 32B or null
    this.source = spec.source;               // remoteAddr for the limiter, if any
    this.onAuth = spec.onAuth;
    this.onFrame = spec.onFrame;
    this.onClose = spec.onClose;
    this.handshakeTimeoutMs = spec.handshakeTimeoutMs;
    this.rekeyAfter = spec.rekeyAfterFrames || REKEY_AFTER_FRAMES;
    // The secret this link opens under: THE PEER's on a dial, OURS on an accept — carried
    // per link at open, so the gate tracks the node's secret (§12.6.3).
    this.contactSecret = spec.linkSecret || contactSecret;
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
    this.sawTraffic = false;  // whether anything crossed since it last ticked
    this.sendKey = null;
    this.recvKey = null;
    this.sendEpoch = 0;
    this.sendCtr = 0;
    this.recvEpoch = 0;
    this.recvCtr = 0;
    this.th = null;
    this.ee = null;

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
    // Everything from here on can THROW (`timer/arm`'s cap is a co-resident app's to
    // spend), so a throw escaping the constructor would leak the slot and the host
    // channel. Hence the same deferred teardown the refused slot takes.
    try {
      if (this.weDialed) {
        this.ensureKeys();
        this.armDeadline(this.handshakeTimeoutMs || HANDSHAKE_TIMEOUT_MS);
        this.sendMsg1();
      } else {
        this.armDeadline(this.handshakeTimeoutMs || UNVERIFIED_TIMEOUT_MS);
      }
    } catch {
      // The slot first and on its own: it is the resource with a hard cap, and releasing
      // it touches nothing outside this module; a failure to tidy must not cost the slot.
      this.releaseSlot();
      try { this.teardown(); } catch { /* the host has evidently lost the timer anyway */ }
      this.deferTeardown();
    }
  }

  /** Close the host channel and notify, but AFTER the current event: the caller's
   *  bookkeeping (core.openLink's pools, entry "openLink"'s `openLinks`) runs once the
   *  constructor returns. */
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
        // stream after our record, so the peer reads one clean shutdown.
        if (this.framer && this.framer.goodbye) this.framer.goodbye();
        saidGoodbye = true;
      } catch { /* the channel is already gone */ }
    }
    this.teardown();
    // The goodbye record is QUEUED, not yet on the wire; only closing once the framer's
    // last write has landed lets the peer read a clean shutdown, not a truncation.
    const flushed = (this.framer && this.framer.flush ? this.framer.flush() : Promise.resolve()).catch(() => {});
    void flushed.then(() => {
      try { netLinkClose(this.linkId, saidGoodbye); } catch { /* already gone */ }
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

  /** Inbound bytes. Over-cap is a defensive abort. Framed push is async; delivery
   *  order rides the framer's one-chunk-at-a-time read chain. Returns the delivery
   *  frame this input produced — the count-prefixed record list, or null when none. */
  onWire(bytes) {
    if (!this.framer) {
      // A platform-framed link (browser WebSocket, RTCDataChannel) arrives with message
      // boundaries already on it — but the two-stage cap is about how much a peer may
      // make us HOLD, not about who framed it. Without this, one huge message takes the
      // realm down.
      if (bytes.length > (this.authed ? maxFrameBytes : maxHandshakeFrameBytes)) { this.abort(true); return null; }
      const d = this.onMessage(bytes);
      return d ? packDeliveries([d]) : null;
    }
    const out = [];
    const deliver = (m) => { const d = this.onMessage(m); if (d) out.push(d); };
    try {
      const ok = this.framer.push(bytes, deliver);
      // The promise must ALWAYS yield bytes (never null): the empty case is "nothing
      // deliverable", and the host reads any non-empty return as a frame.
      return Promise.resolve(ok).then(
        (good) => { if (!good) this.abort(true); return packDeliveries(out) ?? new Uint8Array(0); },
        () => { this.abort(true); return new Uint8Array(0); },
      );
    } catch {
      this.abort(true);
      return new Uint8Array(0);
    }
  }

  /** Route one whole link message. A message is a bare body — the sender chooses
   *  nothing: which one it is follows from our role and how far the exchange got, each
   *  handler checks its exact width, and a post-auth body goes to the AEAD, which fails
   *  closed (see §12.6). Returns the delivery frame a request produced, or null for
   *  everything the handshake itself answers. */
  onMessage(m) {
    if (this.closed) return null;
    if (this.authed) return this.onRecord(m);
    if (this.weDialed) { this.peerEph ? this.onMsg4(m) : this.onMsg2(m); }
    else { this.peerEph ? this.onMsg3(m) : this.onMsg1(m); }
    return null;
  }

  // Refuse WITHOUT saying so — every refusal funnels here, so they are
  // indistinguishable from each other and from silence (§12.6.2).
  stall() { /* deliberately nothing */ }

  becomeAuthed() {
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
    for (const f of this.queue) this.wire(this.seal(f));
    this.queue.length = 0;
    this.queuedBytes = 0;
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
    // it and prefixes this slot's network scope — which is why the network binding
    // survives a transport that lies about its own root.
    const r = channelSign(this.root, th, ownPk);
    // The seam refused: our own misconfiguration, never the peer's doing, so it aborts —
    // a stall would claim this address went quiet, which is a different fact.
    if (!r.ok) { this.abort(); return null; }
    return { id: ownPk, sig: r.sig };
  }

  openIdentity(key, ct, th) {
    const r = this.openZero(key, ct);
    if (!r.ok) return null;
    const plain = r.pt;
    const id = plain.slice(0, PK_LEN);
    const sig = plain.slice(PK_LEN, PK_LEN + SIG_LEN);
    // node/verify applies the same host-owned scope this node signs under, so the
    // preimage the two ends must agree on is the host's for its prefix half. The channel
    // format tag is ours, so the two ends reconstruct that half here.
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
    // turned away is indistinguishable from a msg3 that never arrived (§12.6.2).
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
    // A mismatch here is a local fault, not a probe to hide from — we already revealed
    // ourselves at msg3 — so it aborts rather than stalls.
    if (this.expectPeerId && peerId !== toHex(this.expectPeerId)) { this.abort(); return; }
    // The peer lint, on the end that dialed. Not concealed: we named ourselves at
    // msg3, so an abort here is honest rather than a probe.
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
    // Framed links were measured on arrival; this is the platform-framed link's floor.
    if (!this.recvKey || body.length < TAG_LEN || body.length > maxFrameBytes) { this.abort(true); return null; }
    if (this.recvEpoch >= REJECT_AFTER_EPOCHS) { this.abort(); return null; }
    const r = aeadDec(this.recvKey, this.nonce(this.recvEpoch, this.recvCtr), body);
    if (!r.ok) { this.abort(true); return null; }
    this.sawTraffic = true;
    // Advance only on success — a failed decrypt must never move the counter.
    if (++this.recvCtr >= this.rekeyAfter) {
      this.recvKey = this.ratchet(this.recvKey);
      this.recvEpoch++;
      this.recvCtr = 0;
    }
    // The reserved empty record: an authenticated end-of-stream.
    if (r.pt.length === 0) { this.peerSaidGoodbye = true; this.close(); return null; }
    return this.onFrame(this.peerId, r.pt);
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
