// Transport bundle guest: the host-call helpers and the link — handshake and record layer (§12.6).

const N_SIGN = "node/sign";
const N_VERIFY = "node/verify";
const N_RANDOM = "crypto/random";
// Bundle modules: a bare name, no `/`, is a module rather than a host name (§12.2).
const N_WS = "ws";
const N_MLKEM = "mlkem";

const N_LINK_OPEN = "link/open";
const N_LINK_SEND = "link/send";
const N_LINK_CLOSE = "link/close";
// Inbound: a request decoded off a link, handed to the host's claim routing.
const N_LINK_DELIVER = "link/deliver";

const N_TIMER_ARM = "timer/arm";

const P_HASH = "crypto/blake2b";
const P_SEAL = "crypto/chacha20poly1305-ietf/seal";
const P_OPEN = "crypto/chacha20poly1305-ietf/open";
const P_DH = "crypto/x25519/dh";

// The X25519 base point: `dh(sk, BASEPOINT)` derives the public key.
const X25519_BASEPOINT = new Uint8Array([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

// Why a link went down, returned from `linkClosed` and printed by the driver
// (`logLinkDown`) when its severity is above 0. Only the end holding the session keys can
// tell these apart. A local fact, never on the wire, so a refused peer still sees only
// silence (§12.6.2).
const REASON_NONE = "", REASON_HANDSHAKE = "handshake", REASON_CLEAN = "clean",
  REASON_ABORTED = "aborted", REASON_LOCAL = "local", REASON_TRUNCATED = "truncated",
  REASON_REFUSED = "refused", REASON_TIMEOUT = "timeout", REASON_DROPPED = "dropped";
/** Reasons a healthy node produces constantly, reported at severity 0; the rest at 1. */
const ROUTINE_REASONS = new Set([REASON_NONE, REASON_CLEAN, REASON_LOCAL]);

// ── channel handshake constants (§12.6) ──────────────────────────────────────

const SUITE_CHANNEL_CONCEALED = 0x03;
const SUITE_LEN = 1, PK_LEN = 32, EPH_LEN = 32, SIG_LEN = 64;
const NPUB_LEN = 12, TAG_LEN = 16;
const KEM_PK_LEN = 1184, KEM_SK_LEN = 2400, KEM_CT_LEN = 1088, KEM_SS_LEN = 32;
// msg1's seal carries nothing: its tag is the contact-secret proof. msg2 carries only the
// receiver's signature, since every dial already holds the key it is checked against.
const M1_LEN = SUITE_LEN + EPH_LEN + KEM_PK_LEN + TAG_LEN; // 1233
const M2_LEN = EPH_LEN + KEM_CT_LEN + SIG_LEN + TAG_LEN;   // 1200
const M3_LEN = PK_LEN + SIG_LEN + TAG_LEN;                 // 112

// The one suite this transport speaks, not negotiated (§12.6, §14.1).
const SUITE_BYTE = new Uint8Array([SUITE_CHANNEL_CONCEALED]);

const ZERO_NPUB = new Uint8Array(NPUB_LEN);

// Directional session-key labels and the ratchet label — distinct, versioned, trailing NUL.
const LABEL_REKEY = utf8Encode("seedkernel-session-rekey-v1\0");
const LABEL_PROBE = utf8Encode("seedkernel-c-probe-v1\0");
const LABEL_M2 = utf8Encode("seedkernel-c-msg2-v1\0");
const LABEL_M3 = utf8Encode("seedkernel-c-msg3-v1\0");
const LABEL_I2R = utf8Encode("seedkernel-session-i->r-v1\0");
const LABEL_R2I = utf8Encode("seedkernel-session-r->i-v1\0");

// The channel format tag: seeds the session root and prefixes every identity-signature
// payload. Transport content, not a host signing domain (§12.6.2b).
const DOMAIN_CHANNEL = utf8Encode("seedkernel-channel-id-v1\0");

// This suite's policy constants; the host never reads them.
const REJECT_AFTER_EPOCHS = 1 << 16; // ratchets per direction before the link retires
const MAX_QUEUE_BYTES = 1024 * 1024; // pre-auth send buffer byte budget (drop-oldest)

// ── the seam helpers ──────────────────────────────────────────────────────────

/** BLAKE2b-256 over the concatenation; `crypto/blake2b` takes `[outLen][keyLen][key][msg]`. */
const HASH_256 = new Uint8Array([32, 0]);
function hash(...parts) {
  return host.call(P_HASH, concatBytes([HASH_256, ...parts]));
}
async function verify(pk, sig, msg) {
  let len = pk.length + sig.length + msg.length;
  const out = new Uint8Array(len);
  out.set(pk, 0); out.set(sig, pk.length); out.set(msg, pk.length + sig.length);
  const r = await host.call(N_VERIFY, out);
  return r[0] === 1;
}
function randomBytes(n) {
  return host.call(N_RANDOM, argU32(n));
}
/** `[npub 12][key 32][adLen u32][ad][msg]`. This suite binds no associated data, so
 *  `adLen` stays zero. */
function aeadArgs(key, npub, msg) {
  const at = npub.length + key.length + 4;
  const out = new Uint8Array(at + msg.length);
  out.set(npub, 0); out.set(key, npub.length); out.set(msg, at);
  return out;
}
function aeadEnc(key, npub, msg) {
  return host.call(P_SEAL, aeadArgs(key, npub, msg));
}
async function aeadDec(key, npub, ct) {
  const r = await host.call(P_OPEN, aeadArgs(key, npub, ct));
  return r[0] === 1 ? { ok: true, pt: r.subarray(1) } : { ok: false, pt: null };
}
async function scalarmult(sk, pk) {
  const out = new Uint8Array(64);
  out.set(sk, 0); out.set(pk, 32);
  const r = await host.call(P_DH, out);
  out.fill(0); // it held a copy of the private scalar
  return r[0] === 1 ? { ok: true, x: r.subarray(1) } : { ok: false, x: null };
}
/** An ephemeral X25519 pair. */
async function boxKeypair() {
  const sk = await randomBytes(32);
  const r = await scalarmult(sk, X25519_BASEPOINT);
  if (!r.ok) throw new Error("transport: ephemeral keygen failed");
  return { publicKey: r.x, privateKey: sk };
}
/** One call into the ML-KEM module: `[op][parts …]` in, `take` reads the answer. The
 *  request, the inputs in `wipe` and the answer are zeroed on every path. */
async function kemCall(op, parts, wipe, take) {
  const req = concatBytes([Uint8Array.of(op), ...parts]);
  let r;
  try {
    r = await host.call(N_MLKEM, req);
  } finally {
    req.fill(0);
    for (const secret of wipe) secret.fill(0);
  }
  try {
    return take(r);
  } finally {
    r.fill(0);
  }
}
/** The width is the status; a wrong one is our own module failing, so it throws. */
function kemKeypair(seed) {
  return kemCall(0, [seed], [seed], (r) => {
    if (r.length !== KEM_PK_LEN + KEM_SK_LEN) throw new Error("transport: ML-KEM keygen failed");
    return { publicKey: r.slice(0, KEM_PK_LEN), privateKey: r.slice(KEM_PK_LEN) };
  });
}
function kemEncaps(pk, coins) {
  return kemCall(1, [pk, coins], [coins], (r) => (
    r.length === 1 + KEM_CT_LEN + KEM_SS_LEN && r[0] === 1
      ? { ok: true, ciphertext: r.slice(1, 1 + KEM_CT_LEN), sharedSecret: r.slice(1 + KEM_CT_LEN) }
      : { ok: false, ciphertext: null, sharedSecret: null }));
}
function kemDecaps(sk, ct) {
  // `sk` is still needed; `clearEphemeral` zeroes it.
  return kemCall(2, [sk, ct], [], (r) => (
    r.length === 1 + KEM_SS_LEN && r[0] === 1
      ? { ok: true, sharedSecret: r.slice(1) }
      : { ok: false, sharedSecret: null }));
}
/** The channel's identity-signature payload; the host prefixes its scope. */
function channelIdentityMessage(root, th, id) {
  return concatBytes([DOMAIN_CHANNEL, root, th, id]);
}
/** Sign with the node's channel key under `DOMAIN_link_scope`. A refusal answers
 *  `{ok:false}` so the caller can abort the link. */
async function channelSign(root, th, id) {
  try {
    return { ok: true, sig: await host.call(N_SIGN, channelIdentityMessage(root, th, id)) };
  } catch {
    return { ok: false, sig: null };
  }
}

// ── calling out: the link ops ─────────────────────────────────────────────────

/** Open a link to an opaque destination string. Link id 0 means no route. The
 *  destination selects the codec (§12.1). */
async function netLinkOpen(dest) {
  const r = await host.call(N_LINK_OPEN, utf8Encode(dest));
  return { linkId: readU32BE(r, 0), stream: r[4] === 1 };
}
/** Answer once the raw-link owner has accepted the bytes. */
function netLinkSend(linkId, bytes) { return host.call(N_LINK_SEND, args([linkId], [], bytes)); }
/** Answers false when the seam refused the call (the host-call budget), so the close is
 *  owed rather than thrown out of a teardown (`Link.closeChannel`). */
function netLinkClose(linkId, graceful) {
  try {
    void host.call(N_LINK_CLOSE, args([linkId], [graceful ? 1 : 0])).catch(() => {});
    return true;
  } catch {
    return false;
  }
}
/** Hand one decoded request to the host's claim routing:
 *  `[claimLen u8][claim][attribution 32][payload]`, answered with the claimant's bytes
 *  (empty for an unreachable claim or a failed handler). Fire it and return: the answer is
 *  another turn of this realm. */
function netLinkDeliver(claim, attribution, payload) {
  return host.call(N_LINK_DELIVER, concatBytes([Uint8Array.of(claim.length), claim, attribution, payload]));
}

/** Peer lint (§12.6), on a verified identity: msg3 when accepting, msg2 when dialing. */
function admits(peerBytes) {
  if (admitPeers === null) return true;
  return admitPeers.has(toHex(peerBytes));
}

// ── the link ─────────────────────────────────────────────────────────────────

/** One host-managed channel, addressed by its host-supplied link id. */
class Link {
  constructor(spec) {
    this.linkId = spec.linkId;
    this.framer = makeFramer(spec.stream, spec.linkId, spec.dest, spec.listener);
    this.weDialed = spec.weDialed;
    // The peer this dial is for (msg2 must verify under it); empty for an accept.
    this.dialedPeerId = spec.dialedPeerId || "";
    this.source = spec.source;               // remoteAddr for the limiter, if any
    this.onAuth = spec.onAuth;
    this.onFrame = spec.onFrame;
    // Called the moment the link closes, before its teardown runs.
    this.onClose = spec.onClose;
    // Dials use the peer's secret; accepts use our live one (§12.6.3).
    this.contactSecret = spec.linkSecret || contactSecret;
    this.root = null; // set by the boot chain below

    this.peerPubkey = null;
    this.peerId = "";
    this.authed = false;
    this.peerSaidGoodbye = false;
    this.myEph = null;
    this.myKem = null;
    this.kemSecret = null;
    this.queue = [];
    this.queueHead = 0;
    this.queuedBytes = 0;
    this.outboundQueuedBytes = 0;
    this.outboundQueuedSlices = 0;
    this.peerEph = null;
    this.closed = false;
    this.stalled = false;
    // How this link ended, for `closeReason`: we closed it, a peer provoked it, a deadline
    // retired it.
    this.closedLocally = false;
    this.aborted = false;
    this.timedOut = false;
    this.slot = null;
    this.due = Infinity;      // when the handshake deadline or the idle window ends
    this.lastSeen = 0;        // when anything last crossed, for the idle window
    this.closeOwed = null;    // a refused close's `graceful`, asked again shortly
    this.sendKey = null;
    this.recvKey = null;
    this.sendEpoch = 0;
    this.sendCtr = 0;
    this.recvEpoch = 0;
    this.recvCtr = 0;
    this.th = null;
    this.ee = null;

    // One work chain per link, so handshake steps never interleave and records keep
    // arrival order (the record layer counts nonces).
    this.work = Promise.resolve();

    // The half-open slot before any key material, so a refusal costs no keypair.
    if (spec.limiter) {
      this.slot = spec.limiter.acquire(this.source, () => this.abort());
      if (!this.slot) {
        this.abort();
        return;
      }
    }

    // Only a dialer speaks unprompted; an accept waits for a msg1 that opens under the
    // contact secret (§12.6.2). A failed boot aborts, and the chain recovers.
    this.work = (async () => {
      this.root = await hash(DOMAIN_CHANNEL, networkKey);
      if (this.weDialed) {
        await this.ensureKeys();
        this.armDeadline(handshakeTimeoutMs);
        await this.sendMsg1();
      } else {
        this.armDeadline(unverifiedTimeoutMs);
      }
    })().catch(() => this.abort());
  }

  /** Run `fn` as the next step of the work chain. The result settles with fn's outcome;
   *  the chain itself swallows it, so a failed step never wedges the rest. */
  enqueue(fn) {
    const done = this.work.then(fn);
    this.work = done.catch(() => {});
    return done;
  }

  /** Hand the socket back to the host. A refused close is retried (`onWake`) until the
   *  host takes it. */
  closeChannel(graceful) {
    this.closeOwed = netLinkClose(this.linkId, graceful) ? null : graceful;
    if (this.closeOwed !== null) this.due = dueIn(CLOSE_RETRY_MS);
  }

  async ensureKeys() {
    if (!this.myEph) this.myEph = await boxKeypair();
    // Only the initiator publishes an encapsulation key.
    if (this.weDialed && !this.myKem) this.myKem = await kemKeypair(await randomBytes(64));
  }

  /** The pre-auth deadline, 0 disabling it; authentication hands it over to `armIdle`. */
  armDeadline(ms) {
    this.due = ms > 0 ? dueIn(ms) : Infinity;
  }

  /** The post-auth idle clock: `linkIdleTimeoutMs` since anything last crossed. Traffic
   *  only moves `lastSeen`; the deadline is re-read on a wake. */
  armIdle() {
    this.lastSeen = now();
    this.due = linkIdleTimeoutMs > 0 ? dueIn(linkIdleTimeoutMs) : Infinity;
  }

  /** One wake (core.js `onWake`): past `due`, a handshake times out, an idle link closes,
   *  and a closed one retries an owed close. Answers the next deadline, or `Infinity`. */
  onWake(t) {
    if (t < this.due) return this.due;
    this.due = Infinity;
    if (this.closed) {
      if (this.closeOwed !== null) this.closeChannel(this.closeOwed);
      return this.due;
    }
    if (!this.authed) {
      this.timedOut = true;
      this.abort();
    } else if (t - this.lastSeen < linkIdleTimeoutMs) {
      this.due = this.lastSeen + linkIdleTimeoutMs;
    } else {
      this.close();
    }
    return this.due;
  }

  /** Traffic in either direction: resets the idle clock and the limiter's eviction order. */
  markTraffic() {
    this.lastSeen = now();
    if (this.slot) this.slot.limiter.touch(this.slot);
  }

  // Queue (pre-auth) or send (post-auth, as an AEAD record) a frame.
  send(frame) {
    if (this.closed) return;
    // A frame that would seal past the cap would tear the link down at the receiver.
    if (frame.length > maxFrameBytes - TAG_LEN) return;
    // An empty record is the authenticated end-of-stream marker, never app data.
    if (frame.length === 0) return;
    if (this.authed) {
      if (this.sendEpoch >= REJECT_AFTER_EPOCHS) { this.close(); return; }
      if (this.outboundQueuedSlices >= maxOutboundQueueSlices
          || frame.length > maxOutboundQueueBytes - this.outboundQueuedBytes) {
        // Dropping one record would desynchronise the stream, so fail the link.
        this.abort();
        return;
      }
      this.markTraffic();
      this.outboundQueuedSlices++;
      this.outboundQueuedBytes += frame.length;
      void this.enqueue(async () => {
        try {
          if (this.closed) return;
          await this.wireRecord(frame);
        } finally {
          this.outboundQueuedSlices--;
          this.outboundQueuedBytes -= frame.length;
        }
      });
      return;
    }
    this.queue.push(frame);
    this.queuedBytes += frame.length;
    // Drop-oldest through a head index: `shift()` would go quadratic under a flood.
    let live = this.queue.length - this.queueHead;
    while ((this.queuedBytes > MAX_QUEUE_BYTES || live > maxPreAuthQueueSlices) && live > 1) {
      this.queuedBytes -= this.queue[this.queueHead].length;
      this.queue[this.queueHead++] = null;
      live--;
    }
    // Compact once the consumed prefix outnumbers what is queued.
    if (this.queueHead >= 8 && this.queueHead * 2 >= this.queue.length) {
      this.queue = this.queue.slice(this.queueHead);
      this.queueHead = 0;
    }
  }

  /** Hand over the frames still waiting for authentication, oldest first. */
  takeQueued() {
    const frames = this.queue.slice(this.queueHead);
    this.queue = [];
    this.queueHead = 0;
    this.queuedBytes = 0;
    return frames;
  }

  /** Our own end of the link: it leaves routing at once and tears down behind the work
   *  chain, so an in-flight step keeps its keys. `farewell` sends the end-of-stream record
   *  first; `defensive` records that a peer provoked it. */
  end(farewell, defensive) {
    if (this.closed) return;
    this.closed = true;
    this.closedLocally = true;
    if (defensive) this.aborted = true;
    this.severWire();
    void this.enqueue(async () => {
      let saidGoodbye = false;
      if (farewell && this.authed && !this.peerSaidGoodbye && this.sendEpoch <= REJECT_AFTER_EPOCHS && this.sendKey) {
        try {
          await this.wire(await this.seal(new Uint8Array(0)));
          // A codec with its own end-of-stream signal sends it too.
          if (this.framer && this.framer.goodbye) await this.framer.goodbye();
          saidGoodbye = true;
        } catch { /* the channel is already gone */ }
      }
      this.teardown();
      // Graceful only after a goodbye, so the close flushes it.
      this.closeChannel(saidGoodbye);
    });
    this.onClose(this);
  }

  /** Our own deliberate shutdown, and the only path that says goodbye. */
  close() { this.end(true, false); }

  /** Every failure path: no goodbye, so a goodbye always means the peer chose to stop. */
  abort(defensive) { this.end(false, defensive); }

  /** Why this link ended, as a REASON_* word.
   *
   *  Before authentication: `dropped` is the socket dying on its own (refused, unreachable,
   *  hung up); `refused` is a teardown the peer provoked (bad probe, malformed frame, bad
   *  signature, lint); `timeout` is our deadline on a silent socket; `handshake` is the
   *  rest, ours (eviction, a local crypto failure).
   *
   *  After: `clean` is the peer's end-of-stream record; `aborted` a teardown the peer
   *  provoked; `local` our own shutdown; `truncated` a stream that just stopped. */
  get closeReason() {
    if (!this.closed) return REASON_NONE;
    if (!this.authed) {
      if (this.aborted) return REASON_REFUSED;
      if (this.timedOut) return REASON_TIMEOUT;
      if (!this.closedLocally) return REASON_DROPPED;
      return REASON_HANDSHAKE;
    }
    if (this.peerSaidGoodbye) return REASON_CLEAN;
    if (this.aborted) return REASON_ABORTED;
    if (this.closedLocally) return REASON_LOCAL;
    return REASON_TRUNCATED;
  }

  // ── handshake ───────────────────────────────────────────────────────────────

  /** Put one link message on the wire, framed if the platform does not frame it. */
  wire(msg) {
    return this.framer ? this.framer.send(msg) : netLinkSend(this.linkId, msg);
  }

  /** Seal one record and put it on the wire, failing the link if it does not land (§12.6). */
  async wireRecord(frame) {
    try {
      await this.wire(await this.seal(frame));
    } catch {
      this.abort();
    }
  }

  /** Inbound bytes, decoded on the work chain. Answers once this read is decoded, not
   *  once any request it carried is answered. */
  onWire(bytes) {
    // A stall is terminal: later reads are dropped unparsed.
    if (this.closed || this.stalled) return Promise.resolve();
    if (!this.framer) {
      // Platform-framed links get the same two-stage cap.
      if (bytes.length > (this.authed ? maxFrameBytes : MAX_HANDSHAKE_FRAME_BYTES)) { this.refuse(); return Promise.resolve(); }
      return this.enqueue(() => this.onMessage(bytes));
    }
    // Steps settle in order and never reject, so the read is done when the last one is.
    let last;
    const deliver = (m) => (last = this.enqueue(() => this.onMessage(m)));
    try {
      const ok = this.framer.push(bytes, deliver);
      return Promise.resolve(ok).then(
        (good) => {
          if (!good) { this.refuse(); return; }
          return last;
        },
        () => { this.refuse(); },
      );
    } catch {
      this.refuse();
      return Promise.resolve();
    }
  }

  /** Route one whole link message. It carries no type: our role and progress select the
   *  handler, which checks the exact width (§12.6). */
  onMessage(m) {
    // Frames queued behind a refusal are dropped here.
    if (this.closed || this.stalled) return Promise.resolve();
    const step = this.authed
      ? this.onRecord(m)
      : this.weDialed
        ? this.onMsg2(m)
        : (this.peerEph ? this.onMsg3(m) : this.onMsg1(m));
    return Promise.resolve(step).catch(() => { this.refuse(); });
  }

  /** The peer sent something we will not take: an abort once authenticated, a stall before
   *  (framing errors included), so a stranger learns nothing (CHANNEL §5). */
  refuse() {
    if (this.authed) this.abort(true);
    else this.stall();
  }

  /** Refuse without saying so: every refusal looks like silence (§12.6.2). Terminal. The
   *  deadline and slot stay live, so silence still costs the sender a slot. */
  stall() {
    if (this.stalled) return;
    this.stalled = true;
    this.aborted = true; // for `closeReason`: a refusal, not a quiet peer
    if (this.framer) this.framer.discard();
    this.clearEphemeral();
  }

  async becomeAuthed() {
    // A link that closed mid-step left routing and must not re-enter it.
    if (this.closed) return;
    this.authed = true;
    // The slot moves to the authed tier and is held until the link dies.
    if (this.slot && !this.slot.limiter.hold(this.slot)) { this.abort(); return; }
    this.armIdle();
    if (this.framer) this.framer.raiseCap();
    this.onAuth(this.peerId, this);
    // The tie-break may have closed us, handing the queue to the winner.
    if (this.closed) return;
    for (const frame of this.takeQueued()) await this.wireRecord(frame);
  }

  // ── the concealed-identity handshake (suite 0x03, §12.6.2) ──────────────────

  /** Every handshake key comes through here, so every one mixes in the contact secret. */
  kdf(ikm, ctx, label) {
    const parts = [];
    for (const p of ikm) parts.push(p);
    parts.push(this.contactSecret, ctx, label);
    return hash(...parts);
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
    return this.kdf([], await hash(this.root, suiteByte, ephI, kemPkI), LABEL_PROBE);
  }

  async signIdentity(th) {
    const r = await channelSign(this.root, th, ownPk);
    // Our own misconfiguration, so abort rather than stall.
    if (!r.ok) { this.abort(); return null; }
    return { id: ownPk, sig: r.sig };
  }

  async openIdentity(key, ct, th) {
    const r = await this.openZero(key, ct);
    if (!r.ok) return null;
    const plain = r.pt;
    const id = plain.slice(0, PK_LEN);
    const sig = plain.slice(PK_LEN, PK_LEN + SIG_LEN);
    if (!(await verify(id, sig, channelIdentityMessage(this.root, th, id)))) return null;
    if (bytesCompare(id, ownPk) === 0) return null; // our own traffic reflected
    return id;
  }

  async sendMsg1() {
    const eph = this.myEph.publicKey.subarray(0, EPH_LEN);
    const kemPk = this.myKem.publicKey;
    const w1 = concatBytes([SUITE_BYTE, eph, kemPk,
      await this.sealZero(await this.probeKey(SUITE_BYTE, eph, kemPk), new Uint8Array(0))]);
    this.th = await hash(this.root, w1);
    await this.wire(w1);
  }

  async onMsg1(w1) {
    if (w1.length !== M1_LEN || w1[0] !== SUITE_CHANNEL_CONCEALED) { this.stall(); return; }
    const ephI = w1.slice(SUITE_LEN, SUITE_LEN + EPH_LEN);
    const kemPkI = w1.slice(SUITE_LEN + EPH_LEN, SUITE_LEN + EPH_LEN + KEM_PK_LEN);
    const probe = await this.openZero(
      await this.probeKey(w1.slice(0, SUITE_LEN), ephI, kemPkI),
      w1.slice(SUITE_LEN + EPH_LEN + KEM_PK_LEN));
    if (!probe.ok) { this.stall(); return; }
    // A msg1 replays, so each is accepted once, before any expensive work (§12.6.2).
    if (probeSeen(ephI)) { this.stall(); return; }
    // Proved: move off the contended budget before the expensive work.
    if (this.slot && !this.slot.limiter.promote(this.slot)) { this.stall(); return; }
    rememberProbe(ephI);
    this.armDeadline(handshakeTimeoutMs);
    await this.ensureKeys();
    const dh = await scalarmult(this.myEph.privateKey, ephI);
    if (!dh.ok) { this.stall(); return; }
    const kem = await kemEncaps(kemPkI, await randomBytes(32));
    if (!kem.ok) { this.stall(); return; }
    this.ee = dh.x;
    this.kemSecret = kem.sharedSecret;
    this.peerEph = ephI;

    // The receiver signs the transcript without naming itself: the dialer already holds
    // its key.
    const h1 = await hash(this.root, w1);
    const head = concatBytes([this.myEph.publicKey.subarray(0, EPH_LEN), kem.ciphertext]);
    const hs = await hash(h1, head);
    const si = await this.signIdentity(hs);
    if (!si) return;
    const w2 = concatBytes([head,
      await this.sealZero(await this.kdf([this.ee, this.kemSecret], hs, LABEL_M2), si.sig)]);
    this.th = await hash(h1, w2);
    await this.wire(w2);
  }

  async onMsg2(w2) {
    if (w2.length !== M2_LEN) { this.stall(); return; }
    const head = w2.slice(0, EPH_LEN + KEM_CT_LEN);
    const ephR = head.slice(0, EPH_LEN);
    const kemCt = head.slice(EPH_LEN);
    const dh = await scalarmult(this.myEph.privateKey, ephR);
    if (!dh.ok) { this.stall(); return; }
    const kem = await kemDecaps(this.myKem.privateKey, kemCt);
    if (!kem.ok) { this.stall(); return; }
    const hs = await hash(this.th, head);
    const r = await this.openZero(
      await this.kdf([dh.x, kem.sharedSecret], hs, LABEL_M2),
      w2.slice(EPH_LEN + KEM_CT_LEN));
    if (!r.ok) { this.stall(); return; }
    this.ee = dh.x; this.kemSecret = kem.sharedSecret;
    // The receiver must prove the dialed key. Nothing of ours is on the wire yet, so a
    // failure closes rather than stalls.
    const idR = fromHex(this.dialedPeerId);
    if (bytesCompare(idR, ownPk) === 0) { this.abort(); return; }
    if (!(await verify(idR, r.pt, channelIdentityMessage(this.root, hs, idR)))) { this.abort(true); return; }
    if (!admits(idR)) { this.abort(true); return; }
    this.peerPubkey = idR; this.peerId = this.dialedPeerId;

    const h2 = await hash(this.th, w2);
    const si = await this.signIdentity(h2);
    if (!si) return;
    const w3 = await this.sealZero(await this.kdf([this.ee, this.kemSecret], h2, LABEL_M3), concatBytes([si.id, si.sig]));
    this.th = await hash(h2, w3);
    try { await this.deriveConcealedSession(); } catch { this.abort(); return; }
    await this.wire(w3);
    // Records follow msg3 at once: data leaves one round trip after msg1.
    await this.becomeAuthed();
  }

  async onMsg3(w3) {
    if (w3.length !== M3_LEN) { this.stall(); return; }
    const idI = await this.openIdentity(await this.kdf([this.ee, this.kemSecret], this.th, LABEL_M3), w3, this.th);
    if (!idI) { this.stall(); return; }
    // The lint, on a verified key. It closes rather than stalls: the dialer already
    // verified us at msg2 (§12.6.2).
    if (!admits(idI)) { this.abort(true); return; }
    this.peerPubkey = idI; this.peerId = toHex(idI);
    this.th = await hash(this.th, w3);
    try { await this.deriveConcealedSession(); } catch { this.stall(); return; }
    await this.becomeAuthed();
  }

  async deriveConcealedSession() {
    const kI2R = await this.kdf([this.ee, this.kemSecret], this.th, LABEL_I2R);
    const kR2I = await this.kdf([this.ee, this.kemSecret], this.th, LABEL_R2I);
    this.sendKey = this.weDialed ? kI2R : kR2I;
    this.recvKey = this.weDialed ? kR2I : kI2R;
    this.clearEphemeral(); // forward secrecy
  }

  /** Zero and drop the handshake's private material. Dropped, not only zeroed, so
   *  `ensureKeys` never reuses a zeroed secret. */
  clearEphemeral() {
    if (this.myEph) {
      this.myEph.privateKey.fill(0);
      this.myEph = null;
    }
    if (this.myKem) {
      this.myKem.privateKey.fill(0);
      this.myKem = null;
    }
    if (this.ee) { this.ee.fill(0); this.ee = null; }
    if (this.kemSecret) { this.kemSecret.fill(0); this.kemSecret = null; }
  }

  /** A 12-byte nonce from the implicit (epoch, counter) pair, never transmitted. */
  nonce(epoch, ctr) {
    const n = new Uint8Array(NPUB_LEN);
    writeU32BE(n, 0, epoch);
    writeU32BE(n, 8, ctr);
    return n;
  }

  async ratchet(k) {
    const next = await hash(k, LABEL_REKEY);
    k.fill(0);
    return next;
  }

  async seal(frame) {
    const ct = await aeadEnc(this.sendKey, this.nonce(this.sendEpoch, this.sendCtr), frame);
    if (++this.sendCtr >= rekeyAfterFrames) {
      this.sendKey = await this.ratchet(this.sendKey);
      this.sendEpoch++;
      this.sendCtr = 0;
    }
    return ct;
  }

  /** An authenticated record. Unlike the handshake it aborts on anything wrong:
   *  concealment is owed to strangers, not to a proven peer. */
  async onRecord(body) {
    if (!this.recvKey || body.length < TAG_LEN || body.length > maxFrameBytes) { this.abort(true); return; }
    if (this.recvEpoch >= REJECT_AFTER_EPOCHS) { this.abort(); return; }
    const r = await aeadDec(this.recvKey, this.nonce(this.recvEpoch, this.recvCtr), body);
    if (!r.ok) { this.abort(true); return; }
    this.markTraffic();
    // Advance only on success.
    if (++this.recvCtr >= rekeyAfterFrames) {
      this.recvKey = await this.ratchet(this.recvKey);
      this.recvEpoch++;
      this.recvCtr = 0;
    }
    // The reserved empty record: an authenticated end-of-stream.
    if (r.pt.length === 0) { this.peerSaidGoodbye = true; this.close(); return; }
    // Not awaited, so the next record never waits on an answer. Both forms of the peer's
    // id travel: hex for routing, bytes for attribution.
    this.onFrame(this.peerId, r.pt, this.peerPubkey);
  }

  /** The socket went away. */
  onChannelClosed() {
    if (this.closed) return;
    this.closed = true;
    this.teardown();
    this.onClose(this);
  }

  // ── teardown ────────────────────────────────────────────────────────────────

  /** End the wire now, off the work chain: a step parked on the wire would otherwise hold
   *  the chain against its own teardown (§12.6). Idempotent. */
  severWire() {
    try { if (this.framer && this.framer.abort) this.framer.abort(); }
    catch { /* already gone */ }
  }

  teardown() {
    this.severWire();
    this.due = Infinity;
    this.releaseSlot();
    // The pre-auth queue stays, for `forget` (core.js) to hand on.
    if (this.sendKey) this.sendKey.fill(0);
    if (this.recvKey) this.recvKey.fill(0);
    this.sendKey = null;
    this.recvKey = null;
    this.clearEphemeral();
  }

  releaseSlot() {
    if (!this.slot) return;
    const slot = this.slot;
    this.slot = null;
    slot.limiter.release(slot);
  }
}
