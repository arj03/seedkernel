// Transport bundle guest: the host-call helpers and the link, with its handshake and
// record layer (§12.6).

const N_SIGN = "node/sign";
const N_VERIFY = "node/verify";
const N_RANDOM = "crypto/random";
// Bundle modules: a bare name without `/` is a module, not a host name (§12.2).
const N_WS = "ws";
const N_MLKEM = "mlkem";

const N_LINK_OPEN = "link/open";
const N_LINK_SEND = "link/send";
const N_LINK_CLOSE = "link/close";
// Inbound: a request decoded from a link, handed to the host's claim routing.
const N_LINK_DELIVER = "link/deliver";
// The home relay's state and who is linked, told to the host when either changes.
const N_LINK_STATUS = "link/status";

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
// tell these apart. Local only, never sent, so a refused peer still sees only silence
// (§12.6).
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

// Directional session-key labels and the ratchet label: distinct, versioned, trailing NUL.
const LABEL_REKEY = utf8Encode("seedkernel-session-rekey-v1\0");
const LABEL_PROBE = utf8Encode("seedkernel-c-probe-v1\0");
const LABEL_M2 = utf8Encode("seedkernel-c-msg2-v1\0");
const LABEL_M3 = utf8Encode("seedkernel-c-msg3-v1\0");
const LABEL_I2R = utf8Encode("seedkernel-session-i->r-v1\0");
const LABEL_R2I = utf8Encode("seedkernel-session-r->i-v1\0");
const LABEL_HS_I2R = utf8Encode("seedkernel-channel-handshake-i->r-v1\0");
const LABEL_HS_R2I = utf8Encode("seedkernel-channel-handshake-r->i-v1\0");

// The channel format tag: seeds the session root and prefixes every identity-signature
// payload. Transport content, not a host signing domain (§12.6.2b).
const DOMAIN_CHANNEL = utf8Encode("seedkernel-channel-id-v1\0");

// This suite's policy constants; the host never reads them.
const REJECT_AFTER_EPOCHS = 1 << 16; // ratchets per direction before the link retires
const MAX_QUEUE_BYTES = 1024 * 1024; // pre-auth send buffer byte budget (drop-oldest)

// ── the seam helpers ──────────────────────────────────────────────────────────
//
// A call's arguments go to `host.call` as their parts, which the realm lays back to back,
// so none of these concatenates them.

/** BLAKE2b-256 over the concatenation; `crypto/blake2b` takes `[outLen][keyLen][key][msg]`. */
const HASH_256 = new Uint8Array([32, 0]);
function hash(...parts) {
  return host.call(P_HASH, [HASH_256, ...parts]);
}
async function verify(pk, sig, msg) {
  const r = await host.call(N_VERIFY, [pk, sig, msg]);
  return r[0] === 1;
}
function randomBytes(n) {
  return host.call(N_RANDOM, argU32(n));
}
/** An AEAD call's `[npub 12][key 32][adLen u32]`, ahead of its message: the nonce from the
 *  implicit (epoch, counter) pair, never transmitted. This suite binds no associated data,
 *  so `adLen` stays zero. */
function aeadHead(key, epoch, ctr) {
  const head = new Uint8Array(NPUB_LEN + 32 + 4);
  writeU32BE(head, 0, epoch);
  writeU32BE(head, 8, ctr);
  head.set(key, NPUB_LEN);
  return head;
}
function aeadEnc(key, epoch, ctr, msg) {
  return host.call(P_SEAL, [aeadHead(key, epoch, ctr), msg]);
}
/** `[1][plaintext]`, or `[0]` when `ct` does not open. */
function aeadDec(key, epoch, ctr, ct) {
  return host.call(P_OPEN, [aeadHead(key, epoch, ctr), ct]);
}
async function scalarmult(sk, pk) {
  const r = await host.call(P_DH, [sk, pk]);
  return r[0] === 1 ? { ok: true, x: r.subarray(1) } : { ok: false, x: null };
}
/** An ephemeral X25519 pair. */
async function boxKeypair() {
  const sk = await randomBytes(32);
  const r = await scalarmult(sk, X25519_BASEPOINT);
  if (!r.ok) throw new Error("transport: ephemeral keygen failed");
  return { publicKey: r.x, privateKey: sk };
}
/** One call into the ML-KEM module: `[op][parts ...]` in, `take` reads the answer. The
 *  inputs in `wipe` and the answer are zeroed on every path. */
async function kemCall(op, parts, wipe, take) {
  let r;
  try {
    r = await host.call(N_MLKEM, [Uint8Array.of(op), ...parts]);
  } finally {
    for (const secret of wipe) secret.fill(0);
  }
  try {
    return take(r);
  } finally {
    r.fill(0);
  }
}
/** The answer's width is the status; a wrong width means this bundle's own module
 *  failed, so it throws. */
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
/** The root every handshake starts from: the channel tag hashed over a network key, this
 *  node's or, for a relay link (relay.js), the public network's. Each is hashed once and
 *  every link shares the answer; per link, any stranger who opened a socket bought a host
 *  call. Asked for on the first link, since a host call at load is refused, and asked
 *  again after a failure. */
const channelRoots = new Map();
function rootKey(key) {
  const id = toHex(key);
  let root = channelRoots.get(id);
  if (!root) {
    root = hash(DOMAIN_CHANNEL, key);
    channelRoots.set(id, root);
    root.catch(() => { channelRoots.delete(id); });
  }
  return root;
}
/** A node's own contact secret, when it is given none (§12.6.3): a hash of its signature
 *  over DOMAIN_CONTACT. Ed25519 signs deterministically, so it lasts as long as the key and
 *  needs nothing stored, and only the key's holder can compute it. The tag cannot begin a
 *  channel identity message, so the signature stands for nothing a link carries, and it
 *  never leaves this realm. Asked for on first use, since a host call at load is refused,
 *  and asked again after a failure. */
const DOMAIN_CONTACT = utf8Encode("seedkernel-contact-secret-v1\0");
let ownKeySecret = null;
function keySecret() {
  if (ownKeySecret === null) {
    ownKeySecret = host.call(N_SIGN, DOMAIN_CONTACT).then((sig) => hash(DOMAIN_CONTACT, sig));
    ownKeySecret.catch(() => { ownKeySecret = null; });
  }
  return ownKeySecret;
}
/** The channel's identity-signature payload; the host prefixes its scope. */
function channelIdentityMessage(root, th, id) {
  return concatBytes([DOMAIN_CHANNEL, root, th, id]);
}

// ── calling out: the link ops ─────────────────────────────────────────────────

/** Open a link to an opaque destination string. Link id 0 means no route. The
 *  destination selects the codec (§12.1). */
async function netLinkOpen(dest) {
  const r = await host.call(N_LINK_OPEN, utf8Encode(dest));
  return { linkId: readU32BE(r, 0), stream: r[4] === 1 };
}
/** Resolves once the host has accepted `bytes`, then `tail` if given. */
function netLinkSend(linkId, bytes, tail) {
  const id = argU32(linkId);
  return host.call(N_LINK_SEND, tail ? [id, bytes, tail] : [id, bytes]);
}
/** A host link as the channel a `Link` writes to: `send(bytes, tail)` writes `bytes` and
 *  then `tail`, if given, resolving once they are taken, and `close(graceful)` ends it. A
 *  link this realm runs itself (quic.js) is a channel of its own. */
function hostChannel(linkId) {
  return { send: (bytes, tail) => netLinkSend(linkId, bytes, tail), close: (graceful) => netLinkClose(linkId, graceful) };
}
/** Never throws out of a teardown: a close the host-call budget refuses is asked again
 *  (`callRetried`, core.js). */
function netLinkClose(linkId, graceful) {
  callRetried(N_LINK_CLOSE, args([linkId], [graceful ? 1 : 0]));
}
/** Hand one decoded request to the host's claim routing:
 *  `[claimLen u8][claim][attribution 32][payload]`, answered with the claimant's bytes
 *  (empty for an unreachable claim or a failed handler). Do not wait on it in the same
 *  turn: the answer comes in another turn of this realm. */
function netLinkDeliver(claim, attribution, payload) {
  return host.call(N_LINK_DELIVER, [Uint8Array.of(claim.length), claim, attribution, payload]);
}

// Proved msg1s, by the initiator's ephemeral key, so a replayed recording is refused (a
// msg1 is not bound to its connection). Only proved ones are remembered, so a stranger
// cannot flush the set; the oldest is evicted at the cap.
const MAX_SEEN_PROBES = 4096;
const seenProbes = new Set();
function probeSeen(ephI) { return seenProbes.has(toHex(ephI)); }
function rememberProbe(ephI) {
  if (seenProbes.size >= MAX_SEEN_PROBES) seenProbes.delete(seenProbes.values().next().value);
  seenProbes.add(toHex(ephI));
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
    this.channel = spec.channel ?? hostChannel(spec.linkId);
    this.framer = makeFramer(spec.stream, (bytes, tail) => this.channel.send(bytes, tail), spec.dest, spec.listener);
    this.weDialed = spec.weDialed;
    // A splice through a relay (relay.js), rather than a path of its own to the peer.
    this.relayed = spec.relayed === true;
    this.relay = this.relayed ? relayOrigin(spec.dest) : ""; // its relay's origin
    // The peer this dial is for (msg2 must verify under it); empty for an accept.
    this.dialedPeerId = spec.dialedPeerId || "";
    // The one peer this accept is for (msg3 must name it); empty takes whoever
    // authenticates.
    this.acceptPeerId = spec.acceptPeerId || "";
    this.source = spec.source;               // remoteAddr for the limiter, if any
    this.onAuth = spec.onAuth;
    this.onFrame = spec.onFrame;
    // Called the moment the link closes, before its teardown runs.
    this.onClose = spec.onClose;
    // A dial presents the peer's secret; an accept takes the first of its own that its msg1
    // opens under (§12.6.3).
    this.contactSecret = spec.linkSecret ?? null;
    // An accept's secrets, tried in order: a function answering them, read when a msg1
    // arrives so each accept sees the current ones (core.js `acceptSecrets`).
    this.acceptSecrets = spec.acceptSecrets;
    // The network the root is for: this node's, or the public one for a relay link.
    this.networkKey = spec.networkKey ?? networkKey;
    // The peer lint (`admits`), which a relay link, pinned to its relay, skips.
    this.lint = spec.lint !== false;
    // How long the link may carry nothing once authenticated; 0 keeps it.
    this.idleMs = spec.idleMs ?? linkIdleTimeoutMs;
    // Records per direction between ratchets, which both ends must agree on.
    this.rekeyAfterFrames = spec.rekeyAfterFrames ?? rekeyAfterFrames;
    this.root = null; // set by the boot chain below

    this.peerPubkey = null;
    this.peerId = "";
    this.authed = false;
    this.peerSaidGoodbye = false;
    this.myEph = null;
    this.myKem = null;
    this.kemSecret = null;
    this.queue = new Fifo();
    this.queuedBytes = 0;
    this.outboundQueuedBytes = 0;
    this.outboundQueuedSlices = 0;
    this.peerEph = null;
    this.closed = false;
    this.parting = false;     // closed deliberately, and still sending what came before
    this.stalled = false;
    // How this link ended, for `closeReason`: closed locally, provoked by the peer, or
    // timed out.
    this.closedLocally = false;
    this.aborted = false;
    this.timedOut = false;
    this.slot = null;
    this.due = Infinity;      // when the handshake deadline or the idle window ends
    this.lastSeen = 0;        // when anything last crossed, for the idle window
    this.sendKey = null;
    this.recvKey = null;
    // A channel that carries the handshake in its own (quic.js) seals every packet under the
    // keys it derives, so the records go in the clear above it: one AEAD a packet, not two.
    this.plain = typeof this.channel.handshake === "function";
    this.sendEpoch = 0;
    this.sendCtr = 0;
    this.recvEpoch = 0;
    this.recvCtr = 0;
    this.th = null;
    this.ee = null;

    // One work chain per link, so handshake steps never interleave and records keep
    // arrival order (the record layer counts nonces): a step runs at once while the chain is
    // idle and waits behind the running one otherwise (`enqueue`).
    this.busy = false;
    this.waiting = new Fifo();
    this.stepDone = () => {
      this.busy = false;
      while (!this.busy && this.waiting.size > 0) {
        const w = this.waiting.shift();
        w.resolve(this.runStep(w.step, w.arg));
      }
    };
    // What a framed read delivered last, for `onWire` to answer.
    this.lastStep = undefined;
    this.deliver = (m) => (this.lastStep = this.enqueue(this.onMessage, m));

    // The half-open slot before any key material, so a refusal costs no keypair.
    if (spec.limiter) {
      this.slot = spec.limiter.acquire(this.source, () => this.abort());
      if (!this.slot) {
        this.abort();
        return;
      }
    }

    void this.enqueue(this.boot);
  }

  /** Only a dialer speaks unprompted; an accept waits for a msg1 that opens under the
   *  contact secret (§12.6). An accept for one expected peer, a negotiation's data link,
   *  waits as long as its dialer does: the negotiation's own deadline bounds it, and on a
   *  lossy UDP path the msg1 retransmissions back off past the stranger's bound. A failed
   *  boot aborts. */
  async boot() {
    try {
      this.root = await rootKey(this.networkKey);
      if (this.weDialed) {
        await this.ensureKeys();
        this.armDeadline(handshakeTimeoutMs);
        await this.sendMsg1();
      } else {
        this.armDeadline(this.acceptPeerId ? handshakeTimeoutMs : unverifiedTimeoutMs);
      }
    } catch {
      this.abort();
    }
  }

  /** Run `step` (a method of this link, given `arg`) as the next step of the work chain: at
   *  once while the chain is idle, behind the running step otherwise. Answers what the step
   *  answers, or a promise of its end while it runs or waits; never a rejection, so a
   *  failed step never wedges the rest. */
  enqueue(step, arg) {
    if (this.busy) return new Promise((resolve) => { this.waiting.push({ step, arg, resolve }); });
    const r = this.runStep(step, arg);
    if (!this.busy) this.stepDone(); // what the step queued while it ran
    return r;
  }

  /** One step, holding the chain until it ends. */
  runStep(step, arg) {
    this.busy = true;
    let r;
    try { r = step.call(this, arg); } catch { /* swallowed, as a rejection is */ }
    if (r instanceof Promise) return r.then(this.stepDone, this.stepDone);
    this.busy = false;
    return r;
  }

  async ensureKeys() {
    if (!this.myEph) this.myEph = await boxKeypair();
    // Only the initiator publishes an encapsulation key.
    if (this.weDialed && !this.myKem) this.myKem = await kemKeypair(await randomBytes(64));
  }

  /** The pre-auth deadline, 0 disabling it; after authentication `armIdle` takes over. */
  armDeadline(ms) {
    this.due = ms > 0 ? dueIn(ms) : Infinity;
  }

  /** The post-auth idle clock: `idleMs` since anything last crossed. Traffic only moves
   *  `lastSeen`; the deadline is re-read on a wake. */
  armIdle() {
    this.lastSeen = now();
    this.due = this.idleMs > 0 ? dueIn(this.idleMs) : Infinity;
  }

  /** One wake (core.js `onWake`): past `due`, a handshake times out and an idle link
   *  closes. Returns the next deadline, or `Infinity`. */
  onWake(t) {
    if (t < this.due) return this.due;
    this.due = Infinity;
    if (this.closed) return Infinity;
    if (!this.authed) {
      this.timedOut = true;
      this.abort();
    } else if (this.idleMs <= 0) {
      this.due = Infinity;
    } else if (t - this.lastSeen < this.idleMs) {
      this.due = this.lastSeen + this.idleMs;
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

  /** Queue (pre-auth) or send (post-auth, as an AEAD record) a frame. A record answers a
   *  promise that settles once it is on the wire or the link has failed. */
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
      return this.enqueue(this.sendRecord, frame);
    }
    this.queue.push(frame);
    this.queuedBytes += frame.length;
    // Drop-oldest past either bound, keeping the newest.
    while ((this.queuedBytes > MAX_QUEUE_BYTES || this.queue.size > maxPreAuthQueueSlices) && this.queue.size > 1) {
      this.queuedBytes -= this.queue.shift().length;
    }
  }

  /** Hand over the frames still waiting for authentication, oldest first. */
  takeQueued() {
    this.queuedBytes = 0;
    const frames = [];
    while (this.queue.size > 0) frames.push(this.queue.shift());
    return frames;
  }

  /** End the link locally: it leaves routing at once and tears down behind the work
   *  chain, so an in-flight step keeps its keys. `farewell` sends the end-of-stream record
   *  first, behind the records handed to the link before it, which a failure drops;
   *  `defensive` records that the peer provoked it. */
  end(farewell, defensive) {
    if (this.closed) {
      // A failure while a deliberate close is still sending ends the sending.
      if (!farewell) this.parting = false;
      return;
    }
    this.closed = true;
    // Nothing more is sent to a peer that has said goodbye, or with the epochs used up.
    this.parting = farewell && !this.peerSaidGoodbye && this.sendEpoch < REJECT_AFTER_EPOCHS;
    this.closedLocally = true;
    if (defensive) this.aborted = true;
    this.severWire();
    this.onClose(this);
    void this.enqueue(this.part);
  }

  /** `end`'s step, behind the records handed to the link before it. */
  async part() {
    let saidGoodbye = false;
    // Read again behind the records before it: a failure meanwhile ends the parting, and
    // those records may have used the last epoch.
    if (this.parting && this.authed && (this.plain || this.sendKey) && this.sendEpoch < REJECT_AFTER_EPOCHS) {
      try {
        await this.wire(await this.seal(EMPTY));
        // A codec with its own end-of-stream signal sends it too.
        if (this.framer && this.framer.goodbye) await this.framer.goodbye();
        saidGoodbye = true;
      } catch { /* the channel is already gone */ }
    }
    this.teardown();
    // Graceful only after a goodbye, so the close flushes it.
    this.channel.close(saidGoodbye);
  }

  /** A deliberate local shutdown, and the only path that says goodbye. */
  close() { this.end(true, false); }

  /** Every failure path: no goodbye, so a goodbye always means the peer chose to stop. */
  abort(defensive) { this.end(false, defensive); }

  /** Why this link ended, as a REASON_* word.
   *
   *  Before authentication: `dropped` is the socket dying on its own (refused, unreachable,
   *  hung up); `refused` is a teardown the peer provoked (bad probe, malformed frame, bad
   *  signature, lint); `timeout` is the local deadline on a silent socket; `handshake` is
   *  any other local cause (eviction, a local crypto failure).
   *
   *  After: `clean` is the peer's end-of-stream record; `aborted` a teardown the peer
   *  provoked; `local` a local shutdown; `truncated` a stream that just stopped. */
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

  /** Put one link message on the wire, framed if the platform does not frame it, or a
   *  handshake message into a channel that carries the handshake itself. */
  wire(msg) {
    if (this.plain && !this.authed) return this.channel.handshake(msg);
    return this.framer ? this.framer.send(msg) : this.channel.send(msg);
  }

  /** A handshake message from a channel that carries the handshake itself, which nothing
   *  past authentication is. */
  onHandshake(m) {
    if (this.closed || this.stalled) return;
    if (m.length > MAX_HANDSHAKE_FRAME_BYTES) { this.refuse(); return; }
    void this.enqueue(this.handshakeStep, m);
  }

  handshakeStep(m) {
    return this.authed ? this.refuse() : this.onMessage(m);
  }

  /** That channel's handshake secrets, from the second message on, under which it carries
   *  the third: each end's under its own label, as the session keys are. */
  async channelHandshakeKeys(th) {
    const i2r = await this.kdf([this.ee, this.kemSecret], th, LABEL_HS_I2R);
    const r2i = await this.kdf([this.ee, this.kemSecret], th, LABEL_HS_R2I);
    if (this.weDialed) this.channel.handshakeKeys(i2r, r2i);
    else this.channel.handshakeKeys(r2i, i2r);
    i2r.fill(0);
    r2i.fill(0);
  }

  /** Seal a record `send` took and put it on the wire, unless the link closed without
   *  parting meanwhile, failing the link if that fails (§12.6). */
  async sendRecord(frame) {
    try {
      if (!this.closed || this.parting) await this.wire(await this.seal(frame));
    } catch {
      this.abort();
    } finally {
      this.outboundQueuedSlices--;
      this.outboundQueuedBytes -= frame.length;
    }
  }

  /** Inbound bytes, decoded on the work chain. Answers once this read is decoded (a
   *  promise only while that waits on something), not once any request it carried is
   *  answered. */
  onWire(bytes) {
    // A stall is terminal: later reads are dropped unparsed.
    if (this.closed || this.stalled) return;
    if (!this.framer) {
      // Platform-framed links get the same two-stage cap.
      if (bytes.length > (this.authed ? maxFrameBytes : MAX_HANDSHAKE_FRAME_BYTES)) { this.refuse(); return; }
      return this.enqueue(this.onMessage, bytes);
    }
    // Steps settle in order and never reject, so the read is done when the last one is.
    this.lastStep = undefined;
    let ok;
    try { ok = this.framer.push(bytes, this.deliver); } catch { this.refuse(); return; }
    if (ok === true) return this.lastStep;
    if (ok === false) { this.refuse(); return; }
    return ok.then((good) => (good ? this.lastStep : this.refuse()), () => this.refuse());
  }

  /** Route one whole link message. It carries no type: this end's role and progress pick
   *  the handler, which checks the exact width (§12.6). */
  onMessage(m) {
    // Frames queued behind a refusal are dropped here.
    if (this.closed || this.stalled) return;
    // A record answers its own failures.
    if (this.authed) return this.onRecord(m);
    const step = this.weDialed ? this.onMsg2(m) : (this.peerEph ? this.onMsg3(m) : this.onMsg1(m));
    return step.catch(() => { this.refuse(); });
  }

  /** The peer sent something unacceptable: abort once authenticated, stall before
   *  (framing errors included), so a stranger learns nothing (docs/TRANSPORT.md, Refusals are silent). */
  refuse() {
    if (this.authed) this.abort(true);
    else this.stall();
  }

  /** Refuse without saying so: every refusal looks like silence (§12.6). Terminal. The
   *  deadline and slot stay in place, so the sender still occupies a slot until timeout. */
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
    if (this.plain) {
      // The channel seals under them from here on, and the link keeps no copy.
      this.channel.keys(this.sendKey, this.recvKey);
      this.sendKey.fill(0);
      this.recvKey.fill(0);
      this.sendKey = this.recvKey = null;
    }
    this.onAuth(this.peerId, this);
    // The tie-break may have closed this link, handing its queue to the winner.
    if (this.closed) return;
    for (const frame of this.takeQueued()) {
      this.outboundQueuedSlices++;
      this.outboundQueuedBytes += frame.length;
      await this.sendRecord(frame);
    }
  }

  // ── the concealed-identity handshake (suite 0x03, §12.6) ────────────────────

  /** Every handshake key comes through here, so every one mixes in the contact secret. */
  kdf(ikm, ctx, label) {
    return hash(...ikm, this.contactSecret, ctx, label);
  }

  async sealZero(key, plain) {
    const ct = await aeadEnc(key, 0, 0, plain);
    key.fill(0);
    return ct;
  }
  async openZero(key, ct) {
    try {
      const r = await aeadDec(key, 0, 0, ct);
      return r[0] === 1 ? { ok: true, pt: r.subarray(1) } : { ok: false, pt: null };
    }
    finally { key.fill(0); }
  }

  /** What the probe key derives from before the secret is mixed in (`probeKey`), so an
   *  accept trying several secrets hashes it once. */
  probeContext(suiteByte, ephI, kemPkI) {
    return hash(this.root, suiteByte, ephI, kemPkI);
  }

  probeKey(ctx) {
    return this.kdf([], ctx, LABEL_PROBE);
  }

  /** Sign the transcript with the node's key under `DOMAIN_link_scope`. A refusal is a local
   *  misconfiguration, so the link aborts instead of stalling, and this answers null. */
  async signTranscript(th) {
    try {
      return await host.call(N_SIGN, channelIdentityMessage(this.root, th, ownPk));
    } catch {
      this.abort();
      return null;
    }
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
      await this.sealZero(await this.probeKey(await this.probeContext(SUITE_BYTE, eph, kemPk)), EMPTY)]);
    this.th = await hash(this.root, w1);
    await this.wire(w1);
  }

  async onMsg1(w1) {
    if (w1.length !== M1_LEN || w1[0] !== SUITE_CHANNEL_CONCEALED) { this.stall(); return; }
    const ephI = w1.slice(SUITE_LEN, SUITE_LEN + EPH_LEN);
    const kemPkI = w1.slice(SUITE_LEN + EPH_LEN, SUITE_LEN + EPH_LEN + KEM_PK_LEN);
    const seal = w1.slice(SUITE_LEN + EPH_LEN + KEM_PK_LEN);
    // The first secret the probe opens under is the link's, so every later key mixes it.
    let secrets;
    try { secrets = await this.acceptSecrets(); } catch { this.stall(); return; }
    const ctx = await this.probeContext(w1.slice(0, SUITE_LEN), ephI, kemPkI);
    let probe = { ok: false };
    for (const secret of secrets) {
      this.contactSecret = secret;
      probe = await this.openZero(await this.probeKey(ctx), seal);
      if (probe.ok) break;
    }
    if (!probe.ok) { this.stall(); return; }
    // A msg1 can be replayed, so each is accepted once, before any expensive work
    // (§12.6.2).
    if (probeSeen(ephI)) { this.stall(); return; }
    // Proved: move off the contended budget before the expensive work.
    if (this.slot && !this.slot.limiter.promote(this.slot)) { this.stall(); return; }
    rememberProbe(ephI);
    this.armDeadline(handshakeTimeoutMs);
    await this.ensureKeys();
    // Each secret is the link's as soon as it exists, so `clearEphemeral` wipes it on
    // every path out.
    const dh = await scalarmult(this.myEph.privateKey, ephI);
    if (!dh.ok) { this.stall(); return; }
    this.ee = dh.x;
    const kem = await kemEncaps(kemPkI, await randomBytes(32));
    if (!kem.ok) { this.stall(); return; }
    this.kemSecret = kem.sharedSecret;
    this.peerEph = ephI;

    // The receiver signs the transcript without naming itself: the dialer already holds
    // its key.
    const h1 = await hash(this.root, w1);
    const head = concatBytes([this.myEph.publicKey.subarray(0, EPH_LEN), kem.ciphertext]);
    const hs = await hash(h1, head);
    const sig = await this.signTranscript(hs);
    if (!sig) return;
    const w2 = concatBytes([head,
      await this.sealZero(await this.kdf([this.ee, this.kemSecret], hs, LABEL_M2), sig)]);
    this.th = await hash(h1, w2);
    if (this.plain) await this.channelHandshakeKeys(this.th);
    await this.wire(w2);
  }

  async onMsg2(w2) {
    if (w2.length !== M2_LEN) { this.stall(); return; }
    const head = w2.slice(0, EPH_LEN + KEM_CT_LEN);
    const ephR = head.slice(0, EPH_LEN);
    const kemCt = head.slice(EPH_LEN);
    // Each secret is the link's as soon as it exists, as in `onMsg1`.
    const dh = await scalarmult(this.myEph.privateKey, ephR);
    if (!dh.ok) { this.stall(); return; }
    this.ee = dh.x;
    const kem = await kemDecaps(this.myKem.privateKey, kemCt);
    if (!kem.ok) { this.stall(); return; }
    this.kemSecret = kem.sharedSecret;
    const hs = await hash(this.th, head);
    const r = await this.openZero(
      await this.kdf([this.ee, this.kemSecret], hs, LABEL_M2),
      w2.slice(EPH_LEN + KEM_CT_LEN));
    if (!r.ok) { this.stall(); return; }
    // The receiver must prove the dialed key. This end has sent nothing identifying yet,
    // so a failure closes instead of stalling.
    const idR = fromHex(this.dialedPeerId);
    if (bytesCompare(idR, ownPk) === 0) { this.abort(); return; }
    if (!(await verify(idR, r.pt, channelIdentityMessage(this.root, hs, idR)))) { this.abort(true); return; }
    if (this.lint && !admits(idR)) { this.abort(true); return; }
    this.peerPubkey = idR; this.peerId = this.dialedPeerId;

    const h2 = await hash(this.th, w2);
    if (this.plain) await this.channelHandshakeKeys(h2);
    const sig = await this.signTranscript(h2);
    if (!sig) return;
    const w3 = await this.sealZero(await this.kdf([this.ee, this.kemSecret], h2, LABEL_M3), concatBytes([ownPk, sig]));
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
    // The lint, on a verified key, and the one peer this accept is for, if it has one. It
    // closes instead of stalling, since the dialer already verified this node at msg2
    // (§12.6).
    if ((this.lint && !admits(idI)) || (this.acceptPeerId && toHex(idI) !== this.acceptPeerId)) { this.abort(true); return; }
    this.peerPubkey = idI; this.peerId = toHex(idI);
    this.th = await hash(this.th, w3);
    try { await this.deriveConcealedSession(); } catch { this.stall(); return; }
    await this.becomeAuthed();
  }

  /** Each key is the link's as soon as it exists, so `teardown` wipes it on every path. */
  async deriveConcealedSession() {
    const derive = (label) => this.kdf([this.ee, this.kemSecret], this.th, label);
    if (this.weDialed) this.sendKey = await derive(LABEL_I2R);
    else this.recvKey = await derive(LABEL_I2R);
    if (this.weDialed) this.recvKey = await derive(LABEL_R2I);
    else this.sendKey = await derive(LABEL_R2I);
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

  async ratchet(k) {
    const next = await hash(k, LABEL_REKEY);
    k.fill(0);
    return next;
  }

  /** One record under the send key, which ratchets once `rekeyAfterFrames` have used it. */
  seal(frame) {
    if (this.plain) return frame;
    const ct = aeadEnc(this.sendKey, this.sendEpoch, this.sendCtr, frame);
    return ++this.sendCtr < this.rekeyAfterFrames ? ct : this.rekeySend(ct);
  }

  async rekeySend(ct) {
    const sealed = await ct;
    this.sendKey = await this.ratchet(this.sendKey);
    this.sendEpoch++;
    this.sendCtr = 0;
    return sealed;
  }

  /** An authenticated record. Unlike the handshake it aborts on anything wrong, since
   *  concealment protects against strangers, not a proven peer. */
  onRecord(body) {
    if (this.plain) {
      if (body.length > maxFrameBytes) { this.abort(true); return; }
      try { this.received(body); } catch { this.abort(true); }
      return;
    }
    if (!this.recvKey || body.length < TAG_LEN || body.length > maxFrameBytes) { this.abort(true); return; }
    if (this.recvEpoch >= REJECT_AFTER_EPOCHS) { this.abort(); return; }
    return this.openRecord(body);
  }

  async openRecord(body) {
    try {
      const r = await aeadDec(this.recvKey, this.recvEpoch, this.recvCtr, body);
      if (r[0] !== 1) { this.abort(true); return; }
      // Advance only on success.
      if (++this.recvCtr >= this.rekeyAfterFrames) {
        this.recvKey = await this.ratchet(this.recvKey);
        this.recvEpoch++;
        this.recvCtr = 0;
      }
      this.received(r.subarray(1));
    } catch {
      this.abort(true);
    }
  }

  /** A record's plaintext. */
  received(pt) {
    this.markTraffic();
    // The reserved empty record: an authenticated end-of-stream.
    if (pt.length === 0) { this.peerSaidGoodbye = true; this.close(); return; }
    // Not awaited, so the next record never waits on an answer. Both forms of the peer's
    // id travel: hex for routing, bytes for attribution.
    this.onFrame(this.peerId, pt, this.peerPubkey, this);
  }

  /** The socket went away. */
  onChannelClosed() {
    if (this.closed) return;
    this.closed = true;
    this.teardown();
    this.onClose(this);
  }

  // ── teardown ────────────────────────────────────────────────────────────────

  /** End the wire now, outside the work chain, since a step waiting on the wire would
   *  otherwise block the chain from reaching the teardown (§12.6). Idempotent. */
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
