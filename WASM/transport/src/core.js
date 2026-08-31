// ============================================================================
// transport/src/core.js — the link bookkeeping, the per-host state, and the
// entrypoints the host invokes by name. Last part of the concatenation: it declares
// the state the earlier parts read at runtime.
// ============================================================================

// ── per-host state, read from installation-local config ──────────────────────
// Identity comes from `node/identity`, so it cannot drift from `node/sign` (§12.2).
// Initialization is async; config validation stays synchronous so invalid bundles fail
// during load (§12.4).

let ownPk = null;                       // 32B node channel public key, once `ready` has run
let ownId = "";                         // the same, hex
const networkKey = fromHex(LOCAL.networkKey);
const ZERO32 = new Uint8Array(32);

const hex32 = (v) => typeof v === "string" && v.length === 64 && !/[^0-9a-f]/.test(v);

// Inbound gate; zero means open. The host-only `contact` op rotates it at runtime (§12.6.3).
let contactSecret = ZERO32;
if (LOCAL.contactSecret !== undefined) {
  if (!hex32(LOCAL.contactSecret)) {
    throw new Error("transport: config contactSecret must be 64 lowercase hex characters");
  }
  contactSecret = fromHex(LOCAL.contactSecret);
}

/** One policy number: this installation's override, else the author's signed default.
 *  Every one of these bounds a resource, and a bound read as `undefined` does not fail
 *  the comparison that applies it — it makes that comparison always false, which is a
 *  cap silently absent rather than a cap set wrong. So an unresolved or non-finite value
 *  throws HERE, at realm evaluation, and the bundle is refused at load rather than
 *  running unbounded. A bundle carrying no `guest.config` fails on the first name. */
function policy(name) {
  const v = LOCAL[name] ?? APP[name];
  if (!Number.isFinite(v) || v < 0) {
    throw new Error(`transport: config ${name} must be a non-negative finite number`);
  }
  return v;
}

const connsPerPeer = Math.max(1, policy("connsPerPeer"));
// The operator's peer list as a Set of hex keys, or null for "admit everyone".
// A lint applied by `admits` (ake.js); LOCAL may override the signed APP default.
const configuredAdmitPeers = LOCAL.admitPeers ?? APP.admitPeers;
if (!Array.isArray(configuredAdmitPeers)) throw new Error("transport: config admitPeers must be an array");
const admitPeers = configuredAdmitPeers.length > 0 ? new Set(configuredAdmitPeers) : null;
// Validate the guest-owned address book during load. Missing peer secrets mean open nodes
// (§12.10).
const configuredPeers = LOCAL.peers ?? APP.peers;
if (!Array.isArray(configuredPeers)) throw new Error("transport: config peers must be an array");
const cohort = configuredPeers.map((p) => {
  if (!p || !hex32(p.peerId)) throw new Error("transport: config peers[].peerId must be 64 lowercase hex characters");
  if (p.contactSecret !== undefined && !hex32(p.contactSecret)) {
    throw new Error("transport: config peers[].contactSecret must be 64 lowercase hex characters");
  }
  if (p.dest !== undefined && typeof p.dest !== "string") throw new Error("transport: config peers[].dest must be a string");
  return {
    peer: fromHex(p.peerId),
    secret: p.contactSecret === undefined ? ZERO32 : fromHex(p.contactSecret),
    dest: p.dest ?? "",
  };
});
const requestDeadlineMs = policy("requestDeadlineMs");
// The peers we hold at least one authenticated link to; the host asks with `peers`.
const connected = new Set();
// These policies and their defaults belong to this signed program. LOCAL is the
// installation's general override path; APP is the author's signed fallback.
const maxFrameBytes = policy("maxFrameBytes");
// Work waiting to be sealed has not reached a socket adapter yet, so its socket-side cap
// cannot see it. Give it the same eight-frame byte window and tiny-write count ceiling.
const maxOutboundQueueBytes = 8 * maxFrameBytes;
const maxOutboundQueueSlices = 4096;
const maxUnverified = policy("maxHalfOpenUnverified");
const maxPerSource = policy("maxHalfOpenPerSource");
const maxVerified = policy("maxHalfOpenVerified");
const maxAuthed = policy("maxAuthedLinks");
// How long an AUTHENTICATED link may carry no traffic before it is retired; 0 disables.
const linkIdleTimeoutMs = policy("linkIdleTimeoutMs");
// How long a link may stay pre-authentication: the dialing side's whole handshake, and
// the shorter clock an accept runs until a msg1 opens under the contact secret. 0
// disables, like every other deadline here.
const handshakeTimeoutMs = policy("handshakeTimeoutMs");
const unverifiedTimeoutMs = policy("unverifiedTimeoutMs");
// Frames per direction between key ratchets — a deployment-wide constant BOTH ends must
// share; a mismatch desynchronizes the record layer and the link dies.
const rekeyAfterFrames = Math.max(1, policy("rekeyAfterFrames"));

// The one router and the one request/response layer per host instance.
let router = null;
let reqres = null;
let core = null;

// Timers this module asked the host to arm — host events carry the id back.
let nextTimerId = 1;
const timers = new Map();

// Deferred teardowns (see Link constructor): flushed after the current event.
const deferQueue = [];

// Links that are down but whose SOCKET the platform has not reported yet, by id. A link we
// tore down ourselves is out of every pool the moment it finishes — but the causal event,
// `linkClosed`, arrives a turn later and its return is the only thing that carries WHY. So
// the link is kept here until that event consumes it. Bounded by construction: the driver
// answers every close with exactly one `linkClosed`, including on a sever, and each one
// drains its entry.
const closing = new Map();

// The link limiter, over budgets from LOCAL (§12.6.2). THREE tiers: a slot is acquired
// when a socket is accepted, moves to `verified` when a msg1 opens under the contact
// secret, and to `authed` once the peer's identity is proved and admitted — HELD there
// for the link's whole life. Each tier evicts its own stalest occupant when full, so a
// newcomer that has proved more than the incumbents is never refused at the door.
// Per-source is not evictable and spans all three tiers.
class LinkLimiter {
  constructor(maxUnverified, maxPerSource, maxVerified, maxAuthed) {
    this.maxPerSource = maxPerSource;
    this.max = { unverified: maxUnverified, verified: maxVerified, authed: maxAuthed };
    this.count = { unverified: 0, verified: 0, authed: 0 };
    // One book per tier; insertion order is the eviction policy.
    this.books = { unverified: new Map(), verified: new Map(), authed: new Map() };
    this.nextId = 0;
    this.perSource = new Map();
  }

  acquire(source, evict) {
    if (source !== undefined && (this.perSource.get(source) || 0) >= this.maxPerSource) return null;
    if (!this.makeRoom("unverified")) return null;
    const slot = { source, tier: "unverified", released: false, evict, limiter: this };
    if (source !== undefined) this.perSource.set(source, (this.perSource.get(source) || 0) + 1);
    this.count.unverified++;
    this.books.unverified.set(this.nextId++, slot);
    return slot;
  }

  /** A msg1 opened under the contact secret: off the contended budget, before the
   *  expensive work. */
  promote(slot) { return this.move(slot, "verified"); }

  /** The identity is proved and admitted. The slot stays until the link dies. */
  hold(slot) { return this.move(slot, "authed"); }

  move(slot, tier) {
    if (slot.released || slot.tier === tier) return true;
    if (!this.makeRoom(tier)) return false;
    this.unbook(slot);
    if (this.count[slot.tier] > 0) this.count[slot.tier]--;
    slot.tier = tier;
    this.count[tier]++;
    this.books[tier].set(this.nextId++, slot);
    return true;
  }

  /** Make one slot's worth of room in a tier, evicting its stalest occupant if it is
   *  full. False only when the tier's budget is zero — nothing to evict and no room. */
  makeRoom(tier) {
    if (this.count[tier] < this.max[tier]) return true;
    const oldest = this.books[tier].keys().next();
    if (oldest.done) return false;
    const victim = this.books[tier].get(oldest.value);
    this.books[tier].delete(oldest.value);
    this.forget(victim);
    try { victim.evict(); } catch { /* already gone */ }
    return true;
  }

  release(slot) {
    if (slot.released) return;
    this.unbook(slot);
    this.forget(slot);
  }

  unbook(slot) {
    const book = this.books[slot.tier];
    for (const [id, s] of book) if (s === slot) { book.delete(id); break; }
  }

  forget(slot) {
    if (slot.released) return;
    slot.released = true;
    if (this.count[slot.tier] > 0) this.count[slot.tier]--;
    if (slot.source === undefined) return;
    const n = this.perSource.get(slot.source);
    if (n === undefined) return;
    if (n <= 1) this.perSource.delete(slot.source); else this.perSource.set(slot.source, n - 1);
  }
}

// ── the routing core ──────────────────────────────────────────────────────────

class Core {
  constructor() {
    this.connecting = new Map(); // peerId → Link[] (outbound, pre-auth)
    this.inbound = new Set();    // accepted, pre-auth
    this.addrs = new Map();      // peerId → { dest, secret } — this program's address book
    this.readyWaiters = [];      // [{check, d, timer}] — one per in-flight ready()
    this.dialing = new Map();    // peerId → in-flight dial, so concurrent senders share one
    this.limiter = new LinkLimiter(maxUnverified, maxPerSource, maxVerified, maxAuthed);
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

  /** Learn (or re-learn) one peer: where to reach it and the secret its door gates on.
   *  An EMPTY `dest` is a peer we know of but cannot dial — an RTC peer, whose links arrive
   *  through signaling — which is a real entry and not a missing one: it carries the contact
   *  secret an inbound link needs without pretending we hold a route. */
  addAddr(peerBytes, secret, dest) {
    this.addrs.set(toHex(peerBytes), { dest, secret: secret.length > 0 ? secret : null });
  }

  /** Top a dialed peer up to connsPerPeer outbound links. One dial per peer at a time:
   *  two callers racing to reach the same peer must not open double the budget. */
  dial(peerId) {
    const inFlight = this.dialing.get(peerId);
    if (inFlight) return inFlight;
    const done = this.dialNow(peerId).finally(() => this.dialing.delete(peerId));
    this.dialing.set(peerId, done);
    return done;
  }

  async dialNow(peerId) {
    const addr = this.addrs.get(peerId);
    // Unknown, or known and not dialable BY US: an entry with no destination is a peer whose
    // links can only arrive (signaling brought it), so there is nothing to open here. Both
    // read the same at every caller — the frame waits for an inbound link or is dropped.
    if (!addr || addr.dest === "") return;
    const have = router.linkCount(peerId) + (this.connecting.get(peerId) || []).length;
    for (let n = have; n < connsPerPeer; n++) {
      const opened = await netLinkOpen(addr.dest);
      if (opened.linkId === 0) return; // no route — a fabric with nowhere to send drops the frame
      this.openLink({
        linkId: opened.linkId,
        stream: opened.stream,
        dest: addr.dest,
        weDialed: true,
        expectPeerId: fromHex(peerId),
        linkSecret: addr.secret,
        limiter: null,
        dialedPeerId: peerId,
      });
    }
  }

  // An inbound (accepted) channel, or a link we just dialed.
  openLink(spec) {
    const link = new Link({
      linkId: spec.linkId,
      stream: spec.stream,
      dest: spec.dest,
      listener: spec.listener,
      weDialed: spec.weDialed,
      expectPeerId: spec.expectPeerId,
      linkSecret: spec.linkSecret,
      source: spec.source,
      limiter: spec.limiter,
      onAuth: (pid, l) => this.onAuth(pid, l),
      onFrame: (pid, frame) => router.deliver(pid, frame),
      onClose: (l) => this.forget(l),
    });
    // `connecting` is keyed by peer because it is what steers an outbound frame at a link
    // that has not authenticated yet — a dial whose peer we cannot name steers nothing, so
    // it waits in `inbound` like an accept. (`spec.weDialed` is still passed to `Link`; it
    // decides who speaks first.)
    if (spec.dialedPeerId) Core.push(this.connecting, spec.dialedPeerId, link);
    else this.inbound.add(link);
    return link;
  }

  onAuth(peerId, link) {
    this.inbound.delete(link);
    Core.drop(this.connecting, peerId, link);
    // The peer lint already answered at msg3/msg4, so a refused peer never reaches the
    // router. Only routing is left.
    router.promote(peerId, link);
  }

  forget(link) {
    this.inbound.delete(link);
    for (const pid of [...this.connecting.keys()]) {
      if (Core.drop(this.connecting, pid, link)) break;
    }
    router.remove(link);
    // Out of every pool, but not yet out of this program: `linkClosed` still has to be
    // able to say why it went (see `closing`).
    closing.set(link.linkId, link);
  }

  // A frame for a peer with no routable link yet: dial, then hand the frame to the
  // link that lands (it queues pre-auth). The dial is shared per peer (`dial`), so a
  // burst of frames to one unreachable peer costs one open, and a frame with no
  // address at all is dropped, as a fabric with no route drops it.
  async sendFrame(to, frame) {
    if (to === ownId) return;
    if (router.send(to, frame)) return;
    const pool = this.connecting.get(to);
    if (pool && pool.length > 0) { pool[0].send(frame); return; }
    if (!this.addrs.has(to)) return;
    await this.dial(to);
    const landed = this.connecting.get(to);
    if (landed && landed.length > 0) landed[0].send(frame);
  }

  // Resolve once every known peer is authenticated, or the deadline passes —
  // event-driven off the router's up edge. Dials are issued fire-and-forget: the
  // deadline below settles the waiter either way.
  ready(d, timeoutMs) {
    const targets = [...this.addrs.keys()].filter((p) => p !== ownId);
    for (const p of targets) void this.dial(p);
    const allUp = () => targets.every((p) => router.linkCount(p) >= 1);
    if (allUp()) { d.settle(EMPTY); return; }
    // A LIST, not a slot: two callers may wait at once, each with its own deferred.
    const w = { check: allUp, d, timer: 0 };
    w.timer = armTimer(timeoutMs, () => {
      this.dropWaiter(w);
      // Settles either way: the caller asked to WAIT for the cohort, not to be told
      // whether it arrived — one that cares reads `peers`.
      d.settle(EMPTY);
    });
    this.readyWaiters.push(w);
  }

  dropWaiter(w) {
    const i = this.readyWaiters.indexOf(w);
    if (i >= 0) this.readyWaiters.splice(i, 1);
  }

  checkReady() {
    for (const w of [...this.readyWaiters]) {
      if (!w.check()) continue;
      clearTimer(w.timer);
      this.dropWaiter(w);
      w.d.settle(EMPTY);
    }
  }

  close() {
    for (const w of this.readyWaiters.splice(0)) { clearTimer(w.timer); w.d.settle(EMPTY); }
    const pending = [];
    for (const arr of this.connecting.values()) for (const l of arr) pending.push(l);
    for (const l of this.inbound) pending.push(l);
    this.connecting.clear();
    this.inbound.clear();
    router.closeAll();
    for (const l of pending) l.close();
  }
}

/** Every link, wherever it currently sits: authenticated ones live in the router's pools,
 *  pre-auth ones in the core's connecting/inbound tables, and one already torn down waits
 *  in `closing` for the socket event that will ask why. */
function findLink(linkId) {
  const gone = closing.get(linkId);
  if (gone) return gone;
  for (const pool of router.links.values()) {
    for (const link of pool) if (link.linkId === linkId) return link;
  }
  for (const arr of core.connecting.values()) {
    for (const link of arr) if (link.linkId === linkId) return link;
  }
  for (const link of core.inbound) if (link.linkId === linkId) return link;
  return null;
}

// ── the one entrypoint ────────────────────────────────────────────────────────
//
// Reached as an app is: `handle([caller 32][body …])`, body always an op envelope
// `[opLen u8][op][args]` (util.js `readOp`) — this bundle's envelope, which is how an
// app's `send` and the host's own events (a fired deadline included) land on one
// entrypoint. For a deadline this bundle supplies the complete `timer` envelope when it
// arms the host table; the kernel stores and returns those bytes opaquely. The op is a
// NAME, not a tag byte — an unimplemented op fails loud.
//
// Two kinds of caller, told apart by those 32 bytes and nothing else:
//   the HOST  32 zero bytes — the platform's events: sockets opening, bytes
//              arriving, an address, a fired deadline, and the operator's `ready`/`peers`.
//   an APP    its app key, exactly as an inbound frame carries the authenticated
//              sender's key. `send` is the only op an app may name.
//
// Most ops answer with `NOTHING` and work by calling out. Three have an answer, two of
// which cannot be answered or awaited in the same turn — the events that settle them
// arrive as further invocations, which would queue behind the frame doing the awaiting
// (realm-queue.ts). They use `defer()` (below).
//
// A deferred teardown is flushed at the end of whichever event provoked it, so a link's
// bookkeeping is never undone by an onClose that ran before its caller finished.

const NOTHING = new Uint8Array(0);

// Answer on a later turn without holding the realm's queue; the kernel supplies the
// release marker (`__deferred`), everything else is ours.
const defer = () => {
  let settle, fail;
  const promise = new Promise((res, rej) => { settle = res; fail = rej; });
  globalThis.__deferred = true;
  return { promise, settle, fail };
};

const ops = Object.create(null);
function entry(name, fn) { ops[name] = fn; }

/** The ops an app may name. A lookup rather than a chain of `!==`; null-prototype like
 *  `ops` itself, so an inherited `toString` is not an admitted op. */
const APP_OPS = Object.assign(Object.create(null), { send: 1, peers: 1 });

// Early calls await this promise (§12.3).
const ready = (async () => {
  ownPk = (await host.call(N_IDENTITY, NOTHING)).slice();
  ownId = toHex(ownPk);
  router = new Router(ownPk, ownId);
  reqres = new ReqRes();
  core = new Core();
  reqres.attach((to, frame) => core.sendFrame(to, frame));
  router.sink = (from, frame) => reqres.onFrame(from, frame);
  // The cohort edges stay in this heap; the host reads them with the `peers` op.
  router.onPeerUp = (peerId) => { connected.add(peerId); core.checkReady(); };
  router.onPeerDown = (peerId) => { connected.delete(peerId); };
  for (const p of cohort) core.addAddr(p.peer, p.secret, p.dest);
})();
// Avoid an unhandled rejection if the realm is disposed before its first invocation.
ready.catch(() => {});

/** Pre-ready calls defer without holding the realm queue (§12.3). */
function handle(argBytes) {
  if (core) return dispatch(argBytes);
  globalThis.__deferred = true;
  return ready.then(() => dispatch(argBytes));
}

function dispatch(argBytes) {
  const { fromHost, caller, body } = callerOf(argBytes);
  try {
    const { op, args } = readOp(body);
    const r = new Reader(args);
    const fn = ops[op];
    if (!fn) throw new Error("transport: no op '" + op + "'");
    // The platform's events are the host's alone; the caller id is the host's to write,
    // so this is a real boundary and not a hint.
    if (!fromHost && !APP_OPS[op]) throw new Error("transport: '" + op + "' is the host's, not an app's");
    return fn(r, caller) || NOTHING;
  } finally {
    const deferred = deferQueue.splice(0);
    for (const f of deferred) { try { f(); } catch { /* teardown of a gone link */ } }
  }
}

/** Platform-opened link event (§12.1). */
entry("linkOpen", (r) => {
  const linkId = r.u32();
  const weDialed = r.u8() === 1;
  const stream = r.u8() === 1;
  const listener = r.blob();
  const expectPeerId = r.blob();
  const source = r.blob();
  core.openLink({
    linkId, weDialed, stream,
    listener: listener.length > 0 ? utf8Decode(listener) : "",
    dest: "",
    expectPeerId: expectPeerId.length > 0 ? expectPeerId.slice() : null,
    linkSecret: null,
    source: source.length > 0 ? utf8Decode(source) : undefined,
    // Only an accept spends half-open budget; a dial is our own decision to make.
    limiter: weDialed ? null : core.limiter,
    dialedPeerId: weDialed && expectPeerId.length > 0 ? toHex(expectPeerId) : null,
  });
});

/** Bytes off one socket read. Awaits the READ's own decoding — framing, the handshake
 *  step, the AEAD — but answers nothing: a request it decoded goes to the host as this
 *  program's own `link/deliver` call, on a later turn. */
entry("linkBytes", async (r) => {
  const link = findLink(r.u32());
  if (link) await link.onWire(r.blob());
  // Explicit, because this op is `async`: `handle`'s `|| NOTHING` sees a truthy Promise
  // and never applies, so a bare `undefined` here would reach the seam's return check.
  return NOTHING;
});

/** The socket is gone. The return is the one-byte reason (`reasonCode`, ake.js) — a fact
 *  only this program ever held, since it is the end with the session keys. It carries no
 *  link id: the event names the link, so a return cannot speak about another socket, and a
 *  link already reported is off `closing` and answers nothing a second time. */
entry("linkClosed", (r) => {
  const linkId = r.u32();
  const link = findLink(linkId);
  if (!link) return NOTHING;
  link.onChannelClosed();
  closing.delete(linkId);
  return Uint8Array.of(reasonCode(link));
});

/** A fired deadline (§12.2): the shell's per-realm timer table re-entering this realm as
 *  an ordinary host loopback, body `[id u32]`. HOST-ONLY — an app naming it could fire
 *  an id it never armed. */
entry("timer", (r) => fireTimer(r.u32()));

/** App-facing send: deferred because the peer's response is another invocation of this
 *  realm. `deadlineMs` 0 → node default. */
entry("send", (r, caller) => {
  const noReply = r.u8() === 1;
  const deadlineMs = r.u32() || requestDeadlineMs;
  // `blob` is a VIEW of the caller's argument bytes; `.slice()` below is the first copy.
  const to = r.blob();
  const protoIn = r.blob();
  const payloadIn = r.blob();
  // Measured BEFORE anything is copied: a co-resident app naming a 50 MiB payload would
  // take this realm down before the frame it was refused for existed. A caller error, so
  // it is LOUD — the silent drop in Link.send is for a frame we chose to build.
  if (to.length !== PK_LEN) throw new Error("transport: send needs a 32-byte peer id");
  if (protoIn.length > 0xff) throw new Error("transport: protocol id too long");
  if (REQ_HEAD_LEN + protoIn.length + payloadIn.length > maxFrameBytes - TAG_LEN) {
    throw new Error("transport: send over the frame cap");
  }
  const proto = protoIn.slice();
  const payload = payloadIn.slice();
  if (noReply) {
    reqres.request(null, toHex(to), proto, payload, true, 0);
    return Uint8Array.from([1]);
  }
  const d = defer();
  reqres.request(d, toHex(to), proto, payload, false, deadlineMs);
  return d.promise;
});

/** One peer, taught by the host on the embedder's behalf: who, the secret its door gates
 *  on, and where to reach it. The destination is opaque to everything between this book and
 *  the host's socket factory, and an EMPTY one is a peer we cannot dial (see `addAddr`). */
entry("addr", (r) => {
  const peer = r.blob();
  const secret = r.blob();
  core.addAddr(peer, secret, utf8Decode(r.blob()));
});

/** Rotate the inbound contact secret (§12.6.3). */
entry("contact", (r) => {
  const secret = r.blob();
  if (secret.length !== 0 && secret.length !== PK_LEN) {
    throw new Error("transport: contact needs 32 bytes, or none for an open node");
  }
  contactSecret = secret.length === 0 ? ZERO32 : secret.slice();
});

/** Wait until every known peer is linked, or the deadline passes. Deferred for the same
 *  reason `send` is. */
entry("ready", (r) => {
  const d = defer();
  core.ready(d, r.u32());
  return d.promise;
});

/** The peers we hold at least one authenticated link to, as raw 32-byte keys. Answered
 *  in the same turn — a read of this heap, not a question about the wire. An app's to
 *  name as well as the host's: it is what an app placing replicas has to know. */
entry("peers", () => {
  const out = [];
  for (const p of connected) out.push(fromHex(p));
  return concatBytes(out);
});

// There is deliberately no `shutdown` entrypoint. Teardown releases sockets and timers,
// both the HOST's, and it closes them itself (transport-host.ts `close`) rather than
// asking an occupant that must not be able to refuse. What is left is this realm's heap,
// which dies with the realm.
