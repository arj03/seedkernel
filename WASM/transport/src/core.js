// ============================================================================
// transport/src/core.js — the link bookkeeping, the per-host state, and the
// entrypoints the host invokes by name. Last part of the concatenation: it declares
// the state the earlier parts read at runtime.
// ============================================================================

// ── per-host state, set by the `init` op ─────────────────────────────────────

let ownPk = null;          // 32B node channel public key
let ownId = "";            // its hex — the peer id
let networkKey = null;     // 32B
let contactSecret = null;  // 32B — OUR inbound gate (zeros = open)
let connsPerPeer = 1;
// The operator's peer list as a Set of hex keys, or null for "admit everyone".
// A lint applied by `admits` (ake.js); a node fact, shipped in the init payload.
let admitPeers = null;
// Fallback request deadline, learned at init.
let requestDeadlineMs = 10000;
// The peers we hold at least one authenticated link to; the host asks with `peers`.
const connected = new Set();
// Every literal below is what INIT overwrites — the bounds belong to whoever owns the
// resource (net-limits.ts, core); this module only applies them.
let maxFrameBytes = 2 * 1024 * 1024;
// The pre-auth cap, applied HERE because on an unframed link the host holds a byte
// duplex and has no frames to measure — we impose the boundaries.
let maxHandshakeFrameBytes = 8 * 1024;
let maxUnverified = 1024, maxPerSource = 8, maxVerified = 256, maxAuthed = 256;
// How long an AUTHENTICATED link may carry no traffic before it is retired; 0 disables.
let linkIdleTimeoutMs = 0;

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

// The link limiter, over budgets from INIT (§12.6.2). THREE tiers: a slot is acquired
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
    this.addrs = new Map();      // peerId → 32B contact secret (or null = open)
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

  addAddr(peerBytes, secret) {
    this.addrs.set(toHex(peerBytes), secret.length > 0 ? secret : null);
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
    if (!this.addrs.has(peerId)) return;
    const have = router.linkCount(peerId) + (this.connecting.get(peerId) || []).length;
    for (let n = have; n < connsPerPeer; n++) {
      const opened = await netLinkOpen(fromHex(peerId));
      if (opened.linkId === 0) return; // no route — a fabric with nowhere to send drops the frame
      this.openLink({
        linkId: opened.linkId,
        framing: opened.framing,
        authority: opened.authority,
        weDialed: true,
        expectPeerId: fromHex(peerId),
        linkSecret: this.addrs.get(peerId),
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
      linkSecret: spec.linkSecret,
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

// ── init: the host delivers this node once ───────────────────────────────────
//
// The shell invokes `handle` with an `init` op while the slot is still a candidate —
// the constructor's argument, delivered with the host's caller id. Node facts are an
// input, not a grant: the seam's name table has no entry for them.

/** Every core link, wherever it currently sits: authenticated ones live in the
 *  router's pools, pre-auth ones in the core's connecting/inbound tables, a
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
//   the HOST  32 zero bytes — the platform's events: `init`, sockets opening, bytes
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
const ZERO32 = new Uint8Array(32);

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

/** The host's one-time delivery of the immutable node facts. The shape is a contract
 *  with the pinned bundle — transport-host.ts `initialConfig` — not a kernel version:
 *  removing or reordering a field is a bundle update, appending one breaks nothing. */
entry("init", (r) => {
  if (core !== null) throw new Error("transport: node facts delivered twice");
  // No version word inside: the host feeding a different shape fails the load at this
  // line, and the fix is shipping the matching bundle.
  ownPk = r.blob();
  ownId = toHex(ownPk);
  networkKey = r.blob();
  contactSecret = r.blob();
  connsPerPeer = Math.max(1, r.u32());
  maxUnverified = r.u32();
  maxPerSource = r.u32();
  maxVerified = r.u32();
  maxAuthed = r.u32();
  maxFrameBytes = r.u32();
  maxHandshakeFrameBytes = r.u32();
  requestDeadlineMs = r.u32();
  linkIdleTimeoutMs = r.u32();
  // An empty list means "admit everyone", said as a zero-length blob rather than a
  // missing field, so there is one shape to read.
  const peers = new Reader(r.blob());
  admitPeers = peers.b.length > 0 ? new Set() : null;
  while (peers.off < peers.b.length) admitPeers.add(toHex(peers.blob()));

  router = new Router(ownPk, ownId);
  reqres = new ReqRes();
  core = new Core();
  connected.clear();
  reqres.attach((to, frame) => core.sendFrame(to, frame));
  router.sink = (from, frame) => reqres.onFrame(from, frame);
  // The cohort edges stay in this heap; the host reads them with the `peers` op.
  router.onPeerUp = (peerId) => { connected.add(peerId); core.checkReady(); };
  router.onPeerDown = (peerId) => { connected.delete(peerId); };
});

/**
 * The one entrypoint. The kernel's part of the argument is exactly the 32-byte caller;
 * everything after it is this bundle's format (util.js `callerOf`/`readOp`).
 */
function handle(argBytes) {
  const { fromHost, caller, body } = callerOf(argBytes);
  try {
    const { op, args } = readOp(body);
    const r = new Reader(args);
    const fn = ops[op];
    if (!fn) throw new Error("transport: no op '" + op + "'");
    // The platform's events are the host's alone; the caller id is the host's to write,
    // so this is a real boundary and not a hint.
    if (!fromHost && !APP_OPS[op]) throw new Error("transport: '" + op + "' is the host's, not an app's");
    // The node facts arrive before anything else; without init, refuse by name.
    if (core === null && op !== "init") throw new Error("transport: node facts never arrived — '" + op + "' ran before init");
    return fn(r, caller) || NOTHING;
  } finally {
    const deferred = deferQueue.splice(0);
    for (const f of deferred) { try { f(); } catch { /* teardown of a gone link */ } }
  }
}

/** A link the HOST opened: an accepted socket (kind CORE), or one a host-managed
 *  transport handed over (kind OPEN, either direction). A core link we dialed never
 *  arrives here. `linkSecret` is the secret THIS link opens under: the peer's on a dial,
 *  the host's own current one on an accept — so an accept gates on the secret now, not
 *  on the one the init saw (§12.6.3). */
entry("linkOpen", (r) => {
  const linkId = r.u32();
  const weDialed = r.u8() === 1;
  const kind = r.u8();
  const framing = r.u8();
  const authority = r.blob();
  const handshakeTimeoutMs = r.u32();
  const rekeyAfterFrames = r.u32();
  const expectPeerId = r.blob();
  const linkSecret = r.blob();
  const source = r.blob();
  const spec = {
    linkId, weDialed, framing,
    authority: authority.length > 0 ? utf8Decode(authority) : "",
    expectPeerId: expectPeerId.length > 0 ? expectPeerId.slice() : null,
    linkSecret: linkSecret.length > 0 ? linkSecret.slice() : null,
    source: source.length > 0 ? utf8Decode(source) : undefined,
    handshakeTimeoutMs: handshakeTimeoutMs > 0 ? handshakeTimeoutMs : undefined,
    rekeyAfterFrames: rekeyAfterFrames > 0 ? rekeyAfterFrames : undefined,
    limiter: null,
  };
  if (kind === LINK_CORE) {
    // Only an accept spends half-open budget; a dial is our own decision to make.
    spec.limiter = weDialed ? null : core.limiter;
    spec.dialedPeerId = weDialed ? toHex(expectPeerId) : null;
    core.openLink(spec);
    return;
  }
  // A host-managed transport (WebRTC / browser WS): the socket is the caller's;
  // auth goes to the shared router, and the host tracks the link by its id.
  const link = new Link(Object.assign({}, spec, {
    onAuth: (peerId, l) => {
      // The peer lint answered at msg3/msg4 (`admits`); what is left is the
      // double-connect tie-break. The host owns this socket, so it is told.
      if (!router.promote(peerId, l)) { l.close(); return; }
      hostLinkAuth(linkId, fromHex(peerId));
    },
    onFrame: (peerId, frame) => router.deliver(peerId, frame),
    // `l`, not the `link` binding below: a Link that tears itself down in its own
    // constructor (a refused limiter slot, a failed timer arm) notifies from the
    // deferred flush, and `link` is a `const` that was never initialized — closing
    // over it would raise a ReferenceError instead of telling the host its socket is down.
    onClose: (l) => {
      openLinks.delete(linkId);
      router.remove(l);
      hostLinkDown(linkId, reasonCode(l));
    },
  }));
  openLinks.set(linkId, link);
});

entry("linkBytes", async (r) => {
  const link = findLink(r.u32());
  // onWire answers a promise for the delivery frame — every seam call the processing
  // awaits is one — and an empty answer means nothing deliverable.
  if (!link) return NOTHING;
  return (await link.onWire(r.blob())) || NOTHING;
});

/** The claim handler's answer to a delivery this program returned off a `linkBytes`
 *  event: `[from blob][corr u32][payload]`. The host answers on a later turn of its
 *  own, never inside a frame, so nothing here re-enters this realm mid-record. */
entry("linkResp", (r) => {
  const from = r.blob();
  const corr = r.u32();
  const payload = r.blob();
  const meta = reqres.redeemInbound(from, corr);
  if (meta) reqres.respond(corr, meta.noReply, toHex(from), payload);
});

entry("linkClosed", (r) => {
  const link = findLink(r.u32());
  if (link) link.onChannelClosed();
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

entry("addr", (r) => {
  const peer = r.blob();
  core.addAddr(peer, r.blob());
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

// ── the host-managed link handle (openLink's LinkHandle) ──────────────────────

entry("linkSend", (r) => {
  const link = findLink(r.u32());
  if (link) link.send(r.blob().slice());
});

entry("linkClose", (r) => {
  const link = findLink(r.u32());
  if (link) link.close();
});
