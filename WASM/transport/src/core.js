// ============================================================================
// transport/src/core.js — the link bookkeeping (ex net-route.ts NodeNetworkCore),
// the per-host state, and the entrypoints the host invokes by name. This is the
// last part of the concatenation: it declares the state the earlier parts read
// at runtime and registers the whole program's face to the host.
// ============================================================================

// ── per-host state, set by EVT_INIT ───────────────────────────────────────────

let ownPk = null;          // 32B node channel public key
let ownId = "";            // its hex — the peer id
let networkKey = null;     // 32B
let contactSecret = null;  // 32B — OUR inbound gate (zeros = open)
let connsPerPeer = 1;
// The operator's peer list, as a Set of hex keys — or null for "admit everyone". A
// LINT applied by `admits` (ake.js), not a gate, and configuration rather than a seam:
// the host ships it at init and never asks about a peer again.
let admitPeers = null;
// The node's fallback request deadline, learned at init. A caller that names its own
// overrides it; this is the number that has to be right for one that did not think
// about it. Resolved here now that the request path is entirely ours.
let requestDeadlineMs = 10000;
// The peers we hold at least one authenticated link to. It lives here because it is a
// fact about links, and links are ours — the host asks for it with the `peers` op
// rather than keeping a mirror it would have to be told about.
const connected = new Set();
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

// ── the routing core (ex net-route.ts NodeNetworkCore) ────────────────────────

class Core {
  constructor() {
    this.connecting = new Map(); // peerId → Link[] (outbound, pre-auth)
    this.inbound = new Set();    // accepted, pre-auth
    this.addrs = new Map();      // peerId → 32B contact secret (or null = open)
    this.readyWaiters = [];      // [{check, d, timer}] — one per in-flight ready()
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
    // The peer lint already answered, at msg3 or msg4 — a link that reaches auth is one
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
  //
  // `d` is the deferred the `ready` op's invocation returned. The answer is that op's
  // return value now, rather than a `transport/ready` call back to a waiter the host was
  // holding — so there is no waiter to join, overwrite or leak, and a second `ready`
  // while one is in flight simply supersedes it.
  ready(d, timeoutMs) {
    const targets = [...this.addrs.keys()].filter((p) => p !== ownId);
    for (const p of targets) this.dial(p);
    const allUp = () => targets.every((p) => router.linkCount(p) >= 1);
    if (allUp()) { d.settle(EMPTY); return; }
    // A LIST, not a slot. Two callers may be waiting at once — each holds its own
    // deferred and its own deadline — and a single slot would let the second strand
    // the first, which is a bug this design inherited rather than invented.
    const w = { check: allUp, d, timer: 0 };
    w.timer = armTimer(timeoutMs, () => {
      this.dropWaiter(w);
      // Settles either way: the caller asked to wait for the cohort, not to be told
      // whether it arrived, and every caller that cares reads `peers` afterwards.
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
  requestDeadlineMs = cfg.requestDeadlineMs;
  // An empty list means "admit everyone", said as a zero-length blob rather than a
  // missing field — one shape to read.
  admitPeers = cfg.admitPeers.length > 0 ? new Set(cfg.admitPeers) : null;

  router = new Router(ownPk, ownId);
  reqres = new ReqRes();
  core = new Core();
  connected.clear();
  reqres.attach((to, frame) => core.sendFrame(to, frame));
  router.sink = (from, frame) => reqres.onFrame(from, frame);
  // The cohort edges stay in this heap. Nothing host-side is told about them any more:
  // what the host used to do with a peer edge was maintain a mirror of this set, and it
  // reads the set itself now (the `peers` op).
  router.onPeerUp = (peerId) => { connected.add(peerId); core.checkReady(); };
  router.onPeerDown = (peerId) => { connected.delete(peerId); };
}

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

// ── the one entrypoint ────────────────────────────────────────────────────────
//
// This program is reached exactly as an app is: the manifest claims `_net` (§12.10) and
// `handle` is invoked with `[caller 32][opLen u8][op][args]`. Two kinds of caller, told
// apart by those 32 bytes and nothing else:
//
//   the HOST   32 zero bytes (transport-host.ts) — the platform's own events: the config
//              turn, sockets opening, bytes arriving, an address, and the two questions
//              the operator's console asks (`ready`, `peers`).
//   an APP     its app key, derived host-side from the admitted manifest, exactly as an
//              inbound frame carries the authenticated sender's key. `send` is the only
//              op an app may name; anything else is refused, because the platform's
//              events are not an app's to fake.
//
// The op is a NAME, not a tag byte. Collapsing twelve entrypoints onto one call must not
// smuggle in a number two sides have to agree on — that is what the per-entrypoint
// dispatch was right about — so the discriminator stays a string and an op this program
// does not implement fails loud by name.
//
// Most ops answer with `NOTHING` and do their work by calling out. Three genuinely have
// an answer: `send` (the peer's response), `ready` (the cohort arrived) and `peers`. The
// first two cannot be answered in the same turn, and cannot be AWAITED either — the
// events that settle them arrive as further invocations of this same realm, which would
// queue behind the frame doing the awaiting (realm-queue.ts). They use `defer()`.
//
// A deferred teardown (Link's over-budget path) is flushed at the end of whichever op
// provoked it, so a link's bookkeeping is never undone by an onClose that ran before its
// caller finished.

const NOTHING = new Uint8Array(0);
const ZERO32 = new Uint8Array(32);

const ops = Object.create(null);
function entry(name, fn) { ops[name] = fn; }

/** The ops an app may name, as opposed to the platform events the host alone writes.
 *  A lookup rather than a chain of `!==`, so adding one is adding a key. Null-prototype
 *  like `ops` itself: an inherited `toString` would otherwise read as an admitted op. */
const APP_OPS = Object.assign(Object.create(null), { send: 1, peers: 1 });

register("handle", (argBytes) => {
  // The envelope is the guest ABI's, read with the preamble's own two functions
  // (guest-seam.ts) rather than open-coded here: this program and the host write and
  // read the same bytes, so they are described in one place.
  const { fromHost, caller, body } = callerOf(argBytes);
  const { op, args } = readOp(body);
  const r = new Reader(args);
  const fn = ops[op];
  if (!fn) throw new Error("transport: no op '" + op + "'");
  // The platform's events are the host's alone. An app that could spell `init` could
  // re-key the node; one that could spell `linkBytes` could inject a frame on any link.
  // The caller id is the host's to write, so this is a real boundary and not a hint.
  //
  // Two ops are an APP's to name, and they are the two that were app-facing names before
  // this bundle existed: `send` (was `net/send`) and `peers` (was `net/peers`). Both are
  // questions about the app's own traffic rather than levers on the platform — `peers`
  // reads the authenticated set, which is what an app placing replicas has to know. The
  // rest stay the host's.
  if (!APP_OPS[op] && !fromHost) throw new Error("transport: '" + op + "' is the host's, not an app's");
  try {
    return fn(r, caller) || NOTHING;
  } finally {
    const deferred = deferQueue.splice(0);
    for (const f of deferred) { try { f(); } catch { /* teardown of a gone link */ } }
  }
});

/** The one config turn: who we are, which network, and the budgets — including the
 *  HOST's flood cap, which this module learns rather than declares.
 *
 *  There is no request-timing config here. A deadline is per request, not per node, so
 *  it rides on `request` instead — which is also what leaves the host's default in one
 *  place (transport-host.ts) rather than mirrored on both sides of the seam. */
entry("init", (r) => {
  const cfg = {
    ownPk: r.blob(), networkKey: r.blob(), contactSecret: r.blob(),
    connsPerPeer: r.u32(),
    maxUnverified: r.u32(), maxPerSource: r.u32(), maxVerified: r.u32(),
    maxFrameBytes: r.u32(),
    maxHandshakeFrameBytes: r.u32(),
    requestDeadlineMs: r.u32(),
    admitPeers: [],
  };
  const list = new Reader(r.blob());
  while (list.off < list.b.length) cfg.admitPeers.push(toHex(list.blob()));
  init(cfg);
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
      // The peer lint answered at msg3/msg4 (`admits`); what is left is ours — the
      // double-connect tie-break. The host is told only because IT owns this socket
      // and handed it over, so whoever passed it in is waiting to hear.
      if (!router.promote(peerId, l)) { l.close(); return; }
      hostLinkAuth(linkId, fromHex(peerId));
    },
    onFrame: (peerId, frame) => router.deliver(peerId, frame),
    onClose: () => {
      openLinks.delete(linkId);
      router.remove(link);
      hostLinkDown(linkId, reasonCode(link));
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

// A fired deadline, and the ONE other entrypoint this program registers. It is not an
// op on `handle` because it is not a call: it is the shell's per-realm timer table
// re-entering the realm that armed it (shell-core.ts), and every guest that declares
// `timer/*` gets the same one. Nothing about it is the transport's.
register("timer", (argBytes) => {
  fireTimer(readU32BE(argBytes, 0));
  const deferred = deferQueue.splice(0);
  for (const f of deferred) { try { f(); } catch { /* teardown of a gone link */ } }
  return NOTHING;
});

/** THE app-facing op — one of the two an app may name (`APP_OPS`). `[noReply u8][deadlineMs u32]
 *  [to blob][proto blob][payload blob]` in, `[ok u8][response]` out — the same answer
 *  shape the retired `net/send` name had, because it is the same question.
 *
 *  `deadlineMs` 0 means the caller named none and takes the node's default. Resolving it
 *  here rather than host-side is not a move of policy: the default is a CONFIG value the
 *  host ships at init, and this is simply where the config now lives.
 *
 *  The answer cannot be produced in this turn — the peer's response arrives as another
 *  invocation of this realm — and cannot be awaited either, for exactly that reason. So
 *  the op returns a deferred and `ReqRes` settles it. A noReply send has no answer to
 *  wait for and says so immediately.
 *
 *  `caller` is unused today beyond the boundary check above. It is the app's key,
 *  prepended host-side like an inbound frame's sender, and it is what a future
 *  per-app accounting or rate limit would key on without any new seam. */
entry("send", (r, caller) => {
  const noReply = r.u8() === 1;
  const deadlineMs = r.u32() || requestDeadlineMs;
  const to = r.blob();
  const proto = r.blob().slice();
  const payload = r.blob().slice();
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
 *  reason `send` is: the up edge that settles it is another invocation of this realm. */
entry("ready", (r) => {
  const d = defer();
  core.ready(d, r.u32());
  return d.promise;
});

/** The peers we hold at least one authenticated link to, as raw 32-byte keys. Answered
 *  in the same turn — it is a read of this heap, not a question about the wire.
 *
 *  An app's to name as well as the host's (`APP_OPS`): "who am I linked to" is what an
 *  app placing replicas across a cohort has to know, and it was an app-facing name
 *  (`net/peers`) before the transport became a bundle. */
entry("peers", () => {
  const out = [];
  for (const p of connected) out.push(fromHex(p));
  return concatBytes(out);
});

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
