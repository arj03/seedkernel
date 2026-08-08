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
