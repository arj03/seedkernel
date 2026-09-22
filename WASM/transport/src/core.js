// ============================================================================
// transport/src/core.js — the link bookkeeping, the per-host state, and the
// entrypoints the host invokes by name. Last part of the concatenation: it declares
// the state the earlier parts read at runtime.
// ============================================================================

// ── per-host state, read from the preamble ───────────────────────────────────
// Identity comes from `HOST`, which the host fills from the keypair `node/sign` signs
// with, so the two cannot drift (§12.2). Everything here is built during load, so invalid
// config fails the load (§12.4) and the first invocation finds the program ready.

const ownId = HOST.identity;            // the node channel public key, hex
const ownPk = fromHex(ownId);           // the same, 32 bytes
const ZERO32 = new Uint8Array(32);

const hex32 = (v) => typeof v === "string" && v.length === 64 && !/[^0-9a-f]/.test(v);

// Network separation belongs to the transport's handshake, including its signed root.
// Absent selects the public network; malformed explicit values fail the load.
if (LOCAL.networkKey !== undefined && !hex32(LOCAL.networkKey)) {
  throw new Error("transport: config networkKey must be 64 lowercase hex characters");
}
const networkKey = LOCAL.networkKey === undefined ? ZERO32 : fromHex(LOCAL.networkKey);

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
// These policies and their defaults belong to this signed program. LOCAL is the
// installation's general override path; APP is the author's signed fallback.
const maxFrameBytes = policy("maxFrameBytes");
// Work waiting to be sealed has not reached a socket adapter yet, so its socket-side cap
// cannot see it. Give it the same eight-frame byte window and tiny-write count ceiling.
const maxOutboundQueueBytes = 8 * maxFrameBytes;
const maxOutboundQueueSlices = 4096;
// A request handed to `link/deliver` holds one of this realm's host calls and its bytes until
// its claimant answers. Every record open, seal and teardown draws on that same budget (HOST),
// and one it refuses takes a link down with it, so waiting requests stay below the budget by
// room for a max-size record open and its plaintext. Each weighs its bytes plus the budget's
// bytes per call, which bounds both of its ceilings in one sum (router.js `admits`); the
// widest is a whole frame plus the attribution its delivery adds.
const callWeight = HOST.maxOutstandingHostCallBytes / HOST.maxOutstandingHostCalls;
const maxRequestWeight = maxFrameBytes + PK_LEN + callWeight;
const deliveryWindow = HOST.maxOutstandingHostCallBytes - 2 * maxRequestWeight;
const maxPreAuthQueueSlices = Math.max(1, policy("maxPreAuthQueueSlices"));
const maxUnverified = policy("maxHalfOpenUnverified");
const maxPerSource = policy("maxHalfOpenPerSource");
const maxVerified = policy("maxHalfOpenVerified");
const maxAuthed = policy("maxAuthedLinks");
// How long an AUTHENTICATED link may carry no traffic before it is retired; 0 disables.
const linkIdleTimeoutMs = policy("linkIdleTimeoutMs");
// How long one open correlation is retained waiting for its peer's response; 0 disables.
// Not the caller's deadline — the kernel owns that and no field here can name it — but the
// transport's bound on its own waiting state. It gives the caller time to ask someone else
// only when configured shorter than that caller's live remainder; otherwise the kernel
// deadline wins and this timer cleans the correlation afterwards.
const requestTimeoutMs = policy("requestTimeoutMs");
// How long a link may stay pre-authentication: the dialing side's whole handshake, and
// the shorter clock an accept runs until a msg1 opens under the contact secret. 0
// disables, like every other deadline here.
const handshakeTimeoutMs = policy("handshakeTimeoutMs");
const unverifiedTimeoutMs = policy("unverifiedTimeoutMs");
// Frames per direction between key ratchets — a deployment-wide constant BOTH ends must
// share; a mismatch desynchronizes the record layer and the link dies.
const rekeyAfterFrames = Math.max(1, policy("rekeyAfterFrames"));

// Every link by the id the platform names it with. Outlives the link's own teardown on
// purpose: `linkClosed` arrives a turn later, and its return is the only thing that carries
// WHY the link went. Bounded — ids are never reused, and the driver answers every link with
// exactly one `linkClosed`, which drains the entry.
const linksById = new Map();

// ── deadlines ───────────────────────────────────────────────────────────────────
// A zero-authority realm has no clock, so a deadline here is a count of the host's one wake
// (§12.3). Each wake is a tick, and every link, open correlation and `ready` waiter holds the
// tick it ends on — no timer per deadline, one walk per tick (`onWake`). A tick is 100 ms, or
// the shortest configured timeout when that is shorter.
const tickMs = Math.max(1, Math.ceil(Math.min(100,
  ...[linkIdleTimeoutMs, requestTimeoutMs, handshakeTimeoutMs, unverifiedTimeoutMs].filter((ms) => ms > 0))));
let tick = 0;
let waking = false;   // the wake is armed
let wakeOwed = false; // its arm was refused, so the next event asks again

/** The tick by which `ms` has surely passed. A tick already under way counts for nothing, so
 *  a deadline runs up to two ticks long and never short. */
function dueTick(ms) {
  const due = tick + Math.max(1, Math.ceil(ms / tickMs)) + (waking ? 1 : 0);
  wake();
  return due;
}

/** Arm the wake unless it is armed. It is never cleared, so every wake that arrives is a tick. */
function wake() {
  if (waking) return;
  waking = true;
  wakeOwed = false;
  try { void host.call(N_TIMER_ARM, args([tickMs, 0], [])).catch(wakeRefused); } catch { wakeRefused(); }
}

/** Refused by this realm's host-call budget, which frees up on its own. Failing the deadlines
 *  over it would close every link at once, so they stand until an event re-arms (`dispatch`). */
function wakeRefused() {
  waking = false;
  wakeOwed = true;
}

/** One tick: retire what is due, and arm again while anything still waits. */
function onWake() {
  waking = false;
  tick++;
  let waiting = reqres.onTick();
  if (core.checkReady()) waiting = true;
  for (const link of linksById.values()) if (link.onTick()) waiting = true;
  if (waiting) wake();
}

// The link limiter, over budgets from LOCAL (§12.6.2). THREE tiers: a slot is acquired
// when a socket is accepted, moves to `verified` when a msg1 opens under the contact
// secret, and to `authed` once the peer's identity is proved and admitted — HELD there
// for the link's whole life. Each tier evicts its own stalest occupant when full, so a
// newcomer that has proved more than the incumbents is never refused at the door. Stalest
// means longest-waiting in the half-open tiers, where waiting is all an occupant does, and
// longest-QUIET in `authed`, where the incumbents have all proved the same thing and the
// one carrying nothing is the one worth losing (`touch`).
// Per-source is not evictable and spans all three tiers.
class LinkLimiter {
  constructor(maxUnverified, maxPerSource, maxVerified, maxAuthed) {
    this.maxPerSource = maxPerSource;
    this.max = { unverified: maxUnverified, verified: maxVerified, authed: maxAuthed };
    // One book per tier, whose SIZE is that tier's occupancy; book order is the eviction
    // policy. A slot carries the id it was booked under, so leaving a tier is a delete
    // rather than a scan for itself — the scan was O(n) per move, which is O(n²) across
    // filling and promoting a full tier, and unauthenticated inbound connections are what
    // drive it.
    this.books = { unverified: new Map(), verified: new Map(), authed: new Map() };
    this.nextId = 0;
    this.perSource = new Map();
  }

  acquire(source, evict) {
    if (source !== undefined && (this.perSource.get(source) || 0) >= this.maxPerSource) return null;
    if (!this.makeRoom("unverified")) return null;
    const slot = { source, tier: "unverified", released: false, evict, limiter: this, bookId: this.nextId++ };
    if (source !== undefined) this.perSource.set(source, (this.perSource.get(source) || 0) + 1);
    this.books.unverified.set(slot.bookId, slot);
    return slot;
  }

  /** A msg1 opened under the contact secret: off the contended budget, before the
   *  expensive work. */
  promote(slot) { return this.move(slot, "verified"); }

  /** The identity is proved and admitted. The slot stays until the link dies. */
  hold(slot) { return this.move(slot, "authed"); }

  /** Something crossed an authenticated link: re-book it at the tail. Eviction takes the
   *  head, so this makes a full authed tier shed the link that has been quiet longest
   *  instead of the one admitted longest — without it, anyone who can complete handshakes
   *  walks established, busy peers off the node one fresh connection at a time. */
  touch(slot) {
    if (slot.released || slot.tier !== "authed") return;
    this.books.authed.delete(slot.bookId);
    slot.bookId = this.nextId++;
    this.books.authed.set(slot.bookId, slot);
  }

  move(slot, tier) {
    if (slot.released || slot.tier === tier) return true;
    if (!this.makeRoom(tier)) return false;
    this.unbook(slot);
    slot.tier = tier;
    slot.bookId = this.nextId++;
    this.books[tier].set(slot.bookId, slot);
    return true;
  }

  /** Make one slot's worth of room in a tier, evicting its stalest occupant if it is
   *  full. False only when the tier's budget is zero — nothing to evict and no room. */
  makeRoom(tier) {
    const book = this.books[tier];
    if (book.size < this.max[tier]) return true;
    const victim = book.values().next().value;
    if (victim === undefined) return false;
    this.release(victim);
    try { victim.evict(); } catch { /* already gone */ }
    return true;
  }

  /** Out of its tier and off its source's tally, for good: a slot never returns. */
  release(slot) {
    if (slot.released) return;
    this.unbook(slot);
    slot.released = true;
    if (slot.source === undefined) return;
    const n = this.perSource.get(slot.source);
    if (n === undefined) return;
    if (n <= 1) this.perSource.delete(slot.source); else this.perSource.set(slot.source, n - 1);
  }

  unbook(slot) {
    this.books[slot.tier].delete(slot.bookId);
  }
}

// A msg1 that opened under the contact secret, remembered by the initiator's ephemeral
// key — fresh per link for any honest dialer, so a second sighting is a RECORDING being
// replayed. Nothing in a msg1 binds it to the connection carrying it, so this memory is
// what makes the proof single-use: one captured message would otherwise buy promotion out
// of the contended tier, the DH and encapsulation behind it, and an answer from a node
// otherwise silent to strangers, as often as it is sent. Only a PROVED msg1 is remembered,
// so a stranger cannot flush it; the oldest goes at the cap, and a fresh realm starts empty.
const MAX_SEEN_PROBES = 4096;
const seenProbes = new Set();
function probeSeen(ephI) { return seenProbes.has(toHex(ephI)); }
function rememberProbe(ephI) {
  if (seenProbes.size >= MAX_SEEN_PROBES) seenProbes.delete(seenProbes.values().next().value);
  seenProbes.add(toHex(ephI));
}

// ── the routing core ──────────────────────────────────────────────────────────

class Core {
  constructor() {
    this.connecting = new Map(); // peerId → Link[] (outbound, pre-auth)
    this.addrs = new Map();      // peerId → { dest, secret } — this program's address book
    this.readyWaiters = [];      // [{check, d, due}] — one per in-flight ready()
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
        linkSecret: addr.secret,
        limiter: null,
        dialedPeerId: peerId,
      });
    }
  }

  // An inbound (accepted) channel, or a link we just dialed. The spec IS the link's own
  // description, so it is passed through whole: a field its callers fill is a field `Link`
  // reads, with no second spelling here to keep in step. Only the callbacks are ours.
  openLink(spec) {
    const link = new Link({
      ...spec,
      onAuth: (pid, l) => this.onAuth(pid, l),
      onFrame: (pid, frame, pk) => reqres.onFrame(pid, frame, pk),
      onClose: (l) => this.forget(l),
    });
    linksById.set(link.linkId, link);
    // `connecting` is keyed by peer because it is what steers an outbound frame at a link
    // that has not authenticated yet. An accept, or a dial whose peer we cannot name, steers
    // nothing, so until it authenticates it is on `linksById` alone. (`spec.weDialed` is
    // still passed to `Link`; it decides who speaks first.)
    if (link.dialedPeerId) Core.push(this.connecting, link.dialedPeerId, link);
    return link;
  }

  onAuth(peerId, link) {
    Core.drop(this.connecting, link.dialedPeerId, link);
    // The peer lint already answered at msg3/msg4, so a refused peer never reaches the
    // router. Only routing is left.
    router.promote(peerId, link);
  }

  /** A link leaving routing — the moment it closes, not once its teardown has run. */
  forget(link) {
    Core.drop(this.connecting, link.dialedPeerId, link);
    router.remove(link);
    // What still waits in its queue never left. Another link to the same peer carries it —
    // the winner of a double-connect tie-break, or a second dial — and a dial that dies as
    // the last way to its peer fails what waits on that peer now, not at its retention
    // timeout. (An authenticated link's last departure is the router's down edge.)
    const peerId = link.peerId || link.dialedPeerId;
    if (peerId) {
      for (const frame of link.takeQueued()) this.place(peerId, frame);
      if (!link.authed && router.linkCount(peerId) === 0 && !this.connecting.has(peerId)) reqres.peerDown(peerId);
    }
    // Left in `linksById`: `linkClosed` has yet to ask why it went.
  }

  /** Put a frame on a link that can carry it to `to`: an authenticated one, else the queue
   *  of a dial still handshaking. False when there is neither. */
  place(to, frame) {
    if (router.send(to, frame)) return true;
    const pool = this.connecting.get(to);
    if (!pool || pool.length === 0) return false;
    pool[0].send(frame);
    return true;
  }

  // A frame for a peer with no routable link yet: dial, then hand the frame to the
  // link that lands (it queues pre-auth). The dial is shared per peer (`dial`), so a
  // burst of frames to one unreachable peer costs one open. Answers whether a link took
  // the frame: false is a frame dropped for want of a route — no address, or a dial that
  // opened nothing — as a fabric with no route drops it.
  async sendFrame(to, frame) {
    if (to === ownId) return false;
    if (this.place(to, frame)) return true;
    if (!this.addrs.has(to)) return false;
    await this.dial(to);
    return this.place(to, frame);
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
    this.readyWaiters.push({ check: allUp, d, due: dueTick(timeoutMs) });
  }

  /** Settle each waiter whose cohort is up or whose deadline tick has come. Either way: the
   *  caller asked to WAIT for the cohort, not to be told whether it arrived — one that cares
   *  reads `peers`. Run on each up edge and each tick; answers whether any still wait. */
  checkReady() {
    for (const w of [...this.readyWaiters]) {
      if (!w.check() && tick < w.due) continue;
      this.readyWaiters.splice(this.readyWaiters.indexOf(w), 1);
      w.d.settle(EMPTY);
    }
    return this.readyWaiters.length > 0;
  }
}

// The one router, request/response layer and routing core per host instance, wired
// during load: none of it asks the host for anything.
const router = new Router(ownPk);
const reqres = new ReqRes();
const core = new Core();
for (const p of cohort) core.addAddr(p.peer, p.secret, p.dest);

// ── the one entrypoint ────────────────────────────────────────────────────────
//
// Reached as an app is: `handle([caller 32][body …])`, body an op envelope
// `[opLen u8][op][args]` (util.js `readOp`) — this bundle's envelope, which is how an
// app's `send` and the host's own events land on one entrypoint. The op is a NAME, not a
// tag byte — an unimplemented op fails loud. The one body without a name is the host's
// wake: four bytes, shorter than any envelope (`onWake`).
//
// Two kinds of caller, told apart by those 32 bytes and nothing else:
//   the HOST  32 zero bytes — the platform's events: sockets opening, bytes
//              arriving, an address, a wake, and the operator's `ready`/`peers`.
//   an APP    its app key, exactly as an inbound frame carries the authenticated
//              sender's key. `send` is the only op an app may name.
//
// Most ops answer with `NOTHING` and work by calling out. Three have an answer, two of
// which cannot be answered or awaited in the same turn — the events that settle them
// arrive as further invocations, which would queue behind the frame doing the awaiting
// (realm-queue.ts). They use `defer()` (below).

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

function handle(argBytes) {
  const { fromHost, caller, body } = callerOf(argBytes);
  if (wakeOwed) wake();
  if (fromHost && body.length === 4) { onWake(); return NOTHING; }
  const { op, args } = readOp(body);
  const r = new Reader(args);
  const fn = ops[op];
  if (!fn) throw new Error("transport: no op '" + op + "'");
  // The platform's events are the host's alone; the caller id is the host's to write,
  // so this is a real boundary and not a hint.
  if (!fromHost && !APP_OPS[op]) throw new Error("transport: '" + op + "' is the host's, not an app's");
  return fn(r, caller) || NOTHING;
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
    linkSecret: null,
    source: source.length > 0 ? utf8Decode(source) : undefined,
    // Only an accept spends half-open budget; a dial is our own decision to make.
    limiter: weDialed ? null : core.limiter,
    // The identity a platform-initiated dial expects; an accept's is not ours to demand.
    dialedPeerId: weDialed && expectPeerId.length > 0 ? toHex(expectPeerId) : null,
  });
});

/** Bytes off one socket read. Awaits the READ's own decoding — framing, the handshake
 *  step, the AEAD — but answers nothing: a request it decoded goes to the host as this
 *  program's own `link/deliver` call, on a later turn. */
entry("linkBytes", async (r) => {
  const link = linksById.get(r.u32());
  if (link) await link.onWire(r.blob());
  // Explicit, because this op is `async`: `handle`'s `|| NOTHING` sees a truthy Promise
  // and never applies, so a bare `undefined` here would reach the seam's return check.
  return NOTHING;
});

/** The socket is gone. The return is the one-byte reason (`closeReason`, ake.js) — a fact
 *  only this program ever held, since it is the end with the session keys, and the driver
 *  prints the non-routine ones so a node that cannot reach its cohort says why. It carries
 *  no link id: the event names the link, so a return cannot speak about another socket, and
 *  a link already reported is off `linksById` and answers nothing a second time. */
entry("linkClosed", (r) => {
  const linkId = r.u32();
  const link = linksById.get(linkId);
  if (!link) return NOTHING;
  link.onChannelClosed();
  linksById.delete(linkId);
  return Uint8Array.of(link.closeReason);
});

/** App-facing send: deferred because the peer's response is another invocation of this
 *  realm. Its deadline is kernel handoff state, not a field in this content protocol. */
entry("send", (r, caller) => {
  const noReply = r.u8() === 1;
  // VIEWS of the caller's argument bytes, and they stay views: `buildReq` gathers both
  // into the frame synchronously, before this handler returns. A defensive copy here
  // would buy no ownership boundary and walk the payload a second time.
  const to = r.blob();
  const proto = r.blob();
  const payload = r.blob();
  // Measured BEFORE anything is copied: a co-resident app naming a 50 MiB payload would
  // take this realm down before the frame it was refused for existed. A caller error, so
  // it is LOUD — the silent drop in Link.send is for a frame we chose to build.
  if (to.length !== PK_LEN) throw new Error("transport: send needs a 32-byte peer id");
  if (proto.length > 0xff) throw new Error("transport: protocol id too long");
  if (REQ_HEAD_LEN + proto.length + payload.length > maxFrameBytes - TAG_LEN) {
    throw new Error("transport: send over the frame cap");
  }
  if (noReply) {
    reqres.request(null, toHex(to), proto, payload, true);
    return Uint8Array.from([1]);
  }
  const d = defer();
  reqres.request(d, toHex(to), proto, payload, false);
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
  for (const pool of router.pools.values()) out.push(pool.links[0].peerPubkey);
  return concatBytes(out);
});

// There is deliberately no `shutdown` entrypoint. Teardown releases sockets and timers,
// both the HOST's, and it closes them itself (transport-host.ts `close`) rather than
// asking an occupant that must not be able to refuse. What is left is this realm's heap,
// which dies with the realm.
