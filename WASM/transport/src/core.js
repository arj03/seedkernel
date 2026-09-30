// Link bookkeeping, per-node state and the entrypoint. Last in the concatenation, since
// it declares the state the earlier parts read at runtime.

// ── per-host state, read from the preamble ───────────────────────────────────
// Built during load, so invalid config fails the load (§12.4). The identity comes from
// `HOST`: the key `node/sign` signs with (§12.2).

const ownId = HOST.identity;            // the node channel public key, hex
const ownPk = fromHex(ownId);           // the same, 32 bytes
const ZERO32 = new Uint8Array(32);

const hex32 = (v) => typeof v === "string" && v.length === 64 && !/[^0-9a-f]/.test(v);

// Network separation, bound into the handshake root. Absent selects the public network.
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

/** One policy number: the installation's override, else the author's signed default.
 *  Each bounds a resource, so a missing one fails the load instead of running unbounded. */
function policy(name) {
  const v = LOCAL[name] ?? APP[name];
  if (!Number.isFinite(v) || v < 0) {
    throw new Error(`transport: config ${name} must be a non-negative finite number`);
  }
  return v;
}

const connsPerPeer = Math.max(1, policy("connsPerPeer"));
// The admit lint's peers as hex keys, or null to admit everyone (`admits`, ake.js).
const configuredAdmitPeers = LOCAL.admitPeers ?? APP.admitPeers;
if (!Array.isArray(configuredAdmitPeers)) throw new Error("transport: config admitPeers must be an array");
const admitPeers = configuredAdmitPeers.length > 0 ? new Set(configuredAdmitPeers) : null;
/** One cohort member as an operator types it: `pk[.secret]@dest`, where `.secret` is that
 *  peer's contact secret and `dest` is `[scheme://]host:port[/path]` (bare means tcp), or
 *  `relay+ws[s]://host:port` for a peer reached through that relay. The host never reads
 *  it (§12.8). */
function peerRef(spec) {
  const bad = (why) => new Error(`transport: config peers entry ${JSON.stringify(spec)}: ${why}`);
  if (typeof spec !== "string" || spec.indexOf("@") < 0) throw bad("want pk[.secret]@dest");
  const at = spec.indexOf("@");
  const [pk, secret, ...extra] = spec.slice(0, at).trim().toLowerCase().split(".");
  if (!hex32(pk) || extra.length > 0) throw bad("the key must be 64 hex characters");
  if (secret !== undefined && !hex32(secret)) throw bad("the contact secret must be 64 hex characters");
  const where = spec.slice(at + 1).trim();
  const dest = where.includes("://") ? where : "tcp://" + where;
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:\[[^\]]+\]|[^\s:/[\]]+):(\d{1,5})(?:\/\S*)?$/i.exec(dest);
  if (!m || Number(m[1]) < 1 || Number(m[1]) > 65535) throw bad("the destination must be [scheme://]host:port[/path]");
  if (dest.startsWith(RELAY_SCHEME) && !relayOrigin(dest.slice(RELAY_SCHEME.length))) {
    throw bad("a relay must be relay+ws:// or relay+wss://");
  }
  return { peer: fromHex(pk), secret: secret === undefined ? ZERO32 : fromHex(secret), dest };
}
const configuredPeers = LOCAL.peers ?? APP.peers;
if (!Array.isArray(configuredPeers)) throw new Error("transport: config peers must be an array");
const cohort = configuredPeers.map(peerRef);
const maxFrameBytes = policy("maxFrameBytes");
// Records waiting to be sealed, before any socket-side cap can see them.
const maxOutboundQueueBytes = 8 * maxFrameBytes;
const maxOutboundQueueSlices = 4096;
// A delivered request holds a host call and its bytes until answered, from the same budget
// every seal and open uses (HOST). Requests leave room in it for one max-size record, and
// each counts its bytes plus a per-call share (router.js `admits`).
const callWeight = HOST.maxOutstandingHostCallBytes / HOST.maxOutstandingHostCalls;
const maxRequestWeight = maxFrameBytes + PK_LEN + callWeight;
const deliveryWindow = HOST.maxOutstandingHostCallBytes - 2 * maxRequestWeight;
const maxPreAuthQueueSlices = Math.max(1, policy("maxPreAuthQueueSlices"));
const maxUnverified = policy("maxHalfOpenUnverified");
const maxPerSource = policy("maxHalfOpenPerSource");
const maxVerified = policy("maxHalfOpenVerified");
const maxAuthed = policy("maxAuthedLinks");
// Deadlines; 0 disables each.
// How long an authenticated link may carry no traffic.
const linkIdleTimeoutMs = policy("linkIdleTimeoutMs");
// How long an open correlation waits for its response: the transport's bound on its own
// state, not the caller's deadline, which the host owns.
const requestTimeoutMs = policy("requestTimeoutMs");
// The whole pre-auth handshake, and an accept's shorter clock until a msg1 opens.
const handshakeTimeoutMs = policy("handshakeTimeoutMs");
const unverifiedTimeoutMs = policy("unverifiedTimeoutMs");
// Frames per direction between key ratchets; both ends must agree.
const rekeyAfterFrames = Math.max(1, policy("rekeyAfterFrames"));

// Every link by its platform id. An entry stays after teardown until its `linkClosed`
// reads why the link closed.
const linksById = new Map();

// ── deadlines ───────────────────────────────────────────────────────────────────
// Every link, correlation and `ready` waiter holds the `performance.now()` time it expires
// (`Infinity` for none). The host's single wake (§12.3) is armed for the soonest; each
// wake walks them all (`onWake`) and re-arms.
const now = () => performance.now();
/** A refused close is retried after this long (`Link.closeChannel`). */
const CLOSE_RETRY_MS = 100;
let wakeAt = Infinity;  // when the armed wake fires
let armGen = 0;         // which arm is the latest, so a stale refusal changes nothing
let owedAt = Infinity;  // the latest arm was refused; the next event asks again for this
let walking = false;    // inside `onWake`, which arms once at the end

/** The time `ms` from now, with the wake armed to see it. */
function dueIn(ms) {
  const at = now() + ms;
  wakeBy(at);
  return at;
}

/** Make sure a wake comes by `at`. */
function wakeBy(at) {
  if (at >= wakeAt) return;
  wakeAt = at;
  if (!walking) arm(at);
}

function arm(at) {
  const gen = ++armGen;
  owedAt = Infinity;
  const ms = Math.min(0x7fffffff, Math.max(0, Math.ceil(at - now())));
  const refused = () => {
    if (gen !== armGen) return;
    wakeAt = Infinity;
    owedAt = at;
  };
  try { void host.call(N_TIMER_ARM, args([ms], [])).catch(refused); } catch { refused(); }
}

/** Expire what is due and arm for the soonest remaining deadline; an early wake just
 *  re-arms. */
function onWake() {
  wakeAt = Infinity;
  walking = true;
  try {
    const t = now();
    wakeBy(reqres.onWake(t));
    wakeBy(core.checkReady(t));
    wakeBy(relays.onWake(t));
    for (const link of linksById.values()) wakeBy(link.onWake(t));
  } finally {
    walking = false;
  }
  if (wakeAt < Infinity) arm(wakeAt);
}

// The link limiter (§12.6.2), in three tiers: `unverified` on accept, `verified` once a
// msg1 opens, `authed` for the link's whole life once the peer is proved. A full tier
// evicts its stalest member: longest waiting when half-open, longest quiet when authed
// (`touch`). The per-source cap spans all tiers and never evicts.
class LinkLimiter {
  constructor(maxUnverified, maxPerSource, maxVerified, maxAuthed) {
    this.maxPerSource = maxPerSource;
    this.max = { unverified: maxUnverified, verified: maxVerified, authed: maxAuthed };
    // One book per tier, in eviction order, keyed by the slot's `bookId`.
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

  /** A msg1 opened: move off the contended budget before the expensive work. */
  promote(slot) { return this.move(slot, "verified"); }

  /** The identity is proved and admitted. The slot stays until the link dies. */
  hold(slot) { return this.move(slot, "authed"); }

  /** Traffic on an authenticated link moves it to the tail, so a full tier sheds its
   *  quietest link, not its oldest busy one. */
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

  /** Make room for one slot, evicting the stalest if full. False only for a zero budget. */
  makeRoom(tier) {
    const book = this.books[tier];
    if (book.size < this.max[tier]) return true;
    const victim = book.values().next().value;
    if (victim === undefined) return false;
    this.release(victim);
    try { victim.evict(); } catch { /* already gone */ }
    return true;
  }

  /** Remove from its tier and its source's count, permanently. */
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

// ── the routing core ──────────────────────────────────────────────────────────

class Core {
  constructor() {
    this.connecting = new Map(); // peerId to Link[] (outbound, pre-auth)
    this.addrs = new Map();      // peerId to { dest, secret }: the address book
    this.readyWaiters = [];      // [{check, d, due}], one per in-flight ready()
    this.dialing = new Map();    // peerId to in-flight dial, so concurrent senders share one
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

  /** Record one peer: where to reach it and its contact secret. An empty `dest` is a peer
   *  this node cannot dial but `ready` still waits for. */
  addAddr(peerBytes, secret, dest) {
    this.addrs.set(toHex(peerBytes), { dest, secret: secret.length > 0 ? secret : null });
  }

  /** Top a peer up to connsPerPeer outbound links, one dial per peer at a time. */
  dial(peerId) {
    const inFlight = this.dialing.get(peerId);
    if (inFlight) return inFlight;
    const done = this.dialNow(peerId).finally(() => this.dialing.delete(peerId));
    this.dialing.set(peerId, done);
    return done;
  }

  async dialNow(peerId) {
    const addr = this.addrs.get(peerId);
    // Unknown or undialable: the frame waits for an inbound link or is dropped.
    if (!addr || addr.dest === "") return;
    const have = router.linkCount(peerId) + (this.connecting.get(peerId) || []).length;
    for (let n = have; n < connsPerPeer; n++) {
      if (!(await this.dialDest(peerId, addr.dest, addr.secret))) return; // no route
    }
  }

  /** Open one outbound link to `peerId` at `dest`, through the relay a `relay+` one names.
   *  The link, or null for no route. */
  async dialDest(peerId, dest, secret) {
    const relayed = dest.startsWith(RELAY_SCHEME);
    const opened = relayed
      ? await relays.call(peerId, relayOrigin(dest.slice(RELAY_SCHEME.length)))
      : { ...(await netLinkOpen(dest)), dest };
    if (opened.linkId === 0) return null;
    return this.openLink({
      linkId: opened.linkId,
      stream: opened.stream,
      dest: opened.dest,
      weDialed: true,
      linkSecret: secret,
      limiter: null,
      dialedPeerId: peerId,
      relayed,
      ticket: opened.ticket,
    });
  }

  /** An accepted channel or a fresh dial; `spec` passes through to `Link` whole. */
  openLink(spec) {
    const link = new Link({
      ...spec,
      onAuth: (pid, l) => this.onAuth(pid, l),
      onFrame: (pid, frame, pk, l) => (frame[0] === KIND_CTL ? this.onControl(pid, frame, l) : reqres.onFrame(pid, frame, pk)),
      onClose: (l) => this.forget(l),
    });
    linksById.set(link.linkId, link);
    // `connecting` steers outbound frames at a dial still handshaking.
    if (link.dialedPeerId) Core.push(this.connecting, link.dialedPeerId, link);
    return link;
  }

  /** A link authenticated. A relayed one starts the move to WebRTC; a direct one this end
   *  accepted retires the relayed links it replaces (router.js `retireRelayed`). */
  onAuth(peerId, link) {
    Core.drop(this.connecting, link.dialedPeerId, link);
    router.promote(peerId, link);
    if (!router.routes(link)) return;
    if (link.relayed) void rtc.upgrade(peerId).catch(() => {});
    else if (!link.weDialed) {
      router.retireRelayed(peerId);
    }
  }

  /** The transport's own message from a peer (router.js `KIND_CTL`): a retire closes a
   *  relayed link once a direct one routes, and otherwise leaves it to the idle clock. */
  onControl(peerId, frame, link) {
    const tag = frame[1];
    if (tag !== CTL_RETIRE) rtc.receive(peerId, tag, frame.subarray(2));
    else if (link.relayed && router.hasDirect(peerId)) link.close();
  }

  /** A link leaving routing, as soon as it closes, not once its teardown has run. */
  forget(link) {
    Core.drop(this.connecting, link.dialedPeerId, link);
    router.remove(link);
    if (link.ticket) relays.tickets.delete(link.ticket);
    // Its queued frames move to another link to the peer. A dial that dies as the last way
    // to its peer fails what waits on it now, not at its timeout.
    const peerId = link.peerId || link.dialedPeerId;
    if (peerId) {
      for (const frame of link.takeQueued()) this.place(peerId, frame);
      if (!link.authed && router.linkCount(peerId) === 0 && !this.connecting.has(peerId)) {
        reqres.peerDown(peerId);
      }
    }
    // Left in `linksById`: `linkClosed` still has to ask why it closed.
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

  /** Send to a peer, dialing first if nothing routes to it. Returns whether a link took
   *  the frame; false means it was dropped for lack of a route. */
  async sendFrame(to, frame) {
    if (to === ownId) return false;
    if (this.place(to, frame)) return true;
    if (!this.addrs.has(to)) return false;
    await this.dial(to);
    return this.place(to, frame);
  }

  /** Settle `d` once every known peer is authenticated, or the deadline passes. */
  ready(d, timeoutMs) {
    const targets = [...this.addrs.keys()].filter((p) => p !== ownId);
    for (const p of targets) void this.dial(p);
    const allUp = () => targets.every((p) => router.linkCount(p) >= 1);
    if (allUp()) { d.settle(EMPTY); return; }
    this.readyWaiters.push({ check: allUp, d, due: dueIn(timeoutMs) });
  }

  /** Settle each waiter whose cohort is up or whose deadline has passed (a caller that
   *  needs to know which can read `peers`). Returns the soonest deadline still waiting. */
  checkReady(t = now()) {
    let next = Infinity;
    for (const w of [...this.readyWaiters]) {
      if (!w.check() && t < w.due) { next = Math.min(next, w.due); continue; }
      this.readyWaiters.splice(this.readyWaiters.indexOf(w), 1);
      w.d.settle(EMPTY);
    }
    return next;
  }
}

const router = new Router(ownPk);
const reqres = new ReqRes();
const core = new Core();
const rtc = new Rtc();
const relays = new Relays();
for (const p of cohort) core.addAddr(p.peer, p.secret, p.dest);

// ── the one entrypoint ────────────────────────────────────────────────────────
//
// `handle([caller 32][body ...])`, where body is an op envelope `[opLen u8][op][args]`
// (`readOp`). The caller is the host (32 zero bytes: platform events and operator ops) or
// an app (its id), which may only name APP_OPS. Ops whose answer comes in a later
// invocation use `defer()`, so they do not hold the realm's queue (realm-queue.ts).

const NOTHING = new Uint8Array(0);

// Answer on a later turn; `__deferred` tells the host the realm is free.
const defer = () => {
  let settle, fail;
  const promise = new Promise((res, rej) => { settle = res; fail = rej; });
  globalThis.__deferred = true;
  return { promise, settle, fail };
};

const ops = Object.create(null);
function entry(name, fn) { ops[name] = fn; }

/** The ops an app may name; null-prototype, so `toString` is not one. */
const APP_OPS = Object.assign(Object.create(null), { send: 1, peers: 1 });

function handle(argBytes) {
  const { fromHost, caller, body } = callerOf(argBytes);
  if (owedAt < Infinity) wakeBy(owedAt);
  const { op, args } = readOp(body);
  const r = new Reader(args);
  const fn = ops[op];
  if (!fn) throw new Error("transport: no op '" + op + "'");
  // The caller id is written by the host, so this is a real boundary.
  if (!fromHost && !APP_OPS[op]) throw new Error("transport: '" + op + "' is the host's, not an app's");
  return fn(r, caller) || NOTHING;
}

/** The realm's wake (§12.3): walk the deadlines (`onWake`). */
entry("wake", () => { onWake(); });

/** Platform-opened link event (§12.2): an accepted socket, or a WebRTC data channel that
 *  arrived through the negotiation link named by `via`. */
entry("linkOpen", (r) => {
  const linkId = r.u32();
  const stream = r.u8() === 1;
  const listener = r.blob();
  const via = r.u32();
  const source = r.blob();
  if (via !== 0) { rtc.bindData(via, linkId, stream); return; }
  core.openLink({
    linkId, weDialed: false, stream,
    listener: listener.length > 0 ? utf8Decode(listener) : "",
    dest: "",
    linkSecret: null,
    source: source.length > 0 ? utf8Decode(source) : undefined,
    limiter: core.limiter, // accepts spend half-open budget; dials do not
    dialedPeerId: null,
  });
});

/** Bytes from one socket read, answered once decoded; decoded requests go out as their
 *  own `link/deliver` calls. */
entry("linkBytes", async (r) => {
  const link = linksById.get(r.u32());
  if (link) await link.onWire(r.blob());
  return NOTHING; // an async op bypasses `handle`'s `|| NOTHING`
});

/** The socket closed. Answers `[severity u8][reason utf8]` (`closeReason`, ake.js), once
 *  per link. */
entry("linkClosed", (r) => {
  const linkId = r.u32();
  const link = linksById.get(linkId);
  if (!link) return NOTHING;
  link.onChannelClosed();
  linksById.delete(linkId);
  const why = link.closeReason;
  return concatBytes([Uint8Array.of(ROUTINE_REASONS.has(why) ? 0 : 1), utf8Encode(why)]);
});

/** App-facing send, deferred: the response is another invocation of this realm. */
entry("send", (r, caller) => {
  const noReply = r.u8() === 1;
  // Views, copied into the frame synchronously by `buildReq`.
  const to = r.blob();
  const proto = r.blob();
  const payload = r.blob();
  // Checked before any copy, and loud: a caller error.
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

/** Add one peer: key, contact secret and destination (`addAddr`). */
entry("addr", (r) => {
  const peer = r.blob();
  const secret = r.blob();
  core.addAddr(peer, secret, utf8Decode(r.blob()));
});

/** Register on the relay at this `ws://`/`wss://` URL, so peers can reach this node through
 *  it, leaving any other; empty leaves (relay.js). Deferred: registering waits on the relay's
 *  challenge, which arrives in a later invocation. */
entry("relay", (r) => {
  const d = defer();
  relays.join(utf8Decode(r.blob())).then(() => d.settle(NOTHING), d.fail);
  return d.promise;
});

/** `[state u8]`: 0 no relay, 1 registered on it, 2 waiting to redial it. */
entry("relayState", () => Uint8Array.of(relays.state()));

/** Rotate the inbound contact secret (§12.6.3). */
entry("contact", (r) => {
  const secret = r.blob();
  if (secret.length !== 0 && secret.length !== PK_LEN) {
    throw new Error("transport: contact needs 32 bytes, or none for an open node");
  }
  contactSecret = secret.length === 0 ? ZERO32 : secret.slice();
});

/** Wait until every known peer is linked, or the deadline passes. */
entry("ready", (r) => {
  const d = defer();
  core.ready(d, r.u32());
  return d.promise;
});

/** The peers holding an authenticated link, as raw 32-byte keys. */
entry("peers", () => {
  const out = [];
  for (const pool of router.pools.values()) out.push(pool.links[0].peerPubkey);
  return concatBytes(out);
});

// No `shutdown` op: the host closes its own sockets and timers (transport-host.ts `close`).
