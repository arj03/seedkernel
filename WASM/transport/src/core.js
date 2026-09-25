// The link bookkeeping, the per-host state and the entrypoint. Last in the
// concatenation: it declares the state the earlier parts read at runtime.

// ── per-host state, read from the preamble ───────────────────────────────────
// Built during load, so invalid config fails the load (§12.4). Identity is `HOST`'s, the
// key `node/sign` signs with (§12.2).

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
 *  Each bounds a resource, so a missing one fails the load rather than running unbounded. */
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
 *  peer's contact secret and `dest` is `[scheme://]host:port[/path]` (bare means tcp). The
 *  host never reads it (§12.8). */
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
// every seal and open draws on (HOST). Requests stay below it by room for one max-size
// record, each weighing its bytes plus the per-call share (router.js `admits`).
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

// Every link by its platform id. An entry outlives teardown until its one `linkClosed`
// reads why the link went.
const linksById = new Map();

// ── deadlines ───────────────────────────────────────────────────────────────────
// Every link, correlation and `ready` waiter holds the `performance.now()` time it ends on
// (`Infinity`: none). The host's one wake (§12.3) is armed for the soonest; each wake
// walks them all (`onWake`) and re-arms.
const now = () => performance.now();
/** A refused close is asked again after this long (`Link.closeChannel`). */
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

/** Retire what is due and arm for the soonest deadline left; an early wake just re-arms. */
function onWake() {
  wakeAt = Infinity;
  walking = true;
  try {
    const t = now();
    wakeBy(reqres.onWake(t));
    wakeBy(core.checkReady(t));
    wakeBy(rtc.onWake(t));
    for (const link of linksById.values()) wakeBy(link.onWake(t));
  } finally {
    walking = false;
  }
  if (wakeAt < Infinity) arm(wakeAt);
}

// The link limiter (§12.6.2), in three tiers: `unverified` on accept, `verified` once a
// msg1 opens, `authed` for the link's whole life once the peer is proved. A full tier
// evicts its stalest occupant: longest-waiting when half-open, longest-quiet when authed
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

  /** A msg1 opened: off the contended budget, before the expensive work. */
  promote(slot) { return this.move(slot, "verified"); }

  /** The identity is proved and admitted. The slot stays until the link dies. */
  hold(slot) { return this.move(slot, "authed"); }

  /** Traffic on an authenticated link re-books it at the tail, so a full tier sheds its
   *  quietest link rather than its oldest busy one. */
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

  /** Out of its tier and off its source's tally, for good. */
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

// Proved msg1s, by the initiator's ephemeral key, so a replayed recording is refused: a
// msg1 is bound to nothing about its connection. Only proved ones are remembered, so a
// stranger cannot flush it; the oldest goes at the cap.
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

  /** Learn one peer: where to reach it and its contact secret. An empty `dest` is a peer
   *  we cannot dial but `ready` still waits for (a WebRTC peer from the relay). */
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
      const opened = await netLinkOpen(addr.dest);
      if (opened.linkId === 0) return; // no route
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

  /** An accepted channel or a fresh dial; `spec` passes through to `Link` whole. */
  openLink(spec) {
    const link = new Link({
      ...spec,
      onAuth: (pid, l) => this.onAuth(pid, l),
      onFrame: (pid, frame, pk) => reqres.onFrame(pid, frame, pk),
      onClose: (l) => this.forget(l),
    });
    linksById.set(link.linkId, link);
    // `connecting` steers outbound frames at a dial still handshaking.
    if (link.dialedPeerId) Core.push(this.connecting, link.dialedPeerId, link);
    return link;
  }

  onAuth(peerId, link) {
    Core.drop(this.connecting, link.dialedPeerId, link);
    router.promote(peerId, link);
  }

  /** A link leaving routing — the moment it closes, not once its teardown has run. */
  forget(link) {
    Core.drop(this.connecting, link.dialedPeerId, link);
    router.remove(link);
    // Its queued frames move to another link to the peer. A dial that dies as the last way
    // to its peer fails what waits on it now, not at its timeout.
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

  /** Send to a peer, dialing first if nothing routes to it. Answers whether a link took
   *  the frame; false is a frame dropped for want of a route. */
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

  /** Settle each waiter whose cohort is up or whose deadline has come (a caller that cares
   *  which reads `peers`). Answers the soonest deadline still waiting. */
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
for (const p of cohort) core.addAddr(p.peer, p.secret, p.dest);

// ── the one entrypoint ────────────────────────────────────────────────────────
//
// `handle([caller 32][body …])`, body an op envelope `[opLen u8][op][args]` (util.js
// `readOp`). The caller is the host (32 zero bytes: platform events and operator ops) or
// an app (its key), which may name only APP_OPS. Ops whose answer arrives as a later
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

/** The realm's one wake (§12.3): walk the deadlines (`onWake`). */
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

/** Bytes off one socket read, answered once decoded; decoded requests go out as their
 *  own `link/deliver` calls. */
entry("linkBytes", async (r) => {
  const link = linksById.get(r.u32());
  if (link) await link.onWire(r.blob());
  return NOTHING; // an async op bypasses `handle`'s `|| NOTHING`
});

/** The socket is gone. Answers `[severity u8][reason utf8]` (`closeReason`, ake.js), once
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

/** Teach one peer: key, contact secret and destination (`addAddr`). */
entry("addr", (r) => {
  const peer = r.blob();
  const secret = r.blob();
  core.addAddr(peer, secret, utf8Decode(r.blob()));
});

/** Join the WebRTC signaling relay at this `ws://`/`wss://` URL, leaving any other; empty
 *  leaves (rtc.js). */
entry("relay", async (r) => {
  await rtc.join(utf8Decode(r.blob()));
  return NOTHING;
});

/** `[state u8]`: 0 no relay joined, 1 its link is up, 2 joined and waiting to redial. */
entry("relayState", () => Uint8Array.of(rtc.state()));

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
