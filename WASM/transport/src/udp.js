// UDP paths (§12.7): a direct path between two nodes whose hosts lend this transport raw
// datagram sockets (`link/udpBind`), with no WebRTC. A negotiation here speaks the same
// messages as the host's `rtc:` negotiation links (direct.js), so signaling is the same for
// both kinds. What differs is what the messages hold:
//
//   description  this end's token, 8 random bytes in hex, which every probe to it carries
//   candidate    an IPv4 `host:port` or IPv6 `[host]:port` this end's socket may be
//                reached at: its own addresses, then what each STUN server sees; or
//                `host:*`, this end's NAT gives each destination its own port (below)
//
// Punching is ICE's idea without its machinery. Once an end has the peer's token and a
// candidate it probes every candidate until one answers, and the first answer is its path.
// A probe leaving through a NAT opens it for the peer's probes back, so two ends whose
// NATs keep one public port per socket meet. Nothing here is trusted beyond the token:
// the path is a QUIC connection (quic.js) whose handshake is the link's own, so only the
// peer the negotiation names can complete it.
//
// A socket is dual-stack where the machine has IPv6. An IPv6 address is mostly routed end
// to end, behind a firewall that lets replies in, which the same probes open as they open
// a NAT that keeps one port, so two ends with IPv6 meet whatever NATs their IPv4 is
// behind. The STUN servers are asked over IPv4: an IPv6 address needs no one to name it.
//
// A NAT that gives each destination its own random port (endpoint-dependent mapping, a
// symmetric NAT) is hard: its STUN address is good for the STUN server alone. Two STUN
// answers that differ tell an end it is behind one, and it says so with a `host:*`
// candidate. Against a NAT that filters, the plain punch then cannot meet, so after
// `BIRTHDAY_AFTER_MS` without a path the two ends play the birthday paradox, as Tailscale
// does: the hard end opens `BIRTHDAY_SOCKETS` more sockets, each probing the peer and so
// opening a port of its own toward it, and the easy end, whose two answers agreed, probes
// random ports at the hard end's address until one of its probes lands on one of them.
// Two hard ends cannot meet this way, and stay on the relay.
//
//   PROBE      [type][receiver's token 8][sender's token 8][challenge 8]
//   PROBE_ACK  [type][receiver's token 8][the probe's challenge 8]
//
// A probe carries its sender's token, so it can be answered, and a random challenge. The
// token is in every probe in the clear and so proves nothing; the offering end takes the path
// only on an ack that echoes the challenge from the address it was sent to, which only
// something that received the probe can send. A probe can be answered before the peer's
// description has come the long way round, and its source is a candidate too.
//
// The offering end then dials the connection from the socket the ack came to, to the path's
// address, and the answering end takes the socket the first QUIC packet reaches it on, from
// an address whose probe it has seen, as its path. Every QUIC packet has the fixed bit
// (0x40) set and the probes have it clear, so one byte tells them apart; a STUN answer is
// told apart by its cookie. Past the punch, QUIC is the path: a peer whose NAT moves it is followed once the
// new address answers a challenge only the peer can, since QUIC seals that too.
//
// The host reads none of it (§12.7): what its sockets read comes as one `datagrams` event
// a turn, and what this end sends goes out as one `link/udpSend` a turn.

const N_UDP_BIND = "link/udpBind";
const N_UDP_SEND = "link/udpSend";
const N_UDP_CLOSE = "link/udpClose";

/** The probes' types, with QUIC's fixed bit clear (the header). */
const TYPE_PROBE = 0x30, TYPE_PROBE_ACK = 0x31;
const QUIC_FIXED_BIT = 0x40;
const TOKEN = 8, SEED = 32;
const PROBE_BYTES = 1 + 2 * TOKEN + 8, PROBE_ACK_BYTES = 1 + TOKEN + 8;
/** How often every candidate is probed until one answers. */
const PROBE_MS = 50;
/** The most of a peer's candidates probed. The peer names them, so without a cap it could
 *  aim this node's probes at any number of addresses. */
const MAX_PEER_CANDIDATES = 16;
const STUN_TRIES = 4, STUN_RETRY_MS = 500;
/** How long the plain punch has before a hard NAT is played for (the header). */
const BIRTHDAY_AFTER_MS = 1000;
/** The hard end's extra sockets, and so the ports it opens toward the peer, and how many
 *  binds it has asked the host for at once, which share the realm's host-call budget. */
const BIRTHDAY_SOCKETS = 256, BIRTHDAY_BINDS = 8;
/** The sockets all a node's birthday punches at once may hold, since each punch wants
 *  `BIRTHDAY_SOCKETS` and the transport may run many negotiations: without a shared ceiling
 *  a peer (or a relay forcing `host:*`) could make a node open tens of thousands at once.
 *  A spray holds the same share, which bounds the node's concurrent sprays too. */
const MAX_NODE_BIRTHDAY_SOCKETS = 1024;
/** The easy end's random probes: how many each `PROBE_MS` to each of the peer's `host:*`,
 *  and how many in all, since the peer names those addresses. With 256 ports open among
 *  the 64,512 a NAT draws from, a probe lands with odds of 1 in 252, so the first 1,160
 *  land one 99 times in 100, and all 4,096 miss about once in 10^7. */
const SPRAY_EACH = 64, SPRAY_MAX = 4096;
/** The ports a NAT maps to: those above the privileged ones. */
const SPRAY_LOW = 1024, SPRAY_PORTS = 65536 - SPRAY_LOW;
/** What one `link/udpSend` carries at most, so a burst does not take the host-call budget
 *  the record layer shares. */
const SEND_BATCH = 256 * 1024;
const DESCRIPTION = /^[0-9a-f]{16}$/;
/** The addresses whose probes the answering end has seen, any of which its connection may
 *  come from: a peer's are a handful. */
const MAX_PROBED = 64;
const CANDIDATE = /^(?:((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})|\[([0-9a-f:]{2,39})\]):(\d{1,5}|\*)$/;

// ── STUN ──────────────────────────────────────────────────────────────────────
// Binding (RFC 8489), the one request a path makes of a server: what address the internet
// sees this socket at. The request carries no attributes and only XOR-MAPPED-ADDRESS is
// read from the answer, which is all a server must send, and all seedrelay's `--stun` does.

const STUN_COOKIE = 0x2112a442;
const STUN_BINDING_REQUEST = 0x0001, STUN_BINDING_SUCCESS = 0x0101, STUN_XOR_MAPPED_ADDRESS = 0x0020;

/** A Binding request under transaction id `txn` (12 bytes). */
function bindingRequest(txn) {
  const out = new Uint8Array(20);
  writeU16BE(out, 0, STUN_BINDING_REQUEST);
  writeU32BE(out, 4, STUN_COOKIE);
  out.set(txn, 8);
  return out;
}

/** Whether a datagram is STUN at all, which a path's own packets never are: STUN's first
 *  two bits are zero, and its cookie follows the length. */
function isStun(msg) {
  return msg.length >= 20 && msg[0] < 2 && readU32BE(msg, 4) === STUN_COOKIE;
}

/** The `host:port` a Binding success for `txn` names, or null for anything else. */
function mappedAddress(msg, txn) {
  if (readU16BE(msg, 0) !== STUN_BINDING_SUCCESS || readU16BE(msg, 2) !== msg.length - 20) return null;
  if (bytesCompare(msg.subarray(8, 20), txn) !== 0) return null;
  for (let at = 20; at + 4 <= msg.length; at += 4 + ((readU16BE(msg, at + 2) + 3) & ~3)) {
    const len = readU16BE(msg, at + 2);
    if (at + 4 + len > msg.length) return null;
    if (readU16BE(msg, at) !== STUN_XOR_MAPPED_ADDRESS || len !== 8 || msg[at + 5] !== 1) continue;
    // The port XORed with the cookie's top half, the address with the cookie.
    const port = readU16BE(msg, at + 6) ^ (STUN_COOKIE >>> 16);
    return `${msg[at + 8] ^ msg[4]}.${msg[at + 9] ^ msg[5]}.${msg[at + 10] ^ msg[6]}.${msg[at + 11] ^ msg[7]}:${port}`;
  }
  return null;
}

// ── addresses ─────────────────────────────────────────────────────────────────

/** An address, as sent to: `port` 0 is `host:*`, any port of a hard NAT. `b` is the host as
 *  `link/udpSend` takes it: `[4][ip 4]` or `[16][ip 16]`, or a name as `[0][len u8][name]`. */
function addrOf(host, port) { return { host, port, b: hostBytes(host) }; }

function hostBytes(host) {
  if (host.includes(":")) return concatBytes([Uint8Array.of(16), ipv6Bytes(host)]);
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (v4) return Uint8Array.of(4, ...v4.slice(1).map(Number));
  const name = utf8Encode(host);
  return concatBytes([Uint8Array.of(0, name.length), name]);
}

/** The 16 bytes of an IPv6 address in the shape `isIPv6` takes. */
function ipv6Bytes(text) {
  const [head, tail] = text.split("::");
  const groups = (part) => (part ? part.split(":").map((g) => parseInt(g, 16)) : []);
  const front = groups(head), back = groups(tail);
  const all = tail === undefined ? front : [...front, ...new Array(8 - front.length - back.length).fill(0), ...back];
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) writeU16BE(out, 2 * i, all[i]);
  return out;
}

/** Whether `text` is an IPv6 address in lowercase hex: eight groups, or fewer around one
 *  `::`, with no zone and no IPv4 tail. */
function isIPv6(text) {
  const halves = text.split("::");
  if (halves.length > 2) return false;
  const groups = halves.flatMap((h) => (h === "" ? [] : h.split(":")));
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return false;
  return halves.length === 2 ? groups.length <= 7 : groups.length === 8;
}

/** The 16 bytes of an IPv6 address at `at`, as RFC 5952 writes them: lowercase, no leading
 *  zeros, and the longest run of two or more zero groups, the first of equals, as `::`. */
function ipv6Text(b, at = 0) {
  const g = [];
  let run = -1, runLen = 1;
  for (let i = 0, zeros = 0; i < 8; i++) {
    const v = readU16BE(b, at + 2 * i);
    g.push(v.toString(16));
    zeros = v === 0 ? zeros + 1 : 0;
    if (zeros > runLen) { run = i - zeros + 1; runLen = zeros; }
  }
  return run < 0 ? g.join(":") : `${g.slice(0, run).join(":")}::${g.slice(run + runLen).join(":")}`;
}

/** `host:port`, with an IPv6 host in brackets. */
const endpoint = (host, port) => (host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`);

function candidateOf(text) {
  const m = CANDIDATE.exec(text);
  if (!m || (m[2] !== undefined && !isIPv6(m[2]))) return null;
  const host = m[1] ?? m[2];
  if (m[3] === "*") return addrOf(host, 0);
  const port = Number(m[3]);
  return port > 0 && port < 65536 ? addrOf(host, port) : null;
}

/** Of a host's addresses (`link/udpBind`), the candidates: the outward IPv4 ones, or
 *  loopback on a machine with none, then IPv6 but for loopback and link-local, which needs
 *  a zone no candidate carries. */
function hostCandidates(text) {
  const all = text.toLowerCase().split("\n").filter((a) => a !== "");
  const v4 = all.filter((a) => !a.includes(":"));
  const outward = v4.filter((a) => !a.startsWith("127."));
  const v6 = all.filter((a) => a.includes(":") && a !== "::1" && !/^fe[89ab]/.test(a));
  return [...(outward.length > 0 ? outward : v4), ...v6];
}

/** The `stun:` servers of an RTCConfiguration's `iceServers`. */
function stunServers(iceServers) {
  const out = [];
  for (const s of iceServers) {
    for (const u of [s && s.urls].flat()) {
      const m = typeof u === "string" ? /^stun:([\w.-]{1,253})(?::(\d{1,5}))?$/.exec(u) : null;
      if (m) out.push(addrOf(m[1], m[2] ? Number(m[2]) : 3478));
    }
  }
  return out;
}

// ── the sockets ───────────────────────────────────────────────────────────────

/** This realm's datagram sockets, by host id, and the negotiations they serve. */
class Udp {
  constructor() {
    this.listeners = new Map(); // socket id to its negotiation
    this.live = new Set();      // negotiations, for the wake
    /** Connections that took packets in this event, for one call each after it. */
    this.turns = [];
    /** What goes out this turn, as `link/udpSend` takes it. */
    this.out = new Uint8Array(SEND_BATCH);
    this.outLen = 0;
    this.flushDue = false;
    this.flushNow = () => { this.flushDue = false; this.flush(); };
    /** Birthday sockets this node may still open, shared across every negotiation. */
    this.birthdayBudget = MAX_NODE_BIRTHDAY_SOCKETS;
    /** Ids for links this realm runs itself: past any the host gives. */
    this.nextLocalId = 2 ** 32;
  }

  nextId() { return this.nextLocalId++; }

  takeSockets(n) {
    const got = Math.min(n, this.birthdayBudget);
    this.birthdayBudget -= got;
    return got;
  }

  freeSockets(n) { this.birthdayBudget += n; }

  /** A negotiation for `offer`ing or answering, not yet started (`start`); null when the
   *  host has no socket for it, which the transport takes as no route. */
  async open(offer, iceServers) {
    const stun = stunServers(iceServers);
    const socket = await this.bind();
    if (!socket) return null;
    let entropy;
    try {
      entropy = await randomBytes(2 * TOKEN + SEED + 12 * stun.length);
    } catch {
      this.close(socket.id);
      return null;
    }
    return new UdpNegotiation(offer, stun, socket, entropy);
  }

  /** `{id, port, addresses}` on `port`, or one the OS picks for 0; or null. */
  async bind(port = 0) {
    let r;
    try { r = await host.call(N_UDP_BIND, port ? Uint8Array.of(port >> 8, port & 0xff) : EMPTY); } catch { return null; }
    const id = readU32BE(r, 0);
    return id === 0 ? null : { id, port: readU16BE(r, 4), addresses: utf8Decode(r.subarray(6)) };
  }

  /** Send `p` from socket `id` to `to`, at `port` if given, with the turn's others. */
  sendto(id, to, p, port = to.port) {
    const need = 8 + to.b.length + p.length;
    if (this.outLen + need > this.out.length) this.flush();
    const o = this.out;
    let at = this.outLen;
    writeU32BE(o, at, id);
    o.set(to.b, at + 4);
    at += 4 + to.b.length;
    writeU16BE(o, at, port);
    writeU16BE(o, at + 2, p.length);
    o.set(p, at + 4);
    this.outLen = at + 4 + p.length;
    if (!this.flushDue) {
      this.flushDue = true;
      void Promise.resolve().then(this.flushNow);
    }
  }

  /** Datagrams already in `link/udpSend`'s shape (quic.js), behind what this turn sent. */
  send(batch) {
    this.flush();
    try { void host.call(N_UDP_SEND, batch).catch(() => {}); } catch { /* lost */ }
  }

  /** What this turn sent, in one host call. One the budget refuses is lost datagrams, which
   *  the connection recovers. */
  flush() {
    if (this.outLen === 0) return;
    const batch = this.out.slice(0, this.outLen);
    this.outLen = 0;
    try { void host.call(N_UDP_SEND, batch).catch(() => {}); } catch { /* lost */ }
  }

  listen(id, negotiation) { this.listeners.set(id, negotiation); }

  /** Close a socket, behind what it has sent. */
  close(id) {
    this.listeners.delete(id);
    this.flush();
    callRetried(N_UDP_CLOSE, argU32(id));
  }

  /** One `datagrams` event: `[socket u32][batch blob]` until the end, each batch the
   *  platform's `[n u8][ip n][port u16][len u16][bytes]`, n 4 for IPv4 and 16 for IPv6. */
  onDatagrams(r) {
    while (r.more()) {
      const id = r.u32(), b = r.blob();
      const to = this.listeners.get(id);
      if (!to) continue;
      // A socket of QUIC's alone (`QuicListener`, `QuicDial`) reads its batch itself.
      if (to.onBatch) { to.onBatch(b); continue; }
      // The connection takes the batch whole; past the punch nothing else here reads it.
      const fed = to.quic !== null;
      if (fed) to.quic.feed(b);
      if (to.path) continue;
      // A batch is mostly one peer's, so its address is spelled once, not once a datagram:
      // an IPv4 one is told from the last by its four bytes as a number, an IPv6 one by
      // comparing its sixteen bytes with the last's (`v6`, their offset in the batch).
      let from = "", ip = -1, v6 = -1;
      for (let at = 0; at + 5 <= b.length;) {
        const n = b[at++];
        if (n === 4) {
          const v = readU32BE(b, at);
          if (v !== ip) { ip = v; from = `${b[at]}.${b[at + 1]}.${b[at + 2]}.${b[at + 3]}`; }
          v6 = -1;
        } else {
          let same = v6 >= 0;
          for (let i = 0; same && i < 16; i++) {
            same = b[v6 + i] === b[at + i];
          }
          if (!same) {
            from = ipv6Text(b, at);
          }
          ip = -1;
          v6 = at;
        }
        at += n;
        const len = readU16BE(b, at + 2);
        to.onPacket(id, b.subarray(at + 4, at + 4 + len), from, readU16BE(b, at), b.subarray(at - n - 1, at + 2));
        at += 4 + len;
      }
      // The answering end's connection began in this batch (`take`): it has it whole.
      if (!fed && to.quic) to.quic.feed(b);
    }
    this.runTurns();
  }

  /** One call for each connection that took packets since the last of these. */
  runTurns() {
    const turns = this.turns;
    this.turns = [];
    for (const s of turns) s.turn();
  }

  /** Listen for QUIC on `port` (`QuicListener`): the port bound, or 0 for none. */
  async listenQuic(port) {
    const socket = await this.bind(port);
    if (!socket) return 0;
    let key;
    try { key = await randomBytes(SEED); } catch { this.close(socket.id); return 0; }
    // It holds its socket and its wake, which hold it.
    new QuicListener(socket, key);
    return socket.port;
  }

  /** Dial a `quic://` destination (`quicTarget`) from a socket of its own:
   *  `{linkId, channel}`, the channel the connection, or null for no route. */
  async dialQuic(dest) {
    const remote = quicTarget(dest);
    const socket = remote && (await this.bind());
    if (!socket) return null;
    let seed;
    try { seed = await randomBytes(SEED); } catch { this.close(socket.id); return null; }
    const linkId = this.nextId();
    const owner = { onBatch: (b) => { quic.feed(b); }, onWake: (t) => quic.onWake(t) };
    const quic = new QuicPath(() => {
      this.live.delete(owner);
      this.close(socket.id);
      localClosed(linkId);
    });
    this.listen(socket.id, owner);
    this.live.add(owner);
    quic.open(seed, socket.id, remote, true);
    return { linkId, channel: quic };
  }

  /** One wake (core.js `onWake`): every negotiation's timers, and the soonest next. */
  onWake(t) {
    let next = Infinity;
    for (const n of this.live) next = Math.min(next, n.onWake(t));
    return next;
  }
}

// ── one negotiation ───────────────────────────────────────────────────────────

/** A negotiation: its sockets, its candidates and the punch, and the connection that becomes
 *  the data link once a path is found. A local link to direct.js, under its own id. */
class UdpNegotiation {
  constructor(offer, stun, socket, entropy) {
    this.offer = offer;
    this.linkId = udp.nextId();
    this.token = entropy.subarray(0, TOKEN);
    /** The token as two words, which every probe is checked against. */
    this.tokenHi = readU32BE(this.token, 0);
    this.tokenLo = readU32BE(this.token, 4);
    /** The challenge every probe carries, which an ack must echo for the path to be taken. */
    this.challenge = entropy.subarray(TOKEN, 2 * TOKEN);
    /** This end's seed for its connection (quic.js). */
    this.seed = entropy.subarray(2 * TOKEN, 2 * TOKEN + SEED);
    const txns = 2 * TOKEN + SEED;
    /** The STUN servers not yet answered, and each one's answer, the address it saw. */
    this.asking = stun.map((server, i) => ({ server, txn: entropy.subarray(txns + 12 * i, txns + 12 * i + 12) }));
    this.mapped = [];
    /** direct.js's side: `up(tag, text)`, `open(linkId, channel)` and `closed(linkId)`. */
    this.sink = null;
    this.peerToken = null;
    this.peerCandidates = [];
    /** `socket host port` of each probe the answering end has seen (`MAX_PROBED`). */
    this.probed = new Set();
    /** The addresses of a hard peer's NAT, from its `host:*` candidates. */
    this.peerHard = [];
    this.own = new Set();
    /** Own candidates found before the description is up, which must go first. */
    this.held = [];
    /** The socket the STUN servers are asked from, and the path's once there is one. */
    this.socket = socket.id;
    this.port = socket.port;
    this.addresses = socket.addresses;
    /** A hard end's birthday sockets until a path is found: null until they are asked
     *  for. */
    this.extra = null;
    /** Whether the punch is over: this end has its path, and its connection on it. */
    this.path = false;
    this.quic = null;
    /** The next probe round, and the rounds sent; the next STUN retry, and those left. */
    this.roundAt = Infinity;
    this.rounds = 0;
    this.stunAt = Infinity;
    this.stunTries = STUN_TRIES;
    this.spraying = false;
    this.sprayed = 0;
    /** Birthday sockets taken from the node-wide budget, returned once a path is found or
     *  the negotiation ends. */
    this.reservedExtra = 0;
    this.dead = false;
    this.dataId = 0;
    udp.listen(this.socket, this);
  }

  /** Begin, telling `sink`: the offer's description first, then the candidates. */
  start(sink) {
    this.sink = sink;
    udp.live.add(this);
    if (this.offer) this.describe();
    for (const a of hostCandidates(this.addresses)) this.addOwn(endpoint(a, this.port));
    this.askStun();
    this.probe();
  }

  /** The description, then the candidates that waited for it. */
  describe() {
    this.up(this.offer ? RTC_OFFER : RTC_ANSWER, toHex(this.token));
    const held = this.held ?? [];
    this.held = null;
    for (const c of held) this.up(RTC_CANDIDATE, c);
  }

  up(tag, text) { if (!this.dead && this.sink) this.sink.up(tag, text); }

  addOwn(c) {
    if (this.own.has(c)) return;
    this.own.add(c);
    if (this.held) this.held.push(c);
    else this.up(RTC_CANDIDATE, c);
  }

  addPeer(c) {
    if (this.peerCandidates.length + this.peerHard.length >= MAX_PEER_CANDIDATES) return;
    if (c.port === 0) {
      if (this.peerHard.some((h) => h.host === c.host)) return;
      this.peerHard.push(c);
      this.birthday();
      return;
    }
    if (this.peerCandidates.some((p) => p.host === c.host && p.port === c.port)) return;
    this.peerCandidates.push(c);
    if (this.extra && this.extra.length > 0) {
      const p = this.probePacket();
      for (const id of this.extra) udp.sendto(id, c, p);
    }
    this.probe();
  }

  /** Ask every STUN server not yet answered, `STUN_RETRY_MS` apart, `STUN_TRIES` times. */
  askStun() {
    this.stunAt = Infinity;
    if (this.dead || this.stunTries === 0 || this.asking.length === 0) return;
    this.stunTries--;
    for (const a of this.asking) udp.sendto(this.socket, a.server, bindingRequest(a.txn));
    this.stunAt = dueIn(STUN_RETRY_MS);
  }

  /** A STUN server's answer: a candidate, and with two that differ, `host:*` for each
   *  address seen, since this end's NAT gives each destination its own port. */
  onMapped(addr) {
    this.addOwn(addr);
    this.mapped.push(addr);
    if (this.hard()) {
      for (const m of this.mapped) this.addOwn(`${m.slice(0, m.lastIndexOf(":"))}:*`);
    }
    this.birthday();
  }

  hard() { return this.mapped.some((m) => m !== this.mapped[0]); }
  /** Two STUN servers saw this socket at one address: its NAT keeps one port for all. */
  easy() { return this.mapped.length >= 2 && !this.hard(); }

  /** `[PROBE][peer's token][own token][challenge]`. */
  probePacket() {
    const p = new Uint8Array(PROBE_BYTES);
    p[0] = TYPE_PROBE;
    p.set(this.peerToken, 1);
    p.set(this.token, 1 + TOKEN);
    p.set(this.challenge, 1 + 2 * TOKEN);
    return p;
  }

  /** Start the probe rounds, once there is someone to probe. */
  probe() {
    if (this.dead || this.path || this.roundAt < Infinity || !this.peerToken || this.peerCandidates.length === 0) return;
    this.round();
  }

  /** Probe every candidate the peer has, a round each `PROBE_MS` until a path is found, and
   *  once spraying, random ports at a hard peer's addresses too (the header). */
  round() {
    this.roundAt = Infinity;
    if (this.dead || this.path) return;
    const p = this.probePacket();
    for (const c of this.peerCandidates) udp.sendto(this.socket, c, p);
    if (this.spraying && this.sprayed < SPRAY_MAX) {
      for (const h of this.peerHard) {
        for (let i = 0; i < SPRAY_EACH; i++) udp.sendto(this.socket, h, p, SPRAY_LOW + Math.floor(Math.random() * SPRAY_PORTS));
      }
      this.sprayed += SPRAY_EACH * this.peerHard.length;
    }
    if (++this.rounds * PROBE_MS === BIRTHDAY_AFTER_MS) this.birthday();
    this.roundAt = dueIn(PROBE_MS);
  }

  /** Once the plain punch has had its time, a hard end facing an easy one opens its
   *  birthday sockets, and an easy end facing a hard one sprays (the header). Each waits
   *  for what it needs to know, and each happens once. */
  birthday() {
    if (this.rounds * PROBE_MS < BIRTHDAY_AFTER_MS || this.dead || this.path || !this.peerToken) return;
    if (this.hard() && this.peerHard.length === 0 && this.peerCandidates.length > 0 && this.extra === null) {
      this.extra = [];
      this.reservedExtra = udp.takeSockets(BIRTHDAY_SOCKETS);
      let left = this.reservedExtra;
      const next = () => {
        if (left === 0 || this.dead || this.path) return;
        left--;
        void udp.bind().then((s) => { this.addExtra(s); next(); });
      };
      for (let i = 0; i < BIRTHDAY_BINDS; i++) next();
    }
    // A spray holds a birthday's share of the node budget, so a peer cannot aim many
    // negotiations' probes at once; one refused goes on with the plain punch.
    if (!this.spraying && this.easy() && this.peerHard.length > 0) {
      const got = udp.takeSockets(BIRTHDAY_SOCKETS);
      if (got === BIRTHDAY_SOCKETS) {
        this.reservedExtra = got;
        this.spraying = true;
      } else {
        udp.freeSockets(got);
      }
    }
  }

  /** A birthday socket, bound: it probes the peer, and so opens a port toward it. */
  addExtra(s) {
    if (!s) return;
    if (this.dead || this.path) { udp.close(s.id); return; }
    this.extra.push(s.id);
    udp.listen(s.id, this);
    const p = this.probePacket();
    for (const c of this.peerCandidates) udp.sendto(s.id, c, p);
  }

  /** One datagram, to socket `id` from `host`:`port`, which `addr` is as the batch spells it
   *  (`[n u8][ip n][port u16]`). Its bytes are this realm's. */
  onPacket(id, p, host, port, addr) {
    if (this.dead || port < 1 || p.length === 0) return;
    if (isStun(p)) {
      for (let i = 0; i < this.asking.length; i++) {
        const mapped = mappedAddress(p, this.asking[i].txn);
        if (mapped) { this.asking.splice(i, 1); this.onMapped(mapped); return; }
      }
      return;
    }
    // QUIC: the answering end's path, from an address whose probe it has seen.
    if (p[0] & QUIC_FIXED_BIT) {
      if (!this.offer && !this.path && this.probed.has(`${id} ${host} ${port}`)) this.take(id, addr);
      return;
    }
    if (p.length < PROBE_ACK_BYTES || readU32BE(p, 1) !== this.tokenHi || readU32BE(p, 5) !== this.tokenLo) return;
    if (p[0] === TYPE_PROBE) {
      if (p.length !== PROBE_BYTES) return;
      this.peerToken ??= p.slice(1 + TOKEN, 1 + 2 * TOKEN);
      if (this.probed.size < MAX_PROBED) this.probed.add(`${id} ${host} ${port}`);
      const from = { host, port, b: addr.slice(0, -2) };
      // The ack is the probe from the sender's token on, its type written over the last
      // byte of this end's token.
      p[TOKEN] = TYPE_PROBE_ACK;
      udp.sendto(id, from, p.subarray(TOKEN));
      // Probe back from this socket, so this end's own challenge makes the round trip here
      // and the path can be taken, even when the source is a candidate already known (which
      // a birthday socket's peer always is) and the probe rounds would not reach it.
      if (!this.path) udp.sendto(id, from, this.probePacket());
      this.addPeer(from);
    } else if (p[0] === TYPE_PROBE_ACK) {
      if (p.length !== PROBE_ACK_BYTES) return;
      if (this.offer && bytesCompare(p.subarray(1 + TOKEN), this.challenge) === 0) this.choose(id, addr);
    }
  }

  /** The offering end's path is the peer's address `addr` from socket `id`, which may be a
   *  birthday socket: the connection is dialed there. */
  choose(id, addr) {
    if (this.path || !this.peerToken) return;
    this.take(id, addr.slice());
  }

  /** The path is socket `id`'s, which may be a birthday socket, to the peer at `remote`: the
   *  other sockets close, the STUN servers are not asked again, and the connection, which
   *  the offering end dials there and the answering end takes from there alone, goes to
   *  direct.js as the data link, whose handshake is the connection's. */
  take(id, remote) {
    this.path = true;
    this.keepOnly(id);
    this.stopPunching();
    this.quic = new QuicPath(() => this.onQuicGone());
    this.quic.open(this.seed, this.socket, remote, this.offer);
    this.dataId = udp.nextId();
    this.sink.open(this.dataId, this.quic);
  }

  /** The connection stopped, for whatever reason, which ends the negotiation, and once it
   *  has said so, its last socket. */
  onQuicGone() {
    if (this.dead) this.keepOnly(0);
    else this.close();
  }

  /** A description or candidate from the peer, which direct.js has from the authenticated
   *  link; one malformed ends the negotiation. */
  down(tag, text) {
    if (this.dead) return;
    if (tag === RTC_OFFER || tag === RTC_ANSWER) {
      // An offer reaches only the answering side, an answer only the offering one.
      if ((tag === RTC_OFFER) === this.offer || !DESCRIPTION.test(text)) { this.close(); return; }
      if (this.peerToken) return;
      this.peerToken = fromHex(text);
      if (tag === RTC_OFFER) {
        // Up on a later turn, not inside the signal being applied.
        void Promise.resolve().then(() => {
          if (!this.dead && this.held) this.describe();
        });
      }
      this.probe();
    } else if (tag === RTC_CANDIDATE) {
      const c = candidateOf(text);
      if (!c) { this.close(); return; }
      this.addPeer(c);
    } else {
      this.close();
    }
  }

  onWake(t) {
    if (this.dead) return Infinity;
    if (t >= this.stunAt) this.askStun();
    if (t >= this.roundAt) this.round();
    return Math.min(this.stunAt, this.roundAt, this.quic ? this.quic.onWake(t) : Infinity);
  }

  /** End the negotiation and its data link, whoever asked. A connection still open closes
   *  first, telling the peer, and the path's socket goes once it has. */
  close() {
    if (this.dead) return;
    this.dead = true;
    this.stopPunching();
    if (this.quic && !this.quic.gone) {
      this.keepOnly(this.path ? this.socket : 0);
      this.quic.end();
    } else {
      this.keepOnly(0);
    }
    udp.live.delete(this);
    if (!this.sink) return;
    if (this.dataId !== 0) this.sink.closed(this.dataId);
    this.sink.closed(this.linkId);
  }

  /** Close every socket but `keep`, which is the path's from now on, and return the
   *  birthday sockets to the node-wide budget. */
  keepOnly(keep) {
    for (const id of [this.socket, ...(this.extra ?? [])]) {
      if (id !== keep) udp.close(id);
    }
    this.socket = keep;
    this.extra = [];
    if (this.reservedExtra > 0) { udp.freeSockets(this.reservedExtra); this.reservedExtra = 0; }
  }

  stopPunching() {
    this.roundAt = Infinity;
    this.stunAt = Infinity;
  }
}

// ── listening and dialing ─────────────────────────────────────────────────────
// A node can also be reached over UDP directly, with no relay and no punch, as a TCP
// listener is reached: `quic://ip:port` dials a QUIC connection to a node whose config names
// a `quicPort` (`QuicListener`), and the link runs on it as on an upgraded path. The
// listener answers anyone, as a TCP listener does, and the contact secret gates the
// handshake the same way, since msg1 crosses in the first Initial.
//
// One socket carries every connection it accepts, told apart by the connection ID each
// packet is addressed to: each path names its IDs as they change (quic.js `onIds`), and the
// first four bytes of each route to it. A packet addressed to no path is a stranger's: an
// Initial is answered with a stateless Retry, and only one that echoes it opens a path
// (quic.c `OP_SCREEN`), so a spoofed source costs one small answer and no state. The
// accept is then a link like a TCP accept, held to the same half-open limiter, and to
// `MAX_QUIC_HALF_OPEN` paths besides, since each holds a connection in quic.wasm's memory.

const QUIC_SCHEME = "quic://";
/** The listener's paths whose link is not yet authenticated, at most. */
const MAX_QUIC_HALF_OPEN = 64;
/** The Initials one screen takes at most (quic.c `SCREEN_MAX`). */
const SCREEN_MAX = 2048;
const QUIC_LONG_HEADER = 0x80;

/** The peer a `quic://` destination names, `[n u8][ip n][port u16]`, or null: it must be an
 *  IP address, since the connection is taken only from the address it dials. */
function quicTarget(dest) {
  const c = dest.startsWith(QUIC_SCHEME) ? candidateOf(dest.slice(QUIC_SCHEME.length)) : null;
  if (!c || c.port === 0 || c.b[0] === 0) return null;
  const out = new Uint8Array(c.b.length + 2);
  out.set(c.b);
  writeU16BE(out, c.b.length, c.port);
  return out;
}

/** The first four bytes of the connection ID the QUIC packet of `len` bytes at `p` is
 *  addressed to, or -1. A short header's is one of this end's own, 16 bytes long. */
function dcidWord(b, p, len) {
  if (!(b[p] & QUIC_LONG_HEADER)) return len >= 17 ? readU32BE(b, p + 1) : -1;
  return len >= 10 && b[p + 5] >= 4 ? readU32BE(b, p + 6) : -1;
}

/** Run `link` on a QUIC path, whose handshake is the link's (quic.js). */
function runOnQuic(link, quic) {
  quic.handshakeReader((m) => link.onHandshake(m));
  quic.reader((bytes) => link.onWire(bytes));
}

class QuicListener {
  constructor(socket, key) {
    this.socket = socket.id;
    this.port = socket.port;
    /** What its Retry tokens are keyed under (quic.c `token_ok`). */
    this.key = key;
    this.routes = new Map(); // a connection ID's first four bytes to its path
    this.links = new Map();  // each path to its link
    udp.listen(this.socket, this);
    udp.live.add(this);
  }

  /** The socket's datagrams: each run of them for one path goes to it, and the strangers'
   *  long-header packets to the screen. */
  onBatch(b) {
    const strangers = [];
    let run = 0, runPath = null;
    for (let at = 0; at + 5 <= b.length;) {
      const start = at, p = at + 1 + b[at] + 4, len = readU16BE(b, p - 2);
      at = p + len;
      const path = len > 0 && b[p] & QUIC_FIXED_BIT ? this.routes.get(dcidWord(b, p, len)) ?? null : null;
      if (path !== runPath) {
        if (runPath) runPath.feed(b.subarray(run, start));
        run = start;
        runPath = path;
      }
      if (!path && len > 0 && b[p] & QUIC_LONG_HEADER && strangers.length < SCREEN_MAX) strangers.push(b.subarray(start, at));
    }
    if (runPath) runPath.feed(b.subarray(run));
    if (strangers.length > 0) this.screen(strangers);
  }

  /** `[Q_SCREEN][now f64][key 32][socket u32]` and the strangers' datagrams: the module
   *  sends the Retries, and names the Initials whose token stood. */
  screen(strangers) {
    const head = new Uint8Array(1 + 8 + 32 + 4);
    head[0] = Q_SCREEN;
    new DataView(head.buffer).setFloat64(1, now());
    head.set(this.key, 9);
    writeU32BE(head, 41, this.socket);
    let answer;
    try { answer = host.call(N_QUIC, concatBytes([head, ...strangers])); } catch { return; }
    void answer.then((a) => {
      const n = readU16BE(a, 0);
      if (a.length > 2 + 2 * n) udp.send(a.subarray(2 + 2 * n));
      for (let i = 0; i < n; i++) this.accept(strangers[readU16BE(a, 2 + 2 * i)]);
      udp.runTurns();
    }, () => {});
  }

  /** A path for Initial `d` (`[n u8][ip n][port u16][len u16][bytes]`), whose Retry token
   *  stood, and the link on it as on an accepted socket. */
  accept(d) {
    const n = d[0], p = 1 + n + 4, word = dcidWord(d, p, d.length - p);
    // A copy of one already let in.
    const known = this.routes.get(word);
    if (known) { known.feed(d); return; }
    let halfOpen = 0;
    for (const link of this.links.values()) {
      if (!link.authed) halfOpen++;
    }
    if (halfOpen >= MAX_QUIC_HALF_OPEN) return;
    const linkId = udp.nextId();
    const quic = new QuicPath(() => this.gone(quic, linkId));
    quic.words = [word];
    quic.onIds = (ids) => this.route(quic, ids);
    this.routes.set(word, quic);
    const link = core.openLink({
      linkId, stream: true, channel: quic, dest: "", listener: "quic",
      weDialed: false, linkSecret: null, acceptSecrets,
      source: sourceOf(n === 4 ? `${d[1]}.${d[2]}.${d[3]}.${d[4]}` : ipv6Text(d, 1)),
      limiter: core.limiter, dialedPeerId: null,
    });
    this.links.set(quic, link);
    // Refused by the limiter: nothing was opened.
    if (link.closed) { quic.fail(); return; }
    runOnQuic(link, quic);
    quic.feed(d);
    const remote = d.slice(0, 1 + n + 2);
    void randomBytes(SEED).then((seed) => quic.open(seed, this.socket, remote, false, this.key), () => quic.fail());
  }

  /** The IDs a path answers to now, beside the one its client first reached it on. */
  route(quic, ids) {
    for (const w of quic.words.slice(1)) {
      if (this.routes.get(w) === quic) this.routes.delete(w);
    }
    quic.words = [quic.words[0], ...ids];
    for (const w of ids) this.routes.set(w, quic);
  }

  gone(quic, linkId) {
    for (const w of quic.words) {
      if (this.routes.get(w) === quic) this.routes.delete(w);
    }
    this.links.delete(quic);
    localClosed(linkId);
  }

  onWake(t) {
    let next = Infinity;
    for (const quic of this.links.keys()) next = Math.min(next, quic.onWake(t));
    return next;
  }
}
