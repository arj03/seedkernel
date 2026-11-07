// Relays (§12.7): a relay is a peer this node holds one channel link to, dialed and
// pinned to the relay's key like any peer, so everything a node and its relay say to each
// other travels in records. The link is the registration: the relay routes calls for the
// key the handshake proved. Splices are the sockets a relay joins end to end, so the
// channel handshake between two nodes runs straight through it. Which peers to reach is
// not the relay's to say: an app learns them however it likes and hands them over as
// `relay+` addresses. The host only opens the WebSockets; the wire is this bundle's and
// the relay's (seedrelay).

/** An address whose destination starts with this is reached through the relay after it. */
const RELAY_SCHEME = "relay+";
/** A dropped home relay is dialed again after a wait that starts at RELAY_RETRY_MS and
 *  doubles with each drop in a row up to RELAY_RETRY_MAX_MS, drawn from its upper half so a
 *  relay's clients do not all come back at once. */
const RELAY_RETRY_MS = 2000, RELAY_RETRY_MAX_MS = 60_000;
const TICKET_LEN = 16;
/** Records per direction between ratchets on a relay link: fixed, since the relay cannot
 *  know a node's own setting, and both ends must agree. */
const RELAY_REKEY_AFTER_FRAMES = 1 << 24;
/** Every relay path starts with the wire version it speaks, so a relay that speaks
 *  another refuses the socket instead of misreading it. */
const RELAY_WIRE = "/v1/";
/** The UDP ports a relay answers STUN on, beside its WebSocket port. Two, so a UDP path
 *  can tell a NAT that gives each destination its own port (udp.js). */
const RELAY_STUN_PORTS = [3478, 3479];

// ── the relay wire ────────────────────────────────────────────────────────────
//
// Records on the relay link, `[type u8][body]`. A ticket is 16 random bytes the caller
// picks.
//
//   relay → node                                  node → relay
//   0x01 registered                               0x05 call [to 32][ticket 16]
//   0x05 incoming    [from 32][ticket 16]         0x08 tell [bytes]
//   0x06 unreachable [to 32][ticket 16]
//   0x08 tell        [bytes]
//
// A relay link is `<origin>/v1/`, a splice socket `<origin>/v1/?splice=<ticket hex>`: the
// caller's under the ticket it called with, the callee's under the one its `incoming`
// names. The relay joins the two and forwards what one sends to the other. `unreachable`
// is not read: the relay also refuses that call's splice socket, which fails the dial. A
// `tell` is the host's and the relay's to read (rooms, say): the transport passes it on
// unread, the host's to its home relay and the home relay's to the host.
const R_REGISTERED = 0x01, R_CALL = 0x05, R_TELL = 0x08;

/** A relay as an address names it, `ws[s]://<key>[.<secret>]@host:port`: its origin, the
 *  key its link is pinned to, and its contact secret (all zero for an open relay); null
 *  when malformed. */
function relayAddr(url) {
  const m = /^(wss?):\/\/([0-9a-f]{64})(?:\.([0-9a-f]{64}))?@([^/?#\s@]+?)\/?$/i.exec(url);
  if (!m) return null;
  return {
    origin: m[1].toLowerCase() + "://" + m[4].toLowerCase(),
    key: m[2].toLowerCase(),
    secret: m[3] ? fromHex(m[3].toLowerCase()) : ZERO32,
  };
}

/** `ws[s]://authority` of a splice URL, the origin of the relay it runs through. */
function relayOrigin(url) {
  const m = /^(wss?):\/\/([^/?#\s]+)/i.exec(url);
  return m ? m[1].toLowerCase() + "://" + m[2].toLowerCase() : null;
}

/** The host a relay origin names, without its port. */
function relayHost(origin) {
  return origin.slice(origin.indexOf("://") + 3).replace(/:\d+$/, "");
}

/** The splice socket the relay at `origin` joins under `ticket`. */
function spliceDest(origin, ticket) {
  return origin + RELAY_WIRE + "?splice=" + toHex(ticket);
}

/** One link to a relay, registered there once its handshake is done. It stands in
 *  `linksById` for its channel link, so it is told the link's events. */
class RelayConn {
  constructor(addr) {
    this.origin = addr.origin;
    this.key = addr.key;
    this.secret = addr.secret;
    this.link = null;
    this.linkId = 0;
    this.registered = false;
    this.upSince = Infinity;   // when it registered
    this.gone = false;
    this.waiters = [];         // settle(bool) once registered or gone
  }

  /** Dial it. False when there is no route. */
  async open() {
    const dest = this.origin + RELAY_WIRE;
    const opened = await netLinkOpen(dest);
    if (opened.linkId === 0 || this.gone) {
      if (opened.linkId !== 0) netLinkClose(opened.linkId, false);
      this.onLinkClosed();
      return false;
    }
    this.linkId = opened.linkId;
    // Pinned to the relay's key, on the public network's root so one relay serves every
    // network, and outside the peer lint. The home relay's link never idles out.
    this.link = new Link({
      linkId: opened.linkId, stream: opened.stream, dest, listener: "", linkSecret: this.secret,
      weDialed: true, limiter: null, dialedPeerId: this.key, networkKey: ZERO32, lint: false,
      idleMs: this.origin === relays.home ? 0 : linkIdleTimeoutMs, rekeyAfterFrames: RELAY_REKEY_AFTER_FRAMES,
      onAuth: () => {}, onFrame: (_peer, m) => this.onMessage(m), onClose: () => this.onLinkClosed(),
    });
    linksById.set(this.linkId, this);
    return true;
  }

  /** Resolves true once registered, false if the link goes first. */
  ready() {
    if (this.registered) return Promise.resolve(true);
    if (this.gone) return Promise.resolve(false);
    return new Promise((settle) => this.waiters.push(settle));
  }

  /** Keep the link while it is the home relay's, rather than leaving it once idle. */
  keep() { if (this.link) this.link.idleMs = 0; }

  /** Resolves true once the record is on the wire, false when it was not. */
  async send(bytes) {
    if (!this.link || !this.link.authed) return false;
    await this.link.send(bytes);
    return !this.link.closed;
  }

  onMessage(m) {
    if (m.length === 0) return;
    const type = m[0], body = m.subarray(1);
    if (type === R_REGISTERED && !this.registered) {
      this.registered = true;
      this.upSince = now();
      statusChanged();
      for (const settle of this.waiters.splice(0)) settle(true);
    } else if (!this.registered || this.origin !== relays.home) {
      // Calls and tells are taken on the home relay alone, once registered there: a relay
      // this node only calls through has no reason to send either.
    } else if (type === R_CALL && body.length === PK_LEN + TICKET_LEN) {
      void relays.accept(this.origin, toHex(body.subarray(0, PK_LEN)), body.subarray(PK_LEN));
    } else if (type === R_TELL) {
      relays.told(body);
    }
  }

  close() { if (this.link) this.link.close(); }

  // The link's events, as `linksById` hands them on.
  onWire(bytes) { return this.link.onWire(bytes); }
  onChannelClosed() { this.link.onChannelClosed(); }
  onWake(t) { return this.link.onWake(t); }
  get closeReason() { return REASON_NONE; } // a relay is not a peer: nothing to print

  onLinkClosed() {
    if (this.gone) return;
    this.gone = true;
    for (const settle of this.waiters.splice(0)) settle(false);
    relays.onGone(this);
  }
}

class Relays {
  constructor() {
    this.conns = new Map();    // origin to its one RelayConn
    this.home = null;          // origin of the relay this node stays registered on, or null
    this.homeAddr = null;      // and that relay's address
    this.retryAt = Infinity;   // when a dropped home relay is dialed again
    this.retryMs = RELAY_RETRY_MS; // the ceiling of the next redial's wait
  }

  /** 0 no relay, 1 registered on it, 2 waiting to (re)connect. */
  state() {
    if (!this.home) return 0;
    const c = this.conns.get(this.home);
    return c && c.registered ? 1 : 2;
  }

  /** Stay registered on the relay at `url` (`relayAddr`), leaving any other; "" leaves. A
   *  `secret` stands in for one the URL names. Resolves once registered there, or once
   *  that attempt has failed and a redial is due. Links already up stay up. */
  async join(url, secret = null) {
    const addr = url === "" ? null : relayAddr(url);
    if (url !== "" && !addr) {
      throw new Error("transport: relay needs ws[s]://<key>[.<secret>]@host:port, with no path");
    }
    if (addr && secret) addr.secret = secret;
    const origin = addr ? addr.origin : null;
    if (this.home && this.home !== origin) {
      const old = this.conns.get(this.home);
      if (old) this.drop(old);
    }
    this.home = origin;
    this.homeAddr = addr;
    this.retryAt = Infinity;
    this.retryMs = RELAY_RETRY_MS;
    statusChanged();
    if (addr) await this.dialHome();
  }

  /** The one link to the relay at `addr`, dialed if there is none. A link already up keeps
   *  the secret it was dialed with, so a peer's address need not carry the home relay's. A
   *  link pinned to another key is the home relay's word against a peer address's: the
   *  `home` dial replaces it, and a call gets null, so an address that names the wrong key
   *  cannot take the node off its relay. A dial that fails leaves it gone, so its `ready`
   *  answers false. */
  async conn(addr, home = false) {
    let c = this.conns.get(addr.origin);
    if (c && c.key !== addr.key) {
      if (!home) return null;
      this.drop(c);
      c = null;
    }
    if (!c) {
      c = new RelayConn(addr);
      this.conns.set(addr.origin, c);
      await c.open();
    }
    return c;
  }

  async dialHome() {
    const c = await this.conn(this.homeAddr, true);
    c.keep();
    await c.ready();
  }

  /** Close a relay link. */
  drop(c) {
    // Off the map first, so its closing is not taken for a lost home relay.
    if (this.conns.get(c.origin) === c) this.conns.delete(c.origin);
    c.close();
    c.onLinkClosed();
  }

  onGone(c) {
    if (this.conns.get(c.origin) !== c) return;
    this.conns.delete(c.origin);
    if (this.home !== c.origin) return;
    statusChanged();
    // A registration that held longer than the longest wait starts the backoff over.
    if (c.upSince < now() - RELAY_RETRY_MAX_MS) this.retryMs = RELAY_RETRY_MS;
    this.retryAt = dueIn(this.retryMs * (1 + Math.random()) / 2);
    this.retryMs = Math.min(2 * this.retryMs, RELAY_RETRY_MAX_MS);
  }

  /** Redial a dropped home relay. */
  onWake(t) {
    if (t >= this.retryAt) {
      this.retryAt = Infinity;
      void this.dialHome().catch(() => {});
    }
    return this.retryAt;
  }

  /** Call `peer` through the relay at `addr`: `{linkId, stream, dest}` of our end of the
   *  splice, link id 0 when there is none. The call is on the wire before the splice
   *  socket is opened: the relay refuses a socket whose ticket it has not heard, which is
   *  also how a call to a key it cannot reach fails without waiting. */
  async call(peer, addr) {
    const c = await this.conn(addr);
    if (!c || !(await c.ready())) return { linkId: 0 };
    const ticket = await randomBytes(TICKET_LEN);
    if (!(await c.send(concatBytes([Uint8Array.of(R_CALL), fromHex(peer), ticket])))) return { linkId: 0 };
    const dest = spliceDest(addr.origin, ticket);
    return { ...(await netLinkOpen(dest)), dest };
  }

  /** A call for this node from `from`, the key the relay names: open our end of the splice
   *  and accept it as any accept, under the half-open budgets with that key as its source.
   *  The name decides nothing else: the msg1 must open under one of this node's secrets
   *  (core.js `acceptSecrets`) and `admitPeers` waits for the key msg3 proves, so what a
   *  relay names a caller reads nothing off this node. A caller at the per-source cap gets
   *  no socket. */
  async accept(origin, from, ticket) {
    if ((core.limiter.perSource.get(from) || 0) >= core.limiter.maxPerSource) return;
    const dest = spliceDest(origin, ticket);
    const opened = await netLinkOpen(dest);
    if (opened.linkId === 0) return;
    core.openLink({
      linkId: opened.linkId, stream: opened.stream, dest, listener: "", linkSecret: null,
      acceptSecrets, source: from, weDialed: false, limiter: core.limiter,
      dialedPeerId: null, relayed: true,
    });
  }

  /** Hand `bytes` to the home relay, unread (`tell`). Resolves whether they went. */
  async tell(bytes) {
    const c = this.home ? this.conns.get(this.home) : null;
    if (!c || !c.registered) return false;
    return c.send(concatBytes([Uint8Array.of(R_TELL), bytes]));
  }

  /** What the home relay told this node, for the host (`link/status`). */
  told(bytes) {
    callRetried(N_LINK_STATUS, concatBytes([Uint8Array.of(STATUS_RELAY), bytes]));
  }
}
