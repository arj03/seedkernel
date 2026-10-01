// Relays (§12.7): the signed registration that makes this node reachable by key on a
// relay, and splices, the sockets a relay joins end to end so the channel handshake runs
// straight through it. Which peers to reach is not the relay's to say: an app learns them
// however it likes and hands them over as `relay+` addresses. The host only opens the
// WebSockets; the wire is this bundle's and the relay's (seedrelay).

/** An address whose destination starts with this is reached through the relay after it. */
const RELAY_SCHEME = "relay+";
/** A relay frame past this is not relay wire, and closes the relay link. */
const MAX_SIGNAL_BYTES = 64 * 1024;
/** A dropped home relay is dialed again after a wait that starts at RELAY_RETRY_MS and
 *  doubles with each drop in a row up to RELAY_RETRY_MAX_MS, drawn from its upper half so a
 *  relay's clients do not all come back at once. */
const RELAY_RETRY_MS = 2000, RELAY_RETRY_MAX_MS = 60_000;
const NONCE_LEN = 32, TICKET_LEN = 16;
/** Every relay path starts with the wire version it speaks, so a relay that speaks
 *  another refuses the socket instead of misreading it. */
const RELAY_WIRE = "/v1/";
/** The UDP port a relay answers STUN on, beside its WebSocket port. */
const RELAY_STUN_PORT = 3478;

// ── the relay wire ────────────────────────────────────────────────────────────
//
// Binary frames, `[type u8][body]`. A ticket is 16 random bytes the caller picks.
//
//   relay → node                                  node → relay
//   0x00 challenge   [nonce 32]                   0x01 register  [pk 32][sig 64][mac 64]?
//   0x01 registered                               0x05 call      [to 32][ticket 16]
//   0x05 incoming    [from 32][ticket 16]
//   0x06 unreachable [to 32][ticket 16]
//
// A control socket is `<origin>/v1/`, a splice socket `<origin>/v1/?splice=<ticket hex>`:
// the caller's under the ticket it called with, the callee's under the one its `incoming`
// names. The relay joins the two and forwards what one sends to the other.
const R_CHALLENGE = 0x00, R_REGISTER = 0x01, R_CALL = 0x05, R_UNREACHABLE = 0x06;

// The registration's format tag: a second format under the host's link scope, beside
// DOMAIN_CHANNEL, so neither signature can stand for the other.
const DOMAIN_RELAY = utf8Encode("seedkernel-relay-register-v1\0");

// A private relay (seedrelay's `--secret`) also wants the MAC
//   BLAKE2b-512(DOMAIN_SECRET ‖ pk ‖ sig ‖ secret)
// after the signature: proof of its secret that never sends it, and is good on this socket
// only, since the signature is over its nonce. BLAKE2b cannot be length-extended, so
// hashing the secret in needs no HMAC around it. Unkeyed, as the relay's Node has no keyed
// BLAKE2b. seedrelay's tag. Only the home relay, the one the secret was given with, gets
// the MAC: a relay this node only calls through could test guesses at the secret against
// it. A relay without secrets ignores the MAC.
const DOMAIN_SECRET = utf8Encode("seedrelay-secret-v1\0");
const HASH_512 = new Uint8Array([64, 0]);

/** `ws[s]://authority` of a relay URL, the name a relay is known by, or null. */
function relayOrigin(url) {
  const m = /^(wss?):\/\/([^/?#\s]+)/i.exec(url);
  return m ? m[1].toLowerCase() + "://" + m[2].toLowerCase() : null;
}

/** The host a relay origin names, without its port. */
function relayHost(origin) {
  return origin.slice(origin.indexOf("://") + 3).replace(/:\d+$/, "");
}

/** What a registration is bound to: the authority without a default port, which is how
 *  the relay reads the Host a browser sends. */
function relayAuthority(origin) {
  return origin.slice(origin.indexOf("://") + 3).replace(/:(?:80|443)$/, "");
}

/** One control socket to a relay, registered under this node's key. */
class RelayConn {
  constructor(origin) {
    this.origin = origin;
    this.linkId = 0;
    this.framer = null;
    this.registered = false;
    this.upSince = Infinity;   // when it registered
    this.gone = false;
    this.waiters = [];         // settle(bool) once registered or gone
    this.due = Infinity;       // registration deadline
    this.closeReason = REASON_NONE; // a relay is not a peer: nothing to print
  }

  /** Dial it. False when there is no route. */
  async open() {
    const url = this.origin + RELAY_WIRE;
    const opened = await netLinkOpen(url);
    if (opened.linkId === 0 || this.gone) {
      if (opened.linkId !== 0) netLinkClose(opened.linkId, false);
      this.onChannelClosed();
      return false;
    }
    this.linkId = opened.linkId;
    this.framer = makeFramer(opened.stream, opened.linkId, url, "");
    if (this.framer) this.framer.cap = MAX_SIGNAL_BYTES;
    linksById.set(this.linkId, this);
    if (handshakeTimeoutMs > 0) this.due = dueIn(handshakeTimeoutMs);
    return true;
  }

  /** Resolves true once registered, false if the socket goes first. */
  ready() {
    if (this.registered) return Promise.resolve(true);
    if (this.gone) return Promise.resolve(false);
    return new Promise((settle) => this.waiters.push(settle));
  }

  send(bytes) {
    try {
      const sent = this.framer ? this.framer.send(bytes) : netLinkSend(this.linkId, bytes);
      void Promise.resolve(sent).catch(() => {});
    } catch { /* budget: a lost frame, and the caller's dial times out */ }
  }

  async onWire(bytes) {
    if (!this.framer) {
      if (bytes.length <= MAX_SIGNAL_BYTES) await this.onMessage(bytes);
      return;
    }
    if ((await this.framer.push(bytes, (m) => this.onMessage(m))) === false) this.close();
  }

  async onMessage(m) {
    if (m.length === 0) return;
    const body = m.subarray(1);
    const type = m[0];
    if (type === R_CHALLENGE && body.length === NONCE_LEN && !this.registered) {
      let sig, mac = new Uint8Array(0);
      try {
        sig = await host.call(N_SIGN, concatBytes([DOMAIN_RELAY, utf8Encode(relayAuthority(this.origin)), body]));
        const secret = this.origin === relays.home ? relays.secret : null;
        if (secret) mac = await host.call(P_HASH, concatBytes([HASH_512, DOMAIN_SECRET, ownPk, sig, secret]));
      } catch { this.close(); return; }
      this.send(concatBytes([Uint8Array.of(R_REGISTER), ownPk, sig, mac]));
    } else if (type === R_REGISTER && !this.registered) {
      this.registered = true;
      this.upSince = now();
      this.due = Infinity;
      for (const settle of this.waiters.splice(0)) settle(true);
    } else if (type === R_CALL && body.length === PK_LEN + TICKET_LEN) {
      await relays.accept(this.origin, toHex(body.subarray(0, PK_LEN)), body.subarray(PK_LEN));
    } else if (type === R_UNREACHABLE && body.length === PK_LEN + TICKET_LEN) {
      relays.unreachable(toHex(body.subarray(PK_LEN)));
    }
  }

  close() { if (this.linkId !== 0) netLinkClose(this.linkId, false); }

  onChannelClosed() {
    if (this.gone) return;
    this.gone = true;
    this.due = Infinity;
    for (const settle of this.waiters.splice(0)) settle(false);
    relays.onGone(this);
  }

  /** An unregistered socket past its deadline is closed. */
  onWake(t) {
    if (t < this.due) return this.due;
    this.due = Infinity;
    if (!this.registered) this.close();
    return Infinity;
  }
}

class Relays {
  constructor() {
    this.conns = new Map();    // origin to its one RelayConn
    this.home = null;          // origin of the relay this node stays registered on, or null
    this.retryAt = Infinity;   // when a dropped home relay is dialed again
    this.retryMs = RELAY_RETRY_MS; // the ceiling of the next redial's wait
    this.tickets = new Map();  // our splice sockets waiting on a call, ticket hex to link id
    this.secret = null;        // the home relay's secret, proved only there, or null
  }

  /** 0 no relay, 1 registered on it, 2 waiting to (re)connect. */
  state() {
    if (!this.home) return 0;
    const c = this.conns.get(this.home);
    return c && c.registered ? 1 : 2;
  }

  /** Stay registered on the relay at `url`, leaving any other; "" leaves. A `secret` is
   *  that relay's, when it is private (seedrelay's `--secret`), and is proved to it alone,
   *  never to a relay this node only calls a peer through. Resolves once registered there,
   *  or once that attempt has failed and a redial is due. Links already up stay up. */
  async join(url, secret = null) {
    const origin = url === "" ? null : relayOrigin(url);
    if (url !== "" && (!origin || !/^\/?$/.test(url.slice(origin.length)))) {
      throw new Error("transport: relay needs a ws:// or wss:// URL with no path");
    }
    if (this.home && this.home !== origin) {
      const old = this.conns.get(this.home);
      if (old) this.drop(old);
    }
    this.secret = origin && secret && secret.length > 0 ? secret.slice() : null;
    this.home = origin;
    this.retryAt = Infinity;
    this.retryMs = RELAY_RETRY_MS;
    if (origin) await this.dialHome();
  }

  async dialHome() {
    let c = this.conns.get(this.home);
    if (!c) {
      c = new RelayConn(this.home);
      this.conns.set(this.home, c);
      await c.open();
    }
    await c.ready();
  }

  /** Close a relay socket. */
  drop(c) {
    if (this.conns.get(c.origin) === c) this.conns.delete(c.origin);
    c.gone = true;
    c.close();
    for (const settle of c.waiters.splice(0)) settle(false);
  }

  onGone(c) {
    if (this.conns.get(c.origin) !== c) return;
    this.conns.delete(c.origin);
    if (this.home !== c.origin) return;
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

  /** Call `peer` through the relay at `origin`: `{linkId, stream, dest}` of our end of the
   *  splice, link id 0 when there is none. */
  async call(peer, origin) {
    let c = this.conns.get(origin);
    if (!c) {
      c = new RelayConn(origin);
      this.conns.set(origin, c);
      if (!(await c.open())) return { linkId: 0 };
    }
    if (!(await c.ready())) return { linkId: 0 };
    const ticket = await randomBytes(TICKET_LEN);
    c.send(concatBytes([Uint8Array.of(R_CALL), fromHex(peer), ticket]));
    const dest = origin + RELAY_WIRE + "?splice=" + toHex(ticket);
    const opened = await netLinkOpen(dest);
    if (opened.linkId !== 0) this.tickets.set(toHex(ticket), opened.linkId);
    return { linkId: opened.linkId, stream: opened.stream, dest, ticket: toHex(ticket) };
  }

  /** A call for this node from `from`, the key the relay registered: open our end of the
   *  splice and accept whoever authenticates, under the half-open budgets with the caller's
   *  key as its source. A caller outside `admitPeers`, or at the per-source cap, gets no
   *  socket. */
  async accept(origin, from, ticket) {
    if (admitPeers !== null && !admitPeers.has(from)) return;
    if ((core.limiter.perSource.get(from) || 0) >= core.limiter.maxPerSource) return;
    const dest = origin + RELAY_WIRE + "?splice=" + toHex(ticket);
    const opened = await netLinkOpen(dest);
    if (opened.linkId === 0) return;
    core.openLink({
      linkId: opened.linkId, stream: opened.stream, dest, listener: "", linkSecret: null,
      source: from, weDialed: false, limiter: core.limiter, dialedPeerId: null, relayed: true,
    });
  }

  /** The relay has nobody to put our call through to: fail the dial now. */
  unreachable(ticket) {
    const linkId = this.tickets.get(ticket);
    if (linkId === undefined) return;
    this.tickets.delete(ticket);
    netLinkClose(linkId, false);
  }
}
