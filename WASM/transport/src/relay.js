// Relays (§12.7): the signed registration that makes this node reachable by key on a
// relay, the room membership it learns there, and splices, the sockets a relay joins end
// to end so the channel handshake runs straight through it. The host only opens the
// WebSockets; the wire is this bundle's and the relay's (seedrelay).

/** An address whose destination starts with this is reached through the relay after it. */
const RELAY_SCHEME = "relay+";
/** A relay frame past this is not relay wire, and closes the relay link. */
const MAX_SIGNAL_BYTES = 64 * 1024;
/** How long a dropped home relay waits before it is dialed again. */
const RELAY_RETRY_MS = 2000;
const NONCE_LEN = 32, TICKET_LEN = 16;

// ── the relay wire ────────────────────────────────────────────────────────────
//
// Binary frames, `[type u8][body]`. A ticket is 16 random bytes the caller picks.
//
//   relay → node                                  node → relay
//   0x00 challenge   [nonce 32]                   0x01 register  [pk 32][sig 64]
//   0x01 registered                               0x05 call      [to 32][ticket 16]
//   0x02 members     [pk 32]*  (the room, once)
//   0x03 joined      [pk 32]
//   0x04 left        [pk 32]
//   0x05 incoming    [from 32][ticket 16]
//   0x06 unreachable [to 32][ticket 16]
//
// A splice socket is `<origin>/?splice=<ticket hex>`; the relay joins the caller's and
// the callee's, and forwards what one sends to the other.
const R_CHALLENGE = 0x00, R_REGISTER = 0x01, R_MEMBERS = 0x02, R_JOINED = 0x03,
  R_LEFT = 0x04, R_CALL = 0x05, R_UNREACHABLE = 0x06;

// The registration's format tag: a second format under the host's link scope, beside
// DOMAIN_CHANNEL, so neither signature can stand for the other.
const DOMAIN_RELAY = utf8Encode("seedkernel-relay-register-v1\0");

/** `ws[s]://authority` of a relay URL, the name a relay is known by, or null. */
function relayOrigin(url) {
  const m = /^(wss?):\/\/([^/?#\s]+)/i.exec(url);
  return m ? m[1].toLowerCase() + "://" + m[2].toLowerCase() : null;
}

/** What a registration is bound to: the authority without a default port, which is how
 *  the relay reads the Host a browser sends. */
function relayAuthority(origin) {
  return origin.slice(origin.indexOf("://") + 3).replace(/:(?:80|443)$/, "");
}

/** One control socket to a relay: registered under this node's key, in `room` or none. */
class RelayConn {
  constructor(origin, room) {
    this.origin = origin;
    this.room = room;
    this.linkId = 0;
    this.framer = null;
    this.registered = false;
    this.gone = false;
    this.members = new Set();  // the room's keys, hex
    this.waiters = [];         // settle(bool) once registered or gone
    this.due = Infinity;       // registration deadline
    this.closeReason = REASON_NONE; // a relay is not a peer: nothing to print
  }

  /** Dial it. False when there is no route. */
  async open() {
    const url = this.origin + "/" + this.room;
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
      let sig;
      try {
        sig = await host.call(N_SIGN, concatBytes([DOMAIN_RELAY, utf8Encode(relayAuthority(this.origin)), body]));
      } catch { this.close(); return; }
      this.send(concatBytes([Uint8Array.of(R_REGISTER), ownPk, sig]));
    } else if (type === R_REGISTER && !this.registered) {
      this.registered = true;
      this.due = Infinity;
      for (const settle of this.waiters.splice(0)) settle(true);
    } else if ((type === R_MEMBERS || type === R_JOINED || type === R_LEFT) && body.length % PK_LEN === 0) {
      for (let off = 0; off < body.length; off += PK_LEN) {
        const peer = toHex(body.subarray(off, off + PK_LEN));
        if (type === R_LEFT) this.members.delete(peer); else this.members.add(peer);
        core.onRoomMember(this.origin, peer, type !== R_LEFT);
      }
    } else if (type === R_CALL && body.length === PK_LEN + TICKET_LEN) {
      await relays.accept(this.origin, body.subarray(PK_LEN));
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
    this.home = null;          // { origin, room } of the joined relay, or null
    this.retryAt = Infinity;   // when a dropped home relay is dialed again
    this.tickets = new Map();  // our splice sockets waiting on a call, ticket hex to link id
  }

  /** 0 no relay joined, 1 registered on it, 2 joined and waiting to (re)connect. */
  state() {
    if (!this.home) return 0;
    const c = this.conns.get(this.home.origin);
    return c && c.registered && c.room === this.home.room ? 1 : 2;
  }

  /** Join the room at `url` on its relay, leaving any other; "" leaves. Links already up
   *  stay up. */
  async join(url) {
    const origin = url === "" ? null : relayOrigin(url);
    if (url !== "" && !origin) throw new Error("transport: relay needs a ws:// or wss:// URL");
    const room = origin ? url.slice(origin.length).replace(/^\//, "") : "";
    if (this.home && origin === this.home.origin && room === this.home.room && this.state() === 1) return;
    const old = this.home && this.conns.get(this.home.origin);
    if (old) this.drop(old);
    this.home = origin ? { origin, room } : null;
    this.retryAt = Infinity;
    if (origin) await this.dialHome();
  }

  async dialHome() {
    const home = this.home;
    const stale = this.conns.get(home.origin);
    // A socket there without the room (one opened to place a call) makes way.
    if (stale && stale.room !== home.room) this.drop(stale);
    if (this.conns.has(home.origin)) return;
    const c = new RelayConn(home.origin, home.room);
    this.conns.set(home.origin, c);
    await c.open();
  }

  /** Close a relay socket and forget the room it held. */
  drop(c) {
    if (this.conns.get(c.origin) === c) this.conns.delete(c.origin);
    c.gone = true;
    c.close();
    for (const settle of c.waiters.splice(0)) settle(false);
    for (const peer of c.members) core.onRoomMember(c.origin, peer, false);
    c.members.clear();
  }

  onGone(c) {
    if (this.conns.get(c.origin) !== c) return;
    this.conns.delete(c.origin);
    if (this.home && this.home.origin === c.origin) this.retryAt = dueIn(RELAY_RETRY_MS);
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
      c = new RelayConn(origin, "");
      this.conns.set(origin, c);
      if (!(await c.open())) return { linkId: 0 };
    }
    if (!(await c.ready())) return { linkId: 0 };
    const ticket = await randomBytes(TICKET_LEN);
    c.send(concatBytes([Uint8Array.of(R_CALL), fromHex(peer), ticket]));
    const dest = origin + "/?splice=" + toHex(ticket);
    const opened = await netLinkOpen(dest);
    if (opened.linkId !== 0) this.tickets.set(toHex(ticket), opened.linkId);
    return { linkId: opened.linkId, stream: opened.stream, dest, ticket: toHex(ticket) };
  }

  /** A call for this node: open our end of the splice and accept whoever authenticates,
   *  under the half-open budgets like any accept. */
  async accept(origin, ticket) {
    const dest = origin + "/?splice=" + toHex(ticket);
    const opened = await netLinkOpen(dest);
    if (opened.linkId === 0) return;
    core.openLink({
      linkId: opened.linkId, stream: opened.stream, dest, listener: "", linkSecret: null,
      source: undefined, weDialed: false, limiter: core.limiter, dialedPeerId: null, relayed: true,
    });
  }

  /** The relay has nobody to put our call through to: fail the dial now. */
  unreachable(ticket) {
    const linkId = this.tickets.get(ticket);
    if (linkId === undefined) return;
    this.tickets.delete(ticket);
    netLinkClose(linkId, false);
  }

  /** Whether `peer` is in a room this node is in. */
  isMember(peer) {
    for (const c of this.conns.values()) if (c.members.has(peer)) return true;
    return false;
  }
}
