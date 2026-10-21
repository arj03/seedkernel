// Direct upgrades (§12.7): once a peer is linked through a relay, the smaller key offers a
// direct path, signaled over that authenticated link, and the path's data link becomes a
// direct link. A path is one of two kinds: `udp`, this transport's own over the host's
// datagram sockets (udp.js), tried first, and `rtc:`, a WebRTC peer connection the host
// holds and decides nothing about. A node offers the first it has, and the next when the
// peer declines.

// The negotiation link's message tags (services/net-rtc.ts `RTC_TAG`), the same for both
// kinds: each message is `[tag u8][UTF-8 text]`. Up: a local description, a local
// candidate, and a connection state this transport does not read, since a connection that
// fails closes its links. Down: a remote description, a remote candidate. An ICE restart is
// never asked for: its offer would have to cross the very link whose path was lost, so a
// lost connection is dialed again through the relay instead. Signaling reuses the
// description and candidate tags, and adds a UDP offer and a decline.
const RTC_OFFER = 0x6f, RTC_ANSWER = 0x61, RTC_CANDIDATE = 0x63;
/** Signaling only: an offer of a UDP path, answered and trickled as a WebRTC one is. */
const UDP_OFFER = 0x75;
/** Signaling only: the answering side has no path of the kind offered, so the offer is
 *  dropped. */
const RTC_DECLINE = 0x78;
/** The kinds of path, in the order they are offered. */
const SCHEMES = ["udp", "rtc"];
/** A negotiation's id, chosen by the offering side, so a signal for a negotiation this end
 *  has dropped or replaced is told from one for the negotiation it holds. */
const SID_LEN = 8;

// ── signaling ─────────────────────────────────────────────────────────────────
//
// A signal is a control frame on the peer's first link (router.js `KIND_CTL`,
// `sendInOrder`), so a candidate never passes its description on another link:
//
//   [KIND_CTL][tag u8][sid 8][UTF-8 text]
//
// with tag `o` (offer), `u` (UDP offer), `a` (answer), `c` (candidate) or `x` (decline,
// empty), the text as the path's host gives it. It comes from the authenticated peer, so
// nothing in it needs checking beyond its shape.

/** A negotiation's place among the links: what a host's `rtc:` link says up, and for either
 *  kind the deadline its data link has to open by, and its close. */
class NegotiationLink {
  constructor(linkId, e, owner) {
    this.linkId = linkId;
    this.e = e;
    this.owner = owner;
    this.closeReason = REASON_NONE;
  }
  async onWire(bytes) { if (bytes.length > 0) this.owner.up(this.e, bytes[0], utf8Decode(bytes.subarray(1))); }
  onChannelClosed() { this.owner.gone(this.e); }
  onWake(t) {
    const e = this.e;
    if (e.data !== null || e.gone) return Infinity;
    if (t < e.due) return e.due;
    this.owner.drop(e);
    return Infinity;
  }
}

class Direct {
  constructor() {
    // ICE servers (STUN/TURN) as the platform takes them, beside the relay's own STUN
    // (`iceServersFor`).
    const iceServers = LOCAL.iceServers ?? APP.iceServers ?? [];
    if (!Array.isArray(iceServers) || iceServers.some((s) => typeof s !== "object" || s === null)) {
      throw new Error("transport: config iceServers must be an array of objects");
    }
    this.iceServers = iceServers;
    this.maxNegotiating = policy("maxRtcNegotiating");
    // How long a peer connection may take to open its data channel: ICE, DTLS and SCTP.
    this.connectTimeoutMs = policy("rtcConnectTimeoutMs");
    this.byPeer = new Map(); // peer hex to negotiation
    this.byCtl = new Map();  // negotiation link id to negotiation
    // Data links announced before `open` has recorded their negotiation.
    this.early = new Map();  // negotiation link id to { linkId, stream }
    // Signals are applied one at a time, in arrival order: records are not, and a
    // candidate must never reach the peer connection ahead of its description.
    this.signals = Promise.resolve();
  }

  /** The ICE servers for a negotiation with `peer`: STUN at the relay it is linked
   *  through, else at this node's home relay, on both its ports, which already sees this
   *  node's address, so asking it tells no one new, then the configured servers. */
  iceServersFor(peer) {
    const relay = router.relayOf(peer) || relays.home || "";
    const atRelay = relay ? RELAY_STUN_PORTS.map((port) => ({ urls: `stun:${relayHost(relay)}:${port}` })) : [];
    return [...atRelay, ...this.iceServers];
  }

  /** Negotiations that have not produced an authenticated link; the cap counts these. */
  pending() {
    let n = 0;
    for (const e of this.byPeer.values()) {
      if (!authedData(e)) n++;
    }
    return n;
  }

  /** The smaller key offers, just as the smaller key's dial wins a double connect. */
  weOffer(peer) { return ownId < peer; }

  /** Offer a direct path to a peer this node reaches only through a relay: the first of
   *  `schemes` its host routes. */
  async upgrade(peer, schemes = SCHEMES) {
    if (!this.weOffer(peer) || this.byPeer.has(peer) || router.hasDirect(peer)) return;
    const sid = toHex(await randomBytes(SID_LEN));
    for (const scheme of schemes) {
      if (await this.open(peer, true, sid, scheme)) return;
    }
  }

  signal(peer, tag, sid, text) {
    const frame = concatBytes([Uint8Array.of(KIND_CTL, tag), fromHex(sid), utf8Encode(text)]);
    return frame.length <= maxFrameBytes - TAG_LEN && router.sendInOrder(peer, frame);
  }

  /** One signal from `peer` (router.js `KIND_CTL`), queued behind the ones before it. */
  receive(peer, tag, body) {
    this.signals = this.signals.then(() => this.onSignal(peer, tag, body)).catch(() => {});
  }

  async onSignal(peer, tag, body) {
    if (body.length < SID_LEN) return;
    const sid = toHex(body.subarray(0, SID_LEN));
    const text = utf8Decode(body.subarray(SID_LEN));
    let e = this.byPeer.get(peer);
    if (tag === RTC_OFFER || tag === UDP_OFFER) {
      if (this.weOffer(peer)) return;
      // A new negotiation from the peer replaces ours: it restarted.
      if (e && e.sid !== sid) { this.drop(e); e = undefined; }
      if (!e) e = await this.open(peer, false, sid, tag === UDP_OFFER ? "udp" : "rtc");
      if (!e) { this.signal(peer, RTC_DECLINE, sid, ""); return; }
      this.down(e, RTC_OFFER, text);
      return;
    }
    if (!e || e.sid !== sid) return;
    if (tag === RTC_ANSWER && e.offer) this.down(e, RTC_ANSWER, text);
    else if (tag === RTC_CANDIDATE) this.down(e, RTC_CANDIDATE, text);
    else if (tag === RTC_DECLINE && e.offer) {
      this.drop(e);
      const rest = SCHEMES.slice(SCHEMES.indexOf(e.scheme) + 1);
      if (rest.length > 0) void this.upgrade(peer, rest).catch(() => {});
    }
  }

  /** Open a negotiation of `scheme` for one peer: a UDP one this realm runs (udp.js), or
   *  a host's `rtc:` link (`HostNegotiation`), both `e.neg`. Null when the cap is reached
   *  or no route (a host without that kind of path). */
  async open(peer, offer, sid, scheme) {
    if (this.pending() >= this.maxNegotiating) return null;
    const e = { peer, offer, sid, scheme, ctl: 0, neg: null, data: null, gone: false, due: Infinity };
    this.byPeer.set(peer, e);
    const neg = await (scheme === "udp" ? udp : HostNegotiation).open(offer, this.iceServersFor(peer));
    const early = neg ? this.early.get(neg.linkId) : undefined;
    if (neg) this.early.delete(neg.linkId);
    if (e.gone || this.byPeer.get(peer) !== e || !neg) {
      if (neg) neg.close();
      if (early) netLinkClose(early.linkId, false);
      if (this.byPeer.get(peer) === e) this.byPeer.delete(peer);
      return null;
    }
    e.ctl = neg.linkId;
    e.neg = neg;
    this.byCtl.set(e.ctl, e);
    if (this.connectTimeoutMs > 0) e.due = dueIn(this.connectTimeoutMs);
    linksById.set(e.ctl, new NegotiationLink(e.ctl, e, this));
    if (early) this.bindData(e.ctl, early.linkId, early.stream);
    neg.start({
      up: (tag, text) => this.up(e, tag, text),
      open: (linkId, stream) => this.bindData(e.ctl, linkId, true, stream),
      closed: localClosed,
    });
    return e;
  }

  /** A description or candidate the path's host produced: send it to the peer. */
  up(e, tag, text) {
    if (tag !== RTC_OFFER && tag !== RTC_ANSWER && tag !== RTC_CANDIDATE) return;
    if (!this.signal(e.peer, tag === RTC_OFFER && e.scheme === "udp" ? UDP_OFFER : tag, e.sid, text)) this.drop(e);
  }

  down(e, tag, text) { if (e.neg) e.neg.down(tag, text); }

  /** The data channel of negotiation `via` arrived as `linkId`: the offering side dials
   *  the peer it signaled, and the answering side accepts that peer and no other. Both run
   *  open, with no contact secret: the channel exists only through signaling over the
   *  authenticated link, so only that peer can reach it, and a key it brought along would
   *  otherwise pass a gate it never opened. A UDP negotiation's data link is its stream
   *  (`channel`), which the link reads. */
  bindData(via, linkId, stream, channel) {
    const e = this.byCtl.get(via);
    if (!e && !linksById.has(via)) { this.early.set(via, { linkId, stream }); return; }
    if (!e || e.data) { (channel ?? hostChannel(linkId)).close(false); return; }
    const link = e.data = core.openLink({
      linkId, stream, channel, dest: "", listener: "", source: undefined,
      linkSecret: ZERO32,
      weDialed: e.offer,
      limiter: e.offer ? null : core.limiter,
      dialedPeerId: e.offer ? e.peer : null,
      acceptPeerId: e.offer ? null : e.peer,
    });
    if (channel) channel.reader((bytes) => link.onWire(bytes));
  }

  /** End a negotiation this end gave up on. It leaves `byCtl` at once, so a data link it
   *  announced meanwhile is closed (`bindData`) rather than run on a closing channel. */
  drop(e) {
    this.gone(e);
    if (e.neg) e.neg.close();
  }

  /** A negotiation link closed, and its data link with it. The peer is still reachable
   *  through its address, which is where the next upgrade starts. */
  gone(e) {
    this.byCtl.delete(e.ctl);
    e.gone = true;
    if (this.byPeer.get(e.peer) === e) this.byPeer.delete(e.peer);
  }
}

/** Whether this negotiation's data link ever authenticated. */
function authedData(e) { return e.data !== null && e.data.peerId !== ""; }

/** An `rtc:` negotiation link the host holds, in a UDP negotiation's shape (udp.js): what
 *  it says up comes as `linkBytes` (`NegotiationLink`), and its data link as a `linkOpen`
 *  naming it as `via`. */
class HostNegotiation {
  /** One for `offer`ing or answering, with `iceServers` as the destination's
   *  RTCConfiguration; null for no route. */
  static async open(offer, iceServers) {
    const config = iceServers.length > 0 ? "?" + JSON.stringify({ iceServers }) : "";
    const { linkId } = await netLinkOpen(`rtc:${offer ? "offer" : "answer"}${config}`);
    return linkId === 0 ? null : new HostNegotiation(linkId);
  }

  constructor(linkId) { this.linkId = linkId; }

  start() {}

  down(tag, text) {
    const msg = concatBytes([Uint8Array.of(tag), utf8Encode(text)]);
    try { void netLinkSend(this.linkId, msg).catch(() => {}); } catch { /* budget: the negotiation times out */ }
  }

  close() { netLinkClose(this.linkId, false); }
}
