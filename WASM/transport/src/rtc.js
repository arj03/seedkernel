// WebRTC upgrades (§12.7): once a peer is linked through a relay, the smaller key offers a
// peer connection, signaled over that authenticated link, and the data channel becomes a
// direct link. The host's `rtc:` socket factory holds only the RTCPeerConnection.

// The negotiation link's message tags (services/net-rtc.ts `RTC_TAG`): each message is
// `[tag u8][UTF-8 text]`. Up: a local description, a local candidate, a connection state.
// Down: a remote description, a remote candidate, an ICE restart. Signaling reuses the
// description and candidate tags, and adds a decline.
const RTC_OFFER = 0x6f, RTC_ANSWER = 0x61, RTC_CANDIDATE = 0x63, RTC_STATE = 0x73, RTC_RESTART = 0x72;
/** Signaling only: the answering side has no WebRTC, so the offer is dropped. */
const RTC_DECLINE = 0x78;
/** A negotiation's id, chosen by the offering side, so a new negotiation is told apart
 *  from an ICE restart without reading the SDP. */
const SID_LEN = 8;

// ── signaling ─────────────────────────────────────────────────────────────────
//
// A signal is a control frame on any link to the peer (router.js `KIND_CTL`):
//
//   [KIND_CTL][tag u8][sid 8][UTF-8 text]
//
// with tag `o` (offer SDP), `a` (answer SDP), `c` (candidate: `candidate`, `sdpMid`,
// `sdpMLineIndex` and `usernameFragment`, NUL-separated) or `x` (decline, empty). It
// comes from the authenticated peer, so nothing in it needs checking beyond its shape.

/** A negotiation link: the host's peer connection for one peer, and the deadline its data
 *  channel has to open by. */
class RtcCtlLink {
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

class Rtc {
  constructor() {
    // ICE servers (STUN/TURN) as the platform takes them, beside the relay's own STUN
    // (`configFor`).
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
    // Peers that declined an offer, not offered again while they stay linked.
    this.declined = new Set();
    // Signals are applied one at a time, in arrival order: records are not, and a
    // candidate must never reach the peer connection ahead of its description.
    this.signals = Promise.resolve();
  }

  /** The RTCConfiguration suffix for a negotiation with `peer`: STUN at the relay it is
   *  linked through, which already sees this node's address, so asking it tells no one
   *  new, then the configured servers. */
  configFor(peer) {
    const relay = router.relayOf(peer);
    const iceServers = relay ? [{ urls: `stun:${relayHost(relay)}:${RELAY_STUN_PORT}` }, ...this.iceServers] : this.iceServers;
    return iceServers.length > 0 ? "?" + JSON.stringify({ iceServers }) : "";
  }

  /** Negotiations that have not produced an authenticated link; the cap counts these. */
  pending() {
    let n = 0;
    for (const e of this.byPeer.values()) if (!authedData(e)) n++;
    return n;
  }

  /** The smaller key offers, just as the smaller key's dial wins a double connect. */
  weOffer(peer) { return ownId < peer; }

  /** Offer a peer connection to a peer this node reaches only through a relay. */
  async upgrade(peer) {
    if (!this.weOffer(peer) || this.byPeer.has(peer) || this.declined.has(peer) || router.hasDirect(peer)) return;
    await this.open(peer, true, toHex(await randomBytes(SID_LEN)));
  }

  /** The peer went down: it may offer or answer differently next time. */
  forget(peer) { this.declined.delete(peer); }

  signal(peer, tag, sid, text) {
    const frame = concatBytes([Uint8Array.of(KIND_CTL, tag), fromHex(sid), utf8Encode(text)]);
    return frame.length <= maxFrameBytes - TAG_LEN && router.send(peer, frame);
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
    if (tag === RTC_OFFER) {
      if (this.weOffer(peer)) return;
      // A new negotiation from the peer replaces ours: it restarted.
      if (e && e.sid !== sid) { this.drop(e); e = undefined; }
      if (!e) e = await this.open(peer, false, sid);
      if (!e) { this.signal(peer, RTC_DECLINE, sid, ""); return; }
      this.down(e, RTC_OFFER, text);
      return;
    }
    if (!e || e.sid !== sid) return;
    if (tag === RTC_ANSWER && e.offer) this.down(e, RTC_ANSWER, text);
    else if (tag === RTC_CANDIDATE) this.down(e, RTC_CANDIDATE, text);
    else if (tag === RTC_DECLINE && e.offer) { this.declined.add(peer); this.drop(e); }
  }

  /** Open a negotiation link for one peer. Null when the cap is reached or no route (a
   *  host without WebRTC). */
  async open(peer, offer, sid) {
    if (this.pending() >= this.maxNegotiating) return null;
    const e = { peer, offer, sid, ctl: 0, data: null, gone: false, due: Infinity };
    this.byPeer.set(peer, e);
    const opened = await netLinkOpen((offer ? "rtc:offer" : "rtc:answer") + this.configFor(peer));
    const early = this.early.get(opened.linkId);
    this.early.delete(opened.linkId);
    if (e.gone || this.byPeer.get(peer) !== e || opened.linkId === 0) {
      if (opened.linkId !== 0) netLinkClose(opened.linkId, false);
      if (early) netLinkClose(early.linkId, false);
      if (this.byPeer.get(peer) === e) this.byPeer.delete(peer);
      return null;
    }
    e.ctl = opened.linkId;
    this.byCtl.set(e.ctl, e);
    if (this.connectTimeoutMs > 0) e.due = dueIn(this.connectTimeoutMs);
    linksById.set(e.ctl, new RtcCtlLink(e.ctl, e, this));
    if (early) this.bindData(e.ctl, early.linkId, early.stream);
    return e;
  }

  /** Something the peer connection produced: send it to the peer, or act on its state. */
  up(e, tag, text) {
    if (tag === RTC_OFFER || tag === RTC_ANSWER || tag === RTC_CANDIDATE) {
      if (!this.signal(e.peer, tag, e.sid, text)) this.drop(e);
    } else if (tag === RTC_STATE && text === "disconnected" && e.offer) {
      // A path went away (a network change, a NAT rebind): new candidates, same connection.
      this.down(e, RTC_RESTART, "");
    }
  }

  down(e, tag, text) {
    if (e.ctl === 0) return;
    const body = utf8Encode(text);
    const msg = new Uint8Array(1 + body.length);
    msg[0] = tag;
    msg.set(body, 1);
    try { void netLinkSend(e.ctl, msg).catch(() => {}); } catch { /* budget: the negotiation times out */ }
  }

  /** The data channel of negotiation `via` arrived as `linkId`: the offering side dials
   *  the peer it signaled, and the answering side accepts whoever authenticates. Both run
   *  open, with no contact secret: the channel exists only through signaling over the
   *  authenticated link, so no stranger can reach it. */
  bindData(via, linkId, stream) {
    const e = this.byCtl.get(via);
    if (!e && !linksById.has(via)) { this.early.set(via, { linkId, stream }); return; }
    if (!e || e.data) { netLinkClose(linkId, false); return; }
    e.data = core.openLink({
      linkId, stream, dest: "", listener: "", source: undefined,
      linkSecret: ZERO32,
      weDialed: e.offer,
      limiter: e.offer ? null : core.limiter,
      dialedPeerId: e.offer ? e.peer : null,
    });
  }

  drop(e) {
    e.gone = true;
    if (this.byPeer.get(e.peer) === e) this.byPeer.delete(e.peer);
    if (e.ctl !== 0) netLinkClose(e.ctl, false);
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
