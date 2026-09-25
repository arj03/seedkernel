// WebRTC peers (§12.7): the signaling relay, who offers, and the negotiation links the
// host's `rtc:` socket factory drives. The host holds only the RTCPeerConnection.

// The negotiation link's message tags (services/net-rtc.ts `RTC_TAG`): each message is
// `[tag u8][UTF-8 text]`. Up: a local description, a local candidate, a connection state.
// Down: a remote description, a remote candidate, an ICE restart.
const RTC_OFFER = 0x6f, RTC_ANSWER = 0x61, RTC_CANDIDATE = 0x63, RTC_STATE = 0x73, RTC_RESTART = 0x72;
/** A relay frame past this is not signaling, and closes the relay link. */
const MAX_SIGNAL_BYTES = 64 * 1024;
/** How long a dropped or unreachable relay waits before it is dialed again. */
const RELAY_RETRY_MS = 2000;

// ── the relay wire ────────────────────────────────────────────────────────────
//
// A relay is a room forwarding every frame to every other member, unauthenticated, so
// everything here is a claim until the handshake proves it. A frame is UTF-8,
// NUL-separated; each tag pins its field count:
//
//   h  from  to                      a hello; `to` empty is a broadcast
//   o  from  to  sid  sdp            an offer, for negotiation `sid`
//   a  from  to  sid  sdp            its answer
//   i  from  to  sid  candidate  sdpMid  sdpMLineIndex  usernameFragment
//
// `sid` names one negotiation, telling a new one from an ICE restart.

/** A link to the relay: WebSocket frames over a raw stream, or whole platform messages. */
class RelayLink {
  constructor(linkId, stream, dest, onSignal) {
    this.linkId = linkId;
    this.framer = makeFramer(stream, linkId, dest, "");
    if (this.framer) this.framer.cap = MAX_SIGNAL_BYTES;
    this.onSignal = onSignal;
    this.onGone = null;
    this.closeReason = REASON_NONE; // a relay is not a peer: nothing to print
  }
  send(bytes) {
    try {
      const sent = this.framer ? this.framer.send(bytes) : netLinkSend(this.linkId, bytes);
      void Promise.resolve(sent).catch(() => {});
    } catch { /* budget: a lost signal, retried by the peer */ }
  }
  async onWire(bytes) {
    if (!this.framer) {
      if (bytes.length <= MAX_SIGNAL_BYTES) await this.onSignal(bytes);
      return;
    }
    if ((await this.framer.push(bytes, (msg) => this.onSignal(msg))) === false) this.close();
  }
  close() { netLinkClose(this.linkId, false); }
  onChannelClosed() { this.onGone?.(); }
  onWake() { return Infinity; }
}

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

// ── the peers ─────────────────────────────────────────────────────────────────

class Rtc {
  constructor() {
    // ICE servers (STUN/TURN) as the platform takes them; empty offers host candidates only.
    const iceServers = LOCAL.iceServers ?? APP.iceServers ?? [];
    if (!Array.isArray(iceServers) || iceServers.some((s) => typeof s !== "object" || s === null)) {
      throw new Error("transport: config iceServers must be an array of objects");
    }
    this.configSuffix = iceServers.length > 0 ? "?" + JSON.stringify({ iceServers }) : "";
    this.maxNegotiating = policy("maxRtcNegotiating");
    // How long a peer connection may take to open its data channel: ICE, DTLS and SCTP.
    this.connectTimeoutMs = policy("rtcConnectTimeoutMs");
    this.url = "";           // the relay this node has joined, "" for none
    this.relay = null;       // its live link
    this.retryAt = Infinity; // when a dropped relay is dialed again
    this.byPeer = new Map(); // peer hex → negotiation
    this.byCtl = new Map();  // negotiation link id → negotiation
    // Data links announced before `open` has filed their negotiation.
    this.early = new Map();  // negotiation link id → { linkId, stream }
  }

  /** 0 not joined, 1 relay link up, 2 joined and waiting to redial. */
  state() { return this.url === "" ? 0 : this.relay ? 1 : 2; }

  /** Join the relay at `url`, leaving any other; "" leaves. Links already up stay up. */
  async join(url) {
    if (url === this.url && this.relay) { this.signal("h", ""); return; }
    this.url = url;
    this.retryAt = Infinity;
    const old = this.relay;
    this.relay = null;
    if (old) old.close();
    if (url !== "") await this.dialRelay();
  }

  async dialRelay() {
    const url = this.url;
    const opened = await netLinkOpen(url);
    if (url !== this.url || this.relay) {
      if (opened.linkId !== 0) netLinkClose(opened.linkId, false);
      return;
    }
    if (opened.linkId === 0) { this.retryAt = dueIn(RELAY_RETRY_MS); return; }
    const r = new RelayLink(opened.linkId, opened.stream, url, (m) => this.onSignal(m));
    r.onGone = () => {
      if (this.relay !== r) return;
      this.relay = null;
      if (this.url !== "") this.retryAt = dueIn(RELAY_RETRY_MS);
    };
    linksById.set(opened.linkId, r);
    this.relay = r;
    this.signal("h", "");
  }

  onWake(t) {
    if (t >= this.retryAt) {
      this.retryAt = Infinity;
      void this.dialRelay().catch(() => { if (this.url !== "" && !this.relay) this.retryAt = dueIn(RELAY_RETRY_MS); });
    }
    return this.retryAt;
  }

  signal(tag, to, ...fields) {
    this.relay?.send(utf8Encode([tag, ownId, to, ...fields].join("\0")));
  }

  /** Negotiations that have not produced an authenticated link — the ones the cap bounds. */
  pending() {
    let n = 0;
    for (const e of this.byPeer.values()) if (!authedData(e)) n++;
    return n;
  }

  /** One relay frame. Decoded and checked before anything is allocated for it. */
  async onSignal(bytes) {
    if (bytes.length > MAX_SIGNAL_BYTES) return;
    const f = utf8Decode(bytes).split("\0");
    if (f.length < 3) return;
    const [tag, from, to] = f;
    if (!hex32(from) || from === ownId || (to !== "" && to !== ownId)) return;
    if (admitPeers !== null && !admitPeers.has(from)) return;
    if (tag === "h" && f.length === 3) return this.onHello(from, to === "");
    if (to === "" || !/^[0-9a-f]{16}$/.test(f[3] ?? "")) return;
    if ((tag === "o" || tag === "a") && f.length === 5) return this.onDescription(from, f[3], tag === "o", f[4]);
    if (tag === "i" && f.length === 8) return this.onCandidate(from, f[3], f.slice(4).join("\0"));
  }

  /** The smaller key offers, as the smaller key's dial wins a TCP double-connect. */
  weOffer(peer) { return ownId < peer; }

  async onHello(from, broadcast) {
    // Answer a broadcast with a directed hello; never answer a directed one.
    if (broadcast) this.signal("h", from);
    const e = this.byPeer.get(from);
    if (e) {
      // A fresh broadcast from a peer whose negotiation never authenticated: it reloaded.
      if (!broadcast || authedData(e)) return;
      this.drop(e);
    }
    if (this.weOffer(from)) await this.open(from, true, toHex(await randomBytes(8)));
  }

  async onDescription(from, sid, isOffer, sdp) {
    let e = this.byPeer.get(from);
    if (isOffer) {
      if (this.weOffer(from)) return;
      if (e && e.sid !== sid) {
        // An authenticated negotiation keeps its link against a fresh offer.
        if (authedData(e)) return;
        this.drop(e);
        e = undefined;
      }
      if (!e) e = await this.open(from, false, sid);
      if (!e) return;
    } else if (!e || !e.offer || e.sid !== sid) {
      return;
    }
    this.down(e, isOffer ? RTC_OFFER : RTC_ANSWER, sdp);
  }

  onCandidate(from, sid, candidate) {
    const e = this.byPeer.get(from);
    if (e && e.sid === sid) this.down(e, RTC_CANDIDATE, candidate);
  }

  /** Open a negotiation link for one peer. Null when the cap is reached or no route. */
  async open(peer, offer, sid) {
    if (this.pending() >= this.maxNegotiating) return null;
    const e = { peer, offer, sid, ctl: 0, data: null, gone: false, due: Infinity };
    this.byPeer.set(peer, e);
    const opened = await netLinkOpen((offer ? "rtc:offer" : "rtc:answer") + this.configSuffix);
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
    if (tag === RTC_OFFER || tag === RTC_ANSWER) {
      this.signal(tag === RTC_OFFER ? "o" : "a", e.peer, e.sid, text);
    } else if (tag === RTC_CANDIDATE) {
      this.signal("i", e.peer, e.sid, text);
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
   *  the peer the relay named, and the answering side accepts whoever authenticates. */
  bindData(via, linkId, stream) {
    const e = this.byCtl.get(via);
    if (!e && !linksById.has(via)) { this.early.set(via, { linkId, stream }); return; }
    if (!e || e.data) { netLinkClose(linkId, false); return; }
    e.data = core.openLink({
      linkId, stream, dest: "", listener: "", linkSecret: null, source: undefined,
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

  /** A negotiation link went. If it carried an authenticated link, renegotiate: the
   *  offering side offers again, the answering side says hello. */
  gone(e) {
    this.byCtl.delete(e.ctl);
    const lost = !e.gone && authedData(e);
    e.gone = true;
    if (this.byPeer.get(e.peer) !== e) return;
    this.byPeer.delete(e.peer);
    if (!lost || !this.relay) return;
    if (e.offer) void randomBytes(8).then((sid) => this.open(e.peer, true, toHex(sid))).catch(() => {});
    else this.signal("h", e.peer);
  }
}

/** Whether this negotiation's data link ever authenticated. */
function authedData(e) { return e.data !== null && e.data.peerId !== ""; }
