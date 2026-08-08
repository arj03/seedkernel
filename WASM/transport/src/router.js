// ============================================================================
// transport/src/router.js — the two routing layers above the record layer: the
// authenticated link router (ex link-router.ts), which picks the wire a frame
// goes out on, and the request/response layer (ex net.ts Transport), which
// gives the wire its correlation, protocol ids and deadlines.
// ============================================================================

// ── the router (ex link-router.ts) ────────────────────────────────────────────

class Router {
  constructor(ownPubkey, ownId) {
    this.ownPubkey = ownPubkey;
    this.ownId = ownId;
    this.links = new Map();      // peerId → Link[] (authenticated, routable)
    this.rr = new Map();         // peerId → round-robin cursor
    this.sink = null;            // the request/response layer's frame intake
    this.onPeerUp = () => {};
    this.onPeerDown = () => {};
  }

  linkCount(peerId) { const a = this.links.get(peerId); return a ? a.length : 0; }
  /** This peer's routable links, for the stall clock's backlog read. Empty for a peer
   *  still dialing — whose frames sit in the pre-auth pool instead (Core.sendFrame),
   *  where a handshake that never completes is the half-open deadline's business, not
   *  this one's. */
  linksTo(peerId) { return this.links.get(peerId) || []; }

  send(to, frame) {
    const pool = this.links.get(to);
    if (!pool || pool.length === 0) return false;
    const i = (this.rr.get(to) || 0) % pool.length;
    this.rr.set(to, i + 1);
    pool[i].send(frame);
    return true;
  }

  // Install a freshly-authenticated link: the double-connect tie-break and the up edge
  // on a peer's first link. Returns false — the link closed — when it lost the tie-break.
  //
  // The whitelist gate is NOT here. It is the host's policy, and a gate this program is
  // asked to apply to itself is one a hostile occupant of this slot simply skips; the
  // driver enforces it on the attribution this program reports (LINK_AUTH / PEER_UP),
  // where it cannot be bypassed.
  promote(peerId, link) {
    const pool = this.links.get(peerId) || [];
    const wasEmpty = pool.length === 0;
    let rival = null;
    for (const l of pool) if (l.weDialed !== link.weDialed) { rival = l; break; }
    if (rival) {
      if (!this.canonicalKeep(link)) { link.close(); return false; }
      // Splice the rival out BEFORE closing it: close() reaches the transport's
      // forget() → remove() synchronously, which would otherwise splice the very
      // array we are editing (link-router.ts promote).
      pool.splice(pool.indexOf(rival), 1);
      this.links.set(peerId, pool);
      rival.close();
    }
    pool.push(link);
    this.links.set(peerId, pool);
    if (wasEmpty) this.onPeerUp(peerId);
    return true;
  }

  // Keep the link whose *dialer* is the lexicographically smaller identity.
  canonicalKeep(link) {
    const peer = link.peerPubkey, mine = this.ownPubkey;
    const dialer = link.weDialed ? mine : peer;
    const smaller = bytesCompare(mine, peer) <= 0 ? mine : peer;
    return bytesCompare(dialer, smaller) === 0;
  }

  deliver(peerId, frame) {
    if (!this.sink || peerId === this.ownId) return;
    this.sink(peerId, frame);
  }

  remove(link) {
    for (const [pid, pool] of this.links) {
      const i = pool.indexOf(link);
      if (i < 0) continue;
      pool.splice(i, 1);
      if (pool.length === 0) { this.links.delete(pid); this.rr.delete(pid); this.onPeerDown(pid); }
      return true;
    }
    return false;
  }

  closeAll() {
    const all = [];
    for (const pool of this.links.values()) for (const l of pool) all.push(l);
    this.links.clear();
    this.rr.clear();
    for (const l of all) l.close();
  }
}

// ── the request/response layer (ex net.ts Transport) ──────────────────────────

// The event-driven twin of net.ts's Promise-based Transport: the HOST holds the
// promises (keyed by the corr it assigned) and this layer holds the wire state —
// correlation, the response binding, one deadline per request — driven by host timer
// events. `to`/`from` are hex peer ids; proto is opaque bytes.
//
// The deadline arrives WITH each request rather than being inferred here, and that is
// the whole of the timing policy. This layer cannot tell a 200-byte control message
// from a 4 MB block, so anything it computed would be a guess. Re-arming a silence
// window whenever ANY frame arrived from the peer, under an absolute backstop, makes a
// request's lifetime depend on unrelated traffic to the same peer — a chatty request
// keeps a stalled one alive, and a quiet-but-progressing transfer dies. The caller
// knows what it sent; it says so (`request` entrypoint).
//
// The deadline is a STALL clock, not a budget for the whole exchange. Arming it at
// enqueue and letting it expire measured our OWN upload: a request whose bytes are
// still draining out of a backpressured socket has not been answered late, it has not
// finished being asked. A 50 MB PUT across two holders queued ~42 MB behind four
// sockets and every request in the window was cancelled at 5 s while the wire was
// working perfectly — the holders were blamed for our backlog.
//
// So on expiry this asks whether OUR OWN REQUEST is still going out, and only gives up
// if it is not. Two numbers say it, both from bytes rather than from traffic:
//
//   flushed = sent − buffered   bytes for this peer that actually left (monotone)
//   owed                        `sent` at the moment this request was handed over
//
// A link is FIFO, so `flushed ≥ owed` means precisely "this request's last byte is on
// the wire". Until then the exchange has not begun — we are still asking — and an
// expiry that finds `flushed` moving re-arms. After that the clock is a pure silence
// window and settles on schedule.
//
// Bounding the re-arm by `owed` is what keeps this from being the old silence window
// under a new name. Progress measured per PEER would let unrelated frames to the same
// peer keep a request alive — a chatty caller resurrecting a stalled request, exactly
// the flaw that got the previous design deleted. Later frames raise `sent`, never this
// request's `owed`, so nothing another request does can extend this one past its own
// transmission.
class ReqRes {
  constructor() {
    this.pending = new Map();   // corr → {to}
    this.timers = new Map();    // corr → timerId
    this.sent = new Map();      // peerId → bytes handed to its links, ever
  }

  /** Count bytes on their way to a peer — the numerator of the progress measure. */
  note(to, n) { this.sent.set(to, (this.sent.get(to) || 0) + n); }

  /** Bytes of ours that have actually left for this peer: everything handed over,
   *  less what its links are still holding. Monotone non-decreasing while the wire
   *  moves, flat while it does not. */
  flushed(to) {
    let buffered = 0;
    for (const link of router.linksTo(to)) buffered += netLinkBuffered(link.linkId);
    return (this.sent.get(to) || 0) - buffered;
  }

  /** Arm one request's stall clock. `owed` is `sent` including this request's own
   *  frame — the point at which it has finished being asked. */
  armStall(corr, to, deadlineMs, owed) {
    // The baseline is taken on the FIRST expiry, not here. A frame handed over while the
    // peer is still being dialled routes through the pre-auth pool, where there is no
    // link to read a backlog from — so a baseline taken now would be `sent` with nothing
    // subtracted, an over-estimate no later reading could ever beat, and every such
    // request would settle on its first tick however hard the wire was working. One
    // deadline of grace to find the link is the cost, and it is bounded by `owed` like
    // everything else here.
    let mark = null;
    const tick = () => {
      this.timers.delete(corr);
      if (!this.pending.has(corr)) return;
      const now = this.flushed(to);
      // Still going out, and moving: we have not finished asking, so nothing here is
      // late. Anything else — drained (the peer owes us an answer) or not moving (the
      // wire is stuck) — settles.
      if (now < owed && (mark === null || now > mark)) {
        mark = now;
        this.timers.set(corr, armTimer(deadlineMs, tick));
        return;
      }
      this.pending.delete(corr);
      netSettle(corr, false, utf8Encode("net.send: timeout to " + to.slice(0, 8)));
    };
    this.timers.set(corr, armTimer(deadlineMs, tick));
  }

  attach(sendFrame) {
    this.sendFrame = sendFrame;
  }

  request(corr, to, proto, payload, noReply, deadlineMs) {
    const frame = this.buildReq(corr, noReply, proto, payload);
    if (!noReply) {
      // A noReply send carries corr 0 and never resolves — the host keeps no
      // promise for it, so nothing here is parked on its behalf.
      this.pending.set(corr, { to });
    }
    // Count the frame BEFORE it is handed over, so the first stall check cannot read a
    // `flushed` that already includes bytes this request has not yet contributed.
    this.note(to, frame.length);
    const owed = this.sent.get(to);
    this.sendFrame(to, frame);
    if (!noReply) this.armStall(corr, to, deadlineMs, owed);
  }

  buildReq(corr, noReply, proto, payload) {
    const frame = new Uint8Array(1 + 4 + 1 + proto.length + payload.length);
    frame[0] = noReply ? 0x80 : 0; // KIND_REQ | FLAG_NO_REPLY
    writeU32BE(frame, 1, corr);
    frame[5] = proto.length;
    frame.set(proto, 6);
    frame.set(payload, 6 + proto.length);
    return frame;
  }

  onFrame(from, frame) {
    // A response is `[1][corr u32][payload]`, so an EMPTY response is exactly five
    // bytes — the shortest legal frame. Requiring six here dropped it, and since a
    // request nobody is bound to answers empty by contract, that made "no app serves
    // this protocol" indistinguishable from an unreachable peer: the caller waited out
    // its whole deadline instead of being told nothing was there. The six-byte floor is
    // the REQUEST branch's (it needs the protocol-id length at offset 5) and is
    // checked there.
    if (frame.length < 5) return;
    const kind = frame[0];
    const noReply = !!(kind & 0x80);
    const corr = readU32BE(frame, 1);
    if ((kind & 1) === 1) {
      // res = [1][corr u32][payload]
      const p = this.pending.get(corr);
      if (!p || p.to !== from) return; // response bound to the peer it went to
      this.pending.delete(corr);
      const t = this.timers.get(corr);
      if (t) { clearTimer(t); this.timers.delete(corr); }
      netSettle(corr, true, frame.slice(5));
      return;
    }
    if ((kind & 1) === 0) {
      if (frame.length < 6) return; // no room for the protocol-id length byte
      const idLen = frame[5];
      if (frame.length < 6 + idLen) return;
      const proto = frame.slice(6, 6 + idLen);
      const payload = frame.slice(6 + idLen);
      netDeliver(corr, noReply, fromHex(from), proto, payload);
    }
  }

  // The response to a DELIVER'd request, addressed back to `from`. noReply runs
  // the host's handler but skips the wire response.
  respond(corr, noReply, from, payload) {
    if (noReply) return;
    const body = payload || new Uint8Array(0);
    const frame = new Uint8Array(5 + body.length);
    frame[0] = 1; // KIND_RES
    writeU32BE(frame, 1, corr);
    frame.set(body, 5);
    this.sendFrame(from, frame);
  }

  close() {
    for (const t of this.timers.values()) clearTimer(t);
    this.timers.clear();
    this.pending.clear();
  }
}
