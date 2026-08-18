// ============================================================================
// transport/src/router.js — the two routing layers above the record layer: the
// authenticated link router, which picks the wire a frame goes out on, and the
// request/response layer, which gives the wire its correlation, protocol ids and
// deadlines.
// ============================================================================

// ── the router ────────────────────────────────────────────────────────────────

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

  // Install a freshly-authenticated link: the double-connect tie-break and the up edge on
  // a peer's first link. Returns false — the link closed — when it lost the tie-break.
  // The peer lint already ran at msg3/msg4 (`admits`, ake.js), the only place it can run
  // without becoming an oracle.
  promote(peerId, link) {
    const pool = this.links.get(peerId) || [];
    const wasEmpty = pool.length === 0;
    let rival = null;
    for (const l of pool) if (l.weDialed !== link.weDialed) { rival = l; break; }
    if (rival) {
      if (!this.canonicalKeep(link)) { link.close(); return false; }
      // Splice the rival out BEFORE closing it: close() reaches forget() → remove()
      // synchronously, which would otherwise splice the array we are editing.
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

// ── the request/response layer ────────────────────────────────────────────────

/** A request frame's own head: `[kind u8][corr u32][protoLen u8]`. Named because the
 *  `send` op measures a caller's arguments against the frame cap before copying them,
 *  and what a request adds to a payload is this layer's business to say. */
const REQ_HEAD_LEN = 1 + 4 + 1;

// Correlation, the response binding, one deadline per request — and the promise. An
// app's send arrives as an ordinary invocation of `handle`, which answers with
// `defer()`: this layer holds the deferred, matches the response frame to it by corr,
// and settles it. The corr is a wire value only, never crossing the seam in either
// direction, so nothing about a request is visible outside this heap. `to`/`from` are
// hex peer ids; proto is opaque bytes.
//
// The deadline arrives WITH each request rather than being inferred here: this layer
// cannot tell a 200-byte control message from a 4 MB block, so anything it computed
// would be a guess.
//
// It is a STALL clock, not a budget for the whole exchange. A request whose bytes are
// still draining out of a backpressured socket has not been answered late — it has not
// finished being asked, and blaming the holder for our own backlog cancels every
// request in the window while the wire works perfectly. So on expiry this asks whether
// OUR OWN request is still going out, from bytes rather than traffic:
//
//   flushed = sent − buffered   bytes for this peer that actually left (monotone)
//   owed                        `sent` at the moment this request was handed over
//
// A link is FIFO, so `flushed ≥ owed` means precisely "this request's last byte is on
// the wire". Until then an expiry that finds `flushed` moving re-arms; after it, the
// clock is a pure silence window and settles on schedule.
//
// Bounding the re-arm by `owed` is what keeps this from being a silence window under
// another name: progress measured per PEER would let a chatty caller's unrelated frames
// resurrect a stalled request. Later frames raise `sent`, never this request's `owed`.
class ReqRes {
  constructor() {
    this.pending = new Map();   // corr → {to, d} — d is the deferred answering the app
    this.timers = new Map();    // corr → timerId
    this.sent = new Map();      // peerId → bytes handed to its links, ever
    this.nextCorr = 1;
  }

  /** Settle an outstanding request and drop its bookkeeping. `ok` false ⇒ `payload` is
   *  a utf8 failure message, which becomes the rejection the calling app sees. */
  finish(corr, ok, payload) {
    const p = this.pending.get(corr);
    if (!p) return;
    this.pending.delete(corr);
    const t = this.timers.get(corr);
    if (t) { clearTimer(t); this.timers.delete(corr); }
    if (ok) p.d.settle(concatBytes([Uint8Array.from([1]), payload]));
    else p.d.settle(Uint8Array.from([0]));
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
    // link to read a backlog from — a baseline taken now would be `sent` with nothing
    // subtracted, an over-estimate no later reading could beat, and every such request
    // would settle on its first tick however hard the wire was working. The cost is one
    // deadline of grace to find the link.
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
      this.finish(corr, false, EMPTY);
    };
    this.timers.set(corr, armTimer(deadlineMs, tick));
  }

  attach(sendFrame) {
    this.sendFrame = sendFrame;
  }

  /** One request out, on behalf of an app. `d` is the deferred its `handle` invocation
   *  returned (null for a noReply send, which nothing is waiting on); `deadlineMs` is the
   *  caller's, already resolved against the node's default. */
  request(d, to, proto, payload, noReply, deadlineMs) {
    const corr = noReply ? 0 : this.nextCorr++;
    const frame = this.buildReq(corr, noReply, proto, payload);
    if (!noReply) {
      // A noReply send carries corr 0 and never resolves — nothing is parked on its
      // behalf, here or anywhere.
      this.pending.set(corr, { to, d });
    }
    // Count the frame BEFORE it is handed over, so the first stall check cannot read a
    // `flushed` that already includes bytes this request has not yet contributed.
    this.note(to, frame.length);
    const owed = this.sent.get(to);
    this.sendFrame(to, frame);
    if (!noReply) this.armStall(corr, to, deadlineMs, owed);
  }

  buildReq(corr, noReply, proto, payload) {
    const frame = new Uint8Array(REQ_HEAD_LEN + proto.length + payload.length);
    frame[0] = noReply ? 0x80 : 0; // KIND_REQ | FLAG_NO_REPLY
    writeU32BE(frame, 1, corr);
    frame[5] = proto.length;
    frame.set(proto, 6);
    frame.set(payload, 6 + proto.length);
    return frame;
  }

  onFrame(from, frame) {
    // A response is `[1][corr u32][payload]`, so an EMPTY response is exactly five bytes
    // — the shortest legal frame, and the one a request nobody claims answers with. A
    // six-byte floor here would drop it and make "no app serves this protocol"
    // indistinguishable from an unreachable peer. Six is the REQUEST branch's floor (it
    // needs the protocol-id length at offset 5) and is checked there.
    if (frame.length < 5) return;
    const kind = frame[0];
    const noReply = !!(kind & 0x80);
    const corr = readU32BE(frame, 1);
    if ((kind & 1) === 1) {
      // res = [1][corr u32][payload]
      const p = this.pending.get(corr);
      if (!p || p.to !== from) return; // response bound to the peer it went to
      this.finish(corr, true, frame.slice(5));
      return;
    }
    if ((kind & 1) === 0) {
      if (frame.length < 6) return; // no room for the protocol-id length byte
      const idLen = frame[5];
      if (frame.length < 6 + idLen) return;
      const proto = frame.slice(6, 6 + idLen);
      const payload = frame.slice(6 + idLen);
      // Dispatched with `.then`, never awaited: the answer comes back through THIS
      // realm's queue, so a frame that awaited it would hold the queue against its own
      // reply (realm-queue.ts).
      hostDeliver(fromHex(from), proto, payload).then(
        (resp) => this.respond(corr, noReply, from, resp),
        // A protocol nobody claims, or an app whose handler threw: the request is
        // answered with an empty body rather than discarded, so a caller learns
        // "nothing is there" now instead of waiting out its whole deadline (§12.10).
        () => this.respond(corr, noReply, from, EMPTY),
      );
    }
  }

  // The response to a delivered request, addressed back to `from`. noReply ran the
  // app's handler but skips the wire response.
  respond(corr, noReply, from, payload) {
    if (noReply) return;
    const body = payload || EMPTY;
    const frame = new Uint8Array(5 + body.length);
    frame[0] = 1; // KIND_RES
    writeU32BE(frame, 1, corr);
    frame.set(body, 5);
    this.sendFrame(from, frame);
  }

  close() {
    for (const t of this.timers.values()) clearTimer(t);
    this.timers.clear();
    // Settle rather than drop: every one of these is an app parked on a `_net` call,
    // and a realm going away must not leave it waiting forever.
    for (const corr of [...this.pending.keys()]) this.finish(corr, false, EMPTY);
    this.pending.clear();
  }
}
