// Link router + request/response layer (§12.6): correlation, protocol ids, stall clocks.

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
   *  still dialing, whose frames sit in the pre-auth pool instead (Core.sendFrame). */
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
  // The peer lint already ran at msg3/msg4 (`admits`, ake.js).
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

  /** One inbound, authenticated, whole message, handed to the request/response layer:
   *  a request goes on to the host's claim routing, a response settles the app waiting
   *  on it, and anything else is dropped there. */
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
 *  `send` op measures a caller's arguments against the frame cap before copying them. */
const REQ_HEAD_LEN = 1 + 4 + 1;

// Stall clock, §16.1.
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

  /** Bytes of ours that have actually left for this peer: everything handed over, less
   *  what its links are still holding. Flat while the wire is not moving.
   *  Async: link/stat answers a Promise like every seam call, so the reads FAN OUT —
   *  one round trip for the peer rather than one per link. The ids are taken in this
   *  turn, before the first await: the pool is live, and a link retired mid-read would
   *  otherwise shorten the array being walked and skip a sibling's backlog. */
  async flushed(to) {
    const ids = router.linksTo(to).map((link) => link.linkId);
    const held = await Promise.all(ids.map((id) => netLinkBuffered(id)));
    let buffered = 0;
    for (const n of held) buffered += n;
    return (this.sent.get(to) || 0) - buffered;
  }

  /** Arm one request's stall clock (§16.1 `REQUEST_DEADLINE_MS`). `owed` is `sent`
   *  including this request's own frame — the point at which it has finished being
   *  asked. Baseline taken on first expiry, not here, at the cost of one deadline of
   *  grace: see §16.1 for why. */
  armStall(corr, to, deadlineMs, owed) {
    let mark = null;
    const tick = async () => {
      this.timers.delete(corr);
      if (!this.pending.has(corr)) return;
      const now = await this.flushed(to);
      // Still going out, and moving: we have not finished asking. Anything else —
      // drained (the peer owes us an answer) or stuck (the wire is one) — settles.
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
   *  returned (null for a noReply send, which carries corr 0 and nothing waits on);
   *  `deadlineMs` is the caller's, already resolved against the node's default. */
  request(d, to, proto, payload, noReply, deadlineMs) {
    const corr = noReply ? 0 : this.nextCorr++;
    const frame = this.buildReq(corr, noReply, proto, payload);
    if (!noReply) {
      this.pending.set(corr, { to, d });
    }
    // Count the frame before it is handed over, so the first stall check cannot read a
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
    // A response is `[1][corr u32][payload]`, so an empty response is exactly five
    // bytes — the shortest legal frame, and the one a request nobody claims answers
    // with. Six, the request branch's floor, would drop it and make "no app serves
    // this protocol" indistinguishable from an unreachable peer.
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
      // One request out to the host's claim routing, answered in the continuation — the
      // mirror image of `request` above. FIRED, never awaited: the answer is another turn
      // of this realm, so the event that decoded this frame must return first. Nothing is
      // filed against the correlation, because `corr`, `noReply` and the AUTHENTICATED
      // sender are all held right here until the answer lands — so a corr collision
      // between two peers cannot answer one with the other's response, and a noReply
      // request needs no bookkeeping to be dropped by `respond`.
      //
      // This program is the link occupant, so it is the one that attributes: it saw the
      // plaintext, and `from` is who the record layer proved wrote it.
      netLinkDeliver(proto, fromHex(from), payload).then(
        (answer) => this.respond(corr, noReply, from, answer),
        // Only the seam itself can reject — a refused claim and a handler that threw
        // both answer empty. A realm on its way down owes no response.
        () => {},
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
    // Settle rather than drop: every one of these is an app parked on a `_net` call.
    for (const corr of [...this.pending.keys()]) this.finish(corr, false, EMPTY);
    this.pending.clear();
  }
}
