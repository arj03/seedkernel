// Link router + request/response layer (§12.6): correlation and protocol ids.

// ── the router ────────────────────────────────────────────────────────────────

class Router {
  constructor(ownPubkey) {
    this.ownPubkey = ownPubkey;
    // By peerId: { links: routable Link[], held: tie-break losers still being read, next:
    // round-robin cursor }. A peer is here exactly while it has a routable link.
    this.pools = new Map();
  }

  linkCount(peerId) { const p = this.pools.get(peerId); return p ? p.links.length : 0; }
  send(to, frame) {
    const pool = this.pools.get(to);
    // Empty only inside `promote`, while a tie-break loser passes its queue on.
    if (!pool || pool.links.length === 0) return false;
    const i = pool.next % pool.links.length;
    pool.next = i + 1;
    pool.links[i].send(frame);
    return true;
  }

  /** Add a newly authenticated link, after the double-connect tie-break. A peer's first
   *  link marks it up. */
  promote(peerId, link) {
    let pool = this.pools.get(peerId);
    const rival = pool && pool.links.find((l) => l.weDialed !== link.weDialed);
    if (rival) {
      if (!this.canonicalKeep(link)) { this.retire(pool, link); return; }
      pool.links.splice(pool.links.indexOf(rival), 1);
      this.retire(pool, rival);
    }
    const up = !pool;
    if (up) { pool = { links: [], held: [], next: 0 }; this.pools.set(peerId, pool); }
    pool.links.push(link);
    if (up) core.checkReady();
  }

  /** Only the end that dialed a losing link closes it. Records may already be in flight on
   *  it, so the accepting end keeps it out of routing and reads until the goodbye. */
  retire(pool, loser) {
    if (loser.weDialed) loser.close();
    else pool.held.push(loser);
  }

  /** Keep the link whose dialer is the lexicographically smaller identity. */
  canonicalKeep(link) {
    return link.weDialed === (bytesCompare(this.ownPubkey, link.peerPubkey) < 0);
  }

  /** Take a link out of its peer's pool; removing the last one marks the peer down. */
  remove(link) {
    const pid = link.peerId;
    const pool = this.pools.get(pid);
    if (!pool) return;
    const h = pool.held.indexOf(link);
    if (h >= 0) { pool.held.splice(h, 1); return; }
    const i = pool.links.indexOf(link);
    if (i < 0) return;
    pool.links.splice(i, 1);
    if (pool.links.length > 0) return;
    // The winner closed first: a held loser is now the only way to the peer, so route it.
    if (pool.held.length > 0) { pool.links = pool.held; pool.held = []; return; }
    this.pools.delete(pid);
    reqres.peerDown(pid);
  }
}

// ── the request/response layer ────────────────────────────────────────────────

/** A request frame's head: `[kind u8][corr u32][protoLen u8]`. */
const REQ_HEAD_LEN = 1 + 4 + 1;
/** A response frame's head: `[kind u8][corr u32]`. */
const RES_HEAD_LEN = 1 + 4;

class ReqRes {
  constructor() {
    // By corr: {to, d, due}, the deferred that answers the app and when it times out.
    this.pending = new Map();
    this.nextCorr = 1;
    // By peerId: the weight of its requests waiting on `link/deliver`; plus the total.
    this.delivering = new Map();
    this.deliveringWeight = 0;
  }

  /** Settle an outstanding request: `[1][payload]`, or `[0]` when `payload` is null (peer
   *  down, or timed out). */
  finish(corr, payload) {
    const p = this.pending.get(corr);
    if (!p) return;
    this.pending.delete(corr);
    p.d.settle(payload === null ? Uint8Array.of(0) : concatBytes([Uint8Array.of(1), payload]));
  }

  /** Whether `from` may put one more request of `weight` on `link/deliver` (core.js
   *  `deliveryWindow`). A peer already waiting must leave room for one max-size request
   *  from others and stops at an equal share, so no peer can starve another. */
  admits(from, weight) {
    const mine = this.delivering.get(from) || 0;
    if (mine === 0) return this.deliveringWeight + weight <= deliveryWindow;
    return this.deliveringWeight + weight <= deliveryWindow - maxRequestWeight
      && mine + weight <= deliveryWindow / this.delivering.size;
  }

  /** Count one of `from`'s requests onto the window, or off it with a negative `weight`. */
  hold(from, weight) {
    const mine = (this.delivering.get(from) || 0) + weight;
    if (mine > 0) this.delivering.set(from, mine); else this.delivering.delete(from);
    this.deliveringWeight += weight;
  }

  /** Send one request for an app. `d` is its deferred (null for noReply, corr 0). `proto`
   *  and `payload` are borrowed views, so `buildReq` runs before any await.
   *  `requestTimeoutMs` bounds the correlation, not the caller (§16.1); a frame no link
   *  accepted fails at once. */
  request(d, to, proto, payload, noReply) {
    const corr = noReply ? 0 : this.nextCorr++;
    // corr is a u32 on the wire; 0 is noReply's.
    if (this.nextCorr > 0xffffffff) this.nextCorr = 1;
    const frame = this.buildReq(corr, noReply, proto, payload);
    if (!noReply) {
      this.pending.set(corr, { to, d, due: requestTimeoutMs > 0 ? dueIn(requestTimeoutMs) : Infinity });
    }
    const unanswerable = () => this.finish(corr, null);
    core.sendFrame(to, frame).then((placed) => { if (!placed) unanswerable(); }, unanswerable);
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

  onFrame(from, frame, fromPubkey) {
    // An empty response (five bytes) is the shortest legal frame.
    if (frame.length < RES_HEAD_LEN) return;
    const kind = frame[0];
    const noReply = !!(kind & 0x80);
    const corr = readU32BE(frame, 1);
    if ((kind & 1) === 1) {
      // res = [1][corr u32][payload]
      const p = this.pending.get(corr);
      if (!p || p.to !== from) return; // only from the peer it went to
      this.finish(corr, frame.subarray(RES_HEAD_LEN));
      return;
    }
    if (frame.length < 6) return; // no room for the protocol-id length byte
    const idLen = frame[5];
    if (frame.length < 6 + idLen) return;
    const proto = frame.subarray(6, 6 + idLen);
    const payload = frame.subarray(6 + idLen);
    // Deliver to the host's claim routing, attributed to the authenticated sender. Not
    // awaited: the answer comes in another turn, and the closure keeps corr and sender.
    // Past the window, answer empty as for an unclaimed request.
    const weight = 1 + idLen + PK_LEN + payload.length + callWeight;
    if (!this.admits(from, weight)) { this.respond(corr, noReply, from, EMPTY); return; }
    const answer = netLinkDeliver(proto, fromPubkey, payload);
    this.hold(from, weight);
    // A seam rejection (deadline, budget) is no answer either: reply empty.
    const done = (bytes) => { this.hold(from, -weight); this.respond(corr, noReply, from, bytes); };
    answer.then(done, () => done(EMPTY));
  }

  /** Answer a delivered request to `from`, unless noReply. An answer too big for one
   *  record is sent back empty instead of leaving the caller waiting. */
  respond(corr, noReply, from, payload) {
    if (noReply) return;
    const fits = payload && RES_HEAD_LEN + payload.length <= maxFrameBytes - TAG_LEN;
    const body = fits ? payload : EMPTY;
    const frame = new Uint8Array(RES_HEAD_LEN + body.length);
    frame[0] = 1; // KIND_RES
    writeU32BE(frame, 1, corr);
    frame.set(body, RES_HEAD_LEN);
    core.sendFrame(from, frame);
  }

  peerDown(peerId) {
    for (const [corr, p] of this.pending) {
      if (p.to === peerId) this.finish(corr, null);
    }
  }

  /** One wake (core.js `onWake`): fail timed-out requests. `pending` is in due order, so
   *  the walk stops at the first one still waiting. */
  onWake(t) {
    if (requestTimeoutMs <= 0) return Infinity;
    for (const [corr, p] of this.pending) {
      if (t < p.due) return p.due;
      this.finish(corr, null);
    }
    return Infinity;
  }
}
