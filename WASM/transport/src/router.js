// Link router + request/response layer (§12.6): correlation and protocol ids.

/** A frame's first byte for the transport's own messages between two nodes, beside a
 *  request (0x00, 0x80 without reply) and a response (0x01): `[KIND_CTL][tag u8][body]`. */
const KIND_CTL = 0x02;
/** The control tag asking the peer to close the relayed link it arrived on, since a
 *  direct one has replaced it. rtc.js's signals are the other tags, all letters, so this
 *  one is none. */
const CTL_RETIRE = 0x00;

// ── the router ────────────────────────────────────────────────────────────────

class Router {
  constructor(ownPubkey) {
    this.ownPubkey = ownPubkey;
    // By peerId: { links: routable Link[], direct: how many of them lead, held: links read
    // but no longer written, next: round-robin cursor }. Direct links come before relayed
    // ones, and a peer is here exactly while it has a routable link.
    this.pools = new Map();
  }

  linkCount(peerId) { const p = this.pools.get(peerId); return p ? p.links.length : 0; }
  hasDirect(peerId) { const p = this.pools.get(peerId); return p !== undefined && p.direct > 0; }
  /** The origin of the relay a peer's relayed link runs through, "" for none. */
  relayOf(peerId) { const p = this.pools.get(peerId); return p?.links.find((l) => l.relay)?.relay ?? ""; }

  /** Round-robin over the direct links, or over the relayed ones when there is none. */
  send(to, frame) {
    const pool = this.pools.get(to);
    // Empty only inside `promote`, while a tie-break loser passes its queue on.
    if (!pool || pool.links.length === 0) return false;
    const i = pool.next % (pool.direct || pool.links.length);
    pool.next = i + 1;
    pool.links[i].send(frame);
    return true;
  }

  /** Send on the peer's first link, for frames that must arrive in the order they were
   *  sent: two links deliver in no order between them. */
  sendInOrder(to, frame) {
    const pool = this.pools.get(to);
    if (!pool || pool.links.length === 0) return false;
    pool.links[0].send(frame);
    return true;
  }

  /** Add a newly authenticated link, after the double-connect tie-break, which compares
   *  it only with links of its own kind: a relayed link and a direct one are two paths,
   *  not a double connect. A peer's first link marks it up. False when the link lost the
   *  tie-break, and so does not route. */
  promote(peerId, link) {
    let pool = this.pools.get(peerId);
    const rival = pool && pool.links.find((l) => l.weDialed !== link.weDialed && l.relayed === link.relayed);
    if (rival) {
      if (!this.canonicalKeep(link)) { this.retire(pool, link); return false; }
      Router.unlist(pool, rival);
      this.retire(pool, rival);
    }
    const up = !pool;
    if (up) { pool = { links: [], direct: 0, held: [], next: 0 }; this.pools.set(peerId, pool); }
    Router.list(pool, link);
    if (up) core.checkReady();
    statusChanged();
    return true;
  }

  static list(pool, link) {
    if (link.relayed) { pool.links.push(link); return; }
    pool.links.splice(pool.direct++, 0, link);
  }
  static unlist(pool, link) {
    const i = pool.links.indexOf(link);
    if (i < 0) return false;
    pool.links.splice(i, 1);
    if (!link.relayed) pool.direct--;
    return true;
  }

  /** Only the end that dialed a losing link closes it. Records may already be in flight on
   *  it, so the accepting end keeps it out of routing and reads until the goodbye. */
  retire(pool, loser) {
    if (loser.weDialed) loser.close();
    else pool.held.push(loser);
  }

  /** A direct link to `peerId` has authenticated at this end, the second end to see it:
   *  the peer already routes over it. Stop writing the relayed links, keep reading them
   *  for what is still in flight, and ask the peer to close them, which it does behind
   *  the last record it sent on them. */
  retireRelayed(peerId) {
    const pool = this.pools.get(peerId);
    if (!pool || pool.direct === 0) return;
    for (const link of pool.links.slice(pool.direct)) {
      Router.unlist(pool, link);
      pool.held.push(link);
      link.send(Uint8Array.of(KIND_CTL, CTL_RETIRE));
    }
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
    if (!Router.unlist(pool, link)) return;
    statusChanged();
    if (pool.links.length > 0) return;
    // The winner closed first: a held link is now the only way to the peer, so route it.
    if (pool.held.length > 0) {
      for (const l of pool.held.splice(0)) Router.list(pool, l);
      return;
    }
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
