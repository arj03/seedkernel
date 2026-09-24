// Link router + request/response layer (§12.6): correlation and protocol ids.

// ── the router ────────────────────────────────────────────────────────────────

class Router {
  constructor(ownPubkey) {
    this.ownPubkey = ownPubkey;
    // peerId → { links: Link[] (authenticated, routable), held: Link[] (tie-break losers
    // the peer has yet to close, read but never routed to), next: round-robin cursor }. A
    // peer is here exactly while it holds a routable link, so this map IS the cohort `peers`
    // reports.
    this.pools = new Map();
  }

  linkCount(peerId) { const p = this.pools.get(peerId); return p ? p.links.length : 0; }
  send(to, frame) {
    const pool = this.pools.get(to);
    // Empty only inside `promote`, while a tie-break loser hands its queue on.
    if (!pool || pool.links.length === 0) return false;
    const i = pool.next % pool.links.length;
    pool.next = i + 1;
    pool.links[i].send(frame);
    return true;
  }

  // Install a freshly-authenticated link: the double-connect tie-break, and the up edge on
  // a peer's first link. A link that loses the tie-break is retired instead (`retire`).
  // The peer lint already ran at msg3/msg2 (`admits`, ake.js).
  promote(peerId, link) {
    let pool = this.pools.get(peerId);
    const rival = pool && pool.links.find((l) => l.weDialed !== link.weDialed);
    if (rival) {
      if (!this.canonicalKeep(link)) { this.retire(pool, link); return; }
      // Out of the pool before it retires, so nothing more is routed to it.
      pool.links.splice(pool.links.indexOf(rival), 1);
      this.retire(pool, rival);
    }
    const up = !pool;
    if (up) { pool = { links: [], held: [], next: 0 }; this.pools.set(peerId, pool); }
    pool.links.push(link);
    if (up) core.checkReady();
  }

  // Only the end that DIALED a losing link closes it. A dialer is authenticated at msg2 and
  // sends behind msg3, before the far end has run this tie-break, so records may already be
  // in flight on the loser; closing it from the accepting end would drop them unread. The
  // dialer's goodbye follows everything it sent there, so the accepting end holds the link
  // out of routing (`held`) and keeps reading until it arrives. A losing dial's queue goes
  // to the winner as it closes (core.js `forget`).
  retire(pool, loser) {
    if (loser.weDialed) loser.close();
    else pool.held.push(loser);
  }

  // Keep the link whose *dialer* is the lexicographically smaller identity. The two are
  // never equal: a link to our own key is refused in the handshake (ake.js `openIdentity`).
  canonicalKeep(link) {
    return link.weDialed === (bytesCompare(this.ownPubkey, link.peerPubkey) < 0);
  }

  // Keyed on the link's own peer id: a link is only ever pooled under the identity it
  // authenticated as (`promote`), so leaving the pool is one map hit and not a walk of
  // every peer. A link that never authenticated carries "" and finds nothing. The last
  // link out is the peer's down edge.
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
    // The winner went before the peer retired a held loser: that loser is now the only
    // way to this peer, and the peer is still sending on it, so it routes again.
    if (pool.held.length > 0) { pool.links = pool.held; pool.held = []; return; }
    this.pools.delete(pid);
    reqres.peerDown(pid);
  }
}

// ── the request/response layer ────────────────────────────────────────────────

/** A request frame's own head: `[kind u8][corr u32][protoLen u8]`. Named because the
 *  `send` op measures a caller's arguments against the frame cap before copying them. */
const REQ_HEAD_LEN = 1 + 4 + 1;
/** A response frame's: `[kind u8][corr u32]`, which `respond` measures an answer against. */
const RES_HEAD_LEN = 1 + 4;

class ReqRes {
  constructor() {
    // corr → {to, d, due} — d is the deferred answering the app, due when its retention
    // bound ends (Infinity: none)
    this.pending = new Map();
    this.nextCorr = 1;
    // peerId → the weight of that peer's requests waiting on `link/deliver`, and their sum
    this.delivering = new Map();
    this.deliveringWeight = 0;
  }

  /** Settle an outstanding request and drop its bookkeeping: `[1][payload]` for the peer's
   *  response, `[0]` when `payload` is null — the peer went down, or the correlation's
   *  retention bound ran out. */
  finish(corr, payload) {
    const p = this.pending.get(corr);
    if (!p) return;
    this.pending.delete(corr);
    p.d.settle(payload === null ? Uint8Array.of(0) : concatBytes([Uint8Array.of(1), payload]));
  }

  /** Whether `from` may put one more request, `weight` wide, on `link/deliver` (core.js
   *  `deliveryWindow`). A peer with none waiting may take any room left; one already waiting
   *  leaves a max-size request's room to a peer that is not, and stops at an equal share
   *  among the peers waiting — so no peer's pipeline can refuse another's. */
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

  /** One request out, on behalf of an app. `d` is the deferred its `handle` invocation
   *  returned (null for a noReply send, which carries corr 0 and nothing waits on).
   *  `proto` and `payload` are BORROWED views of the calling app's argument bytes: `buildReq`
   *  is their only reader and must stay the first thing this does, ahead of any await.
   *
   *  The host owns the caller's TIME and no field here can name it. What this arms is the
   *  transport's own retention bound on the correlation it just opened — the same kind of
   *  bound `handshakeTimeoutMs` puts on a half-open link and `linkIdleTimeoutMs` on a silent
   *  one, and the pending map is the last waiting state that had none. It cannot EXTEND the
   *  host's deadline. When shorter it leaves the caller time to try another peer; when
   *  longer it only cleans this correlation after the caller has expired. That cleanup still
   *  matters because a peer that vanished mid-link sends no close for anything else to notice
   *  (§16.1). A frame no link took is another matter: nothing will ever answer it, so it
   *  fails at once, while the caller may still have time to ask someone else. */
  request(d, to, proto, payload, noReply) {
    const corr = noReply ? 0 : this.nextCorr++;
    // The wire carries corr as a u32, so the counter wraps where the wire does: past 2^32 a
    // plain JS number would key `pending` on something no peer echo can match, and every
    // request from then on would only ever end at `requestTimeoutMs`. 0 is noReply's.
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
    // A response is `[1][corr u32][payload]`, so an empty response is exactly five
    // bytes — the shortest legal frame, and the one a request nobody claims answers
    // with. Six, the request branch's floor, would drop it and make "no app serves
    // this protocol" indistinguishable from an unreachable peer.
    if (frame.length < RES_HEAD_LEN) return;
    const kind = frame[0];
    const noReply = !!(kind & 0x80);
    const corr = readU32BE(frame, 1);
    if ((kind & 1) === 1) {
      // res = [1][corr u32][payload]
      const p = this.pending.get(corr);
      if (!p || p.to !== from) return; // response bound to the peer it went to
      // finish copies into the answer synchronously; an intermediate payload copy adds
      // no ownership boundary. netLinkDeliver below likewise assembles its own buffer.
      this.finish(corr, frame.subarray(RES_HEAD_LEN));
      return;
    }
    if (frame.length < 6) return; // no room for the protocol-id length byte
    const idLen = frame[5];
    if (frame.length < 6 + idLen) return;
    const proto = frame.subarray(6, 6 + idLen);
    const payload = frame.subarray(6 + idLen);
    // One request out to the host's claim routing, answered in the continuation — the
    // mirror image of `request` above. FIRED, never awaited: the answer is another turn
    // of this realm, so the event that decoded this frame must return first. Nothing is
    // filed against the correlation, because `corr`, `noReply` and the AUTHENTICATED
    // sender are all held right here until the answer lands — so a corr collision
    // between two peers cannot answer one with the other's response, and a noReply
    // request needs no bookkeeping to be dropped by `respond`.
    //
    // This program is the link occupant, so it is the one that attributes: it saw the
    // plaintext, and `from` is who the record layer proved wrote it — `fromPubkey` is
    // that same proof in bytes, handed down from the link rather than decoded from the
    // hex, which is per-request work on identity neither end ever re-derives.
    //
    // Past the window, a request is refused the way an unclaimed one is: answered empty.
    const weight = 1 + idLen + PK_LEN + payload.length + callWeight;
    if (!this.admits(from, weight)) { this.respond(corr, noReply, from, EMPTY); return; }
    const answer = netLinkDeliver(proto, fromPubkey, payload);
    this.hold(from, weight);
    // Only the seam itself rejects — the delivery's handoff deadline, or an answer this
    // realm's budget would not copy in. That is no answer either, and it goes back empty
    // like a refused claim or a handler that threw. Either arm is a turn of its own
    // (guest-seam.ts `link/deliver`), so the reply has a budget to be written with.
    const done = (bytes) => { this.hold(from, -weight); this.respond(corr, noReply, from, bytes); };
    answer.then(done, () => done(EMPTY));
  }

  // The response to a delivered request, addressed back to `from`. noReply ran the
  // app's handler but skips the wire response. An answer too big for one record goes back
  // empty — this boundary's one voice for "no answer" — rather than being dropped at the
  // link, which would leave the caller waiting out its deadline.
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

  /** One wake (core.js `onWake`): retire the correlations whose retention bound has come.
   *  Every bound is the same length, so `pending` is in due order and the walk stops at the
   *  first still waiting. Answers its deadline, or `Infinity` when none waits. */
  onWake(t) {
    if (requestTimeoutMs <= 0) return Infinity;
    for (const [corr, p] of this.pending) {
      if (t < p.due) return p.due;
      this.finish(corr, null);
    }
    return Infinity;
  }
}
