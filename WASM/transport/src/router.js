// Link router + request/response layer (§12.6): correlation and protocol ids.

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
   *  on it, and anything else is dropped there. `peerPubkey` is the same identity as
   *  `peerId`, in the form the host's attribution takes — carried rather than decoded
   *  again below (ake.js `onRecord`). */
  deliver(peerId, frame, peerPubkey) {
    if (!this.sink || peerId === this.ownId) return;
    this.sink(peerId, frame, peerPubkey);
  }

  // Keyed on the link's own peer id: a link is only ever pooled under the identity it
  // authenticated as (`promote`), so leaving the pool is one map hit and not a walk of
  // every peer. A link that never authenticated carries "" and finds nothing, which is
  // the same answer the walk gave.
  remove(link) {
    const pid = link.peerId;
    const pool = this.links.get(pid);
    if (!pool) return false;
    const i = pool.indexOf(link);
    if (i < 0) return false;
    pool.splice(i, 1);
    if (pool.length === 0) { this.links.delete(pid); this.rr.delete(pid); this.onPeerDown(pid); }
    return true;
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

class ReqRes {
  constructor() {
    // corr → {to, d, due} — d is the deferred answering the app, due the tick its retention
    // bound ends on (0: none)
    this.pending = new Map();
    this.nextCorr = 1;
    // peerId → the weight of that peer's requests waiting on `link/deliver`, and their sum
    this.delivering = new Map();
    this.deliveringWeight = 0;
  }

  /** Settle an outstanding request and drop its bookkeeping. `ok` false ⇒ `payload` is
   *  a utf8 failure message, which becomes the rejection the calling app sees. */
  finish(corr, ok, payload) {
    const p = this.pending.get(corr);
    if (!p) return;
    this.pending.delete(corr);
    if (ok) p.d.settle(concatBytes([Uint8Array.from([1]), payload]));
    else p.d.settle(Uint8Array.from([0]));
  }

  attach(sendFrame) {
    this.sendFrame = sendFrame;
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
   *  The kernel owns the caller's TIME and no field here can name it. What this arms is the
   *  transport's own retention bound on the correlation it just opened — the same kind of
   *  bound `handshakeTimeoutMs` puts on a half-open link and `linkIdleTimeoutMs` on a silent
   *  one, and the pending map is the last waiting state that had none. It cannot EXTEND the
   *  kernel's deadline. When shorter it leaves the caller time to try another peer; when
   *  longer it only cleans this correlation after the caller has expired. That cleanup still
   *  matters because a peer that vanished mid-link sends no close for anything else to notice
   *  (§16.1). */
  request(d, to, proto, payload, noReply) {
    const corr = noReply ? 0 : this.nextCorr++;
    // The wire carries corr as a u32, so the counter wraps where the wire does: past 2^32 a
    // plain JS number would key `pending` on something no peer echo can match, and every
    // request from then on would only ever end at `requestTimeoutMs`. 0 is noReply's.
    if (this.nextCorr > 0xffffffff) this.nextCorr = 1;
    const frame = this.buildReq(corr, noReply, proto, payload);
    if (!noReply) {
      this.pending.set(corr, { to, d, due: requestTimeoutMs > 0 ? dueTick(requestTimeoutMs) : 0 });
    }
    this.sendFrame(to, frame);
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
    if (frame.length < 5) return;
    const kind = frame[0];
    const noReply = !!(kind & 0x80);
    const corr = readU32BE(frame, 1);
    if ((kind & 1) === 1) {
      // res = [1][corr u32][payload]
      const p = this.pending.get(corr);
      if (!p || p.to !== from) return; // response bound to the peer it went to
      // finish copies into the answer synchronously; an intermediate payload copy adds
      // no ownership boundary. netLinkDeliver below likewise assembles its own buffer.
      this.finish(corr, true, frame.subarray(5));
      return;
    }
    if ((kind & 1) === 0) {
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
      answer.then(
        (bytes) => { this.hold(from, -weight); this.respond(corr, noReply, from, bytes); },
        // Only the seam itself can reject — a refused claim and a handler that threw
        // both answer empty. A realm on its way down owes no response.
        () => this.hold(from, -weight),
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

  peerDown(peerId) {
    for (const [corr, p] of this.pending) {
      if (p.to === peerId) this.finish(corr, false, EMPTY);
    }
  }

  /** One tick (core.js `onWake`): retire the correlations whose retention bound has come.
   *  Every bound is the same length, so `pending` is in due order and the walk stops at the
   *  first still waiting. Answers whether one is. */
  onTick() {
    if (requestTimeoutMs <= 0) return false;
    for (const [corr, p] of this.pending) {
      if (tick < p.due) return true;
      this.finish(corr, false, EMPTY);
    }
    return false;
  }

  close() {
    // Settle rather than drop: every one of these is an app parked on a `_net` call.
    for (const corr of [...this.pending.keys()]) this.finish(corr, false, EMPTY);
    this.pending.clear();
  }
}
