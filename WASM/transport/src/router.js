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

  /** One inbound, authenticated, whole message. Returns the delivery frame the request
   *  produced (the link occupant's return convention), or null for a response or a
   *  frame nobody is waiting on. */
  deliver(peerId, frame) {
    if (!this.sink || peerId === this.ownId) return null;
    return this.sink(peerId, frame);
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

// Stall clock (§16.1): re-arms while this request's bytes still drain
// (`flushed < owed`); baseline on first expiry, not at send.
class ReqRes {
  constructor() {
    this.pending = new Map();   // corr → {to, d} — d is the deferred answering the app
    this.timers = new Map();    // corr → timerId
    this.sent = new Map();      // peerId → bytes handed to its links, ever
    this.nextCorr = 1;
    // Inbound requests handed to the host, keyed `peer:corr` — the correlation the
    // response frame echoes, plus whose request it belongs to. The answer arrives as the
    // host's `linkResp` event and this metadata is what frames it onto the wire.
    this.pendingIn = new Map();
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
   *  what its links are still holding. Flat while the wire is not moving. */
  flushed(to) {
    let buffered = 0;
    for (const link of router.linksTo(to)) buffered += netLinkBuffered(link.linkId);
    return (this.sent.get(to) || 0) - buffered;
  }

  /** Arm one request's stall clock. `owed` is `sent` including this request's own
   *  frame — the point at which it has finished being asked. */
  armStall(corr, to, deadlineMs, owed) {
    // The baseline is taken on the first expiry, not here: a frame handed over while the
    // peer is still being dialled routes through the pre-auth pool, where there is no
    // link to read a backlog from, so a baseline taken now would be `sent` with nothing
    // subtracted — an over-estimate no later reading could beat. The cost is one deadline
    // of grace to find the link.
    let mark = null;
    const tick = () => {
      this.timers.delete(corr);
      if (!this.pending.has(corr)) return;
      const now = this.flushed(to);
      // Still going out, and moving: we have not finished asking. Anything else —
      // drained (the peer owes us an answer) or stuck (the wire is) — settles.
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
    // A response is `[1][corr u32][payload]`, so an empty response is exactly five bytes
    // — the shortest legal frame, and the one a request nobody claims answers with. A
    // six-byte floor here would drop it and make "no app serves this protocol"
    // indistinguishable from an unreachable peer. Six is the request branch's floor (it
    // needs the protocol-id length at offset 5) and is checked there.
    if (frame.length < 5) return null;
    const kind = frame[0];
    const noReply = !!(kind & 0x80);
    const corr = readU32BE(frame, 1);
    if ((kind & 1) === 1) {
      // res = [1][corr u32][payload]
      const p = this.pending.get(corr);
      if (!p || p.to !== from) return null; // response bound to the peer it went to
      this.finish(corr, true, frame.slice(5));
      return null;
    }
    if ((kind & 1) === 0) {
      if (frame.length < 6) return null; // no room for the protocol-id length byte
      const idLen = frame[5];
      if (frame.length < 6 + idLen) return null;
      const proto = frame.slice(6, 6 + idLen);
      const payload = frame.slice(6 + idLen);
      // The delivery RETURN frame, not a call: the relation here is that this program
      // returns a request its host must route — `[noReply u8][corr u32][claimLen u8]
      // [claim][attrLen u32][attribution][payload]` — and the answer comes back as the
      // host's own `linkResp` event on a later turn, never re-entering this realm
      // (realm-queue). This program is the link occupant, so it is the one that saw the
      // plaintext and so the one that attributes the request; the host prepends that
      // attribution to the claim handler's input. The KEY the pending answer is filed
      // under is the authenticated sender's, so a corr collision between two peers never
      // answers one peer with the other's response. A noReply request has nothing
      // waiting for it on the wire, so nothing is filed — the host still delivers it and
      // answers nothing, exactly as the request asked.
      const head = new Uint8Array(1 + 4 + 1);
      head[0] = noReply ? 1 : 0;
      writeU32BE(head, 1, corr);
      head[5] = proto.length;
      const attrHead = new Uint8Array(4);
      writeU32BE(attrHead, 0, PK_LEN);
      if (!noReply) this.pendingIn.set(from + ":" + corr, { noReply });
      return concatBytes([head, proto, attrHead, fromHex(from), payload]);
    }
    return null;
  }

  /** Reclaim one inbound request's answer metadata by the wire correlation the answer
   *  event carries. Gone after one use, like every pending entry. */
  redeemInbound(fromBytes, corr) {
    const key = toHex(fromBytes) + ":" + corr;
    const meta = this.pendingIn.get(key);
    if (meta) this.pendingIn.delete(key);
    return meta || null;
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
