// A reliable, ordered byte stream over a datagram path (§12.7), the data link of a UDP
// path (udp.js). The link above it authenticates and encrypts, frames its records and
// times idle links out, so all this does is get bytes across, in order, at a rate the path
// takes.
//
// The recovery design is QUIC's (RFC 9002), cut down:
// - Every packet gets a new number, a resent chunk's too, so an ack names one send and a
//   round-trip sample is never ambiguous.
// - The stream is cut into chunks at their first send, and a lost chunk is resent whole at
//   its offset, so the receiver reassembles by offset alone. What waits past a gap is
//   capped at two credits, counted as the packets it came in; a peer past that is gone.
// - An ack carries ranges of packet numbers, of those the sender still waits on: every
//   DATA packet names the oldest, and the receiver forgets the ranges below it, so a lost
//   packet is not named in every ack after. A packet is lost once one sent three later is
//   acked, or once it is 9/8 of a round trip older than one that was. A probe timeout finds
//   a lost tail, which has no later packet to give it away.
// - NewReno congestion control, run as `FLOWS` flows at once: slow start, the window cut
//   by 1/(2 FLOWS) once per loss episode, then grown by `FLOWS` packets a round trip, and
//   only while it is what holds the sender back. Losses through `PERSISTENT_PTOS` probe
//   timeouts, with nothing acked between, start the window over at two packets.
// - Every ack says how far the receiver will take the stream, so a reader still decoding
//   the last read stops the sender, and a credit read in under two round trips doubles it,
//   up to `MAX_CREDIT`. Nothing acks an ack, so the one that lets a sender that has used
//   all it was given go on is sent three times.
// - Data in flight that draws no ack through `MAX_PTOS` probe timeouts, from a peer heard
//   from not at all for `DEAD_MS`, ends the path: the peer is gone.
// - A path starts at QUIC's 1200-byte packets and, once the peer first acks, probes for
//   `MAX_PACKET` (RFC 8899): a probe the peer acks raises the size, and a second probe
//   timeout in a row drops it back and probes again. Every cost of the stream is per
//   packet, so larger ones are that much cheaper. A chunk cut larger than the path now
//   carries is split when it is resent.
//
// A packet is the path's header, `[type u8][receiver's token 8]`, then:
//   DATA   [pn 6][offset 6][floor 6][bytes]   no packet below floor is waited on
//   ACK    [credit 6][delay u16 ms][count u8]([largest 6][smallest 6])*   newest range first
//   PROBE  [pn 6], padded to `MAX_PACKET`
//   CLOSE  nothing
// The stream writes the type and leaves the token to the path. Its timers are due times
// the realm's wake walks (core.js `onWake`).

const S_DATA = 0x64, S_ACK = 0x61, S_PROBE = 0x6d, S_CLOSE = 0x78;
/** The path's header in front of every packet. */
const PATH_HEADER = 9;
/** A DATA packet's bytes ahead of its chunk. */
const DATA_HEADER = PATH_HEADER + 18;
/** The size a path starts at: QUIC's floor, which every path is taken to carry. */
const BASE_PACKET = 1200;
/** The size a probe asks a path to carry: Ethernet's 1500 bytes less IPv6's and UDP's
 *  headers, quinn's ceiling, which a tunnel or PPPoE beneath still carries. */
const MAX_PACKET = 1452;
/** Probes sent, a probe timeout apart, before a path is taken not to carry `MAX_PACKET`. */
const MAX_PROBES = 3;
const INITIAL_WINDOW = 10 * BASE_PACKET;
const MIN_WINDOW = 2 * BASE_PACKET;
/** How many NewReno flows the window behaves as (MulTCP): it grows by this many packets a
 *  round trip and a loss cuts it by 1/(2 FLOWS), as that many TCP connections would
 *  together, which is what a TCP peer opens to fill a lossy path. */
const FLOWS = 8;
/** Lost packets sent further apart than this many probe timeouts, with none acked between,
 *  are persistent congestion (RFC 9002 §7.6): nothing got across for that long, so what the
 *  window learned no longer holds. */
const PERSISTENT_PTOS = 3;
/** The most packets a loss episode can declare lost and still have its cut undone. Reordering
 *  holds back a few; more at once is congestion, and every ack tests each one. */
const MAX_SUSPECTS = 32;
/** How far past what its reader has taken a receiver takes the stream, to begin with, and
 *  at most: a sender has one credit a round trip, so this is 84 MB/s at 100 ms. */
const CREDIT = 1 << 20, MAX_CREDIT = 8 * CREDIT;
/** What each buffered datagram is charged against the credit as a count, so the slices held
 *  for the reader are bounded whatever their size. */
const MIN_CHUNK = 256;
/** The most one read hands the link. */
const MAX_READ = 256 * 1024;
/** Written and not yet acked, past which a write fails the link, as the host fails a socket
 *  whose backlog passes its cap (net-limits.ts `MAX_OUTBOUND_QUEUE_BYTES`). */
const MAX_BUFFERED = 16 * 1024 * 1024;
/** Received packet numbers are acked as at most this many ranges, the newest. */
const MAX_RANGES = 32;
/** What the probe timeout allows for a receiver holding its ack, which it does for a turn. */
const ACK_DELAY_MS = 25;
const INITIAL_RTT_MS = 333;
/** Something is sent at least this often, which keeps the path's NAT mappings open. */
const KEEPALIVE_MS = 5_000;
/** A path that has said nothing for this long is gone. */
const SILENT_MS = 30_000;
/** Data in flight through this many probe timeouts in a row, with the peer silent for
 *  `DEAD_MS`, means the peer is gone. The floor is above twice the host's default guest
 *  deadline, since a peer whose loop a guest holds acks nothing until it lets go. */
const MAX_PTOS = 6;
const DEAD_MS = 10_000;
/** How long a graceful close waits for what was written to be acked. */
const LINGER_MS = 10_000;

const SENT = Promise.resolve();

/** Where a packet's body starts. */
const B = PATH_HEADER;

/** Whether an ACK's `count` ranges name packet `pn`. */
function names(p, count, pn) {
  for (let i = 0; i < count; i++) {
    if (pn <= readU48BE(p, B + 9 + 12 * i) && pn >= readU48BE(p, B + 15 + 12 * i)) return true;
  }
  return false;
}

/** A packet with `body` bytes behind the header, its type written. */
function packet(type, body) {
  const p = new Uint8Array(B + body);
  p[0] = type;
  return p;
}

/** The stream, and the channel its link writes to (ake.js `Link`): `send` keeps the bytes
 *  it is given. */
class UdpStream {
  /** `onGone` runs once when the stream stops, however it does. */
  constructor(onGone) {
    this.onGone = onGone;
    /** The path, once it is chosen; until then nothing is sent. */
    this.out = null;
    /** The link reading the stream, and whether it is still decoding the last read. */
    this.read = null;
    this.reading = false;
    this.readDone = () => { this.reading = false; this.deliver(); };

    // ── sending ──
    this.unsent = new Pieces();
    /** The stream offset past the last byte written, and past the last ever sent. */
    this.written = 0;
    this.nextOffset = 0;
    /** Chunks sent and not acked, by offset. */
    this.chunks = new Map();
    /** Chunk offsets in the order first sent, all acked before `sentHead`: the oldest chunk
     *  not acked, found without iterating the map, which QuickJS charges for per entry. */
    this.sentOffsets = [];
    this.sentHead = 0;
    /** Offsets of chunks to send again. */
    this.lost = new Set();
    /** Packets in flight, `{offset, size, time}` by number, none below `oldestPn`. They are
     *  walked by number, not iterated, for the same reason. */
    this.inFlight = new Map();
    this.oldestPn = 0;
    this.nextPn = 0;
    this.largestAcked = -1;
    this.bytesInFlight = 0;
    this.window = INITIAL_WINDOW;
    this.threshold = Infinity;
    this.recoveryStart = -Infinity;
    /** The packets the current loss episode declared lost, up to `MAX_SUSPECTS`, and the
     *  window it cut. Should every one of them be acked after all, they were late, not
     *  lost, and the cut is undone. */
    this.suspects = [];
    this.undo = null;
    this.windowLimited = false;
    this.peerCredit = CREDIT;
    this.srtt = INITIAL_RTT_MS;
    this.rttvar = INITIAL_RTT_MS / 2;
    /** Infinity until the first round-trip sample. */
    this.minRtt = Infinity;
    this.latestRtt = 0;
    this.ptoCount = 0;
    this.lastSentData = 0;
    this.lossTime = Infinity;
    /** The size a packet is on this path, and the probes for `MAX_PACKET` not yet
     *  answered. */
    this.packetBytes = BASE_PACKET;
    this.probes = [];
    /** Started, or dropped back to `BASE_PACKET`: probe once the peer acks. */
    this.reprobe = false;

    // ── receiving ──
    /** The offset the reader has been handed up to, and what follows it in order. */
    this.taken = 0;
    this.held = new Pieces();
    /** Chunks past a gap, by offset, and the packet bytes they came in. */
    this.ahead = new Map();
    this.aheadBytes = 0;
    /** The offset past the furthest byte received. */
    this.furthest = 0;
    this.turnDue = false;
    /** Packet numbers received, as `[largest, smallest]`, newest first. */
    this.ranges = [];
    this.largestAt = 0;
    this.unacked = 0;
    /** How far past `taken` this end takes the stream, and when its reader began this
     *  credit. */
    this.credit = CREDIT;
    this.creditAt = -Infinity;
    this.creditEnd = 0;
    this.advertised = CREDIT;

    // ── life ──
    this.lastSent = 0;
    this.lastHeard = 0;
    // When each timer is due, `Infinity` for none.
    this.recoveryAt = Infinity;
    this.probeAt = Infinity;
    this.liveAt = Infinity;
    this.lingerAt = Infinity;
    this.closing = false;
    this.gone = false;
  }

  /** The path is chosen: start sending through `out`. */
  start(out) {
    if (this.gone || this.out) return;
    this.out = out;
    this.lastHeard = this.lastSent = now();
    this.liveAt = dueIn(KEEPALIVE_MS);
    if (this.ranges.length > 0) this.sendAck();
    this.flush();
    // Not yet: the peer's end may not be running, and a probe it never hears holds the
    // floor of every chunk until the probe times out.
    this.reprobe = true;
  }

  /** The path moved to another address, `rttMs` away: what was learned of the old one no
   *  longer holds, so the window and the packet size start over, and a loss among what was
   *  sent before the move does not cut the new window. */
  repath(rttMs) {
    if (this.gone) return;
    this.window = INITIAL_WINDOW;
    this.threshold = Infinity;
    this.recoveryStart = now();
    this.undo = null;
    this.suspects.length = 0;
    this.minRtt = Infinity;
    this.sample(rttMs, 0);
    this.ptoCount = 0;
    this.packetBytes = BASE_PACKET;
    this.reprobe = false;
    this.sendAck();
    this.flush();
    this.startProbe();
  }

  /** One packet from the peer, header included. */
  receive(p) {
    if (this.gone) return;
    this.lastHeard = now();
    const body = p.length - B;
    if (p[0] === S_DATA && body > 18) this.onChunk(readU48BE(p, B), readU48BE(p, B + 6), readU48BE(p, B + 12), p.subarray(B + 18));
    else if (p[0] === S_ACK && body >= 9 && body >= 9 + 12 * p[B + 8]) this.onAck(p);
    else if (p[0] === S_PROBE && body >= 6) this.received(readU48BE(p, B));
    else if (p[0] === S_CLOSE) this.fail();
  }

  // ── the channel ──

  send(bytes) {
    if (this.gone || this.closing) throw new Error("udp: link is closed");
    if (this.buffered() + bytes.length > MAX_BUFFERED) throw new Error("udp: outbound limit exceeded");
    if (bytes.length === 0) return SENT;
    this.unsent.push(bytes);
    this.written += bytes.length;
    this.flush();
    return SENT;
  }

  /** The link that reads the stream: `read(bytes)` answers a promise of having decoded
   *  them, and nothing more is handed over until it settles. */
  reader(read) {
    this.read = read;
    this.deliver();
  }

  /** Written and not yet acked, which drains in send order. */
  buffered() {
    const oldest = this.oldestChunk();
    return this.written - (oldest < 0 ? this.nextOffset : oldest);
  }

  /** A graceful close waits for what was written to be acked, up to `LINGER_MS`. */
  close(graceful) {
    if (this.gone || this.closing) return true;
    if (graceful && this.out && this.buffered() > 0) {
      this.closing = true;
      this.lingerAt = dueIn(LINGER_MS);
      return true;
    }
    this.end();
    return true;
  }

  /** Tell the peer, in case it can still hear, then stop. */
  end() {
    if (this.gone) return;
    this.sendClose();
    this.fail();
  }

  /** One wake (core.js `onWake`): what is due, and when the next is. */
  onWake(t) {
    if (this.gone) return Infinity;
    if (t >= this.lingerAt) { this.end(); return Infinity; }
    if (t >= this.liveAt) this.tick(t);
    if (!this.gone && t >= this.recoveryAt) this.onRecovery(t);
    if (!this.gone && t >= this.probeAt) this.sendProbe();
    return this.gone ? Infinity : Math.min(this.recoveryAt, this.probeAt, this.liveAt, this.lingerAt);
  }

  // ── receiving ──

  onChunk(pn, offset, floor, bytes) {
    // Past the credit this end gave: not taken and not acked, so it comes again.
    if (offset + bytes.length > this.taken + this.credit) return;
    this.received(pn);
    // The sender waits on nothing below `floor`, which is never past `pn`.
    const r = this.ranges;
    while (r.length > 1 && r[r.length - 1][0] < floor) r.pop();
    this.furthest = Math.max(this.furthest, offset + bytes.length);
    let end = this.taken + this.held.bytes;
    if (offset === end) {
      // Held as it came: an event's datagrams are this realm's to keep.
      this.held.push(bytes);
      for (let next; (next = this.ahead.get(end = this.taken + this.held.bytes));) {
        this.ahead.delete(end);
        this.aheadBytes -= DATA_HEADER + next.length;
        this.held.push(next);
      }
      // A chunk split on its way can arrive both whole and in pieces, and a piece waiting
      // inside a whole one is never reached; once nothing is missing, none is of use.
      if (end === this.furthest && this.ahead.size > 0) { this.ahead.clear(); this.aheadBytes = 0; }
    } else if (offset > end && !this.ahead.has(offset)) {
      // A copy, so a chunk waiting on a gap keeps no whole batch of datagrams alive.
      this.ahead.set(offset, bytes.slice());
      // An honest sender has a credit of chunks past a gap, which a split overlaps a little.
      // Chunks at every offset in it, each overlapping the next, would be a credit per byte.
      this.aheadBytes += DATA_HEADER + bytes.length;
    }
    // Bound the datagrams held by their count as well as their bytes: a credit of one-byte
    // chunks is a credit of slices, each costing far more than its byte.
    if (this.aheadBytes > 2 * this.credit || this.held.slices + this.ahead.size > 2 * this.credit / MIN_CHUNK) this.fail();
  }

  /** Note `pn` as received, and see it acked. */
  received(pn) {
    const largest = this.ranges.length > 0 ? this.ranges[0][0] : -1;
    this.record(pn);
    // Only ever inside `receive`, which has just read the clock.
    if (pn > largest) this.largestAt = this.lastHeard;
    // Out of order, a gap or a repeat is acked at once, so the sender learns of it.
    if (pn !== largest + 1) this.sendAck();
    else this.unacked++;
    // Everything else once a datagrams event, not once a packet (udp.js `turn`).
    if (!this.turnDue) {
      this.turnDue = true;
      udp.turns.push(this);
    }
  }

  /** The end of the datagrams event that brought packets: one read and one ack for all. */
  turn() {
    this.turnDue = false;
    this.deliver();
    if (this.unacked > 0) this.sendAck();
  }

  /** Hand the reader what is in order, once it has decoded the last, and tell the sender
   *  once that has freed half the credit. */
  deliver() {
    while (!this.reading && this.read && this.held.bytes > 0 && !this.gone) {
      const bytes = this.held.take(Math.min(this.held.bytes, MAX_READ));
      this.taken += bytes.length;
      this.reading = true;
      this.read(bytes).then(this.readDone, this.readDone);
    }
    // A credit read in under two round trips held the sender back (quiche's autotune).
    if (this.taken >= this.creditEnd) {
      const t = now();
      if (t - this.creditAt < 2 * this.srtt) this.credit = Math.min(2 * this.credit, MAX_CREDIT);
      this.creditAt = t;
      this.creditEnd = this.taken + this.credit;
    }
    if (this.taken + this.credit - this.advertised >= this.credit / 2) this.sendAck();
  }

  /** Note a packet number as received, merging it into the ranges. */
  record(pn) {
    const r = this.ranges;
    let i = 0;
    while (i < r.length && r[i][1] > pn + 1) i++;
    if (i === r.length || r[i][0] + 1 < pn) r.splice(i, 0, [pn, pn]);
    else if (pn === r[i][0] + 1) r[i][0] = pn;
    else if (pn === r[i][1] - 1) {
      r[i][1] = pn;
      if (i + 1 < r.length && r[i + 1][0] === pn - 1) r[i][1] = r.splice(i + 1, 1)[0][1];
    }
    if (r.length > MAX_RANGES) r.length = MAX_RANGES;
  }

  sendAck() {
    if (!this.out || this.gone) return;
    this.unacked = 0;
    const r = this.ranges;
    const p = packet(S_ACK, 9 + 12 * r.length);
    const credit = this.taken + this.credit;
    // More credit for a sender that has used all it had, which may have nothing in flight to
    // draw another ack: one lost would leave it waiting for the keepalive, so it goes three
    // times, as a close does.
    const copies = credit > this.advertised && this.furthest >= this.advertised ? 3 : 1;
    this.advertised = credit;
    writeU48BE(p, B, credit);
    const delay = Math.min(0xffff, Math.round(now() - this.largestAt));
    writeU16BE(p, B + 6, delay);
    p[B + 8] = r.length;
    for (let i = 0; i < r.length; i++) {
      writeU48BE(p, B + 9 + 12 * i, r[i][0]);
      writeU48BE(p, B + 15 + 12 * i, r[i][1]);
    }
    for (let i = 0; i < copies; i++) this.emit(p);
  }

  // ── sending ──

  onAck(p) {
    this.peerCredit = Math.max(this.peerCredit, readU48BE(p, B));
    const count = p[B + 8];
    if (count > 0) {
      // Ranges are newest first. Each is clamped below the previous range's floor, so a
      // peer cannot make overlapping ranges walk the same packet numbers again: the work
      // is bounded by the packets sent, not by the range count.
      const sent = this.nextPn - 1;
      const largest = Math.min(readU48BE(p, B + 9), sent);
      let newest;
      let below = Infinity;
      for (let i = 0; i < count; i++) {
        const hi = Math.min(readU48BE(p, B + 9 + 12 * i), sent, below);
        const lo = Math.max(readU48BE(p, B + 15 + 12 * i), this.oldestPn);
        if (lo > hi) continue;
        for (let pn = lo; pn <= hi; pn++) {
          const s = this.inFlight.get(pn);
          if (!s) continue;
          this.inFlight.delete(pn);
          this.bytesInFlight -= s.size;
          this.chunks.delete(s.offset);
          this.ptoCount = 0;
          if (pn === largest) newest = s;
          // NewReno growth, but not for what was sent before the last loss, or while the
          // window is not what holds the sender back.
          if (s.time > this.recoveryStart && this.windowLimited)
            this.window += this.window < this.threshold ? s.size : FLOWS * this.packetBytes * s.size / this.window;
        }
        below = lo - 1;
      }
      if (this.probes.length > 0) this.probeAcked(p, count);
      // A suspect the ack names was late, not lost.
      for (let i = this.suspects.length - 1; i >= 0; i--) {
        if (names(p, count, this.suspects[i])) this.suspects.splice(i, 1);
      }
      if (this.undo && this.suspects.length === 0) {
        this.window = Math.max(this.window, this.undo.window);
        this.threshold = this.undo.threshold;
        this.undo = null;
      }
      this.largestAcked = Math.max(this.largestAcked, largest);
      this.advanceOldest();
      const t = now();
      if (newest) this.sample(t - newest.time, readU16BE(p, B + 6));
      this.detectLoss(t);
      // The peer acks again after a drop back: see whether the path still carries more.
      if (this.reprobe && this.ptoCount === 0) { this.reprobe = false; this.startProbe(); }
    }
    if (this.closing && this.buffered() === 0) { this.end(); return; }
    this.flush();
  }

  sample(latest, delay) {
    this.latestRtt = latest;
    if (this.minRtt === Infinity) {
      this.minRtt = this.srtt = latest;
      this.rttvar = latest / 2;
      return;
    }
    this.minRtt = Math.min(this.minRtt, latest);
    const adjusted = latest - delay >= this.minRtt ? latest - delay : latest;
    this.rttvar = 0.75 * this.rttvar + 0.25 * Math.abs(this.srtt - adjusted);
    this.srtt = 0.875 * this.srtt + 0.125 * adjusted;
  }

  /** Declare lost what an ack has passed, and arm the loss timer for what it nearly has. */
  detectLoss(t) {
    this.lossTime = Infinity;
    const delay = Math.max(9 / 8 * Math.max(this.latestRtt, this.srtt), 1);
    const persistence = PERSISTENT_PTOS * this.pto();
    let lostSentAt = -Infinity, runFrom = Infinity, persistent = false;
    const lost = [];
    this.advanceOldest();
    for (let pn = this.oldestPn; pn < this.largestAcked; pn++) {
      const s = this.inFlight.get(pn);
      // A run of losses goes unbroken by number: a packet acked, or not in flight, ends it.
      if (!s) { runFrom = Infinity; continue; }
      if (this.largestAcked - pn >= 3 || s.time <= t - delay) {
        this.inFlight.delete(pn);
        this.bytesInFlight -= s.size;
        if (this.chunks.has(s.offset)) this.lost.add(s.offset);
        lostSentAt = Math.max(lostSentAt, s.time);
        lost.push(pn);
        // Of what was sent since the last cut only, as for the cut, so what went to an
        // address the path has left does not count against the new one.
        if (s.time <= this.recoveryStart) continue;
        if (runFrom === Infinity) runFrom = s.time;
        else if (s.time - runFrom > persistence) persistent = true;
      } else {
        this.lossTime = Math.min(this.lossTime, s.time + delay);
      }
    }
    // One cut per episode: losses among packets sent before it began are the same one.
    if (lostSentAt > this.recoveryStart) {
      this.recoveryStart = t;
      this.undo = { window: this.window, threshold: this.threshold };
      this.suspects.length = 0;
      this.window = this.threshold = Math.max(this.window * (1 - 1 / (2 * FLOWS)), MIN_WINDOW);
      // Persistent congestion: slow start again from two packets, up to the cut.
      if (persistent) this.window = MIN_WINDOW;
    }
    if (this.undo) {
      if (this.suspects.length + lost.length > MAX_SUSPECTS) {
        // So many at once were lost, not late: the cut stands, and acks stop testing them.
        this.undo = null;
        this.suspects.length = 0;
      } else {
        for (const pn of lost) this.suspects.push(pn);
      }
    }
    this.advanceOldest();
  }

  advanceOldest() {
    while (this.oldestPn < this.nextPn && !this.inFlight.has(this.oldestPn)) this.oldestPn++;
  }

  /** The offset of the oldest chunk not acked, or -1. */
  oldestChunk() {
    const o = this.sentOffsets;
    while (this.sentHead < o.length && !this.chunks.has(o[this.sentHead])) this.sentHead++;
    if (this.sentHead > 1024 && this.sentHead * 2 > o.length) { o.splice(0, this.sentHead); this.sentHead = 0; }
    return this.sentHead < o.length ? o[this.sentHead] : -1;
  }

  /** Send what the window allows, and `probes` packets past it. */
  flush(probes = 0) {
    if (!this.out || this.gone) return;
    for (;;) {
      if (probes === 0 && this.bytesInFlight + this.packetBytes > this.window) {
        this.windowLimited = this.lost.size > 0 || (this.unsent.bytes > 0 && this.nextOffset < this.peerCredit);
        break;
      }
      const offset = this.nextChunk(probes > 0);
      if (offset < 0) { this.windowLimited = false; break; }
      if (probes > 0) probes--;
      this.sendChunk(offset, this.chunks.get(offset));
    }
    this.arm();
  }

  /** The offset of what to send next, a lost chunk first, then new bytes the peer has room
   *  for, and for a probe with neither, the oldest chunk not acked; -1 for nothing. */
  nextChunk(probe) {
    if (this.lost.size > 0) {
      for (const offset of this.lost) {
        this.lost.delete(offset);
        const chunk = this.chunks.get(offset);
        if (chunk) { this.fit(offset, chunk); return offset; }
      }
    }
    const n = Math.min(this.unsent.bytes, this.packetBytes - DATA_HEADER, this.peerCredit - this.nextOffset);
    if (n > 0) {
      const offset = this.nextOffset;
      this.chunks.set(offset, this.unsent.take(n));
      this.nextOffset += n;
      this.sentOffsets.push(offset);
      return offset;
    }
    const oldest = probe ? this.oldestChunk() : -1;
    if (oldest >= 0) this.fit(oldest, this.chunks.get(oldest));
    return oldest;
  }

  /** Cut the chunk at `offset` to what a packet now carries. One cut when packets were
   *  larger is split, and the rest becomes a chunk of its own, sent again behind what is
   *  already lost. The receiver may then have the bytes twice, whole and in pieces, which it
   *  takes either way. */
  fit(offset, chunk) {
    const max = this.packetBytes - DATA_HEADER;
    if (chunk.length <= max) return;
    const rest = offset + max;
    this.chunks.set(offset, chunk.subarray(0, max));
    this.chunks.set(rest, chunk.subarray(max));
    this.sentOffsets.splice(this.sentOffsets.indexOf(offset, this.sentHead) + 1, 0, rest);
    this.lost.add(rest);
  }

  sendChunk(offset, chunk) {
    const pn = this.nextPn++;
    const p = packet(S_DATA, 18 + chunk.length);
    writeU48BE(p, B, pn);
    writeU48BE(p, B + 6, offset);
    // What the peer's acks must still name: a packet in flight, and a probe not answered. A
    // suspect arriving late is out of order, so it is acked at once, below the floor or not.
    writeU48BE(p, B + 12, Math.min(this.oldestPn, this.probes[0] ?? Infinity));
    p.set(chunk, B + 18);
    const t = now();
    this.inFlight.set(pn, { offset, size: p.length, time: t });
    this.bytesInFlight += p.length;
    this.lastSentData = t;
    this.emit(p, t);
  }

  pto() {
    return this.srtt + Math.max(4 * this.rttvar, 1) + ACK_DELAY_MS;
  }

  /** When recovery is next due: the loss timer if one is set, else the probe timeout,
   *  doubled for each in a row. */
  recoveryDue() {
    return this.lossTime < Infinity ? this.lossTime : this.lastSentData + this.pto() * 2 ** this.ptoCount;
  }

  /** Be woken by `recoveryDue`. A wake due no later is kept, and looks again when it comes
   *  early, so the wake moves when recovery comes sooner, not with every send. */
  arm() {
    if (this.gone || this.inFlight.size === 0) return;
    const at = this.recoveryDue();
    if (at >= this.recoveryAt) return;
    this.recoveryAt = at;
    wakeBy(at);
  }

  onRecovery(t) {
    this.recoveryAt = Infinity;
    if (this.inFlight.size === 0) return;
    if (t < this.recoveryDue()) { this.arm(); return; }
    if (this.lossTime < Infinity) {
      this.detectLoss(t);
      this.flush();
      return;
    }
    if (this.peerGone(t)) { this.end(); return; }
    // A second timeout in a row: the path may have stopped carrying the larger packets.
    if (this.ptoCount >= 1 && this.packetBytes > BASE_PACKET) {
      this.packetBytes = BASE_PACKET;
      this.reprobe = true;
    }
    this.ptoCount++;
    this.flush(2);
  }

  // ── the packet size ──

  /** Probe the path for `MAX_PACKET`, up to `MAX_PROBES` times. */
  startProbe() {
    this.probes = [];
    this.sendProbe();
  }

  sendProbe() {
    this.probeAt = Infinity;
    if (this.gone || !this.out) return;
    if (this.probes.length >= MAX_PROBES) { this.probes = []; return; }
    const pn = this.nextPn++;
    const p = packet(S_PROBE, MAX_PACKET - B);
    writeU48BE(p, B, pn);
    this.probes.push(pn);
    this.emit(p);
    this.probeAt = dueIn(this.pto());
  }

  /** Whether an ack names a probe: then the path carries `MAX_PACKET`. */
  probeAcked(p, count) {
    if (!this.probes.some((pn) => names(p, count, pn))) return;
    this.probeAt = Infinity;
    this.probes = [];
    this.packetBytes = MAX_PACKET;
  }

  emit(p, t = now()) {
    this.lastSent = t;
    this.out(p);
  }

  // ── life ──

  /** Data in flight through `MAX_PTOS` probe timeouts, from a peer silent for `DEAD_MS`. */
  peerGone(t) {
    return this.inFlight.size > 0 && this.ptoCount >= MAX_PTOS && t - this.lastHeard > DEAD_MS;
  }

  /** Every `KEEPALIVE_MS`. */
  tick(t) {
    if (t - this.lastHeard > SILENT_MS) { this.fail(); return; }
    if (this.peerGone(t)) { this.end(); return; }
    if (t - this.lastSent >= KEEPALIVE_MS) this.sendAck();
    this.liveAt = dueIn(KEEPALIVE_MS);
  }

  /** Nothing acks a CLOSE, and one lost would leave the peer waiting out `SILENT_MS`, so it
   *  goes three times. */
  sendClose() {
    if (!this.out) return;
    for (let i = 0; i < 3; i++) {
      this.emit(packet(S_CLOSE, 0));
    }
  }

  /** What the stream holds goes with it. */
  fail() {
    if (this.gone) return;
    this.gone = true;
    this.onGone();
  }
}
