// A reliable, ordered byte stream over a datagram path (§12.7), the data link of a UDP
// path. The transport above it authenticates and encrypts, frames its records, bounds what
// it sends by `buffered()` and times idle links out, so all this does is get bytes across,
// in order, at a rate the path takes.
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
// - Every ack says how far the receiver will take the stream, so a reader the driver holds
//   back (`setReadable`) stops the sender, and a credit read in under two round trips
//   doubles it, up to `MAX_CREDIT`. Nothing acks an ack, so the one that lets a sender
//   that has used all it was given go on is sent three times.
// - Data in flight that draws no ack through `MAX_PTOS` probe timeouts, from a peer heard
//   from not at all for `DEAD_MS`, ends the path: the peer is gone.
// - A path starts at QUIC's 1200-byte packets and probes for `MAX_PACKET` (RFC 8899): a
//   probe the peer acks raises the size, and a second probe timeout in a row drops it back
//   and probes again. Every cost of the stream is per packet, so larger ones are that much
//   cheaper. A chunk cut larger than the path now carries is split when it is resent.
//
// A packet is the path's header, `[type u8][receiver's token 8]`, then:
//   DATA   [pn 6][offset 6][floor 6][bytes]   no packet below floor is waited on
//   ACK    [credit 6][delay u16 ms][count u8]([largest 6][smallest 6])*   newest range first
//   PROBE  [pn 6], padded to `MAX_PACKET`
//   CLOSE  nothing
// The stream writes the type and leaves the token to the path (net-udp.ts).
import { type RawLink } from "../socket-seam.js";

const TYPE_DATA = 0x64, TYPE_ACK = 0x61, TYPE_PROBE = 0x6d, TYPE_CLOSE = 0x78;
/** The path's header in front of every packet. */
export const PATH_HEADER = 9;
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
 *  for the reader are bounded whatever their size: a datagram costs this much host heap or so. */
const MIN_CHUNK = 256;
/** The receive and send buffers a platform asks for on a path's socket, one stream's. A
 *  sender may put a whole credit on the wire in a burst, and a kernel charges a datagram
 *  well past its payload, so a smaller buffer drops the burst's tail and every drop halves
 *  the sender's window. Windows' default is far below one credit. */
export const SOCKET_BUFFER_BYTES = 4 * CREDIT;
/** The most one read hands the driver, well under its `MAX_LINK_READ_BYTES`. */
const MAX_READ = 256 * 1024;
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

/** After the I/O the platform is in the middle of: Node's `setImmediate`, which runs once
 *  the socket's pending datagrams are read, and elsewhere a timer, which the native loop
 *  runs after the turn's socket deliveries. */
const nextTurn: (f: () => void) => void = (globalThis as { setImmediate?: (f: () => void) => void }).setImmediate
  ?? ((f) => setTimeout(f, 0));

/** A 48-bit big-endian field, written and read on the packet's own bytes, with no view
 *  allocated per packet. */
function put48(p: Uint8Array, at: number, n: number): void {
  const hi = Math.floor(n / 2 ** 32), lo = n >>> 0;
  p[at] = hi >>> 8; p[at + 1] = hi; p[at + 2] = lo >>> 24; p[at + 3] = lo >>> 16; p[at + 4] = lo >>> 8; p[at + 5] = lo;
}
const get48 = (p: Uint8Array, at: number) =>
  ((p[at] << 8) | p[at + 1]) * 2 ** 32 + p[at + 2] * 2 ** 24 + ((p[at + 3] << 16) | (p[at + 4] << 8) | p[at + 5]);
/** Where a packet's body starts. */
const B = PATH_HEADER;

/** Whether an ACK's `count` ranges name packet `pn`. */
function names(p: Uint8Array, count: number, pn: number): boolean {
  for (let i = 0; i < count; i++) if (pn <= get48(p, B + 9 + 12 * i) && pn >= get48(p, B + 15 + 12 * i)) return true;
  return false;
}

/** Bytes in pieces, taken from the front: what was written and is not yet sent, and what
 *  arrived in order and is not yet read. */
class Pieces {
  private readonly list: Uint8Array[] = [];
  /** Where in `list[0]` the next byte is. */
  private at = 0;
  bytes = 0;
  /** The datagrams held, each a slice the platform will not reuse. */
  get slices(): number { return this.list.length; }

  push(piece: Uint8Array): void {
    this.list.push(piece);
    this.bytes += piece.length;
  }

  /** The next `n` bytes, of the `bytes` there are: a view of the piece they sit in, or a
   *  copy across pieces. */
  take(n: number): Uint8Array {
    this.bytes -= n;
    if (this.at === 0 && this.list[0].length === n) return this.list.shift()!;
    let out: Uint8Array | undefined;
    for (let got = 0; got < n;) {
      const piece = this.list[0], k = Math.min(piece.length - this.at, n - got);
      if (k === n) out = piece.subarray(this.at, this.at + k);
      else (out ??= new Uint8Array(n)).set(piece.subarray(this.at, this.at + k), got);
      got += k;
      this.at += k;
      if (this.at === piece.length) { this.list.shift(); this.at = 0; }
    }
    return out!;
  }
}

/** A packet with `body` bytes behind the header, its type written. */
function packet(type: number, body: number): Uint8Array {
  const p = new Uint8Array(B + body);
  p[0] = type;
  return p;
}

/** A packet sent and not yet acked or lost. Every one carries a chunk. */
interface Sent { offset: number; size: number; time: number }

type Timer = ReturnType<typeof setTimeout>;

export class UdpStream implements RawLink {
  readonly stream = true;
  private onMsg: ((bytes: Uint8Array) => void) | null = null;
  private onCls: (() => void) | null = null;
  /** The path, once it is chosen; until then nothing is sent. */
  private out: ((packet: Uint8Array) => void) | null = null;

  // ── sending ──
  private readonly unsent = new Pieces();
  /** The stream offset past the last byte written, and past the last ever sent. */
  private written = 0;
  private nextOffset = 0;
  /** Chunks sent and not acked, by offset. */
  private readonly chunks = new Map<number, Uint8Array>();
  /** Chunk offsets in the order first sent, all acked before `sentHead`: the oldest chunk
   *  not acked, found without iterating the map, which QuickJS charges for per entry. */
  private readonly sentOffsets: number[] = [];
  private sentHead = 0;
  /** Offsets of chunks to send again. */
  private readonly lost = new Set<number>();
  /** Packets in flight, by number, none of them below `oldestPn`. They are walked by
   *  number, not iterated, for the same reason. */
  private readonly inFlight = new Map<number, Sent>();
  private oldestPn = 0;
  private nextPn = 0;
  private largestAcked = -1;
  private bytesInFlight = 0;
  private window = INITIAL_WINDOW;
  private threshold = Infinity;
  private recoveryStart = -Infinity;
  /** The packets the current loss episode declared lost, up to `MAX_SUSPECTS`, and the window
   *  it cut. Should every one of them be acked after all, they were late, not lost, and the
   *  cut is undone. */
  private readonly suspects: number[] = [];
  private undo: { window: number; threshold: number } | null = null;
  private windowLimited = false;
  private peerCredit = CREDIT;
  private srtt = INITIAL_RTT_MS;
  private rttvar = INITIAL_RTT_MS / 2;
  /** Infinity until the first round-trip sample. */
  private minRtt = Infinity;
  private latestRtt = 0;
  private ptoCount = 0;
  private lastSentData = 0;
  private lossTime = Infinity;
  private recoveryTimer: Timer | undefined;
  private armedAt = Infinity;
  /** The size a packet is on this path, and the probes for `MAX_PACKET` not yet answered. */
  private packetBytes = BASE_PACKET;
  private probes: number[] = [];
  private probeTimer: Timer | undefined;
  /** Dropped back to `BASE_PACKET`: probe again once the peer acks. */
  private reprobe = false;

  // ── receiving ──
  /** The offset the reader has been handed up to, and what follows it in order. */
  private taken = 0;
  private readonly held = new Pieces();
  /** Chunks past a gap, by offset, and the packet bytes they came in. */
  private readonly ahead = new Map<number, Uint8Array>();
  private aheadBytes = 0;
  /** The offset past the furthest byte received. */
  private furthest = 0;
  private readable = true;
  private turnDue = false;
  /** Packet numbers received, as `[largest, smallest]`, newest first. */
  private ranges: [number, number][] = [];
  private largestAt = 0;
  private unacked = 0;
  /** How far past `taken` this end takes the stream, and when its reader began this credit. */
  private credit = CREDIT;
  private creditAt = -Infinity;
  private creditEnd = 0;
  private advertised = CREDIT;

  // ── life ──
  private lastSent = 0;
  private lastHeard = 0;
  private liveTimer: Timer | undefined;
  private lingerTimer: Timer | undefined;
  private closing = false;
  private gone = false;

  /** `onGone` runs once when the stream stops, however it does. */
  constructor(private readonly onGone: () => void) {}

  /** The path is chosen: start sending through `out`, with `rttMs` as the first
   *  round-trip sample if the path measured one. */
  start(out: (packet: Uint8Array) => void, rttMs?: number): void {
    if (this.gone || this.out) return;
    this.out = out;
    if (rttMs !== undefined) this.sample(rttMs, 0);
    this.lastHeard = this.lastSent = performance.now();
    this.liveTimer = setTimeout(() => this.tick(), KEEPALIVE_MS);
    if (this.ranges.length > 0) this.sendAck();
    this.flush();
    this.startProbe();
  }

  /** The path moved to another address, `rttMs` away: what was learned of the old one no
   *  longer holds, so the window and the packet size start over, and a loss among what was
   *  sent before the move does not cut the new window. */
  repath(rttMs: number): void {
    if (this.gone) return;
    this.window = INITIAL_WINDOW;
    this.threshold = Infinity;
    this.recoveryStart = performance.now();
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
  receive(p: Uint8Array): void {
    if (this.gone) return;
    this.lastHeard = performance.now();
    const body = p.length - B;
    if (p[0] === TYPE_DATA && body > 18) this.onChunk(get48(p, B), get48(p, B + 6), get48(p, B + 12), p.subarray(B + 18));
    else if (p[0] === TYPE_ACK && body >= 9 && body >= 9 + 12 * p[B + 8]) this.onAck(p);
    else if (p[0] === TYPE_PROBE && body >= 6) this.received(get48(p, B));
    else if (p[0] === TYPE_CLOSE) this.fail();
  }

  // ── RawLink ──

  send(bytes: Uint8Array): void {
    if (this.gone || this.closing) throw new Error("udp: link is closed");
    if (bytes.length === 0) return;
    this.unsent.push(bytes.slice());
    this.written += bytes.length;
    this.flush();
  }
  onData(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; this.deliver(); }
  onClose(cb: () => void): void { this.onCls = cb; }
  setReadable(enabled: boolean): void {
    this.readable = enabled;
    if (enabled) this.deliver();
  }
  /** Written and not yet acked, which drains in send order. */
  buffered(): number {
    const oldest = this.oldestChunk();
    return this.written - (oldest < 0 ? this.nextOffset : oldest);
  }
  close(graceful = false): void {
    if (this.gone || this.closing) return;
    if (graceful && this.out && this.buffered() > 0) {
      this.closing = true;
      this.lingerTimer = setTimeout(() => this.finish(), LINGER_MS);
      return;
    }
    this.finish();
  }
  /** The negotiation link closed, or the peer stopped answering: tell it, in case it can
   *  still hear, then stop and tell the driver. */
  end(): void {
    if (this.gone) return;
    this.sendClose();
    this.fail();
  }

  // ── receiving ──

  private onChunk(pn: number, offset: number, floor: number, bytes: Uint8Array): void {
    // Past the credit this end gave: not taken and not acked, so it comes again.
    if (offset + bytes.length > this.taken + this.credit) return;
    this.received(pn);
    // The sender waits on nothing below `floor`, which is never past `pn`.
    const r = this.ranges;
    while (r.length > 1 && r[r.length - 1][0] < floor) r.pop();
    this.furthest = Math.max(this.furthest, offset + bytes.length);
    let end = this.taken + this.held.bytes;
    if (offset === end) {
      // Held as it came: a platform hands over datagrams it does not reuse (net-udp.ts).
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
    // chunks is a credit of slices, each costing far more than its byte in host heap.
    if (this.aheadBytes > 2 * this.credit || this.held.slices + this.ahead.size > 2 * this.credit / MIN_CHUNK) this.fail();
  }

  /** Note `pn` as received, and see it acked. */
  private received(pn: number): void {
    const largest = this.ranges.length > 0 ? this.ranges[0][0] : -1;
    this.record(pn);
    if (pn > largest) this.largestAt = performance.now();
    // Out of order, a gap or a repeat is acked at once, so the sender learns of it.
    if (pn !== largest + 1) this.sendAck();
    else this.unacked++;
    // Everything else once a turn, not once a packet: every read is a call into the
    // transport's realm, and every ack a datagram, and what arrives in one turn needs one
    // of each.
    if (!this.turnDue) {
      this.turnDue = true;
      nextTurn(() => {
        this.turnDue = false;
        this.deliver();
        if (this.unacked > 0) this.sendAck();
      });
    }
  }

  /** Hand the reader what is in order, while it reads, and tell the sender once that has
   *  freed half the credit. */
  private deliver(): void {
    while (this.readable && this.onMsg && this.held.bytes > 0 && !this.gone) {
      const bytes = this.held.take(Math.min(this.held.bytes, MAX_READ));
      this.taken += bytes.length;
      this.onMsg(bytes);
    }
    // A credit read in under two round trips held the sender back (quiche's autotune).
    if (this.taken >= this.creditEnd) {
      const now = performance.now();
      if (now - this.creditAt < 2 * this.srtt) this.credit = Math.min(2 * this.credit, MAX_CREDIT);
      this.creditAt = now;
      this.creditEnd = this.taken + this.credit;
    }
    if (this.taken + this.credit - this.advertised >= this.credit / 2) this.sendAck();
  }

  /** Note a packet number as received, merging it into the ranges. */
  private record(pn: number): void {
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

  private sendAck(): void {
    if (!this.out || this.gone) return;
    this.unacked = 0;
    const r = this.ranges;
    const p = packet(TYPE_ACK, 9 + 12 * r.length);
    const credit = this.taken + this.credit;
    // More credit for a sender that has used all it had, which may have nothing in flight to
    // draw another ack: one lost would leave it waiting for the keepalive, so it goes three
    // times, as a close does.
    const copies = credit > this.advertised && this.furthest >= this.advertised ? 3 : 1;
    this.advertised = credit;
    put48(p, B, credit);
    const delay = Math.min(0xffff, Math.round(performance.now() - this.largestAt));
    p[B + 6] = delay >>> 8; p[B + 7] = delay; p[B + 8] = r.length;
    r.forEach(([hi, lo], i) => { put48(p, B + 9 + 12 * i, hi); put48(p, B + 15 + 12 * i, lo); });
    for (let i = 0; i < copies; i++) this.emit(p);
  }

  // ── sending ──

  private onAck(p: Uint8Array): void {
    this.peerCredit = Math.max(this.peerCredit, get48(p, B));
    const count = p[B + 8];
    if (count > 0) {
      // A range is clamped to what was sent, so a peer naming numbers never sent costs nothing.
      const sent = this.nextPn - 1;
      const largest = Math.min(get48(p, B + 9), sent);
      let newest: Sent | undefined;
      for (let i = 0; i < count; i++) {
        const hi = Math.min(get48(p, B + 9 + 12 * i), sent);
        for (let pn = Math.max(get48(p, B + 15 + 12 * i), this.oldestPn); pn <= hi; pn++) {
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
      const now = performance.now();
      if (newest) this.sample(now - newest.time, (p[B + 6] << 8) | p[B + 7]);
      this.detectLoss(now);
      // The peer acks again after a drop back: see whether the path still carries more.
      if (this.reprobe && this.ptoCount === 0) { this.reprobe = false; this.startProbe(); }
    }
    if (this.closing && this.buffered() === 0) { this.finish(); return; }
    this.flush();
  }

  private sample(latest: number, delay: number): void {
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
  private detectLoss(now: number): void {
    this.lossTime = Infinity;
    const delay = Math.max(9 / 8 * Math.max(this.latestRtt, this.srtt), 1);
    const persistence = PERSISTENT_PTOS * this.pto();
    let lostSentAt = -Infinity, runFrom = Infinity, persistent = false;
    const lost: number[] = [];
    this.advanceOldest();
    for (let pn = this.oldestPn; pn < this.largestAcked; pn++) {
      const s = this.inFlight.get(pn);
      // A run of losses goes unbroken by number: a packet acked, or not in flight, ends it.
      if (!s) { runFrom = Infinity; continue; }
      if (this.largestAcked - pn >= 3 || s.time <= now - delay) {
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
      this.recoveryStart = now;
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

  private advanceOldest(): void {
    while (this.oldestPn < this.nextPn && !this.inFlight.has(this.oldestPn)) this.oldestPn++;
  }

  /** The offset of the oldest chunk not acked, or -1. */
  private oldestChunk(): number {
    const o = this.sentOffsets;
    while (this.sentHead < o.length && !this.chunks.has(o[this.sentHead])) this.sentHead++;
    if (this.sentHead > 1024 && this.sentHead * 2 > o.length) { o.splice(0, this.sentHead); this.sentHead = 0; }
    return this.sentHead < o.length ? o[this.sentHead] : -1;
  }

  /** Send what the window allows, and `probes` packets past it. */
  private flush(probes = 0): void {
    if (!this.out || this.gone) return;
    for (;;) {
      if (probes === 0 && this.bytesInFlight + this.packetBytes > this.window) {
        this.windowLimited = this.lost.size > 0 || (this.unsent.bytes > 0 && this.nextOffset < this.peerCredit);
        break;
      }
      const next = this.nextChunk(probes > 0);
      if (!next) { this.windowLimited = false; break; }
      if (probes > 0) probes--;
      this.sendChunk(next[0], next[1]);
    }
    this.arm();
  }

  /** A lost chunk first, then new bytes the peer has room for; for a probe with neither,
   *  the oldest chunk not acked. */
  private nextChunk(probe: boolean): [number, Uint8Array] | null {
    if (this.lost.size > 0) {
      for (const offset of this.lost) {
        this.lost.delete(offset);
        const chunk = this.chunks.get(offset);
        if (chunk) return [offset, this.fit(offset, chunk)];
      }
    }
    const n = Math.min(this.unsent.bytes, this.packetBytes - DATA_HEADER, this.peerCredit - this.nextOffset);
    if (n > 0) {
      const chunk = this.unsent.take(n);
      const offset = this.nextOffset;
      this.nextOffset += n;
      this.chunks.set(offset, chunk);
      this.sentOffsets.push(offset);
      return [offset, chunk];
    }
    const oldest = probe ? this.oldestChunk() : -1;
    return oldest < 0 ? null : [oldest, this.fit(oldest, this.chunks.get(oldest)!)];
  }

  /** The chunk at `offset`, cut to what a packet now carries. One cut when packets were
   *  larger is split, and the rest becomes a chunk of its own, sent again behind what is
   *  already lost. The receiver may then have the bytes twice, whole and in pieces, which it
   *  takes either way. */
  private fit(offset: number, chunk: Uint8Array): Uint8Array {
    const max = this.packetBytes - DATA_HEADER;
    if (chunk.length <= max) return chunk;
    const head = chunk.subarray(0, max), rest = offset + max;
    this.chunks.set(offset, head);
    this.chunks.set(rest, chunk.subarray(max));
    this.sentOffsets.splice(this.sentOffsets.indexOf(offset, this.sentHead) + 1, 0, rest);
    this.lost.add(rest);
    return head;
  }

  private sendChunk(offset: number, chunk: Uint8Array): void {
    const pn = this.nextPn++;
    const p = packet(TYPE_DATA, 18 + chunk.length);
    put48(p, B, pn);
    put48(p, B + 6, offset);
    // What the peer's acks must still name: a packet in flight, and a probe not answered. A
    // suspect arriving late is out of order, so it is acked at once, below the floor or not.
    put48(p, B + 12, Math.min(this.oldestPn, this.probes[0] ?? Infinity));
    p.set(chunk, B + 18);
    const now = performance.now();
    this.inFlight.set(pn, { offset, size: p.length, time: now });
    this.bytesInFlight += p.length;
    this.lastSentData = now;
    this.emit(p);
  }

  private pto(): number {
    return this.srtt + Math.max(4 * this.rttvar, 1) + ACK_DELAY_MS;
  }

  /** When recovery is next due: the loss timer if one is set, else the probe timeout,
   *  doubled for each in a row. */
  private recoveryDue(): number {
    return this.lossTime < Infinity ? this.lossTime : this.lastSentData + this.pto() * 2 ** this.ptoCount;
  }

  /** Arm for `recoveryDue`. A timer armed for no later is kept, and re-arms when it fires
   *  early, so the timer moves when recovery comes sooner, not with every send. */
  private arm(): void {
    if (this.gone || this.inFlight.size === 0) return;
    const at = this.recoveryDue();
    if (this.recoveryTimer !== undefined && this.armedAt <= at) return;
    clearTimeout(this.recoveryTimer);
    this.armedAt = at;
    this.recoveryTimer = setTimeout(this.onRecoveryTimer, Math.max(0, at - performance.now()));
  }

  private readonly onRecoveryTimer = (): void => {
    this.recoveryTimer = undefined;
    if (this.gone || this.inFlight.size === 0) return;
    if (performance.now() < this.recoveryDue()) { this.arm(); return; }
    if (this.lossTime < Infinity) {
      this.detectLoss(performance.now());
      this.flush();
      return;
    }
    if (this.ptoCount >= MAX_PTOS && performance.now() - this.lastHeard > DEAD_MS) { this.end(); return; }
    // A second timeout in a row: the path may have stopped carrying the larger packets.
    if (this.ptoCount >= 1 && this.packetBytes > BASE_PACKET) {
      this.packetBytes = BASE_PACKET;
      this.reprobe = true;
    }
    this.ptoCount++;
    this.flush(2);
  };

  // ── the packet size ──

  /** Probe the path for `MAX_PACKET`, up to `MAX_PROBES` times. */
  private startProbe(): void {
    clearTimeout(this.probeTimer);
    this.probes = [];
    this.sendProbe();
  }

  private readonly sendProbe = (): void => {
    this.probeTimer = undefined;
    if (this.gone || !this.out) return;
    if (this.probes.length >= MAX_PROBES) { this.probes = []; return; }
    const pn = this.nextPn++;
    const p = packet(TYPE_PROBE, MAX_PACKET - B);
    put48(p, B, pn);
    this.probes.push(pn);
    this.emit(p);
    this.probeTimer = setTimeout(this.sendProbe, this.pto());
  };

  /** Whether an ack names a probe: then the path carries `MAX_PACKET`. */
  private probeAcked(p: Uint8Array, count: number): void {
    if (!this.probes.some((pn) => names(p, count, pn))) return;
    clearTimeout(this.probeTimer);
    this.probeTimer = undefined;
    this.probes = [];
    this.packetBytes = MAX_PACKET;
  }

  private emit(p: Uint8Array): void {
    this.lastSent = performance.now();
    this.out!(p);
  }

  // ── life ──

  /** Every `KEEPALIVE_MS`, re-armed rather than an interval, since a platform need only
   *  have `setTimeout`. */
  private tick(): void {
    const now = performance.now();
    if (now - this.lastHeard > SILENT_MS) { this.fail(); return; }
    if (this.inFlight.size > 0 && this.ptoCount >= MAX_PTOS && now - this.lastHeard > DEAD_MS) { this.end(); return; }
    if (now - this.lastSent >= KEEPALIVE_MS) this.sendAck();
    this.liveTimer = setTimeout(() => this.tick(), KEEPALIVE_MS);
  }

  /** Tell the peer, then stop. */
  private finish(): void {
    if (this.gone) return;
    this.sendClose();
    this.stop();
  }

  /** Nothing acks a CLOSE, and one lost would leave the peer waiting out `SILENT_MS`, so it
   *  goes three times. */
  private sendClose(): void {
    if (this.out) for (let i = 0; i < 3; i++) this.emit(packet(TYPE_CLOSE, 0));
  }

  /** The peer closed or went silent: stop, and tell the driver. */
  private fail(): void {
    if (this.gone) return;
    this.stop();
    this.onCls?.();
  }

  /** What the stream holds goes with it, once the driver and the negotiation let go. */
  private stop(): void {
    this.gone = true;
    clearTimeout(this.recoveryTimer);
    clearTimeout(this.lingerTimer);
    clearTimeout(this.liveTimer);
    clearTimeout(this.probeTimer);
    this.onGone();
  }
}
