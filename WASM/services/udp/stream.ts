// A reliable, ordered byte stream over a datagram path (§12.7), the data link of a UDP
// path. The transport above it authenticates and encrypts, frames its records, bounds what
// it sends by `buffered()` and times idle links out, so all this does is get bytes across,
// in order, at a rate the path takes.
//
// The recovery design is QUIC's (RFC 9002), cut down:
// - Every packet gets a new number, a resent chunk's too, so an ack names one send and a
//   round-trip sample is never ambiguous.
// - The stream is cut into chunks at their first send, and a lost chunk is resent whole at
//   its offset, so the receiver reassembles by offset alone.
// - An ack carries ranges of packet numbers. A packet is lost once one sent three later is
//   acked, or once it is 9/8 of a round trip older than one that was. A probe timeout finds
//   a lost tail, which has no later packet to give it away.
// - NewReno congestion control, run as `FLOWS` flows at once: slow start, the window cut
//   by 1/(2 FLOWS) once per loss episode, then grown by `FLOWS` packets a round trip, and
//   only while it is what holds the sender back.
// - Every ack says how far the receiver will take the stream, so a reader the driver holds
//   back (`setReadable`) stops the sender.
//
// A packet is the path's header, `[type u8][receiver's token 8]`, then:
//   DATA   [pn 6][offset 6][bytes]
//   ACK    [credit 6][delay u16 ms][count u8]([largest 6][smallest 6])*   newest range first
//   CLOSE  nothing
// The stream writes the type and leaves the token to the path (net-udp.ts).
import { type RawLink } from "../socket-seam.js";

const TYPE_DATA = 0x64, TYPE_ACK = 0x61, TYPE_CLOSE = 0x78;
/** The path's header in front of every packet. */
export const PATH_HEADER = 9;
/** The most a packet is: QUIC's floor, which every path is taken to carry, so there is no
 *  path MTU to discover. */
const PACKET_BYTES = 1200;
const CHUNK = PACKET_BYTES - PATH_HEADER - 12;
const INITIAL_WINDOW = 10 * PACKET_BYTES;
const MIN_WINDOW = 2 * PACKET_BYTES;
/** How many NewReno flows the window behaves as (MulTCP): it grows by this many packets a
 *  round trip and a loss cuts it by 1/(2 FLOWS), as that many TCP connections would
 *  together, which is what a TCP peer opens to fill a lossy path. */
const FLOWS = 8;
/** How far past what its reader has taken a receiver takes the stream. */
const CREDIT = 1 << 20;
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

/** The first `n` bytes of `parts`, removed from it. */
function take(parts: Uint8Array[], n: number): Uint8Array {
  if (parts[0].length === n) return parts.shift()!;
  const out = new Uint8Array(n);
  for (let at = 0; at < n;) {
    const part = parts[0], k = Math.min(part.length, n - at);
    out.set(part.subarray(0, k), at);
    at += k;
    if (k === part.length) parts.shift(); else parts[0] = part.subarray(k);
  }
  return out;
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
  private readonly queue: Uint8Array[] = [];
  /** Where the next chunk starts in `queue[0]`. */
  private queueAt = 0;
  private queued = 0;
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
  /** The packets the current loss episode declared lost, and the window it cut. Should every
   *  one of them be acked after all, they were late, not lost, and the cut is undone. */
  private readonly suspects = new Set<number>();
  private undo: { window: number; threshold: number } | null = null;
  private windowLimited = false;
  private peerCredit = CREDIT;
  private srtt = INITIAL_RTT_MS;
  private rttvar = INITIAL_RTT_MS / 2;
  private minRtt = Infinity;
  private latestRtt = 0;
  private sampled = false;
  private ptoCount = 0;
  private lastSentData = 0;
  private lossTime = Infinity;
  private recoveryTimer: Timer | undefined;
  private armedAt = Infinity;

  // ── receiving ──
  /** The offset the reader has been handed up to, and what follows it in order. */
  private taken = 0;
  private readonly held: Uint8Array[] = [];
  private heldBytes = 0;
  /** Chunks past a gap, by offset. */
  private readonly ahead = new Map<number, Uint8Array>();
  private readable = true;
  private turnDue = false;
  /** Packet numbers received, as `[largest, smallest]`, newest first. */
  private ranges: [number, number][] = [];
  private largestAt = 0;
  private unacked = 0;
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
  }

  /** One packet from the peer, header included. */
  receive(p: Uint8Array): void {
    if (this.gone) return;
    this.lastHeard = performance.now();
    const body = p.length - B;
    if (p[0] === TYPE_DATA && body > 12) this.onChunk(get48(p, B), get48(p, B + 6), p.subarray(B + 12));
    else if (p[0] === TYPE_ACK && body >= 9 && body >= 9 + 12 * p[B + 8]) this.onAck(p);
    else if (p[0] === TYPE_CLOSE) this.fail();
  }

  // ── RawLink ──

  send(bytes: Uint8Array): void {
    if (this.gone || this.closing) throw new Error("udp: link is closed");
    if (bytes.length === 0) return;
    this.queue.push(bytes.slice());
    this.queued += bytes.length;
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
  /** The negotiation link closed: this closes too, and the peer and the driver hear it. */
  end(): void {
    if (this.gone) return;
    this.sendClose();
    this.fail();
  }

  // ── receiving ──

  private onChunk(pn: number, offset: number, bytes: Uint8Array): void {
    // Past the credit this end gave: not taken and not acked, so it comes again.
    if (offset + bytes.length > this.taken + CREDIT) return;
    const largest = this.ranges.length > 0 ? this.ranges[0][0] : -1;
    this.record(pn);
    if (pn > largest) this.largestAt = performance.now();
    let end = this.taken + this.heldBytes;
    if (offset === end) {
      // Held as it came: a platform hands over datagrams it does not reuse (net-udp.ts).
      this.hold(bytes);
      for (let next; (next = this.ahead.get(end = this.taken + this.heldBytes));) {
        this.ahead.delete(end);
        this.hold(next);
      }
    } else if (offset > end && !this.ahead.has(offset)) {
      // A copy, so a chunk waiting on a gap keeps no whole batch of datagrams alive.
      this.ahead.set(offset, bytes.slice());
    }
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

  private hold(chunk: Uint8Array): void {
    this.held.push(chunk);
    this.heldBytes += chunk.length;
  }

  /** Hand the reader what is in order, while it reads, and tell the sender once that has
   *  freed half the credit. */
  private deliver(): void {
    while (this.readable && this.onMsg && this.heldBytes > 0 && !this.gone) {
      const n = Math.min(this.heldBytes, MAX_READ);
      const bytes = take(this.held, n);
      this.heldBytes -= n;
      this.taken += n;
      this.onMsg(bytes);
    }
    if (this.taken + CREDIT - this.advertised >= CREDIT / 2) this.sendAck();
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
    this.advertised = this.taken + CREDIT;
    put48(p, B, this.advertised);
    const delay = Math.min(0xffff, Math.round(performance.now() - this.largestAt));
    p[B + 6] = delay >>> 8; p[B + 7] = delay; p[B + 8] = r.length;
    r.forEach(([hi, lo], i) => { put48(p, B + 9 + 12 * i, hi); put48(p, B + 15 + 12 * i, lo); });
    this.emit(p);
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
            this.window += this.window < this.threshold ? s.size : FLOWS * PACKET_BYTES * s.size / this.window;
        }
      }
      if (this.suspects.size > 0) {
        for (let i = 0; i < count; i++) {
          const hi = get48(p, B + 9 + 12 * i), lo = get48(p, B + 15 + 12 * i);
          for (const pn of this.suspects) if (pn >= lo && pn <= hi) this.suspects.delete(pn);
        }
      }
      if (this.undo && this.suspects.size === 0) {
        this.window = Math.max(this.window, this.undo.window);
        this.threshold = this.undo.threshold;
        this.undo = null;
      }
      this.largestAcked = Math.max(this.largestAcked, largest);
      this.advanceOldest();
      const now = performance.now();
      if (newest) this.sample(now - newest.time, (p[B + 6] << 8) | p[B + 7]);
      this.detectLoss(now);
    }
    if (this.closing && this.buffered() === 0) { this.finish(); return; }
    this.flush();
  }

  private sample(latest: number, delay: number): void {
    this.latestRtt = latest;
    if (!this.sampled) {
      this.sampled = true;
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
    let lostSentAt = -Infinity;
    const lost: number[] = [];
    this.advanceOldest();
    for (let pn = this.oldestPn; pn < this.largestAcked; pn++) {
      const s = this.inFlight.get(pn);
      if (!s) continue;
      if (this.largestAcked - pn >= 3 || s.time <= now - delay) {
        this.inFlight.delete(pn);
        this.bytesInFlight -= s.size;
        if (this.chunks.has(s.offset)) this.lost.add(s.offset);
        lostSentAt = Math.max(lostSentAt, s.time);
        lost.push(pn);
      } else {
        this.lossTime = Math.min(this.lossTime, s.time + delay);
      }
    }
    // One halving per episode: losses among packets sent before it began are the same one.
    if (lostSentAt > this.recoveryStart) {
      this.recoveryStart = now;
      this.undo = { window: this.window, threshold: this.threshold };
      this.suspects.clear();
      this.window = this.threshold = Math.max(this.window * (1 - 1 / (2 * FLOWS)), MIN_WINDOW);
    }
    if (this.undo) for (const pn of lost) this.suspects.add(pn);
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
      if (probes === 0 && this.bytesInFlight + PACKET_BYTES > this.window) {
        this.windowLimited = this.lost.size > 0 || (this.queued > 0 && this.nextOffset < this.peerCredit);
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
        if (chunk) return [offset, chunk];
      }
    }
    const n = Math.min(this.queued, CHUNK, this.peerCredit - this.nextOffset);
    if (n > 0) {
      const chunk = this.takeQueued(n);
      const offset = this.nextOffset;
      this.queued -= n;
      this.nextOffset += n;
      this.chunks.set(offset, chunk);
      this.sentOffsets.push(offset);
      return [offset, chunk];
    }
    const oldest = probe ? this.oldestChunk() : -1;
    return oldest < 0 ? null : [oldest, this.chunks.get(oldest)!];
  }

  /** The next `n` bytes written: a view of the write they sit in, or a copy across writes. */
  private takeQueued(n: number): Uint8Array {
    const head = this.queue[0];
    if (head.length - this.queueAt >= n) {
      const out = head.subarray(this.queueAt, this.queueAt += n);
      if (this.queueAt === head.length) { this.queue.shift(); this.queueAt = 0; }
      return out;
    }
    const out = new Uint8Array(n);
    for (let at = 0; at < n;) {
      const part = this.queue[0], k = Math.min(part.length - this.queueAt, n - at);
      out.set(part.subarray(this.queueAt, this.queueAt + k), at);
      at += k;
      this.queueAt += k;
      if (this.queueAt === part.length) { this.queue.shift(); this.queueAt = 0; }
    }
    return out;
  }

  private sendChunk(offset: number, chunk: Uint8Array): void {
    const pn = this.nextPn++;
    const p = packet(TYPE_DATA, 12 + chunk.length);
    put48(p, B, pn);
    put48(p, B + 6, offset);
    p.set(chunk, B + 12);
    const now = performance.now();
    this.inFlight.set(pn, { offset, size: p.length, time: now });
    this.bytesInFlight += p.length;
    this.lastSentData = now;
    this.emit(p);
  }

  /** When recovery is next due: the loss timer if one is set, else the probe timeout,
   *  doubled for each in a row. */
  private recoveryDue(): number {
    return this.lossTime < Infinity ? this.lossTime
      : this.lastSentData + (this.srtt + Math.max(4 * this.rttvar, 1) + ACK_DELAY_MS) * 2 ** this.ptoCount;
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
    this.ptoCount++;
    this.flush(2);
  };

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

  private stop(): void {
    this.gone = true;
    clearTimeout(this.recoveryTimer);
    clearTimeout(this.lingerTimer);
    clearTimeout(this.liveTimer);
    this.queue.length = 0;
    this.sentOffsets.length = 0;
    this.chunks.clear();
    this.inFlight.clear();
    this.held.length = 0;
    this.ahead.clear();
    this.onGone();
  }
}
