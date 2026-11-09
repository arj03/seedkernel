// The data link of a UDP path (§12.7, udp.js): a QUIC connection, which this bundle's
// `quic.wasm` runs (transport/quic/quic.c, ngtcp2). The module touches no socket and
// keeps no clock: each call hands it the realm's time, the datagrams that came for the path
// and what the link wrote, and its answer is what the link reads, the datagrams to send and
// when to call again. One call runs at a time for a path; whatever arrives meanwhile goes in
// the next.
//
// The link's handshake (ake.js) is the connection's: its messages go down through
// `handshake` and come up through `handshakeReader`, and the keys it derives go down
// through `handshakeKeys` and `keys`, which seal every packet from then on. The link's
// records then go in the clear on the connection's streams: one AEAD a packet, and an
// attacker who sees the path can forge nothing on it.

const N_QUIC = "quic";
const Q_OPEN = 1, Q_TURN = 2, Q_DROP = 3, Q_SCREEN = 4;
const QF_FIN = 1, QF_CLOSE = 2, QF_HS_KEYS = 4, QF_KEYS = 8;
const QE_FINISHED = 1, QE_CLOSED = 2, QE_MORE = 4;
/** The most one read hands the link, and the most of what it wrote one call carries. */
const MAX_READ = 256 * 1024;
const MAX_WRITE = 128 * 1024;
/** The datagrams one call carries at most, within the module's scratch: a whole
 *  `datagrams` event (net-limits.ts `MAX_LINK_READ_BYTES`). */
const MAX_IN = 2 * 1024 * 1024 + 64 * 1024;
const HEAD_IN = 18, HEAD_OUT = 22;
/** The link's handshake messages one call carries at most: the module takes four. */
const MAX_HS = 4;
/** Written and not yet taken by the connection, past which a write fails the link, as the
 *  host fails a socket whose backlog passes its cap (net-limits.ts
 *  `MAX_OUTBOUND_QUEUE_BYTES`). */
const MAX_BUFFERED = 16 * 1024 * 1024;
/** How long a graceful close waits for what was written to be acked. */
const LINGER_MS = 10_000;

const SENT = Promise.resolve();
let nextQuicId = 1;

/** One UDP path's connection, and the channel its link runs on (ake.js `Link`). */
class QuicPath {
  /** `onGone` runs once when the connection stops, however it does. */
  constructor(onGone) {
    this.id = nextQuicId++;
    this.onGone = onGone;
    this.opened = null;
    this.gone = false;
    /** The path socket's batches for the next call, as the `datagrams` event carries them. */
    this.inbound = [];
    this.turnDue = false;
    this.unsent = new Pieces();
    /** The link's handshake messages for the next call, and the keys it handed down. */
    this.hsOut = [];
    this.hsKeys = null;
    this.keySet = null;
    this.authed = false;
    this.flags = 0;
    this.closing = false;
    this.lingerAt = Infinity;
    this.read = null;
    this.onHandshake = null;
    this.reading = false;
    // Whether the module holds what the link has not read yet (`QE_MORE`), which it asks for
    // once it has decoded what it has; otherwise the next comes with the datagrams that
    // bring it.
    this.readMore = false;
    this.readDone = () => {
      this.reading = false;
      if (this.readMore) this.kick();
    };
    this.inFlight = 0;
    this.answered = (r) => this.onAnswer(r);
    this.refused = () => this.onAnswer(null);
    this.dueAt = Infinity;
    this.busy = false;
    this.again = false;
    this.finSent = false;
    /** A listener's: told each time the connection IDs the path answers to change, as the
     *  first four bytes of each (udp.js `QuicListener`). */
    this.onIds = null;
  }

  /** Open the connection on `socket` with the peer at `remote` (`[n u8][ip n][port u16]`, as
   *  a batch spells it): dialed there if `dial`, else taken only from there, and with a
   *  listener's `key` only from an Initial that echoes that listener's Retry. */
  open(seed, socket, remote, dial, key = EMPTY) {
    const head = new Uint8Array(1 + 4 + 1 + 8 + 32 + 4);
    head[0] = Q_OPEN;
    writeU32BE(head, 1, this.id);
    head[5] = dial ? 1 : 0;
    new DataView(head.buffer).setFloat64(6, now());
    head.set(seed, 14);
    writeU32BE(head, 46, socket);
    this.busy = true;
    this.opened = this.call(concatBytes([head, remote, key])).then((r) => {
      this.busy = false;
      if (!r || r[0] !== 1) { this.fail(); return; }
      this.kick();
    });
  }

  call(input) {
    try {
      return host.call(N_QUIC, input).catch(() => null);
    } catch {
      return Promise.resolve(null);
    }
  }

  /** What the path's socket read, as the `datagrams` event has it (udp.js): the module
   *  takes the QUIC datagrams and leaves the rest. */
  feed(batch) {
    if (this.gone) return;
    this.inbound.push(batch);
    // One call for all of a datagrams event's (udp.js `onDatagrams`).
    if (!this.turnDue) {
      this.turnDue = true;
      udp.turns.push(this);
    }
  }

  turn() {
    this.turnDue = false;
    this.kick();
  }

  // ── the channel ──

  send(bytes) {
    if (this.gone || this.closing) throw new Error("udp: link is closed");
    if (this.unsent.bytes + bytes.length > MAX_BUFFERED) throw new Error("udp: outbound limit exceeded");
    if (bytes.length === 0) return SENT;
    this.unsent.push(bytes);
    this.kick();
    return SENT;
  }

  /** The link that reads the streams: `read(bytes)` answers a promise of having decoded
   *  them, and nothing more is handed over until it settles. */
  reader(read) {
    this.read = read;
    this.kick();
  }

  /** The link's handshake, which owns the connection's: `read(message)` takes each of the
   *  peer's messages, and `handshake` sends one of its own. */
  handshakeReader(read) { this.onHandshake = read; }

  handshake(msg) {
    if (this.gone) return SENT;
    this.hsOut.push(msg);
    this.kick();
    return SENT;
  }

  /** The link's handshake secrets, then its session keys, each this end's then the
   *  peer's: the module seals behind them from here on. The handshake secrets wait for the
   *  message the link sends next, so both go in one call. */
  handshakeKeys(local, remote) {
    if (this.gone) return;
    this.hsKeys = concatBytes([local, remote]);
    this.flags |= QF_HS_KEYS;
  }

  keys(local, remote) {
    if (this.gone) return;
    this.keySet = concatBytes([local, remote]);
    this.flags |= QF_KEYS;
    this.authed = true;
    this.kick();
  }

  /** A graceful close of an authenticated link waits for what was written to be acked, up
   *  to `LINGER_MS`. */
  close(graceful) {
    if (this.gone || this.closing) return;
    if (graceful && this.authed) {
      this.closing = true;
      this.lingerAt = dueIn(LINGER_MS);
      this.kick();
      return;
    }
    this.end();
  }

  /** Close the connection now, telling the peer if it can still hear. */
  end() {
    if (this.gone) return;
    this.flags |= QF_CLOSE;
    this.closing = true;
    this.kick();
  }

  onWake(t) {
    if (this.gone) return Infinity;
    if (t >= this.lingerAt) { this.lingerAt = Infinity; this.end(); }
    if (t >= this.dueAt) { this.dueAt = Infinity; this.kick(); }
    return Math.min(this.dueAt, this.lingerAt);
  }

  // ── the calls ──

  kick() {
    if (this.gone || !this.opened) return;
    if (this.busy) { this.again = true; return; }
    this.step();
  }

  /** One call, with one `then` and no `await`: on the native loop each promise turn costs
   *  more than the module's work on a small packet. */
  step() {
    this.busy = true;
    this.again = false;
    this.inFlight = this.flags;
    try {
      host.call(N_QUIC, this.input(this.inFlight)).then(this.answered, this.refused);
    } catch {
      this.refused();
    }
  }

  /** The call is still the path's while its answer is handled, so what the link asks for
   *  meanwhile (a handshake message it answers at once) goes in the next call. */
  onAnswer(r) {
    if (!this.gone && (!r || r.length < HEAD_OUT)) this.fail();
    if (!this.gone) this.output(r, this.inFlight);
    this.busy = false;
    if (this.again && !this.gone) this.step();
  }

  /** `[Q_TURN][id u32][now f64][flags][read max u32]([handshake secrets 64])
   *  ([session keys 64])[n u8]([len u32][message])*[write len u32][write]` and the
   *  batches that came, `[len u32][batch]` each, in one buffer. */
  input(flags) {
    const hsKeys = flags & QF_HS_KEYS ? this.hsKeys : EMPTY;
    const keys = flags & QF_KEYS ? this.keySet : EMPTY;
    const msgs = this.hsOut.splice(0, MAX_HS);
    if (this.hsOut.length > 0) this.again = true;
    const write = Math.min(this.unsent.bytes, MAX_WRITE);
    // A fin once everything written is taken.
    if (this.closing && !this.finSent && this.unsent.bytes === 0 && !(flags & QF_CLOSE)) {
      flags |= QF_FIN;
      this.finSent = true;
    }
    // The batches that fit, at least one; the rest go in the next call.
    let take = 0, bytes = 0;
    while (take < this.inbound.length && (take === 0 || bytes + 4 + this.inbound[take].length <= MAX_IN)) {
      bytes += 4 + this.inbound[take++].length;
    }
    let hs = 1;
    for (const m of msgs) hs += 4 + m.length;
    const at = HEAD_IN + hsKeys.length + keys.length;
    const out = new Uint8Array(at + hs + 4 + write + bytes);
    out[0] = Q_TURN;
    writeU32BE(out, 1, this.id);
    new DataView(out.buffer).setFloat64(5, now());
    out[13] = flags;
    writeU32BE(out, 14, this.read && !this.reading ? MAX_READ : 0);
    out.set(hsKeys, HEAD_IN);
    out.set(keys, HEAD_IN + hsKeys.length);
    let o = at;
    out[o++] = msgs.length;
    for (const m of msgs) {
      writeU32BE(out, o, m.length);
      out.set(m, o + 4);
      o += 4 + m.length;
    }
    writeU32BE(out, o, write);
    if (write > 0) out.set(this.unsent.peek(write), o + 4);
    o += 4 + write;
    for (let i = 0; i < take; i++) {
      const batch = this.inbound[i];
      writeU32BE(out, o, batch.length);
      out.set(batch, o + 4);
      o += 4 + batch.length;
    }
    this.inbound.splice(0, take);
    if (this.inbound.length > 0) this.again = true;
    return out;
  }

  /** `[events][accepted u32][due f64][read len u32][handshake len u32][ids u8][read]
   *  ([len u32][message])*([id u32])*[sends]`, the sends as `link/udpSend` takes them. */
  output(r, flags) {
    // What was asked once is done, and the keys it carried are the module's alone.
    this.flags &= ~(flags & (QF_HS_KEYS | QF_KEYS | QF_CLOSE));
    if (flags & QF_HS_KEYS && this.hsKeys) { this.hsKeys.fill(0); this.hsKeys = null; }
    if (flags & QF_KEYS && this.keySet) { this.keySet.fill(0); this.keySet = null; }
    const events = r[0];
    const accepted = readU32BE(r, 1);
    if (accepted > 0) {
      this.unsent.take(accepted);
      // The connection took all it was given: there may be room for more.
      if (this.unsent.bytes > 0) this.again = true;
      // Or nothing is left, and a close waits to send its fin.
      if (this.unsent.bytes === 0 && this.closing && !this.finSent) this.again = true;
    }
    const due = new DataView(r.buffer, r.byteOffset).getFloat64(5);
    const readLen = readU32BE(r, 13), hsLen = readU32BE(r, 17);
    const at = HEAD_OUT, ids = at + readLen + hsLen, sends = ids + 4 * r[21];
    // Out first: what the answer sends is due now, whatever the link does next.
    if (sends < r.length) udp.send(r.subarray(sends));
    if (sends > ids && this.onIds) {
      const words = [];
      for (let o = ids; o < sends; o += 4) words.push(readU32BE(r, o));
      this.onIds(words);
    }
    for (let o = at + readLen; o < ids;) {
      const n = readU32BE(r, o);
      if (this.onHandshake) this.onHandshake(r.slice(o + 4, o + 4 + n));
      o += 4 + n;
    }
    this.readMore = (events & QE_MORE) !== 0;
    if (readLen > 0 && this.read && !this.gone) {
      this.reading = true;
      this.read(r.subarray(at, at + readLen)).then(this.readDone, this.readDone);
    } else if (this.readMore && this.read && !this.reading) {
      // Asked while the link was still decoding, which it has since finished.
      this.again = true;
    }
    // Everything written is acked: the graceful close can finish.
    if (events & QE_FINISHED && this.closing) {
      this.flags |= QF_CLOSE;
      this.again = true;
    }
    if (flags & QF_CLOSE || events & QE_CLOSED) { this.fail(); return; }
    this.dueAt = due < 0 ? Infinity : due;
    if (this.dueAt < Infinity) wakeBy(this.dueAt);
  }

  /** What the connection holds goes with it. */
  fail() {
    if (this.gone) return;
    this.gone = true;
    this.dueAt = Infinity;
    const drop = new Uint8Array(5);
    drop[0] = Q_DROP;
    writeU32BE(drop, 1, this.id);
    void this.call(drop);
    this.onGone();
  }
}
