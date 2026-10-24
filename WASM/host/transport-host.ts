// Socket driver: owns links and listeners, while protocol and peer state stay in the signed
// guest (§12.1). Destinations are opaque, and events go to the current link occupant
// (§12.10).

import { concatBytes, dec, EMPTY, errMessage, Fifo, readU32BE, u8 } from "../services/util.js";
import {
  DEFAULT_MAX_RAW_LINKS,
  MAX_LINK_READ_BYTES,
  MAX_INBOUND_HOLD_BYTES,
  MAX_INBOUND_HOLD_SLICES,
  MAX_NODE_OUTBOUND_QUEUE_BYTES,
  MAX_NODE_OUTBOUND_QUEUE_SLICES,
  MAX_OUTBOUND_QUEUE_BYTES,
  MAX_OUTBOUND_QUEUE_SLICES,
  MAX_UDP_HELD_BYTES,
  MAX_UDP_SOCKETS,
  UDP_SOCKET_BUFFER_BYTES,
} from "../services/net-limits.js";
import { type LinkEvent } from "../services/domains.js";
import { datagramEnd, type RawDatagrams } from "../services/datagrams.js";
import { type Arrival, type ChannelFactory, type ListenAddress, type RawLink } from "../services/socket-seam.js";
import { HOST_CALLER_ID, type DatagramSocket, type RawNet } from "./guest-seam.js";
import { REALM_DISPOSED } from "./realm-queue.js";
import { OpArgs } from "../services/op-frame.js";

/** Link id 0 means no route; its `stream` bit is ignored. */
const NO_ROUTE = { linkId: 0, stream: false } as const;

const NO_SOCKET: DatagramSocket = { id: 0, port: 0, addresses: "" };

const ev = (name: LinkEvent) => new OpArgs(name);

/** Ceiling on the sockets the driver holds, independent of any guest limit. */
export { DEFAULT_MAX_RAW_LINKS } from "../services/net-limits.js";

/** Active transport entrypoint, called with the whole realm argument
 *  `[caller 32][body ...]`; `null` means no occupant is bound. */
export type TransportCall = (input: Uint8Array) => Promise<Uint8Array> | null;

export interface TransportHostOptions {
  /** Live raw links this driver holds at once (default `DEFAULT_MAX_RAW_LINKS`). Bounds the
   *  host's own table; never shipped to the guest. */
  maxRawLinks?: number;
  /** The socket seam, which alone decides what a destination means. A factory with no
   *  `connect` is accept-only, and `link/open` answers "no route". */
  channels?: ChannelFactory;
  /** The listeners to bind, each labelled for the occupant. */
  listen?: readonly ListenAddress[];
  /** The platform's datagram sockets, lent to the occupant for its UDP paths (§12.7).
   *  Omitted means none: `link/udpBind` answers socket 0. */
  datagrams?: RawDatagrams;
  /** One link went down, with the occupant's reason (for the shipped transport, a word
   *  from ake.js `REASON_*`; empty when it gave none). Observation only. No shell uses it;
   *  tests/transport-link.test.mjs checks reasons through it, and an embedder can use it
   *  to observe link loss. */
  onLinkClosed?: (linkId: number, reason: string) => void;
  /** Silence the link-down diagnostic, for a node whose churn is normal (a relay) or a
   *  test. Teardowns still reach `onLinkClosed`. */
  suppressLinkLog?: boolean;
}

/** One link's outbound accounting (§12.6) across adapter buffering and the socket backlog,
 *  and the driver's table entry for it. What the adapter still holds is charged; the
 *  queue of write sizes turns that byte total back into a count of writes. */
class LinkOutboundOwner {
  /** Admitted write sizes in send order, so a drained prefix is released without waiting
   *  for the whole backlog to empty (the node-wide write count is shared). */
  private readonly queued = new Fifo<number>();
  private charged = 0; // === sum(queued)
  private closed = false;

  constructor(
    readonly channel: RawLink,
    private readonly reserveParent: (bytes: number) => boolean,
    private readonly releaseParent: (bytes: number, slices: number) => void,
  ) {}

  /** The adapter's backlog, or null when it cannot answer. No `buffered` means nothing is
   *  retained past `send`. Null never releases, so a misbehaving adapter fails its next
   *  send instead of dropping a charge the platform still holds (§12.6). */
  private report(): number | null {
    if (!this.channel.buffered) return 0;
    try {
      const n = this.channel.buffered();
      return Number.isSafeInteger(n) && n >= 0 ? n : null;
    } catch {
      return null;
    }
  }

  /** Release what the platform drained since the last check. Links are ordered, so the
   *  backlog is a suffix of what was admitted; a partly drained head stays charged. */
  private settle(now: number | null): void {
    if (now === null) return;
    let n = 0, bytes = 0;
    while (n < this.queued.size && this.charged - bytes - this.queued.at(n) >= now) {
      bytes += this.queued.at(n++);
    }
    if (n === 0) return;
    this.queued.drop(n);
    this.charged -= bytes;
    this.releaseParent(bytes, n);
  }

  send(bytes: Uint8Array): void {
    if (this.closed) throw new Error("socket: link is closed");
    const now = this.report();
    if (now === null) throw new Error("socket: adapter cannot report its outbound backlog");
    this.settle(now);
    if (this.queued.size >= MAX_OUTBOUND_QUEUE_SLICES
      || bytes.length > MAX_OUTBOUND_QUEUE_BYTES - this.charged
      || !this.reserveParent(bytes.length)) {
      throw new Error("socket: outbound queue limit exceeded");
    }
    this.charged += bytes.length;
    this.queued.push(bytes.length);
    try { this.channel.send(bytes); }
    catch (err) { this.releaseAll(); throw err; }
    this.settle(this.report());
  }

  /** Reconcile platform progress before the node-wide parent admits another write. */
  reconcile(): void { this.settle(this.report()); }

  releaseAll(): void {
    if (this.closed) return;
    this.closed = true;
    this.releaseParent(this.charged, this.queued.size);
    this.queued.clear();
    this.charged = 0;
  }
}

/** The host side of the node's network: sockets and listeners. No app reaches it.
 *
 *  A transport replacement carries no links over: listeners survive, but links depend on
 *  the outgoing guest's session keys (§12.6.1), so peers reconnect (§12.10). */
export class TransportHost {
  /** The listeners as bound: each requested address with the port the platform gave it. */
  listening: readonly ListenAddress[] = [];

  private readonly opts: TransportHostOptions;
  /** Every live link, by the id the occupant names it with. */
  private readonly links = new Map<number, LinkOutboundOwner>;
  /** The id each live channel is registered under, for an arrival's `via`. */
  private readonly idOf = new WeakMap<RawLink, number>();
  private nextLinkId = 1;
  private call: TransportCall | null = null;
  private closed = false;
  // One realm sits behind every link, so the inbound allowance is driver-wide: the read
  // in flight per link plus anything held for adapters that cannot pause.
  private inboundReadSlices = 0;
  private inboundReadBytes = 0;
  private outboundSlices = 0;
  private outboundBytes = 0;
  // The occupant's datagram sockets. A socket's reads wait here, at most MAX_UDP_HELD_BYTES
  // together, for the one `datagrams` event in the realm at a time.
  private readonly sockets = new Set<number>();
  private binding = 0;
  /** Counts occupants, so what finishes for one that has gone touches nothing. */
  private socketGen = 0;
  private readonly reads = new Fifo<{ args: OpArgs; bytes: number }>();
  private heldDatagramBytes = 0;
  private readsBusy = false;
  private readsDue = false;

  constructor(opts: TransportHostOptions) {
    this.opts = opts;
  }

  available(): boolean { return !this.closed && this.call !== null; }

  /** Bind a new occupant. The previous occupant's links are closed first, while nothing
   *  is bound, so no `linkClosed` reaches a realm on its way out. */
  activate(call: TransportCall): void {
    this.release();
    this.call = call;
  }

  release(): void {
    if (!this.call) return;
    this.call = null;
    this.reset();
  }

  private reserveInboundRead(length: number): boolean {
    if (this.inboundReadSlices >= MAX_INBOUND_HOLD_SLICES
      || length > MAX_INBOUND_HOLD_BYTES - this.inboundReadBytes) return false;
    this.inboundReadSlices++;
    this.inboundReadBytes += length;
    return true;
  }

  private releaseInboundRead(length: number): void {
    this.inboundReadSlices--;
    this.inboundReadBytes -= length;
  }

  private outboundFits(length: number): boolean {
    return this.outboundSlices < MAX_NODE_OUTBOUND_QUEUE_SLICES
      && length <= MAX_NODE_OUTBOUND_QUEUE_BYTES - this.outboundBytes;
  }

  private reserveOutbound(length: number): boolean {
    if (!this.outboundFits(length)) {
      // Pull-based adapters report drain only when asked. Sweep the other links only on a
      // refusal, so a write never walks the whole table.
      for (const owner of this.links.values()) owner.reconcile();
    }
    if (!this.outboundFits(length)) {
      return false;
    }
    this.outboundSlices++;
    this.outboundBytes += length;
    return true;
  }

  private releaseOutbound(bytes: number, slices: number): void {
    this.outboundBytes -= bytes;
    this.outboundSlices -= slices;
  }

  /** Close every live link, keeping the listeners and the binding. The occupant, if still
   *  bound, hears one `linkClosed` per link. */
  reset(): void {
    // Through the normal close path, over a copy since it deletes as it goes. Clearing the
    // table first would make `channelClosed` skip notifying the occupant.
    for (const [linkId, link] of [...this.links]) this.dropLink(linkId, link);
    // Sockets are the occupant's paths, session state as its links are.
    this.socketGen++;
    for (const id of this.sockets) this.opts.datagrams?.close(id);
    this.sockets.clear();
    this.reads.clear();
    this.heldDatagramBytes = 0;
    this.readsBusy = false;
  }

  /** Close one socket. A throw means the backend already closed it. */
  private shut(channel: RawLink): void {
    try { channel.close(false); } catch { /* already gone */ }
  }

  /** Every hard close the driver makes; only the occupant's `link/close` may be graceful. */
  private dropLink(linkId: number, link: LinkOutboundOwner): void {
    this.shut(link.channel);
    this.channelClosed(linkId, link);
  }

  /** The port the first listener labelled `label` bound, or 0 for none. */
  portOf(label: string): number {
    return this.listening.find((a) => a.label === label)?.port ?? 0;
  }

  // ── reaching the transport ──────────────────────────────────────────────────
  // `OpArgs` (services/op-frame.ts) encodes the raw-link event ABI (§12.2).

  /** Call the transport. The realm serializes invocations, so one link's bytes arrive in
   *  order. */
  private toTransport(args: OpArgs): Promise<Uint8Array> | null {
    if (this.closed || !this.call) return null;
    return this.call(args.build(HOST_CALLER_ID));
  }

  /** Log a rejected op, except a realm disposed by this driver's own teardown. */
  private reportOpError(op: string, err: unknown): void {
    if (errMessage(err) === REALM_DISPOSED) return;
    console.error(`[transport] error in ${op}: ${String(err)}`);
  }

  /** `toTransport` for an op whose answer nobody is waiting on. */
  private tell(args: OpArgs): void {
    const r = this.toTransport(args);
    if (r) void r.catch((err: unknown) => this.reportOpError(args.op, err));
  }

  /** The raw links of the `link` service; the shell adds `deliver` (§12.10). */
  rawNet(): RawNet {
    const bound = () => this.call !== null;
    return {
      open: (dest) => {
        if (!bound()) return NO_ROUTE;
        const channel = this.opts.channels?.connect?.(dest) ?? null;
        if (!channel) return NO_ROUTE;
        // A full link table also means "no route".
        const linkId = this.register(channel);
        if (linkId === 0) return NO_ROUTE;
        return { linkId, stream: channel.stream === true };
      },
      send: (linkId, bytes) => {
        if (!bound()) return;
        const link = this.links.get(linkId);
        if (!link) return;
        try { link.send(bytes); }
        catch {
          // A throwing backend may already have written part of the bytes (an RTC write
          // split into chunks), and continuing would break the framing.
          this.dropLink(linkId, link);
        }
      },
      close: (linkId, graceful) => {
        if (!bound()) return;
        const link = this.links.get(linkId);
        if (!link) return;
        try { link.channel.close(graceful); } catch { /* already gone */ }
        // Backends differ on whether a local close fires onClose (native does not), so the
        // driver always raises the event itself on a later turn; a racing callback is a
        // no-op.
        queueMicrotask(() => this.channelClosed(linkId, link));
      },
      udpBind: () => (bound() ? this.bind() : Promise.resolve(NO_SOCKET)),
      udpSend: (batch) => {
        const raw = this.opts.datagrams;
        if (!bound() || !raw) return;
        // The platform takes the batch whole, so it is checked here: every datagram inside
        // it, and from a socket this occupant holds. One that is not is left out.
        let kept: Uint8Array[] | null = null;
        for (let at = 0; at < batch.length;) {
          const end = datagramEnd(batch, at);
          if (end > batch.length) throw new Error("link/udpSend: a datagram runs past the batch");
          if (this.sockets.has(readU32BE(batch, at))) kept?.push(batch.subarray(at, end));
          else kept ??= [batch.subarray(0, at)];
          at = end;
        }
        raw.send(kept ? concatBytes(kept) : batch);
      },
      udpClose: (id) => {
        if (this.sockets.delete(id)) this.opts.datagrams?.close(id);
      },
    };
  }

  // ── datagrams ───────────────────────────────────────────────────────────────
  // The host reads no datagram and keeps no path (§12.7): it bounds what the occupant holds,
  // its sockets and what they read while it is busy.

  /** A socket, or socket 0 when the platform has none, the cap is reached or the bind
   *  failed. */
  private async bind(): Promise<DatagramSocket> {
    const raw = this.opts.datagrams;
    if (!raw || this.sockets.size + this.binding >= MAX_UDP_SOCKETS) return NO_SOCKET;
    const gen = this.socketGen;
    this.binding++;
    try {
      let id = 0;
      const b = await raw.bind((batch) => {
        if (id !== 0) this.heard(id, u8(batch));
      }, UDP_SOCKET_BUFFER_BYTES, MAX_UDP_HELD_BYTES);
      if (gen !== this.socketGen) { raw.close(b.id); return NO_SOCKET; }
      id = b.id;
      this.sockets.add(id);
      return { id, port: b.port, addresses: raw.addresses() };
    } catch {
      return NO_SOCKET;
    } finally {
      this.binding--;
    }
  }

  /** A socket's read, for the next event. Past what the host holds it is dropped, as a full
   *  socket buffer drops one. */
  private heard(id: number, batch: Uint8Array): void {
    if (!this.sockets.has(id) || batch.length > MAX_UDP_HELD_BYTES - this.heldDatagramBytes) return;
    this.heldDatagramBytes += batch.length;
    let last = this.reads.size > 0 ? this.reads.at(this.reads.size - 1) : undefined;
    if (!last || last.bytes + batch.length > MAX_LINK_READ_BYTES) {
      last = { args: ev("datagrams"), bytes: 0 };
      this.reads.push(last);
    }
    last.args.u32(id).blob(batch);
    last.bytes += batch.length;
    this.pumpReads();
  }

  /** The next event, once the last has been read, on a later turn. */
  private pumpReads(): void {
    if (this.readsBusy || this.readsDue || this.reads.size === 0) return;
    this.readsDue = true;
    // On a later microtask, so the reads that arrive in one platform callback go together.
    queueMicrotask(() => {
      this.readsDue = false;
      const next = this.reads.shift();
      if (!next || this.readsBusy) return;
      const gen = this.socketGen;
      const done = () => {
        if (gen !== this.socketGen) return;
        this.readsBusy = false;
        this.heldDatagramBytes -= next.bytes;
        this.pumpReads();
      };
      const r = this.toTransport(next.args);
      if (!r) { done(); return; }
      this.readsBusy = true;
      void r.then(done, (err: unknown) => { this.reportOpError("datagrams", err); done(); });
    });
  }

  // ── channels ────────────────────────────────────────────────────────────────

  /** Assign a link id to a channel and wire its events to the transport. Returns 0 at
   *  `maxRawLinks`, after closing the channel so no descriptor leaks. */
  private register(channel: RawLink): number {
    if (this.links.size >= (this.opts.maxRawLinks ?? DEFAULT_MAX_RAW_LINKS)) {
      this.shut(channel);
      return 0;
    }
    const linkId = this.nextLinkId++;
    const link = new LinkOutboundOwner(
      channel,
      (bytes) => this.reserveOutbound(bytes),
      (bytes, slices) => this.releaseOutbound(bytes, slices),
    );
    this.links.set(linkId, link);
    this.idOf.set(channel, linkId);
    // One read per link in the realm at a time. A pausable adapter is paused at the socket;
    // otherwise reads are held here. Every read reserves the driver-wide budget first.
    // Width of the read in the realm, or -1 for none (an empty read is still in flight).
    let activeBytes = -1;
    const held = new Fifo<Uint8Array>();

    const dropHeld = () => {
      for (let i = 0; i < held.size; i++) this.releaseInboundRead(held.at(i).length);
      held.clear();
    };
    const releaseActive = () => {
      if (activeBytes < 0) return;
      this.releaseInboundRead(activeBytes);
      activeBytes = -1;
    };
    const failReadSide = () => {
      dropHeld();
      this.dropLink(linkId, link);
    };
    /** A read finished: drain what was held, oldest first. A loop, because with nothing
     *  bound a read finishes synchronously and recursion would grow the stack per read. */
    const releaseRead = () => {
      releaseActive();
      for (;;) {
        if (this.links.get(linkId) !== link) { dropHeld(); return; }
        const next = held.shift();
        if (!next) break;
        if (!dispatchRead(next)) return; // in flight: its settle re-enters here
        releaseActive(); // nothing bound, or a synchronous failure
      }
      try { channel.setReadable?.(true); }
      catch { failReadSide(); }
    };
    /** Hand one read to the realm. True when it finished synchronously (nothing bound);
     *  false when in flight or the link died. */
    const dispatchRead = (bytes: Uint8Array): boolean => {
      activeBytes = bytes.length;
      try { channel.setReadable?.(false); }
      catch { releaseActive(); failReadSide(); return false; }
      let result: Promise<Uint8Array> | null;
      try { result = this.toTransport(ev("linkBytes").u32(linkId).blob(bytes)); }
      catch (err) { this.reportOpError("linkBytes", err); return true; }
      if (!result) return true;
      void result.then(releaseRead, (err: unknown) => { this.reportOpError("linkBytes", err); releaseRead(); });
      return false;
    };

    channel.onData((bytes) => {
      if (this.links.get(linkId) !== link) return;
      // Only a platform-framed message can be this large; refuse it before it is copied.
      if (bytes.length > MAX_LINK_READ_BYTES) { failReadSide(); return; }
      if (!this.reserveInboundRead(bytes.length)) { failReadSide(); return; }
      if (activeBytes < 0) {
        if (dispatchRead(bytes)) releaseRead();
        return;
      }
      // A custom RawLink may reuse its callback buffer, so a held read owns its bytes.
      held.push(new Uint8Array(bytes));
    });
    channel.onClose(() => { dropHeld(); this.channelClosed(linkId, link); });
    return linkId;
  }

  /** Print a link-down reason with the socket's unauthenticated remote address, the only
   *  thing the driver knows about the other end. */
  private logLinkDown(linkId: number, channel: RawLink, reason: string): void {
    if (this.opts.suppressLinkLog) return;
    const from = channel.remoteAddr ? ` from ${channel.remoteAddr}` : "";
    console.error(`[transport] link ${linkId}${from} down: ${reason}`);
  }

  /** A channel became unusable: drop it, tell the occupant, and report its answer,
   *  `[severity u8][reason utf8]`. The driver prints reasons above severity 0 and never
   *  reads the words; an absent answer is an empty reason at severity 0. */
  private channelClosed(linkId: number, link: LinkOutboundOwner): void {
    if (this.links.get(linkId) !== link) return;
    this.links.delete(linkId);
    link.releaseAll();
    const report = (ret: Uint8Array) => {
      const reason = dec.decode(ret.subarray(1));
      if (ret.length > 0 && ret[0] > 0) this.logLinkDown(linkId, link.channel, reason);
      try { this.opts.onLinkClosed?.(linkId, reason); }
      catch { /* a platform callback cannot corrupt this driver's link table */ }
    };
    const r = this.toTransport(ev("linkClosed").u32(linkId));
    if (!r) { report(EMPTY); return; }
    void r.then(
      report,
      (err: unknown) => { report(EMPTY); this.reportOpError("linkClosed", err); },
    );
  }

  /** Announce a link the host hands over: an accepted socket, or one that arrived through
   *  another link (a WebRTC data channel, whose negotiation link is `via`; 0 when there is
   *  none or it is gone). */
  private announce(linkId: number, channel: RawLink, arrival?: Arrival): void {
    const via = arrival?.via ? this.idOf.get(arrival.via) ?? 0 : 0;
    this.tell(ev("linkOpen")
      .u32(linkId)
      .u8(channel.stream ? 1 : 0)
      .text(arrival?.listener ?? "")
      .u32(via && this.links.has(via) ? via : 0)
      .text(channel.remoteAddr ?? ""));
  }

  /** Bind the listeners (if any) through the channel factory, and take its accept sink. */
  async start(): Promise<void> {
    if (!this.opts.channels) return;
    const addrs = this.opts.listen ?? [];
    const ports = await this.opts.channels.listen(
      addrs,
      (channel, arrival) => {
        if (!this.available()) {
          this.shut(channel);
          return;
        }
        const linkId = this.register(channel);
        // Refused without telling the occupant, like every pre-auth refusal.
        if (linkId === 0) return;
        this.announce(linkId, channel, arrival);
      },
    );
    this.listening = addrs.map((a, i) => ({ ...a, port: ports[i] ?? 0 }));
  }

  /** Tear the driver down without the occupant's cooperation, which a wedged occupant
   *  could not give. */
  close(): void {
    if (this.closed) return;
    // First, so the closes below send no `linkClosed` into a dying realm.
    this.closed = true;
    this.call = null;
    this.reset();
    this.opts.channels?.close();
  }
}
