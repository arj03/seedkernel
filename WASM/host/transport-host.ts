// Socket driver: owns links and listeners; protocol and peer state stay in the signed guest
// (§12.1). Destinations remain opaque, and events target the current link occupant (§12.10).

import { dec, errMessage, Fifo } from "../services/util.js";
import {
  DEFAULT_MAX_RAW_LINKS,
  MAX_LINK_READ_BYTES,
  MAX_INBOUND_HOLD_BYTES,
  MAX_INBOUND_HOLD_SLICES,
  MAX_NODE_OUTBOUND_QUEUE_BYTES,
  MAX_NODE_OUTBOUND_QUEUE_SLICES,
  MAX_OUTBOUND_QUEUE_BYTES,
  MAX_OUTBOUND_QUEUE_SLICES,
} from "../services/net-limits.js";
import { type LinkEvent } from "../services/domains.js";
import { type Arrival, type ChannelFactory, type ListenAddress, type RawLink } from "../services/socket-seam.js";
import { HOST_CALLER_ID, type RawNet } from "./guest-seam.js";
import { REALM_DISPOSED, type CausalClock } from "./realm-queue.js";
import { OpArgs } from "../services/op-frame.js";

const EMPTY = new Uint8Array(0);

/** Link id 0 means no route; its `stream` bit is ignored. */
const NO_ROUTE = { linkId: 0, stream: false } as const;

const ev = (name: LinkEvent) => new OpArgs(name);

/** Ceiling on the sockets the driver holds, before the guest has an opinion. */
export { DEFAULT_MAX_RAW_LINKS } from "../services/net-limits.js";

/** Active transport entrypoint, called with the whole realm argument `[caller 32][body …]`;
 *  `null` means the binding is vacant. */
export type TransportCall = (input: Uint8Array) => Promise<Uint8Array> | null;

/** The claim routing `link/deliver` is handed to (§12.10); `null` for a claim no peer may
 *  reach. `framed` is `[attribution 32][payload …]`, already the realm argument. */
export type TransportDeliver = (claim: string, framed: Uint8Array,
  deadlineMs?: number, causalClock?: CausalClock) => Promise<Uint8Array> | null;

export interface TransportHostOptions {
  /** Live raw links this driver holds at once (default `DEFAULT_MAX_RAW_LINKS`). Bounds the
   *  host's own table; never shipped to the guest. */
  maxRawLinks?: number;
  /** Aggregate write custody across every link in this driver. */
  maxOutboundBytes?: number;
  maxOutboundSlices?: number;
  /** The socket seam, which alone decides what a destination means. A factory with no
   *  `connect` is accept-only, and `link/open` answers "no route". */
  channels?: ChannelFactory;
  /** The listeners to bind, each labelled for the occupant. */
  listen?: readonly ListenAddress[];
  /** One link went down, with the occupant's reason (for the shipped transport, a word
   *  from ake.js `REASON_*`; empty when it said nothing). Observation only. No shell here
   *  uses it: it is how tests/transport-link.test.mjs pins what each reason means, and how
   *  a host gets the fact programmatically. */
  onLinkClosed?: (linkId: number, reason: string) => void;
  /** Silence the link-down diagnostic, for a node whose churn is normal (a relay) or a
   *  test. Teardowns still reach `onLinkClosed`. */
  suppressLinkLog?: boolean;
}

/** One link's outbound custody (§12.6) across adapter buffering and the socket backlog,
 *  and the driver's table entry for it. What the adapter still holds is the charge; the
 *  sizes queue turns that byte total back into slices. */
class LinkOutboundOwner {
  /** Admitted write sizes in send order, so a drained prefix is retired without waiting
   *  for the backlog to empty — the node-wide slice count is shared. */
  private readonly queued = new Fifo<number>();
  private charged = 0; // === sum(queued)
  private closed = false;

  constructor(
    readonly channel: RawLink,
    private readonly reserveParent: (bytes: number) => boolean,
    private readonly releaseParent: (bytes: number, slices: number) => void,
  ) {}

  /** The adapter's backlog, or null when it cannot answer. No `buffered` means nothing is
   *  retained past `send`. Null never releases, so a lying adapter fails its next send
   *  rather than dropping a charge the platform still holds (§12.6). */
  private report(): number | null {
    if (!this.channel.buffered) return 0;
    try {
      const n = this.channel.buffered();
      return Number.isSafeInteger(n) && n >= 0 ? n : null;
    } catch {
      return null;
    }
  }

  /** Release what the platform drained since the last look. Transports here are ordered,
   *  so the backlog is a suffix of what was admitted; a partly drained head stays
   *  charged. */
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
 *  A transport update hands nothing over: listeners survive, but links hold the outgoing
 *  guest's session keys (§4.3), so an upgrade is a reconnect (§12.10). */
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
  private deliver: TransportDeliver | null = null;
  private closed = false;
  // One realm sits behind every link, so the inbound allowance is driver-wide: the read
  // dispatched per link plus anything held above unpausable adapters.
  private inboundReadSlices = 0;
  private inboundReadBytes = 0;
  private outboundSlices = 0;
  private outboundBytes = 0;

  constructor(opts: TransportHostOptions) {
    this.opts = opts;
  }

  /** Wire `link/deliver` to current peer claims (§12.10). */
  routeInbound(deliver: TransportDeliver): void { this.deliver = deliver; }

  available(): boolean { return !this.closed && this.call !== null; }

  /** Publish the binding. The previous occupant's links are closed first, while the binding
   *  is vacant, so no `linkClosed` reaches a realm on its way out. */
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
    return this.outboundSlices < (this.opts.maxOutboundSlices ?? MAX_NODE_OUTBOUND_QUEUE_SLICES)
      && length <= (this.opts.maxOutboundBytes ?? MAX_NODE_OUTBOUND_QUEUE_BYTES) - this.outboundBytes;
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
    // Through the ordinary down path, snapshotted because it deletes as it goes; clearing
    // the table first would make `channelClosed` skip the occupant's notice.
    for (const [linkId, link] of [...this.links]) this.dropLink(linkId, link);
  }

  /** Sever one socket. A throw is a backend that has already let go. */
  private shut(channel: RawLink): void {
    try { channel.close(false); } catch { /* already gone */ }
  }

  /** Every hard teardown the driver makes; only the occupant's `link/close` may be
   *  graceful. */
  private dropLink(linkId: number, link: LinkOutboundOwner): void {
    this.shut(link.channel);
    this.channelClosed(linkId, link);
  }

  /** Whether `close` has run: a replaced driver merely dereferenced still holds its
   *  listener. */
  get isClosed(): boolean { return this.closed; }

  /** The port the first listener labelled `label` bound, or 0 for none. */
  portOf(label: string): number {
    return this.listening.find((a) => a.label === label)?.port ?? 0;
  }

  // ── reaching the transport ──────────────────────────────────────────────────
  // `OpArgs` (services/op-frame.ts) encodes the raw-link event ABI (RUNTIME §12.2).

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

  /** The raw `link` service the transport guest's seam is wired to. */
  rawNet(): RawNet {
    const bound = () => this.call !== null;
    return {
      open: (dest) => {
        if (!bound()) return NO_ROUTE;
        const channel = this.opts.channels?.connect?.(dest) ?? null;
        if (!channel) return NO_ROUTE;
        // A full link table also reads as "no route".
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
          // A throwing backend may already have written a prefix (an RTC write split into
          // chunks); continuing would desynchronize the framing.
          this.dropLink(linkId, link);
        }
      },
      close: (linkId, graceful) => {
        if (!bound()) return;
        const link = this.links.get(linkId);
        if (!link) return;
        try { link.channel.close(graceful); } catch { /* already gone */ }
        // Backends disagree on whether a local close fires onClose (native cannot), so the
        // driver makes the event universal on a later turn; a racing callback is a no-op.
        queueMicrotask(() => this.channelClosed(linkId, link));
      },
      // (§12.10) A refused claim and a failed handler both answer empty.
      deliver: (claim, framed, deadlineMs, causalClock) => {
        if (!bound() || !this.deliver) return Promise.resolve(EMPTY);
        const answer = this.deliver(claim, framed, deadlineMs, causalClock);
        if (!answer) return Promise.resolve(EMPTY);
        return answer.then((bytes) => bytes ?? EMPTY, () => EMPTY);
      },
    };
  }

  // ── channels ────────────────────────────────────────────────────────────────

  /** Mint a link id for a channel and wire its events into the transport. Returns 0 at
   *  `maxRawLinks`, having closed the channel so no descriptor is stranded. */
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
    /** A read finished: drain what was held, oldest first. A loop, since a vacant binding
     *  answers synchronously and recursion would stack the whole queue. */
    const releaseRead = () => {
      releaseActive();
      for (;;) {
        if (this.links.get(linkId) !== link) { dropHeld(); return; }
        const next = held.shift();
        if (!next) break;
        if (!dispatchRead(next)) return; // in flight: its settle re-enters here
        releaseActive(); // vacant binding or synchronous failure
      }
      try { channel.setReadable?.(true); }
      catch { failReadSide(); }
    };
    /** Hand one read to the realm. True only when it was over before it began (vacant
     *  binding); false when in flight or the link died. */
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
      try { held.push(new Uint8Array(bytes)); }
      catch {
        this.releaseInboundRead(bytes.length);
        failReadSide();
      }
    });
    channel.onClose(() => { dropHeld(); this.channelClosed(linkId, link); });
    return linkId;
  }

  /** Print a link-down reason with the socket's unauthenticated remote address, the only
   *  thing the driver knows about which machine it was. */
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
   *  another link (a WebRTC data channel, whose negotiation link is `via`; 0 when none or
   *  gone). */
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
        // Refused at the door without telling the occupant, like every pre-auth refusal.
        if (linkId === 0) return;
        this.announce(linkId, channel, arrival);
      },
    );
    this.listening = addrs.map((a, i) => ({ ...a, port: ports[i] ?? 0 }));
  }

  /** Tear the driver down without the occupant's cooperation, which a wedged occupant
   *  could refuse (§1). */
  close(): void {
    if (this.closed) return;
    // First, so the channel closes below queue no `linkClosed` into a dying realm.
    this.closed = true;
    this.call = null;
    this.reset();
    this.opts.channels?.close();
  }
}
