// Socket driver: owns links and listeners; protocol and peer state stay in the signed guest
// (§12.1). Destinations remain opaque, and events target the current link occupant (§12.10).


import { toHex, fromHex } from "../core/util.js";
import { DEFAULT_MAX_RAW_LINKS } from "../core/net-limits.js";
import { type LinkEvent } from "../core/domains.js";
import { type Arrival, type ChannelFactory, type RawLink } from "../core/socket-seam.js";
import { type JsonObject } from "./bundle.js";
import { type RawNet } from "./guest-seam.js";
import { OpArgs } from "./op-frame.js";

const EMPTY = new Uint8Array(0);

/** Link id 0 means no route; its `stream` bit is ignored. */
const NO_ROUTE = { linkId: 0, stream: false } as const;
const ZERO32 = new Uint8Array(32);

const ev = (name: LinkEvent) => new OpArgs(name);

/** Ceiling on what the DRIVER holds — a socket costs a descriptor the moment it
 *  is accepted, before the guest has an opinion. Occupant budgets sit above this. */
export { DEFAULT_MAX_RAW_LINKS } from "../core/net-limits.js";

/** Active transport entrypoint; `null` means the binding is vacant. */
export type TransportCall = (payload: Uint8Array) => Promise<Uint8Array> | null;

/** The claim routing a `link/deliver` call is handed to (§12.10). `null` for a claim no
 *  peer may reach. Inbound attributed delivery costs no grant beyond `link` itself: the
 *  occupant that saw the plaintext is the one that attributes it. */
export type TransportDeliver = (claim: string, attribution: Uint8Array, payload: Uint8Array) => Promise<Uint8Array> | null;

export interface TransportHostOptions {
  /** Network isolation key; absent selects the public network (§12.6.3). */
  networkKey?: Uint8Array;
  /** Live raw links this driver will hold at once (default `DEFAULT_MAX_RAW_LINKS`).
 *  Unlike every budget above it, enforced HERE and never shipped to the guest: it bounds
 *  the host's own link table, not the occupant's link states. */
  maxRawLinks?: number;
  /** The socket seam: dialing and listening live here, and so does every judgement about
 *  what a destination string MEANS. A browser edge passes its WebRTC/WebSocket factory; a
 *  factory with no `connect` (WebRTC, whose peers arrive through signaling) is accept-only,
 *  and its `link/open` calls answer "no route". */
  channels?: ChannelFactory;
  listen?: { host: string; port: number };
  wsListen?: { host: string; port: number };
  /** One link went down, with the occupant's one-byte reason (transport/src/ake.js
 *  `REASON_*`) — a clean farewell, a defensive teardown, a cut stream. The host relays the
 *  number and never interprets it: the vocabulary belongs to whichever bundle holds the
 *  links. NODE-level and observation only, unlike the per-link callbacks it replaces —
 *  nothing here can change what the occupant does, and an app that wants the peer set asks
 *  the transport for it. */
  onLinkClosed?: (linkId: number, reason: number) => void;
}

/** The host side of the node's network: sockets and listeners. Nothing on this object is
 *  reached by an app.
 *
 *  There is no handover of ANY kind across a transport update. The listeners are the
 *  node's and survive, but live links cannot — the session keys are in the outgoing guest's
 *  private memory (§4.3) — and neither can the address book, which is now that guest's too.
 *  So an upgrade is a reconnect, and the embedder re-supplies the addresses (§12.10). */
export class TransportHost {
  port = 0;
  wsPort = 0;

  private readonly opts: Omit<TransportHostOptions, "networkKey">;
  private readonly nodeFacts: Pick<TransportHostOptions, "networkKey">;
  private readonly channels = new Map<number, RawLink>;
  private nextLinkId = 1;
  private call: TransportCall | null = null;
  private deliver: TransportDeliver | null = null;
  private closed = false;

  constructor(
    opts: Omit<TransportHostOptions, "networkKey">,
    nodeFacts: Pick<TransportHostOptions, "networkKey">,
  ) {
    this.opts = opts;
    this.nodeFacts = nodeFacts;
  }

  /** Wire `link/deliver` to current peer claims (§12.10). */
  routeInbound(deliver: TransportDeliver): void { this.deliver = deliver; }

  available(): boolean { return !this.closed && this.call !== null; }

  /** Publish the binding, closing links from any previous occupant. */
  activate(call: TransportCall): void {
    if (this.call) this.reset();
    this.call = call;
  }

  release(): void {
    if (!this.call) return;
    this.call = null;
    this.reset();
  }

  /** Host-owned transport config (§12.10). */
  initialConfig(): JsonObject {
    return { networkKey: toHex(this.nodeFacts.networkKey ?? ZERO32) };
  }

  /** Release link state owned by a departing link-capable slot, retaining the listeners for
   *  a replacement. Also the platform's own "sever": closing every live socket without
   *  moving the binding — the occupant hears one `linkClosed` per link, and the node keeps
   *  its listeners, which are the node's and not the occupant's. */
  reset(): void {
    // Each link through the ordinary down path, rather than clearing the table first: a
    // cleared table makes `channelClosed`'s liveness guard drop the channel's own callback,
    // and the occupant would go on holding a link whose socket is already gone. Snapshotted
    // because `channelClosed` deletes as it goes, and idempotent, so a backend callback
    // racing this loop is a no-op. On a teardown or a handover the binding is released
    // before this runs, so only a sever — where the same occupant stays — hears them.
    for (const [linkId, c] of [...this.channels.entries()]) {
      try { c.close(false); } catch { /* already gone */ }
      this.channelClosed(linkId, c);
    }
  }

  /** Whether `close` has run. Public because a teardown has to be checkable: a replaced
   *  driver that is merely dereferenced still holds its listener. */
  get isClosed(): boolean { return this.closed; }

  // ── reaching the transport ──────────────────────────────────────────────────
  //
  // `OpArgs` (op-frame.ts) is the TRANSPORT BUNDLE's framing, not a kernel ABI: the
  // kernel's only obligation in front of it is the 32-byte caller id the shell adds
  // (shell-core.ts `hostCallSlot`). Paired with this driver like the wire codec, so the
  // two move in one artifact.

  /** Call the transport, with the shell's caller-id prefix added at the realm call.
   *
   *  Not unordered: the realm serializes invocations in acceptance order (realm-queue.ts),
   *  so bytes arriving on one link reach the occupant in arrival order. */
  private toTransport(args: OpArgs): Promise<Uint8Array> | null {
    if (this.closed || !this.call) return null;
    return this.call(args.build());
  }

  /** `toTransport` for an op whose answer nobody is waiting on. A rejection is logged,
   *  except a realm disposed out from under the op — this driver's own teardown or
   *  replacement, which would otherwise print an error per ordinary shutdown. */
  private tell(args: OpArgs): void {
    const r = this.toTransport(args);
    if (r) void r.catch((err: unknown) => {
      if (String((err as Error)?.message ?? err).includes("realm disposed")) return;
      console.error(`[transport] error in ${args.op}: ${String(err)}`);
    });
  }

  // ── the capability backend the transport guest's seam is wired to ───────────

  /** The RAW net capability: an opaque link id over the platform's sockets, and the whole
   *  of what the host contributes to the network. */
  rawNet(): RawNet {
    const bound = () => this.call !== null;
    return {
      open: (dest) => {
        if (!bound()) return NO_ROUTE;
        // ChannelFactory alone decides routing (§12.1).
        const channel = this.opts.channels?.connect?.(dest) ?? null;
        if (!channel) return NO_ROUTE;
        // A full link table reads as "no route" too: the same answer for the same reason —
        // this driver cannot carry the frame.
        const linkId = this.register(channel);
        if (linkId === 0) return NO_ROUTE;
        return { linkId, stream: channel.stream === true };
      },
      send: (linkId, bytes) => {
        if (!bound()) return;
        const channel = this.channels.get(linkId);
        if (!channel) return;
        try { channel.send(bytes); }
        catch {
          // A throwing backend may already have emitted a prefix (notably an RTC write
          // split into SCTP-sized chunks). Continuing would desynchronize LENGTH framing.
          try { channel.close(false); } catch { /* already gone */ }
          this.channelClosed(linkId, channel);
        }
      },
      close: (linkId, graceful) => {
        if (!bound()) return;
        const channel = this.channels.get(linkId);
        if (!channel) return;
        try { channel.close(graceful); } catch { /* already gone */ }
        // RawLink implementations disagree about whether a deliberate local close later
        // fires onClose (native explicitly cannot). The driver owns the table, so it makes
        // the event universal on a later turn; a backend callback racing it is idempotent.
        queueMicrotask(() => this.channelClosed(linkId, channel));
      },
      // A link that is gone, or a channel that cannot say, both read 0 — the safe answer:
      // the occupant's stall clock sees no progress and lets the deadline decide.
      buffered: (linkId) => {
        if (!bound()) return 0;
        try { return this.channels.get(linkId)?.buffered?.() ?? 0; } catch { return 0; }
      },
      // Inbound attributed delivery (§12.10): one request the occupant decoded, routed
      // through the shell's claim table and answered back to the occupant, which frames it
      // and writes it on the wire. Under the same binding check as every op above and no
      // further grant — the occupant names no link here, and it already chose all three of
      // these arguments. A claim no peer may reach and a handler that threw both answer
      // EMPTY, so refusal and silence are one fact at this boundary.
      deliver: (claim, attribution, payload) => {
        if (!bound() || !this.deliver) return Promise.resolve(EMPTY);
        const answer = this.deliver(claim, attribution, payload);
        if (!answer) return Promise.resolve(EMPTY);
        return answer.then((bytes) => bytes ?? EMPTY, () => EMPTY);
      },
    };
  }

  // ── channels ────────────────────────────────────────────────────────────────

  /** Mint a link id for a channel and wire its events into the transport. The callbacks fire
   *  on later turns, which is what lets a channel be registered from inside an op.
   *
   *  Returns 0 — never a live id — when the driver already holds `maxRawLinks`, having CLOSED
   *  the channel it refused: registration is what takes ownership of a socket, so a refusal
   *  that left it open would strand a descriptor. */
  private register(channel: RawLink): number {
    if (this.channels.size >= (this.opts.maxRawLinks ?? DEFAULT_MAX_RAW_LINKS)) {
      try { channel.close(false); } catch { /* already gone */ }
      return 0;
    }
    const linkId = this.nextLinkId++;
    this.channels.set(linkId, channel);
    // Inbound bytes are a plain event now — the request the occupant decoded off this
    // read rides its own `link/deliver` call, not a return here.
    channel.onData((bytes) => {
      if (this.channels.get(linkId) === channel) this.tell(ev("linkBytes").u32(linkId).blob(bytes));
    });
    channel.onClose(() => this.channelClosed(linkId, channel));
    return linkId;
  }

  /** One raw channel became unusable: drop it from the table, tell the guest, and report
   *  the reason it answers with. That one byte is the whole of what the occupant tells the
   *  host about a link, and the only thing here that could not be worked out from the
   *  socket: a descriptor closing looks identical whether it carried a farewell, a
   *  defensive teardown or a cut stream. The event names the link, so the return carries
   *  no link id and cannot be redirected at another socket; a malformed or absent answer
   *  reads as `0` rather than guessing. */
  private channelClosed(linkId: number, channel: RawLink): void {
    if (this.channels.get(linkId) !== channel) return;
    this.channels.delete(linkId);
    const report = (reason: number) => {
      try { this.opts.onLinkClosed?.(linkId, reason); }
      catch { /* a platform callback cannot corrupt this driver's link table */ }
    };
    const r = this.toTransport(ev("linkClosed").u32(linkId));
    if (!r) { report(0); return; }
    void r.then(
      (ret) => report(ret.length === 1 ? ret[0] : 0),
      (err: unknown) => {
        report(0);
        if (String((err as Error)?.message ?? err).includes("realm disposed")) return;
        console.error(`[transport] error in linkClosed: ${String(err)}`);
      },
    );
  }

  /** Tell the transport about a link the HOST hands over: an accepted socket, or one a
   *  factory dialed on its own initiative (WebRTC). A link the guest opened itself through
   *  `link/open` is not here.
   *
   *  Contact policy remains in guest config (§12.6.3). */
  private announce(linkId: number, channel: RawLink, arrival?: Arrival): void {
    this.tell(ev("linkOpen")
      .u32(linkId)
      .u8(arrival?.weDialed ? 1 : 0)
      .u8(channel.stream ? 1 : 0)
      .text(arrival?.listener ?? "")
      .blob(arrival?.expectPeerId ? fromHex(arrival.expectPeerId) : EMPTY)
      .text(channel.remoteAddr ?? ""));
  }

  // ── listening ───────────────────────────────────────────────────────────────

  /** Bind the listeners (if any) through the channel factory. */
  async start(): Promise<void> {
    if (!this.opts.channels) return;
    const { port, wsPort } = await this.opts.channels.listen(
      this.opts.listen, this.opts.wsListen,
      (channel, arrival) => {
        if (!this.available()) {
          try { channel.close(false); } catch { /* already gone */ }
          return;
        }
        const linkId = this.register(channel);
        // Dropped at the door, and the occupant never hears of it: the half-open tiers are
        // policy ABOVE this table, so a connection the driver could not hold is not a link
        // to have an opinion about. Silent like every other pre-authentication refusal.
        if (linkId === 0) return;
        this.announce(linkId, channel, arrival);
      },
    );
    this.port = port;
    this.wsPort = wsPort;
  }

  // ── lifecycle ───────────────────────────────────────────────────────────────

  /** Tear the driver down. Everything released here is the HOST's — the sockets and the
   *  listener — and none of it goes through the occupant: the host owns the descriptor for
   *  the life of the process (§1), so a teardown needing the occupant's cooperation would
   *  be one a wedged occupant could refuse. */
  close(): void {
    if (this.closed) return;
    // First, so nothing below re-enters a realm the caller is about to dispose: the
    // channel closes fire `onClose`, which would otherwise queue a `linkClosed`.
    this.closed = true;
    this.call = null;
    this.reset();
    this.opts.channels?.close();
  }
}
