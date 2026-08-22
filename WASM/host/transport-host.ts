// transport-host.ts — the socket driver: a link table, an address book, the listeners, and
// the links a host-managed transport hands over. Everything above it — the wire codec, the
// handshake, the link router, the request/response layer — runs as the transport bundle's
// zero-authority guest program (§12.6), reached through the `link/*` names.
//
// One invariant makes the arrangement safe: no call re-enters a live frame. A socket write
// does not deliver during the write, an armed timer fires later, and a cross-realm call runs
// its callee on a later turn; the transport's own answers ride `defer()` (realm-queue.ts).

import { toHex, fromHex, writeU32BE, enc } from "../core/util.js";
import { MAX_FRAME_BYTES, MAX_HANDSHAKE_FRAME_BYTES } from "../core/net-limits.js";
import { FRAMING, type ChannelFactory, type Framing, type PeerAddr, type PeerId, type RawLink } from "../core/socket-seam.js";
import { opHeader, type RawNet } from "./guest-seam.js";

/** Link kinds, as `linkOpen` declares them: CORE is the routing core's own (accepted through
 *  the channel factory, so dial bookkeeping and the half-open limiter apply); OPEN is a
 *  host-managed transport — WebRTC, browser WS — that opened the socket itself. */
const LINK_CORE = 0;
const LINK_OPEN = 1;

// The link close-reason codes are the occupant's vocabulary (transport/src/ake.js
// `REASON_*`); the host relays the number and never interprets it.

const EMPTY = new Uint8Array(0);

/** No address book entry, or no channel factory at all. Link id 0 is never live, so the
 *  framing is moot — the guest reads the id first and stops. */
const NO_ROUTE = { linkId: 0, framing: FRAMING.PLATFORM, authority: "" } as const;
const ZERO32 = new Uint8Array(32);

/** Default half-open budgets, shipped to the transport guest at init and enforced there
 *  (§12.6.2). Tests shrink them via TransportHostOptions. */
export const DEFAULT_MAX_HALF_OPEN_UNVERIFIED = 1024;
export const DEFAULT_MAX_HALF_OPEN_PER_SOURCE = 8;
export const DEFAULT_MAX_HALF_OPEN_VERIFIED = 256;
/** ...and the budget past the door: without it anybody who can complete a handshake opens
 *  links without limit, each holding a framer, session keys, timers and buffers. */
export const DEFAULT_MAX_AUTHED_LINKS = 256;

/** ...and the ceiling on what the DRIVER holds, underneath all of them.
 *
 *  The budgets above are content policy: "half-open", "verified" and "authenticated" are
 *  states only the occupant can see, so the occupant enforces them. What this file owns is
 *  cruder and comes first — a socket costs a descriptor and a link-table entry the moment it
 *  is accepted, before the guest has formed any opinion about it — and a limit protecting a
 *  resource is declared by whoever owns the resource (core/net-limits.ts).
 *
 *  Comfortably above the sum of the tiers, because it is not their backstop in the ordinary
 *  case: an honest occupant refuses or evicts long before this, and a wedged or hostile one
 *  meets this instead of the host's memory. */
export const DEFAULT_MAX_RAW_LINKS = 4096;

/** How long one request may take when its caller names no deadline. Generous on purpose: it
 *  has to be right for a caller who did not think about it. Shipped to the guest at init,
 *  since the request path is entirely the guest's. */
export const DEFAULT_REQUEST_DEADLINE_MS = 10_000;

/** How long an AUTHENTICATED link may carry no traffic before the guest retires it (the
 *  address book redials on the next send). The other half of the authed-link budget: the
 *  handshake deadlines stop applying the moment a link authenticates, so a cap alone would
 *  let a peer fill it and sit there. Generous — it is not a liveness probe. */
export const DEFAULT_LINK_IDLE_TIMEOUT_MS = 300_000;

/** `[caller 32][nameLen u8][name utf8]` for one op, memoized: the layout is the seam's
 *  (`opHeader`), but the header is rebuilt on the inbound frame path, once per socket read
 *  per link. Sharing is safe because nothing mutates a header — `Args` only pushes it into a
 *  parts list that `build()` copies out of. The leading 32 bytes stay zero: "the host". */
const OP_HEADERS = new Map<string, Uint8Array>();
function hostOpHeader(op: string): Uint8Array {
  let h = OP_HEADERS.get(op);
  if (h === undefined) {
    h = opHeader(op);
    OP_HEADERS.set(op, h);
  }
  return h;
}

/** Op-argument encoder: the op NAME first as the discriminator, then u32 BE / u8 /
 *  length-prefixed blob fields in the order the op declares. The guest twin is `Reader`
 *  (transport/src/util.js); a field written and not read desyncs the payload rather than
 *  degrading quietly. */
class Args {
  /** The op this payload is for, or `""` for a nested blob. Read back by `tell`. */
  readonly op: string;
  private readonly parts: Uint8Array[] = [];
  private len = 0;
  /** Naming the op here rather than at the send lets `build()` emit the whole cross-realm
   *  call in one pass; otherwise every payload is copied again behind its header, which on
   *  `linkBytes` is a copy of the frame per socket read. */
  constructor(op = "") {
    this.op = op;
    if (op !== "") this.raw(hostOpHeader(op));
  }
  u8(v: number): this {
    const b = new Uint8Array(1);
    b[0] = v;
    return this.raw(b);
  }
  u32(v: number): this {
    const b = new Uint8Array(4);
    writeU32BE(b, 0, v);
    return this.raw(b);
  }
  blob(b: Uint8Array): this {
    const h = new Uint8Array(4);
    writeU32BE(h, 0, b.length);
    return this.raw(h).raw(b);
  }
  private raw(b: Uint8Array): this { this.parts.push(b); this.len += b.length; return this; }
  build(): Uint8Array {
    const out = new Uint8Array(this.len);
    let off = 0;
    for (const p of this.parts) { out.set(p, off); off += p.length; }
    return out;
  }
}

/** How the driver reaches the owner of this platform binding. `null` when nothing does — a
 *  node whose transport bundle has been uninstalled, where a socket event has nowhere to
 *  go and the honest answer is to drop it. */
export type TransportCall = (payload: Uint8Array) => Promise<Uint8Array> | null;

export interface TransportHostOptions {
  /** The channel keypair; its public half is this node's peer id. Never passed to the
 *  guest — signing is serviced host-side, scoped by the privilege (§12.6.2b). */
  identity: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** Which network this node belongs to. Absent ⇒ the public network (§12.6.3). */
  networkKey?: Uint8Array;
  /** This node's contact secret, 32 bytes of full entropy, published with our address.
 *  Absent ⇒ an open node (§12.6.3). */
  contactSecret?: Uint8Array;
  /** Fallback request deadline in ms for a caller that names none
 *  (default `DEFAULT_REQUEST_DEADLINE_MS`). */
  requestDeadlineMs?: number;
  /** Parallel connections per dialed peer (default 1). */
  connsPerPeer?: number;
  /** The host's inbound flood cap (default net-limits MAX_FRAME_BYTES), which the guest
 *  learns at init — the module never declares the number that bounds it. */
  maxFrameBytes?: number;
  /** Concurrent half-open budgets, enforced in the transport guest; tests shrink them. */
  maxHalfOpenUnverified?: number;
  maxHalfOpenPerSource?: number;
  maxHalfOpenVerified?: number;
  /** Concurrent AUTHENTICATED links, and how long one may sit idle before the guest
 *  retires it (ms; 0 disables the clock). */
  maxAuthedLinks?: number;
  linkIdleTimeoutMs?: number;
  /** Live raw links this driver will hold at once (default `DEFAULT_MAX_RAW_LINKS`).
 *  Unlike every budget above it, enforced HERE and never shipped to the guest: it bounds
 *  the host's own link table, not the occupant's link states. */
  maxRawLinks?: number;
  /** The peers this node will talk to, as 32-byte channel keys — a lint the guest applies,
 *  shipped to it at init. Absent ⇒ admit every peer that completes the handshake
 *  (§12.6.3). */
  admitPeers?: Uint8Array[];
  /** The socket seam: dialing, listening, and the address book live here. Absent for a
 *  host-managed-transport-only node (browser edge), which opens links via openLink and
 *  whose link/open calls answer "no route". */
  channels?: ChannelFactory;
  listen?: { host: string; port: number };
  wsListen?: { host: string; port: number };
}

/** A link handle for a host-managed transport (WebRTC / browser WS): the socket
 *  is the caller's; the wire state machine runs in the transport guest. */
export interface LinkHandle {
  linkId: number;
  /** Queue/send a wire frame on this link (pre-auth it buffers). */
  send(frame: Uint8Array): void;
  /** Deliberate teardown: announces the end of the stream, then closes the channel. A
 *  failure path closes the CHANNEL instead, which reads as a truncation. */
  close(): void;
}

export interface OpenLinkOptions {
  channel: RawLink;
  /** true if we opened the connection (outbound dial), false if we accepted it. */
  weDialed: boolean;
  /** For an outbound dial, the peerId we expect to reach (hex) — the handshake is
 *  rejected if the far end presents a different key. */
  expectPeerId?: PeerId;
  /** THE PEER's contact secret for a dial (from the address); absent on accept, where
 *  the guest uses ours. Absent on a dial ⇒ the peer is open (zero secret). */
  contactSecret?: Uint8Array;
  /** Transport-supplied far-end identifier (an IP), for the half-open buckets. */
  source?: string;
  /** Override the half-open deadline (ms). Use only in tests; 0 and absent both mean
 *  "the bundle's own default". */
  handshakeTimeoutMs?: number;
  /** Frames per direction between key ratchets — a deployment-wide constant both ends must
 *  share; settable only because the boundary is otherwise unreachable in a test. */
  rekeyAfterFrames?: number;
  /** Fired once this link's identity verified AND the transport admitted it. */
  onAuth?: (peerId: PeerId) => void;
  /** Fired when the link tears down (any reason). */
  onClose?: (linkId: number, reason: number) => void;
}

/** The host side of the node's network: sockets, addresses, listeners. Nothing on this
 *  object is reached by an app.
 *
 *  There is no link handover across a transport update: the driver holds the link ids and
 *  the address book, both the NODE's rather than the bundle's, but live links cannot survive
 *  — the session keys are in the outgoing guest's private memory (§4.3) — so an upgrade is a
 *  reconnect from this address book. */
export class TransportHost {
  readonly peerId: PeerId;
  port = 0;
  wsPort = 0;

  private readonly opts: TransportHostOptions;
  private readonly channels = new Map<number, RawLink>;
  private readonly openLinks = new Map<number, { onAuth?: (peerId: PeerId) => void; onClose?: (linkId: number, reason: number) => void }>;
  private readonly addrs = new Map<PeerId, PeerAddr>;
  private nextLinkId = 1;
  private transport: TransportCall | null = null;
  private transportAvailable: () => boolean = () => false;
  private activeOwner: object | null = null;
  private closed = false;

  constructor(opts: TransportHostOptions) {
    this.opts = opts;
    this.peerId = toHex(opts.identity.publicKey);
  }

  /** Wire this platform binding once. Both callbacks resolve its capability owner
   *  dynamically, so claim changes never reconfigure this driver. */
  route(transport: TransportCall, available: () => boolean): void {
    this.transport = transport;
    this.transportAvailable = available;
  }

  /** Whether this platform binding currently has an admitted raw-link owner. */
  available(): boolean { return !this.closed && this.transportAvailable(); }

  /** Publish one slot's raw-link binding. A different binding is a handover: live links
   *  belonged to the old guest's private state and are closed before the new owner runs. */
  activate(owner: object): void {
    if (this.activeOwner === owner) return;
    if (this.activeOwner) this.reset();
    this.activeOwner = owner;
  }

  /** Release only the binding named by its owner token. */
  release(owner: object): void {
    if (this.activeOwner !== owner) return;
    this.activeOwner = null;
    this.reset();
  }

  /** Link configuration: a side-effect-free read of immutable node identity and deployment
   *  limits, so a candidate transport can initialize offside without disturbing the slot
   *  that currently owns this raw-link binding.
   *
   *  The mutable address book deliberately is not here: a one-shot snapshot goes stale
   *  between candidate construction and claim commit. It is replayed after publication
   *  through the same `addr` event later additions use (`replayAddresses`).
   *
   *  Its shape is versioned by the manifest's signed `guest.abi` and nothing else, so
   *  REMOVING or reordering a field here means bumping that (§12.4). Appending one does not:
   *  a guest that never reads the tail cannot notice it. */
  private configuration(): Uint8Array {
    const o = this.opts;
    const admit = new Args();
    for (const pk of o.admitPeers ?? []) admit.blob(pk);
    return new Args()
      .blob(o.identity.publicKey)
      .blob(o.networkKey ?? ZERO32)
      .blob(o.contactSecret ?? ZERO32)
      .u32(o.connsPerPeer ?? 1)
      .u32(o.maxHalfOpenUnverified ?? DEFAULT_MAX_HALF_OPEN_UNVERIFIED)
      .u32(o.maxHalfOpenPerSource ?? DEFAULT_MAX_HALF_OPEN_PER_SOURCE)
      .u32(o.maxHalfOpenVerified ?? DEFAULT_MAX_HALF_OPEN_VERIFIED)
      .u32(o.maxAuthedLinks ?? DEFAULT_MAX_AUTHED_LINKS)
      .u32(o.maxFrameBytes ?? MAX_FRAME_BYTES)
      .u32(MAX_HANDSHAKE_FRAME_BYTES)
      .u32(o.requestDeadlineMs ?? DEFAULT_REQUEST_DEADLINE_MS)
      .u32(o.linkIdleTimeoutMs ?? DEFAULT_LINK_IDLE_TIMEOUT_MS)
      .blob(admit.build())
      .build();
  }

  /** Release link state owned by a departing link-capable slot, retaining listeners and
   *  the address book for a replacement. */
  reset(): void {
    const channels = [...this.channels.values()];
    this.channels.clear();
    this.openLinks.clear();
    for (const c of channels) {
      try { c.close(false); } catch { /* already gone */ }
    }
  }

  /** Whether `close` has run. Public because a teardown has to be checkable: a replaced
   *  driver that is merely dereferenced still holds its listener. */
  get isClosed(): boolean { return this.closed; }

  // ── reaching the transport ──────────────────────────────────────────────────

  /** Call the transport. The op name and the 32-byte caller id are already the head of
   *  `args`, so the payload the guest reads is exactly what `build()` returns.
   *
   *  Not unordered: the realm serializes invocations in acceptance order (realm-queue.ts),
   *  so bytes arriving on one link reach the occupant in arrival order. */
  private toTransport(args: Args): Promise<Uint8Array> | null {
    if (this.closed || !this.transport) return null;
    return this.transport(args.build());
  }

  /** `toTransport` for an op whose answer nobody is waiting on. A rejection is logged,
   *  except a realm disposed out from under the op — this driver's own teardown or
   *  replacement, which would otherwise print an error per ordinary shutdown. */
  private tell(args: Args): void {
    const r = this.toTransport(args);
    if (r) void r.catch((err: unknown) => {
      if (String((err as Error)?.message ?? err).includes("realm disposed")) return;
      console.error(`[transport] error in ${args.op}: ${String(err)}`);
    });
  }

  /** `toTransport` for an op whose answer the caller needs. Throws when nothing claims the
   *  binding — a node with no transport bundle is a legitimate configuration, so it has to
   *  be an answer rather than a promise that never settles. */
  private ask(args: Args): Promise<Uint8Array> {
    const r = this.toTransport(args);
    if (!r) return Promise.reject(new Error("transport: no bundle owns the raw-link binding"));
    return r;
  }

  // ── the capability backend the transport guest's seam is wired to ───────────

  /** The RAW net capability: an opaque link id over the platform's sockets, and the whole
   *  of what the host contributes to the network. */
  rawNet(owner: object): RawNet {
    const ownsBinding = () => this.activeOwner === owner;
    return {
      config: () => this.configuration(),
      open: (dest) => {
        if (!ownsBinding()) return NO_ROUTE;
        // The destination is the peer's 32-byte channel key, resolved in the address book.
        // No entry, or no channel factory at all (a browser edge), is "no route", which the
        // caller treats as a fabric dropping a frame.
        if (!this.opts.channels) return NO_ROUTE;
        const addr = this.addrs.get(toHex(dest));
        if (!addr) return NO_ROUTE;
        const channel = this.opts.channels.connect(addr);
        // A full link table reads as "no route" too: the same answer for the same reason —
        // this driver cannot carry the frame.
        const linkId = this.register(channel);
        if (linkId === 0) return NO_ROUTE;
        return { linkId, framing: channel.framing, authority: channel.authority ?? "" };
      },
      send: (linkId, bytes) => { if (ownsBinding()) this.channels.get(linkId)?.send(bytes); },
      close: (linkId, graceful) => {
        if (!ownsBinding()) return;
        try { this.channels.get(linkId)?.close(graceful); } catch { /* already gone */ }
      },
      // A link that is gone, or a channel that cannot say, both read 0 — the safe answer:
      // the occupant's stall clock sees no progress and lets the deadline decide.
      buffered: (linkId) => {
        if (!ownsBinding()) return 0;
        try { return this.channels.get(linkId)?.buffered?.() ?? 0; } catch { return 0; }
      },
      authenticated: (linkId, peer) => { if (ownsBinding()) this.linkAuthed(linkId, peer); },
      down: (linkId, reason) => { if (ownsBinding()) this.linkDown(linkId, reason); },
    };
  }

  // ── reports returned through this raw-link binding ──────────────────────────

  /** A link this driver handed over (`openLink`) authenticated as `pk`. Relayed to
   *  whoever passed the channel in; the driver forms no opinion about the peer. */
  linkAuthed(linkId: number, pk: Uint8Array): void {
    this.openLinks.get(linkId)?.onAuth?.(toHex(pk));
  }

  /** A link this driver handed over tore down, with the occupant's reason code —
   *  relayed, never interpreted. */
  linkDown(linkId: number, reason: number): void {
    const o = this.openLinks.get(linkId);
    if (o) { this.openLinks.delete(linkId); o.onClose?.(linkId, reason); }
  }

  // ── channels ────────────────────────────────────────────────────────────────

  /** Mint a link id for a channel and wire its events into the transport. The callbacks fire
   *  on later turns, which is what lets a channel be registered from inside an op.
   *
   *  Returns 0 — never a live id — when the driver already holds `maxRawLinks`, having CLOSED
   *  the channel it refused: registration is what takes ownership of a socket, so a refusal
   *  that left it open would strand a descriptor. Every path that mints an id comes through
   *  here, so the ceiling covers a guest dial, an accept and a handover alike. */
  private register(channel: RawLink): number {
    if (this.channels.size >= (this.opts.maxRawLinks ?? DEFAULT_MAX_RAW_LINKS)) {
      try { channel.close(false); } catch { /* already gone */ }
      return 0;
    }
    const linkId = this.nextLinkId++;
    this.channels.set(linkId, channel);
    channel.onData((bytes) => {
      this.tell(new Args("linkBytes").u32(linkId).blob(bytes));
    });
    channel.onClose(() => {
      if (!this.channels.delete(linkId)) return;
      this.tell(new Args("linkClosed").u32(linkId));
    });
    return linkId;
  }

  /** Tell the transport about a link the HOST opened: an accepted socket, or one a
   *  host-managed transport handed over. A dialed core link is not here — the guest opens
   *  those itself through `link/open`. */
  private announce(
    linkId: number,
    spec: {
      weDialed: boolean; kind: number; framing: Framing; authority?: string; expectPeerId?: Uint8Array;
      dialSecret?: Uint8Array; source?: string; handshakeTimeoutMs?: number;
      rekeyAfterFrames?: number;
    },
  ): void {
    this.tell(new Args("linkOpen")
      .u32(linkId)
      .u8(spec.weDialed ? 1 : 0)
      .u8(spec.kind)
      .u8(spec.framing)
      .blob(enc.encode(spec.authority ?? ""))
      .u32(spec.handshakeTimeoutMs ?? 0)
      .u32(spec.rekeyAfterFrames ?? 0)
      .blob(spec.expectPeerId ?? EMPTY)
      .blob(spec.dialSecret ?? EMPTY)
      .blob(enc.encode(spec.source ?? "")));
  }

  /** Hand a host-owned channel to the transport (WebRTC / browser WS edges). The channel
   *  object stays the caller's; the link state machine runs in the guest, keyed by the
   *  returned link id. */
  openLink(opts: OpenLinkOptions): LinkHandle {
    if (!this.transportAvailable()) throw new Error("transport: no bundle owns the raw-link binding");
    const linkId = this.register(opts.channel);
    // The channel is already closed (`register`), so this throws rather than returning a
    // handle onto a dead socket: a host-managed transport can be told no, unlike an accept.
    if (linkId === 0) throw new Error(`transport: raw link table is full (${this.opts.maxRawLinks ?? DEFAULT_MAX_RAW_LINKS} links)`);
    this.openLinks.set(linkId, { onAuth: opts.onAuth, onClose: opts.onClose });
    this.announce(linkId, {
      weDialed: opts.weDialed,
      kind: LINK_OPEN,
      framing: opts.channel.framing,
      authority: opts.channel.authority,
      expectPeerId: opts.expectPeerId ? fromHex(opts.expectPeerId) : undefined,
      // A dial gates on THE PEER's secret (from the address), an open peer on the zero
      // secret said explicitly; an accept gates on ours (guest init).
      dialSecret: opts.weDialed ? (opts.contactSecret ?? ZERO32) : undefined,
      source: opts.source,
      handshakeTimeoutMs: opts.handshakeTimeoutMs,
      rekeyAfterFrames: opts.rekeyAfterFrames,
    });
    return {
      linkId,
      send: (frame) => this.tell(new Args("linkSend").u32(linkId).blob(frame)),
      close: () => { this.tell(new Args("linkClose").u32(linkId)); },
    };
  }

  // ── the address book, dialing, listening ────────────────────────────────────

  addPeerAddr(peerId: PeerId, addr: PeerAddr): void {
    this.addrs.set(peerId, addr);
    this.announceAddr(peerId, addr);
  }

  /** The guest's dial needs only the peer's contact secret (or the zero secret for an open
   *  peer) to build msg1; the host keeps the full address, which `link/open` resolves the
   *  peer key against. */
  private announceAddr(peerId: PeerId, addr: PeerAddr): void {
    this.tell(new Args("addr")
      .blob(fromHex(peerId))
      .blob(addr.contactSecret ?? ZERO32));
  }

  /** Seed the current raw-link owner from the node-owned address book. Called only after
   *  a new claimant is published; later mutations use `addPeerAddr`'s identical event.
   *  Queueing is synchronous, so a following `ready`/request cannot overtake the replay. */
  replayAddresses(): void {
    for (const [peerId, addr] of this.addrs) this.announceAddr(peerId, addr);
  }

  /** Bind the listeners (if any) through the channel factory. */
  async start(): Promise<void> {
    if (!this.opts.channels) return;
    const { port, wsPort } = await this.opts.channels.listen(
      this.opts.listen, this.opts.wsListen,
      (channel) => {
        if (!this.transportAvailable()) {
          try { channel.close(false); } catch { /* already gone */ }
          return;
        }
        const linkId = this.register(channel);
        // Dropped at the door, and the occupant never hears of it: the half-open tiers are
        // policy ABOVE this table, so a connection the driver could not hold is not a link
        // to have an opinion about. Silent like every other pre-authentication refusal — a
        // log line per connection would itself be the flood.
        if (linkId === 0) return;
        this.announce(linkId, {
          weDialed: false, kind: LINK_CORE, framing: channel.framing, source: channel.remoteAddr,
        });
      },
    );
    this.port = port;
    this.wsPort = wsPort;
  }

  /** Dial every known peer address and resolve once each is authenticated (or the guest's
   *  deadline passes). Both the dialing and the waiting are the guest's: the answer is this
   *  op's return value, handed back with `defer()` when the last peer comes up, so nothing
   *  is held host-side. */
  async ready(timeoutMs = 5000): Promise<void> {
    await this.ask(new Args("ready").u32(timeoutMs));
  }

  /** The peers we currently hold at least one authenticated link to. The set lives in
   *  the guest — it is a fact about links, and links are the guest's — so this is a
   *  question rather than a field. */
  async linkedPeers(): Promise<PeerId[]> {
    const bytes = await this.ask(new Args("peers"));
    const out: PeerId[] = [];
    for (let off = 0; off + 32 <= bytes.length; off += 32) out.push(toHex(bytes.slice(off, off + 32)));
    return out;
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
    this.transport = null;
    this.transportAvailable = () => false;
    this.activeOwner = null;
    this.reset();
    this.opts.channels?.close();
  }
}
