// transport-host.ts — the SOCKET DRIVER, and nothing above it.
//
// The wire codec, the channel handshake, the authenticated link router, the routing-core
// bookkeeping, the request/response layer, the correlation table and the peer set all run
// as the transport bundle's zero-authority guest program (§12.6). This file is what stands
// between that guest and the platform's sockets: a link table, an address book, the
// listeners, and the links a host-managed transport hands over. That is the whole of it.
//
// There is no transport-shaped seam here, in either direction:
//
//   guest → host  the four `link/*` names (guest-seam.ts) — a byte duplex behind an opaque
//                 link id. Deadlines are not among them: `timer/*` is an ordinary
//                 authority, so a fired timer comes out of the shell's per-realm table.
//   host → guest  the SAME cross-realm call an app makes. The transport claims `_net` and
//                 this driver reaches it through the shell's routing, with the caller id
//                 32 zero bytes for "the host itself".
//
// The op name travels in the payload as a length-prefixed NAME, so an op the guest does
// not implement fails loud rather than turning into a number the two sides must agree on.
//
// One invariant makes the arrangement safe: no call re-enters a live frame. The transport
// calls out from inside its `handle`, and nothing calls straight back in — a socket write
// does not deliver during the write, an armed timer fires later, and a cross-realm call
// runs its callee on a later turn by construction. The transport's own answers ride
// `defer()` for the same reason (realm-queue.ts).
//
// The crypto the guest reaches is the seam's opaque primitive catalog, and the transcript
// signature is the ordinary `node/sign`, which the seam scopes to
// `DOMAIN_channel ‖ networkKey`. The host prefixes and never reads the suffix, so no
// handshake shape is pinned into the core and the node's key never enters the guest.

import { toHex, fromHex, writeU32BE, enc } from "../core/util.js";
import { MAX_FRAME_BYTES, MAX_HANDSHAKE_FRAME_BYTES } from "../core/net-limits.js";
import { FRAMING, type ChannelFactory, type Framing, type PeerAddr, type PeerId, type RawLink } from "../core/socket-seam.js";
import { opHeader, type RawNet } from "./guest-seam.js";

/** Kinds of link, as the `linkOpen` op declares them: CORE is the routing core's own
 *  (accepted through the channel factory, dial bookkeeping and the half-open limiter
 *  apply); OPEN is a host-managed transport — WebRTC, browser WS — that opened the
 *  socket itself and handed it over through `openLink()`. */
const LINK_CORE = 0;
const LINK_OPEN = 1;

// The link close-reason codes are the occupant's vocabulary (transport/src/ake.js
// `REASON_*`); the host relays the number and never interprets it.

const EMPTY = new Uint8Array(0);

/** No address book entry, or no channel factory at all. Link id 0 is never live, so
 *  the framing is moot — the guest reads the id first and stops. */
const NO_ROUTE = { linkId: 0, framing: FRAMING.PLATFORM, authority: "" } as const;
const ZERO32 = new Uint8Array(32);

/** Default half-open budgets, shipped to the transport guest at init and enforced
 *  there. Tests shrink them via TransportHostOptions. */
export const DEFAULT_MAX_HALF_OPEN_UNVERIFIED = 1024;
export const DEFAULT_MAX_HALF_OPEN_PER_SOURCE = 8;
export const DEFAULT_MAX_HALF_OPEN_VERIFIED = 256;
/** ...and the budget past the door: how many links a node holds AUTHENTICATED at once.
 *  Without it, anybody who can complete a handshake can open links without limit, each
 *  holding a framer, session keys, timers and buffers. Same size as the verified tier — a
 *  link that has proved an identity is not entitled to more than one still proving one. */
export const DEFAULT_MAX_AUTHED_LINKS = 256;

/** How long one request may take when its caller names no deadline (§12.6). Generous on
 *  purpose: it has to be right for a caller who did not think about it. Shipped to the
 *  guest at init, since the request path is entirely the guest's. */
export const DEFAULT_REQUEST_DEADLINE_MS = 10_000;

/** How long an AUTHENTICATED link may carry no traffic before the guest retires it (the
 *  address book redials on the next send). The other half of the authed-link budget: a cap
 *  alone would let a peer fill it and sit there, since the handshake deadlines stop
 *  applying the moment a link authenticates. Generous, because it is not a liveness
 *  probe. */
export const DEFAULT_LINK_IDLE_TIMEOUT_MS = 300_000;

/** `[caller 32][nameLen u8][name utf8]` for one op, memoized. The LAYOUT is the seam's
 *  (`opHeader`); what this adds is the memo, because the op set is tiny and fixed while the
 *  header is rebuilt on the INBOUND FRAME PATH — once per socket read, per link. Shared
 *  safely because nothing mutates a header: `Args` only pushes it into a parts list that
 *  `build()` copies out of.
 *
 *  The leading 32 bytes stay zero: the caller id for "the host itself". */
const OP_HEADERS = new Map<string, Uint8Array>();
function hostOpHeader(op: string): Uint8Array {
  let h = OP_HEADERS.get(op);
  if (h === undefined) {
    h = opHeader(op);
    OP_HEADERS.set(op, h);
  }
  return h;
}

/** Op-argument encoder: `[fields …]` where a field is a u32 BE, a u8, or a
 *  length-prefixed blob, in the fixed order the op declares. The op's NAME is the
 *  discriminator and is encoded first, so nothing here is a number the two sides must
 *  agree on. The guest twin is `Reader` (transport/src/util.js); a field written and not
 *  read desyncs the payload rather than degrading quietly. */
class Args {
  /** The op this payload is for, or `""` for a nested list that is somebody's blob.
   *  Read back for diagnostics — a failed op reports by name (`tell`). */
  readonly op: string;
  private readonly parts: Uint8Array[] = [];
  private len = 0;
  /** Naming the op here rather than at the send is what lets `build()` emit the whole
   *  cross-realm call in one pass — otherwise every payload is copied a second time behind
   *  its header, which on `linkBytes` is a copy of the frame per socket read. */
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

/** How the driver reaches the transport: the shell's cross-realm call, already resolved to
 *  whatever realm claims `_net` right now. `null` when nothing does — a node whose
 *  transport bundle has been uninstalled, where a socket event has nowhere to go and
 *  the honest answer is to drop it. */
export type TransportCall = (payload: Uint8Array) => Promise<Uint8Array> | null;

export interface TransportHostOptions {
  /** The CHANNEL keypair — its public half is this node's peer id. Never passed
 *  to the guest; SIGN is serviced host-side with it, scoped by the privilege. */
  identity: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** OPTIONAL network key: which network this node belongs to (isolation
 *  boundary, not a gate — §12.6). Absent ⇒ the public network. */
  networkKey?: Uint8Array;
  /** OPTIONAL contact secret for THIS node — 32 bytes of full entropy, published
 *  with our address; the gate a caller must produce before msg1 opens. Absent ⇒
 *  an open node. Per node, never per deployment (§12.6.3). */
  contactSecret?: Uint8Array;
  /** How long ONE request may take before it settles as unreachable, in ms, for a
 *  caller that names no deadline of its own (default `DEFAULT_REQUEST_DEADLINE_MS`).
 *  A deployment-wide fallback, not a policy. */
  requestDeadlineMs?: number;
  /** Parallel connections per dialed peer (default 1). */
  connsPerPeer?: number;
  /** The host's inbound flood cap (default net-limits MAX_FRAME_BYTES), which the
 *  guest learns at init to size its own send budget — the module never declares
 *  the number that bounds it. */
  maxFrameBytes?: number;
  /** Concurrent half-open budgets, enforced in the transport guest. Defaults
  *  are 1024 unverified / 8 per source / 256 verified; tests shrink them. */
  maxHalfOpenUnverified?: number;
  maxHalfOpenPerSource?: number;
  maxHalfOpenVerified?: number;
  /** Concurrent AUTHENTICATED links, and how long one may sit idle before the guest
 *  retires it (ms; 0 disables the clock). The budget past the handshake — see
 *  `DEFAULT_MAX_AUTHED_LINKS`. */
  maxAuthedLinks?: number;
  linkIdleTimeoutMs?: number;
  /** The peers this node will talk to, as 32-byte channel keys. Shipped to the guest at
 *  init and applied there.
 *
 *  A LINT, not a gate: a host-side version would check a key the occupant supplied, so a
 *  hostile occupant simply supplies one that passes. What it catches is a buggy transport,
 *  or an honest one meeting a peer the operator did not list — the transport's own
 *  business, hence configuration. What holds against a hostile occupant is that it reaches
 *  no authority but `link/*`.
 *
 *  Absent ⇒ admit every peer that completes the handshake. */
  admitPeers?: Uint8Array[];
  /** The socket seam: dialing, listening, and the address book live here. Absent
 *  for a host-managed-transport-only node (browser edge), which opens links via
 *  openLink and whose link/open calls answer "no route". */
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
  /** Deliberate teardown: announces the end of the stream, then closes the
 *  channel. A failure path should close the CHANNEL instead (which reads as a
 *  truncation), not call this. */
  close(): void;
}

export interface OpenLinkOptions {
  channel: RawLink;
  /** true if we opened the connection (outbound dial), false if we accepted it. */
  weDialed: boolean;
  /** For an outbound dial, the peerId we expect to reach (hex) — the handshake
 *  is rejected if the far end presents a different key. */
  expectPeerId?: PeerId;
  /** THE PEER's contact secret for a dial (from the address), OURS on accept —
 *  absent on accept. Absent on a dial ⇒ the peer is open (zero secret). */
  contactSecret?: Uint8Array;
  /** Transport-supplied far-end identifier (an IP), for the half-open buckets. */
  source?: string;
  /** Override the half-open deadline (ms). Use only in tests; 0 and absent both mean
 *  "the bundle's own default". */
  handshakeTimeoutMs?: number;
  /** Frames per direction between key ratchets. A deployment-wide constant that
 *  both ends must share; settable only because the boundary is otherwise
 *  unreachable in a test (§12.6). */
  rekeyAfterFrames?: number;
  /** Fired once this link's identity verified AND the transport admitted it. */
  onAuth?: (peerId: PeerId) => void;
  /** Fired when the link tears down (any reason). */
  onClose?: (linkId: number, reason: number) => void;
}

/** The host side of the node's network: sockets, addresses, listeners.
 *
 *  Deliberately NOT here: any request/response facade, correlation table, peer set or
 *  dispatch sink — each of those was the host standing between two guests. An app's send is
 *  a call to `_net`, the transport's reply is that call's return value, and its wire
 *  correlation never leaves its heap. Nothing on this object is reached by an app.
 *
 *  There is no handover either: the driver holds link ids and the address book, both the
 *  NODE's rather than the current bundle's, so replacing a transport is just a later load
 *  winning a contested protocol id (shell-core `rebuildRoutes`). Live links cannot survive
 *  it — the session keys are in the outgoing guest's private memory (§4.3) — so an upgrade
 *  is a reconnect, and the incoming guest redials from this address book. */
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
  private closed = false;

  constructor(opts: TransportHostOptions) {
    this.opts = opts;
    this.peerId = toHex(opts.identity.publicKey);
  }

  /** Point the driver at the shell's routing and send the one config turn: who we are,
   *  which network, the budgets, the peer list. The guest learns the host's flood cap
   *  here — the module never declares the number that bounds it.
   *
   *  Called again whenever the claimant of `_net` changes, which is what an in-place
   *  transport replacement is: the incoming guest is configured exactly as the first one
   *  was, by the same call, because there is no second path for a replacement to take. */
  attach(transport: TransportCall): void {
    // A RE-attach means the previous occupant is gone, and its link state went with it
    // (§4.3). The sockets are still open and the far ends still believe in them, so they
    // are torn down here rather than left as channels the incoming guest never heard of;
    // it redials from the address book re-seeded below.
    if (this.transport) {
      for (const c of this.channels.values()) {
        try { c.close(false); } catch { /* already gone */ }
      }
      this.channels.clear();
      this.openLinks.clear();
    }
    this.transport = transport;
    const o = this.opts;
    const admit = new Args();
    for (const pk of o.admitPeers ?? []) admit.blob(pk);
    // Through the same `tell` as every other op: a rejected config turn is a transport
    // that failed to stand — logged, never a reason to take the host down.
    this.tell(new Args("init")
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
      // Absent and empty both mean "admit everyone", said as a zero-length list so the
      // guest reads one shape.
      .blob(admit.build()));
    // The incoming guest starts with an empty address book, so re-seed it. On a first
    // attach there is nothing to send; on a replacement this is what lets it redial.
    for (const [id, addr] of this.addrs) this.announceAddr(id, addr);
  }

  /** Whether `close` has run. Public because "the outgoing driver was actually shut
   *  down" is what a teardown has to be checkable on: a replaced driver that is merely
   *  dereferenced still holds its listener. */
  get isClosed(): boolean { return this.closed; }

  // ── reaching the transport ──────────────────────────────────────────────────

  /** Call the transport. The op name and the 32-byte caller id are already the head of
   *  `args`, so the payload the guest reads is exactly what `build()` returns. The occupant
   *  tells the platform's events from an app's requests by those 32 bytes and needs no
   *  second seam.
   *
   *  Not unordered: the realm serializes invocations in acceptance order (realm-queue.ts),
   *  so bytes arriving on one link reach the occupant in arrival order. */
  private toTransport(args: Args): Promise<Uint8Array> | null {
    if (this.closed || !this.transport) return null;
    return this.transport(args.build());
  }

  /** `toTransport` for an op whose answer nobody is waiting on. A rejection is logged and
   *  dropped, except a realm disposed out from under the op: that is this driver's own
   *  teardown or replacement, and reporting it would print an error per ordinary
   *  shutdown. */
  private tell(args: Args): void {
    const r = this.toTransport(args);
    if (r) void r.catch((err: unknown) => {
      if (String((err as Error)?.message ?? err).includes("realm disposed")) return;
      console.error(`[transport] error in ${args.op}: ${String(err)}`);
    });
  }

  /** `toTransport` for an op whose answer the caller needs. Throws when nothing claims
   *  `_net` — a node with no transport bundle, which is a legitimate configuration and
   *  so has to be an answer rather than a promise that never settles. */
  private ask(args: Args): Promise<Uint8Array> {
    const r = this.toTransport(args);
    if (!r) return Promise.reject(new Error("transport: no bundle claims the network"));
    return r;
  }

  // ── the capability backend the transport guest's seam is wired to ───────────

  /** The RAW net capability, as this node implements it: an opaque link id over the
   *  platform's sockets. This is the whole of what the host contributes to the network,
   *  and it is wired to no seam but the transport's. */
  rawNet(): RawNet {
    return {
      open: (dest) => {
        // The destination name is the peer's 32-byte channel key, resolved in the address
        // book. No entry, or no channel factory at all (a browser edge), is "no route",
        // which the caller treats as a fabric dropping a frame.
        if (!this.opts.channels) return NO_ROUTE;
        const addr = this.addrs.get(toHex(dest));
        if (!addr) return NO_ROUTE;
        const channel = this.opts.channels.connect(addr);
        return {
          linkId: this.register(channel), framing: channel.framing, authority: channel.authority ?? "",
        };
      },
      send: (linkId, bytes) => { this.channels.get(linkId)?.send(bytes); },
      close: (linkId, graceful) => {
        try { this.channels.get(linkId)?.close(graceful); } catch { /* already gone */ }
      },
      // A link that is gone, or a channel that cannot say, both read 0 — the safe answer:
      // the occupant's stall clock sees no progress and lets the deadline decide.
      buffered: (linkId) => {
        try { return this.channels.get(linkId)?.buffered?.() ?? 0; } catch { return 0; }
      },
    };
  }

  // ── what the shell hands back off `_host` ───────────────────────────────────

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

  /** Mint a link id for a channel and wire its events into the transport. The callbacks
   *  fire on later turns (a socket does not deliver during the write that provoked it),
   *  which is what lets a channel be registered from inside an op. */
  private register(channel: RawLink): number {
    const linkId = this.nextLinkId++;
    this.channels.set(linkId, channel);
    channel.onData((bytes) => {
      this.tell(new Args("linkBytes").u32(linkId).blob(bytes));
    });
    channel.onClose(() => {
      this.channels.delete(linkId);
      this.tell(new Args("linkClosed").u32(linkId));
    });
    return linkId;
  }

  /** Tell the transport about a link the HOST opened: an accepted socket, or one a
   *  host-managed transport handed over. A dialed core link is not here — the guest
   *  opens those itself through `link/open` and already knows everything about them. */
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

  /** Hand a host-owned channel to the transport (WebRTC / browser WS edges).
   *  The channel object stays the caller's; the link state machine runs in the
   *  guest, keyed by the returned link id. */
  openLink(opts: OpenLinkOptions): LinkHandle {
    const linkId = this.register(opts.channel);
    this.openLinks.set(linkId, { onAuth: opts.onAuth, onClose: opts.onClose });
    this.announce(linkId, {
      weDialed: opts.weDialed,
      kind: LINK_OPEN,
      framing: opts.channel.framing,
      authority: opts.channel.authority,
      expectPeerId: opts.expectPeerId ? fromHex(opts.expectPeerId) : undefined,
      // A dial gates on THE PEER's secret (from the address); an open peer is the
      // zero secret, said explicitly. An accept gates on ours (guest init).
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

  /** The guest's dial needs the peer's contact secret (or the zero secret for an open
   *  peer) to build msg1; the host keeps the full address, which is what `link/open`
   *  resolves the peer key against. */
  private announceAddr(peerId: PeerId, addr: PeerAddr): void {
    this.tell(new Args("addr")
      .blob(fromHex(peerId))
      .blob(addr.contactSecret ?? ZERO32));
  }

  /** Bind the listeners (if any) through the channel factory. */
  async start(): Promise<void> {
    if (!this.opts.channels) return;
    const { port, wsPort } = await this.opts.channels.listen(
      this.opts.listen, this.opts.wsListen,
      (channel) => {
        const linkId = this.register(channel);
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
    for (const c of this.channels.values()) {
      try { c.close(false); } catch { /* already gone */ }
    }
    this.channels.clear();
    this.openLinks.clear();
    this.opts.channels?.close();
  }
}
