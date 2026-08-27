// Socket driver (§12.6): link table, address book, listeners. Wire codec/AKE/router
// run as the transport bundle's guest via `link/*`. No name here re-enters the CALLING
// realm: the one that enters a realm at all is `deliver`, and it enters the claimant's.


import { toHex, fromHex, writeU32BE, enc } from "../core/util.js";
import { DEFAULT_MAX_RAW_LINKS } from "../core/net-limits.js";
import { FRAMING, type ChannelFactory, type Framing, type PeerAddr, type PeerId, type RawLink } from "../core/socket-seam.js";
import { type JsonObject } from "./bundle.js";
import { type RawNet } from "./guest-seam.js";
import { writeOp } from "./op-frame.js";

/** Link kinds, as `linkOpen` declares them: CORE is the routing core's own (accepted through
 *  the channel factory, so dial bookkeeping and the half-open limiter apply); OPEN is a
 *  host-managed transport — WebRTC, browser WS — that opened the socket itself. */
const LINK_CORE = 0;
const LINK_OPEN = 1;

// The link close-reason codes are the occupant's vocabulary (transport/src/ake.js
// `REASON_*`); the host relays the number and never interprets it.

const EMPTY = new Uint8Array(0);

interface OpenLinkRecord {
  onAuth?: (peerId: PeerId) => void;
  onClose?: (linkId: number, reason: number) => void;
  authenticated: boolean;
}

/** No address book entry, or no channel factory at all. Link id 0 is never live, so the
 *  framing is moot — the guest reads the id first and stops. */
const NO_ROUTE = { linkId: 0, framing: FRAMING.PLATFORM, authority: "" } as const;
const ZERO32 = new Uint8Array(32);

/** Ceiling on what the DRIVER holds — a socket costs a descriptor the moment it
 *  is accepted, before the guest has an opinion. Occupant budgets sit above this. */
export { DEFAULT_MAX_RAW_LINKS } from "../core/net-limits.js";

// ── the driver's own event header ──────────────────────────────────────────────
//
// Every payload the driver hands the transport has a `[opLen u8][op]` head. That
// framing is the TRANSPORT BUNDLE's format (its own `readOp`, transport/src/util.js) —
// content paired with this driver like the wire codec — NOT a kernel ABI: the kernel's
// only obligation in front of it is the 32-byte caller id, added by the shell
// (shell-core.ts `hostCallSlot`). A field written here and not read there desyncs the
// payload, which is what forces the pair to move in one artifact.

/** `[opLen u8][op]` for one op, memoized: the header is rebuilt on the inbound frame path,
 *  once per socket read per link. Sharing is safe — nothing mutates a header. */
const OP_HEADERS = new Map<string, Uint8Array>();
function hostOpHeader(op: string): Uint8Array {
  let h = OP_HEADERS.get(op);
  if (h === undefined) {
    h = writeOp(op, EMPTY);
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

/** The claim routing a `link/deliver` call is handed to (§12.10). `null` for a claim no
 *  peer may reach. Inbound attributed delivery costs no grant beyond `link` itself: the
 *  occupant that saw the plaintext is the one that attributes it. */
export type TransportDeliver = (claim: string, attribution: Uint8Array, payload: Uint8Array) => Promise<Uint8Array> | null;

export interface TransportHostOptions {
  /** The channel keypair; its public half is this node's peer id. Never passed to the
 *  guest — signing is serviced host-side, scoped by the privilege (§12.6.2b). */
  identity: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** Which network this node belongs to. Absent ⇒ the public network (§12.6.3). */
  networkKey?: Uint8Array;
  /** This node's contact secret, 32 bytes of full entropy, published with our address.
 *  Absent ⇒ an open node (§12.6.3). */
  contactSecret?: Uint8Array;
  /** Live raw links this driver will hold at once (default `DEFAULT_MAX_RAW_LINKS`).
 *  Unlike every budget above it, enforced HERE and never shipped to the guest: it bounds
 *  the host's own link table, not the occupant's link states. */
  maxRawLinks?: number;
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
  /** THE PEER's contact secret for a dial (from the address); absent on a dial ⇒ the
   *  peer is open (zero secret). Absent on an accept: the driver seals the accept under
   *  ITS OWN current contact secret (§12.6.3), read at announce time — so a getter-backed
   *  value changes the gate with no transport reload — and the LOCAL facts are the fallback. */
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
 *  the address book, both the NODE's, but live links cannot survive — the session keys are
 *  in the outgoing guest's private memory (§4.3) — so an upgrade is a reconnect. */
export class TransportHost {
  readonly peerId: PeerId;
  port = 0;
  wsPort = 0;

  private readonly opts: Omit<TransportHostOptions, "identity" | "networkKey">;
  private readonly nodeFacts: Pick<TransportHostOptions, "identity" | "networkKey">;
  private readonly channels = new Map<number, RawLink>;
  private readonly openLinks = new Map<number, OpenLinkRecord>();
  private readonly addrs = new Map<PeerId, PeerAddr>;
  private nextLinkId = 1;
  private call: TransportCall | null = null;
  private deliver: TransportDeliver | null = null;
  private activeOwner: object | null = null;
  private closed = false;

  constructor(
    opts: Omit<TransportHostOptions, "identity" | "networkKey">,
    nodeFacts: Pick<TransportHostOptions, "identity" | "networkKey">,
  ) {
    this.opts = opts;
    this.nodeFacts = nodeFacts;
    this.peerId = toHex(nodeFacts.identity.publicKey);
  }

  /** Wire the claim routing behind `link/deliver` once. Not owner-keyed: an inbound frame
   *  resolves through the shell's claim table, whoever occupies the link (§12.10). */
  routeInbound(deliver: TransportDeliver): void { this.deliver = deliver; }

  /** Whether this platform binding currently has an admitted raw-link owner. */
  available(): boolean { return !this.closed && this.activeOwner !== null; }

  /** Publish one slot's raw-link binding, with the call this driver reaches it through. A
   *  different binding is a handover: live links belonged to the old guest's private state
   *  and are closed before the new owner runs. */
  activate(owner: object, call: TransportCall): void {
    if (this.activeOwner === owner) return;
    if (this.activeOwner) this.reset();
    this.activeOwner = owner;
    this.call = call;
  }

  /** Release only the binding named by its owner token. */
  release(owner: object): void {
    if (this.activeOwner !== owner) return;
    this.activeOwner = null;
    this.call = null;
    this.reset();
  }

  /** The immutable node facts folded into a link occupant's installation-local config.
   *  Binary values use the same hex spelling as peer references. The address book is not
   *  here: it is mutable node state, replayed after publication as `addr` events. */
  initialConfig(): JsonObject {
    const o = this.opts;
    const { identity, networkKey } = this.nodeFacts;
    return {
      peerId: toHex(identity.publicKey),
      networkKey: toHex(networkKey ?? ZERO32),
      contactSecret: toHex(o.contactSecret ?? ZERO32),
    };
  }

  /** Release link state owned by a departing link-capable slot, retaining listeners and
   *  the address book for a replacement. Also the platform's own "sever": closing every
   *  live socket without moving the binding — the occupant hears one `linkClosed` per
   *  link, and the node keeps its listeners and address book (both are the node's, not
   *  the occupant's). */
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

  /** Call the transport. `args.build()` is the bundle's own event framing; the shell
   *  prepends the host's caller id at the realm call (shell-core.ts `hostCallSlot`).
   *
   *  Not unordered: the realm serializes invocations in acceptance order (realm-queue.ts),
   *  so bytes arriving on one link reach the occupant in arrival order. */
  private toTransport(args: Args): Promise<Uint8Array> | null {
    if (this.closed || !this.call) return null;
    return this.call(args.build());
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

  /** Invoke `linkBytes` and consume its event-bound return: the 32-byte peer key when this
   *  read completed the handshake, and nothing at all otherwise. A request the occupant
   *  decoded off the same read does not ride here — it is handed over by its own
   *  `link/deliver` call — so this buffer holds one fact and needs no length framing to
   *  keep two apart. It contains no link id either: the driver binds the peer to this
   *  invocation's captured channel and owner. */
  private linkBytes(linkId: number, bytes: Uint8Array): void {
    const channel = this.channels.get(linkId);
    if (!channel) return;
    const owner = this.activeOwner;
    const open = this.openLinks.get(linkId);
    const r = this.toTransport(new Args("linkBytes").u32(linkId).blob(bytes));
    if (!r) return;
    void r.then((ret) => {
      if (ret.length === 0) return;
      if (ret.length !== 32) {
        console.error(`[transport] malformed linkBytes return (${ret.length} bytes)`);
        return;
      }
      // A close, reset or slot handover while the guest was awaiting makes this result
      // stale. Link ids are monotonic, but checking the captured object as well makes the
      // non-reuse assumption unnecessary to the authority boundary.
      if (this.activeOwner !== owner || this.channels.get(linkId) !== channel) return;
      // Authentication is meaningful only for a platform-owned openLink. A core link's
      // result cannot manufacture an openLink callback, and a duplicate cannot rename an
      // already-authenticated connection.
      if (!open || this.openLinks.get(linkId) !== open || open.authenticated) return;
      open.authenticated = true;
      try { open.onAuth?.(toHex(ret)); }
      catch { /* a platform callback cannot corrupt this driver's link table */ }
    }, (err: unknown) => {
      if (String((err as Error)?.message ?? err).includes("realm disposed")) return;
      console.error(`[transport] error in linkBytes: ${String(err)}`);
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
      send: (linkId, bytes) => {
        if (!ownsBinding()) return;
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
        if (!ownsBinding()) return;
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
        if (!ownsBinding()) return 0;
        try { return this.channels.get(linkId)?.buffered?.() ?? 0; } catch { return 0; }
      },
      // Inbound attributed delivery (§12.10): one request the occupant decoded, routed
      // through the shell's claim table and answered back to the occupant, which frames it
      // and writes it on the wire. Under the same binding check as every op above and no
      // further grant — the occupant names no link here, and it already chose all three of
      // these arguments. A claim no peer may reach and a handler that threw both answer
      // EMPTY, so refusal and silence are one fact at this boundary.
      deliver: (claim, attribution, payload) => {
        if (!ownsBinding() || !this.deliver) return Promise.resolve(EMPTY);
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
    channel.onData((bytes) => {
      if (this.channels.get(linkId) === channel) this.linkBytes(linkId, bytes);
    });
    channel.onClose(() => this.channelClosed(linkId, channel));
    return linkId;
  }

  /** One raw channel became unusable. The guest returns the close reason from this exact
   *  event; no return field can select a sibling link. A stale owner/record cannot fire a
   *  callback after handover. */
  private channelClosed(linkId: number, channel: RawLink): void {
    if (this.channels.get(linkId) !== channel) return;
    this.channels.delete(linkId);
    const owner = this.activeOwner;
    const open = this.openLinks.get(linkId);
    const finish = (reason: number) => {
      if (!open || this.activeOwner !== owner || this.openLinks.get(linkId) !== open) return;
      this.openLinks.delete(linkId);
      try { open.onClose?.(linkId, reason); }
      catch { /* the platform callback cannot retain a dead driver entry */ }
    };
    const r = this.toTransport(new Args("linkClosed").u32(linkId));
    if (!r) { finish(0); return; }
    void r.then(
      (ret) => finish(ret.length === 1 ? ret[0] : 0),
      (err: unknown) => {
        finish(0);
        if (String((err as Error)?.message ?? err).includes("realm disposed")) return;
        console.error(`[transport] error in linkClosed: ${String(err)}`);
      },
    );
  }

  /** Tell the transport about a link the HOST opened: an accepted socket, or one a
   *  host-managed transport handed over. A dialed core link is not here — the guest opens
   *  those itself through `link/open`. */
  private announce(
    linkId: number,
    spec: {
      weDialed: boolean; kind: number; framing: Framing; authority?: string; expectPeerId?: Uint8Array;
      linkSecret?: Uint8Array; source?: string; handshakeTimeoutMs?: number;
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
      .blob(spec.linkSecret ?? EMPTY)
      .blob(enc.encode(spec.source ?? "")));
  }

  /** Hand a host-owned channel to the transport (WebRTC / browser WS edges). The channel
   *  object stays the caller's; the link state machine runs in the guest, keyed by the
   *  returned link id. */
  openLink(opts: OpenLinkOptions): LinkHandle {
    if (!this.available()) throw new Error("transport: no bundle owns the raw-link binding");
    const linkId = this.register(opts.channel);
    // The channel is already closed (`register`), so this throws rather than returning a
    // handle onto a dead socket: a host-managed transport can be told no, unlike an accept.
    if (linkId === 0) throw new Error(`transport: raw link table is full (${this.opts.maxRawLinks ?? DEFAULT_MAX_RAW_LINKS} links)`);
    this.openLinks.set(linkId, { onAuth: opts.onAuth, onClose: opts.onClose, authenticated: false });
    this.announce(linkId, {
      weDialed: opts.weDialed,
      kind: LINK_OPEN,
      framing: opts.channel.framing,
      authority: opts.channel.authority,
      expectPeerId: opts.expectPeerId ? fromHex(opts.expectPeerId) : undefined,
      // The secret THIS link opens under: the peer's on a dial (an open peer = the zero
      // secret said explicitly); OURS on an accept, read NOW from the options, so a
      // getter-backed contact secret gates this node's accepting side with no transport
      // reload (§12.6.3). The guest falls back to its LOCAL facts if the field is empty.
      linkSecret: opts.weDialed ? (opts.contactSecret ?? ZERO32) : (this.opts.contactSecret ?? ZERO32),
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
        if (!this.available()) {
          try { channel.close(false); } catch { /* already gone */ }
          return;
        }
        const linkId = this.register(channel);
        // Dropped at the door, and the occupant never hears of it: the half-open tiers are
        // policy ABOVE this table, so a connection the driver could not hold is not a link
        // to have an opinion about. Silent like every other pre-authentication refusal.
        if (linkId === 0) return;
        this.announce(linkId, {
          weDialed: false, kind: LINK_CORE, framing: channel.framing, source: channel.remoteAddr,
          // An accept gates on OUR current secret, read at accept time, exactly like a
          // host-managed open — the node facts stay only the fallback, not the truth.
          linkSecret: this.opts.contactSecret ?? ZERO32,
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
    this.call = null;
    this.activeOwner = null;
    this.reset();
    this.opts.channels?.close();
  }
}
