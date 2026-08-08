// transport-host.ts — the host side of the transport bundle
// (§12.6). The wire codec, the channel handshake, the authenticated
// link router, the routing-core bookkeeping and the request/response layer run as
// the transport bundle's zero-authority guest program; this file is the driver
// that stands between that guest and the platform.
//
// **There is no second seam here.** Both directions use the mechanism that already
// exists, rather than a bespoke byte ABI with a hand-maintained twin in the guest:
//
//   guest → host ordinary `host.call` ops (guest-seam.ts). The RAW net capability
//                  — `link/open, send, close, stat` over an opaque link id — plus
//                  `TIMER_*` for deadlines and the `transport` domain the slot
//                  reports its structured output through. Adding one is an op, not
//                  an action id with a decoder on both sides.
//   host → guest ordinary entrypoint invocation (`realm.call(name, bytes)`),
//                  exactly as an app's holder `handle` is invoked. A payload shape
//                  per entrypoint rather than one tagged union, so there is no
//                  unknown-tag case to desync on: an entrypoint this guest does not
//                  register fails loud by name.
//
// **One invariant makes that safe: no name re-enters the realm.** The occupant calls
// out from inside a synchronous entrypoint, so a name that called straight back in
// would re-enter a live guest frame. None does — a socket write does not deliver
// during the write, an armed timer fires on a later turn, and `transport/deliver`
// answers through the `respond` entrypoint rather than inline. That last one is not a
// concession: it is also what keeps an asynchronous app handler possible.
//
// The crypto surface the guest reaches is the seam's, and it names no algorithm
// the host understands: the record layer and the ephemeral DH go
// through `host.call("crypto/<name>", bytes)` over the opaque primitive catalog, and
// the transcript signature is the ordinary node/sign name, which the seam scopes to
// `DOMAIN_channel ‖ networkKey` because THIS bundle claims the transport slot. The
// host prefixes and does not read the suffix, so no handshake shape is pinned into
// the core and the node's key never enters the guest.
//
// What the host holds: the channels (by the link id this file mints), the timers, the
// promises of outbound requests (keyed by the corr the host assigns), the address book
// for dialing, the flood caps (net-limits.ts — the module never declares the number
// that bounds it, it only learns it at init), and the WHITELIST GATE, which is applied
// to the attribution the guest reports rather than handed to the guest to apply to
// itself (see `admits`).

import { toHex, fromHex, writeU32BE, errMessage, enc, dec } from "../core/util.js";
import { MAX_FRAME_BYTES, MAX_HANDSHAKE_FRAME_BYTES } from "../core/net-limits.js";
import { FRAMING, type ChannelFactory, type Framing, type PeerAddr, type RawLink } from "../core/socket-seam.js";
import type { RawNet, HostTimers, TransportSink } from "./guest-seam.js";
import type { SafeRealm } from "./safe-js.js";
import type { Network, PeerId, RequestHandler , Endpoint } from "../core/net.js";

/** 32-byte lowercase hex. A manual scan rather than a regex literal, so it stays safe
 *  under the minifier (scripts/minify.mjs), which has no lexer to tell a regex from a
 *  division. */
export function isHex64(s: string): boolean {
  if (s.length !== 64) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102))) return false; // 0-9 / a-f
  }
  return true;
}

/** The credential half of a peer spec — `pk[.secret]` — plus whatever followed the `@`.
 *
 *  `pk` names WHO lives there and keys the address book; the optional `.secret` is THAT
 *  PEER's contact secret, which is what makes an address a credential rather than merely
 *  a location. They do different jobs: the pk is routing, the secret is the gate our
 *  opening message must be sealed under.
 *
 *  **The grammar is written once.** Where a peer LIVES differs by transport — a
 *  `host:port` to dial, a whole `ws://` URL for the browser edge — but who they are does
 *  not. `location` comes back unparsed, so each caller reads its own address form out of
 *  it and nothing else is duplicated.
 *
 *  Host code, with the driver that consumes what it produces: every check here is a
 *  syntax check, so nothing about admission or trust would change if a target hand-rolled
 *  its own parser and never called this. */
export function parsePeerRef(spec: string): { peerId: PeerId; contactSecret?: Uint8Array; location: string } {
  const at = spec.indexOf("@");
  if (at < 0) throw new Error(`bad peer spec (want pk[.secret]@location): ${spec}`);
  const idPart = spec.slice(0, at).trim().toLowerCase();
  const dot = idPart.indexOf(".");
  const peerId = dot < 0 ? idPart : idPart.slice(0, dot);
  if (!isHex64(peerId)) throw new Error(`bad peer pubkey hex (want 32 bytes): ${spec}`);
  let contactSecret: Uint8Array | undefined;
  if (dot >= 0) {
    const hex = idPart.slice(dot + 1);
    if (!isHex64(hex)) throw new Error(`bad peer contact secret hex (want 32 bytes): ${spec}`);
    contactSecret = fromHex(hex);
  }
  return { peerId, contactSecret, location: spec.slice(at + 1).trim() };
}

/** Split a `host:port` address. The strict form (the default) is a peer dial
 *  address: an explicit host and a port in 1..65535. `defaultHost` fills an empty
 *  host (a bare `:port`), and `allowEphemeral` permits port 0 (ask the OS) — the
 *  two relaxations the operator's `--listen`/`--ws-listen` forms need. */
export function parseHostPort(s: string, opts: { defaultHost?: string; allowEphemeral?: boolean } = {}): { host: string; port: number } {
  const colon = s.lastIndexOf(":");
  if (colon < 0) throw new Error(`expected host:port, got ${s}`);
  const host = s.slice(0, colon) || (opts.defaultHost ?? "");
  const port = Number(s.slice(colon + 1));
  // Bounded, not merely positive: a port outside the 16-bit range names nothing, and
  // learning that at connect time makes a typo look like an unreachable peer.
  if (!Number.isInteger(port) || port < (opts.allowEphemeral ? 0 : 1) || port > 65535) throw new Error(`bad port in ${s}`);
  if (!host) throw new Error(`bad host in ${s}`);
  return { host, port };
}

/** Parse a `pk[.secret]@host:port` peer spec into the peer id + the address to dial:
 *  the socket-seam form (`PeerAddr`), for a target that opens its own TCP/WS sockets. */
export function parsePeerSpec(spec: string, transport: "tcp" | "ws"): { peerId: PeerId; addr: PeerAddr } {
  const { peerId, contactSecret, location } = parsePeerRef(spec);
  const { host, port } = parseHostPort(location);
  return { peerId, addr: { host, port, transport, contactSecret } };
}

/** Kinds of link, as `linkOpen` declares them: CORE is the routing core's own
 *  (accepted through the channel factory, dial bookkeeping and the half-open limiter
 *  apply); OPEN is a host-managed transport — WebRTC, browser WS — that opened the
 *  socket itself and handed it over through `openLink()`. */
const LINK_CORE = 0;
const LINK_OPEN = 1;

// The link close-reason codes are the transport occupant's vocabulary — the host
// only relays the number it reports through transport/link-down (guest-seam.ts) to
// whoever handed the channel in, never interpreting it. The codes live with the
// occupant (transport/src/ake.js, `REASON_*`) and with the tests that assert them
// (tests/transport-harness.mjs).

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

/** How long one request may take when its caller names no deadline (§12.6). Generous
 *  on purpose: it is the number that has to be right for a caller who did not think
 *  about it, which includes every app guest, since net/send carries no deadline of its
 *  own. A caller moving something large, or one that wants to fail fast, passes its own
 *  to `request` rather than moving this. */
export const DEFAULT_REQUEST_DEADLINE_MS = 10_000;

/** Concurrent deadlines the mounted transport may hold. One per half-open link plus one
 *  per in-flight request is the real demand, so this is headroom over both budgets
 *  rather than a tuning knob — it exists so a wedged occupant cannot grow the host's
 *  timer table without bound. */
const MAX_LIVE_TIMERS = 1 << 16;

/** Entrypoint-argument encoder: `[fields …]` where a field is a u32 BE, a u8, or a
 *  length-prefixed blob, in the fixed order the entrypoint declares. There is no tag
 *  byte — the entrypoint's NAME is the discriminator, and it is the realm's, not a
 *  number this file and the guest have to agree on. */
class Args {
  private readonly parts: Uint8Array[] = [];
  private len = 0;
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

export interface TransportHostOptions {
  /** The CHANNEL keypair — its public half is this node's peer id. Never passed
 *  to the guest; SIGN is serviced host-side with it, scoped by the slot. */
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
 *  A deployment-wide fallback, not a policy: a caller that knows what it is sending
 *  passes its own to `request` (§12.6). Small in tests. */
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
  /** Whitelist gate, called with a signature-verified peer key when a link
 *  authenticates and again on the cohort edge. Absent ⇒ admit all. */
  admitPeer?: (pk: Uint8Array) => boolean;
  /** Cohort edges (fired on a peer's FIRST authenticated link / LAST lost). */
  onPeerUp?: (peerId: PeerId) => void;
  onPeerDown?: (peerId: PeerId) => void;
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
  /** Fired once this link's identity verified AND the whitelist admitted it. */
  onAuth?: (peerId: PeerId) => void;
  /** Fired when the link tears down (any reason). */
  onClose?: (linkId: number, reason: number) => void;
}

/** The request/response face of the transport bundle — the shape shell-core's
 *  guest-seam wiring and the shell's `transport` field consume. */
export interface HostTransport {
  readonly peerId: PeerId;
  request(to: PeerId, proto: Uint8Array, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array>;
  send(to: PeerId, proto: Uint8Array, payload: Uint8Array): void;
  onRequest(handler: RequestHandler): void;
  close(): void;
}

/** What survives replacing the transport bundle underneath a running node — and,
 *  more importantly, the statement of what does NOT.
 *
 * **Live links cannot be handed over, and that is a property rather than a gap.**
 *  Session keys, direction counters and the link table live in the guest's own
 *  linear memory (§4.3), which is exactly what makes the occupant confineable: the
 *  host cannot read them out, by construction, and a seam that let it would be the
 *  hole the confinement exists to close. So an in-place upgrade is a **reconnect** —
 *  the outgoing driver closes its links, the incoming one redials from the address
 *  book. Peers see an ordinary disconnect, which the record layer's clean-close
 *  discipline already covers (§12.6).
 *
 *  What is here is therefore only the *host's* half: the things the shell configured
 *  from outside the guest and would otherwise silently lose. Everything in this
 *  object was set by a host-side call, and every one of them is re-applied by
 *  `adopt` through that same call.
 *
 *  The bound ports come along for a reason worth stating: a node that asked for port
 *  0 got an ephemeral one, and its peers hold *that* number in their address books.
 *  Re-binding the originally requested config would move the node during an upgrade,
 *  which is a disconnect nobody asked for. */
export interface TransportHandover {
  /** The address book — who this node knows how to dial, and with which contact
 *  secret. Not identities it has *met*: an authenticated peer whose address was
 *  never configured is not redialable and is not meant to be. */
  addrs: [PeerId, PeerAddr][];
  /** The shell's inbound dispatch sink (`serve`). */
  onRequest: RequestHandler | null;
  peerHooks: { onPeerUp?: (peerId: PeerId) => void; onPeerDown?: (peerId: PeerId) => void };
  /** Whether `start` had been called — an upgrade must not turn a node that was
 *  listening into one that is not, nor bind listeners on a node that never had any. */
  listening: boolean;
  port: number;
  wsPort: number;
}

/** The host-side face of the transport bundle. Implements the Network shape the shell
 *  and its guest seam consume (net.ts's PeerId, Endpoint, RequestHandler), so callers
 *  changed only in construction: the driver is built by the shell when the transport
 *  bundle is admitted, not by each target.
 *
 *  Constructed BEFORE the realm and attached to it after, because the realm's
 *  guest seam needs this object: the guest's raw-net, timer and transport ops resolve
 *  here. `attach` is what sends the one config turn.
 */
export class TransportHost implements Network, HostTransport {
  readonly peerId: PeerId;
  port = 0;
  wsPort = 0;
  /** Frames delivered to the app side — a diagnostic counter. */
  framesDelivered = 0;
  /** Frames issued into the fabric — a diagnostic counter. */
  framesSent = 0;

  private realm: SafeRealm | null = null;
  private readonly opts: TransportHostOptions;
  private readonly channels = new Map<number, RawLink>;
  private readonly openLinks = new Map<number, { onAuth?: (peerId: PeerId) => void; onClose?: (linkId: number, reason: number) => void }>;
  private readonly timers = new Map<number, ReturnType<typeof setTimeout>>;
  private readonly pending = new Map<number, { resolve: (b: Uint8Array) => void; reject: (e: Error) => void }>;
  private readonly addrs = new Map<PeerId, PeerAddr>;
  private readonly connected = new Set<PeerId>;
  private nextLinkId = 1;
  private nextCorr = 1;
  private reqHandler: RequestHandler | null = null;
  private readyWaiter: { promise: Promise<void>; resolve: () => void; timer: ReturnType<typeof setTimeout> } | null = null;
  private closed = false;
  private listening = false;

  constructor(opts: TransportHostOptions) {
    this.opts = opts;
    this.peerId = toHex(opts.identity.publicKey);
  }

  /** Bind the guest realm and send the one config turn: who we are, which network,
 *  the budgets. The guest learns the host's flood cap here — the module never
 *  declares the number that bounds it. */
  attach(realm: SafeRealm): void {
    this.realm = realm;
    const o = this.opts;
    this.enter("init", new Args()
      .blob(o.identity.publicKey)
      .blob(o.networkKey ?? ZERO32)
      .blob(o.contactSecret ?? ZERO32)
      .u32(o.connsPerPeer ?? 1)
      .u32(o.maxHalfOpenUnverified ?? DEFAULT_MAX_HALF_OPEN_UNVERIFIED)
      .u32(o.maxHalfOpenPerSource ?? DEFAULT_MAX_HALF_OPEN_PER_SOURCE)
      .u32(o.maxHalfOpenVerified ?? DEFAULT_MAX_HALF_OPEN_VERIFIED)
      .u32(o.maxFrameBytes ?? MAX_FRAME_BYTES)
      .u32(MAX_HANDSHAKE_FRAME_BYTES)
      .build());
  }

  setPeerHooks(hooks: { onPeerUp?: (peerId: PeerId) => void; onPeerDown?: (peerId: PeerId) => void }): void {
    this.opts.onPeerUp = hooks.onPeerUp;
    this.opts.onPeerDown = hooks.onPeerDown;
  }

  /** Whether `close` has run. Public because "the outgoing driver was actually shut
 *  down" is the thing an in-place upgrade has to be checkable on: a replaced driver
 *  that is merely dereferenced still holds its listener and its realm. */
  get isClosed(): boolean { return this.closed; }

  /** The host-side state to carry across an in-place transport upgrade — see
 *  `TransportHandover` for what is deliberately absent. Read before `close()`. */
  handover(): TransportHandover {
    return {
      addrs: [...this.addrs],
      onRequest: this.reqHandler,
      peerHooks: { onPeerUp: this.opts.onPeerUp, onPeerDown: this.opts.onPeerDown },
      listening: this.listening,
      port: this.port,
      wsPort: this.wsPort,
    };
  }

  /** Re-apply a predecessor's host-side state. Called after `attach`, because every
 *  step below is an ordinary host-side call and `addPeerAddr` enters the guest.
 *
 *  The outgoing driver must already be closed: `start()` binds the listeners, and
 *  the port it is re-binding is the one the predecessor was holding. */
  async adopt(s: TransportHandover): Promise<void> {
    if (s.onRequest) this.onRequest(s.onRequest);
    this.setPeerHooks(s.peerHooks);
    if (s.listening) {
      // Keep the node where its peers think it is (see TransportHandover). Mutating
      // opts is how setPeerHooks already works — these are the host's own knobs, not
      // anything the guest declared.
      if (s.port && this.opts.listen) this.opts.listen = { ...this.opts.listen, port: s.port };
      if (s.wsPort && this.opts.wsListen) this.opts.wsListen = { ...this.opts.wsListen, port: s.wsPort };
      await this.start();
    }
    // Last, so a peer that is dialed immediately meets a driver that is already
    // listening and already knows where to route what comes back.
    for (const [id, addr] of s.addrs) this.addPeerAddr(id, addr);
  }

  // ── entering the guest ──────────────────────────────────────────────────────

  /** Invoke a guest entrypoint. The occupant answers by calling ops back out through
 *  the guest seam, so there is nothing to decode here — the return value is unused,
 *  and an entrypoint that throws is a wedged transport whose links are moot, not a
 *  reason to take the host down.
 *
 *  Fire-and-forget, but not unordered: the realm serializes invocations in the order
 *  they were accepted (realm-queue.ts), so frames arriving on one link reach the occupant
 *  in arrival order and one entrypoint completes before the next begins. */
  private enter(entry: string, args: Uint8Array): void {
    if (this.closed || !this.realm) return;
    void this.realm.call(entry, args).catch((err: unknown) => {
      console.error("[transport] guest error in " + entry + ": " + errMessage(err));
    });
  }

  /** The peer whitelist. Absent ⇒ admit every peer that completes the handshake. */
  private admits(pk: Uint8Array): boolean {
    return this.opts.admitPeer ? this.opts.admitPeer(pk) : true;
  }

  // ── the capability backends the transport guest's seam is wired to ──────────

  /** The RAW net capability, as this node implements it: an opaque link id over the
 *  platform's sockets. This is the whole of what the host contributes to the
 *  network, and it is wired to no seam but the transport slot's. */
  rawNet(): RawNet {
    return {
      open: (dest) => {
        // The destination name is the peer's 32-byte channel key; the host resolves
        // it in the address book it was configured with. No address book entry, or
        // no channel factory at all (a browser edge), is "no route" — which the
        // caller treats exactly as a fabric dropping a frame.
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
      // A link that is gone, or a channel that cannot say, both read 0 — indistinguishable
      // from "nothing queued", which is the safe answer: the occupant's stall clock then
      // sees no progress and lets the deadline decide, exactly as before this existed.
      buffered: (linkId) => {
        try { return this.channels.get(linkId)?.buffered?.() ?? 0; } catch { return 0; }
      },
    };
  }

  /** The platform's event loop. A fired timer re-enters the guest on its own turn,
 *  which is what keeps the no-re-entrancy invariant true for `arm`.
 *
 *  The live-timer bound is HERE rather than in the seam, because this map is the
 *  memory being spent — a limit belongs to whoever owns the resource — and because
 *  the seam never learns that a timer fired, so a count kept there would only ever
 *  grow. */
  timerBackend(): HostTimers {
    return {
      arm: (id, ms) => {
        if (!this.timers.has(id) && this.timers.size >= MAX_LIVE_TIMERS) {
          throw new Error("transport: too many live timers (cap " + MAX_LIVE_TIMERS + ")");
        }
        this.clearTimer(id);
        this.timers.set(id, setTimeout(() => {
          this.timers.delete(id);
          this.enter("timer", new Args().u32(id).build());
        }, ms));
      },
      clear: (id) => this.clearTimer(id),
    };
  }

  /** Where the mounted transport reports its structured output. Everything policy-shaped
 *  is applied HERE, on what the guest reports, rather than handed to the guest. */
  sink(): TransportSink {
    return {
      deliver: (corr, noReply, from, proto, payload) => this.onDeliver(corr, noReply, from, proto, payload),
      settle: (corr, ok, payload) => {
        const p = this.pending.get(corr);
        if (!p) return;
        this.pending.delete(corr);
        if (ok) p.resolve(payload.slice());
        else p.reject(new Error(dec.decode(payload)));
      },
      linkAuth: (linkId, pk, conceal) => {
        // The peer whitelist, host-side. It runs on the attribution the transport
        // reports, which is the only place it cannot be skipped — a predicate handed to
        // the guest to apply to itself gates nothing against a hostile occupant of the
        // slot.
        //
        // A refusal does NOT close the channel when the guest asked us to conceal it.
        // The accepting end asks at msg3, before it has sent msg4, so closing here would
        // answer the one question the four-message ordering exists to leave unanswered:
        // whether the identity the caller dialed lives at this address. Silence, and the
        // guest's own handshake deadline, is the refusal (§12.6.2).
        //
        // Nothing is given up by not closing. Against a *hostile* occupant the close was
        // never the guarantee it looked like — an occupant that ignores this verdict can
        // equally decline to close any socket, and can forge `from` on delivery without a
        // link at all. What actually holds the refusal is that we never fire `onAuth` and
        // `peerEdge` re-checks `admits` before a peer enters `connected`, so a refused
        // peer reaches no cohort edge and no `linkedPeers()` regardless.
        if (!this.admits(pk)) {
          if (!conceal) {
            try { this.channels.get(linkId)?.close(false); } catch { /* already gone */ }
          }
          return false;
        }
        this.openLinks.get(linkId)?.onAuth?.(toHex(pk));
        return true;
      },
      peerEdge: (up, pk) => {
        const peer = toHex(pk);
        if (up) {
          if (!this.admits(pk)) return;
          this.connected.add(peer);
          this.opts.onPeerUp?.(peer);
        } else if (this.connected.delete(peer)) {
          // Only for a peer that was actually up: the down edge is the mirror of an
          // up edge that fired, not of every link that ever closed.
          this.opts.onPeerDown?.(peer);
        }
      },
      ready: (ok) => this.onReady(ok),
      linkDown: (linkId, reason) => {
        const o = this.openLinks.get(linkId);
        if (o) { this.openLinks.delete(linkId); o.onClose?.(linkId, reason); }
      },
    };
  }

  private clearTimer(id: number): void {
    const t = this.timers.get(id);
    if (t !== undefined) { clearTimeout(t); this.timers.delete(id); }
  }

  // ── channels ────────────────────────────────────────────────────────────────

  /** Mint a link id for a channel and wire its events back into the guest. The
 *  callbacks fire on later turns (a socket does not deliver during the write that
 *  provoked it), which is what lets a channel be registered from inside an op. */
  private register(channel: RawLink): number {
    const linkId = this.nextLinkId++;
    this.channels.set(linkId, channel);
    channel.onData((bytes) => {
      this.enter("linkBytes", new Args().u32(linkId).blob(bytes).build());
    });
    channel.onClose(() => {
      this.channels.delete(linkId);
      this.enter("linkClosed", new Args().u32(linkId).build());
    });
    return linkId;
  }

  /** Tell the guest about a link the HOST opened: an accepted socket, or one a
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
    this.enter("linkOpen", new Args()
      .u32(linkId)
      .u8(spec.weDialed ? 1 : 0)
      .u8(spec.kind)
      .u8(spec.framing)
      .blob(enc.encode(spec.authority ?? ""))
      .u32(spec.handshakeTimeoutMs ?? 0)
      .u32(spec.rekeyAfterFrames ?? 0)
      .blob(spec.expectPeerId ?? EMPTY)
      .blob(spec.dialSecret ?? EMPTY)
      .blob(enc.encode(spec.source ?? ""))
      .build());
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
      send: (frame) => this.enter("linkSend", new Args().u32(linkId).blob(frame).build()),
      close: () => { this.enter("linkClose", new Args().u32(linkId).build()); },
    };
  }

  // ── the routing core's host half: address book, dialing, listening ──────────

  addPeerAddr(peerId: PeerId, addr: PeerAddr): void {
    this.addrs.set(peerId, addr);
    // The guest's dial needs the peer's contact secret (or the zero secret for
    // an open peer) to build msg1; the host keeps the full address, which is what
    // link/open resolves the peer key against.
    this.enter("addr", new Args()
      .blob(fromHex(peerId))
      .blob(addr.contactSecret ?? ZERO32)
      .build());
  }

  /** Bind the listeners (if any) through the channel factory. */
  async start(): Promise<void> {
    this.listening = true;
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

  /** Dial every known peer address and resolve once each is authenticated (or
   *  the guest's deadline passes). The dialing itself is the guest's — it counts
   *  the shortfall to connsPerPeer and opens links through the raw capability.
   *
   *  Joining, not racing: a second `ready()` while one is in flight returns the
   *  SAME pending promise rather than overwriting the waiter, so both callers
   *  settle together. */
  ready(timeoutMs = 5000): Promise<void> {
    if (this.readyWaiter) return this.readyWaiter.promise;
    let resolve!: () => void;
    const promise = new Promise<void>((r) => { resolve = r; });
    this.readyWaiter = {
      promise,
      resolve,
      timer: setTimeout(() => { this.onReady(false); }, timeoutMs + 5000),
    };
    this.enter("ready", new Args().u32(timeoutMs).build());
    return promise;
  }

  private onReady(_ok: boolean): void {
    const w = this.readyWaiter;
    if (!w) return;
    this.readyWaiter = null;
    clearTimeout(w.timer);
    w.resolve();
  }

  /** The peers we currently hold at least one authenticated link to. */
  linkedPeers(): PeerId[] { return [...this.connected]; }

  // ── the request/response facade ─────────────────────────────────────────────

  /** Send a typed request and await the typed response. The deadline clock runs in the
 *  guest (host-armed timers); this side holds the promise the guest settles with
 *  transport/settle.
 *
 *  `deadlineMs` is how long THIS exchange may take, and the caller supplies it because
 *  the caller is the only party that knows what it sent: a 200-byte control message and
 *  a 4 MB block deserve different answers, and nothing below this line can tell them
 *  apart. Omitted ⇒ the node's `requestDeadlineMs` default. Resolved here rather than
 *  in the guest, so the default lives in exactly one place. */
  request(to: PeerId, proto: Uint8Array, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array> {
    const corr = this.nextCorr++;
    this.framesSent++;
    return new Promise<Uint8Array>((resolve, reject) => {
      this.pending.set(corr, { resolve, reject });
      this.enter("request", new Args()
        .u32(corr)
        .u8(0)
        .u32(deadlineMs ?? this.opts.requestDeadlineMs ?? DEFAULT_REQUEST_DEADLINE_MS)
        .blob(fromHex(to))
        .blob(proto)
        .blob(payload)
        .build());
    });
  }

  /** Fire-and-forget: the receiver still runs its handler but skips the response
 *  frame (§12.6). No promise, no timeout — the message just goes out. */
  send(to: PeerId, proto: Uint8Array, payload: Uint8Array): void {
    this.framesSent++;
    this.enter("request", new Args()
      .u32(0) // noReply requests carry no meaningful correlation
      .u8(1)
      .u32(0) // ...and no deadline: nothing is waiting on it
      .blob(fromHex(to))
      .blob(proto)
      .blob(payload)
      .build());
  }

  onRequest(handler: RequestHandler): void { this.reqHandler = handler; }

  /** An inbound request the guest attributed (transport/deliver): run the app-facing
 *  handler and hand its response back for framing.
 *
 *  The answer goes back through the `respond` entrypoint on a LATER turn, never as
 *  the call's return value, and that is deliberate twice over: it keeps the
 *  no-re-entrancy invariant (this runs inside the guest's own frame), and it is
 *  what lets `RequestHandler` return a Promise, which is the shape an app handler
 *  awaiting `fs` needs. */
  private onDeliver(corr: number, noReply: boolean, from: Uint8Array, proto: Uint8Array, payload: Uint8Array): void {
    this.framesDelivered++;
    const handler = this.reqHandler;
    const respond = (resp: Uint8Array | null): void => {
      this.enter("respond", new Args()
        .u32(corr)
        .u8(noReply ? 1 : 0)
        .blob(from)
        // The handler is app code, so anything that is not bytes is an empty
        // response rather than something to encode: a `length` read off a number or
        // an ArrayBuffer would size the argument buffer to NaN and take the driver
        // down over one badly-typed app.
        .blob(resp instanceof Uint8Array ? resp : EMPTY)
        .build());
    };
    const later = (resp: Uint8Array | null): void => { queueMicrotask(() => respond(resp)); };
    if (!handler) { later(null); return; }
    let r: Uint8Array | Promise<Uint8Array> | null;
    try { r = handler(toHex(from), dec.decode(proto), payload); }
    catch { r = null; }
    if (r && typeof (r as Promise<Uint8Array>).then === "function") {
      (r as Promise<Uint8Array>).then(respond, () => respond(null));
    } else {
      later(r as Uint8Array | null);
    }
  }

  // ── the Network facade ──────────────────────────────────────────────────────

  /** A single-identity fabric: it vends exactly one endpoint, its own. The send
 *  path routes through the guest's router; inbound content arrives through the
 *  transport sink (transport/deliver / transport/settle), never as raw frames — which is why
 *  `Endpoint` carries no `onFrame` sink. */
  endpoint(id: PeerId): Endpoint {
    if (id !== this.peerId) throw new Error("TransportHost is bound to one identity");
    return {
      send: (to: PeerId, frame: Uint8Array) => {
        this.framesSent++;
        this.enter("sendFrame", new Args().blob(fromHex(to)).blob(frame).build());
      },
      close: () => { this.close(); },
    };
  }

  // ── lifecycle ───────────────────────────────────────────────────────────────

  /** Tear the driver down. Everything released here is the **host's** — the sockets, the
 *  timers, the outbound promises — and **none of it goes through the occupant**. The host
 *  owns the descriptor for the life of the process (README §1), so a teardown that needed
 *  the occupant's cooperation to release one would be a teardown a wedged occupant could
 *  refuse; and an entrypoint invocation queues (§12.3) while the caller disposes the realm
 *  on return, so asking would not even be reliable. */
  close(): void {
    if (this.closed) return;
    // First, so nothing below re-enters a realm the caller is about to dispose: the
    // channel closes fire `onClose`, which would otherwise queue a `linkClosed`.
    this.closed = true;
    for (const p of this.pending.values()) p.reject(new Error("transport closed"));
    this.pending.clear();
    for (const t of this.timers.values()) clearTimeout(t);
    this.timers.clear();
    if (this.readyWaiter) { clearTimeout(this.readyWaiter.timer); this.readyWaiter.resolve(); this.readyWaiter = null; }
    for (const c of this.channels.values()) {
      try { c.close(false); } catch { /* already gone */ }
    }
    this.channels.clear();
    this.opts.channels?.close();
  }
}
