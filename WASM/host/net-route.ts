// net-route.ts — the TCP + WebSocket-server transport of a real Network (README
// §12.6). It owns NO sockets directly: channel creation is injected as a
// ChannelFactory (net-node.ts supplies the node:net factory; the native Go/wazero
// loader supplies one over its __net primitive), so the wire behaviour Go and Bun
// nodes must agree on is the same code on every target. It holds only the
// transport's own bookkeeping — how a peer is reached (addrs), the links still
// completing their handshake (connecting/inbound), the connsPerPeer dial fan-out,
// readiness — and hands each PeerLink to the shared LinkRouter (link-router.ts) once
// it authenticates. The routing, striping, and double-connect rule live there.

import type { Network, Endpoint, PeerId } from "./net.js";
import { PeerLink, HalfOpenLimiter, type RawChannel, type Identity, type TransportCrypto } from "./net-link.js";
import { LinkRouter } from "./link-router.js";
import { toHex, fromHex } from "./util.js";

export interface PeerAddr {
  host: string;
  port: number;
  transport: "tcp" | "ws";
  /** OPTIONAL contact secret for the peer at this address — THEIRS, not ours. It is what
   *  makes an address a credential rather than merely a location: without it a dial to a
   *  gated peer draws no response at all. Omitted for an open peer. */
  contactSecret?: Uint8Array;
}

/** How the routing core opens sockets — the one platform seam. A target supplies
 *  TCP/WS dialing and listening behind the RawChannel shape; everything above is
 *  shared. */
export interface ChannelFactory {
  /** Dial a peer; returns a RawChannel that connects in the background. */
  connect(addr: PeerAddr): RawChannel;
  /** Bind the requested listeners, invoking onAccept(channel) for each inbound
   *  connection; resolves with the bound ports (0 where not listening). */
  listen(
    tcp: { host: string; port: number } | undefined,
    ws: { host: string; port: number } | undefined,
    onAccept: (channel: RawChannel) => void,
  ): Promise<{ port: number; wsPort: number }>;
  /** Stop the listeners. Open channels are closed by the core. */
  close(): void;
}

export interface NodeNetworkCoreOptions {
  identity: Identity;
  /** OPTIONAL contact secret for THIS node — 32 bytes of full entropy, published with
   *  our address to the peers we want to be able to reach us. A caller that cannot
   *  produce it draws no response at all. Absent, this node is open: it answers anyone.
   *
   *  Per node, so a leak is contained to this node's inbound side — rotate it, re-issue
   *  the address to our own peers, and nothing else in the network moves. See
   *  PeerLinkOptions.contactSecret. */
  contactSecret?: Uint8Array;
  /** OPTIONAL network key: which network this node belongs to (staging vs production,
   *  say). An isolation boundary, not a gate — nodes on different network keys cannot
   *  complete a handshake under any circumstances. Public by design; see
   *  PeerLinkOptions.networkKey. */
  networkKey?: Uint8Array;
  sodium: TransportCrypto;
  channels: ChannelFactory;
  listen?: { host: string; port: number };
  wsListen?: { host: string; port: number };
  /** How many parallel connections to open per peer we DIAL (default 1). Bulk
   *  transfers stripe frames round-robin across them so N flows fill a link a
   *  single TCP flow can't. Inbound multiplicity needs no setting — a node keeps
   *  every inbound link a peer opens to it, so a holder serves multi-flow initiators
   *  regardless of its own value.
   *
   *  This assumes an initiator→holder topology: exactly one side dials. The
   *  double-connect tie-break (LinkRouter.promote) only leaves parallel flows alone
   *  when they share a direction (all dialed, or all accepted). If BOTH ends set
   *  connsPerPeer > 1 and dial each other, each outbound flow pairs against an
   *  inbound rival and the tie-break collapses toward a single link — with transiently
   *  mixed pools and dropped frames along the way. Don't stripe from both ends of the
   *  same peer pair. */
  connsPerPeer?: number;
  /** Bounds concurrent half-open (accepted, not yet authenticated) links. Pass the
   *  host's shared limiter to make the cap global across every transport it stands
   *  up; omit it and this core makes its own, which is still a bound but only over
   *  its own listeners. Only ACCEPTED links draw on it — a dial we chose to make is
   *  our own resource decision, and counting it would let inbound pressure starve
   *  outbound connectivity, which is the wrong way round. */
  halfOpen?: HalfOpenLimiter;
  /** Optional peer whitelist. Absent (the default) admits everyone.
   *
   *  One hook, wired to BOTH gates on every transport: PeerLink refuses during the
   *  handshake, silently, before it will finish authenticating; LinkRouter refuses again
   *  before the link is installed or delivers a frame. Same predicate, so a deployment
   *  sets one thing and gets both.
   *
   *  Called with a peer id whose signature has already verified — never with a claimed
   *  key, which is what let the old pre-signature filter be used as a membership oracle
   *  (§12.6.2 §2.3). Keep it pure and fast; it runs per handshake. */
  admitPeer?: (peerId: PeerId) => boolean;
}

export class NodeNetworkCore implements Network {
  /** Frames issued into the fabric — a diagnostic mirroring LoopbackNetwork.
   *  framesDelivered is owned by the router (delivery lives there). */
  framesSent = 0;
  port = 0;
  wsPort = 0;

  private readonly identity: Identity;
  private readonly sodium: TransportCrypto;
  private readonly channels: ChannelFactory;
  private readonly ownId: PeerId;
  private readonly router: LinkRouter;

  private readonly connecting = new Map<PeerId, PeerLink[]>(); // outbound, pre-auth
  private readonly inbound = new Set<PeerLink>();              // accepted, pre-auth
  private readonly addrs = new Map<PeerId, PeerAddr>();
  private readonly authWaiters = new Set<() => void>();
  private readonly conns: number;
  private readonly halfOpen: HalfOpenLimiter;
  private readonly admitPeer?: (peerId: PeerId) => boolean;
  private readonly contactSecret?: Uint8Array;
  private readonly networkKey?: Uint8Array;

  private readonly listenOpt?: { host: string; port: number };
  private readonly wsListenOpt?: { host: string; port: number };

  constructor(opts: NodeNetworkCoreOptions) {
    this.identity = opts.identity;
    this.sodium = opts.sodium;
    this.channels = opts.channels;
    this.ownId = toHex(opts.identity.publicKey);
    this.listenOpt = opts.listen;
    this.wsListenOpt = opts.wsListen;
    this.conns = Math.max(1, Math.floor(opts.connsPerPeer ?? 1));
    // Injected when the host shares one limiter across transports; otherwise ours.
    this.halfOpen = opts.halfOpen ?? new HalfOpenLimiter();
    this.admitPeer = opts.admitPeer;
    this.contactSecret = opts.contactSecret;
    this.networkKey = opts.networkKey;
    // A server core has no roster gate and no cohort mirror; ready() waits on the
    // first link to each dialed peer, so onPeerUp wakes those waiters.
    this.router = new LinkRouter({
      ownPubkey: this.identity.publicKey, ownId: this.ownId,
      admit: opts.admitPeer,
      onPeerUp: () => { for (const w of [...this.authWaiters]) w(); },
    });
  }

  /** Frames delivered to our sink (mirrors LoopbackNetwork) — kept by the router. */
  get framesDelivered(): number { return this.router.framesDelivered; }

  private static push(m: Map<PeerId, PeerLink[]>, peerId: PeerId, link: PeerLink): void {
    const a = m.get(peerId); if (a) a.push(link); else m.set(peerId, [link]);
  }

  // ── Network interface ──────────────────────────────────────────────────────
  endpoint(id: PeerId): Endpoint {
    if (id !== this.ownId) throw new Error("NodeNetwork is bound to one identity");
    return this.router.endpoint((to, frame) => this.sendFrame(to, frame), () => this.close());
  }

  private sendFrame(to: PeerId, frame: Uint8Array): void {
    if (to === this.ownId) return;
    this.framesSent++;
    // Prefer an authenticated link (the router stripes round-robin across its pool).
    if (this.router.send(to, frame)) return;
    // Fall back to a pre-auth link (it buffers until the handshake lands), dialing if
    // we hold none. Pre-auth striping doesn't matter — frames are buffered anyway.
    let pool = this.connecting.get(to);
    if (!pool || pool.length === 0) { this.dial(to); pool = this.connecting.get(to); }
    if (!pool || pool.length === 0) return;
    pool[0].send(frame);
  }

  // ── address book ───────────────────────────────────────────────────────────
  addPeerAddr(peerId: PeerId, addr: PeerAddr): void { this.addrs.set(peerId, addr); }

  // ── lifecycle ──────────────────────────────────────────────────────────────
  async start(): Promise<void> {
    const { port, wsPort } = await this.channels.listen(
      this.listenOpt, this.wsListenOpt, (channel) => this.accept(channel),
    );
    this.port = port;
    this.wsPort = wsPort;
  }

  /** Dial every known peer address and resolve once each is authenticated (or
   *  the deadline passes — links also form lazily on first send). Resolution is
   *  event-driven off promote(), not polled, so an all-up cohort resolves the
   *  moment its last handshake lands. */
  async ready(timeoutMs = 5000): Promise<void> {
    const targets = [...this.addrs.keys()].filter((p) => p !== this.ownId);
    // dial() is idempotent — it tops each peer up to connsPerPeer outbound and never
    // over-dials — so calling it per target is safe and completes any partial fan-out.
    for (const p of targets) this.dial(p);
    const allUp = (): boolean => targets.every((p) => this.router.linkCount(p) >= 1);
    if (allUp()) return;
    await new Promise<void>((resolve) => {
      const done = (): void => { clearTimeout(timer); this.authWaiters.delete(check); resolve(); };
      const check = (): void => { if (allUp()) done(); };
      const timer = setTimeout(done, timeoutMs);
      this.authWaiters.add(check);
    });
  }

  close(): void {
    // Snapshot and clear before closing: PeerLink.close() now reaches opts.onClose on
    // every path, so forget() runs synchronously inside each close() and splices the
    // very arrays this would otherwise be iterating (skipping elements, leaving links
    // open). Clearing first also makes those forget() calls no-ops.
    const pending: PeerLink[] = [];
    for (const arr of this.connecting.values()) for (const l of arr) pending.push(l);
    for (const l of this.inbound) pending.push(l);
    this.connecting.clear();
    this.inbound.clear();
    this.router.closeAll();
    for (const l of pending) l.close();
    this.channels.close();
  }

  // ── link management ────────────────────────────────────────────────────────
  /** Top a dialed peer up to connsPerPeer outbound connections. Idempotent: it only
   *  opens the shortfall (authenticated links + in-flight dials counted), so a
   *  redundant call — from ready() or a send with a not-yet-auth pool — never
   *  over-dials. */
  private dial(peerId: PeerId): void {
    const addr = this.addrs.get(peerId);
    if (!addr) return;
    const have = this.router.linkCount(peerId) + (this.connecting.get(peerId)?.length ?? 0);
    for (let n = have; n < this.conns; n++) {
      const channel = this.channels.connect(addr);
      const link = new PeerLink({
        channel, identity: this.identity, sodium: this.sodium,
        weDialed: true, expectPeerId: peerId,
        // Dialing: the secret gating the far end is THEIRS, carried by the address.
        contactSecret: addr.contactSecret,
        networkKey: this.networkKey,
        admitPeer: this.admitPeer,
        onAuth: (pid, l) => this.onAuth(pid, l),
        onFrame: (pid, frame) => this.router.deliver(pid, frame),
        onClose: (l) => this.forget(l),
      });
      NodeNetworkCore.push(this.connecting, peerId, link);
    }
  }

  private accept(channel: RawChannel): void {
    // The one fully unauthenticated entry point in this transport: anyone who can reach
    // the listener lands here. The limiter caps how many such links may be outstanding
    // (globally and per source) and PeerLink puts a deadline on each, so a peer that
    // connects and never speaks — or ten thousand that do — costs a bounded amount.
    const link = new PeerLink({
      channel, identity: this.identity, sodium: this.sodium,
      weDialed: false,
      limiter: this.halfOpen,
      // Accepting: the secret a caller must produce is OURS.
      contactSecret: this.contactSecret,
      networkKey: this.networkKey,
      admitPeer: this.admitPeer,
      onAuth: (pid, l) => this.onAuth(pid, l),
      onFrame: (pid, frame) => this.router.deliver(pid, frame),
      onClose: (l) => this.forget(l),
    });
    this.inbound.add(link);
  }

  /** A link finished its handshake: lift it out of the pre-auth pools and hand it to
   *  the router, which installs it (resolving any double-connect) and wakes ready(). */
  private onAuth(peerId: PeerId, link: PeerLink): void {
    this.inbound.delete(link);
    NodeNetworkCore.drop(this.connecting, peerId, link);
    this.router.promote(peerId, link);
  }

  private forget(link: PeerLink): void {
    this.inbound.delete(link);
    // Scan by value rather than keying off link.peerId: an outbound dial is
    // registered in `connecting` under the *target* peerId before the peer's
    // HELLO ever arrives (link.peerId is still ""), so a dial that dies pre-
    // handshake (ECONNREFUSED, expectPeerId mismatch) must still be removed —
    // otherwise send() routes to the dead link forever and never redials.
    for (const pid of [...this.connecting.keys()]) if (NodeNetworkCore.drop(this.connecting, pid, link)) break;
    this.router.remove(link);
  }

  /** Remove link from a pre-auth pool, dropping the map entry when it empties.
   *  Returns true if the link was found (and thus removed). */
  private static drop(m: Map<PeerId, PeerLink[]>, peerId: PeerId, link: PeerLink): boolean {
    const a = m.get(peerId); if (!a) return false;
    const i = a.indexOf(link); if (i < 0) return false;
    a.splice(i, 1);
    if (a.length === 0) m.delete(peerId);
    return true;
  }
}

export function parsePeerSpec(spec: string, transport: "tcp" | "ws"): { peerId: PeerId; addr: PeerAddr } {
  const at = spec.indexOf("@");
  if (at < 0) throw new Error(`bad peer spec (want pk[.secret]@host:port): ${spec}`);
  // `pk` names WHO lives there — it keys the address book, so dial-by-identity has
  // something to look up. The optional `.secret` is the peer's contact secret, which is
  // what makes the address a credential: without it a gated peer answers nothing. The two
  // do different jobs, so the pk is not a security field and losing it would only cost
  // routing.
  const idPart = spec.slice(0, at).toLowerCase();
  const dot = idPart.indexOf(".");
  const peerId = dot < 0 ? idPart : idPart.slice(0, dot);
  if (peerId.length !== 64 || /[^0-9a-f]/.test(peerId)) throw new Error(`bad peer pubkey hex: ${spec}`);
  let contactSecret: Uint8Array | undefined;
  if (dot >= 0) {
    const hex = idPart.slice(dot + 1);
    if (hex.length !== 64 || /[^0-9a-f]/.test(hex)) {
      throw new Error(`bad peer contact secret hex (want 32 bytes): ${spec}`);
    }
    contactSecret = fromHex(hex);
  }
  const hostPort = spec.slice(at + 1);
  const colon = hostPort.lastIndexOf(":");
  if (colon < 0) throw new Error(`bad peer host:port: ${spec}`);
  const host = hostPort.slice(0, colon);
  const port = Number(hostPort.slice(colon + 1));
  if (!Number.isInteger(port) || port <= 0) throw new Error(`bad peer port: ${spec}`);
  return { peerId, addr: { host, port, transport, contactSecret } };
}
