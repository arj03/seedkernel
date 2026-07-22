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
import { PeerLink, type RawChannel, type Identity, type TransportCrypto } from "./net-link.js";
import { LinkRouter } from "./link-router.js";
import { toHex } from "./util.js";

export interface PeerAddr {
  host: string;
  port: number;
  transport: "tcp" | "ws";
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
    // A server core has no roster gate and no cohort mirror; ready() waits on the
    // first link to each dialed peer, so onPeerUp wakes those waiters.
    this.router = new LinkRouter({
      ownPubkey: this.identity.publicKey, ownId: this.ownId,
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
    this.router.closeAll();
    for (const arr of this.connecting.values()) for (const l of arr) l.close();
    for (const l of this.inbound) l.close();
    this.connecting.clear();
    this.inbound.clear();
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
        onAuth: (pid, l) => this.onAuth(pid, l),
        onFrame: (pid, frame) => this.router.deliver(pid, frame),
        onClose: (l) => this.forget(l),
      });
      NodeNetworkCore.push(this.connecting, peerId, link);
    }
  }

  private accept(channel: RawChannel): void {
    const link = new PeerLink({
      channel, identity: this.identity, sodium: this.sodium,
      weDialed: false,
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
  if (at < 0) throw new Error(`bad peer spec (want pk@host:port): ${spec}`);
  const peerId = spec.slice(0, at).toLowerCase();
  if (peerId.length !== 64 || /[^0-9a-f]/.test(peerId)) throw new Error(`bad peer pubkey hex: ${spec}`);
  const hostPort = spec.slice(at + 1);
  const colon = hostPort.lastIndexOf(":");
  if (colon < 0) throw new Error(`bad peer host:port: ${spec}`);
  const host = hostPort.slice(0, colon);
  const port = Number(hostPort.slice(colon + 1));
  if (!Number.isInteger(port) || port <= 0) throw new Error(`bad peer port: ${spec}`);
  return { peerId, addr: { host, port, transport } };
}
