// net-route.ts — the platform-agnostic routing core of a real Network (README
// §13.6). It owns NO sockets: links/connecting/inbound/addrs, the PeerLink
// handshake wiring, the deterministic double-connect rule, frame delivery and
// readiness all live here, and channel creation is injected as a ChannelFactory.
//
// This is the part net-node.ts promised was swappable — "PeerLink, the routing,
// and the handshake are untouched; the engine build swaps the native TCP binding
// behind the same RawChannel shape." net-node.ts supplies the node:net factory;
// the native (Go/wazero) loader supplies a factory over its __net primitive. The
// routing — and therefore the wire behaviour Go and Bun nodes must agree on — is
// the same code on every target.

import type { Network, PeerId } from "./net.js";
import { PeerLink, bytesCompare, type RawChannel, type Identity, type TransportCrypto } from "./net-link.js";
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
  /** The platform's socket binding (node:net, or the engine's __net). */
  channels: ChannelFactory;
  listen?: { host: string; port: number };
  wsListen?: { host: string; port: number };
  /** How many parallel connections to open per peer we DIAL (default 1). Bulk
   *  transfers stripe frames round-robin across them so N flows fill a link a
   *  single TCP flow can't. Inbound multiplicity needs no setting — a node keeps
   *  every inbound link a peer opens to it, so a holder serves multi-flow initiators
   *  regardless of its own value. */
  connsPerPeer?: number;
}

export class NodeNetworkCore implements Network {
  /** Diagnostics for tests, mirroring LoopbackNetwork. */
  framesDelivered = 0;
  framesSent = 0;
  /** Bound ports, valid after start() (ephemeral when requested with port 0). */
  port = 0;
  wsPort = 0;

  private readonly identity: Identity;
  private readonly sodium: TransportCrypto;
  private readonly channels: ChannelFactory;
  private readonly ownId: PeerId;
  private sink: ((from: PeerId, frame: Uint8Array) => void) | null = null;

  private readonly links = new Map<PeerId, PeerLink[]>();      // authenticated, routable (1..N per peer)
  private readonly connecting = new Map<PeerId, PeerLink[]>(); // outbound, pre-auth
  private readonly inbound = new Set<PeerLink>();              // accepted, pre-auth
  private readonly addrs = new Map<PeerId, PeerAddr>();        // how to reach a peer
  private readonly authWaiters = new Set<() => void>();        // ready() callers
  private readonly rr = new Map<PeerId, number>();             // round-robin send cursor per peer
  private readonly conns: number;                             // connsPerPeer for outbound dials

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
  }

  // Small helpers for the per-peer link arrays.
  private static push(m: Map<PeerId, PeerLink[]>, peerId: PeerId, link: PeerLink): void {
    const a = m.get(peerId); if (a) a.push(link); else m.set(peerId, [link]);
  }

  // ── Network interface ──────────────────────────────────────────────────────
  register(peerId: PeerId, sink: (from: PeerId, frame: Uint8Array) => void): void {
    if (peerId !== this.ownId) throw new Error("NodeNetwork is bound to one identity");
    this.sink = sink;
  }

  unregister(peerId: PeerId): void {
    if (peerId !== this.ownId) return;
    this.sink = null;
    this.close();
  }

  send(_from: PeerId, to: PeerId, frame: Uint8Array): void {
    if (to === this.ownId) return;
    this.framesSent++;
    // Prefer authenticated links; fall back to a pre-auth one (it buffers until the
    // handshake lands), dialing if we hold none. Stripe round-robin across whatever
    // pool we route over so a bulk transfer fans out across every parallel flow.
    let pool = this.links.get(to);
    if (!pool || pool.length === 0) pool = this.connecting.get(to);
    if (!pool || pool.length === 0) { this.dial(to); pool = this.connecting.get(to); }
    if (!pool || pool.length === 0) return; // no link and no address → dropped; Transport times out
    const i = (this.rr.get(to) ?? 0) % pool.length;
    this.rr.set(to, i + 1);
    pool[i].send(frame);
  }

  // ── teach the network how to reach a peer ──────────────────────────────────
  addPeerAddr(peerId: PeerId, addr: PeerAddr): void {
    this.addrs.set(peerId, addr);
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────
  /** Bind the configured listeners. Resolves once ports are known. */
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
    const allUp = (): boolean => targets.every((p) => (this.links.get(p)?.length ?? 0) >= 1);
    if (allUp()) return;
    await new Promise<void>((resolve) => {
      const done = (): void => { clearTimeout(timer); this.authWaiters.delete(check); resolve(); };
      const check = (): void => { if (allUp()) done(); };
      const timer = setTimeout(done, timeoutMs);
      this.authWaiters.add(check);
    });
  }

  /** Tear down every connection and listener. */
  close(): void {
    for (const arr of this.links.values()) for (const l of arr) l.close();
    for (const arr of this.connecting.values()) for (const l of arr) l.close();
    for (const l of this.inbound) l.close();
    this.links.clear();
    this.connecting.clear();
    this.inbound.clear();
    this.rr.clear();
    this.channels.close();
  }

  // ── link management ────────────────────────────────────────────────────────
  /** Top a dialed peer up to connsPerPeer outbound connections. Idempotent: it only
   *  opens the shortfall (existing links + in-flight dials counted), so a redundant
   *  call — from ready() or a send with a not-yet-auth pool — never over-dials. */
  private dial(peerId: PeerId): void {
    const addr = this.addrs.get(peerId);
    if (!addr) return;
    const have = (this.links.get(peerId)?.length ?? 0) + (this.connecting.get(peerId)?.length ?? 0);
    for (let n = have; n < this.conns; n++) {
      const channel = this.channels.connect(addr);
      const link = new PeerLink({
        channel, identity: this.identity, sodium: this.sodium,
        weDialed: true, expectPeerId: peerId,
        onAuth: (pid, l) => this.promote(pid, l),
        onFrame: (pid, frame) => this.deliver(pid, frame),
        onClose: (l) => this.forget(l),
      });
      NodeNetworkCore.push(this.connecting, peerId, link);
    }
  }

  private accept(channel: RawChannel): void {
    const link = new PeerLink({
      channel, identity: this.identity, sodium: this.sodium,
      weDialed: false,
      onAuth: (pid, l) => this.promote(pid, l),
      onFrame: (pid, frame) => this.deliver(pid, frame),
      onClose: (l) => this.forget(l),
    });
    this.inbound.add(link);
  }

  /** A link finished its handshake: install it as the routable link for its
   *  peer, resolving a double-connect by a rule both ends compute identically. */
  private promote(peerId: PeerId, link: PeerLink): void {
    this.inbound.delete(link);
    NodeNetworkCore.drop(this.connecting, peerId, link);
    const arr = this.links.get(peerId) ?? [];
    // A symmetric double-connect — OUR outbound and THEIR inbound for the same peer,
    // each end having dialed the other — is ONE logical link carried twice, so keep
    // exactly one, chosen by a rule both ends compute identically (canonicalKeep).
    // Deliberate parallel connections are all one direction (all dialed, or all
    // accepted), so `weDialed` matches across them and they never trip this — they
    // coexist as the N flows we opened on purpose.
    const rival = arr.find((l) => l.weDialed !== link.weDialed);
    if (rival) {
      if (this.canonicalKeep(link)) {
        rival.close();
        const i = arr.indexOf(rival); if (i >= 0) arr.splice(i, 1);
        arr.push(link);
      } else {
        link.close();
        return;
      }
    } else {
      arr.push(link);
    }
    this.links.set(peerId, arr);
    for (const w of [...this.authWaiters]) w();
  }

  private canonicalKeep(link: PeerLink): boolean {
    const peer = link.peerPubkey!;
    const mine = this.identity.publicKey;
    const dialer = link.weDialed ? mine : peer;
    const smaller = bytesCompare(mine, peer) <= 0 ? mine : peer;
    return bytesCompare(dialer, smaller) === 0;
  }

  private deliver(peerId: PeerId, frame: Uint8Array): void {
    if (!this.sink || peerId === this.ownId) return;
    this.framesDelivered++;
    this.sink(peerId, frame);
  }

  private forget(link: PeerLink): void {
    this.inbound.delete(link);
    // Scan by value rather than keying off link.peerId: an outbound dial is
    // registered in `connecting` under the *target* peerId before the peer's
    // HELLO ever arrives (link.peerId is still ""), so a dial that dies pre-
    // handshake (ECONNREFUSED, expectPeerId mismatch) must still be removed —
    // otherwise send() routes to the dead link forever and never redials. Only the
    // peer whose LAST link drops loses its rr cursor; losing one of several parallel
    // flows leaves the peer routable over the rest.
    for (const pid of [...this.connecting.keys()]) if (NodeNetworkCore.drop(this.connecting, pid, link)) break;
    for (const pid of [...this.links.keys()]) {
      if (NodeNetworkCore.drop(this.links, pid, link)) {
        if (!this.links.has(pid)) this.rr.delete(pid);
        break;
      }
    }
  }

  /** Remove link from its peer's array, dropping the map entry when it empties.
   *  Returns true if the link was found (and thus removed). */
  private static drop(m: Map<PeerId, PeerLink[]>, peerId: PeerId, link: PeerLink): boolean {
    const a = m.get(peerId); if (!a) return false;
    const i = a.indexOf(link); if (i < 0) return false;
    a.splice(i, 1);
    if (a.length === 0) m.delete(peerId);
    return true;
  }
}

/** Parse a `--peers` entry: `<pubkeyhex>@<host>:<port>`. */
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
  // The length+charset check above already guarantees 64 valid hex chars, so no
  // round-trip decode is needed to confirm the pubkey is real hex.
  return { peerId, addr: { host, port, transport } };
}
