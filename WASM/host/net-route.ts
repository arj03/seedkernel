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

  private readonly links = new Map<PeerId, PeerLink>();      // authenticated, routable
  private readonly connecting = new Map<PeerId, PeerLink>(); // outbound, pre-auth
  private readonly inbound = new Set<PeerLink>();            // accepted, pre-auth
  private readonly addrs = new Map<PeerId, PeerAddr>();      // how to reach a peer
  private readonly authWaiters = new Set<() => void>();      // ready() callers

  private readonly listenOpt?: { host: string; port: number };
  private readonly wsListenOpt?: { host: string; port: number };

  constructor(opts: NodeNetworkCoreOptions) {
    this.identity = opts.identity;
    this.sodium = opts.sodium;
    this.channels = opts.channels;
    this.ownId = toHex(opts.identity.publicKey);
    this.listenOpt = opts.listen;
    this.wsListenOpt = opts.wsListen;
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
    const link = this.links.get(to) ?? this.connecting.get(to) ?? this.dial(to);
    if (link) link.send(frame);
    // No link and no address → silently dropped, exactly as LoopbackNetwork drops
    // a frame to an unknown peer; the Transport's timeout handles the fallout.
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
    // Skip peers already dialing (in `connecting`) as well as connected ones —
    // a second dial would orphan the in-flight PeerLink and open a redundant
    // socket, and the double-self-dial defeats canonicalKeep's tie-break.
    for (const p of targets) if (!this.links.has(p) && !this.connecting.has(p)) this.dial(p);
    const allUp = (): boolean => targets.every((p) => this.links.has(p));
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
    for (const l of this.links.values()) l.close();
    for (const l of this.connecting.values()) l.close();
    for (const l of this.inbound) l.close();
    this.links.clear();
    this.connecting.clear();
    this.inbound.clear();
    this.channels.close();
  }

  // ── link management ────────────────────────────────────────────────────────
  private dial(peerId: PeerId): PeerLink | null {
    const addr = this.addrs.get(peerId);
    if (!addr) return null;
    const channel = this.channels.connect(addr);
    const link = new PeerLink({
      channel, identity: this.identity, sodium: this.sodium,
      weDialed: true, expectPeerId: peerId,
      onAuth: (pid, l) => this.promote(pid, l),
      onFrame: (pid, frame) => this.deliver(pid, frame),
      onClose: (l) => this.forget(l),
    });
    this.connecting.set(peerId, link);
    return link;
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
    if (this.connecting.get(peerId) === link) this.connecting.delete(peerId);
    const existing = this.links.get(peerId);
    if (existing && existing !== link) {
      // Two connections to the same peer (each dialed the other). Keep the one
      // whose *dialer* holds the smaller pubkey — a deterministic choice both
      // ends agree on, so exactly one survives.
      if (this.canonicalKeep(link)) { existing.close(); this.links.set(peerId, link); }
      else { link.close(); }
    } else {
      this.links.set(peerId, link);
    }
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
    // otherwise send() returns the dead link forever and never redials.
    for (const [pid, l] of this.connecting) if (l === link) this.connecting.delete(pid);
    for (const [pid, l] of this.links) if (l === link) this.links.delete(pid);
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
