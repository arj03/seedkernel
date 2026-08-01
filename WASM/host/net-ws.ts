// Browser↔node edge over a plain WebSocket (the README's "browser edge over
// WebSocket"). A browser cannot open raw TCP, and WebRTC (net-rtc.ts) needs a
// signaling relay + STUN; when a node is directly reachable — a public IP, a LAN,
// a port-forward — the simplest path is the oldest one: the browser opens a
// WebSocket straight at the node's --ws-listen endpoint.
//
// A browser WebSocket is already an ordered, whole-message binary pipe — exactly
// the RawChannel shape — so the whole stack above is unchanged, identical to
// net-rtc.ts with only the bottom swapped and no signaling:
//   Transport (unchanged) → WsNetwork → PeerLink (unchanged identity handshake)
//                                         → WsChannel (this file) → WebSocket
// There is no rendezvous: the browser dials a known set of `pubkey@host:port`
// peers (the cohort), exactly like a node's --peers flag. The node side is
// net-node.ts's WsServerChannel — a standard RFC 6455 server — so the same
// Go/Node `--ws-listen` that accepts a node peer accepts a browser tab.
//
// Platform-neutral: the WebSocket global is touched only inside a dial (or an
// injected factory), so importing this module where WebSocket is absent is safe. A
// Node/Bun *node* uses net-node.ts's WsClientChannel (raw-socket WS codec); this is
// the browser's native-WebSocket counterpart, and also runs under Node ≥22 / Bun
// (which expose a global WebSocket) for headless testing.

import type { Network, Endpoint, PeerId } from "./net.js";
import { PeerLink, type Identity, type TransportCrypto } from "./net-link.js";
import { BufferedChannel } from "./net-channel.js";
import { LinkRouter } from "./link-router.js";
import { toHex, fromHex } from "./util.js";

/** The minimal structural view of the platform WebSocket that WsChannel uses — so
 *  this module type-checks without committing to a DOM lib and accepts any
 *  conforming implementation (the browser global, Bun's, or a test double). */
export interface WsLike {
  binaryType: string;
  readyState: number;
  send(data: Uint8Array): void;
  close(): void;
  addEventListener(type: "open" | "close" | "error", cb: () => void): void;
  addEventListener(type: "message", cb: (ev: { data: unknown }) => void): void;
}

// ── RawChannel over one WebSocket ─────────────────────────────────────────────
// A WebSocket delivers whole binary messages in order, so this is a thin adapter —
// the role RtcChannel plays for an RTCDataChannel. BufferedChannel (net-channel.ts)
// carries the shared machinery, including the pre-open send buffer PeerLink needs
// because it emits its HELLO the instant the link is constructed.
export class WsChannel extends BufferedChannel {
  constructor(private readonly ws: WsLike) {
    super();
    ws.binaryType = "arraybuffer";
    ws.addEventListener("message", (ev: { data: unknown }) => {
      // Only binary frames are PeerLink messages; a string frame is never ours.
      if (typeof ev.data !== "string") this.deliver(new Uint8Array(ev.data as ArrayBuffer));
    });
    ws.addEventListener("open", () => this.open());
    ws.addEventListener("close", () => this.fail());
    ws.addEventListener("error", () => this.fail());
  }
  protected write(bytes: Uint8Array): void { this.ws.send(bytes); }
  // WebSocket.close() sends the queued frames before the close frame, so a graceful
  // stop needs nothing extra here.
  protected stop(_graceful: boolean): void { this.ws.close(); }
}

export interface WsNetworkOptions {
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
  /** Open a WebSocket to `url`. Defaults to the platform global, which is what a
   *  browser tab (and Node ≥22 / Bun) provide. Referenced only here, so importing
   *  this module where WebSocket is absent stays safe. */
  webSocketFactory?: (url: string) => WsLike;
  /** Called when a peer's link authenticates / drops — the storage demo mirrors
   *  these into a StorageNode's cohort (addPeer / removePeer), same as RtcNetwork. */
  onPeerUp?: (peerId: PeerId) => void;
  onPeerDown?: (peerId: PeerId) => void;
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
  /** How many parallel connections to open per peer (default 1). Bulk PUT/GET
   *  stripes its frames round-robin across them — each still its own PeerLink and
   *  record session — so a high-RTT/lossy link that a single TCP flow can't fill is
   *  filled by N flows. The peer must keep multiple inbound links per peer for this
   *  to take effect (NodeNetworkCore does; a full holder cohort must be built with
   *  the multi-link routing core). */
  connsPerPeer?: number;
}

export class WsNetwork implements Network {
  private readonly opts: WsNetworkOptions;
  private readonly ownId: PeerId;
  private readonly mkWs: (url: string) => WsLike;
  private readonly conns: number;
  private readonly router: LinkRouter;
  private readonly dialing = new Map<PeerId, PeerLink[]>();  // every link we have dialed to a peer

  constructor(opts: WsNetworkOptions) {
    this.opts = opts;
    this.ownId = toHex(opts.identity.publicKey);
    this.mkWs = opts.webSocketFactory ?? ((url: string) => new WebSocket(url) as unknown as WsLike);
    this.conns = Math.max(1, Math.floor(opts.connsPerPeer ?? 1));
    // Authenticated-pool routing, the roster gate, and the up/down edges the cohort
    // mirrors are all the shared LinkRouter (link-router.ts). All links here are
    // outbound (weDialed = true), so its double-connect tie-break never fires.
    this.router = new LinkRouter({
      ownPubkey: opts.identity.publicKey, ownId: this.ownId,
      admit: opts.admitPeer, onPeerUp: opts.onPeerUp, onPeerDown: opts.onPeerDown,
    });
  }

  /** Frames delivered to the Transport's sink — a diagnostic mirroring LoopbackNetwork. */
  get framesDelivered(): number { return this.router.framesDelivered; }

  // ── Network interface ──────────────────────────────────────────────────────────
  /** A single-identity fabric: it vends exactly one endpoint, its own. */
  endpoint(id: PeerId): Endpoint {
    if (id !== this.ownId) throw new Error("WsNetwork is bound to one identity");
    return this.router.endpoint((to, frame) => this.sendFrame(to, frame), () => this.close());
  }
  private sendFrame(to: PeerId, frame: Uint8Array): void {
    // The router stripes across the peer's flows, or drops if it has no authenticated
    // link — the Transport's timeout copes, exactly as the other Networks' drops.
    this.router.send(to, frame);
  }

  /** Dial a cohort peer given `pubkey@host:port` (or `pubkey@ws://host:port[/path]`,
   *  `wss://…` for TLS). The link authenticates in-channel (PeerLink), pinned to the
   *  declared `pubkey`, and onPeerUp fires once it does. Idempotent top-up, mirroring
   *  NodeNetworkCore.dial(): it opens only the shortfall to connsPerPeer, so the first
   *  call opens the full fan-out and a re-connect() after some of the parallel flows
   *  dropped restores just the lost ones instead of no-op'ing on the survivors (an
   *  early-return on "already dialing" would leave the pool permanently degraded to
   *  whatever survived). Returns the parsed peer id either way. */
  connect(spec: string): PeerId {
    const { peerId, contactSecret, url } = parseWsPeer(spec);
    if (peerId === this.ownId) return peerId;
    // `dialing` holds every live link we dialed to this peer — pre-auth AND post-auth
    // (promote() leaves them here; forget() removes one the instant it closes) — so its
    // length is the current outbound flow count. Open connsPerPeer parallel connections,
    // each its own PeerLink over its own WebSocket. They authenticate independently;
    // onPeerUp fires on the first to reach a peer that had none.
    let arr = this.dialing.get(peerId);
    if (!arr) { arr = []; this.dialing.set(peerId, arr); }
    for (let i = arr.length; i < this.conns; i++) {
      const link: PeerLink = new PeerLink({
        channel: new WsChannel(this.mkWs(url)),
        identity: this.opts.identity,
        sodium: this.opts.sodium,
        weDialed: true,
        expectPeerId: peerId, // pin the far key to the address we dialed
        // DIALING: the secret gating the far end is THEIRS, from the peer spec — not
        // ours. Passing our own here seals msg1 under a secret the peer has never seen,
        // so every dial to a gated peer draws silence.
        contactSecret,
        networkKey: this.opts.networkKey,
        admitPeer: this.opts.admitPeer,
        // On auth the router installs the link and fires onPeerUp; if it declines
        // (off-roster), drop the link from `dialing` too so it isn't counted as a
        // live flow — a rejected link never fires its channel-close forget().
        onAuth: (pid, l) => { if (!this.router.promote(pid, l)) this.forget(peerId, l); },
        onFrame: (pid, frame) => this.router.deliver(pid, frame),
        onClose: () => this.forget(peerId, link),
      });
      arr.push(link);
    }
    return peerId;
  }

  /** The peers we currently hold at least one authenticated link to (for UI / cohort). */
  linkedPeers(): PeerId[] { return this.router.linkedPeers(); }

  /** Tear down every link. */
  close(): void {
    // Snapshot and clear first: PeerLink.close() now reaches opts.onClose on every path,
    // so forget() runs synchronously inside each close() and splices the arrays this
    // loop is walking. Clearing up front also makes those forget() calls no-ops.
    const pending: PeerLink[] = [];
    for (const arr of this.dialing.values()) for (const l of arr) pending.push(l);
    this.dialing.clear();
    this.router.closeAll(); // authenticated links also live in `dialing`; double-close is a no-op
    for (const l of pending) l.close();
  }

  // A link died (channel close) or was declined by the roster: remove it from the
  // outbound `dialing` pool, then from the router (which fires onPeerDown when the
  // peer's LAST authenticated link goes — losing one of several parallel flows
  // leaves the peer reachable, so the cohort must not evict it).
  private forget(peerId: PeerId, link: PeerLink): void {
    const dl = this.dialing.get(peerId);
    if (dl) { const i = dl.indexOf(link); if (i >= 0) dl.splice(i, 1); if (dl.length === 0) this.dialing.delete(peerId); }
    this.router.remove(link);
  }
}

/** Parse a `pubkey@host:port` (or `pubkey@ws://host:port[/path]`) cohort peer spec
 *  into the peer id + the WebSocket URL to dial. A bare host:port defaults to the
 *  ws:// scheme; pass wss:// explicitly for TLS. */
export function parseWsPeer(spec: string): { peerId: PeerId; contactSecret?: Uint8Array; url: string } {
  const at = spec.indexOf("@");
  if (at < 0) throw new Error(`ws peer must be pubkey[.secret]@host:port, got ${spec}`);
  // `pk` names WHO lives there and keys the peer table; the optional `.secret` is THAT
  // PEER's contact secret, which is what our opening message must be sealed under. They
  // do different jobs — the pk is routing, the secret is the credential.
  const idPart = spec.slice(0, at).trim().toLowerCase();
  const dot = idPart.indexOf(".");
  const peerId = dot < 0 ? idPart : idPart.slice(0, dot);
  if (!isHex64(peerId)) throw new Error(`ws peer id must be 32-byte hex, got ${peerId}`);
  let contactSecret: Uint8Array | undefined;
  if (dot >= 0) {
    const hex = idPart.slice(dot + 1);
    if (!isHex64(hex)) throw new Error(`ws peer contact secret must be 32-byte hex, got ${hex}`);
    contactSecret = fromHex(hex);
  }
  let url = spec.slice(at + 1).trim();
  if (!url.startsWith("ws://") && !url.startsWith("wss://")) url = "ws://" + url;
  return { peerId, contactSecret, url };
}

// The host JS carries no regex literals (the minifier treats every `/` as
// division), so the 32-byte-hex check is a manual scan rather than /^[0-9a-f]{64}$/.
function isHex64(s: string): boolean {
  if (s.length !== 64) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102))) return false; // 0-9 / a-f
  }
  return true;
}
