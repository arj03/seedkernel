// Browser↔node edge over a plain WebSocket (the README's "browser edge over
// WebSocket"). A browser cannot open raw TCP, and WebRTC (net-rtc.ts) needs a
// signaling relay + STUN; when a node is directly reachable — a public IP, a LAN,
// a port-forward — the simplest path is the oldest one: the browser opens a
// WebSocket straight at the node's --ws-listen endpoint.
//
// The transport itself — the identity handshake, the record layer, the routing —
// runs in the transport bundle's guest program, driven by the shared TransportHost
// (transport-host.ts). This file is what remains of the old WsNetwork: the browser
// side of the socket seam. It opens platform WebSockets and hands them to the
// driver's openLink() — everything above is the bundle's, identical to the TCP
// path with only the bottom swapped.
//
// Platform-neutral: the WebSocket global is touched only inside a dial (or an
// injected factory), so importing this module where WebSocket is absent is safe.

import type { Network, Endpoint, PeerId } from "../core/net.js";
import { BufferedChannel } from "../core/net-channel.js";
import { fromHex } from "../core/util.js";
import type { TransportHost, LinkHandle } from "./transport-host.js";

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
// A WebSocket delivers whole binary messages in order, so this is a thin adapter.
// BufferedChannel (net-channel.ts) carries the shared machinery, including the
// pre-open send buffer the transport needs because it emits its HELLO the instant
// a link is constructed.
export class WsChannel extends BufferedChannel {
  constructor(private readonly ws: WsLike) {
    super();
    ws.binaryType = "arraybuffer";
    ws.addEventListener("message", (ev: { data: unknown }) => {
      // Only binary frames are transport messages; a string frame is never ours.
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
  /** The transport driver — the shell's `net` once the transport bundle is
   *  admitted. It holds the node identity, the network key, the contact secret
   *  and the peer whitelist; this file only opens sockets. */
  driver: TransportHost;
  /** Open a WebSocket to `url`. Defaults to the platform global, which is what a
   *  browser tab (and Node ≥22 / Bun) provide. Referenced only here, so importing
   *  this module where WebSocket is absent stays safe. */
  webSocketFactory?: (url: string) => WsLike;
  /** Called when a peer's link authenticates / drops — the storage demo mirrors
   *  these into a StorageNode's cohort (addPeer / removePeer), same as RtcNetwork. */
  onPeerUp?: (peerId: PeerId) => void;
  onPeerDown?: (peerId: PeerId) => void;
  /** How many parallel connections to open per peer (default 1). Bulk PUT/GET
   *  stripes its frames round-robin across them — each still its own link and
   *  record session — so a high-RTT/lossy link that a single TCP flow can't fill
   *  is filled by N flows. The peer must keep multiple inbound links per peer for
   *  this to take effect (the routing core does). */
  connsPerPeer?: number;
}

export class WsNetwork implements Network {
  private readonly driver: TransportHost;
  private readonly ownId: PeerId;
  private readonly mkWs: (url: string) => WsLike;
  private readonly conns: number;
  private readonly dialing = new Map<PeerId, LinkHandle[]>(); // every link we have dialed to a peer

  constructor(private readonly opts: WsNetworkOptions) {
    this.driver = opts.driver;
    this.ownId = opts.driver.peerId;
    this.mkWs = opts.webSocketFactory
      ?? ((url: string) => new (globalThis as unknown as { WebSocket: new (u: string) => WsLike }).WebSocket(url));
    this.conns = Math.max(1, Math.floor(opts.connsPerPeer ?? 1));
    this.driver.setPeerHooks({ onPeerUp: opts.onPeerUp, onPeerDown: opts.onPeerDown });
  }

  /** Frames delivered to the app side — the driver's diagnostic mirror. */
  get framesDelivered(): number { return this.driver.framesDelivered; }

  // ── Network interface ──────────────────────────────────────────────────────────

  /** A single-identity fabric: it vends exactly one endpoint, its own. */
  endpoint(id: PeerId): Endpoint {
    if (id !== this.ownId) throw new Error("WsNetwork is bound to one identity");
    return this.driver.endpoint(id);
  }

  /** Dial a cohort peer given `pubkey@host:port` (or `pubkey@ws://host:port[/path]`,
   *  `wss://…` for TLS). The link authenticates in-channel, pinned to the declared
   *  `pubkey`, and onPeerUp fires once it does. Idempotent top-up, mirroring the
   *  routing core's dial(): it opens only the shortfall to connsPerPeer. Returns
   *  the parsed peer id either way. */
  connect(spec: string): PeerId {
    const { peerId, contactSecret, url } = parseWsPeer(spec);
    if (peerId === this.ownId) return peerId;
    // `dialing` holds every live link we dialed to this peer — pre-auth AND
    // post-auth (the guest forgets one the instant it closes) — so its length is
    // the current outbound flow count. Open connsPerPeer parallel connections,
    // each its own link over its own WebSocket.
    let arr = this.dialing.get(peerId);
    if (!arr) {
      arr = [];
      this.dialing.set(peerId, arr);
    }
    for (let i = arr.length; i < this.conns; i++) {
      const handle: LinkHandle = this.driver.openLink({
        channel: new WsChannel(this.mkWs(url)),
        weDialed: true,
        expectPeerId: peerId, // pin the far key to the address we dialed
        // DIALING: the secret gating the far end is THEIRS, from the peer spec —
        // not ours. Passing our own here would seal msg1 under a secret the peer
        // has never seen, so every dial to a gated peer would draw silence.
        contactSecret,
        onClose: () => this.forget(peerId, handle),
      });
      arr.push(handle);
    }
    return peerId;
  }

  /** The peers we currently hold at least one authenticated link to (for UI / cohort). */
  linkedPeers(): PeerId[] { return this.driver.linkedPeers(); }

  /** Tear down every link and the driver's channels. */
  close(): void {
    const pending: LinkHandle[] = [];
    for (const arr of this.dialing.values()) for (const l of arr) pending.push(l);
    this.dialing.clear();
    for (const l of pending) l.close();
  }

  // A link died (or was declined by the whitelist): remove it from the outbound
  // `dialing` pool. The router bookkeeping is the guest's.
  private forget(peerId: PeerId, handle: LinkHandle): void {
    const dl = this.dialing.get(peerId);
    if (dl) {
      const i = dl.indexOf(handle);
      if (i >= 0) dl.splice(i, 1);
      if (dl.length === 0) this.dialing.delete(peerId);
    }
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
