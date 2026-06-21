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

import type { Network, PeerId } from "./net.js";
import { PeerLink, type RawChannel, type Identity, type TransportCrypto } from "./net-link.js";
import { toHex } from "./util.js";

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

const WS_OPEN = 1; // WebSocket.OPEN

// ── RawChannel over one WebSocket ─────────────────────────────────────────────
// A WebSocket delivers whole binary messages in order, so this is a thin adapter —
// the role RtcChannel plays for an RTCDataChannel. Its one job beyond shuffling
// bytes: buffer sends issued before "open", because PeerLink emits its HELLO the
// instant the link is constructed.
export class WsChannel implements RawChannel {
  private onMsg: ((b: Uint8Array) => void) | null = null;
  private onCls: (() => void) | null = null;
  private readonly pending: Uint8Array[] = [];
  private dead = false;

  constructor(private readonly ws: WsLike) {
    ws.binaryType = "arraybuffer";
    ws.addEventListener("message", (ev: { data: unknown }) => {
      // Only binary frames are PeerLink messages; a string frame is never ours.
      const d = ev.data;
      if (this.dead || typeof d === "string") return;
      this.onMsg?.(new Uint8Array(d as ArrayBuffer));
    });
    ws.addEventListener("open", () => {
      for (const b of this.pending) ws.send(b);
      this.pending.length = 0;
    });
    ws.addEventListener("close", () => this.fail());
    ws.addEventListener("error", () => this.fail());
  }

  send(bytes: Uint8Array): void {
    if (this.dead) return;
    if (this.ws.readyState === WS_OPEN) this.ws.send(bytes);
    else this.pending.push(bytes);
  }
  onMessage(cb: (b: Uint8Array) => void): void { this.onMsg = cb; }
  onClose(cb: () => void): void { this.onCls = cb; }
  close(): void { if (!this.dead) { this.dead = true; try { this.ws.close(); } catch { /* already gone */ } } }

  // Failure teardown notifies onClose so the owning PeerLink is forgotten from the
  // routing maps (same contract as RtcChannel / TcpChannel).
  private fail(): void { if (!this.dead) { this.dead = true; this.onCls?.(); } }
}

export interface WsNetworkOptions {
  identity: Identity;
  sodium: TransportCrypto;
  /** Open a WebSocket to `url`. Defaults to the platform global, which is what a
   *  browser tab (and Node ≥22 / Bun) provide. Referenced only here, so importing
   *  this module where WebSocket is absent stays safe. */
  webSocketFactory?: (url: string) => WsLike;
  /** Called when a peer's link authenticates / drops — the storage demo mirrors
   *  these into a StorageNode's cohort (addPeer / removePeer), same as RtcNetwork. */
  onPeerUp?: (peerId: PeerId) => void;
  onPeerDown?: (peerId: PeerId) => void;
  /** Optional roster gate applied *after* the identity handshake proves who the
   *  peer is: an off-roster peer is dropped before any frame is delivered. */
  admit?: (peerId: PeerId) => boolean;
}

export class WsNetwork implements Network {
  /** Diagnostics, mirroring LoopbackNetwork / RtcNetwork. */
  framesDelivered = 0;

  private readonly opts: WsNetworkOptions;
  private readonly ownId: PeerId;
  private readonly mkWs: (url: string) => WsLike;
  private sink: ((from: PeerId, frame: Uint8Array) => void) | null = null;
  private readonly links = new Map<PeerId, PeerLink>();    // authenticated, routable
  private readonly dialing = new Map<PeerId, PeerLink>();   // every peer we have dialed

  constructor(opts: WsNetworkOptions) {
    this.opts = opts;
    this.ownId = toHex(opts.identity.publicKey);
    this.mkWs = opts.webSocketFactory ?? ((url: string) => new WebSocket(url) as unknown as WsLike);
  }

  // ── Network interface ──────────────────────────────────────────────────────────
  register(peerId: PeerId, sink: (from: PeerId, frame: Uint8Array) => void): void {
    if (peerId !== this.ownId) throw new Error("WsNetwork is bound to one identity");
    this.sink = sink; // Transport registers its frame sink here (net.ts)
  }
  unregister(peerId: PeerId): void {
    if (peerId !== this.ownId) return;
    this.sink = null;
    this.close();
  }
  send(_from: PeerId, to: PeerId, frame: Uint8Array): void {
    // A frame to a peer with no authenticated link is dropped, exactly as the other
    // Networks drop to an unknown peer; the Transport's timeout copes with it.
    this.links.get(to)?.send(frame);
  }

  /** Dial a cohort peer given `pubkey@host:port` (or `pubkey@ws://host:port[/path]`,
   *  `wss://…` for TLS). The link authenticates in-channel (PeerLink), pinned to the
   *  declared `pubkey`, and onPeerUp fires once it does. Dialing a peer already
   *  linked or in-flight is a no-op; returns the parsed peer id either way. */
  connect(spec: string): PeerId {
    const { peerId, url } = parseWsPeer(spec);
    if (peerId === this.ownId || this.dialing.has(peerId)) return peerId;
    const link = new PeerLink({
      channel: new WsChannel(this.mkWs(url)),
      identity: this.opts.identity,
      sodium: this.opts.sodium,
      weDialed: true,
      expectPeerId: peerId, // pin the far key to the address we dialed
      onAuth: (pid, l) => this.promote(pid, l),
      onFrame: (pid, frame) => this.deliver(pid, frame),
      onClose: () => this.forget(peerId),
    });
    this.dialing.set(peerId, link);
    return peerId;
  }

  /** The peers we currently hold an authenticated link to (for UI / cohort). */
  linkedPeers(): PeerId[] { return [...this.links.keys()]; }

  /** Tear down every link. */
  close(): void {
    for (const l of this.dialing.values()) l.close();
    this.links.clear();
    this.dialing.clear();
  }

  private promote(peerId: PeerId, link: PeerLink): void {
    // Final gate: even a peer that completed the identity handshake is dropped if it
    // is not on the roster. Identity is proven now, so this is a trustworthy call.
    if (this.opts.admit && !this.opts.admit(peerId)) { link.close(); return; }
    this.links.set(peerId, link);
    this.opts.onPeerUp?.(peerId);
  }

  private deliver(peerId: PeerId, frame: Uint8Array): void {
    if (!this.sink || peerId === this.ownId) return;
    this.framesDelivered++;
    this.sink(peerId, frame); // PeerLink only delivers post-auth, tagged with the proven id
  }

  private forget(peerId: PeerId): void {
    const had = this.links.delete(peerId);
    this.dialing.delete(peerId);
    if (had) this.opts.onPeerDown?.(peerId);
  }
}

/** Parse a `pubkey@host:port` (or `pubkey@ws://host:port[/path]`) cohort peer spec
 *  into the peer id + the WebSocket URL to dial. A bare host:port defaults to the
 *  ws:// scheme; pass wss:// explicitly for TLS. */
export function parseWsPeer(spec: string): { peerId: PeerId; url: string } {
  const at = spec.indexOf("@");
  if (at < 0) throw new Error(`ws peer must be pubkey@host:port, got ${spec}`);
  const peerId = spec.slice(0, at).trim().toLowerCase();
  if (!isHex64(peerId)) throw new Error(`ws peer id must be 32-byte hex, got ${peerId}`);
  let url = spec.slice(at + 1).trim();
  if (!url.startsWith("ws://") && !url.startsWith("wss://")) url = "ws://" + url;
  return { peerId, url };
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
