// link-router.ts — the transport-agnostic routing core every real Network shares.
//
// A transport (net-route.ts TCP/WS, net-ws.ts browser edge, net-rtc.ts WebRTC) owns
// connection *setup* — dialing, listening, signaling, the pre-auth bookkeeping
// peculiar to its medium. The moment a PeerLink authenticates it is handed here, and
// from there everything is identical and lives once: the per-peer pool of
// authenticated links (1..N), round-robin frame striping across it, the
// deterministic double-connect tie-break, delivery, and the onPeerUp/onPeerDown
// edges a cohort mirrors. A pool (not a single link) because connsPerPeer opens N
// parallel flows to fill a path one TCP flow can't; RtcNetwork holds one link per
// peer, so its pool is size ≤1 and the tie-break never fires — the same code as a
// degenerate case, not a third hand-rolled variant.

import { bytesCompare, type PeerLink } from "./net-link.js";
import type { Endpoint, PeerId } from "./net.js";

export interface LinkRouterOptions {
  /** Own kernel public key + its hex; one half of the tie-break, and the id whose
   *  own frames are never routed or delivered. */
  ownPubkey: Uint8Array;
  ownId: PeerId;
  /** Roster gate applied once identity is proven (promote): an off-roster peer is
   *  dropped before it is installed or delivers a frame. Default: admit all. */
  admit?: (peerId: PeerId) => boolean;
  /** Fired on the reachability edge only — a peer's FIRST authenticated link (up) /
   *  LAST one lost (down) — so a cohort sees one up and one down per peer whatever
   *  connsPerPeer is. */
  onPeerUp?: (peerId: PeerId) => void;
  onPeerDown?: (peerId: PeerId) => void;
}

export class LinkRouter {
  /** Frames delivered to the sink — a diagnostic mirroring LoopbackNetwork. */
  framesDelivered = 0;

  private readonly opts: LinkRouterOptions;
  private readonly links = new Map<PeerId, PeerLink[]>(); // authenticated, routable (1..N per peer)
  private readonly rr = new Map<PeerId, number>();        // round-robin send cursor per peer
  private sink: ((from: PeerId, frame: Uint8Array) => void) | null = null;

  constructor(opts: LinkRouterOptions) { this.opts = opts; }

  /** Wrap this router's delivery into the single Endpoint its fabric vends. The
   *  fabric supplies `send` (transport-specific: dial-on-miss for net-route, drop
   *  otherwise) and `close` (its full teardown). */
  endpoint(send: (to: PeerId, frame: Uint8Array) => void, close: () => void): Endpoint {
    return { send, onFrame: (sink) => { this.sink = sink; }, close: () => { this.sink = null; close(); } };
  }

  /** Peers we hold ≥1 authenticated link to (cohort / UI). */
  linkedPeers(): PeerId[] { return [...this.links.keys()]; }
  /** How many authenticated links the peer has right now. */
  linkCount(peerId: PeerId): number { return this.links.get(peerId)?.length ?? 0; }

  /** Stripe one frame across a peer's authenticated pool. Returns false — frame
   *  unsent — when the peer has no authenticated link, so the caller can drop it or
   *  fall back to a pre-auth (buffering) link of its own. */
  send(to: PeerId, frame: Uint8Array): boolean {
    const pool = this.links.get(to);
    if (!pool || pool.length === 0) return false;
    const i = (this.rr.get(to) ?? 0) % pool.length;
    this.rr.set(to, i + 1);
    pool[i].send(frame);
    return true;
  }

  /** Install a freshly-authenticated link: apply the roster gate, resolve a
   *  symmetric double-connect (OUR outbound + THEIR inbound for one peer is one
   *  logical link carried twice — keep exactly one, chosen identically at both ends
   *  by canonicalKeep), and fire onPeerUp on the peer's first link. Returns false —
   *  the link closed — if rejected or it lost the tie-break, so the transport drops
   *  it from its own pre-auth bookkeeping. Deliberate parallel flows share a
   *  direction (weDialed matches), so N of them coexist and never trip the tie-break. */
  promote(peerId: PeerId, link: PeerLink): boolean {
    if (this.opts.admit && !this.opts.admit(peerId)) { link.close(); return false; }
    const pool = this.links.get(peerId) ?? [];
    const wasEmpty = pool.length === 0;
    const rival = pool.find((l) => l.weDialed !== link.weDialed);
    if (rival) {
      if (!this.canonicalKeep(link)) { link.close(); return false; }
      rival.close();
      pool.splice(pool.indexOf(rival), 1);
    }
    pool.push(link);
    this.links.set(peerId, pool);
    if (wasEmpty) this.opts.onPeerUp?.(peerId);
    return true;
  }

  /** Keep the link whose *dialer* is the lexicographically smaller identity — a rule
   *  both ends compute identically. */
  private canonicalKeep(link: PeerLink): boolean {
    const peer = link.peerPubkey!, mine = this.opts.ownPubkey;
    const dialer = link.weDialed ? mine : peer;
    const smaller = bytesCompare(mine, peer) <= 0 ? mine : peer;
    return bytesCompare(dialer, smaller) === 0;
  }

  /** Deliver an inbound post-auth frame. PeerLink only calls this after auth, tagged
   *  with the proven id. */
  deliver(peerId: PeerId, frame: Uint8Array): void {
    if (!this.sink || peerId === this.opts.ownId) return;
    this.framesDelivered++;
    this.sink(peerId, frame);
  }

  /** Remove `link` from its peer's pool, found by value: an outbound dial is pooled
   *  under the target id before the peer's key is known, so a scan is the only
   *  reliable removal. Fires onPeerDown on the peer's LAST link — losing one of
   *  several parallel flows leaves it reachable. Returns true if it was authenticated. */
  remove(link: PeerLink): boolean {
    for (const [pid, pool] of this.links) {
      const i = pool.indexOf(link);
      if (i < 0) continue;
      pool.splice(i, 1);
      if (pool.length === 0) { this.links.delete(pid); this.rr.delete(pid); this.opts.onPeerDown?.(pid); }
      return true;
    }
    return false;
  }

  /** Close every authenticated link and clear the tables. The transport clears its
   *  own pre-auth bookkeeping; double-closing a link it also tracks is a no-op. */
  closeAll(): void {
    for (const pool of this.links.values()) for (const l of pool) l.close();
    this.links.clear();
    this.rr.clear();
  }
}
