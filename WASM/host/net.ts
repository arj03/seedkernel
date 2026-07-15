// net.send transport (README §13.6) + a request/response layer over it.
//
// net.send is "addressed unicast to a peer over its data channel" and is async
// by nature — it returns a correlation id and the host later delivers the
// response (§13.6). This module provides:
//   - Network:   the delivery fabric. LoopbackNetwork wires nodes in-process
//                for tests; a WebRTC/data-channel or TCP implementation (see
//                net-node.ts) satisfies the same interface in a real deployment.
//   - Transport: per-node request/response keyed by correlation id — a single
//                frame plane (§13.6). Block bytes ride it too: a STORE pushes
//                bytes in a `req` body and a FETCH returns them in a `res` body,
//                so the §13.6 record layer authenticates and encrypts them along
//                with every other frame. There is deliberately no separate
//                unauthenticated bulk path.
//
// Frames on the wire (carried inside the §13.6 AEAD record layer):
//   req/res = [0|1 kind][corr u32 BE][type u8][payload ...]

import { writeU32BE, readU32BE } from "./util.js";

export type PeerId = string; // hex of the peer's kernel public key

const KIND_REQ = 0;
const KIND_RES = 1;

/** The delivery fabric. send() is fire-and-forget unicast; the receiver's
 *  registered sink is invoked with the raw frame. */
export interface Network {
  send(from: PeerId, to: PeerId, frame: Uint8Array): void;
  register(peerId: PeerId, sink: (from: PeerId, frame: Uint8Array) => void): void;
  unregister(peerId: PeerId): void;
}

/** In-process network for tests and single-process multi-node demos. Delivery
 *  is asynchronous (a microtask) to mirror a real data channel. A peer can be
 *  taken offline to model churn: frames to or from it are dropped, so the
 *  sender's request rejects and the cohort tips it toward Suspected/Lost. */
export class LoopbackNetwork implements Network {
  private sinks = new Map<PeerId, (from: PeerId, frame: Uint8Array) => void>();
  private offline = new Set<PeerId>();
  /** Total frames delivered — handy for asserting traffic in tests. */
  framesDelivered = 0;

  register(peerId: PeerId, sink: (from: PeerId, frame: Uint8Array) => void): void {
    this.sinks.set(peerId, sink);
  }
  unregister(peerId: PeerId): void {
    this.sinks.delete(peerId);
  }
  setOnline(peerId: PeerId, online: boolean): void {
    if (online) this.offline.delete(peerId);
    else this.offline.add(peerId);
  }
  isOnline(peerId: PeerId): boolean {
    return this.sinks.has(peerId) && !this.offline.has(peerId);
  }
  send(from: PeerId, to: PeerId, frame: Uint8Array): void {
    if (this.offline.has(from) || this.offline.has(to)) return; // dropped
    const sink = this.sinks.get(to);
    if (!sink) return;
    const copy = frame.slice();
    queueMicrotask(() => {
      if (this.offline.has(from) || this.offline.has(to)) return;
      this.framesDelivered++;
      sink(from, copy);
    });
  }
}

export type RequestHandler = (from: PeerId, type: number, payload: Uint8Array) => Uint8Array | Promise<Uint8Array> | null;

interface Pending {
  /** The peer the request went to — a response only resolves if it arrives from
   *  this peer, so an authenticated-but-malicious cohort member cannot spoof a
   *  response on behalf of another peer by guessing the correlation counter. */
  to: PeerId;
  resolve: (payload: Uint8Array) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  /** When the request was issued — the floor of its silence clock (see request()). */
  issuedAt: number;
}

/** Per-node request/response transport over a Network — a single frame plane. */
export class Transport {
  private corr = 1;
  private pending = new Map<number, Pending>();
  /** Most-recent frame arrival time per peer — the O(1) liveness signal every pending
   *  request to that peer reads to decide whether it has stalled (see onFrame/request). */
  private lastFrameAt = new Map<PeerId, number>();
  private reqHandler: RequestHandler | null = null;

  constructor(
    readonly peerId: PeerId,
    private readonly net: Network,
    /** How long a peer may stay SILENT before a request to it is treated as
     *  unreachable (§13.6). This is a stall bound, not an absolute deadline: any
     *  frame arriving from the peer re-arms the clock of every request pending to
     *  it (see request()). Small in tests; a deployment tunes it against real
     *  latency. */
    private readonly timeoutMs = 200,
  ) {
    this.net.register(peerId, (from, frame) => this.onFrame(from, frame));
  }

  onRequest(handler: RequestHandler): void { this.reqHandler = handler; }

  /** Send a typed control request and await the typed response. Rejects when the
   *  peer stalls — no frame of any kind from it for timeoutMs. The clock is
   *  re-armed by every arriving frame from that peer rather than fixed at issue
   *  time: a bulk fan-out (a PUT's STORE round) hands the socket many queued
   *  megabytes against one issue instant, so an absolute deadline would fail the
   *  tail of a transfer that is visibly progressing on a slow link. A dead peer
   *  still rejects after exactly timeoutMs of silence; a peer that keeps
   *  responding can never string one request along forever, because each reset
   *  costs it a delivered frame. */
  request(to: PeerId, type: number, payload: Uint8Array): Promise<Uint8Array> {
    const corr = this.corr++;
    const frame = new Uint8Array(1 + 4 + 1 + payload.length);
    frame[0] = KIND_REQ;
    writeU32BE(frame, 1, corr);
    frame[5] = type & 255;
    frame.set(payload, 6);
    return new Promise<Uint8Array>((resolve, reject) => {
      const issuedAt = Date.now();
      // Silence-based stall clock, re-armed lazily. On expiry, reject only if the peer
      // has been silent for timeoutMs since the later of this request's issue time and
      // the peer's last frame; otherwise a frame arrived recently (a bulk fan-out is
      // still progressing), so re-arm just this one timer for the remaining window. The
      // liveness signal is the single per-peer timestamp updated O(1) in onFrame — no
      // per-frame sweep over every pending request.
      const check = (): void => {
        const p = this.pending.get(corr);
        if (!p) return;
        const last = Math.max(issuedAt, this.lastFrameAt.get(to) ?? 0);
        const remaining = last + this.timeoutMs - Date.now();
        if (remaining > 0) { p.timer = setTimeout(check, remaining); return; }
        this.pending.delete(corr);
        reject(new Error(`net.send: timeout to ${to.slice(0, 8)} (type ${type})`));
      };
      const timer = setTimeout(check, this.timeoutMs);
      this.pending.set(corr, { to, resolve, reject, timer, issuedAt });
      this.net.send(this.peerId, to, frame);
    });
  }

  /** Scatter-gather: send the same typed request to many peers and gather the
   *  responses that arrive before the timeout. One entry per input peer (order
   *  preserved); an unreachable or timed-out peer comes back `ok:false` with no
   *  bytes (partial results, never a reject). This is the one concurrency a
   *  confined safe-js guest cannot do itself — `Promise.all` aborts the VM, so
   *  the fan-out lives host-side and the guest just consumes a finished list. */
  async requestMany(
    peers: PeerId[],
    type: number,
    payload: Uint8Array,
  ): Promise<{ peer: PeerId; ok: boolean; bytes: Uint8Array }[]> {
    return Promise.all(
      peers.map(async (peer) => {
        try {
          return { peer, ok: true, bytes: await this.request(peer, type, payload) };
        } catch {
          return { peer, ok: false, bytes: new Uint8Array(0) };
        }
      }),
    );
  }

  /** Per-peer scatter-gather: send a *distinct* typed request to each peer and
   *  gather the responses that arrive before the timeout. The general case of
   *  `requestMany` (which is this with one shared payload broadcast to all). One
   *  entry per input request, order preserved; an unreachable/timed-out peer comes
   *  back `ok:false` with no bytes (partial results, never a reject). This is the
   *  app-neutral parallel primitive a confined safe-js guest drives one batched cap
   *  at a time — `Promise.all` aborts the VM, so the fan-out lives here and the
   *  sync guest just consumes a finished list (see cap-bridge NET_SEND_MANY). */
  async sendMany(
    requests: { peer: PeerId; type: number; payload: Uint8Array }[],
  ): Promise<{ peer: PeerId; ok: boolean; bytes: Uint8Array }[]> {
    return Promise.all(
      requests.map(async ({ peer, type, payload }) => {
        try {
          return { peer, ok: true, bytes: await this.request(peer, type, payload) };
        } catch {
          return { peer, ok: false, bytes: new Uint8Array(0) };
        }
      }),
    );
  }

  close(): void {
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new Error("transport closed")); }
    this.pending.clear();
    this.lastFrameAt.clear();
    this.net.unregister(this.peerId);
  }

  private onFrame(from: PeerId, frame: Uint8Array): void {
    // Liveness proof: record this peer's most-recent frame time. Every request pending to
    // it reads this as its stall clock (the timeout is silence-based — see request()), so
    // a frame costs one O(1) timestamp write instead of clearing + re-arming a timer for
    // every pending request on the hot receive path. Each pending timer re-arms itself
    // lazily off this stamp when it fires.
    this.lastFrameAt.set(from, Date.now());
    const kind = frame[0];
    const corr = readU32BE(frame, 1);
    if (kind === KIND_RES) {
      const p = this.pending.get(corr);
      if (!p) return;
      // Bind the response to the request's target: a frame from anyone else is
      // dropped (the real response can still arrive before the timeout).
      if (p.to !== from) return;
      clearTimeout(p.timer);
      this.pending.delete(corr);
      p.resolve(frame.slice(6));
      return;
    }
    // KIND_REQ — dispatch to the node's handler and reply with the same corr.
    if (kind === KIND_REQ) {
      const type = frame[5];
      const payload = frame.slice(6);
      void this.dispatchRequest(from, corr, type, payload);
    }
  }

  private async dispatchRequest(from: PeerId, corr: number, type: number, payload: Uint8Array): Promise<void> {
    let resp: Uint8Array | null = null;
    if (this.reqHandler) {
      try {
        const r = this.reqHandler(from, type, payload);
        resp = r instanceof Promise ? await r : r;
      } catch {
        resp = null;
      }
    }
    const body = resp ?? new Uint8Array(0);
    const frame = new Uint8Array(6 + body.length);
    frame[0] = KIND_RES;
    writeU32BE(frame, 1, corr);
    frame[5] = type & 255;
    frame.set(body, 6);
    this.net.send(this.peerId, from, frame);
  }
}
