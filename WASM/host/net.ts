// net.send transport (README §12.6) + a request/response layer over it.
//
// net.send is "addressed unicast to a peer over its data channel" and is async
// by nature — it returns a correlation id and the host later delivers the
// response (§12.6). This module provides:
//   - Network:   the delivery fabric. It vends a per-node Endpoint bound to one
//                id; LoopbackNetwork multiplexes many in-process nodes over one
//                fabric for tests, and a WebRTC/data-channel or TCP transport (see
//                net-node.ts) is a single-identity fabric satisfying the same shape.
//   - Endpoint:  one node's attachment to the fabric — send(to, frame) with the
//                sender implicit, plus an onFrame sink.
//   - Transport: per-node request/response keyed by correlation id — a single
//                frame plane (§12.6). Block bytes ride it too: a STORE pushes
//                bytes in a `req` body and a FETCH returns them in a `res` body,
//                so the §12.6 record layer authenticates and encrypts them along
//                with every other frame. There is deliberately no separate
//                unauthenticated bulk path.
//
// Frames on the wire (carried inside the §12.6 AEAD record layer):
//   req = [0 kind][corr u32 BE][type u8][payload ...]
//   res = [1 kind][corr u32 BE][payload ...]   (no type — the requester matches
//         the response to its request by corr; the type it sent is what it wanted)

import { writeU32BE, readU32BE } from "./util.js";

export type PeerId = string; // hex of the peer's kernel public key

const KIND_REQ = 0;
const KIND_RES = 1;

// Absolute backstop, as a multiple of timeoutMs (see Transport.request). The silence
// clock re-arms on any frame from the peer, so on its own it never bounds a request
// whose response will never come while the peer keeps sending *other* frames. This caps
// that. Generous — a legit bulk request's tail waits out the whole concurrent batch
// draining to the peer — but finite, so a busy-and-buggy or hostile peer can't pin the
// pending map forever.
const DEFAULT_MAX_STALL_WINDOWS = 50;

/** A node's attachment to a Network: an endpoint is bound to one local id, so
 *  `send` names only the destination — the sender is implicit. Transport (and the
 *  browser shells) hold one of these rather than the whole fabric, which is why no
 *  `from` rides the hot send path. */
export interface Endpoint {
  /** Unicast `frame` to peer `to`. The sender is this endpoint's own id. */
  send(to: PeerId, frame: Uint8Array): void;
  /** Route inbound frames to `sink` (`from` is the sending peer's id). Last set wins. */
  onFrame(sink: (from: PeerId, frame: Uint8Array) => void): void;
  /** Detach from the fabric: stop delivering; a real transport also tears down. */
  close(): void;
}

/** The delivery fabric. It vends a per-node {@link Endpoint} for a local id.
 *  LoopbackNetwork multiplexes many in-process nodes over one fabric; a real
 *  transport (net-node/net-rtc/net-ws) is a single-identity fabric that vends only
 *  its own endpoint. */
export interface Network {
  endpoint(id: PeerId): Endpoint;
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

  /** An endpoint for `id`. Every in-process node calls this for its own id; the
   *  endpoints share this one fabric, and each send attributes `from = id`. */
  endpoint(id: PeerId): Endpoint {
    return {
      send: (to, frame) => this.deliver(id, to, frame),
      onFrame: (sink) => { this.sinks.set(id, sink); },
      close: () => { this.sinks.delete(id); },
    };
  }
  setOnline(peerId: PeerId, online: boolean): void {
    if (online) this.offline.delete(peerId);
    else this.offline.add(peerId);
  }
  isOnline(peerId: PeerId): boolean {
    return this.sinks.has(peerId) && !this.offline.has(peerId);
  }
  private deliver(from: PeerId, to: PeerId, frame: Uint8Array): void {
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
  /** This node's attachment to the fabric — bound to peerId, so sends carry no `from`. */
  private readonly endpoint: Endpoint;

  constructor(
    readonly peerId: PeerId,
    net: Network,
    /** How long a peer may stay SILENT before a request to it is treated as
     *  unreachable (§12.6). This is a stall bound, not an absolute deadline: any
     *  frame arriving from the peer re-arms the clock of every request pending to
     *  it (see request()). Small in tests; a deployment tunes it against real
     *  latency. */
    private readonly timeoutMs = 200,
    /** Hard ceiling on a single request's lifetime, as a multiple of timeoutMs — the
     *  backstop the silence clock lacks. A request rejects after this many silence
     *  windows since it was issued regardless of how live the peer looks, so a peer that
     *  withholds one response while keeping the wire warm (buggy or hostile) cannot pin
     *  the pending map indefinitely. Kept generous so it never kills a legit bulk
     *  request whose tail is genuinely still draining. */
    private readonly maxStallWindows = DEFAULT_MAX_STALL_WINDOWS,
  ) {
    this.endpoint = net.endpoint(peerId);
    this.endpoint.onFrame((from, frame) => this.onFrame(from, frame));
  }

  onRequest(handler: RequestHandler): void { this.reqHandler = handler; }

  /** Send a typed control request and await the typed response. Rejects when the
   *  peer stalls — no frame of any kind from it for timeoutMs. The clock is
   *  re-armed by every arriving frame from that peer rather than fixed at issue
   *  time: a bulk fan-out (a PUT's STORE round) hands the socket many queued
   *  megabytes against one issue instant, so an absolute deadline would fail the
   *  tail of a transfer that is visibly progressing on a slow link. A dead peer
   *  still rejects after exactly timeoutMs of silence.
   *
   *  Silence is not the only failure signal, though: a peer that withholds *this*
   *  response while other traffic keeps flowing (a hung/declining handler, or a
   *  hostile peer selectively answering) would re-arm the clock forever. So a
   *  second, absolute backstop rejects after maxStallWindows silence windows since
   *  issue no matter how live the peer looks — finite, but generous enough never to
   *  fire on a legit request whose tail is still draining. */
  request(to: PeerId, type: number, payload: Uint8Array): Promise<Uint8Array> {
    const corr = this.corr++;
    const frame = new Uint8Array(1 + 4 + 1 + payload.length);
    frame[0] = KIND_REQ;
    writeU32BE(frame, 1, corr);
    frame[5] = type & 255;
    frame.set(payload, 6);
    return new Promise<Uint8Array>((resolve, reject) => {
      const issuedAt = Date.now();
      // Absolute deadline the per-frame re-arm cannot push out (see maxStallWindows).
      const deadline = issuedAt + this.timeoutMs * this.maxStallWindows;
      // Silence-based stall clock, re-armed lazily. On expiry, reject if the peer has
      // been silent for timeoutMs since the later of this request's issue time and the
      // peer's last frame; otherwise a frame arrived recently (a bulk fan-out is still
      // progressing), so re-arm just this one timer for the remaining window — but never
      // past the absolute backstop, so a live-but-withholding peer still rejects. The
      // liveness signal is the single per-peer timestamp updated O(1) in onFrame — no
      // per-frame sweep over every pending request.
      const check = (): void => {
        const p = this.pending.get(corr);
        if (!p) return;
        const now = Date.now();
        const last = Math.max(issuedAt, this.lastFrameAt.get(to) ?? 0);
        const remaining = last + this.timeoutMs - now;
        if (remaining > 0 && now < deadline) {
          p.timer = setTimeout(check, Math.min(remaining, deadline - now));
          return;
        }
        this.pending.delete(corr);
        const why = remaining > 0 ? "backstop" : "timeout"; // live-but-withholding vs. silent
        reject(new Error(`net.send: ${why} to ${to.slice(0, 8)} (type ${type})`));
      };
      const timer = setTimeout(check, this.timeoutMs);
      this.pending.set(corr, { to, resolve, reject, timer, issuedAt });
      this.endpoint.send(to, frame);
    });
  }

  /** Per-peer scatter-gather: send a *distinct* typed request to each peer and
   *  gather the responses that arrive before the timeout. A broadcast of one shared
   *  payload to many peers is just N identical entries. One entry per input request,
   *  order preserved; an unreachable/timed-out peer comes back `ok:false` with no
   *  bytes (partial results, never a reject). This is the one concurrency a confined
   *  safe-js guest cannot do itself — `Promise.all` aborts the VM, so the fan-out
   *  lives host-side and the sync guest just consumes a finished list (see cap-bridge
   *  NET_SEND_MANY). */
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
    this.endpoint.close();
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
      p.resolve(frame.slice(5)); // res = [1][corr u32][payload] — no type byte
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
    // res carries no type byte: the requester matches by corr and already knows the
    // type it asked for. (req still carries it — that's how the responder dispatches.)
    const frame = new Uint8Array(5 + body.length);
    frame[0] = KIND_RES;
    writeU32BE(frame, 1, corr);
    frame.set(body, 5);
    this.endpoint.send(from, frame);
  }
}
