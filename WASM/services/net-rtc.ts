// The WebRTC socket seam (§12.7): a `ChannelFactory` for `rtc:` destinations. A browser has
// no UDP, so its only peer-to-peer primitive is the platform's RTCPeerConnection, and a
// confined guest cannot hold a platform object. This file holds it and nothing else: every
// decision — which peers to connect, the signaling relay and its wire, who offers, when to
// restart ICE, how long a negotiation may take — is the transport bundle's.
//
// A peer connection is two links. `link/open("rtc:offer")` or `"rtc:answer"` opens the
// NEGOTIATION link: its messages are the local descriptions, candidates and connection states
// going up, and the remote descriptions, candidates and ICE restarts coming down, each
// `[tag u8][UTF-8 text]` (below) — the W3C verbs, passed through without a reading of their
// contents. The pre-agreed data channel (`negotiated`, id 0, on both sides) arrives as the
// DATA link, announced with the negotiation link as its `via`, so neither side is "the dialer"
// as far as the host can tell. Closing either link closes both.
//
// Only the offering side ever offers — its `negotiationneeded` sets a local description, the
// answering side's is ignored — so there is no glare to resolve here. Bounds are the driver's:
// each link is an entry under `maxRawLinks`, what the guest writes is outbound custody
// (`buffered`), and what the platform emits reaches the guest as an ordinary read.
//
// Browser-native, but the platform global is referenced only inside `connect`, so importing
// this under Node is safe — a console peer passes its own `peerConnectionFactory`.
import { MessageChannel } from "./net-channel.js";
import { type Arrival, type ChannelFactory, type ListenAddress, type RawLink } from "./socket-seam.js";
import { enc, dec } from "./util.js";

export interface RtcNetworkOptions {
  /** Factory for the underlying RTCPeerConnection. Defaults to the platform global; a
   *  Node/Bun console node supplies its own (a pure-JS WebRTC library wrapped to the
   *  W3C surface used here) so this exact seam runs off-browser. */
  peerConnectionFactory?: (config?: RTCConfiguration) => RTCPeerConnection;
}

// Keep physical data-channel messages below the conservative cross-browser ceiling while
// exposing an ordered byte stream to the transport. Its existing bounded length framer
// restores record boundaries, so storage can coalesce several blocks per encrypted record
// without asking WebRTC to carry that record as one message.
export const RTC_CHUNK_BYTES = 48 * 1024;

export class RtcChannel extends MessageChannel {
  /** Exposes chunked RTC messages as a byte stream, preserving large writes. */
  readonly stream = true;
  constructor(dc: RTCDataChannel) { super(dc); }
  protected override write(bytes: Uint8Array): void {
    for (let off = 0; off < bytes.length; off += RTC_CHUNK_BYTES) {
      super.write(bytes.subarray(off, Math.min(bytes.length, off + RTC_CHUNK_BYTES)));
    }
  }
  /** Close it as a failure, so its owner hears it: the peer connection under it is gone. */
  end(): void { this.fail(); }
}

/** The negotiation link's message tags. Up (host → guest): a local description, a local
 *  candidate, a connection state. Down (guest → host): a remote description, a remote
 *  candidate, an ICE restart. A candidate is its four W3C fields NUL-separated — NUL is
 *  outside SDP's and ICE's grammar — an absent one empty. */
export const RTC_TAG = { OFFER: 0x6f, ANSWER: 0x61, CANDIDATE: 0x63, STATE: 0x73, RESTART: 0x72 } as const;

/** One message on the negotiation link. */
function message(tag: number, text = ""): Uint8Array {
  const body = enc.encode(text);
  const out = new Uint8Array(1 + body.length);
  out[0] = tag;
  out.set(body, 1);
  return out;
}

function candidateText(c: RTCIceCandidateInit): string {
  return [c.candidate ?? "", c.sdpMid ?? "", c.sdpMLineIndex?.toString() ?? "", c.usernameFragment ?? ""].join("\0");
}

/** The guest's candidate, or undefined for a malformed one. */
function candidateOf(text: string): RTCIceCandidateInit | undefined {
  const parts = text.split("\0");
  if (parts.length !== 4) return undefined;
  const [candidate, sdpMid, line, ufrag] = parts;
  const c: RTCIceCandidateInit = { candidate };
  if (sdpMid !== "") c.sdpMid = sdpMid;
  if (line !== "") {
    const n = Number(line);
    if (!Number.isInteger(n) || n < 0 || n > 0xffff || String(n) !== line) return undefined;
    c.sdpMLineIndex = n;
  }
  if (ufrag !== "") c.usernameFragment = ufrag;
  return c;
}

/** `rtc:offer` or `rtc:answer`, optionally `?` and an RTCConfiguration as JSON. */
function parseRtcDest(dest: string): { offer: boolean; config?: RTCConfiguration } | null {
  const q = dest.indexOf("?");
  const role = q < 0 ? dest : dest.slice(0, q);
  if (role !== "rtc:offer" && role !== "rtc:answer") return null;
  if (q < 0) return { offer: role === "rtc:offer" };
  let config: unknown;
  try { config = JSON.parse(dest.slice(q + 1)); } catch { return null; }
  if (typeof config !== "object" || config === null || Array.isArray(config)) return null;
  return { offer: role === "rtc:offer", config: config as RTCConfiguration };
}

/** The negotiation link: one RTCPeerConnection, driven by the messages its occupant writes. */
class RtcNegotiation implements RawLink {
  private onMsg: ((bytes: Uint8Array) => void) | null = null;
  private onCls: (() => void) | null = null;
  /** Guest writes not yet applied, in order: `setRemoteDescription` and `addIceCandidate`
   *  are asynchronous, and a candidate must not overtake the description it belongs to. */
  private work: Promise<void> = Promise.resolve();
  private pendingBytes = 0;
  /** Local candidates gathered while a local description is being set, held until it has
   *  gone up: a platform may gather before `setLocalDescription` resolves, and a candidate
   *  that reaches the peer ahead of its description is one the peer drops. Null passes them
   *  straight through. */
  private held: string[] | null = [];
  private dead = false;
  readonly data: RtcChannel;

  constructor(private readonly pc: RTCPeerConnection, private readonly offer: boolean,
    private readonly onGone: (n: RtcNegotiation) => void, onOpen: () => void) {
    const dc = pc.createDataChannel("seedkernel", { negotiated: true, id: 0, ordered: true });
    this.data = new RtcChannel(dc);
    // After RtcChannel's own listener, so the channel has flushed and is writable.
    dc.addEventListener("open", () => { if (!this.dead) onOpen(); });
    // The data channel going is the connection going: one peer, one channel, never re-bound.
    // On the platform object, because the driver owns the data link's own `onClose`.
    dc.addEventListener("close", () => this.fail());
    dc.addEventListener("error", () => this.fail());
    pc.addEventListener("icecandidate", (ev) => {
      const c = ev.candidate?.toJSON();
      if (typeof c?.candidate !== "string" || c.candidate === "") return;
      if (this.held) this.held.push(candidateText(c));
      else this.up(RTC_TAG.CANDIDATE, candidateText(c));
    });
    pc.addEventListener("negotiationneeded", () => {
      if (this.offer) this.chain(() => this.describe());
    });
    pc.addEventListener("connectionstatechange", () => {
      const s = pc.connectionState;
      this.up(RTC_TAG.STATE, s);
      if (s === "failed" || s === "closed") this.fail();
    });
  }

  /** Set the implicit local description and hand it to the occupant. */
  private async describe(): Promise<void> {
    this.held ??= [];
    await this.pc.setLocalDescription();
    const d = this.pc.localDescription;
    if (d && typeof d.sdp === "string") this.up(d.type === "offer" ? RTC_TAG.OFFER : RTC_TAG.ANSWER, d.sdp);
    const held = this.held;
    this.held = null;
    for (const c of held) this.up(RTC_TAG.CANDIDATE, c);
  }

  private up(tag: number, text: string): void {
    if (!this.dead) this.onMsg?.(message(tag, text));
  }

  /** Run one platform operation after every earlier one. A rejection is the platform
   *  refusing this peer's input — stale after an ICE restart, or malformed — and is dropped:
   *  a negotiation that cannot complete is ended by its occupant's own deadline. */
  private chain(op: () => Promise<void>, bytes = 0): void {
    this.pendingBytes += bytes;
    this.work = this.work.then(() => (this.dead ? undefined : op())).catch(() => {})
      .then(() => { this.pendingBytes -= bytes; });
  }

  send(bytes: Uint8Array): void {
    if (this.dead) throw new Error("rtc: negotiation is closed");
    if (bytes.length === 0) throw new Error("rtc: empty negotiation message");
    const tag = bytes[0];
    const text = dec.decode(bytes.subarray(1));
    if (tag === RTC_TAG.OFFER || tag === RTC_TAG.ANSWER) {
      // An offer reaches only the answering side, an answer only the offering one.
      if ((tag === RTC_TAG.OFFER) === this.offer) throw new Error("rtc: description for the wrong role");
      const type = tag === RTC_TAG.OFFER ? "offer" : "answer";
      this.chain(async () => {
        await this.pc.setRemoteDescription({ type, sdp: text });
        if (type === "offer") await this.describe();
      }, bytes.length);
    } else if (tag === RTC_TAG.CANDIDATE) {
      const c = candidateOf(text);
      if (!c) throw new Error("rtc: malformed candidate");
      this.chain(() => this.pc.addIceCandidate(c), bytes.length);
    } else if (tag === RTC_TAG.RESTART) {
      try { this.pc.restartIce(); } catch { /* nothing to restart */ }
    } else {
      throw new Error("rtc: unknown negotiation message");
    }
  }

  buffered(): number { return this.pendingBytes; }
  onData(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; }
  onClose(cb: () => void): void { this.onCls = cb; }

  close(): void {
    if (this.dead) return;
    this.dead = true;
    this.data.end();
    try { this.pc.close(); } catch { /* already closed */ }
    this.onGone(this);
  }

  /** The platform ended it: close both links and tell the driver about this one. */
  private fail(): void {
    if (this.dead) return;
    this.close();
    this.onCls?.();
  }
}

export class RtcNetwork implements ChannelFactory {
  private readonly makePc: (config?: RTCConfiguration) => RTCPeerConnection;
  private onAccept: ((channel: RawLink, arrival?: Arrival) => void) | null = null;
  private readonly live = new Set<RtcNegotiation>();

  constructor(opts: RtcNetworkOptions = {}) {
    this.makePc = opts.peerConnectionFactory ?? ((cfg) => new RTCPeerConnection(cfg));
  }

  /** A negotiation link for `rtc:offer` / `rtc:answer`; every other destination is not
   *  this factory's. Its data link is announced once the channel opens — so the occupant's
   *  handshake clock starts when there is a channel to speak on, and how long connecting may
   *  take is the occupant's own deadline on the negotiation link. */
  connect(dest: string): RawLink | null {
    const d = parseRtcDest(dest);
    const accept = this.onAccept;
    if (!d || !accept) return null;
    const n = new RtcNegotiation(this.makePc(d.config), d.offer, (gone) => this.live.delete(gone),
      () => accept(n.data, { via: n }));
    this.live.add(n);
    return n;
  }

  /** Binds nothing: the sink is what data links are announced through. */
  async listen(
    addrs: readonly ListenAddress[],
    onAccept: (channel: RawLink, arrival?: Arrival) => void,
  ): Promise<number[]> {
    this.onAccept = onAccept;
    return addrs.map(() => 0);
  }

  /** Close every peer connection. */
  close(): void {
    this.onAccept = null;
    for (const n of [...this.live]) n.close();
  }
}
