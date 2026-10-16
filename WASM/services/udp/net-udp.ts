// The UDP socket seam (§12.7): a `ChannelFactory` for `udp:` destinations, a direct path
// between two nodes that hold UDP sockets themselves, with no WebRTC. It is the `rtc:`
// seam's twin and speaks the same negotiation-link messages (net-rtc.ts `RTC_TAG`), so the
// transport signals both the same way. What differs is what the messages hold:
//
//   description  this end's token, 8 random bytes in hex, which every packet to it carries
//   candidate    an IPv4 `host:port` this end's socket may be reached at: its own
//                addresses, then what each STUN server in the configuration sees
//
// Punching is ICE's idea without its machinery. Once an end has the peer's token and a
// candidate it probes every candidate until one answers, and the first answer is its path.
// A probe leaving through a NAT opens it for the peer's probes back, so two ends whose
// NATs keep one public port per socket meet. Nothing here is trusted beyond the token:
// the transport runs its handshake over the data link, as over any other.
//
//   PROBE      [type][receiver's token 8][sender's token 8][stamp f64]
//   PROBE_ACK  [type][receiver's token 8][the probe's stamp f64]
//
// A probe carries its sender's token, so it can be answered, and the path taken, before
// the peer's description has come the long way round. Its source is a candidate too.
// The stream's packets (stream.ts) share the socket; a STUN answer is told apart by its
// cookie.
//
// A path can move. A stream packet from another address means the peer's NAT, or the
// peer, now sends from there, but a packet only shows its token, which anyone who has seen
// one can copy. So this end probes the new address with a random challenge in the stamp's
// place, and moves only when the answer echoes it, from there, and only if that address
// has been heard from more recently than the old one, so a late packet cannot pull the path
// back. A node with no `datagrams` of its own gets Node's (node.ts).
import { type Arrival, type ChannelFactory, type ListenAddress, type RawLink } from "../socket-seam.js";
import { dec, enc, fromHex, toHex } from "../util.js";
import { bindingRequest, isStun, mappedAddress } from "./stun.js";
import { PATH_HEADER, UdpStream } from "./stream.js";

/** One UDP socket. A send that fails (an unresolved name, a full buffer) is a lost
 *  datagram, and `close` lets what is being sent go first. */
export interface DatagramSocket {
  send(bytes: Uint8Array, port: number, host: string): void;
  /** Each datagram's bytes are the receiver's to keep: the platform does not reuse them. */
  onMessage(cb: (bytes: Uint8Array, host: string, port: number) => void): void;
  close(): void;
}

/** What a platform gives the seam: sockets, and its own addresses. */
export interface DatagramPlatform {
  /** An IPv4 socket on a port the OS picks, and that port. */
  bind(): Promise<{ socket: DatagramSocket; port: number }>;
  /** This machine's IPv4 addresses, its host candidates. */
  addresses(): string[];
}

export interface UdpNetworkOptions {
  /** Defaults to Node's `node:dgram`. */
  datagrams?: DatagramPlatform;
}

/** The negotiation link's tags, the `rtc:` seam's own (net-rtc.ts `RTC_TAG`), written out
 *  so this seam stands without that one: the transport signals both kinds the same way. */
const TAG = { OFFER: 0x6f, ANSWER: 0x61, CANDIDATE: 0x63 } as const;
const TYPE_PROBE = 0x70, TYPE_PROBE_ACK = 0x71;
const TOKEN = 8;
const PROBE_BYTES = 1 + 2 * TOKEN + 8, PROBE_ACK_BYTES = 1 + TOKEN + 8;
/** How often every candidate is probed until one answers. */
const PROBE_MS = 50;
/** The most of a peer's candidates probed. The peer names them, so without a cap it could
 *  aim this node's probes at any number of addresses. */
const MAX_PEER_CANDIDATES = 16;
const STUN_TRIES = 4, STUN_RETRY_MS = 500;
const DESCRIPTION = /^[0-9a-f]{16}$/;
const CANDIDATE = /^((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}):(\d{1,5})$/;

interface Addr { host: string; port: number }

function candidateOf(text: string): Addr | null {
  const m = CANDIDATE.exec(text);
  const port = m ? Number(m[2]) : 0;
  return m && port > 0 && port < 65536 ? { host: m[1], port } : null;
}

/** `udp:offer` or `udp:answer`, optionally `?` and an RTCConfiguration as JSON, of which
 *  only the `stun:` servers are read. */
function parseUdpDest(dest: string): { offer: boolean; stun: Addr[] } | null {
  const q = dest.indexOf("?");
  const role = q < 0 ? dest : dest.slice(0, q);
  if (role !== "udp:offer" && role !== "udp:answer") return null;
  let config: unknown = {};
  if (q >= 0) {
    try { config = JSON.parse(dest.slice(q + 1)); } catch { return null; }
  }
  if (typeof config !== "object" || config === null || Array.isArray(config)) return null;
  const stun: Addr[] = [];
  const servers = (config as { iceServers?: unknown }).iceServers;
  for (const s of Array.isArray(servers) ? servers : []) {
    const urls = (s as { urls?: unknown } | null)?.urls;
    for (const u of Array.isArray(urls) ? urls : [urls]) {
      const m = typeof u === "string" ? /^stun:([^:[\]?]+)(?::(\d{1,5}))?$/.exec(u) : null;
      if (m) stun.push({ host: m[1], port: m[2] ? Number(m[2]) : 3478 });
    }
  }
  return { offer: role === "udp:offer", stun };
}

const sameToken = (p: Uint8Array, token: Uint8Array) => {
  for (let i = 0; i < TOKEN; i++) if (p[1 + i] !== token[i]) return false;
  return true;
};

/** The negotiation link: one socket, its candidates and the punch, and the stream that
 *  becomes the data link once a path is found. */
class UdpNegotiation implements RawLink {
  private onMsg: ((bytes: Uint8Array) => void) | null = null;
  private onCls: (() => void) | null = null;
  private readonly token = crypto.getRandomValues(new Uint8Array(TOKEN));
  private peerToken: Uint8Array | null = null;
  private readonly peerCandidates: Addr[] = [];
  private readonly own = new Set<string>();
  /** Own candidates found before the description is up, which must go first. */
  private held: string[] | null = [];
  private socket: DatagramSocket | null = null;
  private path: Addr | null = null;
  /** When the path last carried a packet from the peer. */
  private pathHeard = 0;
  /** An address the peer's packets now come from, being probed before the path moves. */
  private moving: { addr: Addr; challenge: Uint8Array; sentAt: number; heard: number } | null = null;
  private probing: ReturnType<typeof setTimeout> | undefined;
  private readonly asking: { txn: Uint8Array; timer?: ReturnType<typeof setTimeout> }[] = [];
  private dead = false;
  readonly data: UdpStream;

  constructor(private readonly offer: boolean, stun: Addr[], platform: Promise<DatagramPlatform>,
    private readonly onGone: (n: UdpNegotiation) => void, private readonly onOpen: () => void) {
    // The stream stopping, for whatever reason, ends the negotiation.
    this.data = new UdpStream(() => this.fail());
    void this.start(platform, stun);
  }

  private async start(platform: Promise<DatagramPlatform>, stun: Addr[]): Promise<void> {
    let p: DatagramPlatform, bound: { socket: DatagramSocket; port: number };
    try {
      p = await platform;
      bound = await p.bind();
    } catch {
      this.fail();
      return;
    }
    if (this.dead) { bound.socket.close(); return; }
    this.socket = bound.socket;
    bound.socket.onMessage((bytes, host, port) => this.onPacket(bytes, host, port));
    if (this.offer) this.describe();
    for (const a of p.addresses()) this.addOwn(`${a}:${bound.port}`);
    for (const s of stun) this.askStun(s);
    this.probe();
  }

  /** The description, then the candidates that waited for it. */
  private describe(): void {
    this.up(this.offer ? TAG.OFFER : TAG.ANSWER, toHex(this.token));
    const held = this.held ?? [];
    this.held = null;
    for (const c of held) this.up(TAG.CANDIDATE, c);
  }

  private addOwn(c: string): void {
    if (this.own.has(c)) return;
    this.own.add(c);
    if (this.held) this.held.push(c);
    else this.up(TAG.CANDIDATE, c);
  }

  private addPeer(c: Addr): void {
    if (this.peerCandidates.length >= MAX_PEER_CANDIDATES) return;
    if (this.peerCandidates.some((p) => p.host === c.host && p.port === c.port)) return;
    this.peerCandidates.push(c);
    this.probe();
  }

  private askStun(server: Addr): void {
    const txn = crypto.getRandomValues(new Uint8Array(12));
    const request = bindingRequest(txn);
    const entry: { txn: Uint8Array; timer?: ReturnType<typeof setTimeout> } = { txn };
    let tries = 0;
    const ask = () => {
      if (this.dead || tries++ >= STUN_TRIES) return;
      this.socket?.send(request, server.port, server.host);
      entry.timer = setTimeout(ask, STUN_RETRY_MS);
    };
    this.asking.push(entry);
    ask();
  }

  /** Probe every candidate the peer has, until a path is found. */
  private probe(): void {
    if (this.dead || this.path || this.probing || !this.peerToken || !this.socket || this.peerCandidates.length === 0) return;
    const send = () => {
      const p = new Uint8Array(PROBE_BYTES);
      p[0] = TYPE_PROBE;
      p.set(this.peerToken!, 1);
      p.set(this.token, 1 + TOKEN);
      new DataView(p.buffer).setFloat64(1 + 2 * TOKEN, performance.now());
      for (const c of this.peerCandidates) this.socket?.send(p, c.port, c.host);
      this.probing = setTimeout(send, PROBE_MS);
    };
    send();
  }

  private onPacket(p: Uint8Array, host: string, port: number): void {
    if (this.dead) return;
    if (isStun(p)) {
      for (const a of this.asking) {
        const mapped = mappedAddress(p, a.txn);
        if (mapped) { clearTimeout(a.timer); this.addOwn(mapped); }
      }
      return;
    }
    if (p.length < PATH_HEADER || !sameToken(p, this.token)) return;
    if (p[0] === TYPE_PROBE) {
      if (p.length !== PROBE_BYTES) return;
      const ack = new Uint8Array(PROBE_ACK_BYTES);
      ack[0] = TYPE_PROBE_ACK;
      ack.set(p.subarray(1 + TOKEN), 1);
      this.socket?.send(ack, port, host);
      this.peerToken ??= p.slice(1 + TOKEN, 1 + 2 * TOKEN);
      this.addPeer({ host, port });
    } else if (p[0] === TYPE_PROBE_ACK) {
      if (p.length !== PROBE_ACK_BYTES) return;
      if (this.path) this.moved(host, port, p.subarray(1 + TOKEN));
      else this.choose(host, port, performance.now() - new DataView(p.buffer, p.byteOffset).getFloat64(1 + TOKEN));
    } else {
      // The peer has its path, and this is the way back to it.
      if (!this.path) this.choose(host, port);
      else if (host === this.path.host && port === this.path.port) this.pathHeard = performance.now();
      else this.probeMove(host, port);
      this.data.receive(p);
    }
  }

  /** The peer's packets come from an address that is not the path: challenge it, at most
   *  once a `PROBE_MS` while they keep coming. */
  private probeMove(host: string, port: number): void {
    const now = performance.now();
    let m = this.moving;
    if (m && m.addr.host === host && m.addr.port === port) {
      m.heard = now;
      if (now - m.sentAt < PROBE_MS) return;
    } else {
      m = this.moving = { addr: { host, port }, challenge: crypto.getRandomValues(new Uint8Array(8)), sentAt: 0, heard: now };
    }
    m.sentAt = now;
    const probe = new Uint8Array(PROBE_BYTES);
    probe[0] = TYPE_PROBE;
    probe.set(this.peerToken!, 1);
    probe.set(this.token, 1 + TOKEN);
    probe.set(m.challenge, 1 + 2 * TOKEN);
    this.socket?.send(probe, port, host);
  }

  /** An answer to a challenge: the path moves, if it came from the address challenged and
   *  that address is the one the peer was heard from last. */
  private moved(host: string, port: number, echoed: Uint8Array): void {
    const m = this.moving;
    if (!m || m.addr.host !== host || m.addr.port !== port || m.heard < this.pathHeard) return;
    for (let i = 0; i < 8; i++) if (echoed[i] !== m.challenge[i]) return;
    this.moving = null;
    this.path = m.addr;
    this.pathHeard = m.heard;
    this.data.repath(performance.now() - m.sentAt);
  }

  private choose(host: string, port: number, rttMs?: number): void {
    if (this.path || !this.peerToken) return;
    this.path = { host, port };
    this.pathHeard = performance.now();
    clearTimeout(this.probing);
    const token = this.peerToken;
    this.data.start((p) => {
      p.set(token, 1);
      this.socket?.send(p, this.path!.port, this.path!.host);
    }, rttMs);
    this.onOpen();
  }

  private up(tag: number, text: string): void {
    if (this.dead || !this.onMsg) return;
    const body = enc.encode(text);
    const msg = new Uint8Array(1 + body.length);
    msg[0] = tag;
    msg.set(body, 1);
    this.onMsg(msg);
  }

  send(bytes: Uint8Array): void {
    if (this.dead) throw new Error("udp: negotiation is closed");
    if (bytes.length === 0) throw new Error("udp: empty negotiation message");
    const tag = bytes[0], text = dec.decode(bytes.subarray(1));
    if (tag === TAG.OFFER || tag === TAG.ANSWER) {
      // An offer reaches only the answering side, an answer only the offering one.
      if ((tag === TAG.OFFER) === this.offer) throw new Error("udp: description for the wrong role");
      if (!DESCRIPTION.test(text)) throw new Error("udp: malformed description");
      this.peerToken = fromHex(text);
      // Up on a later turn, not inside the occupant's own write.
      if (tag === TAG.OFFER) queueMicrotask(() => { if (!this.dead && this.held) this.describe(); });
      this.probe();
    } else if (tag === TAG.CANDIDATE) {
      const c = candidateOf(text);
      if (!c) throw new Error("udp: malformed candidate");
      this.addPeer(c);
    } else {
      throw new Error("udp: unknown negotiation message");
    }
  }

  buffered(): number { return 0; }
  onData(cb: (bytes: Uint8Array) => void): void { this.onMsg = cb; }
  onClose(cb: () => void): void { this.onCls = cb; }

  close(): void {
    if (this.dead) return;
    this.dead = true;
    clearTimeout(this.probing);
    for (const a of this.asking) clearTimeout(a.timer);
    this.data.end();
    this.socket?.close();
    this.socket = null;
    this.onGone(this);
  }

  /** The path ended, or never began: close both links and tell the driver about this one. */
  private fail(): void {
    if (this.dead) return;
    this.close();
    this.onCls?.();
  }
}

export class UdpNetwork implements ChannelFactory {
  private readonly platform: () => Promise<DatagramPlatform>;
  private onAccept: ((channel: RawLink, arrival?: Arrival) => void) | null = null;
  private readonly live = new Set<UdpNegotiation>();

  constructor(opts: UdpNetworkOptions = {}) {
    const given = opts.datagrams;
    this.platform = given ? () => Promise.resolve(given) : () => import("./node.js").then((m) => m.nodeDatagrams);
  }

  /** A negotiation link for `udp:offer` or `udp:answer`. Its data link is announced once a
   *  path is found; how long finding one may take is the occupant's deadline. */
  connect(dest: string): RawLink | null {
    const d = parseUdpDest(dest);
    const accept = this.onAccept;
    if (!d || !accept) return null;
    const n = new UdpNegotiation(d.offer, d.stun, this.platform(), (gone) => this.live.delete(gone),
      () => accept(n.data, { via: n }));
    this.live.add(n);
    return n;
  }

  /** Binds nothing; only keeps the sink data links are announced through. */
  async listen(
    addrs: readonly ListenAddress[],
    onAccept: (channel: RawLink, arrival?: Arrival) => void,
  ): Promise<number[]> {
    this.onAccept = onAccept;
    return addrs.map(() => 0);
  }

  close(): void {
    this.onAccept = null;
    for (const n of [...this.live]) n.close();
  }
}
