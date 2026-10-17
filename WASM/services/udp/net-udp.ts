// The UDP socket seam (§12.7): a `ChannelFactory` for `udp:` destinations, a direct path
// between two nodes that hold UDP sockets themselves, with no WebRTC. It is the `rtc:`
// seam's twin and speaks the same negotiation-link messages (net-rtc.ts `RTC_TAG`), so the
// transport signals both the same way. What differs is what the messages hold:
//
//   description  this end's token, 8 random bytes in hex, which every packet to it carries
//   candidate    an IPv4 `host:port` or IPv6 `[host]:port` this end's socket may be
//                reached at: its own addresses, then what each STUN server in the
//                configuration sees; or `host:*`, this end's NAT gives each destination its
//                own port (below)
//
// Punching is ICE's idea without its machinery. Once an end has the peer's token and a
// candidate it probes every candidate until one answers, and the first answer is its path.
// A probe leaving through a NAT opens it for the peer's probes back, so two ends whose
// NATs keep one public port per socket meet. Nothing here is trusted beyond the token:
// the transport runs its handshake over the data link, as over any other.
//
// A socket is dual-stack where the machine has IPv6. An IPv6 address is mostly routed end
// to end, behind a firewall that lets replies in, which the same probes open as they open
// a NAT that keeps one port, so two ends with IPv6 meet whatever NATs their IPv4 is
// behind. The STUN servers are asked over IPv4: an IPv6 address needs no one to name it.
//
// A NAT that gives each destination its own random port (endpoint-dependent mapping, a
// symmetric NAT) is hard: its STUN address is good for the STUN server alone. Two STUN
// answers that differ tell an end it is behind one, and it says so with a `host:*`
// candidate. Against a NAT that filters, the plain punch then cannot meet, so after
// `BIRTHDAY_AFTER_MS` without a path the two ends play the birthday paradox, as Tailscale
// does: the hard end opens `BIRTHDAY_SOCKETS` more sockets, each probing the peer and so
// opening a port of its own toward it, and the easy end, whose two answers agreed, probes
// random ports at the hard end's address until one of its probes lands on one of them.
// Two hard ends cannot meet this way, and stay on the relay.
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

/** One UDP socket. A host is an IPv4 address dotted, an IPv6 one as `ipv6Text` writes it,
 *  or a name, which resolves to IPv4. A send that fails (an unresolved name, a full buffer,
 *  IPv6 on a machine without it) is a lost datagram, and `close` lets what is being sent
 *  go first. */
export interface DatagramSocket {
  send(bytes: Uint8Array, port: number, host: string): void;
  /** Each datagram's bytes are the receiver's to keep: the platform does not reuse them. */
  onMessage(cb: (bytes: Uint8Array, host: string, port: number) => void): void;
  close(): void;
}

/** What a platform gives the seam: sockets, and its own addresses. */
export interface DatagramPlatform {
  /** A socket on a port the OS picks, and that port: dual-stack where the machine has
   *  IPv6, IPv4 otherwise. */
  bind(): Promise<{ socket: DatagramSocket; port: number }>;
  /** This machine's addresses its sockets are reached at, its host candidates: IPv4, and
   *  IPv6 but for link-local, which needs a zone no candidate carries. */
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
/** How long the plain punch has before a hard NAT is played for (the header). */
const BIRTHDAY_AFTER_MS = 1000;
/** The hard end's extra sockets, and so the ports it opens toward the peer. */
const BIRTHDAY_SOCKETS = 256;
/** The easy end's random probes: how many each `PROBE_MS` to each of the peer's `host:*`,
 *  and how many in all, since the peer names those addresses. With 256 ports open among
 *  the 64,512 a NAT draws from, a probe lands with odds of 1 in 252, so the first 1,160
 *  land one 99 times in 100, and all 4,096 miss about once in 10^7. */
const SPRAY_EACH = 64, SPRAY_MAX = 4096;
/** The ports a NAT maps to: those above the privileged ones. */
const SPRAY_LOW = 1024, SPRAY_PORTS = 65536 - SPRAY_LOW;
const DESCRIPTION = /^[0-9a-f]{16}$/;
const CANDIDATE = /^(?:((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})|\[([0-9a-f:]{2,39})\]):(\d{1,5}|\*)$/;

/** An address, where port 0 is `host:*`: any port of a hard NAT. */
interface Addr { host: string; port: number }

/** Whether `text` is an IPv6 address in lowercase hex: eight groups, or fewer around one
 *  `::`, with no zone and no IPv4 tail. */
export function isIPv6(text: string): boolean {
  const halves = text.split("::");
  if (halves.length > 2) return false;
  const groups = halves.flatMap((h) => (h === "" ? [] : h.split(":")));
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return false;
  return halves.length === 2 ? groups.length <= 7 : groups.length === 8;
}

/** The 16 bytes of an IPv6 address at `at`, as RFC 5952 writes them: lowercase, no leading
 *  zeros, and the longest run of two or more zero groups, the first of equals, as `::`. */
export function ipv6Text(b: Uint8Array, at = 0): string {
  const g: string[] = [];
  let run = -1, runLen = 1;
  for (let i = 0, zeros = 0; i < 8; i++) {
    const v = (b[at + 2 * i] << 8) | b[at + 2 * i + 1];
    g.push(v.toString(16));
    zeros = v === 0 ? zeros + 1 : 0;
    if (zeros > runLen) { run = i - zeros + 1; runLen = zeros; }
  }
  return run < 0 ? g.join(":") : `${g.slice(0, run).join(":")}::${g.slice(run + runLen).join(":")}`;
}

/** `host:port`, with an IPv6 host in brackets. */
const endpoint = (host: string, port: number) => (host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`);

function candidateOf(text: string): Addr | null {
  const m = CANDIDATE.exec(text);
  if (!m || (m[2] !== undefined && !isIPv6(m[2]))) return null;
  const host = m[1] ?? m[2];
  if (m[3] === "*") return { host, port: 0 };
  const port = Number(m[3]);
  return port > 0 && port < 65536 ? { host, port } : null;
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

/** The negotiation link: its sockets, its candidates and the punch, and the stream that
 *  becomes the data link once a path is found. */
class UdpNegotiation implements RawLink {
  private onMsg: ((bytes: Uint8Array) => void) | null = null;
  private onCls: (() => void) | null = null;
  private readonly token = crypto.getRandomValues(new Uint8Array(TOKEN));
  private peerToken: Uint8Array | null = null;
  private readonly peerCandidates: Addr[] = [];
  /** The addresses of a hard peer's NAT, from its `host:*` candidates. */
  private readonly peerHard: string[] = [];
  private readonly own = new Set<string>();
  /** Own candidates found before the description is up, which must go first. */
  private held: string[] | null = [];
  private platform: DatagramPlatform | null = null;
  /** The socket the STUN servers are asked from, and the path's once there is one. */
  private socket: DatagramSocket | null = null;
  /** A hard end's birthday sockets until a path is found: null until they are asked
   *  for, then empty while they bind. */
  private extra: DatagramSocket[] | null = null;
  private path: Addr | null = null;
  /** When the path last carried a packet from the peer. */
  private pathHeard = 0;
  /** An address the peer's packets now come from, being probed before the path moves. */
  private moving: { addr: Addr; challenge: Uint8Array; sentAt: number; heard: number } | null = null;
  private probing: ReturnType<typeof setTimeout> | undefined;
  private readonly asking: { txn: Uint8Array; answered: boolean; timer?: ReturnType<typeof setTimeout> }[] = [];
  /** Each STUN server's answer, the address it saw. */
  private readonly mapped: string[] = [];
  /** Set once the plain punch has had `BIRTHDAY_AFTER_MS`. */
  private birthdayTimer: ReturnType<typeof setTimeout> | undefined;
  private birthdayDue = false;
  private spraying: ReturnType<typeof setTimeout> | undefined;
  private sprayed = 0;
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
    this.platform = p;
    this.socket = bound.socket;
    this.listen(bound.socket);
    if (this.offer) this.describe();
    for (const a of p.addresses()) this.addOwn(endpoint(a, bound.port));
    for (const s of stun) this.askStun(s);
    this.probe();
  }

  private listen(socket: DatagramSocket): void {
    socket.onMessage((bytes, host, port) => this.onPacket(socket, bytes, host, port));
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
    if (this.peerCandidates.length + this.peerHard.length >= MAX_PEER_CANDIDATES) return;
    if (c.port === 0) {
      if (this.peerHard.includes(c.host)) return;
      this.peerHard.push(c.host);
      this.birthday();
      return;
    }
    if (this.peerCandidates.some((p) => p.host === c.host && p.port === c.port)) return;
    this.peerCandidates.push(c);
    if (this.extra?.length) {
      const p = this.probePacket();
      for (const s of this.extra) s.send(p, c.port, c.host);
    }
    this.probe();
  }

  private askStun(server: Addr): void {
    const txn = crypto.getRandomValues(new Uint8Array(12));
    const request = bindingRequest(txn);
    const entry: { txn: Uint8Array; answered: boolean; timer?: ReturnType<typeof setTimeout> } = { txn, answered: false };
    let tries = 0;
    const ask = () => {
      if (this.dead || tries++ >= STUN_TRIES) return;
      this.socket?.send(request, server.port, server.host);
      entry.timer = setTimeout(ask, STUN_RETRY_MS);
    };
    this.asking.push(entry);
    ask();
  }

  /** A STUN server's answer: a candidate, and with two that differ, `host:*` for each
   *  address seen, since this end's NAT gives each destination its own port. */
  private onMapped(addr: string): void {
    this.addOwn(addr);
    this.mapped.push(addr);
    if (this.hard()) for (const m of this.mapped) this.addOwn(`${m.slice(0, m.lastIndexOf(":"))}:*`);
    this.birthday();
  }

  private hard(): boolean { return this.mapped.some((m) => m !== this.mapped[0]); }
  /** Two STUN servers saw this socket at one address: its NAT keeps one port for all. */
  private easy(): boolean { return this.mapped.length >= 2 && !this.hard(); }

  /** `[PROBE][peer's token][own token][stamp]`, the stamp now. */
  private probePacket(): Uint8Array {
    const p = new Uint8Array(PROBE_BYTES);
    p[0] = TYPE_PROBE;
    p.set(this.peerToken!, 1);
    p.set(this.token, 1 + TOKEN);
    new DataView(p.buffer).setFloat64(1 + 2 * TOKEN, performance.now());
    return p;
  }

  /** Probe every candidate the peer has, until a path is found. */
  private probe(): void {
    if (this.dead || this.path || this.probing || !this.peerToken || !this.socket || this.peerCandidates.length === 0) return;
    const send = () => {
      const p = this.probePacket();
      for (const c of this.peerCandidates) this.socket?.send(p, c.port, c.host);
      this.probing = setTimeout(send, PROBE_MS);
    };
    send();
    this.birthdayTimer ??= setTimeout(() => { this.birthdayDue = true; this.birthday(); }, BIRTHDAY_AFTER_MS);
  }

  /** Once the plain punch has had its time, a hard end facing an easy one opens its
   *  birthday sockets, and an easy end facing a hard one sprays (the header). Each waits
   *  for what it needs to know, and each happens once. */
  private birthday(): void {
    if (!this.birthdayDue || this.dead || this.path || !this.peerToken) return;
    if (this.hard() && this.peerHard.length === 0 && this.peerCandidates.length > 0 && this.extra === null) {
      void this.openExtra();
    }
    if (this.easy() && this.peerHard.length > 0 && this.spraying === undefined) this.spray();
  }

  private async openExtra(): Promise<void> {
    const platform = this.platform!;
    this.extra = [];
    const bound = await Promise.all(Array.from({ length: BIRTHDAY_SOCKETS }, () => platform.bind().catch(() => null)));
    const sockets = bound.flatMap((b) => (b ? [b.socket] : []));
    if (this.dead || this.path) { for (const s of sockets) s.close(); return; }
    this.extra = sockets;
    const p = this.probePacket();
    for (const s of sockets) {
      this.listen(s);
      for (const c of this.peerCandidates) s.send(p, c.port, c.host);
    }
  }

  private spray(): void {
    const send = () => {
      if (this.dead || this.path || this.sprayed >= SPRAY_MAX) return;
      const p = this.probePacket();
      const ports = crypto.getRandomValues(new Uint16Array(SPRAY_EACH));
      for (const host of this.peerHard) for (const r of ports) this.socket?.send(p, SPRAY_LOW + (r % SPRAY_PORTS), host);
      this.sprayed += SPRAY_EACH * this.peerHard.length;
      this.spraying = setTimeout(send, PROBE_MS);
    };
    send();
  }

  private onPacket(socket: DatagramSocket, p: Uint8Array, host: string, port: number): void {
    if (this.dead) return;
    if (isStun(p)) {
      for (const a of this.asking) {
        const mapped = a.answered ? null : mappedAddress(p, a.txn);
        if (mapped) { a.answered = true; clearTimeout(a.timer); this.onMapped(mapped); }
      }
      return;
    }
    if (p.length < PATH_HEADER || !sameToken(p, this.token)) return;
    if (p[0] === TYPE_PROBE) {
      if (p.length !== PROBE_BYTES) return;
      const ack = new Uint8Array(PROBE_ACK_BYTES);
      ack[0] = TYPE_PROBE_ACK;
      ack.set(p.subarray(1 + TOKEN), 1);
      socket.send(ack, port, host);
      this.peerToken ??= p.slice(1 + TOKEN, 1 + 2 * TOKEN);
      this.addPeer({ host, port });
    } else if (p[0] === TYPE_PROBE_ACK) {
      if (p.length !== PROBE_ACK_BYTES) return;
      if (this.path) this.moved(host, port, p.subarray(1 + TOKEN));
      else this.choose(socket, host, port, performance.now() - new DataView(p.buffer, p.byteOffset).getFloat64(1 + TOKEN));
    } else {
      // The peer has its path, and this is the way back to it.
      if (!this.path) this.choose(socket, host, port);
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
    const probe = this.probePacket();
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

  /** The path is the peer's `host`:`port` from `socket`, which may be a birthday socket:
   *  the other sockets close, and the STUN servers are not asked again. */
  private choose(socket: DatagramSocket, host: string, port: number, rttMs?: number): void {
    if (this.path || !this.peerToken) return;
    this.path = { host, port };
    this.pathHeard = performance.now();
    if (socket !== this.socket) this.socket?.close();
    this.socket = socket;
    for (const s of this.extra ?? []) if (s !== socket) s.close();
    this.extra = [];
    this.stopPunching();
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
    this.stopPunching();
    this.data.end();
    this.socket?.close();
    this.socket = null;
    for (const s of this.extra ?? []) s.close();
    this.extra = [];
    this.onGone(this);
  }

  private stopPunching(): void {
    clearTimeout(this.probing);
    clearTimeout(this.birthdayTimer);
    clearTimeout(this.spraying);
    for (const a of this.asking) clearTimeout(a.timer);
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
