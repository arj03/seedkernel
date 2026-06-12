// WebRTC-Direct: a browser dials a console node with NO relay and NO answer-back.
//
// Spike 1 reaches a console node over WebRTC but still needs a signaling relay to
// swap the SDP. WebRTC-Direct removes it for the browser→console direction. The
// console publishes a self-describing dial token
//     /ip4/<host>/udp/<port>/certhash/<multibase-multihash-of-its-DTLS-cert>
// (carried in the page's URL #fragment). From that alone the browser *fabricates*
// the console's answer SDP locally — the certhash fills the `a=fingerprint:` line,
// so no real answer has to travel back — and the browser's own ufrag reaches the
// console *inside the first STUN binding request* on the media path, so no offer
// travels over a relay either. The console is an ICE-lite agent on one bound UDP
// port, demultiplexing inbound datagrams by source.
//
// Trust is unchanged: the certhash need not be trusted — PeerLink's in-channel
// AUTH still proves identity — it only has to make the browser's DTLS not reject
// the connection. So the console deliberately does NOT verify the browser's cert.
//
// werift gives us DTLS + SCTP but is not built for a single-port, ufrag-demuxed
// *server* (each werift ICE Connection owns its own sockets). So this module
// hand-rolls exactly the thin layer werift lacks — one dgram socket, a STUN
// responder, ICE-lite — and feeds werift's DTLS(server) + SCTP per flow through a
// minimal fake "ice transport". The opened channel comes back as a werift
// RTCDataChannel, which net-rtc-node.ts already adapts to RtcChannel/PeerLink.
//
// Node/Bun only (node:dgram + node:crypto). The browser side reuses just the pure
// SDP helpers below (fabricateAnswerSdp / certhashToFingerprint).

import { createSocket, type Socket as DgramSocket, type RemoteInfo } from "node:dgram";
import {
  Message, parseMessage, classes, methods,
  RTCCertificate, RTCDtlsTransport, RTCSctpTransport,
  RTCDtlsParameters, RTCDtlsFingerprint, defaultPeerConfig, Event,
  RTCPeerConnection as WeriftPeerConnection,
} from "werift";
import type { RTCDataChannel as WeriftDataChannel, DtlsKeys } from "werift";
import { RtcChannel } from "./net-rtc.js";
import { WeriftRtcDataChannel } from "./net-rtc-node.js";
import { type RawChannel } from "./net-link.js";
import { WebRtcDirectNetworkBase, type WebRtcDirectBaseOptions, type OpenedChannel } from "./webrtc-direct-net.js";
import {
  certhashToFingerprint, fabricateAnswerSdp, randomUfrag, encodeDialToken, parseDialToken,
} from "./webrtc-direct-sdp.js";

// Re-export the browser-shared SDP/token helpers so consumers can reach them via
// this module too (the browser imports them from ./webrtc-direct-sdp directly).
export { certhashToFingerprint, fabricateAnswerSdp, randomUfrag, encodeDialToken, parseDialToken } from "./webrtc-direct-sdp.js";
export type { DialToken } from "./webrtc-direct-sdp.js";

// The SCTP port WebRTC data channels always use.
const SCTP_PORT = 5000;
// DTLS-SRTP profiles to advertise, matching werift's RTCPeerConnection defaults
// (SRTP_AEAD_AES_128_GCM=7 preferred, SRTP_AES128_CM_HMAC_SHA1_80=1). A werift
// dialer always sets up SRTP after the handshake and aborts with "need srtpProfile"
// if none was negotiated — even for a data-only connection — so the server must
// offer a matching profile. (A real browser data channel needs no SRTP at all.)
const SRTP_PROFILES: (1 | 7)[] = [7, 1];
// Optional tracing for bring-up debugging (set WEBRTC_DIRECT_DEBUG=1).
const DEBUG = typeof process !== "undefined" && !!process.env?.WEBRTC_DIRECT_DEBUG;
const dlog = (...a: unknown[]) => { if (DEBUG) console.error("[wd]", ...a); };
// STUN magic cookie (RFC 5389) — present at byte offset 4 of every STUN message.
const STUN_COOKIE = 0x2112a442;

// ── certhash from a pinned cert (Node-side; uses werift) ──────────────────────

/** The dial-token certhash for a pinned cert (multibase multihash of sha256(DER)). */
export function certhashFromKeys(keys: DtlsKeys): string {
  const cert = new RTCCertificate(keys.keyPem, keys.certPem, keys.signatureHash);
  const digest = Buffer.from(cert.getFingerprints()[0].value.replaceAll(":", ""), "hex");
  return "u" + Buffer.concat([Buffer.from([0x12, 0x20]), digest]).toString("base64url");
}

/** Generate a self-signed DTLS cert. Persist {certPem,keyPem} to keep a stable
 *  certhash across restarts; pass it back as the listener's `keys`. */
export async function makeCertKeys(): Promise<DtlsKeys> {
  const cert = await RTCDtlsTransport.SetupCertificate();
  return { certPem: cert.certPem, keyPem: cert.privateKey, signatureHash: cert.signatureHash };
}

/** Wrap an opened werift data channel as a PeerLink-ready RawChannel — the same
 *  RtcChannel net-rtc.ts hands PeerLink, so a WebRTC-Direct link authenticates and
 *  carries Transport frames identically to a relayed RtcNetwork link. */
export function weriftChannelToRaw(dc: WeriftDataChannel): RawChannel {
  return new RtcChannel(new WeriftRtcDataChannel(dc) as unknown as RTCDataChannel);
}

// ── the listener ──────────────────────────────────────────────────────────────

export interface WebRtcDirectListenerOptions {
  /** Pinned DTLS cert — its certhash is what dialers carry in the token. */
  keys: DtlsKeys;
  /** Called with each opened data channel (a werift RTCDataChannel) + the peer addr. */
  onChannel: (channel: WeriftDataChannel, remote: { host: string; port: number }) => void;
  host?: string;   // default 0.0.0.0
  port?: number;   // default 0 (ephemeral)
}

// Per-source connection state. One browser = one (ip,port) flow = one DTLS+SCTP.
interface Flow {
  conn: FakeIceConnection;
  dtls: RTCDtlsTransport;
  sctp: RTCSctpTransport;
  started: boolean;
}

// The tiny surface werift's DTLS/SCTP read off an ICE transport's `connection`:
// send bytes, an onData Event of inbound bytes, a close, and `nominated` (stats only).
interface FakeIceConnection {
  send: (data: Buffer) => Promise<void>;
  onData: Event<[Buffer]>;
  close: () => void;
  nominated: undefined;
}

export class WebRtcDirectListener {
  private socket: DgramSocket | null = null;
  private readonly flows = new Map<string, Flow>();

  constructor(private readonly opts: WebRtcDirectListenerOptions) {}

  async listen(): Promise<void> {
    const socket = createSocket("udp4");
    this.socket = socket;
    socket.on("message", (data, rinfo) => this.onDatagram(data, rinfo));
    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(this.opts.port ?? 0, this.opts.host ?? "0.0.0.0", () => resolve());
    });
  }

  /** The bound address — its host/port + the cert's certhash form the dial token. */
  address(): { host: string; port: number } {
    const a = this.socket!.address();
    return { host: a.address, port: a.port };
  }

  close(): void {
    for (const f of this.flows.values()) {
      try { void f.sctp.stop(); } catch { /* ignore */ }
      try { void f.dtls.stop(); } catch { /* ignore */ }
    }
    this.flows.clear();
    this.socket?.close();
    this.socket = null;
  }

  private onDatagram(data: Buffer, rinfo: RemoteInfo): void {
    const key = `${rinfo.address}:${rinfo.port}`;
    dlog("recv", data.length, "B from", key, isStun(data) ? "STUN" : `data(0x${data[0]?.toString(16)})`);
    if (isStun(data)) { this.onStun(data, rinfo, key); return; }
    // Non-STUN: DTLS/SCTP for an established flow. Feed werift's DTLS via onData.
    this.flows.get(key)?.conn.onData.execute(data);
  }

  private onStun(data: Buffer, rinfo: RemoteInfo, key: string): void {
    const msg = parseMessage(data);
    if (!msg || msg.messageMethod !== methods.BINDING || msg.messageClass !== classes.REQUEST) return;
    // USERNAME = "<our-ufrag>:<their-ufrag>"; WebRTC-Direct sets our-ufrag == our
    // password, so the part before ':' is the integrity key for this connection.
    const username = String(msg.getAttributeValue("USERNAME") ?? "");
    const ufrag = username.split(":")[0];
    if (!ufrag) return;

    dlog("STUN binding request, ufrag", ufrag);
    let flow = this.flows.get(key);
    if (!flow) { flow = this.createFlow(rinfo, ufrag); this.flows.set(key, flow); }

    // Binding success: echo the transaction, reflect the peer's address, sign with
    // the shared ufrag (MESSAGE-INTEGRITY) + FINGERPRINT, exactly as ICE expects.
    const res = new Message(methods.BINDING, classes.RESPONSE, msg.transactionId);
    res.setAttribute("XOR-MAPPED-ADDRESS", [rinfo.address, rinfo.port]);
    res.addMessageIntegrity(Buffer.from(ufrag));
    res.addFingerprint();
    this.socket?.send(res.bytes, rinfo.port, rinfo.address);

    // ICE-lite is passive: we never send our own checks. The first valid request is
    // enough to bring up DTLS — the dialer's ClientHello follows on the same flow.
    if (!flow.started) { flow.started = true; void this.startFlow(flow, rinfo); }
  }

  private createFlow(rinfo: RemoteInfo, _ufrag: string): Flow {
    const socket = this.socket!;
    const conn: FakeIceConnection = {
      onData: new Event<[Buffer]>(),
      send: (buf) => new Promise<void>((resolve) => {
        dlog("send", buf.length, `B to ${rinfo.address}:${rinfo.port} (0x${buf[0]?.toString(16)})`);
        socket.send(buf, rinfo.port, rinfo.address, () => resolve());
      }),
      close: () => {},
      nominated: undefined,
    };
    // werift's DTLS/SCTP read .role and .connection off the ice transport (+ a couple
    // of stats hooks). role "controlled" ⇒ SCTP server; we force DTLS role "server".
    const iceTransport = {
      role: "controlled" as const,
      connection: conn,
      state: "connected" as const,
      onStateChange: new Event(),
      stop: async () => {},
      getStats: async () => [],
    };

    const cert = new RTCCertificate(this.opts.keys.keyPem, this.opts.keys.certPem, this.opts.keys.signatureHash);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const dtls = new RTCDtlsTransport(defaultPeerConfig, iceTransport as any, cert, SRTP_PROFILES);
    dtls.role = "server";
    // start() requires *some* remote fingerprint to exist; we can't know the
    // browser's, so seed a placeholder and disable verification (PeerLink authenticates).
    dtls.setRemoteParams(new RTCDtlsParameters([new RTCDtlsFingerprint("sha-256", "00:".repeat(31) + "00")], "client"));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dtls as any).verifyRemoteCertificateFingerprint = () => {};
    // We advertise SRTP profiles so a werift dialer (which always sets up SRTP) is
    // happy, but a browser data-channel-only dialer negotiates no SRTP — werift then
    // throws "need srtpProfile" in startSrtp(). SRTP is irrelevant to data channels
    // (they ride SCTP-over-DTLS), so swallow it and let the handshake complete.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const startSrtp = (dtls as any).startSrtp.bind(dtls);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dtls as any).startSrtp = () => { try { startSrtp(); } catch { /* no SRTP negotiated */ } };

    const sctp = new RTCSctpTransport();
    sctp.setDtlsTransport(dtls);
    sctp.onDataChannel.subscribe((dc) => this.opts.onChannel(dc, { host: rinfo.address, port: rinfo.port }));

    return { conn, dtls, sctp, started: false };
  }

  private async startFlow(flow: Flow, rinfo: RemoteInfo): Promise<void> {
    try {
      dlog("starting DTLS (server)…");
      await flow.dtls.start();         // resolves once DTLS connects (after the ClientHello)
      dlog("DTLS connected; starting SCTP…");
      await flow.sctp.start(SCTP_PORT); // SCTP server; the dialer opens the channel
      dlog("SCTP started");
    } catch (e) {
      dlog("flow failed:", (e as Error)?.message ?? e);
      this.flows.delete(`${rinfo.address}:${rinfo.port}`);
      // dtls.start()/sctp.start() may have spun up timers and event subscribers
      // before throwing; stop them (same order as close()) so a failed flow
      // doesn't leak. conn.close() can't free the shared UDP socket.
      try { void flow.sctp.stop(); } catch { /* ignore */ }
      try { void flow.dtls.stop(); } catch { /* ignore */ }
      try { flow.conn.close(); } catch { /* ignore */ }
    }
  }
}

function isStun(data: Buffer): boolean {
  return data.length >= 20 && data.readUInt32BE(4) === STUN_COOKIE;
}

// ── the dialer (Node, via werift) ─────────────────────────────────────────────
// The browser equivalent lives in p2p.html and reuses fabricateAnswerSdp /
// certhashToFingerprint; here we drive a werift RTCPeerConnection the same way so
// the path is testable without a browser. No relay, no answer-back: the only input
// is the token's host/port/certhash.

export interface DialResult {
  channel: WeriftDataChannel;
  /** Resolves when the data channel opens (rejects on timeout). The caller must
   *  wrap `channel` (subscribe to its onMessage) BEFORE awaiting this — werift's
   *  message Event does not buffer, so a HELLO the console sends the instant the
   *  channel opens is lost if no listener is attached yet. */
  opened: Promise<void>;
  close: () => void;
}

export async function dialWebRtcDirect(opts: {
  host: string; port: number; certhash: string; timeoutMs?: number;
}): Promise<DialResult> {
  const pc = new WeriftPeerConnection({
    iceUseIpv4: true, iceUseIpv6: false, iceAdditionalHostAddresses: ["127.0.0.1"],
  });
  if (DEBUG) {
    pc.iceConnectionStateChange.subscribe((s) => dlog("dialer ICE:", s));
    pc.connectionStateChange.subscribe((s) => dlog("dialer conn:", s));
    pc.iceGatheringStateChange.subscribe((s) => dlog("dialer gather:", s));
  }
  const dc = pc.createDataChannel("seedkernel", { ordered: true });
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);

  const ufrag = randomUfrag();
  const answer = fabricateAnswerSdp(pc.localDescription!.sdp, {
    ufrag, fingerprint: certhashToFingerprint(opts.certhash), host: opts.host, port: opts.port,
  });
  if (DEBUG) { dlog("OFFER:\n" + pc.localDescription!.sdp); dlog("FABRICATED ANSWER:\n" + answer); }
  await pc.setRemoteDescription({ type: "answer", sdp: answer });
  if (DEBUG) {
    for (const d of pc.dtlsTransports) d.onStateChange.subscribe((s) => dlog("dialer dtls:", s));
    pc.sctpTransport?.dtlsTransport.onStateChange.subscribe((s) => dlog("dialer sctp-dtls:", s));
  }

  // Return at once (the connection is still establishing) so the caller can attach
  // its message listener before the channel opens; expose readiness separately.
  const opened = new Promise<void>((resolve, reject) => {
    if (dc.readyState === "open") return resolve();
    const t = setTimeout(() => reject(new Error("webrtc-direct dial timeout")), opts.timeoutMs ?? 15000);
    dc.stateChanged.subscribe((s) => { if (s === "open") { clearTimeout(t); resolve(); } });
  });

  return { channel: dc, opened, close: () => void pc.close() };
}

// ── WebRtcDirectNetwork: a Network over relay-less WebRTC-Direct links ─────────
//
// The same shape as RtcNetwork (net-rtc.ts), but the fabric underneath is the
// listener + dialer above instead of a relay+signaling mesh. It listens on one UDP
// port (accepting any browser/node that dials its token) and/or dials other nodes'
// tokens; each opened channel runs PeerLink, and once authenticated becomes a
// routable link. So a console node `serveDirect`-ing over this IS a full storage
// node — Transport / cohort / StorageNode ride on top untouched, exactly as they do
// over NodeNetwork or RtcNetwork — reachable by a static dial token, no relay.
//
// All the link plumbing lives in WebRtcDirectNetworkBase (browser-safe); this node
// class supplies only the werift dial (`openChannel`) and the single-port listener.
// The browser fabric (webrtc-direct-browser.ts) shares the same base.

export interface WebRtcDirectNetworkOptions extends WebRtcDirectBaseOptions {
  /** Pinned DTLS cert to listen with (its certhash is what dialers carry). Omit for
   *  a dial-only node (e.g. a client that only reaches out to tokens). */
  keys?: DtlsKeys;
  /** Listen bind address. Default host 0.0.0.0, ephemeral port. */
  listen?: { host?: string; port?: number };
}

export class WebRtcDirectNetwork extends WebRtcDirectNetworkBase {
  private listener: WebRtcDirectListener | null = null;
  private certhash: string | null = null;

  constructor(private readonly opts: WebRtcDirectNetworkOptions) {
    super(opts);
  }

  /** Bind the UDP listener; resolves with its bound host/port + certhash. After this,
   *  `token(advertiseHost)` yields the string a browser/node dials. */
  async listen(): Promise<{ host: string; port: number; certhash: string }> {
    if (!this.opts.keys) throw new Error("WebRtcDirectNetwork.listen needs `keys` (a pinned cert)");
    this.certhash = certhashFromKeys(this.opts.keys);
    this.listener = new WebRtcDirectListener({
      keys: this.opts.keys,
      host: this.opts.listen?.host ?? "0.0.0.0",
      port: this.opts.listen?.port ?? 0,
      onChannel: (dc) => this.acceptInbound(weriftChannelToRaw(dc)),
    });
    await this.listener.listen();
    const { host, port } = this.listener.address();
    return { host, port, certhash: this.certhash };
  }

  /** The dial token for this node's listener (host defaults to the bound address —
   *  pass the reachable LAN/public IP for off-box dialers). */
  token(advertiseHost?: string): string {
    if (!this.listener || !this.certhash) throw new Error("WebRtcDirectNetwork is not listening");
    const { host, port } = this.listener.address();
    return encodeDialToken({ host: advertiseHost ?? host, port, certhash: this.certhash, peerId: this.ownId });
  }

  // Dial with werift. dialWebRtcDirect returns before the channel opens; wrapping it
  // as a RawChannel now (weriftChannelToRaw subscribes immediately) means the console's
  // HELLO is not missed, and `opened` reports a failed connection (werift Events do
  // not buffer). The base handles PeerLink adoption + the auth timeout.
  protected async openChannel(token: string, timeoutMs: number): Promise<OpenedChannel> {
    const t = parseDialToken(token);
    const { channel, opened, close } = await dialWebRtcDirect({ host: t.host, port: t.port, certhash: t.certhash, timeoutMs });
    return { channel: weriftChannelToRaw(channel), opened, close };
  }

  protected stopListener(): void {
    try { this.listener?.close(); } catch { /* ignore */ }
    this.listener = null;
  }
}
