// A werift-backed RTCPeerConnection for the *console* side of net-rtc.ts.
//
// net-rtc.ts is browser-native: RtcNetwork builds connections from the platform
// RTCPeerConnection / RTCDataChannel, and its header promises a Node peer "joins
// the same mesh by swapping those for node-datachannel's equivalents behind the
// same RtcChannel / Signaling — everything above the channel is untouched". This
// module is that swap, implemented in *pure JS* with werift (no native addon, so
// it also bundles into the `bun --compile` shell), and wired through the single
// `peerConnectionFactory` seam RtcNetwork now exposes.
//
//   browser tab  ──RTCDataChannel──┐
//                                  ├── relay (signaling only) ── same room
//   console node ──werift DC───────┘
//
// The whole job here is an impedance match: werift speaks an rxjs-style
// `.subscribe()` event API, delivers Buffers, wants explicit createOffer/
// createAnswer, and exposes no `binaryType` — whereas RtcNetwork / RtcChannel
// drive the W3C surface (addEventListener, parameterless setLocalDescription,
// ArrayBuffer-ish message payloads). We present werift through a thin W3C facade
// so net-rtc.ts needs zero werift-specific code. PeerLink's in-channel identity
// handshake still does the real authentication — werift's DTLS only has to bring
// up *a* channel, exactly as the browser path documents.
//
// This file imports werift and node:Buffer, so it is Node/Bun only. The browser
// never imports it (p2p.html resolves `seedkernel-wasm/net-rtc`, not this), and
// the comment-stripping minifier copies it without bundling werift, so a stray
// copy in a browser dir stays inert.

import { RTCPeerConnection as WeriftPeerConnection } from "werift";
import type {
  RTCDataChannel as WeriftDataChannel,
  PeerConfig as WeriftPeerConfig,
  RTCIceServer as WeriftIceServer,
  RTCIceCandidateInit as WeriftIceCandidateInit,
} from "werift";

// A plain {type,sdp} description — what crosses signaling and what werift's
// setRemoteDescription accepts. We normalise werift's RTCSessionDescription to
// this shape so the value RtcNetwork puts on the wire is always JSON-safe.
type SdpInit = { type: "offer" | "answer"; sdp: string };

// ── a minimal addEventListener target ─────────────────────────────────────────
// RtcNetwork/RtcChannel only ever addEventListener (never remove), so a tiny
// type→listeners map is the whole contract. dispatch() tolerates a throwing
// listener so one bad handler can't wedge the connection.
class Emitter {
  private readonly listeners = new Map<string, ((ev?: unknown) => void)[]>();
  addEventListener(type: string, cb: (ev?: unknown) => void): void {
    const arr = this.listeners.get(type);
    if (arr) arr.push(cb);
    else this.listeners.set(type, [cb]);
  }
  protected dispatch(type: string, ev?: unknown): void {
    for (const cb of this.listeners.get(type) ?? []) {
      try { cb(ev); } catch { /* a listener must not break the channel */ }
    }
  }
}

// ── RTCDataChannel facade over a werift data channel ──────────────────────────
// RtcChannel (net-rtc.ts) consumes exactly: binaryType (set), readyState,
// addEventListener("message"|"open"|"close"|"error"), send(Uint8Array), close().
// werift gives us .onMessage/.stateChanged/.error Events and a Buffer-only send.
export class WeriftRtcDataChannel extends Emitter {
  // RtcChannel sets this to "arraybuffer"; werift always hands us a Buffer, so it
  // is purely cosmetic — stored to satisfy the assignment, never read.
  binaryType = "arraybuffer";
  private opened = false;

  constructor(private readonly dc: WeriftDataChannel) {
    super();
    // A Buffer is a Uint8Array, so RtcChannel's `new Uint8Array(ev.data)` copies
    // the bytes correctly, and `typeof ev.data !== "string"` still distinguishes
    // a (multiplexed) text frame from our binary frames.
    dc.onMessage.subscribe((data) => this.dispatch("message", { data }));
    dc.stateChanged.subscribe((state) => {
      if (state === "open") this.markOpen();
      else if (state === "closed") this.dispatch("close");
    });
    dc.error.subscribe(() => this.dispatch("error"));
    // A channel received via ondatachannel can already be "open" before we
    // subscribe; surface that on a microtask so RtcChannel (constructed right
    // after us) has its "open" listener registered before it fires.
    if (dc.readyState === "open") queueMicrotask(() => this.markOpen());
  }

  private markOpen(): void {
    if (this.opened) return; // stateChanged + the already-open guard can race
    this.opened = true;
    this.dispatch("open");
  }

  get readyState(): string { return this.dc.readyState; }
  send(bytes: Uint8Array): void { this.dc.send(Buffer.from(bytes)); }
  close(): void { this.dc.close(); }
}

// ── RTCPeerConnection facade over a werift peer connection ─────────────────────
class WeriftRtcPeerConnection extends Emitter {
  private readonly pc: WeriftPeerConnection;

  constructor(config: Partial<WeriftPeerConfig>) {
    super();
    this.pc = new WeriftPeerConnection(config);
    // Trickle ICE: werift emits each gathered candidate (and a final `undefined`,
    // which RtcNetwork ignores via its `if (ev.candidate)` guard). werift's
    // RTCIceCandidate.toJSON() — which RtcNetwork calls — is already the standard
    // {candidate,sdpMid,sdpMLineIndex,usernameFragment} init a browser accepts.
    this.pc.onIceCandidate.subscribe((candidate) => this.dispatch("icecandidate", { candidate }));
    this.pc.onDataChannel.subscribe((channel) =>
      this.dispatch("datachannel", { channel: new WeriftRtcDataChannel(channel) }));
    this.pc.connectionStateChange.subscribe(() => this.dispatch("connectionstatechange"));
  }

  createDataChannel(label: string, opts?: { ordered?: boolean }): WeriftRtcDataChannel {
    const dc = this.pc.createDataChannel(label, opts);
    // The browser fires `negotiationneeded` after the impolite side opens the
    // channel; that is RtcNetwork's single entry point for making an offer. werift
    // has its own onNegotiationneeded with looser timing, so we synthesise the
    // event here instead — deterministic, and exactly once per dial.
    queueMicrotask(() => this.dispatch("negotiationneeded"));
    return new WeriftRtcDataChannel(dc);
  }

  // Parameterless setLocalDescription: the W3C "implicit" form RtcNetwork relies
  // on. werift needs the description spelled out, so pick offer vs answer from the
  // signaling state — offer unless we are answering a received offer.
  async setLocalDescription(): Promise<void> {
    const desc = this.pc.signalingState === "have-remote-offer"
      ? await this.pc.createAnswer()
      : await this.pc.createOffer();
    await this.pc.setLocalDescription(desc);
  }

  async setRemoteDescription(desc: SdpInit): Promise<void> { await this.pc.setRemoteDescription(desc); }
  async addIceCandidate(candidate: WeriftIceCandidateInit): Promise<void> { await this.pc.addIceCandidate(candidate); }

  get signalingState(): string { return this.pc.signalingState; }
  get connectionState(): string { return this.pc.connectionState; }
  get localDescription(): SdpInit | null { return norm(this.pc.localDescription); }
  get remoteDescription(): SdpInit | null { return norm(this.pc.remoteDescription); }

  // werift close() is async; RtcNetwork calls close() synchronously inside its own
  // try/catch teardown, so we fire-and-forget.
  close(): void { void this.pc.close(); }
}

function norm(d: { type: "offer" | "answer"; sdp: string } | undefined): SdpInit | null {
  return d ? { type: d.type, sdp: d.sdp } : null;
}

// Translate a W3C RTCConfiguration into werift's PeerConfig. The only real
// mismatch is iceServers.urls: the W3C field is `string | string[]`, werift's is
// a single `string`, so a multi-URL entry fans out into one werift server each.
function translateConfig(
  config: RTCConfiguration | undefined,
  extra: Partial<WeriftPeerConfig>,
): Partial<WeriftPeerConfig> {
  const iceServers: WeriftIceServer[] = [];
  for (const s of config?.iceServers ?? []) {
    const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
    for (const u of urls) {
      iceServers.push({
        urls: u,
        ...(s.username !== undefined ? { username: s.username } : {}),
        ...(s.credential !== undefined ? { credential: String(s.credential) } : {}),
      });
    }
  }
  return { ...(iceServers.length ? { iceServers } : {}), ...extra };
}

/** A `peerConnectionFactory` for RtcNetworkOptions backed by werift, so a Node or
 *  Bun process drives the very same RtcNetwork as a browser tab and joins the
 *  same relay room. `extra` passes werift-only PeerConfig through untouched —
 *  e.g. `{ iceAdditionalHostAddresses: ["127.0.0.1"] }` to make two peers on one
 *  machine connect with no STUN, or an `icePortRange` to pin the UDP ports. */
export function weriftPeerConnectionFactory(
  extra: Partial<WeriftPeerConfig> = {},
): (config?: RTCConfiguration) => RTCPeerConnection {
  // The facade is a structural subset of RTCPeerConnection (only what RtcNetwork
  // touches), so the bridge cast is confined to this one boundary.
  return (config) =>
    new WeriftRtcPeerConnection(translateConfig(config, extra)) as unknown as RTCPeerConnection;
}
