import sodium from "./libsodium-wrappers.mjs";
import { loadKernelHost, CURRENT_VERSION }
  from "../build/host/browser.js";

const RTC_CONFIG = { iceServers: [{ urls: [
  "stun:stun.l.google.com:19302",
  "stun:stun.cloudflare.com:3478",
  "stun:stun.nextcloud.com:443",
] }] };

const shellLog = document.getElementById("shell-log");
const relayUrlInput = document.getElementById("relay-url");
const relayConnectBtn = document.getElementById("connect-relay");
const relayStatus = document.getElementById("relay-status");
const makeOfferBtn = document.getElementById("make-offer");
const copyLinkBtn = document.getElementById("copy-link");
const myOfferArea = document.getElementById("my-offer");
const theirAnswerArea = document.getElementById("their-answer");
const applyAnswerBtn = document.getElementById("apply-answer");
const theirOfferArea = document.getElementById("their-offer");
const makeAnswerBtn = document.getElementById("make-answer");
const myAnswerArea = document.getElementById("my-answer");
const copyAnswerBtn = document.getElementById("copy-answer");
const myOfferBox = document.getElementById("my-offer-box");
const myAnswerBox = document.getElementById("my-answer-box");
const installV1Btn = document.getElementById("install-v1");
const installV2Btn = document.getElementById("install-v2");
const installBtn  = document.getElementById("install-btn");
const appVersionSel = document.getElementById("app-version");
const appStatus = document.getElementById("app-status");
const frame = document.getElementById("app-frame");
const aboutBtn = document.getElementById("about-toggle");
const aboutPanel = document.getElementById("about");

// top-bar status elements
const relayPill = document.getElementById("relay-pill");
const relayPillText = document.getElementById("relay-pill-text");
const peerPill = document.getElementById("peer-pill");
const peerPillText = document.getElementById("peer-pill-text");
const identityPill = document.getElementById("identity-pill");

const tabs = {
  relay:  { btn: document.getElementById("tab-relay"),  panel: document.getElementById("panel-relay")  },
  invite: { btn: document.getElementById("tab-invite"), panel: document.getElementById("panel-invite") },
  accept: { btn: document.getElementById("tab-accept"), panel: document.getElementById("panel-accept") },
  app:    { btn: document.getElementById("tab-app"),    panel: document.getElementById("panel-app")    },
};
function showTab(name) {
  for (const [k, t] of Object.entries(tabs)) {
    t.btn.classList.toggle("active", k === name);
    t.panel.classList.toggle("hidden", k !== name);
  }
  if (name === "app") tabs.app.btn.classList.remove("unread");
}
for (const [k, t] of Object.entries(tabs)) {
  t.btn.addEventListener("click", () => showTab(k));
}

aboutBtn.addEventListener("click", () => {
  aboutPanel.classList.toggle("open");
  aboutPanel.hidden = !aboutPanel.classList.contains("open");
});

function shellPrint(text, cls) {
  const line = document.createElement("div");
  if (cls) line.className = cls;
  line.textContent = text;
  shellLog.appendChild(line);
  shellLog.scrollTop = shellLog.scrollHeight;
}

function bytesToHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}

shellPrint("Loading kernel + bootstrap WASM...", "sys");
const host = await loadKernelHost(
  "../build/kernel.wasm", "../build/bootstrap.wasm", sodium);

// ─── bootstrap: signature, trust, install ──────────────────────────────
const signatureId       = host.deriveId("seedkernel.bootstrap.v1:signature");
const signatureSignerId = host.deriveId("seedkernel.bootstrap.v1:signature.signer");
const trustGrantId      = host.deriveId("seedkernel.bootstrap.v1:trust.grant");
const installId         = host.deriveId("seedkernel.bootstrap.v1:install");

host.registerSignature(signatureId, signatureSignerId);
host.registerTrustGrant(trustGrantId);
host.registerInstallHandler(installId);
// FIXME: this is just a demo
host.setApproveInstall(() => true);

// ─── per-tab Ed25519 identity ──────────────────────────────────────────
let myKeys;
// FIXME: this is just a demo
const stored = sessionStorage.getItem("chat.identity");
if (stored) {
  const parsed = JSON.parse(stored);
  myKeys = {
    publicKey:  new Uint8Array(parsed.pk),
    privateKey: new Uint8Array(parsed.sk),
  };
} else {
  const kp = sodium.crypto_sign_keypair();
  myKeys = { publicKey: kp.publicKey, privateKey: kp.privateKey };
  sessionStorage.setItem("chat.identity", JSON.stringify({
    pk: Array.from(kp.publicKey),
    sk: Array.from(kp.privateKey),
  }));
}
const myPkHex = bytesToHex(myKeys.publicKey);

host.trustGrant(0, myKeys.publicKey, installId);
shellPrint(`I am ${myPkHex.slice(0, 8)}`, "sys");

// ─── top-bar status updates ───────────────────────────────────────────
identityPill.textContent = `id ${myPkHex.slice(0, 8)}`;
identityPill.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(myPkHex);
    const prev = identityPill.textContent;
    identityPill.textContent = "copied!";
    setTimeout(() => { identityPill.textContent = prev; }, 1100);
  } catch {}
});

function setRelayPill(state, label) {
  // state: "off" | "connecting" | "ok" | "err"
  relayPill.classList.remove("ok", "warn", "err");
  if (state === "ok")           relayPill.classList.add("ok");
  else if (state === "connecting") relayPill.classList.add("warn");
  else if (state === "err")     relayPill.classList.add("err");
  relayPillText.textContent = label;
}

function updatePeerPill() {
  let open = 0;
  for (const e of peers.values()) {
    if (e.dc && e.dc.readyState === "open") open++;
  }
  peerPillText.textContent = open === 1 ? "1 peer" : `${open} peers`;
  peerPill.classList.toggle("ok", open > 0);
}

// ─── chat schema_ids ───────────────────────────────────────────────────
//
// chatId is the wire-level schema every peer dispatches messages at, so
// it MUST be globally derivable — peers compute it from the same name
// and find each other's chat handler. Scoping it would break interop.
//
// chatUiId is the local-only bridge from chat WASM → this shell's iframe;
// no remote peer ever addresses it. We scope it to my pubkey (README §5)
// so a future co-installed app cannot compute it and impersonate UI
// renders. Combined with the caller-check on the bridge below, this
// gives the UI two independent locks.
const chatId   = host.deriveId("seedkernel.v1:chat");
const chatUiId = host.deriveScopedId("seedkernel.v1:chat.ui", myKeys.publicKey);

// ─── chat.ui bridge → iframe ───────────────────────────────────────────
//
// The chat WASM has no DOM access; it forwards rendered events here via
// kernel.call. We forward them to the currently-mounted iframe via
// postMessage. Renders that arrive before the iframe says "ready" are
// queued so an upgrade-in-flight doesn't drop the first peer message.
let iframeReady = false;
const renderQueue = [];

function deliverRender(payload) {
  if (iframeReady && frame.contentWindow) {
    frame.contentWindow.postMessage({ type: "render", payload }, "*");
  } else {
    renderQueue.push(payload);
  }
  // Surface unread on a tab that's not "app".
  for (const [k, t] of Object.entries(tabs)) {
    if (k !== "app" && t.btn.classList.contains("active")) {
      tabs.app.btn.classList.add("unread");
      break;
    }
  }
}

function deliverSys(text) {
  if (iframeReady && frame.contentWindow) {
    frame.contentWindow.postMessage({ type: "sys", text }, "*");
  }
}

function callerIsChat() {
  // host.currentCaller is the schema_id of the WASM that invoked us via
  // kernel.call, or null at top-level dispatch. Only the chat handler may
  // drive this UI bridge; anything else (an envelope dispatched directly
  // at chatUiId, or a future co-installed handler) is dropped silently.
  const c = host.currentCaller;
  if (!c || c.length !== chatId.length) return false;
  for (let i = 0; i < c.length; i++) if (c[i] !== chatId[i]) return false;
  return true;
}

host.register(chatUiId, (_sid, payload) => {
  if (!callerIsChat()) return null;
  // Copy out — the underlying buffer is tied to scratch and may be reused.
  deliverRender(new Uint8Array(payload));
  return null;
});

// ─── install + iframe mount ────────────────────────────────────────────
//
// Each install bumps a per-signer monotonic seq (§4.4); the install handler
// drops anything seq <= last_seen. Tracked in sessionStorage so a reload
// inside the same tab doesn't rewind the counter and let an attacker replay
// a captured install message.
let installSeq = parseInt(sessionStorage.getItem("chat.installSeq") || "0", 10);
function nextSeq() {
  installSeq++;
  sessionStorage.setItem("chat.installSeq", String(installSeq));
  return installSeq;
}

function encodeConfigPayload() {
  const buf = new Uint8Array(1 + chatUiId.length + 1 + signatureSignerId.length);
  let o = 0;
  buf[o++] = chatUiId.length;
  buf.set(chatUiId, o); o += chatUiId.length;
  buf[o++] = signatureSignerId.length;
  buf.set(signatureSignerId, o); o += signatureSignerId.length;
  return buf;
}

async function installChatApp(version) {
  installBtn.disabled = true;
  appStatus.textContent = `installing ${version}...`;
  shellPrint(`Fetching chat-app-${version}.wasm...`, "sys");
  try {
    const wasmBytes = new Uint8Array(
      await fetch(`../build/chat-app-${version}.wasm`).then(r => r.arrayBuffer()));

    // Send the signed install message. The install handler verifies the
    // signature, trust-checks our pubkey for the install schema, validates
    // the seq, runs approveInstall, and installs the WASM at chatId.
    //
    // We declare [chatUiId] as the chat handler's caps so capability.of_handler
    // and the host's cap index record what this WASM is allowed to call
    // into. The bridge's caller-check is the load-bearing enforcement; this
    // declaration is the audit trail that goes with it.
    const installPayload = host.encodeInstallPayload(
      nextSeq(), [chatUiId], chatId, wasmBytes);
    host.dispatch(host.wrapAndEncode(
      myKeys.privateKey, myKeys.publicKey, CURRENT_VERSION, installId, installPayload));

    if (!host.isRegistered(chatId)) {
      shellPrint(`Install of ${version} failed.`, "err");
      appStatus.textContent = "install failed";
      return;
    }
    shellPrint(`chat-app-${version} installed.`, "sys");

    // One-shot configuration — this is the new clean primitive that
    // replaces the previous 0xff-tag synthetic envelope.
    host.callDynamicExport(chatId, "configure", encodeConfigPayload());

    // Pull the bundled UI out of the WASMs "ui" custom section. Update
    // is atomic — same artifact carried compute and presentation.
    const mod = await WebAssembly.compile(wasmBytes);
    const sections = WebAssembly.Module.customSections(mod, "ui");
    if (sections.length === 0) {
      shellPrint("WASM has no embedded UI section.", "err");
      return;
    }
    const uiHtml = new TextDecoder().decode(new Uint8Array(sections[0]));

    // Reset the iframe state and mount the new UI. The "ready" handshake
    // below will flush any queued renders.
    iframeReady = false;
    renderQueue.length = 0;
    frame.classList.remove("hidden");
    if (frame.dataset.blobUrl) URL.revokeObjectURL(frame.dataset.blobUrl);
    const uiBlob = new Blob([uiHtml], { type: "text/html" });
    const uiUrl  = URL.createObjectURL(uiBlob);
    frame.dataset.blobUrl = uiUrl;
    frame.src = uiUrl;
    appStatus.textContent = `${version} running`;
    appVersionSel.value = version;
    showTab("app");
  } catch (err) {
    shellPrint(`Install failed: ${err.message}`, "err");
    appStatus.textContent = "install failed";
  } finally {
    installBtn.disabled = false;
  }
}

installV1Btn.addEventListener("click", () => installChatApp("v1"));
installV2Btn.addEventListener("click", () => installChatApp("v2"));
installBtn.addEventListener("click", () => installChatApp(appVersionSel.value));
installBtn.disabled = false;
installV1Btn.disabled = false;
installV2Btn.disabled = false;

// Auto-install v2 on load so the shell drops the user straight into a working
// chat. v1 is selectable to demo the atomic in-place upgrade (and ships with
// a distinct cyberpunk-themed UI so the swap is visible at a glance).
appVersionSel.value = "v2";
installChatApp("v2");

// ─── iframe protocol: handshake + outgoing messages ────────────────────
window.addEventListener("message", (ev) => {
  if (!frame.contentWindow || ev.source !== frame.contentWindow) return;
  const msg = ev.data;
  if (!msg) return;

  if (msg.type === "ready") {
    iframeReady = true;
    frame.contentWindow.postMessage(
      { type: "init", pk: myKeys.publicKey }, "*");
    for (const payload of renderQueue) {
      frame.contentWindow.postMessage({ type: "render", payload }, "*");
    }
    renderQueue.length = 0;
    return;
  }

  if (msg.type === "send" && typeof msg.chatType === "number" && msg.body) {
    const body = msg.body instanceof Uint8Array ? msg.body : new Uint8Array(msg.body);
    const payload = new Uint8Array(1 + body.length);
    payload[0] = msg.chatType & 0xff;
    payload.set(body, 1);
    const wire = host.wrapAndEncode(
      myKeys.privateKey, myKeys.publicKey, CURRENT_VERSION, chatId, payload);
    broadcastWire(wire);
    host.dispatch(wire);              // local echo
  }
  if (msg.chatType === 0x02) {
    lastSentNickBody = body;   // cache for re-broadcast on new DC open
  }
});

// ---------------------------------------------------------------------------
// WebRTC peer mesh — perfect-negotiation pattern.
//
// Each peer is identified by their Ed25519 pubkey hex. We assign a stable
// polite/impolite role per pair from pubkey ordering (polite = my_pk > their).
// The impolite peer creates the data channel, which fires negotiationneeded
// and produces the initial SDP offer; the polite peer waits for ondatachannel.
// Subsequent renegotiation (an ICE restart, a media track add, etc.) reuses
// the same negotiationneeded path. Glare resolution lets simultaneous
// renegotiations converge: if both sides offer at once, the polite side
// rolls back its local offer and applies the impolite one.
//
// Renegotiation signaling rides over whichever transport is available.
// Once the data channel is open, it is preferred — the relay is allowed
// to be killed by then, and an ICE-restart roundtrip during a network
// blip can travel across the still-alive dc to recover the connection
// without any external rendezvous.
//
// We also re-broadcast our last-sent nick body (v2 app only) when a fresh
// dc opens, so the new peer's nick table picks it up.
// ---------------------------------------------------------------------------

const peers = new Map();
let lastSentNickBody = null;

function bindDataChannel(entry, dc, pkHex) {
  entry.dc = dc;
  dc.binaryType = "arraybuffer";
  dc.addEventListener("open", () => {
    shellPrint(`P2P link to ${pkHex.slice(0, 8)} open`, "sys");
    deliverSys(`P2P link to ${pkHex.slice(0, 8)} open`);
    updatePeerPill();
    if (lastSentNickBody) {
      const payload = new Uint8Array(1 + lastSentNickBody.length);
      payload[0] = 0x02;
      payload.set(lastSentNickBody, 1);
      const wire = host.wrapAndEncode(
        myKeys.privateKey, myKeys.publicKey, CURRENT_VERSION, chatId, payload);
      try { dc.send(wire); } catch {}
    }
  });
  dc.addEventListener("message", (ev) => {
    // String frames are renegotiation signaling between this exact pair;
    // binary frames are kernel envelopes routed via host.dispatch.
    if (typeof ev.data === "string") {
      let parsed;
      try { parsed = JSON.parse(ev.data); } catch { return; }
      onSignal(parsed).catch(err =>
        shellPrint(`Signaling error: ${err.message}`, "err"));
    } else {
      host.dispatch(new Uint8Array(ev.data));
    }
  });
  dc.addEventListener("close", () => {
    // Don't tear the peer down here. The pc may recover via ICE restart
    // while the dc briefly drops; if the connection truly died, the
    // connectionstatechange handler below sees "failed" and cleans up.
    if (entry.dc === dc) entry.dc = null;
    updatePeerPill();
  });
}

function attachPeerListeners(entry, pkHex) {
  const pc = entry.pc;
  pc.addEventListener("icecandidate", ({ candidate }) => {
    if (candidate) {
      sendSignal(pkHex, {
        type: "ice", from: myPkHex, to: pkHex, candidate: candidate.toJSON(),
      });
    }
  });
  pc.addEventListener("datachannel", (e) => bindDataChannel(entry, e.channel, pkHex));
  pc.addEventListener("track", (ev) => {
    // A remote peer started sending media — attach the track to a per-peer
    // tile. New tracks for the same peer (e.g. they enabled video later)
    // get appended to the same MediaStream. When a track ends — either the
    // remote did removeTrack via SDP renegotiation, or their pc died —
    // we drop it; when the stream is empty, the tile goes away.
    const tile = getOrCreateRemoteTile(pkHex);
    tile.stream.addTrack(ev.track);
    ev.track.addEventListener("ended", () => {
      try { tile.stream.removeTrack(ev.track); } catch {}
      if (tile.stream.getTracks().length === 0) removeRemoteTile(pkHex);
    });
  });
  pc.addEventListener("negotiationneeded", async () => {
    // Single entry point for producing offers — fires when the impolite
    // side creates the data channel at bootstrap, on restartIce(), and
    // (later) on addTrack/removeTrack. Implicit setLocalDescription()
    // picks createOffer/createAnswer based on signalingState.
    try {
      entry.makingOffer = true;
      await pc.setLocalDescription();
      sendSignal(pkHex, {
        type: "sdp", from: myPkHex, to: pkHex, sdp: pc.localDescription,
      });
    } catch (err) {
      shellPrint(`Negotiation failed: ${err.message}`, "err");
    } finally {
      entry.makingOffer = false;
    }
  });
  pc.addEventListener("connectionstatechange", () => {
    const s = pc.connectionState;
    if (s === "connected") {
      shellPrint(`Link to ${pkHex.slice(0,8)} connected`, "sys");
      // If we're already in a call when this peer finishes its handshake,
      // hand them our tracks now. Doing this on "connected" rather than at
      // ensurePeer-time keeps clear of the perfect-negotiation window —
      // the dc is open, so the renegotiation offer rides it cleanly.
      if (localStream && !entry.callSenders) addLocalTracksToPeer(entry);
    } else if (s === "disconnected") {
      // The dc may still be alive enough to carry an ICE-restart roundtrip.
      // restartIce() schedules a negotiationneeded with new ICE credentials;
      // the resulting offer rides the dc and recovery happens without the
      // user ever seeing the drop.
      shellPrint(`Link to ${pkHex.slice(0,8)} disconnected — restarting ICE`, "sys");
      try { pc.restartIce(); } catch {}
    } else if (s === "failed" || s === "closed") {
      shellPrint(`Link to ${pkHex.slice(0,8)} ${s}`, "sys");
      try { pc.close(); } catch {}
      if (peers.get(pkHex) === entry) peers.delete(pkHex);
      removeRemoteTile(pkHex);
      updatePeerPill();
      updateCallStatus();
    }
  });
}

function makeEntry(pc, pkHex) {
  return {
    pc, dc: null, pendingIce: [],
    polite: myPkHex > pkHex,
    makingOffer: false,
    ignoreOffer: false,
    callSenders: null,
  };
}

function ensurePeer(pkHex) {
  let entry = peers.get(pkHex);
  if (entry) return entry;
  entry = makeEntry(new RTCPeerConnection(RTC_CONFIG), pkHex);
  peers.set(pkHex, entry);
  attachPeerListeners(entry, pkHex);
  return entry;
}

async function flushPendingIce(entry) {
  for (const c of entry.pendingIce) {
    try { await entry.pc.addIceCandidate(c); }
    catch (err) {
      if (!entry.ignoreOffer) shellPrint(`ICE add failed: ${err.message}`, "err");
    }
  }
  entry.pendingIce = [];
}

async function onSignal(msg) {
  if (!msg || typeof msg !== "object") return;
  if (msg.from === myPkHex) return;
  if (msg.to && msg.to !== myPkHex) return;

  switch (msg.type) {
    case "hello": {
      // A hello with no `to` is a broadcast — only sent on relay-open, and
      // semantically means "I'm starting fresh." If we have an entry for
      // this peer it's a zombie (their tab reloaded; their previous pc is
      // gone) and we MUST tear it down even if our dc.readyState still
      // claims "open" — the SCTP session under it is dead and our pc
      // won't notice for ~30s. A directed hello (reply to our broadcast)
      // is just the bootstrap dance bouncing back; we leave any existing
      // entry alone to avoid the entry-recreate / dc-recreate loop that
      // would happen if we tore down on every directed hello.
      const broadcast = !msg.to;
      if (broadcast) {
        const existing = peers.get(msg.from);
        if (existing) {
          try { existing.pc.close(); } catch {}
          peers.delete(msg.from);
        }
      }
      const isFresh = !peers.has(msg.from);
      const entry = ensurePeer(msg.from);
      // Reply only to broadcasts. Replying to directed hellos would loop
      // forever (each side keeps bouncing the directed reply).
      if (broadcast) {
        signalRelay({ type: "hello", from: myPkHex, to: msg.from });
      }
      // Impolite side opens the data channel — only on a fresh entry.
      // Repeated directed hellos for an existing entry are no-ops here.
      if (isFresh && !entry.polite) {
        const dc = entry.pc.createDataChannel("seedkernel");
        bindDataChannel(entry, dc, msg.from);
      }
      break;
    }
    case "sdp": {
      // Only auto-create an entry on a fresh offer. An "answer" arriving
      // for a peer we don't know is meaningless — drop it.
      const entry = msg.sdp.type === "offer"
        ? (peers.get(msg.from) ?? ensurePeer(msg.from))
        : peers.get(msg.from);
      if (!entry) return;
      // Glare check: an offer arriving while we are also offering (or are
      // mid-renegotiation) is a collision. Polite side accepts it (rolling
      // back its own offer implicitly via setRemoteDescription); impolite
      // side ignores. ignoreOffer also gates the matching ICE candidates
      // below so they don't spam errors after the rollback.
      const offerCollision = msg.sdp.type === "offer" &&
        (entry.makingOffer || entry.pc.signalingState !== "stable");
      entry.ignoreOffer = !entry.polite && offerCollision;
      if (entry.ignoreOffer) return;
      try {
        await entry.pc.setRemoteDescription(msg.sdp);
        await flushPendingIce(entry);
        if (msg.sdp.type === "offer") {
          await entry.pc.setLocalDescription();
          sendSignal(msg.from, {
            type: "sdp", from: myPkHex, to: msg.from, sdp: entry.pc.localDescription,
          });
        }
      } catch (err) {
        shellPrint(`SDP handling failed: ${err.message}`, "err");
      }
      break;
    }
    case "ice": {
      const entry = peers.get(msg.from);
      if (!entry) return;
      if (entry.pc.remoteDescription) {
        try { await entry.pc.addIceCandidate(msg.candidate); }
        catch (err) {
          // Stray candidates from a rolled-back offer are expected — ignore
          // them silently when ignoreOffer is set.
          if (!entry.ignoreOffer) shellPrint(`ICE add failed: ${err.message}`, "err");
        }
      } else {
        entry.pendingIce.push(msg.candidate);
      }
      break;
    }
  }
}

function broadcastWire(wire) {
  let sent = 0;
  for (const entry of peers.values()) {
    if (entry.dc && entry.dc.readyState === "open") {
      entry.dc.send(wire);
      sent++;
    }
  }
  return sent;
}

// ─── live audio/video calls ────────────────────────────────────────────
//
// Calls ride on the same RTCPeerConnections that carry the data channel.
// addTrack triggers negotiationneeded; the perfect-negotiation block above
// produces the renegotiation offer and signals it over the dc (or relay
// if the dc isn't open yet). New peers that join mid-call get our tracks
// added in the "connected" branch of connectionstatechange, so we never
// fight the initial handshake.
//
// Per-peer entry.callSenders lets Hang up call removeTrack on the exact
// senders we added (and only those), so a future addTrack from another
// feature wouldn't get ripped out by hangup.
//
// Remote tracks land in attachPeerListeners' "track" handler, which
// builds a per-peer tile keyed by pkHex. Tile cleanup happens on track
// "ended" (clean removeTrack from the other side) and on the peer's
// connectionstate going to failed/closed (their pc died).

const callBar      = document.getElementById("call-bar");
const callStartBtn = document.getElementById("call-start");
const callMuteBtn  = document.getElementById("call-mute");
const callEndBtn   = document.getElementById("call-end");
const callStatus   = document.getElementById("call-status");
const videoTiles   = document.getElementById("video-tiles");

let localStream = null;
let micEnabled = true;
const remoteTiles = new Map(); // pkHex -> { wrap, video, stream }

function updateCallStatus() {
  if (!localStream) {
    callStatus.textContent = "idle";
    callBar.classList.add("idle");
  } else {
    let connected = 0;
    for (const e of peers.values()) if (e.pc.connectionState === "connected") connected++;
    callStatus.textContent = connected === 0
      ? "in call (waiting for peers)"
      : `in call · ${connected} peer${connected === 1 ? "" : "s"}`;
    callBar.classList.remove("idle");
  }
}

function showTilesIfAny() {
  const has = !!localStream || remoteTiles.size > 0;
  videoTiles.classList.toggle("hidden", !has);
}

function ensureLocalTile() {
  if (document.getElementById("tile-local")) return;
  const wrap = document.createElement("div");
  wrap.className = "tile local";
  wrap.id = "tile-local";
  const v = document.createElement("video");
  v.autoplay = true;
  v.muted = true;
  v.playsInline = true;
  v.srcObject = localStream;
  const lab = document.createElement("div");
  lab.className = "tile-label";
  lab.textContent = `me · ${myPkHex.slice(0, 8)}`;
  wrap.appendChild(v);
  wrap.appendChild(lab);
  videoTiles.appendChild(wrap);
  showTilesIfAny();
}

function removeLocalTile() {
  const t = document.getElementById("tile-local");
  if (!t) return;
  const v = t.querySelector("video");
  if (v) v.srcObject = null;
  t.remove();
  showTilesIfAny();
}

function getOrCreateRemoteTile(pkHex) {
  let t = remoteTiles.get(pkHex);
  if (t) return t;
  const wrap = document.createElement("div");
  wrap.className = "tile";
  const v = document.createElement("video");
  v.autoplay = true;
  v.playsInline = true;
  const stream = new MediaStream();
  v.srcObject = stream;
  const lab = document.createElement("div");
  lab.className = "tile-label";
  lab.textContent = pkHex.slice(0, 8);
  wrap.appendChild(v);
  wrap.appendChild(lab);
  videoTiles.appendChild(wrap);
  t = { wrap, video: v, stream };
  remoteTiles.set(pkHex, t);
  showTilesIfAny();
  return t;
}

function removeRemoteTile(pkHex) {
  const t = remoteTiles.get(pkHex);
  if (!t) return;
  for (const track of t.stream.getTracks()) {
    try { t.stream.removeTrack(track); } catch {}
  }
  t.video.srcObject = null;
  t.wrap.remove();
  remoteTiles.delete(pkHex);
  showTilesIfAny();
}

function addLocalTracksToPeer(entry) {
  if (!localStream || entry.callSenders) return;
  entry.callSenders = [];
  try {
    for (const t of localStream.getTracks()) {
      entry.callSenders.push(entry.pc.addTrack(t, localStream));
    }
  } catch (err) {
    entry.callSenders = null;
    shellPrint(`addTrack failed: ${err.message}`, "err");
  }
}

async function startCall() {
  if (localStream) return;
  callStartBtn.disabled = true;
  callStatus.textContent = "requesting camera + mic...";
  try {
    localStream = await navigator.mediaDevices.getUserMedia({
      audio: true, video: true,
    });
  } catch (err) {
    shellPrint(`getUserMedia failed: ${err.message}`, "err");
    callStartBtn.disabled = false;
    updateCallStatus();
    return;
  }
  micEnabled = true;
  callMuteBtn.textContent = "Mute";
  callMuteBtn.disabled = false;
  callEndBtn.disabled = false;
  callStartBtn.disabled = true;
  ensureLocalTile();
  for (const entry of peers.values()) {
    if (entry.pc.connectionState === "connected") addLocalTracksToPeer(entry);
  }
  updateCallStatus();
  shellPrint("Call started.", "sys");
}

function endCall() {
  if (!localStream) return;
  for (const entry of peers.values()) {
    if (entry.callSenders) {
      for (const sender of entry.callSenders) {
        try { entry.pc.removeTrack(sender); } catch {}
      }
      entry.callSenders = null;
    }
  }
  for (const t of localStream.getTracks()) t.stop();
  localStream = null;
  removeLocalTile();
  for (const pkHex of Array.from(remoteTiles.keys())) removeRemoteTile(pkHex);
  callStartBtn.disabled = false;
  callMuteBtn.disabled = true;
  callEndBtn.disabled = true;
  updateCallStatus();
  shellPrint("Call ended.", "sys");
}

function toggleMute() {
  if (!localStream) return;
  micEnabled = !micEnabled;
  for (const t of localStream.getAudioTracks()) t.enabled = micEnabled;
  callMuteBtn.textContent = micEnabled ? "Mute" : "Unmute";
}

callStartBtn.addEventListener("click", startCall);
callEndBtn.addEventListener("click", endCall);
callMuteBtn.addEventListener("click", toggleMute);

// ─── signaling transport ───────────────────────────────────────────────
//
// sendSignal prefers the per-peer data channel and falls back to the relay,
// so renegotiation works after the relay has been killed. signalRelay is
// for messages with no specific peer (the broadcast hello on connect) or
// where we know there is no dc yet.
//
// During the manual SDP bootstrap (no relay, no dc yet) the icecandidate
// listener will fire and reach sendSignal with no transport. That's safe
// to drop silently — the candidates are already baked into the SDP blob
// via waitForIceGatheringComplete.

let ws = null;

function sendSignal(pkHex, obj) {
  const json = JSON.stringify(obj);
  const entry = peers.get(pkHex);
  if (entry && entry.dc && entry.dc.readyState === "open") {
    try { entry.dc.send(json); return; } catch {}
  }
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(json);
}

function signalRelay(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

// Proactive ICE restart on network change. ICE keepalives take 5–10s to
// notice a network flip on their own; firing restartIce() the moment the
// browser tells us connectivity changed cuts straight to recovery.
function restartIceForAll(reason) {
  let kicked = 0;
  for (const entry of peers.values()) {
    try { entry.pc.restartIce(); kicked++; } catch {}
  }
  if (kicked > 0) shellPrint(`${reason} — restarting ICE for ${kicked} peer(s)`, "sys");
}
window.addEventListener("online", () => restartIceForAll("Network online"));
if (navigator.connection && typeof navigator.connection.addEventListener === "function") {
  navigator.connection.addEventListener("change",
    () => restartIceForAll("Network changed"));
}

function connectRelay() {
  const url = relayUrlInput.value.trim();
  if (!url) { shellPrint("Enter a relay URL.", "err"); return; }
  if (ws) { try { ws.close(); } catch {} }
  shellPrint(`Connecting to ${url}...`, "sys");
  relayStatus.textContent = "connecting...";
  setRelayPill("connecting", "connecting");
  relayConnectBtn.disabled = true;
  ws = new WebSocket(url);
  ws.addEventListener("open", () => {
    shellPrint("Relay connected — waiting for peers.", "sys");
    relayStatus.textContent = `connected (${url})`;
    setRelayPill("ok", "relay");
    // Remember the working URL so a reload picks the relay back up
    // automatically (see the auto-reconnect below). Saved on success only,
    // so a typo doesn't get retried forever.
    sessionStorage.setItem("chat.relayUrl", url);
    signalRelay({ type: "hello", from: myPkHex });
  });
  ws.addEventListener("message", (ev) => {
    if (typeof ev.data !== "string") return;
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    onSignal(msg).catch(err => shellPrint(`Signaling error: ${err.message}`, "err"));
  });
  ws.addEventListener("close", () => {
    relayStatus.textContent = "disconnected";
    setRelayPill("off", "no relay");
    relayConnectBtn.disabled = false;
    shellPrint("Relay disconnected. Existing P2P links unaffected.", "sys");
  });
  ws.addEventListener("error", () => {
    relayStatus.textContent = "error";
    setRelayPill("err", "relay error");
    relayConnectBtn.disabled = false;
    shellPrint(`Relay error — is one running at ${url}?`, "err");
  });
}
relayConnectBtn.addEventListener("click", connectRelay);
relayUrlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); connectRelay(); }
});

// Default relay URL: same host the page is loaded from (so phones loading
// the shell off a desktop's LAN IP get the right pre-fill out of the box).
// Always ws:// — the relay is plain WebSocket; user can override to wss://.
// Falls back to "localhost" on file:// where location.hostname is empty.
function defaultRelayUrl() {
  const host = location.hostname || "localhost";
  return `ws://${host}:8080`;
}

// Auto-reconnect to the last relay that successfully accepted us. This is
// the other half of the reload story: re-establishing the relay link is
// what lets our broadcast hello reach peers and tear down their zombie
// entries for our previous tab.
const savedRelayUrl = sessionStorage.getItem("chat.relayUrl");
if (savedRelayUrl) {
  relayUrlInput.value = savedRelayUrl;
  connectRelay();
} else {
  relayUrlInput.value = defaultRelayUrl();
}

// ─── manual SDP exchange ───────────────────────────────────────────────
function waitForIceGatheringComplete(pc) {
  if (pc.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    const check = () => {
      if (pc.iceGatheringState === "complete") {
        pc.removeEventListener("icegatheringstatechange", check);
        resolve();
      }
    };
    pc.addEventListener("icegatheringstatechange", check);
  });
}
function encodeBlob(obj) {
  return btoa(JSON.stringify(obj))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function decodeBlob(text) {
  let s = text.trim();
  const m = s.match(/[#?]offer=([^&\s]+)/);
  if (m) s = m[1];
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return JSON.parse(atob(s));
}
function offerLinkFor(blob) {
  return `${location.origin}${location.pathname}#offer=${blob}`;
}
let pendingManualOffer = null;
let lastOfferBlob = null;

makeOfferBtn.addEventListener("click", async () => {
  makeOfferBtn.disabled = true;
  copyLinkBtn.disabled = true;
  myOfferBox.classList.remove("ready");
  myOfferArea.value = "";
  myOfferArea.placeholder = "gathering ICE candidates...";
  try {
    if (pendingManualOffer) { try { pendingManualOffer.pc.close(); } catch {} }
    const pc = new RTCPeerConnection(RTC_CONFIG);
    const dc = pc.createDataChannel("seedkernel");
    pendingManualOffer = { pc, dc };
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await waitForIceGatheringComplete(pc);
    lastOfferBlob = encodeBlob({ from: myPkHex, type: "offer", sdp: pc.localDescription });
    myOfferArea.value = lastOfferBlob;
    myOfferBox.classList.add("ready");
    copyLinkBtn.disabled = false;
    shellPrint("Invite ready — send the link to your peer.", "sys");
  } catch (err) {
    myOfferArea.value = "";
    lastOfferBlob = null;
    shellPrint(`Offer failed: ${err.message}`, "err");
  } finally {
    makeOfferBtn.disabled = false;
    myOfferArea.placeholder = "No invite yet — press Generate.";
  }
});

copyLinkBtn.addEventListener("click", async () => {
  if (!lastOfferBlob) return;
  const link = offerLinkFor(lastOfferBlob);
  try {
    await navigator.clipboard.writeText(link);
    const prev = copyLinkBtn.textContent;
    copyLinkBtn.textContent = "copied!";
    setTimeout(() => { copyLinkBtn.textContent = prev; }, 1100);
    shellPrint("Invite link copied to clipboard.", "sys");
  } catch {
    myOfferArea.value = link;
    shellPrint("Couldn't write to clipboard — link is in the textarea above.", "err");
  }
});

applyAnswerBtn.addEventListener("click", async () => {
  if (!pendingManualOffer) {
    shellPrint("No pending offer — generate one first.", "err");
    return;
  }
  let parsed;
  try { parsed = decodeBlob(theirAnswerArea.value); }
  catch (err) { shellPrint(`Bad answer blob: ${err.message}`, "err"); return; }
  if (parsed.type !== "answer" || !parsed.from) {
    shellPrint("That doesn't look like an answer.", "err"); return;
  }
  const peerPkHex = parsed.from;
  const { pc, dc } = pendingManualOffer;
  pendingManualOffer = null;
  // Adopt the pre-built pc + dc into the peers map under the just-learned
  // peer pubkey. attachPeerListeners installs the same negotiationneeded /
  // icecandidate / connectionstatechange handlers as ensurePeer, so any
  // future renegotiation (ICE restart on network change, future media-track
  // adds) flows through the perfect-negotiation path over the dc.
  const entry = makeEntry(pc, peerPkHex);
  peers.set(peerPkHex, entry);
  attachPeerListeners(entry, peerPkHex);
  bindDataChannel(entry, dc, peerPkHex);
  try {
    await pc.setRemoteDescription(parsed.sdp);
    shellPrint(`Negotiating manual link to ${peerPkHex.slice(0,8)}...`, "sys");
    showTab("app");
  } catch (err) {
    shellPrint(`Apply answer failed: ${err.message}`, "err");
  }
});

makeAnswerBtn.addEventListener("click", async () => {
  let parsed;
  try { parsed = decodeBlob(theirOfferArea.value); }
  catch (err) { shellPrint(`Bad offer blob: ${err.message}`, "err"); return; }
  if (parsed.type !== "offer" || !parsed.from) {
    shellPrint("That doesn't look like an offer.", "err"); return;
  }
  const peerPkHex = parsed.from;
  if (peers.has(peerPkHex)) {
    shellPrint(`Already have a peer entry for ${peerPkHex.slice(0,8)}.`, "err"); return;
  }
  makeAnswerBtn.disabled = true;
  copyAnswerBtn.disabled = true;
  myAnswerBox.classList.remove("ready");
  myAnswerArea.value = "";
  myAnswerArea.placeholder = "gathering ICE candidates...";
  try {
    const entry = ensurePeer(peerPkHex);
    await entry.pc.setRemoteDescription(parsed.sdp);
    const answer = await entry.pc.createAnswer();
    await entry.pc.setLocalDescription(answer);
    await waitForIceGatheringComplete(entry.pc);
    myAnswerArea.value = encodeBlob({
      from: myPkHex, type: "answer", sdp: entry.pc.localDescription,
    });
    myAnswerBox.classList.add("ready");
    copyAnswerBtn.disabled = false;
    shellPrint("Answer ready — send it back to your peer.", "sys");
  } catch (err) {
    myAnswerArea.value = "";
    shellPrint(`Generate answer failed: ${err.message}`, "err");
  } finally {
    makeAnswerBtn.disabled = false;
    myAnswerArea.placeholder = "No answer yet — generate one first.";
  }
});

copyAnswerBtn.addEventListener("click", async () => {
  if (!myAnswerArea.value) return;
  try {
    await navigator.clipboard.writeText(myAnswerArea.value);
    const prev = copyAnswerBtn.textContent;
    copyAnswerBtn.textContent = "copied!";
    setTimeout(() => { copyAnswerBtn.textContent = prev; }, 1100);
  } catch {
    myAnswerArea.select();
    shellPrint("Couldn't write to clipboard — answer is selected, press copy.", "err");
  }
});

if (location.hash.startsWith("#offer=")) {
  const code = location.hash.slice("#offer=".length);
  showTab("accept");
  theirOfferArea.value = code;
  history.replaceState(null, "", location.pathname + location.search);
  shellPrint("Invite link detected — generating answer...", "sys");
  makeAnswerBtn.click();
}

// Initial peer / call status. (relay pill is already in its "off" default
// state from markup; connectRelay below will manage it from here on.)
updatePeerPill();
updateCallStatus();
