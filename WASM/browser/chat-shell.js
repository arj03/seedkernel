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
const relayRoomInput = document.getElementById("relay-room");
const relayConnectBtn = document.getElementById("connect-relay");
const relayNewRoomBtn = document.getElementById("new-room");
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
const appStatus = document.getElementById("app-status");
const frame = document.getElementById("app-frame");
const appEmpty = document.getElementById("app-empty");
const aboutBtn = document.getElementById("about-toggle");
const aboutPanel = document.getElementById("about");
const dropzone = document.getElementById("dropzone");
const appFileInput = document.getElementById("app-file");
const appListEl = document.getElementById("app-list");
const offerListEl = document.getElementById("offer-list");
const offersSection = document.getElementById("offers-section");
const openAppsBtn = document.getElementById("open-apps-btn");
const appsNotice = document.getElementById("apps-notice");
let appsNoticeTimer = null;

// Surface a message on the Apps panel. Diagnostics still gets the full text
// via shellPrint; this is the part the user actually sees when they're not
// looking at the App-tab diagnostics drawer.
function showAppsNotice(text, kind = "err") {
  appsNotice.textContent = text;
  appsNotice.classList.remove("err", "ok");
  if (kind === "err" || kind === "ok") appsNotice.classList.add(kind);
  appsNotice.hidden = false;
  if (appsNoticeTimer) clearTimeout(appsNoticeTimer);
  appsNoticeTimer = setTimeout(() => { appsNotice.hidden = true; }, 6000);
  // Make sure the panel is visible — if the user dropped a file from the
  // Chat tab via the toolbar shortcut, surface the result where they'll see it.
  showTab("apps");
}

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
  apps:   { btn: document.getElementById("tab-apps"),   panel: document.getElementById("panel-apps")   },
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

// ─── bootstrap: signature wrapper + installer ──────────────────────────
const signatureName       = host.deriveBootstrapName("signature");
const signatureSignerName = host.deriveBootstrapName("signature.signer");
const installName         = host.deriveBootstrapName("install");
const lookupName          = host.deriveBootstrapName("installer.lookup");
const capsOfName          = host.deriveBootstrapName("installer.caps_of");

host.registerSignature(signatureName);
host.registerSignerQuery(signatureSignerName);   // apps query the signer
host.registerInstaller(installName, lookupName, capsOfName);

// ── install-approval policy ────────────────────────────────────────────
//
// Updates from an author we already trust (= we already hold an install
// record under this name with the same author key) are auto-approved as long
// as the parent chain matches — that is exactly the "trust updates from the
// same author" guarantee. First installs require explicit user consent; the
// UI gates them by adding the install's bytes_hash to `pendingApprovals`
// before dispatching the signed envelope. Anything else is dropped.
const pendingApprovals = new Set();   // hex bytesHash → awaiting policy call

host.setApproveInstall((name, author, bytesHash, _wasm, _caps, parent, existing) => {
  const hex = bytesToHex(bytesHash);
  if (existing) {
    if (existing.author.algoId !== author.algoId) return false;
    if (!bytesEqual(existing.author.publicKey, author.publicKey)) return false;
    if (!parent || !bytesEqual(existing.bytesHash, parent)) return false;
    pendingApprovals.delete(hex);   // consume even if not strictly needed
    return true;
  }
  if (pendingApprovals.has(hex)) {
    pendingApprovals.delete(hex);
    return true;
  }
  return false;
});

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

shellPrint(`I am ${myPkHex.slice(0, 8)}`, "sys");

// ─── DTLS-fingerprint identity assertion (RFC 8827 §5.6.4) ─────────────
//
// WebRTC already gives us a confidential, integrity-protected DTLS channel
// for each pc. To bind that channel to a kernel identity we sign the SDP's
// a=fingerprint lines with the kernel privkey and ship the signature in the
// signaling envelope. The peer verifies the signature against the fingerprint
// it actually sees in the SDP, so from that point on every byte that comes
// out of the resulting DTLS tunnel is provably from the holder of `pk`.
//
// As defense-in-depth we ALSO peek at each binary dc frame's wrapper bytes
// and drop anything whose signer doesn't equal the pk we've bound to that
// channel — so even if the kernel later grows an unsigned-envelope path,
// a peer cannot smuggle envelopes signed by some other key over a dc we've
// already authenticated to their identity.
const DTLS_AUTH_DOMAIN = "seedkernel-dtls-id-v1\0";
const DTLS_AUTH_DOMAIN_BYTES = new TextEncoder().encode(DTLS_AUTH_DOMAIN);

// Cap on speculative (unauthed) peer entries that the relay can force us to
// allocate via unauthenticated `hello` signals. Authed peers do not count, so
// genuine fleet size is unbounded; only the unauthenticated allocator is. A
// hello that would push the count above this is dropped — the attacker can
// recover slots by waiting for entries to time out / get torn down, but cannot
// grow the table without bound. Sized for a worst-case legitimate burst
// (everyone reconnecting after the relay flaps) with headroom.
const MAX_UNAUTHED_PEERS = 32;

function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) return null;
    out[i] = b;
  }
  return out;
}

function extractFingerprintsFromSdp(sdpString) {
  // Canonical form: each `a=fingerprint:...` line trimmed, joined by '\n'
  // in the order they appear in the SDP. Both peers see the same SDP text,
  // so this is deterministic across the wire.
  if (typeof sdpString !== "string") return "";
  const lines = sdpString.split(/\r?\n/);
  const fps = [];
  for (const l of lines) if (l.startsWith("a=fingerprint:")) fps.push(l.trim());
  return fps.join("\n");
}

function signSdpIdentity(sdpString) {
  const fps = extractFingerprintsFromSdp(sdpString);
  if (!fps) throw new Error("SDP has no a=fingerprint lines to bind");
  const fpsBytes = new TextEncoder().encode(fps);
  const msg = new Uint8Array(DTLS_AUTH_DOMAIN_BYTES.length + fpsBytes.length);
  msg.set(DTLS_AUTH_DOMAIN_BYTES, 0);
  msg.set(fpsBytes, DTLS_AUTH_DOMAIN_BYTES.length);
  return sodium.crypto_sign_detached(msg, myKeys.privateKey);
}

function verifySdpIdentity(sdpString, pk, sig) {
  const fps = extractFingerprintsFromSdp(sdpString);
  if (!fps) return false;
  const fpsBytes = new TextEncoder().encode(fps);
  const msg = new Uint8Array(DTLS_AUTH_DOMAIN_BYTES.length + fpsBytes.length);
  msg.set(DTLS_AUTH_DOMAIN_BYTES, 0);
  msg.set(fpsBytes, DTLS_AUTH_DOMAIN_BYTES.length);
  try { return sodium.crypto_sign_verify_detached(sig, msg, pk); }
  catch { return false; }
}

// Peek the signer pubkey from a §6.3 signature envelope without invoking the
// kernel — used to enforce signer==entry.pk on every dc frame.
// Outer: MAGIC(2) | version(1) | name_len(1) | name | payload
// Payload (signature name): algo u16 | signer_len u16 | signer | sig_len u16 | sig | inner
function peekEnvelopeSigner(bytes) {
  if (bytes.length < 4) return null;
  if (bytes[0] !== 0x53 || bytes[1] !== 0x44) return null;
  const nameLen = bytes[3];
  if (nameLen !== signatureName.length) return null;
  if (bytes.length < 4 + nameLen) return null;
  for (let i = 0; i < nameLen; i++) {
    if (bytes[4 + i] !== signatureName[i]) return null;
  }
  let o = 4 + nameLen;
  if (bytes.length < o + 4) return null;
  o += 2; // skip algo
  const signerLen = (bytes[o] << 8) | bytes[o + 1]; o += 2;
  if (bytes.length < o + signerLen) return null;
  return bytes.subarray(o, o + signerLen);
}

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function sendSignedSdp(toPkHex, desc) {
  const sig = signSdpIdentity(desc.sdp);
  sendSignal(toPkHex, {
    type: "sdp", from: myPkHex, to: toPkHex,
    sdp: desc,
    idSig: bytesToHex(sig),
  });
}

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

// ─── app registry ──────────────────────────────────────────────────────
//
// An "app" is a signed install envelope (signature wrapper around an inner
// install envelope §7.2) that carries a WASM payload with two embedded
// custom sections: "app_meta" (a JSON manifest — id, name, version) and
// "ui" (HTML rendered in the sandboxed iframe).
//
// Each app installs under a kernel name derived from its `id`:
//     handlerName  = SHA-3-256("seedkernel.bootstrap.v1:app:" + id)
//     uiBridgeName = SHA-3-256("app:" + id + ".ui" + myPubKey)        (scoped)
//
// `handlerName` is globally derivable so two peers running the same app id
// route messages to the same name. `uiBridgeName` is scoped to this peer's
// pubkey: it is a local-only bridge from app WASM → this shell's iframe and
// must not be reachable by an envelope another peer constructs.
//
// `installedApps` keeps the per-app state we need to re-mount the UI, send
// updates, and re-broadcast the sealed bytes transitively (`sealedBytes` is
// the original signature-wrapped install envelope — author's signature intact
// — and is what every "Offer" hands to a peer).
//
// The local user authors installs they originate by signing with `myKeys`.
// Apps received via Offer keep the original author's signature: we never
// re-sign install content, we only wrap it in our own outer `app.offer`
// envelope to satisfy the dc per-frame signer check.
const installedApps = new Map();   // id → AppRecord
let activeAppId = null;

// Per-signer monotonic seq for installs we author (§4.4). Bumped on every
// own-signed install we dispatch.
let installSeq = parseInt(sessionStorage.getItem("apps.installSeq") || "0", 10);
function nextSeq() {
  installSeq++;
  sessionStorage.setItem("apps.installSeq", String(installSeq));
  return installSeq;
}

function appHandlerName(id) {
  return host.deriveBootstrapName("app:" + id);
}
function appUiBridgeName(id) {
  return host.deriveScopedName("app:" + id + ".ui", myKeys.publicKey);
}

// ── iframe bridge ──────────────────────────────────────────────────────
//
// The active app's WASM forwards render events to its uiBridgeName via
// kernel.call. We forward those to the iframe via postMessage. Renders that
// arrive before the iframe says "ready" are queued so a hot-swap doesn't
// drop the first message.
let iframeReady = false;
const renderQueue = [];

function deliverRender(payload) {
  if (iframeReady && frame.contentWindow) {
    frame.contentWindow.postMessage({ type: "render", payload }, "*");
  } else {
    renderQueue.push(payload);
  }
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

function registerUiBridge(appId) {
  const uiName = appUiBridgeName(appId);
  const handlerName = appHandlerName(appId);
  host.register(uiName, (_n, payload) => {
    // Only the active app's handler may drive the UI bridge. The
    // caller-check defends against a co-installed app calling another app's
    // bridge — kernel.caller (§4.2) returns the immediate caller; we
    // compare against the expected handler name for this bridge.
    if (appId !== activeAppId) return null;
    const c = host.currentCaller;
    if (!c || c.length !== handlerName.length) return null;
    for (let i = 0; i < c.length; i++) if (c[i] !== handlerName[i]) return null;
    deliverRender(new Uint8Array(payload));
    return null;
  });
}

function encodeConfigPayload(uiName) {
  const buf = new Uint8Array(1 + uiName.length + 1 + signatureSignerName.length);
  let o = 0;
  buf[o++] = uiName.length;
  buf.set(uiName, o); o += uiName.length;
  buf[o++] = signatureSignerName.length;
  buf.set(signatureSignerName, o); o += signatureSignerName.length;
  return buf;
}

// ── parsing the wasm artifact ──────────────────────────────────────────
async function readWasmSections(wasmBytes) {
  const mod = await WebAssembly.compile(wasmBytes);
  const ui = WebAssembly.Module.customSections(mod, "ui");
  const meta = WebAssembly.Module.customSections(mod, "app_meta");
  let parsedMeta = null;
  if (meta.length > 0) {
    try { parsedMeta = JSON.parse(new TextDecoder().decode(new Uint8Array(meta[0]))); }
    catch { parsedMeta = null; }
  }
  const uiHtml = ui.length > 0 ? new TextDecoder().decode(new Uint8Array(ui[0])) : null;
  return { meta: parsedMeta, uiHtml };
}

function promptMeta(defaultId) {
  // Fallback when a dropped .wasm has no app_meta section.
  const id = prompt("App id (lowercase, no spaces — used as the kernel name):", defaultId);
  if (!id) return null;
  const trimmed = id.trim();
  if (!/^[a-z0-9._-]+$/i.test(trimmed)) {
    const msg = "App id must be alphanumeric / . _ -";
    shellPrint(msg, "err");
    showAppsNotice(msg, "err");
    return null;
  }
  const name = prompt("Display name:", trimmed) || trimmed;
  const version = prompt("Version label:", "v1") || "v1";
  return { id: trimmed, name, version };
}

// ── kernel envelope parsing helpers ────────────────────────────────────
//
// We use these to peek inside a sealed install (the signature wrapper around
// an install envelope) without going through kernel dispatch — needed so the
// Apps UI can surface author + meta before the user accepts an install.
function parseEnvelope(bytes) {
  if (bytes.length < 4) return null;
  if (bytes[0] !== 0x53 || bytes[1] !== 0x44) return null;
  const version = bytes[2];
  const nameLen = bytes[3];
  if (nameLen === 0 || bytes.length < 4 + nameLen) return null;
  const name = bytes.subarray(4, 4 + nameLen);
  const payload = bytes.subarray(4 + nameLen);
  return { version, name, payload };
}

function parseSignatureWrapperPayload(payload) {
  if (payload.length < 6) return null;
  let o = 0;
  const algo = (payload[o] << 8) | payload[o + 1]; o += 2;
  const signerLen = (payload[o] << 8) | payload[o + 1]; o += 2;
  if (payload.length < o + signerLen + 2) return null;
  const signer = payload.subarray(o, o + signerLen); o += signerLen;
  const sigLen = (payload[o] << 8) | payload[o + 1]; o += 2;
  if (payload.length < o + sigLen) return null;
  const sig = payload.subarray(o, o + sigLen); o += sigLen;
  const inner = payload.subarray(o);
  return { algo, signer, sig, inner };
}

function parseInstallPayload(payload) {
  if (payload.length < 5) return null;
  let o = 0;
  const seq = ((payload[o] << 24) | (payload[o + 1] << 16) |
               (payload[o + 2] << 8) | payload[o + 3]) >>> 0;
  o += 4;
  const nameLen = payload[o++];
  if (nameLen === 0 || payload.length < o + nameLen) return null;
  const name = payload.subarray(o, o + nameLen); o += nameLen;
  if (payload.length < o + 1) return null;
  const capsCount = payload[o++];
  const caps = [];
  for (let i = 0; i < capsCount; i++) {
    if (payload.length < o + 1) return null;
    const capLen = payload[o++];
    if (payload.length < o + capLen) return null;
    caps.push(payload.subarray(o, o + capLen)); o += capLen;
  }
  if (payload.length < o + 1) return null;
  const parentLen = payload[o++];
  if (payload.length < o + parentLen) return null;
  const parent = parentLen > 0 ? payload.subarray(o, o + parentLen) : null;
  o += parentLen;
  const wasm = payload.subarray(o);
  if (wasm.length === 0) return null;
  return { seq, name, caps, parent, wasm };
}

function unwrapSealed(sealedBytes) {
  const outer = parseEnvelope(sealedBytes);
  if (!outer || !bytesEqual(outer.name, signatureName)) return null;
  const wrapper = parseSignatureWrapperPayload(outer.payload);
  if (!wrapper) return null;
  const inner = parseEnvelope(wrapper.inner);
  if (!inner || !bytesEqual(inner.name, installName)) return null;
  const install = parseInstallPayload(inner.payload);
  if (!install) return null;
  return {
    authorPk: wrapper.signer,
    authorAlgo: wrapper.algo,
    installPayload: inner.payload,
    bytesHash: host.genesisHash(inner.payload),
    install,
  };
}

// ── installing an app (local-authored) ─────────────────────────────────
async function buildSealedInstall(meta, wasmBytes, parent) {
  const handlerName = appHandlerName(meta.id);
  const uiName = appUiBridgeName(meta.id);
  const installPayload = host.encodeInstallPayload(
    nextSeq(), handlerName, [uiName], parent, wasmBytes);
  return host.wrapAndEncode(
    myKeys.privateKey, myKeys.publicKey, CURRENT_VERSION, installName, installPayload);
}

// Dispatch a sealed install we already trust (the bytesHash has been added to
// pendingApprovals if needed). Returns the AppRecord on success.
async function applySealedInstall(sealedBytes) {
  const peeked = unwrapSealed(sealedBytes);
  if (!peeked) throw new Error("not a valid sealed install");
  const { meta, uiHtml } = await readWasmSections(peeked.install.wasm);
  // If the WASM carries no manifest at all we cannot derive an id. Sealed
  // installs always come from a path that already chose an id (either the
  // author embedded it or the local user supplied one before sealing); a
  // missing manifest here means a malformed bundle.
  if (!meta || !meta.id) throw new Error("install has no app_meta");

  const handlerName = appHandlerName(meta.id);
  // Make sure the bridge is wired before the WASM tries to call into it on
  // its first configure / message. Idempotent — re-registering replaces.
  registerUiBridge(meta.id);

  host.dispatch(sealedBytes);
  if (!host.isRegistered(handlerName)) {
    throw new Error("installer rejected the install");
  }

  // One-shot configure (§3.2 helper contract) — tell the WASM the names of
  // its UI bridge and the signer-query handler.
  host.callDynamicExport(handlerName, "configure",
    encodeConfigPayload(appUiBridgeName(meta.id)));

  const record = {
    id: meta.id,
    name: meta.name || meta.id,
    version: meta.version || "",
    description: meta.description || "",
    authorPk: peeked.authorPk.slice(),
    authorAlgo: peeked.authorAlgo,
    bytesHash: peeked.bytesHash,
    // Content hash of just the WASM payload. Stable across re-signings /
    // re-seqs by different authors, so two peers offering the same compiled
    // artifact display the same hash. `bytesHash` (above) covers the full
    // install payload — author seq, parent, caps — and so changes per
    // install message.
    wasmHash: host.genesisHash(peeked.install.wasm),
    sealedBytes: sealedBytes.slice(),
    handlerName,
    uiHtml,
  };
  installedApps.set(meta.id, record);
  // Persist sealed bytes across reloads so transitive offers / updates keep
  // working without re-receiving them.
  persistInstalledApps();
  renderAppList();
  return record;
}

// Add an app from raw WASM bytes by signing the install with the local key
// (the local user becomes the author).
async function addAppFromWasm(wasmBytes, fallbackId) {
  let { meta } = await readWasmSections(wasmBytes);
  if (!meta || !meta.id) {
    meta = promptMeta(fallbackId);
    if (!meta) return;
    // Re-embed the meta into the wasm so the sealed bundle carries it.
    wasmBytes = embedAppMeta(wasmBytes, meta);
  }
  const handlerName = appHandlerName(meta.id);
  const existing = host.lookupInstall(handlerName);
  // If we're updating something WE authored, chain the parent. Updates to
  // an app authored by someone else are not supported from this path —
  // those arrive via Offer from the original author.
  if (existing) {
    if (existing.author.algoId !== 0 ||
        !bytesEqual(existing.author.publicKey, myKeys.publicKey)) {
      const authorHex = bytesToHex(existing.author.publicKey).slice(0, 8);
      const msg =
        `Cannot install "${meta.id}": already installed and authored by ` +
        `${authorHex}, not you. Updates have to come from that author ` +
        `(e.g. via an Offer). Remove the existing app first if you want ` +
        `to author a different one under the same id.`;
      shellPrint(msg, "err");
      showAppsNotice(msg, "err");
      return;
    }
  }
  const parent = existing ? existing.bytesHash : null;
  const sealedBytes = await buildSealedInstall(meta, wasmBytes, parent);
  const peeked = unwrapSealed(sealedBytes);
  if (!peeked) throw new Error("internal: just-built sealed install did not parse");

  pendingApprovals.add(bytesToHex(peeked.bytesHash));
  try {
    const record = await applySealedInstall(sealedBytes);
    shellPrint(`Installed ${record.name} ${record.version}`, "sys");
    setActiveApp(record.id);
  } catch (err) {
    pendingApprovals.delete(bytesToHex(peeked.bytesHash));
    shellPrint(`Install failed: ${err.message}`, "err");
    showAppsNotice(`Install failed: ${err.message}`, "err");
  }
}

// Embed an app_meta JSON custom section into a wasm buffer. Mirror of
// scripts/embed-meta.mjs so the shell can produce a fully self-describing
// bundle when the user supplies metadata for a meta-less .wasm.
function embedAppMeta(wasmBytes, meta) {
  const json = new TextEncoder().encode(JSON.stringify(meta));
  const nameUtf = new TextEncoder().encode("app_meta");
  const leb = (n) => {
    const out = [];
    do { let b = n & 0x7f; n >>>= 7; if (n !== 0) b |= 0x80; out.push(b); } while (n !== 0);
    return new Uint8Array(out);
  };
  const inner = (() => {
    const nl = leb(nameUtf.length);
    const buf = new Uint8Array(nl.length + nameUtf.length + json.length);
    let o = 0;
    buf.set(nl, o); o += nl.length;
    buf.set(nameUtf, o); o += nameUtf.length;
    buf.set(json, o);
    return buf;
  })();
  const sz = leb(inner.length);
  const section = new Uint8Array(1 + sz.length + inner.length);
  section[0] = 0x00;
  section.set(sz, 1);
  section.set(inner, 1 + sz.length);
  const out = new Uint8Array(wasmBytes.length + section.length);
  out.set(wasmBytes, 0);
  out.set(section, wasmBytes.length);
  return out;
}

// ── persistence ────────────────────────────────────────────────────────
// Sealed bytes are the only piece of app state we need to rebuild — the
// install record on the installer side, the handler in the kernel, and the
// uiHtml all derive from them. We keep them in sessionStorage so a reload
// within the same tab keeps the user's app set and lets transitive offers
// continue to work.
function persistInstalledApps() {
  try {
    const arr = [];
    for (const rec of installedApps.values()) {
      arr.push(Array.from(rec.sealedBytes));
    }
    sessionStorage.setItem("apps.sealed", JSON.stringify(arr));
    if (activeAppId) sessionStorage.setItem("apps.active", activeAppId);
    else sessionStorage.removeItem("apps.active");
  } catch {}
}

async function restoreInstalledApps() {
  let arr;
  try { arr = JSON.parse(sessionStorage.getItem("apps.sealed") || "[]"); }
  catch { return; }
  if (!Array.isArray(arr)) return;
  for (const raw of arr) {
    try {
      // Restored installs were already approved in a prior tab session —
      // wave them through the approveInstall gate the same way an update
      // would be: by adding their bytesHash to pendingApprovals.
      const sealed = new Uint8Array(raw);
      const peeked = unwrapSealed(sealed);
      if (!peeked) continue;
      pendingApprovals.add(bytesToHex(peeked.bytesHash));
      await applySealedInstall(sealed);
    } catch (err) {
      shellPrint(`Could not restore an app: ${err.message}`, "err");
    }
  }
  const saved = sessionStorage.getItem("apps.active");
  if (saved && installedApps.has(saved)) setActiveApp(saved);
}

// ── active-app iframe mount ────────────────────────────────────────────
function setActiveApp(id) {
  const rec = installedApps.get(id);
  if (!rec) return;
  if (!rec.uiHtml) {
    shellPrint(`${rec.name} has no UI; cannot mount.`, "err");
    return;
  }
  activeAppId = id;
  iframeReady = false;
  renderQueue.length = 0;
  if (frame.dataset.blobUrl) URL.revokeObjectURL(frame.dataset.blobUrl);
  const uiBlob = new Blob([rec.uiHtml], { type: "text/html" });
  const uiUrl  = URL.createObjectURL(uiBlob);
  frame.dataset.blobUrl = uiUrl;
  frame.src = uiUrl;
  frame.classList.remove("hidden");
  appEmpty.classList.add("hidden");
  appStatus.textContent = `${rec.name} ${rec.version}`.trim();
  persistInstalledApps();
  renderAppList();
}

function unmountActiveApp() {
  activeAppId = null;
  iframeReady = false;
  renderQueue.length = 0;
  frame.src = "about:blank";
  if (frame.dataset.blobUrl) {
    URL.revokeObjectURL(frame.dataset.blobUrl);
    delete frame.dataset.blobUrl;
  }
  frame.classList.add("hidden");
  appEmpty.classList.remove("hidden");
  appStatus.textContent = "no app loaded";
  persistInstalledApps();
}

// ── peer-to-peer app offers ────────────────────────────────────────────
//
// An offer is a sealed install envelope forwarded over a data channel. Any
// peer who holds the sealed bytes can forward them (transitive offer) —
// the original author's signature on the inner install is preserved by the
// wrapper, so the recipient still authenticates against the author.
//
// The wire format: the sender wraps the sealed bytes inside their own
// signature envelope under the bootstrap name `app.offer`. The outer
// signature on the wrapper is required only because the dc per-frame check
// (bindDataChannel below) requires every binary frame to be signed by the
// channel owner. The inner sealed bytes are the load-bearing object.
const appOfferName = host.deriveBootstrapName("app.offer");
const pendingOffers = new Map();   // bytesHashHex → { sealedBytes, peeked, fromPkHex }

host.register(appOfferName, (_n, payload) => {
  // Defer processing: we cannot dispatch from inside a host handler (the
  // kernel is single-threaded re-entrantly), and a first-install needs an
  // async user prompt anyway.
  const sealed = new Uint8Array(payload);
  const fromSigner = host.currentTopSigner;
  const fromPkHex = fromSigner ? bytesToHex(fromSigner.publicKey) : "?";
  queueMicrotask(() => handleOffer(sealed, fromPkHex));
  return null;
});

async function handleOffer(sealedBytes, fromPkHex) {
  const peeked = unwrapSealed(sealedBytes);
  if (!peeked) return;
  const { install, authorPk, bytesHash } = peeked;

  let meta = null;
  try { meta = (await readWasmSections(install.wasm)).meta; } catch {}
  if (!meta || !meta.id) {
    shellPrint(`Offer from ${fromPkHex.slice(0, 8)} dropped: bundle has no app_meta`, "err");
    return;
  }
  const handlerName = appHandlerName(meta.id);
  const existing = host.lookupInstall(handlerName);

  // Auto-install path: the author + parent chain match an app we already
  // trust. The reference policy in setApproveInstall verifies the same
  // facts, so dispatching is safe — no extra approval needed.
  if (existing &&
      existing.author.algoId === peeked.authorAlgo &&
      bytesEqual(existing.author.publicKey, authorPk) &&
      install.parent && bytesEqual(existing.bytesHash, install.parent)) {
    try {
      const rec = await applySealedInstall(sealedBytes);
      shellPrint(
        `Auto-updated ${rec.name} → ${rec.version} ` +
        `(from ${fromPkHex.slice(0, 8)}, signed by ${bytesToHex(authorPk).slice(0, 8)})`, "sys");
      // If this was the active app, re-mount the new UI.
      if (activeAppId === rec.id) setActiveApp(rec.id);
    } catch (err) {
      shellPrint(`Auto-update failed: ${err.message}`, "err");
    }
    return;
  }

  // Hand the user the decision. We don't dispatch yet — installation only
  // happens after they click Install in the offer row.
  const hex = bytesToHex(bytesHash);
  if (pendingOffers.has(hex)) return;   // duplicate
  pendingOffers.set(hex, {
    sealedBytes: sealedBytes.slice(),
    peeked: { ...peeked, meta },
    wasmHash: host.genesisHash(peeked.install.wasm),
    fromPkHex,
  });
  renderOfferList();
  tabs.apps.btn.classList.add("unread");
  shellPrint(
    `${fromPkHex.slice(0, 8)} offers app "${meta.name || meta.id}" — see the Apps tab.`, "sys");
}

async function acceptOffer(bytesHashHex) {
  const offer = pendingOffers.get(bytesHashHex);
  if (!offer) return;
  pendingApprovals.add(bytesHashHex);
  try {
    const rec = await applySealedInstall(offer.sealedBytes);
    pendingOffers.delete(bytesHashHex);
    renderOfferList();
    shellPrint(`Installed ${rec.name} ${rec.version} from offer.`, "sys");
    setActiveApp(rec.id);
  } catch (err) {
    pendingApprovals.delete(bytesHashHex);
    shellPrint(`Install from offer failed: ${err.message}`, "err");
    showAppsNotice(`Install from offer failed: ${err.message}`, "err");
  }
}

function dismissOffer(bytesHashHex) {
  pendingOffers.delete(bytesHashHex);
  renderOfferList();
}

// Broadcast the stored sealed bytes for `id` to every open peer. Anyone who
// receives this can forward it to others — that's transitivity for free.
function offerApp(id) {
  const rec = installedApps.get(id);
  if (!rec) return;
  const offerWire = host.wrapAndEncode(
    myKeys.privateKey, myKeys.publicKey, CURRENT_VERSION, appOfferName, rec.sealedBytes);
  const n = broadcastWire(offerWire);
  shellPrint(
    n > 0
      ? `Offered ${rec.name} ${rec.version} to ${n} peer${n === 1 ? "" : "s"}.`
      : `No connected peers to offer ${rec.name} to.`,
    n > 0 ? "sys" : "err");
}

// ── apps panel UI ──────────────────────────────────────────────────────
function renderAppList() {
  appListEl.innerHTML = "";
  if (installedApps.size === 0) {
    const li = document.createElement("li");
    li.className = "empty-row";
    li.textContent = "No apps installed yet.";
    appListEl.appendChild(li);
    return;
  }
  for (const rec of installedApps.values()) {
    appListEl.appendChild(buildAppRow(rec));
  }
}

function buildAppRow(rec) {
  const li = document.createElement("li");
  li.className = "app-row";
  if (rec.id === activeAppId) li.classList.add("active");

  const head = document.createElement("div");
  head.className = "app-row-head";
  const nm = document.createElement("span");
  nm.className = "app-row-name";
  nm.textContent = rec.name;
  head.appendChild(nm);
  if (rec.version) {
    const v = document.createElement("span");
    v.className = "app-row-version";
    v.textContent = rec.version;
    head.appendChild(v);
  }
  li.appendChild(head);

  if (rec.description) {
    const d = document.createElement("div");
    d.className = "app-row-desc";
    d.textContent = rec.description;
    li.appendChild(d);
  }

  const meta = document.createElement("div");
  meta.className = "app-row-meta";
  const authorHex = bytesToHex(rec.authorPk);
  const isMine = bytesEqual(rec.authorPk, myKeys.publicKey);
  meta.innerHTML =
    `<b>id</b> ${rec.id} · <b>author</b> ${authorHex.slice(0, 8)}` +
    (isMine ? " (you)" : "") +
    ` · <b>wasm</b> ${bytesToHex(rec.wasmHash).slice(0, 12)}`;
  li.appendChild(meta);

  const btns = document.createElement("div");
  btns.className = "app-row-buttons";
  if (rec.uiHtml) {
    const openBtn = document.createElement("button");
    openBtn.className = "icon primary";
    openBtn.textContent = rec.id === activeAppId ? "Active" : "Open";
    openBtn.disabled = rec.id === activeAppId;
    openBtn.addEventListener("click", () => {
      setActiveApp(rec.id);
      showTab("app");
    });
    btns.appendChild(openBtn);
  }
  if (isMine) {
    const updateBtn = document.createElement("button");
    updateBtn.className = "icon";
    updateBtn.textContent = "Update…";
    const fileInput = document.createElement("input");
    fileInput.type = "file";
    fileInput.accept = ".wasm,application/wasm";
    fileInput.addEventListener("change", async () => {
      const f = fileInput.files && fileInput.files[0];
      if (!f) return;
      const bytes = new Uint8Array(await f.arrayBuffer());
      fileInput.value = "";
      await addAppFromWasm(bytes, rec.id);
    });
    updateBtn.addEventListener("click", () => fileInput.click());
    btns.appendChild(updateBtn);
    btns.appendChild(fileInput);
  }
  const offerBtn = document.createElement("button");
  offerBtn.className = "icon";
  offerBtn.textContent = "Offer to peers";
  offerBtn.addEventListener("click", () => offerApp(rec.id));
  btns.appendChild(offerBtn);

  const removeBtn = document.createElement("button");
  removeBtn.className = "icon danger";
  removeBtn.textContent = "Remove";
  removeBtn.addEventListener("click", () => removeApp(rec.id));
  btns.appendChild(removeBtn);

  li.appendChild(btns);
  return li;
}

function removeApp(id) {
  const rec = installedApps.get(id);
  if (!rec) return;
  if (!confirm(`Remove ${rec.name} ${rec.version}? The kernel handler will be uninstalled.`)) return;
  if (host.installer) host.installer.remove(rec.handlerName);
  installedApps.delete(id);
  if (activeAppId === id) unmountActiveApp();
  persistInstalledApps();
  renderAppList();
}

function renderOfferList() {
  offerListEl.innerHTML = "";
  if (pendingOffers.size === 0) {
    offersSection.hidden = true;
    return;
  }
  offersSection.hidden = false;
  for (const [hex, offer] of pendingOffers) {
    offerListEl.appendChild(buildOfferRow(hex, offer));
  }
}

function buildOfferRow(hex, offer) {
  const meta = offer.peeked.meta;
  const li = document.createElement("li");
  li.className = "app-row offer-row";
  const head = document.createElement("div");
  head.className = "app-row-head";
  const nm = document.createElement("span");
  nm.className = "app-row-name";
  nm.textContent = meta.name || meta.id;
  head.appendChild(nm);
  if (meta.version) {
    const v = document.createElement("span");
    v.className = "app-row-version";
    v.textContent = meta.version;
    head.appendChild(v);
  }
  li.appendChild(head);
  if (meta.description) {
    const d = document.createElement("div");
    d.className = "app-row-desc";
    d.textContent = meta.description;
    li.appendChild(d);
  }
  const m = document.createElement("div");
  m.className = "app-row-meta";
  m.innerHTML =
    `<b>id</b> ${meta.id} · <b>author</b> ${bytesToHex(offer.peeked.authorPk).slice(0, 8)}` +
    ` · <b>from</b> ${offer.fromPkHex.slice(0, 8)}` +
    ` · <b>wasm</b> ${bytesToHex(offer.wasmHash).slice(0, 12)}`;
  li.appendChild(m);
  const btns = document.createElement("div");
  btns.className = "app-row-buttons";
  const ok = document.createElement("button");
  ok.className = "icon primary";
  ok.textContent = "Install";
  ok.addEventListener("click", () => acceptOffer(hex));
  const no = document.createElement("button");
  no.className = "icon";
  no.textContent = "Dismiss";
  no.addEventListener("click", () => dismissOffer(hex));
  btns.appendChild(ok);
  btns.appendChild(no);
  li.appendChild(btns);
  return li;
}

// ── drag-drop + file picker plumbing ───────────────────────────────────
async function loadDroppedFile(file) {
  if (!file) return;
  const bytes = new Uint8Array(await file.arrayBuffer());
  // The filename's stem is the only signal we have for an id when the
  // bundle is meta-less; the prompt fallback uses it as a default.
  const stem = (file.name || "app").replace(/\.wasm$/i, "");
  await addAppFromWasm(bytes, stem);
}

dropzone.addEventListener("click", () => appFileInput.click());
dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    appFileInput.click();
  }
});
appFileInput.addEventListener("change", async () => {
  const f = appFileInput.files && appFileInput.files[0];
  appFileInput.value = "";
  if (f) await loadDroppedFile(f);
});
;["dragenter", "dragover"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.add("dragover");
  }));
;["dragleave", "drop"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (ev !== "drop") dropzone.classList.remove("dragover");
  }));
dropzone.addEventListener("drop", async (e) => {
  dropzone.classList.remove("dragover");
  const dt = e.dataTransfer;
  if (!dt || !dt.files || dt.files.length === 0) return;
  for (const f of dt.files) await loadDroppedFile(f);
});
openAppsBtn.addEventListener("click", () => showTab("apps"));

renderAppList();
renderOfferList();
// Pull back anything we installed earlier in this session before any peer
// link comes up — so once peers connect, transitive Offer works straight
// away with the saved sealed bytes.
restoreInstalledApps().catch((err) =>
  shellPrint(`Restore failed: ${err.message}`, "err"));

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
    if (!activeAppId) return;
    const body = msg.body instanceof Uint8Array ? msg.body : new Uint8Array(msg.body);
    const payload = new Uint8Array(1 + body.length);
    payload[0] = msg.chatType & 0xff;
    payload.set(body, 1);
    const wire = host.wrapAndEncode(
      myKeys.privateKey, myKeys.publicKey, CURRENT_VERSION,
      appHandlerName(activeAppId), payload);
    broadcastWire(wire);
    host.dispatch(wire);              // local echo
    if (msg.chatType === 0x02) {
      // Sticky "presence" replay: nick announcements are cached and
      // re-broadcast on every newly-opened dc so peers joining mid-session
      // pick up our identity without us having to send it again. The chat
      // app uses chatType=0x02 for this; other apps that don't use the
      // same convention simply never set the cache.
      lastSentNickBody = { appId: activeAppId, body };
    }
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
    if (lastSentNickBody && installedApps.has(lastSentNickBody.appId)) {
      const body = lastSentNickBody.body;
      const payload = new Uint8Array(1 + body.length);
      payload[0] = 0x02;
      payload.set(body, 1);
      const wire = host.wrapAndEncode(
        myKeys.privateKey, myKeys.publicKey, CURRENT_VERSION,
        appHandlerName(lastSentNickBody.appId), payload);
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
      // The DTLS-fingerprint assertion binds this channel to entry.pk; the
      // per-frame check below makes that binding load-bearing on the kernel
      // path. Anything arriving before SDP-auth, or signed by a different
      // key than the one we bound to this dc, is silently dropped.
      if (!entry.authed) return;
      const bytes = new Uint8Array(ev.data);
      const signer = peekEnvelopeSigner(bytes);
      if (!signer || !bytesEqual(signer, entry.pk)) return;
      host.dispatch(bytes);
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
      sendSignedSdp(pkHex, pc.localDescription);
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
  const pk = hexToBytes(pkHex);
  return {
    pc, dc: null, pendingIce: [],
    pk,                       // Uint8Array form, pinned for per-frame signer check
    polite: myPkHex > pkHex,
    makingOffer: false,
    ignoreOffer: false,
    callSenders: null,
    authed: false,            // flipped true once we've verified a signed SDP
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
      // semantically means "I'm starting fresh." If we have an UN-AUTHED
      // entry for this peer it's a zombie (we created it speculatively from
      // some earlier signal that never produced a signed SDP, or their tab
      // reloaded before we ever authed them) and we tear it down. A directed
      // hello (reply to our broadcast) is just the bootstrap dance bouncing
      // back; we leave any existing entry alone to avoid the entry-recreate /
      // dc-recreate loop that would happen if we tore down on every directed
      // hello.
      //
      // The hello case is unauthenticated — the relay (or anyone on it) can
      // spam hellos with arbitrary `from` values — but two guards contain
      // the blast radius:
      //   1. Impersonation is blocked: each spawned entry stays authed=false
      //      until a valid signed SDP arrives (sdp case verifies idSig
      //      against a=fingerprint lines under msg.from's pubkey, RFC 8827
      //      §5.6.4), and the dc-level filter in bindDataChannel refuses to
      //      dispatch from any entry that isn't authed.
      //   2. Memory growth is bounded: the MAX_UNAUTHED_PEERS cap below
      //      limits how many speculative entries the relay can force us to
      //      allocate. Authed peers don't count against the cap, so genuine
      //      fleet size is unconstrained.
      //   3. Targeted connection resets against authed peers are blocked:
      //      we deliberately do NOT tear down an authed entry on a spoofed
      //      broadcast hello. The trade-off is that a legitimate peer-reload
      //      from an already-authed peer will not be auto-recovered by the
      //      hello path; recovery has to come from the next signed SDP offer
      //      (perfect-negotiation renegotiation on the existing pc) or from
      //      a manual reconnect.
      const broadcast = !msg.to;
      if (broadcast) {
        const existing = peers.get(msg.from);
        if (existing && !existing.authed) {
          try { existing.pc.close(); } catch {}
          peers.delete(msg.from);
        }
      }
      const isFresh = !peers.has(msg.from);
      // Cap unauthed allocations (see MAX_UNAUTHED_PEERS comment). Only
      // applies when we're about to create a new entry; existing entries
      // (authed or not) keep working.
      if (isFresh) {
        let unauthed = 0;
        for (const e of peers.values()) if (!e.authed) unauthed++;
        if (unauthed >= MAX_UNAUTHED_PEERS) return;
      }
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
      // Identity binding (RFC 8827 §5.6.4). Before we touch the SDP we
      // require msg.idSig to verify against the a=fingerprint lines IN this
      // SDP, under msg.from's pubkey. That binds the DTLS endpoint described
      // by this SDP to the identity we'll key the peer entry under. A MITM
      // relay swapping in its own fingerprint must also swap in its own pk +
      // its own valid sig — at which point msg.from changes and the swap is
      // visible as "a different peer", not as impersonation.
      if (typeof msg.from !== "string" || msg.from.length !== 64) return;
      if (!msg.sdp || typeof msg.sdp.sdp !== "string") return;
      const peerPk = hexToBytes(msg.from);
      const idSig  = hexToBytes(msg.idSig);
      if (!peerPk || peerPk.length !== 32 || !idSig || idSig.length !== 64 ||
          !verifySdpIdentity(msg.sdp.sdp, peerPk, idSig)) {
        shellPrint(`Rejected SDP from ${msg.from.slice(0,8)} — identity not bound to DTLS fingerprint`, "err");
        return;
      }
      // Only auto-create an entry on a fresh offer. An "answer" arriving
      // for a peer we don't know is meaningless — drop it.
      const entry = msg.sdp.type === "offer"
        ? (peers.get(msg.from) ?? ensurePeer(msg.from))
        : peers.get(msg.from);
      if (!entry) return;
      entry.authed = true;
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
          sendSignedSdp(msg.from, entry.pc.localDescription);
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

// Room names mirror the relay-side validation (see scripts/relay.mjs):
// URL-safe identifier characters, length 1..128. Empty input is allowed
// and means "use the default room".
const ROOM_NAME_RE = /^[A-Za-z0-9._-]{1,128}$/;
const DEFAULT_ROOM = "global";

// Splice the chosen room onto the base relay URL as a path component. The
// relay reads the first path segment as the room name; if the user typed
// a URL that already contains a path we keep it (lets them paste a full
// `ws://host:8080/my-room` URL in just the URL field if they prefer).
function buildRelayUrl(base, room) {
  // Trim any trailing slash on the base, then append `/<encoded room>`.
  // If `base` already ends with a non-empty path we leave it alone — the
  // user typed an explicit URL.
  let u;
  try { u = new URL(base); } catch { return null; }
  if (u.protocol !== "ws:" && u.protocol !== "wss:") return null;
  const hasPath = u.pathname && u.pathname !== "/";
  if (!hasPath && room) u.pathname = "/" + encodeURIComponent(room);
  return u.toString();
}

function connectRelay() {
  const base = relayUrlInput.value.trim();
  if (!base) { shellPrint("Enter a relay URL.", "err"); return; }
  const room = relayRoomInput.value.trim();
  if (room && !ROOM_NAME_RE.test(room)) {
    shellPrint("Room name must match [A-Za-z0-9._-] (up to 128 chars).", "err");
    return;
  }
  const url = buildRelayUrl(base, room);
  if (!url) { shellPrint("Relay URL must be ws:// or wss://.", "err"); return; }
  if (ws) { try { ws.close(); } catch {} }
  const label = room || DEFAULT_ROOM;
  shellPrint(`Connecting to ${url} (room: ${label})...`, "sys");
  relayStatus.textContent = "connecting...";
  setRelayPill("connecting", `room ${label}`);
  relayConnectBtn.disabled = true;
  ws = new WebSocket(url);
  ws.addEventListener("open", () => {
    shellPrint(`Relay connected — room ${label}, waiting for peers.`, "sys");
    relayStatus.textContent = `connected · room ${label}`;
    setRelayPill("ok", `room ${label}`);
    // Remember the working URL + room so a reload picks the relay back up
    // automatically. Saved on success only, so a typo doesn't get retried
    // forever.
    sessionStorage.setItem("chat.relayUrl", base);
    sessionStorage.setItem("chat.relayRoom", room);
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
relayRoomInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); connectRelay(); }
});

// Generate a short random room name. 64 bits of entropy — plenty to keep
// a private room private without making the string a pain to share. We
// stick to lowercase hex so it round-trips through case-insensitive copy
// paths (URLs, chat clients) without surprises.
relayNewRoomBtn.addEventListener("click", () => {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  relayRoomInput.value = bytesToHex(bytes);
  relayRoomInput.focus();
  relayRoomInput.select();
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
const savedRelayRoom = sessionStorage.getItem("chat.relayRoom");
relayUrlInput.value = savedRelayUrl || defaultRelayUrl();
if (savedRelayRoom) relayRoomInput.value = savedRelayRoom;
if (savedRelayUrl) connectRelay();

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
    lastOfferBlob = encodeBlob({
      from: myPkHex, type: "offer", sdp: pc.localDescription,
      idSig: bytesToHex(signSdpIdentity(pc.localDescription.sdp)),
    });
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
  if (typeof peerPkHex !== "string" || peerPkHex.length !== 64) {
    shellPrint("Answer has malformed identity.", "err"); return;
  }
  const peerPk = hexToBytes(peerPkHex);
  const idSig  = hexToBytes(parsed.idSig);
  if (!peerPk || peerPk.length !== 32 || !idSig || idSig.length !== 64 ||
      !parsed.sdp || typeof parsed.sdp.sdp !== "string" ||
      !verifySdpIdentity(parsed.sdp.sdp, peerPk, idSig)) {
    shellPrint("Answer rejected — identity not bound to DTLS fingerprint.", "err");
    return;
  }
  const { pc, dc } = pendingManualOffer;
  pendingManualOffer = null;
  // Adopt the pre-built pc + dc into the peers map under the just-learned
  // peer pubkey. attachPeerListeners installs the same negotiationneeded /
  // icecandidate / connectionstatechange handlers as ensurePeer, so any
  // future renegotiation (ICE restart on network change, future media-track
  // adds) flows through the perfect-negotiation path over the dc.
  const entry = makeEntry(pc, peerPkHex);
  entry.authed = true;   // verified above against parsed.idSig
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
  if (typeof peerPkHex !== "string" || peerPkHex.length !== 64) {
    shellPrint("Offer has malformed identity.", "err"); return;
  }
  const peerPk = hexToBytes(peerPkHex);
  const idSig  = hexToBytes(parsed.idSig);
  if (!peerPk || peerPk.length !== 32 || !idSig || idSig.length !== 64 ||
      !parsed.sdp || typeof parsed.sdp.sdp !== "string" ||
      !verifySdpIdentity(parsed.sdp.sdp, peerPk, idSig)) {
    shellPrint("Offer rejected — identity not bound to DTLS fingerprint.", "err");
    return;
  }
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
    entry.authed = true;   // offer's idSig already verified above
    await entry.pc.setRemoteDescription(parsed.sdp);
    const answer = await entry.pc.createAnswer();
    await entry.pc.setLocalDescription(answer);
    await waitForIceGatheringComplete(entry.pc);
    myAnswerArea.value = encodeBlob({
      from: myPkHex, type: "answer", sdp: entry.pc.localDescription,
      idSig: bytesToHex(signSdpIdentity(entry.pc.localDescription.sdp)),
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
