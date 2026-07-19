import sodium from "./libsodium-wrappers.mjs";
import { loadKernelHost }
  from "../build/host/browser.js";
import { RtcNetwork } from "../build/host/net-rtc.js";
import { signManifest, verifyManifest, contentMatches, packBundle, unpackBundle }
  from "../build/host/bundle.js";

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

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

shellPrint("Loading kernel WASM...", "sys");
const host = await loadKernelHost("../build/kernel.wasm", sodium);

// ─── bootstrap: module registry ────────────────────────────────────────
// The kernel is a named table of pure-transform handlers now — no signature
// wrapper, no envelopes, no signer. The registry (§7) is the only bootstrap
// piece: it admits signed bundles. Message authenticity comes from the AKE
// channel (PeerLink), not a per-message signature.
host.registerInstaller();                         // the module registry (§7)

// ── install-approval policy ────────────────────────────────────────────
//
// Updates from an author we already trust (= we already hold an install
// record under this name with the same author key) are auto-approved — that is
// exactly the "trust updates from the same author" guarantee (§7.4, author-only;
// no parent/lineage gate). First installs require explicit user consent; the
// UI gates them by adding the app's bytes_hash to `pendingApprovals` before
// admitting it via installBundleModule. Anything else is refused.
const pendingApprovals = new Set();   // hex bytesHash → awaiting policy call

host.setApproveInstall((name, author, bytesHash, _wasm, existing) => {
  const hex = bytesToHex(bytesHash);
  if (existing) {
    if (existing.author.algoId !== author.algoId) return false;
    if (!bytesEqual(existing.author.publicKey, author.publicKey)) return false;
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

// ─── channel identity ──────────────────────────────────────────────────
//
// Transport identity is the RtcNetwork's job. Each data channel runs PeerLink's
// in-channel HELLO/AUTH challenge, proving the far end holds the kernel private
// key for the pubkey it claims — a continuous channel binding that subsumes the
// old SDP a=fingerprint signing and any per-message signature. Frames the
// RtcNetwork hands us are already attributed to an authenticated peer, so the
// sender pubkey (`_from`) is authoritative — we prepend it to the message before
// running the app transform; there is no envelope signer to verify.
function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
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
  const open = net.linkedPeers().length;
  peerPillText.textContent = open === 1 ? "1 peer" : `${open} peers`;
  peerPill.classList.toggle("ok", open > 0);
}

// ─── app registry ──────────────────────────────────────────────────────
//
// An "app" is an ordinary signed bundle (§12.4): a signed `manifest.bundle`
// envelope plus the app's WASM module, packed into one blob for the wire
// (bundle.ts packBundle/unpackBundle). This is the SAME format seedstore's
// flagship deployment loads — a chat app is just a handler-only bundle (one
// module, no guest realm). There is no chat-specific install format, domain, or
// peek/unwrap code: `verifyManifest` authenticates the author's signature over
// the manifest, which commits to the module's genesisHash, so the blob survives
// any number of transitive relays and still authenticates against its original
// author — exactly the store-and-forward property an Offer needs. The local
// "add app" flow and the peer-to-peer Offer below carry the identical bundle.
//
// The module's WASM carries two embedded custom sections the runtime ignores but
// this shell reads: "app_meta" (JSON — id, name, version) and "ui" (HTML rendered
// in the sandboxed iframe). The signed manifest's `app` is the id, and the module
// binds under a kernel name derived from it:
//     handlerName = SHA-3-256("seedkernel.bootstrap.v1:app:" + id)
//
// `handlerName` is globally derivable so two peers running the same app id route
// messages to the same name; we derive it from the signed manifest `app` on
// install rather than trusting the manifest's own bind name, so a forged manifest
// cannot redirect a handler onto an unexpected name.
//
// An app's handler is a PURE TRANSFORM: the shell hands it `senderPk ‖ chatType ‖
// body` and it returns the render bytes for the iframe. The shell — not the WASM
// and not the kernel — does all the I/O: it authenticates the sender via the AKE
// channel, calls the transform with `host.callHandler`, and posts the result to
// the iframe. (In a headless deployment a zero-authority guest plays this
// orchestrator role instead; here the browser shell is the natural orchestrator.)
//
// `installedApps` keeps the per-app state we need to re-mount the UI, send
// updates, and re-broadcast the packed bundle transitively (`bundleBytes` is the
// signed bundle blob — the author's manifest signature intact — and is what every
// "Offer" hands to a peer). Apps received via Offer keep the original author's
// manifest signature: we never re-sign a bundle.
const installedApps = new Map();   // id → AppRecord
let activeAppId = null;

function appHandlerName(id) {
  return host.deriveBootstrapName("app:" + id);
}

// ── shell frame wire format ─────────────────────────────────────────────
//
// Without envelopes, the shell frames what it puts on a data channel itself. The
// sender pubkey is NOT in the frame — the AKE channel already authenticates it and
// hands it up as `_from`. Two kinds:
//   CHAT   [0x01][appIdLen u8][appId utf8][chatType u8][body]
//   OFFER  [0x02][bundle bytes]
const FRAME_CHAT = 0x01;
const FRAME_OFFER = 0x02;

function encodeChatFrame(appId, chatBytes) {
  const idBytes = new TextEncoder().encode(appId);
  const out = new Uint8Array(2 + idBytes.length + chatBytes.length);
  out[0] = FRAME_CHAT;
  out[1] = idBytes.length;
  out.set(idBytes, 2);
  out.set(chatBytes, 2 + idBytes.length);
  return out;
}

function encodeOfferFrame(bundleBytes) {
  const out = new Uint8Array(1 + bundleBytes.length);
  out[0] = FRAME_OFFER;
  out.set(bundleBytes, 1);
  return out;
}

// Run an app's transform for one message and, if it's the active app, render it.
// `senderPk` is the authenticated peer (or our own key for a local echo);
// `chatBytes` is [chatType u8][body]. The transform's input is senderPk ‖ chatBytes.
function deliverChat(appId, senderPk, chatBytes) {
  const rec = installedApps.get(appId);
  if (!rec) return;
  const input = new Uint8Array(senderPk.length + chatBytes.length);
  input.set(senderPk, 0);
  input.set(chatBytes, senderPk.length);
  const render = host.callHandler(rec.handlerName, input);
  if (render && appId === activeAppId) deliverRender(new Uint8Array(render));
}

// ── iframe bridge ──────────────────────────────────────────────────────
//
// The app transform returns render bytes; the shell posts them to the iframe.
// Renders that arrive before the iframe says "ready" are queued so a hot-swap
// doesn't drop the first message.
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

// ── build an app bundle (local-authored) ────────────────────────────────
//
// Turn a WASM module into a signed one-module bundle: read its app_meta for the
// id, build a manifest binding the module at appHandlerName(id), sign the manifest
// under the local key (the real §12.4 manifest signature), and pack the manifest
// envelope + module into one blob. `version` is a nominal 1 — the interactive
// shell gates installs on user consent (the approve callback), not on a monotonic
// freshness mark, so a chat bundle carries no meaningful version counter.
async function buildAppBundle(wasmBytes) {
  const { meta } = await readWasmSections(wasmBytes);
  if (!meta || !meta.id) throw new Error("cannot build a bundle: wasm has no app_meta id");
  const manifest = {
    app: meta.id,
    version: 1,
    modules: [{
      name: meta.id,
      file: "app.wasm",
      hash: bytesToHex(host.genesisHash(wasmBytes)),
      kernelName: bytesToHex(appHandlerName(meta.id)),
    }],
    caps: [],
  };
  const manifestEnv = signManifest(sodium, myKeys.privateKey, myKeys.publicKey, manifest);
  return packBundle({ "manifest.bundle": manifestEnv, "app.wasm": wasmBytes });
}

// ── verify + peek a received bundle ──────────────────────────────────────
//
// Unpack the archive, verify the author's manifest signature (§12.4), and
// integrity-check the module against the hash the manifest commits to. Returns
// author + module wasm + content id, so the Apps UI can surface author + meta
// before the user accepts, and a tampered/forged bundle is rejected here rather
// than at some later step. Returns null on anything malformed or unauthentic.
function peekAppBundle(bundleBytes) {
  let files;
  try { files = unpackBundle(bundleBytes); }
  catch { return null; }
  const env = files["manifest.bundle"];
  if (!env) return null;
  let verified;
  try { verified = verifyManifest(sodium, env); }
  catch { return null; }   // signed-but-malformed manifest ⇒ reject in the UI
  if (!verified) return null;
  const { author, manifest } = verified;
  // A chat app is a one-module handler-only bundle.
  if (!Array.isArray(manifest.modules) || manifest.modules.length !== 1) return null;
  const mod = manifest.modules[0];
  const wasm = files[mod.file];
  if (!wasm || wasm.length === 0) return null;
  if (!contentMatches(wasm, mod.hash, (b) => host.genesisHash(b))) return null;
  return {
    authorPk: author,
    authorAlgo: 0,   // Ed25519 genesis suite (§6.2)
    manifest,
    // bytes_hash is the registry's content id for the module (§7.1): genesisHash(wasm),
    // the same value the approve callback receives — so it keys pendingApprovals and
    // doubles as the artifact's display hash. Equal to fromHex(mod.hash) once the
    // integrity check above passes.
    bytesHash: host.genesisHash(wasm),
    install: { wasm },
  };
}

// Admit a received/authored bundle we already trust (its bytesHash added to
// pendingApprovals if needed). Returns the AppRecord on success.
async function applyAppBundle(bundleBytes) {
  const peeked = peekAppBundle(bundleBytes);
  if (!peeked) throw new Error("not a valid app bundle");
  const { meta, uiHtml } = await readWasmSections(peeked.install.wasm);
  if (!meta) throw new Error("bundle module has no app_meta");

  // Derive the bind name from the signed manifest `app`, not the manifest's own
  // kernelName field: a globally-derivable name keeps peer routing consistent and a
  // forged manifest cannot redirect the handler onto an unexpected name.
  const id = peeked.manifest.app;
  const handlerName = appHandlerName(id);

  // The manifest signature is already verified (peekAppBundle). Admit the module
  // through the same policy a seedstore bundle module goes through (§12.4). The
  // approve callback gates first installs on pendingApprovals and updates on
  // same-author. The module is a pure transform — no configure step, nothing to
  // wire; the shell drives it directly with host.callHandler.
  if (!host.installBundleModule(handlerName, peeked.install.wasm, peeked.authorPk)) {
    throw new Error("install rejected by policy");
  }

  const record = {
    id,
    name: meta.name || id,
    version: meta.version || "",
    description: meta.description || "",
    authorPk: peeked.authorPk.slice(),
    authorAlgo: peeked.authorAlgo,
    bytesHash: peeked.bytesHash,
    bundleBytes: bundleBytes.slice(),
    handlerName,
    uiHtml,
  };
  installedApps.set(id, record);
  // Persist the packed bundle across reloads so transitive offers / updates keep
  // working without re-receiving them.
  persistInstalledApps();
  renderAppList();
  return record;
}

// Add an app from raw WASM bytes by building + signing a bundle with the local
// key (the local user becomes the author).
async function addAppFromWasm(wasmBytes, fallbackId) {
  let { meta } = await readWasmSections(wasmBytes);
  if (!meta || !meta.id) {
    meta = promptMeta(fallbackId);
    if (!meta) return;
    // Re-embed the meta into the wasm so the bundle module carries it.
    wasmBytes = embedAppMeta(wasmBytes, meta);
  }
  const handlerName = appHandlerName(meta.id);
  const existing = host.lookupInstall(handlerName);
  // Updating something WE authored is a plain same-author re-install (§7.4 —
  // no parent/lineage gate). Updates to an app authored by someone else are
  // not supported from this path — those arrive via Offer from the original
  // author.
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
  const bundleBytes = await buildAppBundle(wasmBytes);
  const peeked = peekAppBundle(bundleBytes);
  if (!peeked) throw new Error("internal: just-built app bundle did not parse");

  pendingApprovals.add(bytesToHex(peeked.bytesHash));
  try {
    const record = await applyAppBundle(bundleBytes);
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
// The packed bundle is the only piece of app state we need to rebuild — the
// install record on the installer side, the handler in the kernel, and the
// uiHtml all derive from it. We keep them in sessionStorage so a reload
// within the same tab keeps the user's app set and lets transitive offers
// continue to work.
function persistInstalledApps() {
  try {
    const arr = [];
    for (const rec of installedApps.values()) {
      arr.push(Array.from(rec.bundleBytes));
    }
    sessionStorage.setItem("apps.bundles", JSON.stringify(arr));
    if (activeAppId) sessionStorage.setItem("apps.active", activeAppId);
    else sessionStorage.removeItem("apps.active");
  } catch {}
}

async function restoreInstalledApps() {
  let arr;
  try { arr = JSON.parse(sessionStorage.getItem("apps.bundles") || "[]"); }
  catch { return; }
  if (!Array.isArray(arr)) return;
  for (const raw of arr) {
    try {
      // Restored installs were already approved in a prior tab session —
      // wave them through the approveInstall gate the same way an update
      // would be: by adding their bytesHash to pendingApprovals.
      const bundleBytes = new Uint8Array(raw);
      const peeked = peekAppBundle(bundleBytes);
      if (!peeked) continue;
      pendingApprovals.add(bytesToHex(peeked.bytesHash));
      await applyAppBundle(bundleBytes);
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
// An offer is a packed app bundle forwarded over a data channel in an OFFER frame.
// Any peer who holds the bundle can forward it (transitive offer) — the manifest
// inside carries the original author's signature over the module hash, so the
// recipient still authenticates against the author (peekAppBundle verifies it).
//
// The relaying peer is identified by the AKE channel (`_from`), not a signature —
// the frame is unsigned; the bundle's own manifest signature is the load-bearing
// authentication. Inbound OFFER frames are routed here from the network sink.
const pendingOffers = new Map();   // bytesHashHex → { bundleBytes, peeked, fromPkHex }

async function handleOffer(bundleBytes, fromPkHex) {
  const peeked = peekAppBundle(bundleBytes);
  if (!peeked) return;
  const { install, authorPk, bytesHash } = peeked;

  const id = peeked.manifest.app;
  let meta = null;
  try { meta = (await readWasmSections(install.wasm)).meta; } catch {}
  if (!meta) {
    shellPrint(`Offer from ${fromPkHex.slice(0, 8)} dropped: bundle module has no app_meta`, "err");
    return;
  }
  // Route + display by the signed manifest id; the wasm's app_meta id is cosmetic.
  meta = { ...meta, id };
  const handlerName = appHandlerName(id);
  const existing = host.lookupInstall(handlerName);

  // Auto-install path: the author matches an app we already trust. The
  // reference policy in setApproveInstall verifies the same facts (§7.4,
  // author-only), so dispatching is safe — no extra approval needed.
  if (existing &&
      existing.author.algoId === peeked.authorAlgo &&
      bytesEqual(existing.author.publicKey, authorPk)) {
    try {
      const rec = await applyAppBundle(bundleBytes);
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
    bundleBytes: bundleBytes.slice(),
    peeked: { ...peeked, meta },
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
    const rec = await applyAppBundle(offer.bundleBytes);
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

// Broadcast the stored bundle for `id` to every open peer. Anyone who receives
// this can forward it to others — that's transitivity for free.
function offerApp(id) {
  const rec = installedApps.get(id);
  if (!rec) return;
  const n = broadcastFrame(encodeOfferFrame(rec.bundleBytes));
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
    ` · <b>wasm</b> ${bytesToHex(rec.bytesHash).slice(0, 12)}`;
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
    ` · <b>wasm</b> ${bytesToHex(offer.peeked.bytesHash).slice(0, 12)}`;
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
    const chatBytes = new Uint8Array(1 + body.length);   // [chatType][body]
    chatBytes[0] = msg.chatType & 0xff;
    chatBytes.set(body, 1);
    broadcastFrame(encodeChatFrame(activeAppId, chatBytes));
    deliverChat(activeAppId, myKeys.publicKey, chatBytes);   // local echo
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
// Networking — RtcNetwork (host/net-rtc.ts) over a relay signaling channel.
//
// The WebRTC mesh — perfect negotiation, the relay rendezvous, per-peer
// identity, the unauthed-peer cap, ICE-restart recovery — all lives in
// RtcNetwork now. This shell only wires it up: it routes inbound shell frames
// (CHAT / OFFER), broadcasts outbound frames to the linked peers, and mirrors
// link up/down into the UI. Channel identity is PeerLink's in-channel HELLO/AUTH
// (host/net-link.ts), so any frame handed to our sink is already attributed to an
// authenticated peer — `_from` is that peer's pubkey, which we treat as the
// message author. No per-message signature.
// ---------------------------------------------------------------------------

let lastSentNickBody = null;   // {appId, body} — replayed to peers that join mid-session

// Reconnectable relay signaling. RtcNetwork takes a Signaling at construction;
// we hand it one whose underlying WebSocket can be (re)pointed at a relay URL
// at runtime. Dropping or swapping the relay leaves authenticated P2P links
// untouched — the relay was only ever the initial rendezvous.
let relayWs = null;
let signalCb = () => {};
const signalOutbox = [];
const signaling = {
  send(msg) {
    const s = JSON.stringify(msg);
    if (relayWs && relayWs.readyState === WebSocket.OPEN) relayWs.send(s);
    else signalOutbox.push(s);   // queued until the relay is (re)connected
  },
  onMessage(fn) { signalCb = fn; },
  close() { if (relayWs) { try { relayWs.close(); } catch {} } },
};

const net = new RtcNetwork({
  identity: myKeys,
  sodium,
  signaling,
  rtcConfig: RTC_CONFIG,
  onPeerUp: (peerId) => {
    shellPrint(`P2P link to ${peerId.slice(0, 8)} open`, "sys");
    deliverSys(`P2P link to ${peerId.slice(0, 8)} open`);
    updatePeerPill();
    // Replay our last nick so a peer joining mid-session learns our identity
    // without us re-sending it (chat v2 uses chatType 0x02 for nick).
    if (lastSentNickBody && installedApps.has(lastSentNickBody.appId)) {
      const body = lastSentNickBody.body;
      const chatBytes = new Uint8Array(1 + body.length);
      chatBytes[0] = 0x02;
      chatBytes.set(body, 1);
      endpoint.send(peerId, encodeChatFrame(lastSentNickBody.appId, chatBytes));
    }
  },
  onPeerDown: (peerId) => {
    shellPrint(`P2P link to ${peerId.slice(0, 8)} closed`, "sys");
    updatePeerPill();
    removeRemoteTile(peerId);
    updateCallStatus();
  },
  onTrack: (peerId, track) => {
    // A remote peer is sending media — attach the track to their tile. When it
    // ends (they hung up, or their pc died) drop it; an empty tile goes away.
    const tile = getOrCreateRemoteTile(peerId);
    tile.stream.addTrack(track);
    track.addEventListener("ended", () => {
      try { tile.stream.removeTrack(track); } catch {}
      if (tile.stream.getTracks().length === 0) removeRemoteTile(peerId);
    });
  },
});

// Our attachment to the fabric — RtcNetwork is bound to our one key, so it vends
// exactly this endpoint. Each inbound frame is a shell frame (CHAT / OFFER); the
// sender `from` is the authenticated peer's pubkey hex.
const endpoint = net.endpoint(myPkHex);
endpoint.onFrame((from, frame) => {
  const bytes = frame instanceof Uint8Array ? frame : new Uint8Array(frame);
  if (bytes.length < 1) return;
  const kind = bytes[0];
  if (kind === FRAME_CHAT) {
    if (bytes.length < 2) return;
    const idLen = bytes[1];
    if (bytes.length < 2 + idLen) return;
    const appId = new TextDecoder().decode(bytes.subarray(2, 2 + idLen));
    const chatBytes = bytes.subarray(2 + idLen);   // [chatType][body]
    deliverChat(appId, hexToBytes(from), chatBytes);
  } else if (kind === FRAME_OFFER) {
    handleOffer(bytes.slice(1), from).catch(() => {});
  }
});

// Broadcast a shell frame to every authenticated peer. Returns the peer count so
// callers can report "offered to N peers". endpoint.send() drops to any peer we
// hold no authenticated link to, so iterating linkedPeers() is exact.
function broadcastFrame(frameBytes) {
  const linked = net.linkedPeers();
  for (const peerId of linked) endpoint.send(peerId, frameBytes);
  return linked.length;
}

// ─── live audio/video calls ────────────────────────────────────────────
//
// Calls ride the same RTCPeerConnections as the data channel. net.addLocalTrack
// publishes our camera/mic to every connected peer (and to peers that connect
// later); RtcNetwork renegotiates as tracks are added (startCall) or removed
// (endCall → net.removeLocalTracks). Remote tracks arrive via the onTrack
// callback wired on `net` above and land in a per-peer tile keyed by pubkey
// hex; a tile is cleaned up when its track ends or the peer's link drops
// (onPeerDown).

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
    const n = net.linkedPeers().length;
    callStatus.textContent = n === 0
      ? "in call (waiting for peers)"
      : `in call · ${n} peer${n === 1 ? "" : "s"}`;
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
  // RtcNetwork publishes each track to every connected peer and to any peer
  // that connects later, renegotiating as needed.
  for (const track of localStream.getTracks()) net.addLocalTrack(track, localStream);
  updateCallStatus();
  shellPrint("Call started.", "sys");
}

function endCall() {
  if (!localStream) return;
  net.removeLocalTracks();
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

// ─── relay connection ───────────────────────────────────────────────────
//
// Proactive ICE restart on a network change. ICE keepalives take 5–10s to
// notice a network flip on their own; kicking restartAllIce() the moment the
// browser tells us connectivity changed cuts straight to recovery. The
// renegotiation offers ride the relay signaling channel, so the relay must be
// reachable for recovery to complete.
window.addEventListener("online", () => {
  shellPrint("Network online — restarting ICE", "sys");
  net.restartAllIce();
});
if (navigator.connection && typeof navigator.connection.addEventListener === "function") {
  navigator.connection.addEventListener("change", () => {
    shellPrint("Network changed — restarting ICE", "sys");
    net.restartAllIce();
  });
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
  if (relayWs) { try { relayWs.close(); } catch {} }
  const label = room || DEFAULT_ROOM;
  shellPrint(`Connecting to ${url} (room: ${label})...`, "sys");
  relayStatus.textContent = "connecting...";
  setRelayPill("connecting", `room ${label}`);
  relayConnectBtn.disabled = true;
  relayWs = new WebSocket(url);
  relayWs.addEventListener("open", () => {
    shellPrint(`Relay connected — room ${label}, waiting for peers.`, "sys");
    relayStatus.textContent = `connected · room ${label}`;
    setRelayPill("ok", `room ${label}`);
    relayConnectBtn.disabled = false;
    // Remember the working URL + room so a reload picks the relay back up
    // automatically. Saved on success only, so a typo doesn't get retried
    // forever.
    sessionStorage.setItem("chat.relayUrl", base);
    sessionStorage.setItem("chat.relayRoom", room);
    // Flush any signals RtcNetwork queued while the socket was down, then
    // announce ourselves into the room so the WebRTC dance can begin.
    for (const s of signalOutbox) relayWs.send(s);
    signalOutbox.length = 0;
    net.join();
  });
  relayWs.addEventListener("message", (ev) => {
    if (typeof ev.data !== "string") return;
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    signalCb(msg);   // hand it to RtcNetwork's signaling
  });
  relayWs.addEventListener("close", () => {
    relayStatus.textContent = "disconnected";
    setRelayPill("off", "no relay");
    relayConnectBtn.disabled = false;
    shellPrint("Relay disconnected. Existing P2P links unaffected.", "sys");
  });
  relayWs.addEventListener("error", () => {
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

// Initial peer / call status. (relay pill is already in its "off" default
// state from markup; connectRelay below will manage it from here on.)
updatePeerPill();
updateCallStatus();
