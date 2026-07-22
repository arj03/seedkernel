import sodium from "./libsodium-wrappers.mjs";
import { createKernelHost }
  from "../build/host/browser.js";
import { RtcNetwork } from "../build/host/net-rtc.js";
import { signManifest, verifyBundle, checkBundleIntegrity, packBundle,
         admitModule, appKeyFor, genesisHash, handlesOf,
         kernelNameFor, MANIFEST_FILE, moduleFile }
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

shellPrint("Starting the handler table...", "sys");
const host = await createKernelHost(sodium);

// ─── admission policy ──────────────────────────────────────────────────
// The kernel is a named table of pure-transform handlers, held by the host — no
// signature wrapper, no envelopes, no signer. The loader (§12.4) is the only bootstrap
// piece: it admits signed bundles under the admission policy below. Message
// authenticity comes from the AKE channel (PeerLink), not a per-message signature.
//
// This is the multi-app shell's own `admit` (§12.5), and it has exactly one question to
// answer: has the user consented to running THESE bytes? It needs no author or name
// clause — a kernel name derives from its author's key (§5.1), so an author can only ever
// bind over their own app, and two authors shipping an app called "chat" simply coexist.
// The UI gates a consent by adding the app's bytes_hash to `pendingApprovals` before
// admitting it. Anything else is refused.
//
// Consent decides whether the code RUNS. Which app receives a given protocol's messages
// is the separate, freely revisable question `bindings` answers below (§12.10).
const pendingApprovals = new Set();   // hex bytesHash → awaiting policy call

const admit = (_name, _author, bytesHash, _wasm) => {
  const hex = bytesToHex(bytesHash);
  if (!pendingApprovals.has(hex)) return false;
  pendingApprovals.delete(hex);
  return true;
};

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
// envelope plus the app's WASM module in one blob. That blob IS the bundle format —
// the same bytes seedstore's flagship deployment loads from disk, so a chat app is
// just a handler-only bundle (one module, no guest realm) and needs no chat-specific
// install format, domain, or peek/unwrap code. `verifyBundle` (the shared loader)
// authenticates the author's signature over the manifest, which commits to the
// module's genesisHash, so the blob survives any number of transitive relays and
// still authenticates against its original author — exactly the store-and-forward
// property an Offer needs. The local "add app" flow and the peer-to-peer Offer below
// carry the identical bundle.
//
// The module's WASM carries two embedded custom sections the runtime ignores but
// this shell reads: "app_meta" (JSON — id, name, version) and "ui" (HTML rendered
// in the sandboxed iframe). The signed manifest's `app` is the id, and the loader
// binds the module at `kernelNameFor(app, moduleName)` — `"<id>:<module>"` (§5.1).
// The manifest declares no bind name, so there is nothing in it a forged manifest
// could point at an unexpected handler; the shell calls the same derivation the
// loader does rather than keeping its own.
//
// The name is node-local. Two peers need not agree on it: a CHAT frame carries a
// *protocol id*, and each side resolves that through its own `bindings` to whichever
// app it holds — so two peers running different authors' chat apps interoperate as
// long as both speak the protocol.
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
// Keyed by APP KEY — `"<author hex>:<app>"` (§12.4), the same key the loader's freshness
// marks use. Not by the bare app id: two authors may both ship a "chat", and under
// derived names (§5.1) they coexist rather than contend, so the id alone is not an
// identity. `rec.id` remains the display/manifest name.
const installedApps = new Map();   // appKey → AppRecord
let activeAppKey = null;

// ── protocol bindings (§12.10) ─────────────────────────────────────────
//
// Which installed app receives a given protocol's messages. This is a user PREFERENCE,
// not a permission: it cannot make unadmitted code run, cannot widen anyone's authority,
// and is freely rewritable — the worst a wrong binding does is deliver to the wrong app
// the user already chose to install. That is exactly why it lives here in the shell and
// not in the loader's policy.
//
// A manifest's `handles` (defaulting to `[app]`) says what an app is WILLING to serve;
// this table says what it actually does. Declaring is free and confers nothing, so any
// number of apps may offer "chat" without contending for it.
//
// One app per protocol. A second handler would be a fan-out, and today it would be a
// no-op: WASM handlers are pure transforms with zero authority (§4.2), so a would-be
// logger bound alongside could only return bytes the shell discards. The component that
// could genuinely act is a capability-holding guest, and binding one is an authority
// grant needing its own approval — a different question from "which chat app do I want",
// so it is deliberately not what this single-valued table expresses.
const bindings = new Map();        // protocol id → appKey

// Session-storage namespace for the app state below. VERSIONED because `apps.active` and
// the `installedApps` keys hold app keys (§12.4) where they once held bare app ids: a tab
// carrying the older shape would restore its bundles, fail to match its saved active app,
// and sit on the empty-state placeholder as though nothing had installed. Bump this
// whenever the shape of anything under it changes — sessionStorage is per-tab, so the
// stale entries die with the tab and there is nothing to migrate.
const STORE = "apps.v2";

/** The app bound to `proto`, or null. */
function boundApp(proto) {
  const key = bindings.get(proto);
  return key ? (installedApps.get(key) ?? null) : null;
}

/** Bind `proto` to `key`, replacing whatever held it. */
function bindProtocol(proto, key) {
  bindings.set(proto, key);
  persistInstalledApps();
  renderAppList();
}

/** Auto-bind on install, into VACANCIES only (§12.10): the first app to offer a protocol
 *  takes it — there is no decision to surface because there is no alternative — while an
 *  app offering an already-bound protocol lands installed-but-unbound, leaving the choice
 *  to the user. An update (same app key) keeps what it already held and any NEWLY declared
 *  protocol lands unbound, so a v2 cannot inherit traffic on the strength of v1's consent. */
function autoBind(rec) {
  for (const proto of rec.handles) {
    if (!bindings.has(proto)) bindings.set(proto, rec.key);
  }
}

/** Protocols currently pointing at this app. */
function boundProtocols(key) {
  const out = [];
  for (const [proto, k] of bindings) if (k === key) out.push(proto);
  return out;
}

// ── shell frame wire format ─────────────────────────────────────────────
//
// Without envelopes, the shell frames what it puts on a data channel itself. The
// sender pubkey is NOT in the frame — the AKE channel already authenticates it and
// hands it up as `_from`. Two kinds:
//   CHAT   [0x01][protoLen u8][protocol id utf8][chatType u8][body]
//   OFFER  [0x02][bundle bytes]
//
// The CHAT frame names a PROTOCOL, never an app, an author or a kernel name — those are
// node-local (§5.1), and a wire that named them would make one peer's install choices
// everyone else's business.
const FRAME_CHAT = 0x01;
const FRAME_OFFER = 0x02;

function encodeChatFrame(proto, chatBytes) {
  const idBytes = new TextEncoder().encode(proto);
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
function deliverChat(proto, senderPk, chatBytes) {
  // Resolve the wire's protocol id through OUR bindings (§12.10). An unbound protocol
  // drops — the sender got no say in which app runs, or whose code that is.
  const rec = boundApp(proto);
  if (!rec) return;
  const input = new Uint8Array(senderPk.length + chatBytes.length);
  input.set(senderPk, 0);
  input.set(chatBytes, senderPk.length);
  const render = host.callHandler(rec.handlerName, input);
  if (render && rec.key === activeAppKey) deliverRender(new Uint8Array(render));
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
  // The same charset a manifest module name is held to (§12.4): the id becomes the
  // module's name, and so its file in the bundle. Reject it here rather than let the
  // user sign a manifest their own shell would then refuse as malformed.
  if (!/^[A-Za-z0-9_-]+$/.test(trimmed)) {
    const msg = "App id must be alphanumeric / _ -";
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
// id, build a manifest declaring the module under that id, sign the manifest under
// the local key (the real §12.4 manifest signature), and pack the manifest envelope
// + module into one blob. The manifest names no kernel name — the loader derives it
// from the signed `(app, name)` pair. `version` is a nominal 1 — the interactive
// shell gates installs on user consent (the approve callback), not on a monotonic
// freshness mark, so a chat bundle carries no meaningful version counter.
//
// A chat app is a HANDLER-ONLY bundle: it declares no `guest`, and since caps live
// inside `guest` (§12.4) that is the same statement as "this app holds no authority".
// There is no empty caps list to write — the shape says it.
async function buildAppBundle(wasmBytes) {
  const { meta } = await readWasmSections(wasmBytes);
  if (!meta || !meta.id) throw new Error("cannot build a bundle: wasm has no app_meta id");
  const manifest = {
    app: meta.id,
    version: 1,
    modules: [{
      name: meta.id,
      hash: bytesToHex(genesisHash(sodium, wasmBytes)),
    }],
  };
  const manifestEnv = signManifest(sodium, myKeys.privateKey, myKeys.publicKey, manifest);
  return packBundle({
    [MANIFEST_FILE]: manifestEnv,
    [moduleFile(meta.id)]: wasmBytes,
  });
}

// ── verify + peek a received bundle ──────────────────────────────────────
//
// Authenticate + integrity-check a received bundle through the SHARED §12.4 loader
// (bundle.ts verifyBundle + checkBundleIntegrity) — the same code the Node shell and
// the native loader run. This shell only needs the verify half: it must show the
// author and the app's metadata and wait for the user to accept before anything binds,
// which is exactly the seam `verifyBundle` is split at. It carries no policy file and
// no freshness marks — user consent is this deployment's admission policy — so it
// stops short of `installBundle` and drives `admitModule` — the loader's own
// hash-then-policy-then-bind step — itself once the user agrees.
//
// Returns null on anything malformed or unauthentic, so the UI can decline quietly.
function peekAppBundle(bundleBytes) {
  let v;
  try {
    v = verifyBundle(sodium, bundleBytes);
    checkBundleIntegrity(v, (b) => genesisHash(sodium, b));
  } catch { return null; }   // unauthentic, malformed, or a hash mismatch ⇒ decline
  // A chat app is a one-module handler-only bundle: a `guest` would mean authority
  // this shell has no realm to confine.
  if (v.modules.length !== 1 || v.manifest.guest) return null;
  const wasm = v.modules[0].wasm;
  if (wasm.length === 0) return null;
  return {
    authorPk: v.author,
    manifest: v.manifest,
    // This app's identity (§12.4) and the name the loader would bind its module at,
    // both from the signed `(author, app, name)` triple — the shell drives the admission
    // itself here, so it derives them the same way rather than second-guessing.
    key: appKeyFor(v.author, v.manifest.app),
    handlerName: kernelNameFor(v.author, v.manifest.app, v.modules[0].mod.name),
    // The protocol ids this app offers to serve (§12.10), defaulted by the loader.
    // An offer, not a claim: it takes a binding below before a single byte reaches it.
    handles: handlesOf(v.manifest),
    // bytes_hash is the loader's content id for the module (§12.4): genesisHash(wasm),
    // the same value the approve callback receives — so it keys pendingApprovals and
    // doubles as the artifact's display hash. Equal to fromHex(modules[0].hash) now
    // that the integrity check above has passed.
    bytesHash: genesisHash(sodium, wasm),
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

  // Identify by the app KEY — `(author, app)` — not the bare id: two authors may each
  // ship a "chat" and they coexist under distinct derived names (§5.1).
  const id = peeked.manifest.app;
  const key = peeked.key;
  const handlerName = peeked.handlerName;

  // The manifest signature is already verified (peekAppBundle). Admit the module through
  // the loader's own admission step (§12.4) — hash the bytes, ask `admit`, then bind — so
  // this shell runs the same code path a seedstore bundle module does rather than a
  // parallel copy. The module is a pure transform: no configure step, nothing to wire;
  // the shell drives it directly with host.callHandler.
  if (!admitModule(host, sodium, admit, handlerName, peeked.install.wasm, peeked.authorPk)) {
    throw new Error("install rejected by policy");
  }

  const record = {
    id,
    key,
    name: meta.name || id,
    version: meta.version || "",
    description: meta.description || "",
    authorPk: peeked.authorPk.slice(),
    bytesHash: peeked.bytesHash,
    bundleBytes: bundleBytes.slice(),
    handlerName,
    handles: peeked.handles,
    uiHtml,
  };
  installedApps.set(key, record);
  // Bind any protocol nobody holds yet (§12.10). An update keeps the bindings it already
  // had — they point at this same app key — while a protocol this app newly declares, or
  // one another app already holds, lands unbound for the user to decide.
  autoBind(record);
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
  // No name conflict is possible here. We sign under OUR key, so the bundle derives
  // names in our own namespace (§5.1): this either updates the app we already hold at
  // `(us, meta.id)`, or lands beside somebody else's same-named app without touching it.
  // There is nothing to refuse and no existing install to interrogate.
  const bundleBytes = await buildAppBundle(wasmBytes);
  const peeked = peekAppBundle(bundleBytes);
  if (!peeked) throw new Error("internal: just-built app bundle did not parse");

  pendingApprovals.add(bytesToHex(peeked.bytesHash));
  try {
    const record = await applyAppBundle(bundleBytes);
    shellPrint(`Installed ${record.name} ${record.version}`, "sys");
    setActiveApp(record.key);
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
// loader's install record, the handler in the kernel, and the uiHtml all
// derive from it. We keep them in sessionStorage so a reload
// within the same tab keeps the user's app set and lets transitive offers
// continue to work.
function persistInstalledApps() {
  try {
    const arr = [];
    for (const rec of installedApps.values()) {
      arr.push(Array.from(rec.bundleBytes));
    }
    sessionStorage.setItem(STORE + ".bundles", JSON.stringify(arr));
    // Bindings are ordinary user preference (§12.10) — they persist beside the apps and
    // carry no security property, so a hand-edited store can misroute a message and
    // nothing more.
    sessionStorage.setItem(STORE + ".bindings", JSON.stringify(Array.from(bindings)));
    if (activeAppKey) sessionStorage.setItem(STORE + ".active", activeAppKey);
    else sessionStorage.removeItem(STORE + ".active");
  } catch {}
}

async function restoreInstalledApps() {
  let arr;
  try { arr = JSON.parse(sessionStorage.getItem(STORE + ".bundles") || "[]"); }
  catch { return; }
  if (!Array.isArray(arr)) return;
  // Bindings BEFORE apps: `autoBind` only fills vacancies, so restoring the user's
  // choices first is what keeps a reload from silently re-binding a protocol to
  // whichever app happens to come back first.
  try {
    const saved = JSON.parse(sessionStorage.getItem(STORE + ".bindings") || "[]");
    if (Array.isArray(saved)) {
      for (const pair of saved) {
        if (Array.isArray(pair) && typeof pair[0] === "string" && typeof pair[1] === "string") {
          bindings.set(pair[0], pair[1]);
        }
      }
    }
  } catch {}
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
  // Drop bindings pointing at an app that did not restore — a binding is only meaningful
  // while its app is installed — then let the vacancies that leaves be filled by whatever
  // remains. Without the second pass a protocol whose app is gone would stay unbound even
  // with an installed app offering to serve it.
  for (const [proto, key] of bindings) if (!installedApps.has(key)) bindings.delete(proto);
  for (const rec of installedApps.values()) autoBind(rec);
  const saved = sessionStorage.getItem(STORE + ".active");
  if (saved && installedApps.has(saved)) setActiveApp(saved);
}

// ── active-app iframe mount ────────────────────────────────────────────
function setActiveApp(key) {
  const rec = installedApps.get(key);
  if (!rec) return;
  if (!rec.uiHtml) {
    shellPrint(`${rec.name} has no UI; cannot mount.`, "err");
    return;
  }
  activeAppKey = key;
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
  activeAppKey = null;
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
  // "Is this an update to something we already hold?" is now a plain map lookup: the
  // app key contains the author (§12.4), so a match IS same-author — there is no key
  // comparison to get wrong, and a stranger's bundle simply misses and falls through to
  // the consent path below. An auto-update also inherits only the bindings it already
  // had (§12.10), so an offer can never take over a protocol by arriving.
  const existing = installedApps.get(peeked.key);

  if (existing) {
    try {
      const rec = await applyAppBundle(bundleBytes);
      shellPrint(
        `Auto-updated ${rec.name} → ${rec.version} ` +
        `(from ${fromPkHex.slice(0, 8)}, signed by ${bytesToHex(authorPk).slice(0, 8)})`, "sys");
      // If this was the active app, re-mount the new UI.
      if (activeAppKey === rec.key) setActiveApp(rec.key);
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
    setActiveApp(rec.key);
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
function offerApp(key) {
  const rec = installedApps.get(key);
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
  if (rec.key === activeAppKey) li.classList.add("active");

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

  // Protocol bindings (§12.10). One row per protocol this app offers to serve, each a
  // plain toggle: binding is a preference, so switching is one click and reversible.
  // "Handles" is what the author declared; the checkbox is what the user decided.
  const protos = document.createElement("div");
  protos.className = "app-row-meta";
  for (const proto of rec.handles) {
    const holder = bindings.get(proto);
    const mine = holder === rec.key;
    const label = document.createElement("label");
    label.className = "app-row-proto";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = mine;
    cb.addEventListener("change", () => {
      if (cb.checked) bindProtocol(proto, rec.key);
      else { bindings.delete(proto); persistInstalledApps(); renderAppList(); }
    });
    label.appendChild(cb);
    const txt = document.createElement("span");
    // Name the app currently holding a contested protocol, so "why am I not getting
    // messages" has a visible answer rather than being silent.
    const other = holder && !mine ? installedApps.get(holder) : null;
    txt.textContent = ` handles “${proto}”` +
      (mine ? "" : other ? ` — bound to ${other.name}` : " — unbound");
    label.appendChild(txt);
    protos.appendChild(label);
  }
  li.appendChild(protos);

  const btns = document.createElement("div");
  btns.className = "app-row-buttons";
  if (rec.uiHtml) {
    const openBtn = document.createElement("button");
    openBtn.className = "icon primary";
    openBtn.textContent = rec.key === activeAppKey ? "Active" : "Open";
    openBtn.disabled = rec.key === activeAppKey;
    openBtn.addEventListener("click", () => {
      setActiveApp(rec.key);
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
  offerBtn.addEventListener("click", () => offerApp(rec.key));
  btns.appendChild(offerBtn);

  const removeBtn = document.createElement("button");
  removeBtn.className = "icon danger";
  removeBtn.textContent = "Remove";
  removeBtn.addEventListener("click", () => removeApp(rec.key));
  btns.appendChild(removeBtn);

  li.appendChild(btns);
  return li;
}

function removeApp(key) {
  const rec = installedApps.get(key);
  if (!rec) return;
  if (!confirm(`Remove ${rec.name} ${rec.version}? The kernel handler will be uninstalled.`)) return;
  // Revocation (§12.5): removeHandler empties the kernel slot AND clears its install
  // record, so the same name is free to re-admit later with no stale attribution.
  host.removeHandler(rec.handlerName);
  installedApps.delete(key);
  // Drop every protocol this app held (§12.10). Removing an app unbinds it; it does not
  // hand its protocols to anyone else, so the user chooses again from what remains.
  for (const proto of boundProtocols(key)) bindings.delete(proto);
  if (activeAppKey === key) unmountActiveApp();
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
    const active = activeAppKey ? installedApps.get(activeAppKey) : null;
    if (!active) return;
    // Send under a protocol the active app is actually BOUND to, so our own echo
    // (and a peer that binds the same protocol to a different implementation) routes
    // to the right place. An app the user has unbound sends nothing.
    const proto = boundProtocols(active.key)[0];
    if (!proto) return;
    const body = msg.body instanceof Uint8Array ? msg.body : new Uint8Array(msg.body);
    const chatBytes = new Uint8Array(1 + body.length);   // [chatType][body]
    chatBytes[0] = msg.chatType & 0xff;
    chatBytes.set(body, 1);
    broadcastFrame(encodeChatFrame(proto, chatBytes));
    deliverChat(proto, myKeys.publicKey, chatBytes);   // local echo
    if (msg.chatType === 0x02) {
      // Sticky "presence" replay: nick announcements are cached and
      // re-broadcast on every newly-opened dc so peers joining mid-session
      // pick up our identity without us having to send it again. The chat
      // app uses chatType=0x02 for this; other apps that don't use the
      // same convention simply never set the cache.
      lastSentNickBody = { proto, body };
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

let lastSentNickBody = null;   // {proto, body} — replayed to peers that join mid-session

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
    if (lastSentNickBody && bindings.has(lastSentNickBody.proto)) {
      const body = lastSentNickBody.body;
      const chatBytes = new Uint8Array(1 + body.length);
      chatBytes[0] = 0x02;
      chatBytes.set(body, 1);
      endpoint.send(peerId, encodeChatFrame(lastSentNickBody.proto, chatBytes));
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
    const proto = new TextDecoder().decode(bytes.subarray(2, 2 + idLen));
    const chatBytes = bytes.subarray(2 + idLen);   // [chatType][body]
    deliverChat(proto, hexToBytes(from), chatBytes);
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
