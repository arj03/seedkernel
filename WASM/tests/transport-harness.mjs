// transport-harness.mjs — shared plumbing for the transport-bundle tests.
//
// The transport is a signed bundle whose guest program holds the AKE, record
// layer, routing and request/response layer. Tests drive it through the real
// host stack — shell → driver (TransportHost) → guest realm — with in-process
// channel pairs standing in for sockets, so the properties pinned here are
// properties of the shipped bundle, not of a parallel reimplementation.

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

export const { loadCrypto, generateKeyPair } = await imp("build/host/crypto-node.js");
export const sodium = await loadCrypto();
export const { bootShell } = await imp("build/host/shell-core.js");
export const { createSafeRealm } = await imp("build/host/safe-js.js");
export const { policyFromJson } = await imp("build/host/policy.js");
export const { FreshnessMarks, verifyBundle } = await imp("build/host/bundle.js");
export const { ModuleTable } = await imp("build/host/module-table.js");
export const { TransportHost } = await imp("build/host/transport-host.js");
export const { LoopbackChannels } = await imp("tests/loopback-channels.mjs");
/** The link close-reason codes the transport guest reports through link-down
 *  (transport/src/ake.js, `REASON_*`). The host only relays the number, so the vocabulary
 *  lives with the occupant and here, where the tests assert it. */
export const CLOSE_REASON = { OPEN: 0, HANDSHAKE: 1, CLEAN: 2, ABORTED: 3, LOCAL: 4, TRUNCATED: 5 };
export const { transportBundleBytes } = await imp("build/host/transport-bundle.js");
export const { authorBundle } = await imp("build/host/bundle.js");
export const TRANSPORT_SERVICE = "_net";
export const { makeAuthor } = await imp("tests/testkit.mjs");

export const transportBlob = transportBundleBytes();

/** The protocol id the harness app claims. */
export const PROTO = "harness/v1";

/** The harness APP — a real signed bundle, since an app reaches the network by calling the
 *  id the transport claims (`_net`) and is reached by the id it claims itself. A test that
 *  drives the transport therefore has to be an app, which is what makes these tests
 *  exercise the same path a deployment does.
 *
 *  ONE entrypoint, and a mode chosen at load through the manifest's `config`. `handle` is
 *  reached by `dispatch` (a remote peer's frame, echoed) and by the host's `invoke`
 *  loopback (the 32 zero-byte caller id, the op envelope in the payload), whose ops are:
 *    send — one request out; answers `[ok u8][response]` straight through from `_net`.
 *    op   — an already-framed `[opLen u8][op][args]` handed to `_net` verbatim, for the
 *           tests whose subject is WHICH ops an app may name. It writes no name of its
 *           own, so a refusal is the transport's.
 *    seen — everything `handle` was handed INBOUND, as `[len u32][bytes]…`.
 *    from — who each of those was attributed to, `[pk 32]…`, in step with `seen`. */
const HARNESS_GUEST = `
// This app's own copies of the shape it shares with whatever it calls (its own format
// after the kernel's 32-byte caller prefix): a local op is [opLen u8][op][args], and
// the transport's app contract (the id this app calls) is spelled the same way. The
// kernel never reads any of it.
function readOp(b) {
  const n = b.length > 0 ? b[0] : -1;
  if (n < 0 || b.length < 1 + n) throw new Error("harness: malformed op");
  let op = "";
  for (let i = 0; i < n; i++) op += String.fromCharCode(b[1 + i]);
  return { op, args: b.subarray(1 + n) };
}
function writeOp(op, args) {
  const out = new Uint8Array(1 + op.length + args.length);
  out[0] = op.length;
  for (let i = 0; i < op.length; i++) out[1 + i] = op.charCodeAt(i) & 0xff;
  out.set(args, 1 + op.length);
  return out;
}
const seen = [];
// Who each inbound frame was ATTRIBUTED to, in step with \`seen\`: the shell puts the
// authenticated sender in front of the payload, so this is what a delivery claims about
// its own origin. Recorded separately because a test about attribution must be able to
// read it back without the payload tests changing shape.
const from = [];
function handle(arg) {
  const c = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) { if (c[i] !== 0) { fromHost = false; break; } }
  const p = arg.subarray(32);
  // A LOCAL call from the host (caller = 32 zero bytes): the op NAME picks the local op,
  // the one-vocabulary shape the transport's own handle reads.
  if (fromHost) {
    const { op, args } = readOp(p);
    if (op === "send") return host.call(${JSON.stringify(TRANSPORT_SERVICE)}, writeOp("send", args));
    if (op === "op") return host.call(${JSON.stringify(TRANSPORT_SERVICE)}, args);
    if (op === "seen") {
      let n = 0;
      for (const s of seen) n += 4 + s.length;
      const out = new Uint8Array(n);
      let off = 0;
      for (const s of seen) {
        out[off] = s.length >>> 24; out[off + 1] = (s.length >>> 16) & 255;
        out[off + 2] = (s.length >>> 8) & 255; out[off + 3] = s.length & 255;
        out.set(s, off + 4); off += 4 + s.length;
      }
      return out;
    }
    if (op === "from") {
      const out = new Uint8Array(from.length * 32);
      for (let i = 0; i < from.length; i++) out.set(from[i], i * 32);
      return out;
    }
    return new Uint8Array(0);
  }
  // A remote peer's frame: record it and who it came from, then echo it (or hang, or
  // generate).
  seen.push(p);
  from.push(c.slice());
  if (APP.mode === "hang") return new Promise(() => {});
  // A GENERATOR request, for the reassembly tests: [0xff][len u32][mul u8] asks for
  // len bytes where out[i] = (i * mul) & 255 — a response far larger than anything
  // that fits in one segment, and checkable byte for byte.
  if (p.length === 6 && p[0] === 255) {
    const n = ((p[1] << 24) | (p[2] << 16) | (p[3] << 8) | p[4]) >>> 0;
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = (i * p[5]) & 255;
    return out;
  }
  return p;
}
`;

/** The harness app's local op names — the one op vocabulary its `handle` reads. */
const OP = { SEND: "send", RAW: "op", SEEN: "seen", FROM: "from" };

/** One local op into the harness app: `shell.invoke` loops back through `handle`, with the
 *  host's caller id in front of THIS app's own op framing — the name is the app's
 *  vocabulary and the shell never reads it. */
function invoke(shell, appKey, op, args = new Uint8Array(0)) {
  const b = new Uint8Array(1 + op.length + args.length);
  b[0] = op.length;
  for (let i = 0; i < op.length; i++) b[1 + i] = op.charCodeAt(i) & 0xff;
  b.set(args, 1 + op.length);
  return shell.invoke(b, appKey);
}

/** Sign the harness app under `author`, in `mode` ("echo" | "hang"). */
export function harnessAppBlob(author, mode = "echo") {
  const { blob } = authorBundle(sodium, author, {
    app: "harness",
    version: 1,
    protocols: [PROTO],
    modules: [],
    guestSource: HARNESS_GUEST,
    // The whole of what an app needs to talk to the network: the id the transport claims.
    guestRequires: [TRANSPORT_SERVICE],
    guestConfig: { mode },
  });
  return blob;
}

/** The app key the harness app binds under, for `invoke`. */
export function harnessAppKey(author) {
  return `${Buffer.from(author.id).toString("hex")}:harness`;
}

/** The `send` op's argument bytes:
 *  `[noReply u8][deadline u32][to blob][proto blob][payload blob]` (transport/src/core.js).
 *  Written once here because three suites build it. */
export function sendArgs(to, payload, { proto = PROTO, deadlineMs = 0, noReply = false } = {}) {
  const p = new TextEncoder().encode(proto);
  const out = new Uint8Array(1 + 4 + 4 + 32 + 4 + p.length + 4 + payload.length);
  let off = 0;
  out[off++] = noReply ? 1 : 0;
  const u32 = (v) => { out[off] = v >>> 24; out[off + 1] = (v >>> 16) & 255; out[off + 2] = (v >>> 8) & 255; out[off + 3] = v & 255; off += 4; };
  u32(deadlineMs);
  u32(32);
  out.set(Buffer.from(to, "hex"), off); off += 32;
  u32(p.length);
  out.set(p, off); off += p.length;
  u32(payload.length);
  out.set(payload, off);
  return out;
}

/** One request out of `shell`, through the harness app it loaded — the path a real
 *  deployment uses. */
export async function appRequest(shell, appKey, to, payload, opts) {
  const r = await invoke(shell, appKey, OP.SEND, sendArgs(to, payload, opts));
  if (r[0] !== 1) throw new Error("net: request failed");
  return r.slice(1);
}

/** Ask a node's app for `len` generated bytes — the reassembly probe. */
export function generatorRequest(len, mul) {
  return Uint8Array.from([255, (len >>> 24) & 255, (len >>> 16) & 255, (len >>> 8) & 255, len & 255, mul]);
}

/** The author of the artifact-shipped transport bundle, read OUT of the artifact. A fresh
 *  clone mints its own, so a fixed id — or one scraped from the generated header — is
 *  drift waiting to happen. */
export function transportAuthor() {
  return Buffer.from(verifyBundle(sodium, transportBlob).author).toString("hex");
}

/** The policy every harness node runs under: the transport author granted `link`, and
 *  whoever else is named trusted to load an ordinary app. Delivering what the link
 *  occupant decodes is the slot's own return convention, so no second grant exists. */
export function transportPolicy(authorHex, appAuthors = []) {
  return policyFromJson(JSON.stringify({
    authors: [authorHex, ...appAuthors],
    grants: { link: [authorHex] },
  }));
}

/** One transport host: a shell over a fresh identity + the transport bundle, and — unless
 *  `app: false` — the harness app that drives it. Options pass through to the driver
 *  this harness constructs (admitPeers for the peer list, networkKey, contactSecret,
 *  channels, requestDeadlineMs, transportHalfOpen, maxRawLinks, linkIdleTimeoutMs).
 *
 *  `request`/`sendNoReply`/`seen`/`peers` are each one `invoke` into the harness app, so
 *  the bytes cross exactly the seam a real app's would. */
export async function makeTransportHost(opts = {}) {
  const identity = opts.identity ?? generateKeyPair();
  const appAuthor = opts.appAuthor ?? makeAuthor(opts.sodium ?? sodium);
  const appAuthorHex = Buffer.from(appAuthor.id).toString("hex");
  const policy = transportPolicy(opts.transportAuthorHex ?? transportAuthor(), [appAuthorHex]);
  const driver = new TransportHost({
    identity,
    channels: opts.channels,
    listen: opts.listen,
    networkKey: opts.networkKey,
    contactSecret: opts.contactSecret,
    admitPeers: opts.admitPeers,
    connsPerPeer: opts.connsPerPeer,
    requestDeadlineMs: opts.requestDeadlineMs,
    maxHalfOpenUnverified: opts.transportHalfOpen?.unverified,
    maxHalfOpenPerSource: opts.transportHalfOpen?.perSource,
    maxHalfOpenVerified: opts.transportHalfOpen?.verified,
    maxAuthedLinks: opts.transportHalfOpen?.authed,
    // The DRIVER's own ceiling, not one of the tiers above: `transportHalfOpen` is what the
    // guest enforces, this is what the host holds.
    maxRawLinks: opts.maxRawLinks,
    linkIdleTimeoutMs: opts.linkIdleTimeoutMs,
  });
  // A DRIVER INSTANCE, so bootShell wires it and composes the pin but neither loads the
  // transport bundle nor starts the listeners — this harness owns both, because a test
  // wants the load observable (and sometimes refused). `transportBundle` is still stated:
  // it is what the pin is derived from, so the blob loaded below and the blob the pin
  // admits are one fact rather than two that can drift.
  const blob = opts.transportBlob ?? transportBlob;
  const shell = await bootShell({
    sodium: opts.sodium ?? sodium,
    identity,
    modules: new ModuleTable(),
    freshnessStore: new FreshnessMarks(),
    // No disk: nothing here declares `fs`, and the in-memory default would be a backend
    // these tests never meant to hand out.
    fs: false,
    networkKey: opts.networkKey,
    transport: driver,
    transportBundle: blob,
    createRealm: async (o) => createSafeRealm(o),
    admit: policy,
    claims: opts.claims,
  }).then((r) => r.shell);
  await shell.loadBundleBlob(blob);
  const node = { shell, driver, identity, appAuthor };
  if (opts.app === false) return node;
  const appKey = `${appAuthorHex}:harness`;
  await shell.loadBundleBlob(harnessAppBlob(appAuthor, opts.mode ?? "echo"));

  const enc = new TextEncoder();
  const call = (to, proto, payload, deadlineMs, noReply) => {
    // The `send` op's own argument order (transport/src/core.js):
    // [noReply u8][deadline u32][to blob][proto blob][payload blob].
    const p = enc.encode(proto);
    const out = new Uint8Array(1 + 4 + 4 + 32 + 4 + p.length + 4 + payload.length);
    let off = 0;
    out[off++] = noReply ? 1 : 0;
    const u32 = (v) => { out[off] = v >>> 24; out[off + 1] = (v >>> 16) & 255; out[off + 2] = (v >>> 8) & 255; out[off + 3] = v & 255; off += 4; };
    u32(deadlineMs ?? 0);
    u32(32);
    out.set(Buffer.from(to, "hex"), off); off += 32;
    u32(p.length);
    out.set(p, off); off += p.length;
    u32(payload.length);
    out.set(payload, off);
    return invoke(shell, appKey, OP.SEND, out);
  };
  /** One request out, resolving with the response bytes — or rejecting, which is what
   *  the `[0]` failure byte means (an unreachable peer, a deadline, a refusal). */
  node.request = async (to, proto, payload, deadlineMs) => {
    const r = await call(to, proto, payload, deadlineMs, false);
    if (r[0] !== 1) throw new Error("net: request failed");
    return r.slice(1);
  };
  node.sendNoReply = (to, proto, payload) => call(to, proto, payload, 0, true);
  node.appKey = appKey;
  /** Name an arbitrary transport op FROM THE APP, for the tests whose subject is the caller
   *  boundary (transport/src/core.js `APP_OPS`). Rejects when the transport refuses the
   *  name, which is what those tests pin. */
  node.op = (name, args = new Uint8Array(0)) => {
    const n = enc.encode(name);
    const out = new Uint8Array(1 + n.length + args.length);
    out[0] = n.length;
    out.set(n, 1);
    out.set(args, 1 + n.length);
    return invoke(shell, appKey, OP.RAW, out);
  };
  /** Everything this node's app was handed inbound. */
  node.seen = async () => {
    const b = await invoke(shell, appKey, OP.SEEN);
    const out = [];
    for (let off = 0; off + 4 <= b.length;) {
      const n = ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
      out.push(b.slice(off + 4, off + 4 + n));
      off += 4 + n;
    }
    return out;
  };
  /** Who this node's app was told each inbound frame came from, in step with `seen` —
   *  the attribution the shell put in front of the payload, as hex. */
  node.from = async () => {
    const b = await invoke(shell, appKey, OP.FROM);
    const out = [];
    for (let off = 0; off + 32 <= b.length; off += 32) out.push(Buffer.from(b.slice(off, off + 32)).toString("hex"));
    return out;
  };
  node.peers = () => driver.linkedPeers();
  return node;
}

/** Await a condition with a deadline — the tests' tick, bounded. The predicate is
 *  AWAITED, so an async one is polled on its resolved value: a promise object is truthy
 *  on the first tick, which would return immediately and make the whole wait a silent
 *  no-op. A sync predicate costs one microtask per tick and reads the same. */
export async function until(fn, ms = 3000, what = "condition") {
  const start = Date.now();
  for (;;) {
    if (await fn()) return;
    if (Date.now() - start > ms) throw new Error("timeout waiting for " + what);
    await new Promise((r) => setTimeout(r, 2));
  }
}
