// transport-harness.mjs — shared plumbing for the transport-bundle tests. The transport
// is a signed bundle whose guest holds the AKE, record layer, routing and request/response
// layer; these tests drive it through the real host stack — shell → driver (TransportHost)
// → guest realm — with in-process channel pairs for sockets, so the properties pinned
// here are the shipped bundle's, not a parallel reimplementation's.

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
export const { OpArgs } = await imp("build/host/op-frame.js");
export const { LoopbackChannels } = await imp("tests/loopback-channels.mjs");
/** The link close-reason codes the transport guest returns from `linkClosed`
 *  (transport/src/ake.js, `REASON_*`). The host only relays the number, so the vocabulary
 *  lives with the occupant and here, where the tests assert it. */
export const CLOSE_REASON = { OPEN: 0, HANDSHAKE: 1, CLEAN: 2, ABORTED: 3, LOCAL: 4, TRUNCATED: 5 };

/** A `ChannelFactory` that hands the driver channels the TEST built, so a test keeps the
 *  instrumented object it is asserting on (`wirePair`'s recorder, tamperer and backlog).
 *
 *  It is the WebRTC shape, not a fabric: the platform says "here is a socket" and the link
 *  states on itself whether we dialed it and who it expects. There is deliberately no
 *  `connect` — a factory that only accepts is a real configuration, and it is the one that
 *  lets a test hold both ends of a pair. */
export class InjectedChannels {
  #accept = null;
  /** Binds nothing; the driver's `start()` calls this and gets its accept sink in. */
  async listen(_tcp, _ws, onAccept) {
    this.#accept = onAccept;
    return { port: 0, wsPort: 0 };
  }
  close() { this.#accept = null; }
  give(channel, arrival = {}) {
    if (!this.#accept) throw new Error("InjectedChannels: the driver has not started yet");
    this.#accept(channel, arrival);
    return channel;
  }
}

export const { transportBundleBytes } = await imp("build/host/transport-bundle.js");
export const { authorBundle } = await imp("build/host/bundle-author.js");
export const TRANSPORT_SERVICE = "_net";
export const { makeAuthor } = await imp("tests/testkit.mjs");

export const transportBlob = transportBundleBytes();

/** The protocol id the harness app claims. */
export const PROTO = "harness/v1";

/** The harness APP — a real signed bundle, since an app reaches the network by calling the
 *  id the transport claims (`_net`) and is reached by the id it claims itself. ONE
 *  entrypoint, with the mode chosen at load through the manifest's `config`:
 *    send — one request out; answers `[ok u8][response]` straight through from `_net`.
 *    op   — an already-framed `[opLen u8][op][args]` handed to `_net` verbatim, for the
 *           tests whose subject is WHICH ops an app may name (no name of its own).
 *    seen/from — everything `handle` was handed INBOUND, and who it was attributed to. */
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

/** One local op through the harness app's slot-bound handle, with the host's caller id in
 *  front of THIS app's own op framing — the name is the app's vocabulary and the shell
 *  never reads it. */
function invoke(app, op, args = new Uint8Array(0), deadlineMs) {
  const b = new Uint8Array(1 + op.length + args.length);
  b[0] = op.length;
  for (let i = 0; i < op.length; i++) b[1 + i] = op.charCodeAt(i) & 0xff;
  b.set(args, 1 + op.length);
  return app.invoke(b, deadlineMs);
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
    // A local call graph edge, so `calls`; this app holds no host service at all.
    guestRequires: [],
    guestCalls: [TRANSPORT_SERVICE],
    guestConfig: { mode },
  });
  return blob;
}

/** The app key the harness app binds under, for routing assertions. */
export function harnessAppKey(author) {
  return `${Buffer.from(author.id).toString("hex")}:harness`;
}

/** The `send` op's argument bytes:
 *  `[noReply u8][to blob][proto blob][payload blob]` (transport/src/core.js).
 *  Written once here because three suites build it. */
export function sendArgs(to, payload, { proto = PROTO, noReply = false } = {}) {
  const p = new TextEncoder().encode(proto);
  const out = new Uint8Array(1 + 4 + 32 + 4 + p.length + 4 + payload.length);
  let off = 0;
  out[off++] = noReply ? 1 : 0;
  const u32 = (v) => { out[off] = v >>> 24; out[off + 1] = (v >>> 16) & 255; out[off + 2] = (v >>> 8) & 255; out[off + 3] = v & 255; off += 4; };
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
export async function appRequest(app, to, payload, opts) {
  const r = await invoke(app, OP.SEND, sendArgs(to, payload, opts), opts?.deadlineMs);
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
 *  occupant decodes is `link/deliver`, one of that grant's own names, so there is no
 *  second grant to write here. */
export function transportPolicy(authorHex, appAuthors = []) {
  return policyFromJson(JSON.stringify({
    authors: [authorHex, ...appAuthors],
    grants: { link: [authorHex] },
  }));
}

/** One transport host: a shell over a fresh identity + the transport bundle, and — unless
 *  `app: false` — the harness app that drives it. Socket options pass to the driver;
 *  guest-owned policy passes as the transport bundle's one-load LOCAL config.
 *  `request`/`sendNoReply`/`peers`/`seen`/`from`/`op` are
 *  each a single `invoke` into the harness app, so the bytes cross exactly the seam a real
 *  app's would. */
export async function makeTransportHost(opts = {}) {
  const identity = opts.identity ?? generateKeyPair();
  const appAuthor = opts.appAuthor ?? makeAuthor(opts.sodium ?? sodium);
  const appAuthorHex = Buffer.from(appAuthor.id).toString("hex");
  const policy = transportPolicy(opts.transportAuthorHex ?? transportAuthor(), [appAuthorHex]);
  const transport = {
    channels: opts.channels,
    listen: opts.listen,
    // The DRIVER's own ceiling, not one of the guest's link-state tiers.
    maxRawLinks: opts.maxRawLinks,
    // The occupant's one-byte reason per link teardown (CLOSE_REASON above) — the node's
    // own observation seam, and the only place a test can read WHY a link went down.
    onLinkClosed: opts.onLinkClosed,
    load: false,
    bundle: opts.transportBlob ?? transportBlob,
  };
  const transportConfig = {
    ...(opts.transportConfig ?? {}),
    ...(opts.contactSecret === undefined ? {} : {
      contactSecret: Buffer.from(opts.contactSecret).toString("hex"),
    }),
    ...(opts.admitPeers === undefined ? {} : {
      admitPeers: opts.admitPeers.map((peer) => Buffer.from(peer).toString("hex")),
    }),
    ...(opts.connsPerPeer === undefined ? {} : { connsPerPeer: opts.connsPerPeer }),
    ...(opts.transportHalfOpen?.unverified === undefined ? {} : { maxHalfOpenUnverified: opts.transportHalfOpen.unverified }),
    ...(opts.transportHalfOpen?.perSource === undefined ? {} : { maxHalfOpenPerSource: opts.transportHalfOpen.perSource }),
    ...(opts.transportHalfOpen?.verified === undefined ? {} : { maxHalfOpenVerified: opts.transportHalfOpen.verified }),
    ...(opts.transportHalfOpen?.authed === undefined ? {} : { maxAuthedLinks: opts.transportHalfOpen.authed }),
    ...(opts.linkIdleTimeoutMs === undefined ? {} : { linkIdleTimeoutMs: opts.linkIdleTimeoutMs }),
  };
  const blob = transport.bundle;
  const { shell, transport: driver } = await bootShell({
    sodium: opts.sodium ?? sodium,
    identity,
    modules: new ModuleTable(),
    freshnessStore: new FreshnessMarks(),
    // No disk: nothing here declares `fs`, and the in-memory default would be a backend
    // these tests never meant to hand out.
    fs: false,
    networkKey: opts.networkKey,
    transport,
    createRealm: async (o) => createSafeRealm(opts.onHostCall
      ? {
          ...o,
          hostCall: (...args) => {
            opts.onHostCall(...args);
            return o.hostCall(...args);
          },
        }
      : o),
    admit: policy,
  });
  await shell.loadBundleBlob(blob, { localConfig: transportConfig });
  // The node's own channel key, hex — off the identity this harness minted, not asked of
  // the driver: it is `toHex(identity.publicKey)`, which every caller of this factory
  // already holds, and the driver says nothing about peers any more (core/socket-seam.ts).
  const peerId = Buffer.from(identity.publicKey).toString("hex");
  const node = { shell, driver, identity, appAuthor, peerId };
  if (opts.app === false) return node;
  const app = await shell.loadBundleBlob(harnessAppBlob(appAuthor, opts.mode ?? "echo"));

  const enc = new TextEncoder();
  const call = (to, proto, payload, deadlineMs, noReply) => {
    // The `send` op's own argument order (transport/src/core.js):
    // [noReply u8][to blob][proto blob][payload blob]. The deadline is kernel state on
    // `invoke`, not guest protocol data.
    const p = enc.encode(proto);
    const out = new Uint8Array(1 + 4 + 32 + 4 + p.length + 4 + payload.length);
    let off = 0;
    out[off++] = noReply ? 1 : 0;
    const u32 = (v) => { out[off] = v >>> 24; out[off + 1] = (v >>> 16) & 255; out[off + 2] = (v >>> 8) & 255; out[off + 3] = v & 255; off += 4; };
    u32(32);
    out.set(Buffer.from(to, "hex"), off); off += 32;
    u32(p.length);
    out.set(p, off); off += p.length;
    u32(payload.length);
    out.set(payload, off);
    return invoke(app, OP.SEND, out, deadlineMs);
  };
  /** One request out, resolving with the response bytes — or rejecting, which is what
   *  the `[0]` failure byte means (an unreachable peer, a deadline, a refusal). */
  node.request = async (to, proto, payload, deadlineMs) => {
    const r = await call(to, proto, payload, deadlineMs, false);
    if (r[0] !== 1) throw new Error("net: request failed");
    return r.slice(1);
  };
  node.sendNoReply = (to, proto, payload) => call(to, proto, payload, undefined, true);
  node.app = app;
  node.appKey = app.key;
  /** Name an arbitrary transport op FROM THE APP, for the tests whose subject is the caller
   *  boundary (transport/src/core.js `APP_OPS`). Rejects when the transport refuses the
   *  name, which is what those tests pin. */
  node.op = (name, args = new Uint8Array(0)) => {
    const n = enc.encode(name);
    const out = new Uint8Array(1 + n.length + args.length);
    out[0] = n.length;
    out.set(n, 1);
    out.set(args, 1 + n.length);
    return invoke(app, OP.RAW, out);
  };
  /** Everything this node's app was handed inbound. */
  node.seen = async () => {
    const b = await invoke(app, OP.SEEN);
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
    const b = await invoke(app, OP.FROM);
    const out = [];
    for (let off = 0; off + 32 <= b.length; off += 32) out.push(Buffer.from(b.slice(off, off + 32)).toString("hex"));
    return out;
  };
  node.peers = () => linkedPeers(node);
  node.addr = (peerHex, dest, contactSecret) => addr(node, peerHex, dest, contactSecret);
  return node;
}

/** The host's own door into the transport — exactly what the CLI composes, so a test drives
 *  the real path. Throws when nothing claims the id: a node with no transport bundle. */
export function transportOp(node, args) {
  const answer = node.shell.call(TRANSPORT_SERVICE, args.build());
  if (!answer) throw new Error("transport: no bundle claims " + TRANSPORT_SERVICE);
  return answer;
}

/** Dial every known peer and resolve once each is authenticated, or the deadline passes. */
export function ready(node, timeoutMs = 5000) {
  return transportOp(node, new OpArgs("ready").u32(timeoutMs));
}

/** The peers this node holds at least one authenticated link to, as hex. */
export async function linkedPeers(node) {
  const bytes = await transportOp(node, new OpArgs("peers"));
  const out = [];
  for (let off = 0; off + 32 <= bytes.length; off += 32) {
    out.push(Buffer.from(bytes.slice(off, off + 32)).toString("hex"));
  }
  return out;
}

/** Teach this node one peer: where to reach it, and the secret THAT peer's door gates on.
 *  Straight into the occupant's book — the host retains nothing — so a test that replaces
 *  the transport must say it again (§12.10). */
export function addr(node, peerHex, dest, contactSecret) {
  const ZERO32 = new Uint8Array(32);
  return transportOp(node, new OpArgs("addr")
    .blob(Buffer.from(peerHex, "hex"))
    .blob(contactSecret ?? ZERO32)
    .text(dest));
}

/** Rotate the inbound contact secret (§12.6.3). */
export function contact(node, secret) {
  return transportOp(node, new OpArgs("contact").blob(secret ?? new Uint8Array(0)));
}

/** Whether `node` holds an authenticated link to `peerHex` right now. The set lives in the
 *  transport guest — a fact about links, and links are the guest's — so this is a question
 *  rather than a field, and it is what a test reads instead of the per-link callbacks the
 *  driver used to fire. */
export async function linkedTo(node, peerHex) {
  return (await linkedPeers(node)).includes(peerHex);
}

/** Await a condition with a deadline — the tests' tick, bounded. The predicate is
 *  AWAITED: an async one is polled on its resolved value, where a bare promise object
 *  would be truthy on the first tick and make the wait a silent no-op. */
export async function until(fn, ms = 3000, what = "condition") {
  const start = Date.now();
  for (;;) {
    if (await fn()) return;
    if (Date.now() - start > ms) throw new Error("timeout waiting for " + what);
    await new Promise((r) => setTimeout(r, 2));
  }
}
