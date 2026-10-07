// Shared plumbing for the transport-bundle tests. The transport is a signed bundle whose
// guest holds the AKE, record layer, routing and request/response layer; these tests drive
// it through the real host stack (shell, driver (TransportHost), guest realm) with
// in-process channel pairs for sockets, so what they check is the shipped bundle.

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
export const { OpArgs } = await imp("build/services/op-frame.js");
export const { LoopbackChannels } = await imp("tests/loopback-channels.mjs");
/** A `ChannelFactory` that hands the driver channels the test built, so the test keeps the
 *  instrumented object it asserts on (`wirePair`'s recorder, tamperer and backlog). Not a
 *  fabric: a test holds both ends of a pair, passes one in as an accept (`give`) and the
 *  other as the socket a node's transport opens when it dials (`dial`). */
export class InjectedChannels {
  #accept = null;
  /** Channels queued per destination, handed out one per `connect`. */
  #dials = new Map();
  /** Binds nothing; the driver's `start()` calls this and gets its accept sink in. */
  async listen(addrs, onAccept) {
    this.#accept = onAccept;
    return addrs.map(() => 0);
  }
  close() { this.#accept = null; }
  /** The next channel queued for `dest`, or no route. */
  connect(dest) {
    const queue = this.#dials.get(dest);
    const channel = queue?.shift() ?? null;
    if (queue?.length === 0) this.#dials.delete(dest);
    return channel;
  }
  give(channel, arrival = {}) {
    if (!this.#accept) throw new Error("InjectedChannels: the driver has not started yet");
    this.#accept(channel, arrival);
    return channel;
  }
  /** A link `node`'s transport dials to `peerHex` through its own address book, like every
   *  dial: the peer is added at a destination this factory answers with `channel`, under the
   *  contact secret the dial presents, and `ready` starts the dial. The node needs a
   *  `connsPerPeer` above its live links to that peer for a second dial to open. */
  async dial(node, peerHex, channel, secret) {
    const dest = `inject://${peerHex}`;
    const queue = this.#dials.get(dest) ?? [];
    queue.push(channel);
    this.#dials.set(dest, queue);
    await addr(node, peerHex, dest, secret);
    void ready(node, 1).catch(() => {});
    return channel;
  }
}

export const { transportBundleBytes } = await imp("build/host/transport-bundle.js");
export const { authorBundle } = await imp("build/scripts/bundle-author.js");
export const TRANSPORT_SERVICE = "_net";
export const { makeAuthor } = await imp("tests/testkit.mjs");

export const transportBlob = transportBundleBytes();

/** The protocol id the harness app claims. */
export const PROTO = "harness/v1";

/** The harness app: a real signed bundle, since an app reaches the network by calling the
 *  id the transport claims (`_net`) and is reached by the id it claims itself. Its local
 *  ops:
 *    send: one request out; returns `[ok u8][response]` straight from `_net`.
 *    op:   an already-framed `[opLen u8][op][args]` passed to `_net` verbatim, for the
 *          tests about which ops an app may name.
 *    seen/from: everything `handle` received inbound, and who it was attributed to.
 *  The echo/hang mode is chosen at install through the manifest's `config`. */
const HARNESS_GUEST = `
// This app's own copy of the op format it shares with what it calls (after the host's
// 32-byte caller prefix): a local op is [opLen u8][op][args], and the transport's app
// interface uses the same format. The host never reads any of it.
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
// Who each inbound frame was attributed to, in step with \`seen\`: the shell puts the
// authenticated sender in front of the payload. Recorded separately so attribution tests
// can read it without changing the payload tests.
const from = [];
function handle(arg) {
  const c = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) { if (c[i] !== 0) { fromHost = false; break; } }
  const p = arg.subarray(32);
  // A local call from the host (caller = 32 zero bytes): the op name picks the local op,
  // as in the transport's own handle.
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
  // A generator request, for the reassembly tests: [0xff][len u32][mul u8] asks for len
  // bytes where out[i] = (i * mul) & 255, a response far larger than one segment and
  // checkable byte for byte.
  if (p.length === 6 && p[0] === 255) {
    const n = ((p[1] << 24) | (p[2] << 16) | (p[3] << 8) | p[4]) >>> 0;
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = (i * p[5]) & 255;
    return out;
  }
  return p;
}
`;

/** The harness app's local op names. */
const OP = { SEND: "send", RAW: "op", SEEN: "seen", FROM: "from" };

/** One local op through the harness app's slot-bound handle, with the host's caller id in
 *  front of this app's own op framing; the shell never reads the name. */
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
    // All an app needs to use the network: the id the transport claims. A local service
    // id; this app requires no host service at all.
    guestRequires: [TRANSPORT_SERVICE],
    guestConfig: { mode },
  });
  return blob;
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

/** One request through the harness app, the path a real deployment uses. */
export async function appRequest(app, to, payload, opts) {
  const r = await invoke(app, OP.SEND, sendArgs(to, payload, opts), opts?.deadlineMs);
  if (r[0] !== 1) throw new Error("net: request failed");
  return r.slice(1);
}

/** Ask a node's app for `len` generated bytes (the reassembly probe). */
export function generatorRequest(len, mul) {
  return Uint8Array.from([255, (len >>> 24) & 255, (len >>> 16) & 255, (len >>> 8) & 255, len & 255, mul]);
}

/** The author of the default transport bundle, read from the artifact. Each clone
 *  generates its own author, so a fixed id would go stale. */
export function transportAuthor() {
  return Buffer.from(verifyBundle(sodium, transportBlob).author).toString("hex");
}

/** The ordinary app-author policy used by harness nodes. The boot-selected transport needs no entry. */
export function transportPolicy(appAuthors) {
  return policyFromJson(JSON.stringify({
    authors: appAuthors,
  }));
}

/** One transport host: a shell over a fresh identity and the transport bundle, plus
 *  (unless `app: false`) the harness app that drives it. Socket options go to the driver;
 *  guest policy goes into the transport bundle's LOCAL config.
 *  `request`/`sendNoReply`/`peers`/`seen`/`from`/`op` are each a single `invoke` into the
 *  harness app, so the bytes cross the same seam a real app's would. */
export async function makeTransportHost(opts = {}) {
  const identity = opts.identity ?? generateKeyPair();
  const appAuthor = opts.appAuthor ?? makeAuthor(opts.sodium ?? sodium);
  const appAuthorHex = Buffer.from(appAuthor.id).toString("hex");
  const policy = transportPolicy([appAuthorHex]);
  const transport = {
    channels: opts.channels,
    listen: opts.listen,
    // The driver's own ceiling, not one of the guest's link-state tiers.
    maxRawLinks: opts.maxRawLinks,
    // The occupant's reason per link teardown (transport/src/ake.js `REASON_*`), the only
    // place a test can read why a link went down.
    onLinkClosed: opts.onLinkClosed,
    onStatus: opts.onStatus,
    // Most of this suite tears links down on purpose, so the driver's diagnostic would bury
    // the real output. Off by default here only; the line itself has its own test, which
    // turns it back on.
    suppressLinkLog: opts.suppressLinkLog ?? true,
    bundle: opts.transportBlob ?? transportBlob,
  };
  const transportConfig = {
    ...(opts.transportConfig ?? {}),
    ...(opts.networkKey === undefined ? {} : {
      networkKey: Buffer.from(opts.networkKey).toString("hex"),
    }),
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
  transport.config = transportConfig;
  const { shell, transport: driver } = await bootShell({
    sodium: opts.sodium ?? sodium,
    identity,
    modules: new ModuleTable(),
    freshnessStore: new FreshnessMarks(),
    // No fs: nothing here requires it.
    fs: false,
    guestDeadlineMs: opts.guestDeadlineMs,
    transport,
    // `onHostCall` sees every host call this node's realms make and refuses one by
    // throwing; `onHostAnswer(name, answer, payload)` can replace its answer (with a slow
    // one, say).
    createRealm: async (o) => createSafeRealm(opts.onHostCall || opts.onHostAnswer
      ? {
        ...o,
        hostCall: (...args) => {
          opts.onHostCall?.(...args);
          const answer = o.hostCall(...args);
          return opts.onHostAnswer ? opts.onHostAnswer(args[0], answer, args[1]) : answer;
        },
      }
      : o),
    admit: policy,
  });
  // The node's own key, hex, from the identity this harness created. The driver knows
  // nothing about peers (services/socket-seam.ts).
  const peerId = Buffer.from(identity.publicKey).toString("hex");
  const node = { shell, driver, identity, appAuthor, peerId };
  if (opts.app === false) return node;
  const app = await shell.install(harnessAppBlob(appAuthor, opts.mode ?? "echo"));

  const enc = new TextEncoder();
  const call = (to, proto, payload, deadlineMs, noReply) => {
    // The `send` op's own argument order (transport/src/core.js):
    // [noReply u8][to blob][proto blob][payload blob]. The deadline is host state on
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
  /** One request out, resolving with the response bytes, or rejecting on the `[0]`
   *  failure byte (an unreachable peer, a deadline, a refusal). */
  node.request = async (to, proto, payload, deadlineMs) => {
    const r = await call(to, proto, payload, deadlineMs, false);
    if (r[0] !== 1) throw new Error("net: request failed");
    return r.slice(1);
  };
  node.sendNoReply = (to, proto, payload) => call(to, proto, payload, undefined, true);
  /** A request sent through the host's own door to the transport, as the embedder would, for
   *  a protocol the harness app does not claim: an app sends only under its own claims. */
  node.requestAsHost = async (to, proto, payload) => {
    const r = await shell.call(TRANSPORT_SERVICE, new OpArgs("send").u8(0)
      .blob(Buffer.from(to, "hex")).blob(enc.encode(proto)).blob(payload).build());
    if (r[0] !== 1) throw new Error("net: request failed");
    return r.slice(1);
  };
  node.app = app;
  /** Name an arbitrary transport op from the app, for the tests about the caller boundary
   *  (transport/src/core.js `APP_OPS`). Rejects when the transport refuses the name. */
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
  /** Who this node's app was told each inbound frame came from, in step with `seen`: the
   *  attribution the shell put in front of the payload, as hex. */
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

/** The host's own call into the transport, as the CLI makes it, so a test uses the real
 *  path. Throws when nothing claims the id (a node with no transport bundle). */
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

/** Add one peer to this node: where to reach it, and that peer's contact secret. It goes
 *  straight into the occupant's address book (the host keeps nothing), so a test that
 *  replaces the transport must add it again (§12.10). */
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

/** Whether `node` has an authenticated link to `peerHex` right now. Links are state in the
 *  transport guest, so this asks the guest. */
export async function linkedTo(node, peerHex) {
  return (await linkedPeers(node)).includes(peerHex);
}

/** Wait for a condition, with a deadline. The predicate is awaited, so an async one is
 *  polled on its resolved value; a bare promise would be truthy at once and make the wait
 *  a no-op. */
export async function until(fn, ms = 3000, what = "condition") {
  const start = Date.now();
  for (;;) {
    if (await fn()) return;
    if (Date.now() - start > ms) throw new Error("timeout waiting for " + what);
    await new Promise((r) => setTimeout(r, 2));
  }
}
