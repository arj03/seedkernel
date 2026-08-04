// The native loader's binding of the shared host core (README §12.9) — and the whole
// of it. The Go loader (native/) runs this inside QuickJS; it is bundled, together
// with every shared module it imports, into native/host-shell.gen.js by
// scripts/bundle-loader.mjs.
//
// This file is a SEAM, not an implementation. Go supplies platform *primitives* —
// a handler table over wazero, libsodium, an `fs` directory, TCP sockets, a second
// QuickJS realm — and this file adapts them to the interfaces the shared shell
// already consumes (`BundleHost`, `FreshnessStore`, `ChannelFactory`, `RealmFactory`,
// `ShellPlatform`) and hands the result to `createShell`. Everything above the
// primitives — which checks run and in what order (§12.4), who may install (§12.5),
// the name derivation (§5.1), the freshness arithmetic, the deny-all default (§14),
// how a cap-bridge is built for a bundle's declared domains (§12.2), which app a
// protocol is delivered to (§12.10) — comes from those shared modules.
//
// The ASSEMBLY ORDER is the point. It is the last thing two hosts could disagree
// about, so it is not restated here: `createShell` owns it, and this file only names
// the platform. Because it is TypeScript checked against those same interfaces, the
// drift a hand-written second assembly accumulates is now a compile error.
import { policyFromJson } from "./policy.js";
import { appKeyFor, verifyBundle, FreshnessMarks } from "./bundle.js";
import {
  createShell, type KernelBackend, type RealmFactory, type Shell, type ShellSodium,
} from "./shell-core.js";
import { TransportHost } from "./transport-host.js";
import { serializeCalls } from "./realm-queue.js";
import { FRAMING, type ChannelFactory, type Framing, type Identity, type RawLink, type TransportCrypto } from "../core/socket-seam.js";
import type { Fs } from "../core/fs.js";
import { parsePeerSpec } from "../core/socket-seam.js";
import { toHex, fromHex } from "../core/util.js";
// The artifact-shipped transport bundle (scripts/build-transport-bundle.mjs) —
// the signed program that IS the node's network (§12.6).
import { TRANSPORT_BUNDLE_B64 } from "./transport-bundle.js";

/** The guest→host seam Go calls into. A null return means the op parked: Go holds
 *  the guest's Promise under `callId` and settles it later through
 *  `bridge.realmSettle`, the same null-means-async contract safe-js.ts implements. */
type CapCall = (op: number, payload: ArrayBuffer, callId: number) => Uint8Array | null;

/** The handler table and realm plumbing Go exposes (main.go). */
declare const bridge: {
  bindAll(mods: { name: string; wasm: Uint8Array }[]): void;
  callHandler(name: string, payload: Uint8Array): ArrayBuffer | null;
  isBound(name: string): boolean;
  removePrefix(prefix: string): number;
  readFreshness(): string | null;
  writeFreshness(json: string): void;
  createRealm(source: string, capCall: CapCall, memoryLimitBytes: number, deadlineMs: number): number;
  realmCall(realm: number, entry: string, payload: Uint8Array,
            onOk: (bytes: Uint8Array) => void, onErr: (msg: string) => void): void;
  realmSettle(realm: number, callId: number, bytes: Uint8Array | null, err: string | null): void;
  realmDispose(realm: number): void;
};

/** libsodium, in libsodium-wrappers method names (native/sodium.go), plus the PQ
 *  half (native/mldsa.go) and the catalog's KEM (native/mlkem.go). Typed as the full
 *  surface the shared code consumes, so a Go shim that stops satisfying one of them
 *  fails the build rather than a handshake. */
declare const sodium: ShellSodium & TransportCrypto;

/** The `fs.*` primitive over Go's data directory (native/fs.go).
 *
 *  Declared with its real, **synchronous** shape: Go answers a read from the local disk
 *  in the call, and qjs has no promise primitive to hand back anyway. The seam the shared
 *  code consumes is async (`Fs`, core/fs.ts), so the adaptation happens here — which is
 *  the right place for it, because "this target's storage is synchronous" is exactly the
 *  kind of platform fact a shim exists to absorb. Go grows with primitives, never with
 *  logic; making it construct promises would be the latter. */
declare const __fs: {
  get(key: string): ArrayBuffer | null;
  put(key: string, bytes: Uint8Array): void;
  size(key: string): number;
  /** One `\n`-joined string, not an array: building a JS array on the Go side costs an
   *  engine call (plus a C string) per key, so a content store with tens of thousands of
   *  blocks paid tens of thousands of crossings per listing. A key may not contain `\n`
   *  (`fsKeyChars`), so the join is unambiguous. */
  list(prefix?: string): string;
  delete(key: string): boolean;
  stat(): { used: number; available: number };
};

/** The async `Fs` seam over that synchronous primitive: a get miss is null, a hit is a
 *  Uint8Array, and list's joined string becomes the string[].
 *
 *  `async` rather than `Promise.resolve(...)` so a throw from Go becomes a rejection like
 *  every other backend's, instead of a synchronous throw out of a method the caller
 *  awaits. */
// Exported so the native target's tests drive the SAME wrapper production does, rather
// than a second one in a test harness that could quietly disagree with it.
export const fs: Fs = {
  async get(key) { const r = __fs.get(key); return r === null ? null : new Uint8Array(r); },
  async put(key, bytes) { __fs.put(key, bytes); },
  async size(key) { return __fs.size(key); },
  // An empty listing arrives as "", which must map to [] — split would yield [""].
  async list(prefix) { const s = __fs.list(prefix); return s === "" ? [] : s.split("\n"); },
  async delete(key) { return __fs.delete(key); },
  async stat() { return __fs.stat(); },
};

/** Go's TCP socket primitive (native/sock.go): a raw byte duplex and nothing else.
 *  `listen` returns the bound port. This is the whole networking seam — the wire codec,
 *  the channel handshake, the routing table and the request/response layer above it are
 *  all the transport bundle's, over the same primitive every other target hands it.
 *
 *  A link arrives WITHOUT a `framing`: which codec applies follows from the address,
 *  which is this file's to read and never Go's. */
type GoLink = Omit<RawLink, "framing">;
declare function netConnectRaw(host: string, port: number): GoLink;
declare function netListenRaw(host: string, port: number, onAccept: (s: GoLink) => void): number;
declare function netCloseListeners(): void;

// ── The platform ─────────────────────────────────────────────────────────────
/** The §3 handler table, which on this target lives in Go (wazero instances cannot
 *  be JS values). Shape only — every rule about what may land is the shared loader's. */
const kernel: KernelBackend = {
    // Straight through: the all-or-none guarantee is Go's, because Go holds the
    // half-built wazero instances — and has to close them, since neither an instance nor
    // its compiled code is reclaimed on its own (main.go `bindAll`).
    bindAll(mods) { bridge.bindAll(mods); },
    callHandler(name, payload) {
        const r = bridge.callHandler(name, payload);
        return r === null ? null : new Uint8Array(r);
    },
    isBound(name) { return bridge.isBound(name); },
    removePrefix(prefix) { return bridge.removePrefix(prefix); },
};
/** The freshness store over the Go atomic-write seam (README §12.4). */
class NativeFreshnessStore extends FreshnessMarks {
    constructor() {
        super(bridge.readFreshness());
    }
    persist(json: string) { bridge.writeFreshness(json); }
}
/** Say which codec a Go socket carries. The bytes are Go's; the boundaries are the
 *  transport bundle's, and this is the one place that decides which rule it applies. */
function framed(link: GoLink, framing: Framing, authority?: string): RawLink {
    return { ...link, framing, authority };
}
/** This target's socket seam, backed by Go's sockets: the transport driver's
 *  ChannelFactory. connect/listen produce RawLinks identically to the node:net
 *  factory, so the transport bundle's link state machine — driven by TransportHost
 *  — runs over Go's primitives unchanged. */
const channels: ChannelFactory = {
    connect: (addr) => addr.transport === "ws"
        ? framed(netConnectRaw(addr.host, addr.port), FRAMING.WS_CLIENT, `${addr.host}:${addr.port}`)
        : framed(netConnectRaw(addr.host, addr.port), FRAMING.LENGTH),
    listen: (tcp, ws, onAccept) => Promise.resolve({
        port: tcp ? netListenRaw(tcp.host, tcp.port, (s) => onAccept(framed(s, FRAMING.LENGTH))) : 0,
        wsPort: ws ? netListenRaw(ws.host, ws.port, (s) => onAccept(framed(s, FRAMING.WS_SERVER))) : 0,
    }),
    // Close the bound listeners (and, in Go, their accept goroutines) on teardown.
    close: () => { netCloseListeners(); },
};
/** The artifact-shipped transport bundle, as raw bytes (transport-bundle.js). */
const embeddedTransport = (() => {
    try {
        const bin = atob(TRANSPORT_BUNDLE_B64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++)
            out[i] = bin.charCodeAt(i);
        return out;
    }
    catch {
        return null;
    }
})();
/** Who signed the transport this artifact ships — hex, DERIVED from the blob rather
 *  than restated anywhere. This is the id an operator pins as `roles.transport` in a
 *  policy file (§12.5), so a build with a different key needs a different entry and
 *  nothing has to be kept in step by hand. Empty if the artifact carries no transport. */
const embeddedTransportAuthor = (() => {
    if (!embeddedTransport)
        return "";
    try {
        return toHex(verifyBundle(sodium, embeddedTransport).author);
    }
    catch {
        return "";
    }
})();
/** This target's realm factory (§12.3): a second, zero-authority quickjs-ng realm
 *  driven by Go's event loop. safe-js.ts is the JS platform's answer to the same
 *  seam; both present the same `SafeRealm`, so the shell drives either.
 *
 *  The promise plumbing stays here rather than in Go: `capCall` closes over this
 *  realm, so a settled net op routes to the realm that parked it structurally, and
 *  an initiator's result is delivered into a Promise built in plain ECMAScript. Go
 *  needs no promise primitive of its own. */
// `deadlineMs` crosses as milliseconds with two sentinel encodings, because the bridge
// carries numbers and not `undefined`/`Infinity`: 0 means "the target's default" (matching
// how memoryLimitBytes is read on the Go side) and a negative value means Infinity — no
// budget, said explicitly rather than reached by omission.
//
// Note the native realm does NOT enforce this through QuickJS: New_QJS's maxExecutionTime
// argument is inert in the vendored qjs.wasm (a 1 ms limit does not interrupt a spinning
// loop), so guest.go arms a wazero deadline instead. That makes a budget kill fatal to the
// realm rather than a catchable JS error — see qjs.Runtime.Budget.
const createRealm: RealmFactory = async ({ source, bridge: capBridge, memoryLimitBytes, deadlineMs }) => {
    // Assigned before any guest code can call back: bridge.createRealm evaluates the
    // guest, whose top-level can only reach sync ops (a Promise it could not await).
    let realm: number;
    const capCall: CapCall = (op, payload, callId) => {
        const r = capBridge(op, new Uint8Array(payload)) as Uint8Array | Promise<Uint8Array> | null;
        if (!r || typeof (r as Promise<Uint8Array>).then !== "function")
            return r as Uint8Array;
        (r as Promise<Uint8Array>).then((bytes: Uint8Array) => bridge.realmSettle(realm, callId, bytes, null), (e: unknown) => bridge.realmSettle(realm, callId, null, String((e as Error)?.message ?? e)));
        return null;
    };
    realm = bridge.createRealm(source, capCall, memoryLimitBytes ?? 0, deadlineMs === undefined ? 0 : (deadlineMs === Infinity ? -1 : deadlineMs));
    let disposed = false;
    return {
        // Serialized here, in the shared TS, rather than in Go: the guarantee is the
        // realm contract's (realm-queue.ts) and one implementation of it is what keeps
        // the two targets from differing about when a second entrypoint may begin. Go
        // grows with primitives, never with logic.
        call: serializeCalls(
            (entry: string, payload: Uint8Array) => new Promise((resolve, reject) => {
                bridge.realmCall(realm, entry, payload, (bytes: Uint8Array) => resolve(new Uint8Array(bytes)), (msg: string) => reject(new Error(msg)));
            }),
            () => (disposed ? new Error("guest realm disposed") : null),
        ),
        dispose: () => { disposed = true; bridge.realmDispose(realm); },
    };
};
/** Everything that crosses back to Go crosses as BYTES — that is the currency of this
 *  seam (host.call, callHandler, a realm result), and the one shape Go's await harness
 *  carries out of a settled promise. A JSON report is no exception. */
const utf8 = new TextEncoder();
let shell: Shell | null = null;
/** The admission predicate in force (§12.5). It starts deny-all — the realm boots
 *  refusing everything, so the absence of a decision is never permission (README §14)
 *  — and `--policy` replaces it at boot. The shell closes over this indirection rather
 *  than over a fixed predicate, so an operator can narrow or widen trust without
 *  restarting the node; the rules themselves are entirely policy.ts's. */
let admitPredicate = policyFromJson(null);
/** Point the realm at a policy config (§12.5). `null` restores the deny-all default;
 *  malformed JSON throws, so a typo fails loudly rather than silently widening trust. */
function setPolicy(json: string | null): void {
    admitPredicate = policyFromJson(json);
}
/** The one shell, or a clear error if Go asked for something before booting one. */
function theShell() {
    if (!shell)
        throw new Error("native: bootNode has not run");
    return shell;
}
/** Stand a node up on this platform: a shell, the transport bundle admitted under
 *  the policy in force, and its listeners bound. Returns the shell and the driver
 *  that IS its network.
 *
 *  There is one of these and everything uses it — `bootNode` below, and a native test
 *  that needs a second endpoint in the process. That is deliberate: a test standing a
 *  node up some other way is the second assembly this target exists not to have
 *  (§12.9), and the last time the two diverged the drift did not fail to compile, it
 *  surfaced as a network timeout. The config is an OBJECT for the same reason — a
 *  positional signature drifting against a Go harness string is a silent break. */
async function makeTransportNode(cfg: {
    identity: Identity;
    contactSecret?: Uint8Array;
    listen?: {
        host: string;
        port: number;
    };
    wsListen?: {
        host: string;
        port: number;
    };
    requestDeadlineMs?: number;
    config?: Record<string, string | number>;
}): Promise<{
    shell: Shell;
    net: TransportHost;
}> {
    const s = createShell({
        platform: {
            sodium, identity: cfg.identity, kernel, fs,
            freshnessStore: new NativeFreshnessStore(),
            channels, listen: cfg.listen, wsListen: cfg.wsListen,
            contactSecret: cfg.contactSecret, createRealm,
        },
        admit: (v) => admitPredicate(v),
        requestDeadlineMs: cfg.requestDeadlineMs,
        config: cfg.config,
    });
    // The transport bundle IS the node's network: verify + govern under policy
    // (roles.transport), install, and the shell stands the driver up. A policy that
    // does not admit the transport author leaves the node without a network.
    if (embeddedTransport) {
        try {
            await s.loadBundleBlob(embeddedTransport);
        }
        catch (err) {
            if (String((err as Error).message).includes("rejected by admission predicate")) {
                // A deliberate configuration: this node does not speak to anyone.
            }
            else {
                throw err;
            }
        }
    }
    const net = s.net as unknown as TransportHost;
    if (net instanceof TransportHost)
        await net.start();
    return { shell: s, net };
}
/** Stand THE node up and keep it: identity, the transport bundle, the shared shell.
 *  Resolves once the listeners are bound and any cohort peers have been dialled, so
 *  Go can print the real ports. */
async function bootNode(cfgJson: string): Promise<Uint8Array> {
    const cfg = JSON.parse(cfgJson);
    const sk = fromHex(cfg.keyHex);
    const identity = { privateKey: sk, publicKey: sk.slice(32) };
    setPolicy(cfg.policyJson);
    const { shell: s, net: network } = await makeTransportNode({
        identity,
        contactSecret: cfg.contactSecretHex ? fromHex(cfg.contactSecretHex) : undefined,
        listen: cfg.listen,
        wsListen: cfg.wsListen,
        requestDeadlineMs: cfg.requestDeadlineMs,
        config: cfg.config,
    });
    shell = s;
    if (network instanceof TransportHost) {
        for (const spec of cfg.peers ?? []) {
            const { peerId, addr } = parsePeerSpec(spec, "tcp");
            network.addPeerAddr(peerId, addr);
        }
        // Best-effort: ready() resolves on its own timeout rather than rejecting, so a
        // cohort member that is not up yet delays the boot but never fails it.
        if (cfg.peers && cfg.peers.length > 0)
            await network.ready();
    }
    const status = {
        peerId: toHex(identity.publicKey), port: network.port, wsPort: network.wsPort,
    };
    return utf8.encode(JSON.stringify(status));
}
/** Load a signed bundle (README §12.4). Go has read the one file — that is the whole
 *  fs seam — and passes its bytes; every check, its order, and the module binding are
 *  the shared shell's. Returns the little Go needs to report; the guest source, the
 *  caps, the signing scope and the kernel names never leave this realm. */
async function loadBundleBlob(blob: ArrayBuffer): Promise<Uint8Array> {
    const b = await theShell().loadBundleBlob(new Uint8Array(blob));
    return utf8.encode(JSON.stringify({
        app: b.manifest.app,
        version: b.manifest.version,
        author: toHex(b.author),
        // The protocols this app actually ended up serving (§12.10) — auto-bound inside
        // loadBundleBlob, so this reports what happened rather than what was declared.
        // For the operator's console line and nothing else.
        handles: theShell().bindings.boundProtocols(appKeyFor(b.author, b.manifest.app)),
    }));
}
/** Run a loaded bundle's guest entrypoint as the *initiator* (§12.8) — the
 *  `--put` / `--get` one-shots. Arguments and results cross as raw bytes. */
function runGuest(entry: string, arg: ArrayBuffer): Promise<Uint8Array> {
    return theShell().runGuest(entry, new Uint8Array(arg));
}
/** Serve the cohort: route inbound requests to whichever installed app the
 *  protocol is bound to (§12.10), through the shared dispatch. */
function serve(): Promise<void> {
    return theShell().serve();
}
/** Uninstall one app by its app key (§12.5). Returns the boolean JSON-encoded, not
 *  raw: the realm bridge marshals only `Uint8Array`/`ArrayBuffer` results and turns
 *  anything else into zero bytes (native/loop.go `awaitIn`), so a bare `false` would
 *  reach Go as an empty buffer and read as success. Encode it. */
function uninstall(appKey: string): Uint8Array {
    return utf8.encode(JSON.stringify(theShell().uninstall(appKey)));
}
/** Write off a compromised author key (§12.5): refuse everything it signs from here
 *  on, and tear down every app of its already running. Returns the app keys removed,
 *  JSON-encoded, for the operator's console line.
 *
 *  Exposed for the same reason `loadBundleBlob` is: the decision and the state are
 *  the shared shell's, and Go owns only the CLI surface and the durable write. A
 *  native loader that could install but never revoke would leave §12.5's remedy
 *  reachable on some targets and not others. */
function revoke(authorHex: string): Uint8Array {
    return utf8.encode(JSON.stringify(theShell().revoke(authorHex)));
}
// What Go reaches by name in the realm. `createRealm` and the transport bundle
// helpers are here as much for the native tests as for the boot above: a test that
// stands up a guest or a second node drives the very factories production does, so
// there is no test-only wiring to keep in step with the real one.
export { bootNode, setPolicy, loadBundleBlob, runGuest, serve, uninstall, revoke, createRealm, embeddedTransport, embeddedTransportAuthor, makeTransportNode, };
