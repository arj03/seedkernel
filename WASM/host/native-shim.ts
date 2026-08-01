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

import { policyFromJson, type AdmitPredicate } from "./policy.js";
import { appKeyFor, FreshnessMarks } from "./bundle.js";
import {
  createShell, type KernelBackend, type RealmFactory, type Shell, type ShellSodium,
} from "./shell-core.js";
import { NodeNetworkCore, parsePeerSpec, type ChannelFactory } from "./net-route.js";
import { WsClientChannel, WsServerChannel, type RawByteStream } from "./net-frame.js";
import { setWsHandle } from "./ws/ws-codec.js";
import type { Identity, RawChannel, TransportCrypto } from "./net-link.js";
import type { SafeRealm } from "./safe-js.js";
import type { Fs } from "./fs.js";
import { toHex, fromHex } from "./util.js";

// ── The Go seam ──────────────────────────────────────────────────────────────

/** The byte-level powers the Go loader exposes into the realm (native/main.go).
 *  Only the host powers QuickJS genuinely cannot reach: compile and hold wasm,
 *  write a file atomically, and stand up a second (zero-authority) realm.
 *  Everything else on this page is JS. */
declare const bridge: {
  /** Compile + instantiate handler bytes against the §4 ABI. Returns an opaque token
   *  for a later bindWasm; throws on structural failure. No table effect. */
  instantiateWasm(wasm: Uint8Array): unknown;
  /** Bind a pre-instantiated handler token at `name` on the handler table. */
  bindWasm(name: string, token: unknown): void;
  /** Release a handler token that will never be bound (the bundle failed). */
  discardWasm(token: unknown): void;
  /** Invoke a bound handler (§4). null when the name is unbound or it produced nothing. */
  callHandler(name: string, payload: Uint8Array): ArrayBuffer | null;
  isBound(name: string): boolean;
  /** Unbind every handler whose name starts with `prefix`; returns how many went. */
  removePrefix(prefix: string): number;
  /** The persisted freshness store's contents, or null on first boot. */
  readFreshness(): string | null;
  /** Write the freshness store atomically (temp file + rename). */
  writeFreshness(json: string): void;

  // ── the confined realm (§12.3), Go's twin of safe-js.ts ──
  /** Stand up a zero-authority QuickJS realm running `source`, with the guest's
   *  single `host.call` seam funnelled into `capCall`. Returns an opaque handle. */
  createRealm(source: string, capCall: CapCall, memoryLimitBytes: number, deadlineMs: number): unknown;
  /** Invoke an entrypoint as the *initiator*: it may await net, so the result comes
   *  back through `onDone`/`onFail` rather than as a return value. */
  realmCall(
    realm: unknown, entry: string, payload: Uint8Array,
    onDone: (bytes: ArrayBuffer) => void, onFail: (msg: string) => void,
  ): void;
  /** Invoke an entrypoint synchronously — the holder request side (§12.8). */
  realmCallSync(realm: unknown, entry: string, payload: Uint8Array): ArrayBuffer;
  /** Settle a parked net op in `realm`: `bytes` fulfils it, `msg` rejects it. */
  realmSettle(realm: unknown, callId: number, bytes: Uint8Array | null, msg: string | null): void;
  realmDispose(realm: unknown): void;
};

/** What Go calls for every `host.call` a guest makes. A sync op (crypto/fs/clock/
 *  module) returns its bytes here; a net op genuinely round-trips, so it returns
 *  null — Go leaves the guest's Promise parked under `callId` — and is settled later
 *  through `bridge.realmSettle`. The same null-means-async contract safe-js.ts's
 *  host function implements, so one guest preamble serves both targets.
 *  The payload arrives as a bare ArrayBuffer: that is the Go seam's currency, and
 *  the view the cap-bridge wants is made here rather than in Go. */
type CapCall = (op: number, payload: ArrayBuffer, callId: number) => Uint8Array | null;

/** libsodium, in libsodium-wrappers method names (native/sodium.go). Typed as the
 *  full surface the shared code consumes — the loader's verifier and hasher, the
 *  cap-bridge's crypto ops, and the §12.6 channel AKE — so a Go shim that stops
 *  satisfying one of them fails the build rather than a handshake. */
declare const sodium: ShellSodium & TransportCrypto;

/** The `fs.*` backend over Go's data directory (native/fs.go). */
declare const fs: Fs;

/** ws.wasm over wazero (native/wsframe.go): the same RFC 6455 byte transform the
 *  browser/Node targets drive, reached through the codec's one backend seam. */
declare const __ws: { handle(req: Uint8Array): ArrayBuffer };

/** Go's TCP socket primitive as RawChannels / raw byte duplexes (native/sock.go).
 *  `listen` returns the bound port. This is the whole networking seam: the PeerLink
 *  handshake, the routing table and the request/response Transport above it are the
 *  shared TS, unchanged. */
declare function netConnect(host: string, port: number): RawChannel;
declare function netConnectRaw(host: string, port: number): RawByteStream;
declare function netListen(host: string, port: number, onAccept: (ch: RawChannel) => void): number;
declare function netListenRaw(host: string, port: number, onAccept: (s: RawByteStream) => void): number;
declare function netCloseListeners(): void;

// The codec's backend, installed once for the realm. Node/browser install a
// WebAssembly backend; here it is the identical ws.wasm driven over wazero, so
// framing is byte-identical across targets.
setWsHandle((req) => new Uint8Array(__ws.handle(req)));

// ── The platform ─────────────────────────────────────────────────────────────

/** The §3 handler table, which on this target lives in Go (wazero instances cannot
 *  be JS values). Shape only — every rule about what may land is the shared loader's. */
const kernel: KernelBackend = {
  instantiateWasm(wasm: Uint8Array): unknown { return bridge.instantiateWasm(wasm); },
  bindHandler(name: string, ref: unknown): void { bridge.bindWasm(name, ref); },
  discardHandler(ref: unknown): void { bridge.discardWasm(ref); },
  callHandler(name: string, payload: Uint8Array): Uint8Array | null {
    const r = bridge.callHandler(name, payload);
    return r === null ? null : new Uint8Array(r);
  },
  isBound(name: string): boolean { return bridge.isBound(name); },
  removePrefix(prefix: string): number { return bridge.removePrefix(prefix); },
};

/** The freshness store over the Go atomic-write seam (README §12.4). */
class NativeFreshnessStore extends FreshnessMarks {
  constructor() {
    super(bridge.readFreshness());
  }
  protected override persist(json: string): void { bridge.writeFreshness(json); }
}

/** WebSocket RawChannels over Go's raw byte streams: the node-dialing-a-WS-endpoint
 *  and node-accepting-a-browser sides, framed by the shared net-frame classes. The
 *  browser uses its platform WebSocket instead; this is the same codec either way. */
function netConnectWS(host: string, port: number): RawChannel {
  return new WsClientChannel(netConnectRaw(host, port), host, port, sodium);
}
function netListenWS(host: string, port: number, onAccept: (ch: RawChannel) => void): number {
  return netListenRaw(host, port, (stream) => onAccept(new WsServerChannel(stream)));
}

/** The routing core's one platform seam, backed by Go's sockets. connect/listen
 *  produce RawChannels identically to the node:net factory, so NodeNetworkCore —
 *  the address book, the dialing, the link pool — runs unchanged. */
const channels: ChannelFactory = {
  connect: (addr) => addr.transport === "ws"
    ? netConnectWS(addr.host, addr.port)
    : netConnect(addr.host, addr.port),
  listen: (tcp, ws, onAccept) => Promise.resolve({
    port: tcp ? netListen(tcp.host, tcp.port, onAccept) : 0,
    wsPort: ws ? netListenWS(ws.host, ws.port, onAccept) : 0,
  }),
  // Close the bound listeners (and, in Go, their accept goroutines) on teardown.
  close: () => { netCloseListeners(); },
};

/** This target's Network: the shared routing core over the Go channel factory.
 *  Exported because the native tests stand up two of them in one realm. */
function makeNetwork(
  identity: Identity,
  listen?: { host: string; port: number },
  wsListen?: { host: string; port: number },
): NodeNetworkCore {
  return new NodeNetworkCore({ identity, sodium, channels, listen, wsListen });
}

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
const createRealm: RealmFactory = async ({ source, bridge: capBridge, memoryLimitBytes, deadlineMs }): Promise<SafeRealm> => {
  // Assigned before any guest code can call back: bridge.createRealm evaluates the
  // guest, whose top-level can only reach sync ops (a Promise it could not await).
  let realm: unknown;
  const capCall: CapCall = (op, payload, callId) => {
    const r = capBridge(op, new Uint8Array(payload));
    if (!r || typeof (r as Promise<Uint8Array>).then !== "function") return r as Uint8Array;
    (r as Promise<Uint8Array>).then(
      (bytes) => bridge.realmSettle(realm, callId, bytes, null),
      (e) => bridge.realmSettle(realm, callId, null, String((e && (e as Error).message) || e)),
    );
    return null;
  };
  realm = bridge.createRealm(source, capCall, memoryLimitBytes ?? 0,
    deadlineMs === undefined ? 0 : (deadlineMs === Infinity ? -1 : deadlineMs));
  return {
    call: (entry, payload) => new Promise<Uint8Array>((resolve, reject) => {
      bridge.realmCall(realm, entry, payload,
        (bytes) => resolve(new Uint8Array(bytes)),
        (msg) => reject(new Error(msg)));
    }),
    callSync: (entry, payload) => new Uint8Array(bridge.realmCallSync(realm, entry, payload)),
    dispose: () => { bridge.realmDispose(realm); },
  };
};

// ── The entry points Go drives ───────────────────────────────────────────────

/** Everything the operator chose, forwarded from Go's CLI flags as one JSON object
 *  — so the flag surface is parsed once, in Go, and the assembly reads it as data
 *  rather than as spliced-together JS. */
interface BootConfig {
  /** allowed-keys.json contents, or null for the deny-all default (README §14). */
  policyJson: string | null;
  /** This node's 64-byte Ed25519 secret key, hex (libsodium sk = seed‖pk). */
  keyHex: string;
  listen?: { host: string; port: number };
  wsListen?: { host: string; port: number };
  /** Cohort peers to dial, as `pk@host:port`. The network owns connectivity. */
  peers?: string[];
  /** net.send timeout in ms (how long before a peer is treated unreachable). */
  timeoutMs?: number;
  /** Operator app config, merged *over* the bundle manifest's `config`. */
  config?: Record<string, string | number>;
}

/** What a boot reports back: who we are and what we actually bound. */
interface NodeStatus { peerId: string; port: number; wsPort: number; }

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
let admitPredicate: AdmitPredicate = policyFromJson(null);

/** Point the realm at a policy config (§12.5). `null` restores the deny-all default;
 *  malformed JSON throws, so a typo fails loudly rather than silently widening trust. */
function setPolicy(json: string | null): void {
  admitPredicate = policyFromJson(json);
}

/** The one shell, or a clear error if Go asked for something before booting one. */
function theShell(): Shell {
  if (!shell) throw new Error("native: bootNode has not run");
  return shell;
}

/** Stand the node up: identity, network, then the shared shell over this platform.
 *  Resolves once the listeners are bound and any cohort peers have been dialled, so
 *  Go can print the real ports. */
async function bootNode(cfgJson: string): Promise<Uint8Array> {
  const cfg = JSON.parse(cfgJson) as BootConfig;
  const sk = fromHex(cfg.keyHex);
  const identity: Identity = { privateKey: sk, publicKey: sk.slice(32) };

  const network = makeNetwork(identity, cfg.listen, cfg.wsListen);
  await network.start();
  for (const spec of cfg.peers ?? []) {
    const { peerId, addr } = parsePeerSpec(spec, "tcp");
    network.addPeerAddr(peerId, addr);
  }
  // Best-effort: ready() resolves on its own timeout rather than rejecting, so a
  // cohort member that is not up yet delays the boot but never fails it.
  if (cfg.peers && cfg.peers.length > 0) await network.ready();

  setPolicy(cfg.policyJson);
  shell = createShell({
    platform: {
      sodium, identity, kernel, fs,
      freshnessStore: new NativeFreshnessStore(),
      network, createRealm,
    },
    admit: (v) => admitPredicate(v),
    timeoutMs: cfg.timeoutMs,
    config: cfg.config,
  });
  const status: NodeStatus = {
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

// What Go reaches by name in the realm. `createRealm` and `makeNetwork` are here as
// much for the native tests as for the boot above: a test that stands up a guest or
// a second node drives the very factories production does, so there is no test-only
// wiring to keep in step with the real one.
export {
  bootNode, setPolicy, loadBundleBlob, runGuest, serve,
  createRealm, makeNetwork, netConnectWS, netListenWS,
};
