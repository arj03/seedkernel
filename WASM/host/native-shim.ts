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
import { FRAMING, type ChannelFactory, type Framing, type RawLink } from "../core/socket-seam.js";
import type { Keypair } from "../core/subkeys.js";
import { deriveNodeKeys } from "../core/subkeys.js";
import { FS_AVAILABLE_UNKNOWN, type Fs } from "../core/fs.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_REALM_MEMORY_BYTES, DEFAULT_SCRATCH_SIZE } from "../core/wasm-limits.js";
import { parsePeerSpec } from "./transport-host.js";
import { toHex, fromHex, fromBase64, errMessage } from "../core/util.js";
import { isAdmissionRejected } from "./shell-core.js";
// The artifact-shipped transport bundle (scripts/build-transport-bundle.mjs) —
// the signed program that IS the node's network (§12.6).
import { TRANSPORT_BUNDLE_B64 } from "./transport-bundle.js";

/** The guest→host seam Go calls into. A null return means the call parked: Go holds
 *  the guest's Promise under `callId` and settles it later through
 *  `bridge.realmSettle` — the same null-means-async contract safe-js.ts implements.
 *  A sync name returns its bytes here instead. */
type CapCall = (name: string, payload: ArrayBuffer, callId: number) => Uint8Array | null;

/** The handler table and realm plumbing Go exposes (main.go). */
declare const bridge: {
  bindAll(appKey: string, mods: { name: string; wasm: Uint8Array }[], scratchDefault: number): void;
  callModule(appKey: string, module: string, payload: Uint8Array): ArrayBuffer | null;
  isBound(appKey: string, module: string): boolean;
  removeApp(appKey: string): number;
  readFreshness(): string | null;
  writeFreshness(json: string): void;
  createRealm(source: string, capCall: CapCall, memoryLimitBytes: number, deadlineMs: number): number;
  realmCall(realm: number, entry: string, payload: Uint8Array,
            onOk: (bytes: Uint8Array) => void, onErr: (msg: string) => void): void;
  realmSettle(realm: number, callId: number, bytes: Uint8Array | null, err: string | null): void;
  realmDispose(realm: number): void;
};

/** Go's raw crypto primitives (native/sodium.go, plus native/mldsa.go and
 *  native/mlkem.go on the same object). Bytes come back as ArrayBuffers and a failure
 *  comes back as `null`, because that is what the bridge can carry — every method here
 *  is one wazero or Go call and nothing more.
 *
 *  `crypto_generichash` takes its optional key so the native blake2b shim can REFUSE a
 *  keyed hash loudly; dropping the argument here would turn a MAC into a plain hash. */
declare const __sodium: {
  crypto_generichash(hashLength: number, message: Uint8Array, key?: Uint8Array | null): ArrayBuffer;
  crypto_stream_xchacha20_xor(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): ArrayBuffer;
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): ArrayBuffer;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  crypto_scalarmult(sk: Uint8Array, pk: Uint8Array): ArrayBuffer | null;
  /** libsodium-wrappers' signature is (message, ad, nsec, npub, key); the record layer
   *  uses no additional data, so the native primitive takes just (m, npub, key). */
  crypto_aead_chacha20poly1305_ietf_encrypt(message: Uint8Array, npub: Uint8Array, key: Uint8Array): ArrayBuffer;
  crypto_aead_chacha20poly1305_ietf_decrypt(ciphertext: Uint8Array, npub: Uint8Array, key: Uint8Array): ArrayBuffer | null;
  crypto_sign_keypair(): { publicKey: ArrayBuffer; privateKey: ArrayBuffer };
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: ArrayBuffer; privateKey: ArrayBuffer };
  randombytes_buf(n: number): ArrayBuffer;
  ml_dsa65_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  ml_kem768_keypair_from_seed(seed: Uint8Array): { publicKey: ArrayBuffer; privateKey: ArrayBuffer };
  ml_kem768_encaps(pk: Uint8Array, coins: Uint8Array): { ciphertext: ArrayBuffer; sharedSecret: ArrayBuffer } | null;
  ml_kem768_decaps(sk: Uint8Array, ct: Uint8Array): ArrayBuffer | null;
};

/** The crypto surface this target serves: everything the shared code consumes
 *  (`ShellSodium`), plus the two keypair producers a node's identity comes out of
 *  (`SubkeyCrypto`, core/subkeys.ts, is the narrower of the two).
 *
 *  `crypto_generichash` is restated with its key OPTIONAL, which is what satisfies both
 *  halves of `ShellSodium` at once: the loader calls it with an explicit `null` key and
 *  the cap-bridge calls it with two arguments. */
export interface NativeSodium extends ShellSodium {
  crypto_generichash(hashLength: number, message: Uint8Array, key?: Uint8Array | null): Uint8Array;
  crypto_sign_keypair(): Keypair;
  crypto_sign_seed_keypair(seed: Uint8Array): Keypair;
}

/** libsodium, in libsodium-wrappers method names, over Go's primitives: Uint8Array
 *  results, `{publicKey, privateKey}` keypairs, and a throw where the wrappers throw.
 *
 *  **This adaptation is here rather than in Go**, where it used to be a JS string
 *  literal (`sodiumShimJS`). It is ordinary shaping code — the kind that must be
 *  identical on every target — and as a string it was the one part of the seam
 *  TypeScript never saw: the `ShellSodium` annotation below was an assertion about a
 *  Go constant rather than a check of it. Now a primitive that stops satisfying the
 *  surface fails the build, which is what the annotation always claimed. Go keeps the
 *  byte primitives and nothing else.
 *
 *  `null` means different things on the two halves and both are preserved: libsodium's
 *  wrappers throw on a failed open or a bad scalarmult, while ML-KEM's `null` is a
 *  *rejection* the caller must be able to read (a key failing FIPS 203's checks), so it
 *  is passed through. */
function wrapNativeSodium(N: typeof __sodium): NativeSodium {
  const u8 = (b: ArrayBuffer) => new Uint8Array(b);
  const kp = (k: { publicKey: ArrayBuffer; privateKey: ArrayBuffer }): Keypair =>
    ({ publicKey: u8(k.publicKey), privateKey: u8(k.privateKey) });
  return {
    crypto_generichash: (len: number, m: Uint8Array, key?: Uint8Array | null) => u8(N.crypto_generichash(len, m, key)),
    crypto_stream_xchacha20_xor: (m, nonce, key) => u8(N.crypto_stream_xchacha20_xor(m, nonce, key)),
    crypto_sign_detached: (m, sk) => u8(N.crypto_sign_detached(m, sk)),
    crypto_sign_verify_detached: (sig, m, pk) => N.crypto_sign_verify_detached(sig, m, pk),
    ml_dsa65_verify_detached: (sig, m, pk) => N.ml_dsa65_verify_detached(sig, m, pk),
    crypto_scalarmult: (sk, pk) => {
      const r = N.crypto_scalarmult(sk, pk);
      if (r === null) throw new Error("crypto_scalarmult: unexpected result of the multiplication");
      return u8(r);
    },
    crypto_aead_chacha20poly1305_ietf_encrypt: (m, _ad, _nsec, npub, key) =>
      u8(N.crypto_aead_chacha20poly1305_ietf_encrypt(m, npub, key)),
    crypto_aead_chacha20poly1305_ietf_decrypt: (_nsec, c, _ad, npub, key) => {
      const r = N.crypto_aead_chacha20poly1305_ietf_decrypt(c, npub, key);
      if (r === null) throw new Error("crypto_aead_chacha20poly1305_ietf_decrypt: verification failed");
      return u8(r);
    },
    crypto_sign_keypair: () => kp(N.crypto_sign_keypair()),
    crypto_sign_seed_keypair: (seed) => kp(N.crypto_sign_seed_keypair(seed)),
    randombytes_buf: (n) => u8(N.randombytes_buf(n)),
    ml_kem768_keypair_from_seed: (seed) => kp(N.ml_kem768_keypair_from_seed(seed)),
    ml_kem768_encaps: (pk, coins) => {
      const r = N.ml_kem768_encaps(pk, coins);
      return r === null ? null : { ciphertext: u8(r.ciphertext), sharedSecret: u8(r.sharedSecret) };
    },
    ml_kem768_decaps: (sk, ct) => {
      const r = N.ml_kem768_decaps(sk, ct);
      return r === null ? null : u8(r);
    },
  };
}

/** The one `sodium` this target has. Exported — and published as a global by the loader
 *  bundle — so the native tests drive the same wrapper production does, for the reason
 *  `fs` below is exported: a second shaping in a harness is a second thing to keep in
 *  step. Built at module scope because `embeddedTransportAuthor` verifies a bundle with
 *  it further down this file. */
export const sodium: NativeSodium = wrapNativeSodium(__sodium);

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
   *  (`isSafeFsKey`, core/fs.ts), so the join is unambiguous. */
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
  // Go answers -1 when it cannot ask the OS for free space; the sentinel is the
  // seam's (core/fs.ts), so the value a guest reads cannot differ by backend.
  async stat() { const s = __fs.stat(); return { used: s.used, available: s.available === -1 ? FS_AVAILABLE_UNKNOWN : s.available }; },
};

/** Go's socket byte primitives (native/sock.go): a raw byte duplex and nothing else.
 *  `listen` returns the bound port. This is the whole networking seam — the wire codec,
 *  the channel handshake, the routing table and the request/response layer above it are
 *  all the transport bundle's, over the same primitive every other target hands it.
 *
 *  A link arrives WITHOUT a `framing`: which codec applies follows from the address,
 *  which is this file's to read and never Go's. */
type GoLink = Omit<RawLink, "framing">;
declare const __net: {
  /** Open an outbound byte duplex. The id is never 0, and the channel buffers
   *  pre-connect sends, so JS can write the transport's HELLO immediately. */
  connect(host: string, port: number): number;
  /** Bind a listener; returns the bound port, or -1 on failure. */
  listen(host: string, port: number): number;
  /** Queue bytes for the writer goroutine (never blocks the loop goroutine). */
  send(id: number, bytes: Uint8Array): void;
  /** A deliberate close — never fires `__netClosed` (Go closes silently). */
  close(id: number): void;
  closeListeners(): void;
};

// ── the RawLink shaping — ex sock.go's `netShimJS` string ────────────────────
//
// Go's byte-level `__net` becomes the RawLink objects below, and Go's socket
// reader goroutines route deliveries through the three dispatchers defined at the
// end of this block. The dispatchers used to be a JS string literal in Go (the
// `netShimJS` constant), evaluated before the shared bundle loaded so Go could
// retain them early; they are typed TS now, and Go picks them up AFTER the bundle
// evaluates (main.go boot: exposeNet → eval host-shell.gen.js → netHost.retain) —
// the deferred retention is what lets the shaping live where TypeScript sees it.

/** Channel table + accept registry, keyed by Go's socket ids / bound ports. */
const netChans = new Map<number, { deliver: (bytes: Uint8Array) => void; closed: () => void }>();
const netAccepts = new Map<number, (id: number) => void>();

/** One RawLink (core/socket-seam.ts), minus its framing: Go vends one socket kind
 *  and this file says which codec runs over it. */
function makeGoLink(id: number): GoLink {
  let onData: (bytes: Uint8Array) => void = () => {};
  let onClose: () => void = () => {};
  netChans.set(id, {
    deliver: (bytes) => onData(bytes),
    closed: () => { netChans.delete(id); onClose(); },
  });
  return {
    send: (bytes) => __net.send(id, bytes),
    onData: (cb) => { onData = cb; },
    onClose: (cb) => { onClose = cb; },
    // A deliberate close never fires __netClosed (Go closes silently), so drop our own
    // map entry here too — otherwise every local close leaks a chans entry unbounded
    // (the mirror of the guard in native/sock.go's close()).
    close: () => { __net.close(id); netChans.delete(id); },
  };
}

function netConnectRaw(host: string, port: number): GoLink {
  return makeGoLink(__net.connect(host, port));
}

function netListenRaw(host: string, port: number, onAccept: (s: GoLink) => void): number {
  const bound = __net.listen(host, port);
  if (bound < 0) throw new Error("netListenRaw: bind failed");
  netAccepts.set(bound, (id) => onAccept(makeGoLink(id)));
  return bound;
}

function netCloseListeners(): void {
  __net.closeListeners();
  // Teardown closes every bound listener in Go, so every accept closure here is
  // stale — clear them too, or they pin their onAccept graphs for the process
  // lifetime in a long-lived holder that re-serves.
  netAccepts.clear();
}

declare global {
  /** A socket read landed — routes to the channel's onData (sock.go). */
  var __netDeliver: (id: number, bytes: ArrayBuffer) => void;
  /** A channel's fail path fired — the RawLink's onClose (sock.go). */
  var __netClosed: (id: number) => void;
  /** An accepted socket landed — routes to the port's accept closure (sock.go). */
  var __netAccept: (port: number, id: number) => void;
}

// Defined at module scope — i.e. when host-shell.gen.js is evaluated, after Go has
// installed `__net` — and retained by Go once the bundle is up (netHost.retain).
globalThis.__netDeliver = (id, bytes) => { const c = netChans.get(id); if (c) c.deliver(new Uint8Array(bytes)); };
globalThis.__netClosed = (id) => { const c = netChans.get(id); if (c) c.closed(); };
globalThis.__netAccept = (port, id) => { const a = netAccepts.get(port); if (a) a(id); };

// ── The platform ─────────────────────────────────────────────────────────────
/** The §3 handler table, which on this target lives in Go (wazero instances cannot
 *  be JS values). Shape only — every rule about what may land is the shared loader's. */
const kernel: KernelBackend = {
    // Straight through: the all-or-none guarantee is Go's, because Go holds the
    // half-built wazero instances — and has to close them, since neither an instance nor
    // its compiled code is reclaimed on its own (main.go `bindAll`). The §4.1 scratch
    // default crosses with it: it is the shared host's number (core/wasm-limits.ts),
    // so Go's table never owns a copy of the default the JS table enforces.
    bindAll(appKey, mods) { bridge.bindAll(appKey, mods, DEFAULT_SCRATCH_SIZE); },
    callModule(appKey, module, payload) {
        const r = bridge.callModule(appKey, module, payload);
        return r === null ? null : new Uint8Array(r);
    },
    isBound(appKey, module) { return bridge.isBound(appKey, module); },
    removeApp(appKey) { return bridge.removeApp(appKey); },
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
        return fromBase64(TRANSPORT_BUNDLE_B64);
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
// The shell resolves both resource bounds to the shared defaults (core/wasm-limits.ts)
// before calling — see shell-core's `ensureRealm` — so `memoryLimitBytes` here is a
// real number or the same shared default for a direct caller, never "0 means default".
// `deadlineMs` crosses with one sentinel encoding, because the bridge carries numbers
// and not `undefined`/`Infinity`: a negative value means Infinity — no budget, said
// explicitly rather than reached by omission — and everything else is milliseconds.
//
// Note the native realm does NOT enforce this through QuickJS: New_QJS's maxExecutionTime
// argument is inert in the vendored qjs.wasm (a 1 ms limit does not interrupt a spinning
// loop), so guest.go arms a wazero deadline instead. That makes a budget kill fatal to the
// realm rather than a catchable JS error — see qjs.Runtime.Budget.
const createRealm: RealmFactory = async ({ source, bridge: capBridge, memoryLimitBytes, deadlineMs }) => {
    // Assigned before any guest code can call back: bridge.createRealm evaluates the
    // guest, whose top-level can only reach sync names (a Promise it could not await).
    let realm: number;
    const capCall: CapCall = (name, payload, callId) => {
        const r = capBridge(name, new Uint8Array(payload)) as Uint8Array | Promise<Uint8Array> | null;
        if (!r || typeof (r as Promise<Uint8Array>).then !== "function")
            return r as Uint8Array;
        (r as Promise<Uint8Array>).then((bytes: Uint8Array) => bridge.realmSettle(realm, callId, bytes, null), (e: unknown) => bridge.realmSettle(realm, callId, null, errMessage(e)));
        return null;
    };
    realm = bridge.createRealm(source, capCall, memoryLimitBytes ?? DEFAULT_REALM_MEMORY_BYTES, deadlineMs === undefined ? DEFAULT_GUEST_DEADLINE_MS : (deadlineMs === Infinity ? -1 : deadlineMs));
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
 *  seam (host.call, callModule, a realm result), and the one shape Go's await harness
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
    identity: Keypair;
    /** The GUEST signing keypair (§12.9) — a sibling subkey of `identity`. Defaults to
     *  `identity` so a test or embedding host that supplies one keypair still works. */
    guestIdentity?: Keypair;
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
            sodium, identity: cfg.identity, guestIdentity: cfg.guestIdentity, kernel, fs,
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
            if (!isAdmissionRejected(err)) {
                // A deliberate configuration: this node does not speak to anyone.
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
    // The one secret a node stores: the 32-byte master seed in --key (§12.6.2b). Every
    // purpose-bound keypair is derived from it HERE, in the shared subkey code — the
    // exact derivation the JS CLI runs (host/main.ts loadNodeKeys) — so this target's
    // channel and guest roles hold different keys too, instead of one raw keypair
    // signing for both. Go holds the seed and nothing derived from it.
    const keys = deriveNodeKeys(sodium, fromHex(cfg.keyHex));
    setPolicy(cfg.policyJson);
    const { shell: s, net: network } = await makeTransportNode({
        identity: keys.channel,
        guestIdentity: keys.guest,
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
        peerId: toHex(keys.channel.publicKey), port: network.port, wsPort: network.wsPort,
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

/** The confined realm's own plumbing (native/guest.go `guestDriverJS`): a microtask
 *  queue over the shared loop and one pre-compiled `__start` wrapper, so an initiator
 *  call costs an Invoke rather than a parse. Not the guest ABI (that is
 *  `guestPreamble`, cap-bridge.ts), but this driver's twin of what safe-js.ts does in
 *  TypeScript — fetched by Go like the preamble is, rather than restated as a Go
 *  string that TypeScript never saw. */
function guestDriver(): string {
    return GUEST_DRIVER;
}
const GUEST_DRIVER = `
"use strict";
globalThis.__start = function (id, entry, arg) {
  try {
    Promise.resolve(__invoke(entry, arg)).then(
      (v) => __callDone(id, v),
      (e) => __callFail(id, String(e && e.message || e)));
  } catch (e) {
    __callFail(id, String(e && e.message || e));
  }
};
`;

// What Go reaches by name in the realm. `createRealm` and the transport bundle
// helpers are here as much for the native tests as for the boot above: a test that
// stands up a guest or a second node drives the very factories production does, so
// there is no test-only wiring to keep in step with the real one.
export { bootNode, setPolicy, loadBundleBlob, runGuest, serve, uninstall, revoke, createRealm, guestDriver, embeddedTransport, embeddedTransportAuthor, makeTransportNode, };
