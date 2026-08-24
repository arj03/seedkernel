// The native loader's platform seam (§12.9): Go supplies primitives — pure modules over
// wazero, libsodium, an `fs` directory, TCP sockets, a second QuickJS realm — and this file
// adapts them to the interfaces `bootShell` consumes, then hands them to it. Go runs it
// inside QuickJS, bundled with every module it imports into native/host-shell.gen.js by
// scripts/bundle-loader.mjs.
import { policyFromJson } from "./policy.js";
import { verifyBundle, FreshnessMarks, freshnessPathFor, type PureModuleLoader } from "./bundle.js";
import { runCli, parsePeerSpec, requireLinkBinding, type CliHost, type NodeRuntime, type NodeSetup } from "./cli.js";
import {
  bootShell, type AppHandle, type RealmFactory, type Shell, type ShellSodium,
} from "./shell-core.js";
import { serializeCalls } from "./realm-queue.js";
import { FRAMING, type ChannelFactory, type Framing, type RawLink } from "../core/socket-seam.js";
import type { Keypair } from "../core/subkeys.js";
import { deriveNodeKeys } from "../core/subkeys.js";
import { FS_AVAILABLE_UNKNOWN, type Fs } from "../core/fs.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_REALM_MEMORY_BYTES, DEFAULT_SCRATCH_SIZE } from "../core/wasm-limits.js";
import { toHex, fromHex, errMessage } from "../core/util.js";
// The artifact-shipped transport bundle (scripts/build-transport-bundle.mjs) — the signed
// program that is the node's network (§12.6).
import { transportBundleBytes } from "./transport-bundle.js";

/** The seam as Go calls into it — `HostCall` (guest-seam.ts) in this boundary's currency.
 *  The answer is always `null`: every call parks, Go holds the guest's Promise under
 *  `callId`, and the seam's Promise settles it through `bridge.realmSettle` — refused
 *  names included, as rejections. */
type NativeHostCall = (name: string, payload: ArrayBuffer, callId: number) => null;

/** The opaque native-module slots and realm plumbing Go exposes (main.go). */
declare const bridge: {
  buildModules(slot: string, mods: { name: string; wasm: Uint8Array }[], scratchDefault: number): void;
  callModule(slot: string, module: string, payload: Uint8Array): ArrayBuffer | null;
  disposeModules(slot: string): number;
  /** Process arguments after the program name, as a JSON array — not a joined string,
   *  because an argument may legitimately contain any byte. */
  argv(): string;
  /** Read a whole file; `null` when absent/unreadable — the `CliFiles` contract (cli.ts). */
  readFile(path: string): ArrayBuffer | null;
  /** Write a whole file atomically (temp + rename). `mode` is a POSIX permission bit
   *  set, or 0 to leave the platform default. */
  writeFile(path: string, bytes: Uint8Array, mode: number): void;
  /** One operator line on stderr — stdout is the data channel (`stdout` below), which an
   *  operator line would corrupt. */
  log(line: string): void;
  /** One diagnostic line on stderr — where every `console.*` in this realm goes
   *  (native-polyfills.ts). */
  logErr(line: string): void;
  /** Raw bytes on stdout — `--op` writes the app's response verbatim. */
  stdout(bytes: Uint8Array): void;
  /** Raw bytes from stdin — `--op`'s argument, or empty when nothing was piped in. */
  stdin(): ArrayBuffer;
  createRealm(source: string, hostCall: NativeHostCall, memoryLimitBytes: number, deadlineMs: number): number;
  /** Invoke the realm's one `handle` entrypoint. Returns 1 when it handed its answer to a
   *  later turn (the `__deferred` marker), 0 otherwise. */
  realmCall(realm: number, payload: Uint8Array,
            onOk: (bytes: Uint8Array) => void, onErr: (msg: string) => void): number;
  realmSettle(realm: number, callId: number, bytes: Uint8Array | null, err: string | null): void;
  realmDispose(realm: number): void;
};

/** Go's host crypto primitives (native/sodium.go, mldsa.go). Bytes cross as
 *  ArrayBuffers and a failure as `null` — what the bridge can carry.
 *
 *  `crypto_generichash` takes its optional key so the native blake2b shim can refuse a
 *  keyed hash loudly; dropping the argument here would turn a MAC into a plain hash. */
declare const __sodium: {
  crypto_generichash(hashLength: number, message: Uint8Array, key?: Uint8Array | null): ArrayBuffer;
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
};

/** The crypto surface this target serves: `ShellSodium` plus the two keypair producers a
 *  node's identity comes out of. `crypto_generichash` is restated with its key optional,
 *  which is what satisfies both halves of `ShellSodium` at once: the loader calls it with an
 *  explicit `null` key and the guest seam calls it with two arguments. */
export interface NativeSodium extends ShellSodium {
  crypto_generichash(hashLength: number, message: Uint8Array, key?: Uint8Array | null): Uint8Array;
  crypto_sign_keypair(): Keypair;
  crypto_sign_seed_keypair(seed: Uint8Array): Keypair;
}

/** libsodium, in libsodium-wrappers method names, over Go's primitives: Uint8Array
 *  results, `{publicKey, privateKey}` keypairs, and a throw where the wrappers throw.
 *
 *  A native `null` becomes the same throw libsodium wrappers use for failed open or a bad
 *  scalar multiplication. */
function wrapNativeSodium(N: typeof __sodium): NativeSodium {
  const u8 = (b: ArrayBuffer) => new Uint8Array(b);
  const kp = (k: { publicKey: ArrayBuffer; privateKey: ArrayBuffer }): Keypair =>
    ({ publicKey: u8(k.publicKey), privateKey: u8(k.privateKey) });
  return {
    crypto_generichash: (len: number, m: Uint8Array, key?: Uint8Array | null) => u8(N.crypto_generichash(len, m, key)),
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
  };
}

/** The one `sodium` this target has. Exported — and published as a global by the loader
 *  bundle — so the native tests drive the same wrapper production does. Built at module
 *  scope because `embeddedTransportAuthor` verifies a bundle with it below. */
export const sodium: NativeSodium = wrapNativeSodium(__sodium);

/** The `fs.*` primitive over Go's data directory (native/fs.go), declared with its real,
 *  **synchronous** shape: Go answers a read in the call, and qjs has no promise primitive
 *  to hand back anyway. The seam the shared code consumes is async (`Fs`, core/fs.ts), so
 *  the adaptation happens here — Go grows with primitives, never with logic. */
declare const __fs: {
  /** Point the backend at a data directory, creating it if needed. Late-bound because which
   *  directory is the operator's `--dir`, which Go does not read; until called the store
   *  answers as empty and refuses writes. */
  open(dir: string): void;
  get(key: string): ArrayBuffer | null;
  put(key: string, bytes: Uint8Array): void;
  size(key: string): number;
  /** One `\n`-joined string, not an array: a JS array would cost an engine call per key, so
   *  a content store with tens of thousands of blocks would pay tens of thousands of
   *  crossings per listing. A key may not contain `\n` (`isSafeFsKey`), so the join is
   *  unambiguous. */
  list(prefix?: string): string;
  delete(key: string): boolean;
  stat(): { used: number; available: number };
};

/** The async `Fs` seam over that synchronous primitive. `async` rather than
 *  `Promise.resolve(...)` so a throw from Go becomes a rejection like every other
 *  backend's, instead of a synchronous throw out of a method the caller awaits.
 *
 *  Exported so the native tests drive the SAME wrapper production does. */
export const fs: Fs = {
  async get(key) { const r = __fs.get(key); return r === null ? null : new Uint8Array(r); },
  async put(key, bytes) { __fs.put(key, bytes); },
  async size(key) { return __fs.size(key); },
  // An empty listing arrives as "", which must map to [] — split would yield [""].
  async list(prefix) { const s = __fs.list(prefix); return s === "" ? [] : s.split("\n"); },
  async delete(key) { return __fs.delete(key); },
  // Go answers -1 when it cannot ask the OS for free space; the sentinel a guest reads is
  // the seam's (core/fs.ts), so it cannot differ by backend.
  async stat() { const s = __fs.stat(); return { used: s.used, available: s.available === -1 ? FS_AVAILABLE_UNKNOWN : s.available }; },
};

/** Go's socket byte primitives (native/sock.go): a raw byte duplex and nothing else. The
 *  whole networking seam — wire codec, handshake, routing — is the transport bundle's, over
 *  the same primitive every target hands it. A link arrives WITHOUT a `framing`: which codec
 *  applies follows from the address, which is this file's to read and never Go's. */
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

// ── the RawLink shaping ─────────────────────────────────────────────────────
//
// Go's byte-level `__net` becomes the RawLink objects below, and Go's reader goroutines
// route deliveries through the three dispatchers at the end of this block. Go retains
// those AFTER the bundle evaluates (main.go boot: exposeNet → eval host-shell.gen.js →
// netHost.retain), which is what lets the shaping live where TypeScript sees it.

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
    // map entry here too, or every local close leaks one.
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
  // Teardown closes every bound listener in Go, so every accept closure here is stale —
  // clear them too, or they pin their onAccept graphs for the process lifetime.
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
/** Build private module values over opaque Go handles (wazero instances cannot be JS
 *  values). The handle is target plumbing and never an app identity. */
let moduleSlotSeq = 0;
const modules: PureModuleLoader = {
    build(mods) {
        const slot = `slot:${++moduleSlotSeq}`;
        bridge.buildModules(slot, mods, DEFAULT_SCRATCH_SIZE);
        return {
            call(module, payload, _deadlineMs) {
                // The bridge call runs the module synchronously inside the Go event loop, so
                // the wall clock around it IS the module's own compute — nothing sits queued
                // behind earlier calls (the native target serializes per slot in Go). Return
                // it as `ms` so the seam bills actual work, matching the JS worker's report.
                // `performance` is a JS-target global; the quickjs-ng host realm has Date.
                const clock = (typeof performance === "object" && typeof performance.now === "function")
                    ? () => performance.now()
                    : () => Date.now();
                const t0 = clock();
                const r = bridge.callModule(slot, module, payload);
                return Promise.resolve({
                    bytes: r === null ? null : new Uint8Array(r),
                    ms: clock() - t0,
                });
            },
            dispose() { bridge.disposeModules(slot); },
        };
    },
};
/** The data directory a store was opened on, or null for a realm that never opened one
 *  (the native tests' bare `makeTransportNode`, which needs no durable marks). It names
 *  the freshness file's location and nothing else. */
let storeDir: string | null = null;
/** Point the `fs.*` backend at a data directory and remember where its freshness marks
 *  belong. Called by `standUp` below once `--dir` has been read, and by the native test
 *  harness — the one place either learns where this node's disk is. */
function openStore(dir: string): void {
    __fs.open(dir);
    storeDir = dir;
}
/** The freshness store over the Go file seam (§12.4). The marks live in a SIBLING of the
 *  data dir (`freshnessPathFor`, shared with the Node shell) so a `fs`-capable guest cannot
 *  reach its own mark. A realm with no store open keeps its marks in memory. */
class NativeFreshnessStore extends FreshnessMarks {
    path;
    constructor(dir: string | null) {
        const path = dir === null ? null : freshnessPathFor(dir);
        let json: string | null = null;
        if (path !== null) {
            const raw = bridge.readFile(path);
            if (raw !== null) json = utf8dec.decode(new Uint8Array(raw));
        }
        super(json);
        this.path = path;
    }
    persist(json: string) {
        if (this.path === null) return;
        // Fatal, deliberately: `FreshnessMarks` reads a throw here as "the write did not
        // land", which is what rolls a revocation back and un-binds a load whose mark could
        // not be raised — swallowing it would report both as successes while the next boot
        // re-admits the revoked author. 0600, a node's own downgrade guard.
        bridge.writeFile(this.path, utf8.encode(json), 0o600);
    }
}
/** Say which codec a Go socket carries. The bytes are Go's; the boundaries are the
 *  transport bundle's, and this is the one place that decides which rule it applies. */
function framed(link: GoLink, framing: Framing, authority?: string): RawLink {
    return { ...link, framing, authority };
}
/** This target's socket seam: the transport driver's ChannelFactory over Go's sockets,
 *  producing RawLinks identically to the node:net factory, so the transport bundle's link
 *  state machine runs over Go's primitives unchanged. */
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
        return transportBundleBytes();
    }
    catch {
        return null;
    }
})();
/** Who signed the transport this artifact ships — hex, DERIVED from the blob rather than
 *  restated anywhere. It is the id an operator pins under `grants.link` in a policy file
 *  (§12.5). Empty if the artifact carries no transport. */
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
/** This target's realm factory (§12.3): a second, zero-authority quickjs-ng realm driven by
 *  Go's event loop, presenting the same `SafeRealm` safe-js.ts does. The promise plumbing
 *  stays here rather than in Go: `nativeCall` closes over this realm, so a settled op routes
 *  to the realm that parked it structurally, and Go needs no promise primitive of its own.
 *
 *  `deadlineMs` crosses with one sentinel encoding, because the bridge carries numbers and
 *  not `undefined`/`Infinity`: negative means Infinity, everything else is milliseconds. The
 *  native realm does NOT enforce it through QuickJS — New_QJS's maxExecutionTime is inert in
 *  the vendored qjs.wasm — so guest.go arms a wazero deadline instead, which makes a budget
 *  kill fatal to the realm rather than a catchable JS error. */
const createRealm: RealmFactory = async ({ source, hostCall, memoryLimitBytes, deadlineMs }) => {
    // Assigned before any guest code can call back: bridge.createRealm evaluates the guest,
    // whose top level may call the seam but reads only Promises — there is nothing to
    // await at top level, so nothing settles inside realm construction.
    let realm: number;
    // No `CallBudget` crosses here: this realm's segment lives in the engine, not in JS, so
    // there is nothing on this side to read a remainder from or bill a module's burn back
    // to. The module bound this target enforces is Go's own
    // (`SEEDKERNEL_MODULE_DEADLINE_MS`), which is why the seam takes the budget as optional.
    const nativeCall: NativeHostCall = (name, payload, callId) => {
        void Promise.resolve(hostCall(name, new Uint8Array(payload))).then(
            (bytes: Uint8Array) => bridge.realmSettle(realm, callId, bytes, null),
            (e: unknown) => bridge.realmSettle(realm, callId, null, errMessage(e)),
        );
        return null;
    };
    realm = bridge.createRealm(source, nativeCall, memoryLimitBytes ?? DEFAULT_REALM_MEMORY_BYTES, deadlineMs === undefined ? DEFAULT_GUEST_DEADLINE_MS : (deadlineMs === Infinity ? -1 : deadlineMs));
    let disposed = false;
    return {
        // Serialized in the shared TS rather than in Go: one implementation of the realm
        // contract (realm-queue.ts) is what keeps the two targets from differing about
        // when a second entrypoint may begin.
        call: serializeCalls(
            (payload: Uint8Array) => {
                // The executor runs synchronously, so `deferred` carries Go's answer by
                // the time the return statement reads it.
                let deferred = false;
                const result = new Promise<Uint8Array>((resolve, reject) => {
                    deferred = bridge.realmCall(realm, payload, (bytes: Uint8Array) => resolve(new Uint8Array(bytes)), (msg: string) => reject(new Error(msg))) === 1;
                });
                return { result, released: deferred ? Promise.resolve() : result.catch(() => { }) };
            },
            () => (disposed ? new Error("guest realm disposed") : null),
        ),
        dispose: () => { disposed = true; bridge.realmDispose(realm); },
    };
};
/** Everything that crosses back to Go crosses as BYTES — the currency of this seam, and
 *  the one shape Go's await harness carries out of a settled promise. A JSON report is no
 *  exception. */
const utf8 = new TextEncoder();
const utf8dec = new TextDecoder();
let shell: Shell | null = null;
/** The admission predicate in force (§12.5). It starts deny-all, so the absence of a
 *  decision is never permission (§14), and `--policy` replaces it at boot. The shell
 *  closes over this indirection rather than a fixed predicate, so trust can be narrowed or
 *  widened without restarting the node. */
let admissionPolicy = policyFromJson(null);
/** Point the realm at a policy config (§12.5). `null` restores the deny-all default;
 *  malformed JSON throws, so a typo fails loudly rather than silently widening trust. */
function setPolicy(json: string | null): void {
    admissionPolicy = policyFromJson(json);
}
/** The one shell, or a clear error if Go asked for something before booting one. */
function theShell() {
    if (!shell)
        throw new Error("native: bootNode has not run");
    return shell;
}
/** Stand a node up on this platform via the shared `bootShell` (§12.9).
 *  Config is an object so a positional drift against Go is a type error. */
async function makeTransportNode(cfg: {
    identity: Keypair;
    contactSecret?: Uint8Array;
    listen?: {
        host: string;
        port: number;
    };
    wsListen?: {
        host: string;
        port: number;
    };
    /** Which network this node belongs to (§12.6) — an isolation boundary, not a gate. */
    networkKey?: Uint8Array;
    requestDeadlineMs?: number;
    /** The §12.3 guest bounds, threaded through to `bootShell`: a bound the shell accepts
     *  but no target can set is a bound nobody has. */
    guestDeadlineMs?: number;
    realmMemoryBytes?: number;
    /** A transport bundle to load instead of the artifact-shipped one (§12.6). */
    transportBundle?: Uint8Array;
}): Promise<NodeRuntime> {
    const { shell, transport } = await bootShell({
        sodium, identity: cfg.identity, modules, fs,
        freshnessStore: new NativeFreshnessStore(storeDir),
        networkKey: cfg.networkKey,
        transport: {
            contactSecret: cfg.contactSecret,
            requestDeadlineMs: cfg.requestDeadlineMs,
            channels,
            listen: cfg.listen,
            wsListen: cfg.wsListen,
        },
        transportBundle: cfg.transportBundle,
        // The admission predicate in force (§12.5): the shell closes over this
        // indirection rather than a fixed predicate, so trust can be narrowed or widened
        // without restarting the node (`setPolicy`).
        admit: (v, ctx) => admissionPolicy(v, ctx),
        guestDeadlineMs: cfg.guestDeadlineMs,
        realmMemoryBytes: cfg.realmMemoryBytes,
        createRealm,
    });
    return { shell, transport: transport! };
}
/** Stand THE node up and keep it: identity, the transport bundle, the shared shell.
 *  Resolves once the listeners are bound and any cohort peers have been dialled, so
 *  Go can print the real ports. */
async function bootNode(cfgJson: string): Promise<Uint8Array> {
    const cfg = JSON.parse(cfgJson);
    // The one secret a node stores: the 32-byte master seed in --key (§12.6.2b). Derived
    // HERE, by the shared subkey code the JS CLI runs, so this target's peer id is the key
    // the JS shell would compute from the same seed. Go holds the seed and nothing else.
    const keys = deriveNodeKeys(sodium, fromHex(cfg.keyHex));
    setPolicy(cfg.policyJson);
    const s = await makeTransportNode({
        identity: keys.channel,
        contactSecret: cfg.contactSecretHex ? fromHex(cfg.contactSecretHex) : undefined,
        listen: cfg.listen,
        wsListen: cfg.wsListen,
        requestDeadlineMs: cfg.requestDeadlineMs,
    });
    shell = s.shell;
    const network = s.transport;
    const peers: string[] = cfg.peers ?? [];
    if (peers.length > 0) {
        // The same diagnosis the operator flow gives (`--peers`): the adapter is the
        // platform's and always there, so an unowned raw-link binding has to be said rather
        // than discovered as a dial that answers nothing.
        requireLinkBinding(s.transport, "peers were configured, but there is nothing to dial from");
        for (const spec of peers) {
            const { peerId, addr } = parsePeerSpec(spec, "tcp");
            network.addPeerAddr(peerId, addr);
        }
        // Best-effort: ready() resolves on its own timeout rather than rejecting, so a
        // cohort member that is not up yet delays the boot but never fails it.
        await network.ready();
    }
    const status = {
        peerId: toHex(keys.channel.publicKey), port: network.port, wsPort: network.wsPort,
    };
    return utf8.encode(JSON.stringify(status));
}

// ── the operator flow ────────────────────────────────────────────────────────
/** This platform, as `cli.ts` needs it: files, a console line, raw stdout, entropy, and
 *  "stand a node up here" — none of which decides anything. The flag set, the defaults,
 *  the deny-all reading of an absent `--policy`, the order remedies run in and the console
 *  lines are all cli.ts's. */
function nativeCliHost(): CliHost {
    return {
        banner: "seedkernel-loader",
        argv: JSON.parse(bridge.argv()) as string[],
        readFile(path) {
            const r = bridge.readFile(path);
            return r === null ? null : new Uint8Array(r);
        },
        writeFile(path, bytes, mode) { bridge.writeFile(path, bytes, mode ?? 0); },
        log(line) { bridge.log(line); },
        stdout(bytes) { bridge.stdout(bytes); },
        stdin() { return new Uint8Array(bridge.stdin()); },
        sodium,
        async standUp(cfg: NodeSetup) {
            // Where this node's disk is, and who may install on it — both before the
            // transport bundle lands, because that load is governed by the policy and
            // its freshness mark belongs beside the store.
            openStore(cfg.dir);
            setPolicy(cfg.policyJson ?? null);
            const stood = await makeTransportNode({
                identity: cfg.identity,
                contactSecret: cfg.contactSecret,
                listen: cfg.listen,
                wsListen: cfg.wsListen,
                requestDeadlineMs: cfg.requestDeadlineMs,
                guestDeadlineMs: cfg.guestDeadlineMs,
                realmMemoryBytes: cfg.realmMemoryBytes,
                transportBundle: cfg.transportBundle,
            });
            // One "the shell" per realm, whichever entry point stood it up.
            shell = stood.shell;
            return stood;
        },
    };
}
/** Run the operator flow. Go calls this with no arguments — every choice comes from the
 *  argv it hands back through the bridge — and reads back whether the node is listening,
 *  which is the one thing Go still decides: whether to keep its event loop running. */
async function runMain(): Promise<Uint8Array> {
    const { serving, close } = await runCli(nativeCliHost());
    if (!serving) close();
    return utf8.encode(JSON.stringify({ serving }));
}
/** Node-like file convenience over the native platform's byte bridge. The returned
 *  handle remains with the caller; the platform keeps no key-to-handle registry. */
async function loadBundleFile(path: string): Promise<AppHandle> {
    const raw = bridge.readFile(path);
    if (raw === null) throw new Error(`cannot read ${path}`);
    return theShell().loadBundleBlob(new Uint8Array(raw));
}

/** The confined realm's own plumbing (native/guest.go `guestDriverJS`): one pre-compiled
 *  `__start` wrapper, so an initiator call costs an Invoke rather than a parse. Not the
 *  guest ABI (that is `guestPreamble`) but this target's twin of what safe-js.ts does —
 *  fetched by Go rather than restated as a Go string TypeScript never saw. */
function guestDriver(): string {
    return GUEST_DRIVER;
}
const GUEST_DRIVER = `
"use strict";
// Returns 1 when the entrypoint handed its answer to a later turn (the guest's own
// deferred marker) — Go's signal that the realm is free for the next invocation even
// though this one has not settled (realm-queue.ts's Invocation.released). Read after
// __invoke's synchronous segment, and __invoke cleared the flag on entry, so it
// describes exactly this invocation.
globalThis.__start = function (id, arg) {
  try {
    const out = __invoke(arg);
    // A synchronous answer reports WITHOUT a microtask: the guest's job queue is only
    // pumped by the loop (guest.go pump), and this __start can run inside a host-
    // realm eval's own drain, where the loop cannot turn — a then() would leave the
    // caller parked until the drain ends, and the drain ends only when the caller
    // settles. An ASYNC entrypoint really is parked (its promise settles on a later
    // turn), so it keeps the then() path.
    if (out && typeof out.then === "function") {
      out.then(
        (v) => __callDone(id, v),
        (e) => __callFail(id, String(e && e.message || e)));
    } else {
      __callDone(id, out);
    }
  } catch (e) {
    __callFail(id, String(e && e.message || e));
  }
  return globalThis.__deferred === true ? 1 : 0;
};
`;

// What Go reaches by name in the realm. `createRealm` and the transport helpers are here
// for the native tests as much as for the boot above, so a test that stands up a guest or
// a second node drives the very factories production does.
export { runMain, loadBundleFile, openStore, bootNode, setPolicy, createRealm, guestDriver, embeddedTransport, embeddedTransportAuthor, makeTransportNode, };
