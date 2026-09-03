// The native loader's platform seam (§12.9): Go supplies primitives — pure modules over
// wazero, libsodium, an `fs` directory, TCP sockets, a second QuickJS realm — and this file
// adapts them to the interfaces `bootShell` consumes, then hands them to it. Go runs it
// inside QuickJS, bundled with every module it imports into native/host-shell.gen.js by
// scripts/bundle-loader.mjs.
import { policyFromJson } from "./policy.js";
import { verifyBundle, FreshnessMarks, freshnessPathFor, type PureModuleLoader } from "./bundle.js";
import { runCli, awaitCohort, transportConfigFrom, type CliHost, type NodeRuntime, type NodeSetup, type TransportNodeConfig } from "./cli.js";
import { parseDest } from "./peer-addr.js";
import {
  bootShell, type AppHandle, type Shell, type ShellSodium,
} from "./shell-core.js";
import { CausalContext, createDeadlineQueue, raceDeadline, serializeCalls, type CausalClock, type RealmFactory } from "./realm-queue.js";
import type { CallBudget } from "./guest-seam.js";
import { LISTENER, type ChannelFactory, type RawLink } from "../core/socket-seam.js";
import {
  DEFAULT_MAX_RAW_LINKS,
  MAX_INBOUND_HOLD_BYTES,
  MAX_INBOUND_HOLD_SLICES,
  TCP_LINGER_MS,
} from "../core/net-limits.js";
import type { Keypair } from "../core/subkeys.js";
import { deriveNodeKey } from "../core/subkeys.js";
import { FS_AVAILABLE_UNKNOWN, type Fs } from "../core/fs.js";
import {
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
  DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  DEFAULT_REALM_MEMORY_BYTES,
  DEFAULT_SCRATCH_SIZE,
} from "../core/wasm-limits.js";
import { toHex, fromHex, errMessage } from "../core/util.js";
// The artifact-shipped transport bundle (scripts/build-transport-bundle.mjs) — the signed
// program that is the node's network (§12.6).
import { transportBundleBytes } from "./transport-bundle.js";

/** The seam as Go calls into it — `HostCall` (guest-seam.ts) in this boundary's currency.
 *  The answer is always `null`: every call parks, Go holds the guest's Promise under
 *  `callId`, and the seam's Promise settles it through `bridge.realmSettle` — refused
 *  names included, as rejections. */
type NativeHostCall = (name: string, payload: ArrayBuffer, callId: number, deadlineMs: number) => null;

/** The opaque native-module slots and realm plumbing Go exposes (main.go). */
declare const bridge: {
  buildModules(slot: string, mods: { name: string; wasm: Uint8Array }[], scratchDefault: number,
    bindDeadlineMs: number): void;
  callModule(slot: string, module: string, payload: Uint8Array, deadlineMs: number): ArrayBuffer | null;
  disposeModules(slot: string): number;
  /** Process arguments after the program name, as a JSON array — not a joined string,
   *  because an argument may legitimately contain any byte. */
  argv(): string;
  /** Read a whole file; `null` only when absent. Other read failures throw. */
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
  createRealm(source: string, hostCall: NativeHostCall, memoryLimitBytes: number, deadlineMs: number,
    maxOutstandingHostCalls: number, maxOutstandingHostCallBytes: number): number;
  /** Invoke the realm's one `handle` entrypoint. Answers both facts the queue needs as one
   *  number — `elapsedNs * 2`, the execution charged to this causal turn, with the
   *  `__deferred` marker in the low bit — so the dispatch path allocates nothing. */
  realmCall(realm: number, payload: Uint8Array, callId: number,
    onOk: (bytes: Uint8Array) => void, onErr: (msg: string) => void,
    deadlineMs: number): number;
  realmCancel(realm: number, callId: number): void;
  /** Settle one guest host.call and drain the continuation it made runnable. Returns the
   *  execution time of that causal turn in nanoseconds. */
  realmSettle(realm: number, callId: number, bytes: Uint8Array | null, err: string | null): number;
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

/** Go's raw byte-stream primitives (§12.1). */
declare const __net: {
  /** Install host-owned socket limits before any channel can be opened. */
  install(maxLiveChannels: number, closeGraceMs: number,
    maxInboundReadBytes: number, maxInboundReadSlices: number): void;
  /** Open an outbound byte duplex. The id is never 0, and the channel buffers
   *  pre-connect sends, so JS can write the transport's HELLO immediately. */
  connect(host: string, port: number): number;
  /** Bind a listener; returns the bound port, or -1 on failure. */
  listen(host: string, port: number): number;
  /** Queue bytes for the writer goroutine (never blocks the loop goroutine). Answers
   *  nothing: admission happened at the driver's per-link owner, which charged these bytes
   *  against `buffered()` below before calling. */
  send(id: number, bytes: Uint8Array): void;
  /** Bytes queued for the writer goroutine but not yet handed to the socket. */
  buffered(id: number): number;
  /** Release the next socket read after one serialized transport-realm invocation. */
  resume(id: number): void;
  /** A deliberate close — never fires `__netClosed` (Go closes silently). */
  close(id: number, graceful?: boolean): void;
  closeListeners(): void;
};

// Policy values live in shared TypeScript and cross once when the primitive is installed;
// Go retains the mechanisms that must act before JS can observe an accepted socket.
__net.install(DEFAULT_MAX_RAW_LINKS, TCP_LINGER_MS,
  MAX_INBOUND_HOLD_BYTES, MAX_INBOUND_HOLD_SLICES);

// ── the RawLink shaping ─────────────────────────────────────────────────────
//
// Go's byte-level `__net` becomes the RawLink objects below, and Go's reader goroutines
// route deliveries through the three dispatchers at the end of this block. Go retains
// those AFTER the bundle evaluates (main.go boot: exposeNet → eval host-shell.gen.js →
// netHost.retain), which is what lets the shaping live where TypeScript sees it.

/** Channel table + accept registry, keyed by Go's socket ids / bound ports. */
const netChans = new Map<number, { deliver: (bytes: Uint8Array) => void; closed: () => void }>();
const netAccepts = new Map<number, (id: number, remoteAddr: string) => void>();

function makeGoLink(id: number, remoteAddr?: string): RawLink {
  let onData: (bytes: Uint8Array) => void = () => {};
  let onClose: () => void = () => {};
  netChans.set(id, {
    deliver: (bytes) => onData(bytes),
    closed: () => { netChans.delete(id); onClose(); },
  });
  return {
    stream: true,
    remoteAddr,
    send: (bytes) => { __net.send(id, bytes); },
    buffered: () => __net.buffered(id),
    // Go consumes a one-read token before invoking us, so the false edge is already
    // applied at the socket; the true edge returns the token after the realm turn.
    setReadable: (enabled) => { if (enabled) __net.resume(id); },
    onData: (cb) => { onData = cb; },
    onClose: (cb) => { onClose = cb; },
    // A deliberate close never fires __netClosed (Go closes silently), so drop our own
    // map entry here too, or every local close leaks one.
    close: (graceful) => { __net.close(id, graceful); netChans.delete(id); },
  };
}

function netConnectRaw(host: string, port: number): RawLink {
  return makeGoLink(__net.connect(host, port));
}

function netListenRaw(host: string, port: number, onAccept: (s: RawLink) => void): number {
  const bound = __net.listen(host, port);
  if (bound < 0) throw new Error("netListenRaw: bind failed");
  netAccepts.set(bound, (id, remoteAddr) => onAccept(makeGoLink(id, remoteAddr)));
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
  var __netAccept: (port: number, id: number, remoteAddr: string) => void;
}

// Defined at module scope — i.e. when host-shell.gen.js is evaluated, after Go has
// installed `__net` — and retained by Go once the bundle is up (netHost.retain).
globalThis.__netDeliver = (id, bytes) => { const c = netChans.get(id); if (c) c.deliver(new Uint8Array(bytes)); };
globalThis.__netClosed = (id) => { const c = netChans.get(id); if (c) c.closed(); };
globalThis.__netAccept = (port, id, remoteAddr) => { const a = netAccepts.get(port); if (a) a(id, remoteAddr); };

// ── The platform ─────────────────────────────────────────────────────────────
/** Build private module values over opaque Go handles (wazero instances cannot be JS
 *  values). The handle is target plumbing and never an app identity. */
let moduleSlotSeq = 0;
const modules: PureModuleLoader = {
  build(mods) {
    const slot = `slot:${++moduleSlotSeq}`;
    bridge.buildModules(slot, mods, DEFAULT_SCRATCH_SIZE, DEFAULT_GUEST_DEADLINE_MS);
    return {
      call(module, payload, deadlineMs) {
        // The bridge call runs the module synchronously inside the Go event loop, so
        // the wall clock around it IS the module's own compute — nothing sits queued
        // behind earlier calls (the native target serializes per slot in Go). Return
        // it as `ms` so the seam bills actual work, matching the JS worker's report.
        // `performance` is a JS-target global; the quickjs-ng host realm has Date.
        const clock = (typeof performance === "object" && typeof performance.now === "function")
          ? () => performance.now()
          : () => Date.now();
        const t0 = clock();
        const bound = deadlineMs === undefined ? DEFAULT_GUEST_DEADLINE_MS
          : (deadlineMs === Infinity ? -1 : deadlineMs);
        const r = bridge.callModule(slot, module, payload, bound);
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
  override persist(json: string) {
    if (this.path === null) return;
    // Fatal, deliberately: `FreshnessMarks` reads a throw here as "the write did not
    // land", which is what rolls a revocation back and un-binds a load whose mark could
    // not be raised — swallowing it would report both as successes while the next boot
    // re-admits the revoked author. 0600, a node's own downgrade guard.
    bridge.writeFile(this.path, utf8.encode(json), 0o600);
  }
}
/** This target's socket seam: the transport driver's ChannelFactory over Go's sockets,
 *  producing RawLinks identically to the node:net factory, so the transport bundle's link
 *  state machine runs over Go's primitives unchanged. */
const channels: ChannelFactory = {
  // Go has no TLS socket here, so `wss://` is unroutable (§12.1).
  connect: (dest) => {
    const d = parseDest(dest);
    if (!d || d.scheme === "wss")
      return null;
    return netConnectRaw(d.host, d.port);
  },
  listen: (tcp, ws, onAccept) => Promise.resolve({
    port: tcp ? netListenRaw(tcp.host, tcp.port, (s) => onAccept(s, { listener: LISTENER.TCP })) : 0,
    wsPort: ws ? netListenRaw(ws.host, ws.port, (s) => onAccept(s, { listener: LISTENER.WS })) : 0,
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
 *  Go's event loop, implementing the same neutral `Realm` contract as safe-js.ts. The promise plumbing
 *  stays here rather than in Go: `nativeCall` closes over this realm, so a settled op routes
 *  to the realm that parked it structurally, and Go needs no promise primitive of its own.
 *
 *  `deadlineMs` crosses with one sentinel encoding, because the bridge carries numbers and
 *  not `undefined`/`Infinity`: negative means Infinity, everything else is milliseconds. The
 *  native realm does NOT enforce it through QuickJS — New_QJS's maxExecutionTime is inert in
 *  the vendored qjs.wasm — so guest.go arms a wazero deadline instead, which makes a budget
 *  kill fatal to the realm rather than a catchable JS error. */
const createRealm: RealmFactory = async ({ source, hostCall, memoryLimitBytes, deadlineMs }) => {
  // This realm's wall-clock custody, on one wake per tier: the host calls it has not
  // answered, and the invocations waiting to enter it. Both die with the realm; they are
  // deliberately not one queue (realm-queue.ts).
  const hostCallDeadlines = createDeadlineQueue();
  const entryDeadlines = createDeadlineQueue();
  // Go mints the handle, but createRealm runs the guest's top-level code before returning
  // it — so a host.call made from there reaches `nativeCall` while this is still 0. Safe
  // because settlement is a HOST-realm microtask, and that realm is not pumped from
  // inside bridge.createRealm, so none can precede the assignment below (§12.3).
  let realm = 0;
  const causalContext = new CausalContext();
  // Go supplies the live segment remainder because it owns this realm's execution
  // clock. A native module runs synchronously inside that same segment, so its elapsed
  // time is already billed by guest.go; `charge` is deliberately a no-op rather than a
  // second charge when guest-seam's common module path settles.
  const nativeCall: NativeHostCall = (name, payload, callId, deadlineMs) => {
    // Go admitted this call before making the cross-realm copy. This adapter only
    // routes and settles; post-copy accounting here would be a second policy authority.
    const causalClock = causalContext.current;
    const budget: CallBudget = {
      remainingMs: deadlineMs < 0 ? Infinity : deadlineMs,
      charge: () => {},
      causalClock,
    };
    if (budget.remainingMs <= 0)
      throw new Error("guest: handoff deadline exhausted before host.call");
    // A synchronous throw is a refused NAME, which fails at the guest's call site
    // (guest-seam.ts); guest.go releases the call it had already admitted.
    const answer = hostCall(name, new Uint8Array(payload), budget);
    // Expiry arrives as an ordinary rejection, so a late answer and a failed one settle
    // by the same arm and neither can follow the other (realm-queue.ts).
    const settle = (bytes: Uint8Array | null, error: string | null): void =>
      causalContext.run(causalClock, () => {
        const elapsedNs = bridge.realmSettle(realm, callId, bytes, error);
        causalClock?.charge(elapsedNs / 1_000_000);
      });
    void raceDeadline(hostCallDeadlines, budget.remainingMs, answer,
      "guest: host.call handoff deadline exceeded").then(
      (bytes: Uint8Array) => settle(bytes, null),
      (e: unknown) => settle(null, errMessage(e)),
    );
    return null;
  };
  realm = bridge.createRealm(source, nativeCall, memoryLimitBytes ?? DEFAULT_REALM_MEMORY_BYTES,
    deadlineMs === undefined ? DEFAULT_GUEST_DEADLINE_MS : (deadlineMs === Infinity ? -1 : deadlineMs),
    DEFAULT_MAX_OUTSTANDING_HOST_CALLS, DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES);
  const configuredDeadlineMs = deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
  let invocationSeq = 0;
  let disposed = false;
  return {
    // Serialized in the shared TS rather than in Go: one implementation of the realm
    // contract (realm-queue.ts) is what keeps the two targets from differing about
    // when a second entrypoint may begin.
    call: serializeCalls(
      entryDeadlines,
      (payload: Uint8Array, handoffDeadlineMs: number, causalClock?: CausalClock) => {
        // The executor runs synchronously, so `deferred` carries Go's answer by
        // the time the return statement reads it.
        invocationSeq++;
        if (!Number.isSafeInteger(invocationSeq))
          throw new Error("guest: realm invocation id exhausted");
        const callId = invocationSeq;
        let deferred = false;
        let fail!: (reason: Error) => void;
        const result = new Promise<Uint8Array>((resolve, reject) => {
          fail = reject;
          const report = causalContext.run(causalClock, () => bridge.realmCall(
            realm, payload, callId,
            (bytes: Uint8Array) => resolve(new Uint8Array(bytes)),
            (msg: string) => reject(new Error(msg)),
            handoffDeadlineMs === Infinity ? -1 : handoffDeadlineMs));
          // `elapsedNs * 2 | deferred` — see the bridge declaration above.
          deferred = report % 2 === 1;
          causalClock?.charge(Math.floor(report / 2) / 1_000_000);
        });
        return {
          result,
          deferred,
          // guest.go's realmCancel drops the parked callbacks rather than calling them, so
          // the rejection the queue needs to see is made here (realm-queue.ts `cancel`).
          cancel: (reason) => { bridge.realmCancel(realm, callId); fail(reason); },
        };
      },
      () => (disposed ? new Error("guest realm disposed") : null),
      configuredDeadlineMs,
    ),
    dispose: () => {
      disposed = true;
      // guest.go's close() runs settleAll before it frees anything, so every callback
      // it still owns is rejected synchronously here — safe-js.ts needs its own
      // registry for this, and this target does not (§12.3). The armed deadlines are
      // host-side and do NOT go with it: a timer waiting to reject a call this realm
      // no longer holds keeps the host's event loop alive for the whole of its
      // remainder, so a one-shot process would linger a full budget past its work.
      hostCallDeadlines.disarmAll();
      entryDeadlines.disarmAll();
      bridge.realmDispose(realm);
    },
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
/** Stand a node up on this platform via the shared `bootShell` (§12.9). Config is an
 *  object so a positional drift against Go is a type error, and it is cli.ts's
 *  `TransportNodeConfig` so a field added for one target cannot go missing on this one.
 *  The store and its policy are not in it: on this target they are realm state, set
 *  before the boot rather than passed to it (`openStore`, `setPolicy`). */
async function makeTransportNode(cfg: TransportNodeConfig): Promise<NodeRuntime> {
  const { shell, transport } = await bootShell({
    sodium, identity: cfg.identity, modules, fs,
    freshnessStore: new NativeFreshnessStore(storeDir),
    networkKey: cfg.networkKey,
    // The sockets and the signed program that drives them, in one object.
    transport: {
      channels,
      listen: cfg.listen,
      wsListen: cfg.wsListen,
      bundle: cfg.transportBundle,
      config: cfg.transportConfig,
    },
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
  const key = deriveNodeKey(sodium, fromHex(cfg.keyHex));
  setPolicy(cfg.policyJson);
  // The cohort is parsed BEFORE the boot and goes in as the transport's own configuration:
  // the address book is the transport guest's, so a peer list is something a transport is
  // loaded WITH, not something taught to a driver afterwards (§12.10).
  const peers: string[] = cfg.peers ?? [];
  const s = await makeTransportNode({
    identity: key,
    listen: cfg.listen,
    wsListen: cfg.wsListen,
    // Contact policy is transport config (§12.6.3).
    transportConfig: transportConfigFrom(
      peers,
      cfg.contactSecretHex ? fromHex(cfg.contactSecretHex) : undefined,
    ),
  });
  shell = s.shell;
  const network = s.transport;
  if (peers.length > 0) {
    // The same diagnosis the operator flow gives `--peers`, through the same door.
    // Best-effort: the op settles on its own deadline, so a member that is not up yet
    // delays the boot but never fails it.
    await awaitCohort(s.shell, "peers were configured, but there is nothing to dial from");
  }
  const status = {
    peerId: toHex(key.publicKey), port: network.port, wsPort: network.wsPort,
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
      // NodeSetup EXTENDS TransportNodeConfig, so the rest of the config crosses
      // unchanged — no field-by-field copy to fall out of step.
      const stood = await makeTransportNode(cfg);
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
// though this one has not settled (realm-queue.ts's Invocation.deferred). Read after
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
export { runMain, loadBundleFile, openStore, bootNode, setPolicy, createRealm, guestDriver, embeddedTransportAuthor, makeTransportNode, };
