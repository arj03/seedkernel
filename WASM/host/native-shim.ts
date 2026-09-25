// The native binary's platform seam (§12.9): adapts Go's primitives — wazero modules,
// libsodium, an `fs` directory, TCP sockets, one QuickJS realm per app — to what `bootShell`
// consumes. Runs inside QuickJS as part of native/host-shell.gen.js.
import { policyFromJson } from "./policy.js";
import { type PureModuleLoader } from "./bundle.js";
import { freshnessStoreFor, runCli, type CliFiles, type CliHost, type NodeRuntime, type NodeSetup } from "./cli.js";
import { parseDest } from "../services/peer-addr.js";
import { bootShell, type ShellSodium } from "./shell-core.js";
import { CausalContext, createRealmDeadlines, monotonicMs, serializeCalls, settleByDeadline, HOST_CALL_LATE, REALM_DISPOSED, type CausalClock, type RealmFactory } from "./realm-queue.js";
import { CallBudget } from "./guest-seam.js";
import { type ChannelFactory, type RawLink } from "../services/socket-seam.js";
import {
  DEFAULT_MAX_RAW_LINKS,
  MAX_INBOUND_HOLD_BYTES,
  MAX_INBOUND_HOLD_SLICES,
  TCP_LINGER_MS,
} from "../services/net-limits.js";
import type { Keypair } from "../services/subkeys.js";
import { FS_AVAILABLE_UNKNOWN, type Fs } from "../services/fs.js";
import {
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
  DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  DEFAULT_REALM_MEMORY_BYTES,
  DEFAULT_SCRATCH_SIZE,
} from "./wasm-limits.js";
import { enc, errMessage } from "../services/util.js";

/** `HostCall` as Go calls it. Always answers `null`: Go parks the guest's Promise under
 *  `callId` and `bridge.realmSettle` settles it. */
type NativeHostCall = (name: string, payload: ArrayBuffer, callId: number, deadlineMs: number) => null;

/** The opaque native-module slots and realm plumbing Go exposes (main.go). */
declare const bridge: {
  buildModules(slot: string, mods: { name: string; wasm: Uint8Array }[], scratchDefault: number,
    bindDeadlineMs: number): void;
  callModule(slot: string, module: string, payload: Uint8Array, deadlineMs: number): ArrayBuffer | null;
  disposeModules(slot: string): number;
  /** Process arguments after the program name, as a JSON array. */
  argv(): string;
  /** Read a whole file; `null` only when absent. Other read failures throw. */
  readFile(path: string): ArrayBuffer | null;
  /** Write a whole file atomically; `mode` 0 keeps the platform default. */
  writeFile(path: string, bytes: Uint8Array, mode: number): void;
  /** One diagnostic line on stderr; stdout is the data channel. */
  log(line: string): void;
  /** Raw bytes on stdout — `--op` writes the app's response verbatim. */
  stdout(bytes: Uint8Array): void;
  /** Raw bytes from stdin — `--op`'s argument, or empty when nothing was piped in. */
  stdin(): ArrayBuffer;
  createRealm(source: string, hostCall: NativeHostCall, memoryLimitBytes: number, deadlineMs: number,
    maxOutstandingHostCalls: number, maxOutstandingHostCallBytes: number): number;
  /** Invoke `handle`. Answers `elapsedNs * 2 | deferred` as one number, so dispatch
   *  allocates nothing. */
  realmCall(realm: number, payload: Uint8Array, callId: number,
    onOk: (bytes: Uint8Array) => void, onErr: (msg: string) => void,
    deadlineMs: number): number;
  realmCancel(realm: number, callId: number): void;
  /** Settle one guest host.call and run its continuation (a new turn when `detached` is
   *  1). Returns that execution time in ns. */
  realmSettle(realm: number, callId: number, bytes: Uint8Array | null, err: string | null,
    detached: number): number;
  realmDispose(realm: number): void;
};

/** Go's crypto primitives (native/sodium.go, mldsa.go): ArrayBuffers in and out, `null`
 *  for failure. */
declare const __sodium: {
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): ArrayBuffer;
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): ArrayBuffer;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  crypto_scalarmult(sk: Uint8Array, pk: Uint8Array): ArrayBuffer | null;
  /** (m, ad, npub, key): the wrappers' unused `nsec` is dropped. */
  crypto_aead_chacha20poly1305_ietf_encrypt(message: Uint8Array, ad: Uint8Array | null, npub: Uint8Array, key: Uint8Array): ArrayBuffer;
  crypto_aead_chacha20poly1305_ietf_decrypt(ciphertext: Uint8Array, ad: Uint8Array | null, npub: Uint8Array, key: Uint8Array): ArrayBuffer | null;
  crypto_sign_keypair(): { publicKey: ArrayBuffer; privateKey: ArrayBuffer };
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: ArrayBuffer; privateKey: ArrayBuffer };
  randombytes_buf(n: number): ArrayBuffer;
  ml_dsa65_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
};

/** `ShellSodium` plus the keypair producers a node's identity comes from. */
export interface NativeSodium extends ShellSodium {
  crypto_sign_keypair(): Keypair;
  crypto_sign_seed_keypair(seed: Uint8Array): Keypair;
}

/** libsodium-wrappers' shape over Go's primitives; a native `null` becomes the throw the
 *  wrappers use. */
function wrapNativeSodium(N: typeof __sodium): NativeSodium {
  const u8 = (b: ArrayBuffer) => new Uint8Array(b);
  const kp = (k: { publicKey: ArrayBuffer; privateKey: ArrayBuffer }): Keypair =>
    ({ publicKey: u8(k.publicKey), privateKey: u8(k.privateKey) });
  return {
    crypto_generichash: (len, m, key) => u8(N.crypto_generichash(len, m, key)),
    crypto_sign_detached: (m, sk) => u8(N.crypto_sign_detached(m, sk)),
    crypto_sign_verify_detached: (sig, m, pk) => N.crypto_sign_verify_detached(sig, m, pk),
    ml_dsa65_verify_detached: (sig, m, pk) => N.ml_dsa65_verify_detached(sig, m, pk),
    crypto_scalarmult: (sk, pk) => {
      const r = N.crypto_scalarmult(sk, pk);
      if (r === null) throw new Error("crypto_scalarmult: unexpected result of the multiplication");
      return u8(r);
    },
    crypto_aead_chacha20poly1305_ietf_encrypt: (m, ad, _nsec, npub, key) =>
      u8(N.crypto_aead_chacha20poly1305_ietf_encrypt(m, ad, npub, key)),
    crypto_aead_chacha20poly1305_ietf_decrypt: (_nsec, c, ad, npub, key) => {
      const r = N.crypto_aead_chacha20poly1305_ietf_decrypt(c, ad, npub, key);
      if (r === null) throw new Error("crypto_aead_chacha20poly1305_ietf_decrypt: verification failed");
      return u8(r);
    },
    crypto_sign_keypair: () => kp(N.crypto_sign_keypair()),
    crypto_sign_seed_keypair: (seed) => kp(N.crypto_sign_seed_keypair(seed)),
    randombytes_buf: (n) => u8(N.randombytes_buf(n)),
  };
}

/** This target's `sodium`, exported so native tests drive the production wrapper. */
export const sodium: NativeSodium = wrapNativeSodium(__sodium);

/** Go's synchronous `fs.*` primitive (native/fs.go); `fs` below adapts it to the async
 *  `Fs` seam. */
declare const __fs: {
  /** Open the operator's `--dir`. Until then the store reads empty and refuses writes. */
  open(dir: string): void;
  get(key: string): ArrayBuffer | null;
  put(key: string, bytes: Uint8Array): void;
  size(key: string): number;
  /** `\n`-joined, to avoid an engine call per key; keys cannot contain `\n`. */
  list(prefix?: string): string;
  delete(key: string): boolean;
  stat(): { used: number; available: number };
};

/** The async `Fs` seam over `__fs`; `async` so a Go throw becomes a rejection. Exported for
 *  the native tests. */
export const fs: Fs = {
  async get(key) { const r = __fs.get(key); return r === null ? null : new Uint8Array(r); },
  async put(key, bytes) { __fs.put(key, bytes); },
  async size(key) { return __fs.size(key); },
  // An empty listing arrives as "", which must map to [] — split would yield [""].
  async list(prefix) { const s = __fs.list(prefix); return s === "" ? [] : s.split("\n"); },
  async delete(key) { return __fs.delete(key); },
  // Go's -1 becomes the seam's own sentinel.
  async stat() { const s = __fs.stat(); return { used: s.used, available: s.available === -1 ? FS_AVAILABLE_UNKNOWN : s.available }; },
};

/** Go's raw byte-stream primitives (§12.1). */
declare const __net: {
  /** Install host-owned socket limits before any channel can be opened. */
  install(maxLiveChannels: number, closeGraceMs: number,
    maxInboundReadBytes: number, maxInboundReadSlices: number): void;
  /** Open an outbound byte duplex (id never 0) that buffers pre-connect sends. */
  connect(host: string, port: number): number;
  /** Bind a listener and return its port; a failure throws the OS's reason. */
  listen(host: string, port: number): number;
  /** Queue bytes for the writer goroutine; admission already happened in the driver. */
  send(id: number, bytes: Uint8Array): void;
  /** Bytes queued for the writer goroutine but not yet handed to the socket. */
  buffered(id: number): number;
  /** Release the next socket read after one serialized transport-realm invocation. */
  resume(id: number): void;
  /** A deliberate close — never fires `__netClosed` (Go closes silently). */
  close(id: number, graceful?: boolean): void;
  closeListeners(): void;
};

// Policy values cross once; Go enforces the ones that act before JS sees a socket.
__net.install(DEFAULT_MAX_RAW_LINKS, TCP_LINGER_MS,
  MAX_INBOUND_HOLD_BYTES, MAX_INBOUND_HOLD_SLICES);

// ── the RawLink shaping ─────────────────────────────────────────────────────
// Go's reader goroutines route deliveries through the three dispatchers at the end of this
// block, retained by Go after the bundle evaluates (netHost.retain).

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
    // Go spends a one-read token before delivering, so only the true edge crosses.
    setReadable: (enabled) => { if (enabled) __net.resume(id); },
    onData: (cb) => { onData = cb; },
    onClose: (cb) => { onClose = cb; },
    // A local close never fires __netClosed, so drop the entry here.
    close: (graceful) => { __net.close(id, graceful); netChans.delete(id); },
  };
}

function netConnectRaw(host: string, port: number): RawLink {
  return makeGoLink(__net.connect(host, port));
}

function netListenRaw(host: string, port: number, onAccept: (s: RawLink) => void): number {
  const bound = __net.listen(host, port);
  netAccepts.set(bound, (id, remoteAddr) => onAccept(makeGoLink(id, remoteAddr)));
  return bound;
}

function netCloseListeners(): void {
  __net.closeListeners();
  // Every accept closure is stale now; clearing them releases their graphs.
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

// Defined when the bundle evaluates; Go retains them afterwards (netHost.retain).
globalThis.__netDeliver = (id, bytes) => { const c = netChans.get(id); if (c) c.deliver(new Uint8Array(bytes)); };
globalThis.__netClosed = (id) => { const c = netChans.get(id); if (c) c.closed(); };
globalThis.__netAccept = (port, id, remoteAddr) => { const a = netAccepts.get(port); if (a) a(id, remoteAddr); };

// ── The platform ─────────────────────────────────────────────────────────────
/** A deadline as the bridge carries it: `Infinity` → -1, omitted → the shared default. */
const bridgeMs = (ms: number | undefined): number =>
  ms === undefined ? DEFAULT_GUEST_DEADLINE_MS : ms === Infinity ? -1 : ms;

/** Private module values over opaque Go slot handles. */
let moduleSlotSeq = 0;
const modules: PureModuleLoader = {
  build(mods) {
    const slot = `slot:${++moduleSlotSeq}`;
    bridge.buildModules(slot, mods, DEFAULT_SCRATCH_SIZE, DEFAULT_GUEST_DEADLINE_MS);
    return {
      call(module, payload, deadlineMs) {
        // Synchronous, so the wall clock around it is the module's own compute.
        const t0 = monotonicMs();
        const r = bridge.callModule(slot, module, payload, bridgeMs(deadlineMs));
        return Promise.resolve({
          bytes: r === null ? null : new Uint8Array(r),
          ms: monotonicMs() - t0,
        });
      },
      dispose() { bridge.disposeModules(slot); },
    };
  },
};
/** `CliFiles` over Go's file seam. A read throws for anything but a missing file; a write
 *  throws when it did not land, which `FreshnessMarks` relies on to roll back. */
const files: CliFiles = {
  readFile(path) {
    const r = bridge.readFile(path);
    return r === null ? null : new Uint8Array(r);
  },
  writeFile(path, bytes, mode) { bridge.writeFile(path, bytes, mode ?? 0); },
};
/** The driver's ChannelFactory over Go's sockets, shaped like the node:net one. */
const channels: ChannelFactory = {
  // Go has no TLS socket here, so `wss://` is unroutable (§12.1).
  connect: (dest) => {
    const d = parseDest(dest);
    if (!d || d.scheme === "wss")
      return null;
    return netConnectRaw(d.host, d.port);
  },
  listen: (addrs, onAccept) => Promise.resolve(addrs.map((a) =>
    netListenRaw(a.host, a.port, (s) => onAccept(s, { listener: a.label })))),
  // Close the bound listeners (and, in Go, their accept goroutines) on teardown.
  close: () => { netCloseListeners(); },
};
/** This target's realm factory (§12.3): a zero-authority quickjs-ng realm on Go's event
 *  loop, the same `Realm` contract as safe-js.ts. Promise plumbing stays here, so Go needs
 *  no promise primitive. guest.go enforces the deadline with QuickJS's interrupt handler,
 *  so an overrun throws inside the guest and the realm survives. */
const createRealm: RealmFactory = async ({ source, hostCall, memoryLimitBytes, deadlineMs, ownTurns }) => {
  // Wall-clock custody (§12.3), one queue per tier.
  const deadlines = createRealmDeadlines();
  // Still 0 while top-level code runs; safe, since settlement is a host-realm microtask
  // that cannot run before the assignment below.
  let realm = 0;
  const causalContext = new CausalContext();
  // Go owns the execution clock and admitted the call before copying it, so this adapter
  // only routes and settles. No spend record: a native module runs inside the guest's
  // segment and guest.go has already billed it.
  const nativeCall: NativeHostCall = (name, payload, callId, deadlineMs) => {
    const causalClock = causalContext.current;
    const budget = new CallBudget(deadlineMs < 0 ? Infinity : deadlineMs, causalClock, undefined);
    // A synchronous throw is a refused name; guest.go releases the admitted call.
    const answer = hostCall(name, new Uint8Array(payload), budget);
    settleByDeadline(deadlines.hostCall, budget.remainingMs, answer, HOST_CALL_LATE, (bytes, error) =>
      causalContext.run(causalClock, () => {
        const elapsedNs = bridge.realmSettle(realm, callId, bytes,
          bytes === null ? errMessage(error) : null, budget.detached ? 1 : 0);
        causalClock?.charge(elapsedNs / 1_000_000);
      }));
    return null;
  };
  try {
    realm = bridge.createRealm(source, nativeCall, memoryLimitBytes ?? DEFAULT_REALM_MEMORY_BYTES,
      bridgeMs(deadlineMs),
      DEFAULT_MAX_OUTSTANDING_HOST_CALLS, DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES);
  } catch (err) {
    // No Realm is returned to own deadlines its top level armed, so end them here.
    deadlines.disarmAll();
    throw err;
  }
  const configuredDeadlineMs = deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
  let invocationSeq = 0;
  let disposed = false;
  return {
    // Serialized in shared TS (realm-queue.ts) so both targets agree on entry order.
    call: serializeCalls(
      deadlines.entry,
      (payload: Uint8Array, handoffDeadlineMs: number, causalClock?: CausalClock) => {
        // The executor runs synchronously, so `deferred` is set before the return.
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
            // Callers get the shared `REALM_DISPOSED` wording.
            (msg: string) => reject(new Error(disposed ? REALM_DISPOSED : msg)),
            bridgeMs(handoffDeadlineMs)));
          // `elapsedNs * 2 | deferred` — see the bridge declaration above.
          deferred = report % 2 === 1;
          causalClock?.charge(Math.floor(report / 2) / 1_000_000);
        });
        return {
          result,
          deferred,
          // realmCancel drops the callbacks without calling them, so reject here.
          cancel: (reason) => { bridge.realmCancel(realm, callId); fail(reason); },
        };
      },
      () => (disposed ? new Error(REALM_DISPOSED) : null),
      configuredDeadlineMs,
      ownTurns,
    ),
    dispose: () => {
      disposed = true;
      // guest.go rejects every callback it owns before freeing anything; the host-side
      // deadlines are ours to disarm.
      deadlines.disarmAll();
      bridge.realmDispose(realm);
    },
  };
};
/** Stand a node up here via `bootShell` (§12.9), for the operator flow and native tests.
 *  Go's `fs.*` serves one directory, so nodes in one realm share `cfg.dir`. The policy is
 *  parsed before anything is opened. */
async function standUp(cfg: NodeSetup): Promise<NodeRuntime> {
  const admit = policyFromJson(cfg.policyJson);
  __fs.open(cfg.dir);
  return bootShell({
    sodium, identity: cfg.identity, modules, fs, createRealm, admit,
    freshnessStore: freshnessStoreFor(files, cfg.dir),
    // The network as configured, over Go's sockets.
    transport: cfg.transport && { ...cfg.transport, channels },
    guestDeadlineMs: cfg.guestDeadlineMs,
    realmMemoryBytes: cfg.realmMemoryBytes,
  });
}

// ── the operator flow ────────────────────────────────────────────────────────
/** This platform as `cli.ts` needs it; every decision is cli.ts's. */
function nativeCliHost(): CliHost {
  return {
    ...files,
    banner: "seedkernel-native",
    argv: JSON.parse(bridge.argv()) as string[],
    log(line) { bridge.log(line); },
    stdout(bytes) { bridge.stdout(bytes); },
    stdin() { return new Uint8Array(bridge.stdin()); },
    sodium,
    standUp,
  };
}
/** Run the operator flow. Go reads back, as JSON bytes, whether to keep its loop running. */
async function runMain(): Promise<Uint8Array> {
  const { serving, close } = await runCli(nativeCliHost());
  if (!serving) close();
  return enc.encode(JSON.stringify({ serving }));
}
// What Go reaches by name; the native tests drive these same functions.
export { runMain, standUp, createRealm };
