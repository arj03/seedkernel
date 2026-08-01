// The platform-neutral shell core — the §12.9 "move one level up". Everything that
// standing a node up involves EXCEPT the parts that genuinely vary by target lives
// here: the handler table's owner, the cap-bridge wiring, the preamble assembly, the
// realm's lifecycle, the bundle load order, and the inbound dispatch. A target supplies
// the platform seam — { kernel, sodium, identity, freshnessStore, network, fs?,
// createRealm? } — exactly like NodeNetworkCore takes a ChannelFactory, and gets back a
// fully wired Shell.
//
// This is the ONE assemble path, and the assembly ORDER is the point: it is the last
// thing two hosts could disagree about, so no target restates it.
//
//   main.ts       → boot()         → KernelHost + NodeFs + FileFreshnessStore + NodeNetwork + safe-js → createShell()
//   browser       → chat-shell.js  → KernelHost + RtcNetwork + sessionStorage freshness (no realm)    → createShell()
//   native        → native-shim.ts → Go handler table + Go Fs + Go channels + Go realm                → createShell()
//   seedstore     → StorageNode    → { MemoryFs, Network, FreshnessMarks }                            → createShell() + loadBundle(seedstore.skb)
//
// installWasmHandler is not public API on the Shell and there is no raw-bind path — the
// only way code lands is via a signed bundle (§12.4), making the §3.1 claim structurally
// true instead of true-by-convention.

import { denyAll, type AdmitPredicate } from "./policy.js";
import {
  kernelNameFor, appKeyFor, appScopeFor, handlesOf, entryModuleOf, verifyBundle, installBundle,
  type BundleCrypto, type BundleHost, type FreshnessStore, type LoadedBundle, type VerifiedBundle,
} from "./bundle.js";
import { Transport, type Network, type PeerId } from "./net.js";
import { createCapBridge, capPreamble, bundlePreamble, opsForCaps, guestSignScope, type CapSodium } from "./cap-bridge.js";
import { Bindings } from "./bindings.js";
// safe-js is imported for its *types* only — it is the JS platform's realm factory, not
// this module's. The QuickJS engine it wraps is a heavy wasm module with bare-specifier
// imports; a target that runs guests passes `createRealm` (main.ts loads safe-js lazily
// behind it), and a handler-only shell passes none and never pulls the engine into its
// module graph at all. That is what lets shell-core load as plain ESM in the browser —
// and what lets the native target hand in a Go-backed realm instead.
import type { SafeRealm, SafeRealmBridge } from "./safe-js.js";
import { scopedFs, type Fs } from "./fs.js";
import { toHex, fromHex } from "./util.js";

/** The crypto surface the shell needs: manifest verification + genesis hashing
 *  (BundleCrypto) plus the cap-bridge crypto ops (CapSodium). Any sumo libsodium
 *  build satisfies both. */
export type ShellSodium = BundleCrypto & CapSodium;

/** How a target creates the confined realm a guest runs in (§12.3). The JS platform's
 *  factory is `createSafeRealm` (safe-js.ts: QuickJS-over-wasm, driven by
 *  quickjs-emscripten's job pump); the native target's is a second quickjs-ng realm
 *  driven by Go's event loop (native/guest.go). Both honor the same contract —
 *  `call` may await net, `callSync` must not yield — so the shell drives either
 *  without knowing which it holds. */
export type RealmFactory = (opts: {
  source: string;
  bridge: SafeRealmBridge;
  memoryLimitBytes?: number;
  /** Budget of guest *execution* time per entrypoint invocation, in ms. Omitted ⇒ the
   *  factory's own default (safe-js: 5s). Both resource bounds cross this seam, so a
   *  guard a factory implements is one the shell can actually reach — `deadlineMs`
   *  existed in safe-js before this field did and was therefore dead code, since the
   *  shell is the only caller and had no way to pass it. */
  deadlineMs?: number;
}) => Promise<SafeRealm>;

/** The handler table as exposed by the Shell — everything a caller needs to
 *  reach installed handlers, WITHOUT installWasmHandler AND WITHOUT
 *  removeHandler. The bind is the bundle loader's job (§12.4); the unbind
 *  is the shell's uninstall method (§12.5). Neither install nor remove is a
 *  public host method. */
export interface KernelTable {
  callHandler(name: string, payload: Uint8Array): Uint8Array | null;
  isBound(name: string): boolean;
}

/** The §3 handler table as the shell uses it: the two install powers a bundle load
 *  needs (`BundleHost`), plus reaching and releasing what landed. A platform
 *  primitive, not shell logic — `KernelHost` is the JS implementation over
 *  `WebAssembly`, and the native target's is Go's wazero map behind its byte bridge
 *  (§12.9). The table is the same contract either way; only who owns the instances
 *  differs. */
export interface KernelBackend extends BundleHost, KernelTable {
  /** Remove every handler whose name starts with `prefix`, returning how many went.
   *  One pass is all `uninstall` needs: every kernel name of an app shares its app
   *  key as a prefix (§5.1). */
  removePrefix(prefix: string): number;
}

/** The platform seam — everything the shell needs that varies by target.
 *  `fs` is optional: handler-only shells (the browser chat-shell) need no
 *  filesystem backend. `createRealm` is optional for the same reason — absent, the
 *  shell still verifies, admits and installs a bundle's modules, but running or
 *  serving a guest throws rather than silently doing nothing. `livePeers` feeds the
 *  NET_PEERS cap — the network owns connectivity, the shell just passes the closure
 *  through to the cap-bridge. */
export interface ShellPlatform {
  sodium: ShellSodium;
  identity: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** The handler table this shell binds bundle modules into (§3). */
  kernel: KernelBackend;
  fs?: Fs;
  freshnessStore: FreshnessStore;
  network: Network;
  createRealm?: RealmFactory;
  now?: () => number;
  livePeers?: () => PeerId[];
}

/** Interactive admission callback. Runs after verifyBundle proves authenticity
 *  and integrity, before installBundle lands the modules. Return `true` to admit,
 *  `false` or throw to reject. When omitted, deny-all — nothing is admitted.
 *  This is the browser's consent seam (§12.4): the shell verifies the bundle,
 *  shows the author + manifest to the user, and only installs once the user
 *  says yes. */
export type AdmitCallback = (v: VerifiedBundle) => boolean | Promise<boolean>;

export interface CreateShellOptions {
  /** Interactive consent callback (§12.4 browser path). Runs between verify and
   *  install. When absent, deny-all — nothing is admitted. A file-backed author
   *  allowlist, a consent dialog, and "the bundle my operator handed me" are
   *  three constructors of the same predicate type (§12.5). */
  admit?: AdmitCallback;
  timeoutMs?: number;
  /** Operator-supplied app config, merged *over* the bundle manifest's `config`
   *  into the guest's `const APP = …`. Opaque to the shell. */
  config?: Record<string, string | number>;
  /** QuickJS heap limit for the guest realm, in bytes. Omitted ⇒ the safe-js
   *  default (64 MiB). A target that streams large windows through the guest raises
   *  it to run without the realm OOMing (seedstore's `realmMemoryBytes`). */
  realmMemoryBytes?: number;
  /** Budget of guest execution time per entrypoint invocation, in ms. Omitted ⇒ the
   *  realm factory's default (5s, §16.1). Counts time the guest is *running*, not time
   *  it spends parked on a host bridge, so it bounds a wedged guest without penalising
   *  one legitimately awaiting the network. `Infinity` disables it.
   *
   *  This is the operator's number, not the author's: unlike the handler memory ceiling
   *  (§4.3), which a bundle declares in its signed manifest, how long this node is
   *  willing to spend on one message is a property of the deployment. */
  guestDeadlineMs?: number;
}

export type { LoadedBundle, FreshnessStore, VerifiedBundle };
// Re-export the admission predicate constructors so a target that gates admission
// on consent (the browser) or on which bundle it was handed (a StorageNode) can
// reach them from the same module it gets createShell from. KernelHost rides along
// for the same reason: the JS platforms all hand it in as their `kernel`, and a
// re-export keeps that a one-line seam rather than a second import.
export { denyAll, admitAll, authorAllowlist, policyFromJson } from "./policy.js";
export type { AdmitPredicate } from "./policy.js";
export { Bindings } from "./bindings.js";
export { KernelHost } from "./kernel-host.js";

export interface Shell {
  /** The handler table: callHandler to reach installed handlers, isBound to
   *  check occupancy. installWasmHandler is NOT on this interface — code lands
   *  only via loadBundleBlob (§12.4). */
  host: KernelTable;
  /** Protocol bindings (§12.10): which app handles which protocol. */
  bindings: Bindings;
  net: Network;
  transport: Transport;
  /** Filesystem backend. Absent for handler-only shells. */
  fs?: Fs;
  sodium: ShellSodium;
  /** Load a signed bundle blob: verify the manifest, run the admission predicate,
   *  integrity-check + install the modules, and return the guest source. This is
   *  the §12.4 load order — the ONE install path. */
  loadBundleBlob(blob: Uint8Array): Promise<LoadedBundle>;
  /** Uninstall an app: remove every kernel handler derived from `appKey`,
   *  drop every protocol binding for it, and dispose the confined realm if
   *  this was its last app. Returns true if any handlers were removed.
   *  The one uninstall path, symmetric with loadBundleBlob (§12.5). */
  uninstall(appKey: string): boolean;
  /** Write off an author key: refuse everything it signs from now on, and uninstall
   *  every app of its already running. Returns the app keys torn down.
   *
   *  This is the remedy for a stolen author key, and it exists because the two halves
   *  are useless apart. Uninstalling alone leaves nothing to stop the thief's next
   *  bundle landing on the same derived names; refusing alone leaves the compromised
   *  code running. Neither half implies the other, so an operator doing this by hand
   *  can do half of it — which is the actual gap, not the absence of a protocol.
   *
   *  Permanent and host-local: the key stays refused across reboots and across later
   *  edits to the policy allowlist. Recovery is a new author key, which derives new
   *  names and a fresh mark (§5.1) — not an un-revoke. */
  revoke(authorHex: string): string[];
  /** Run one of a loaded bundle's guest entrypoints through a generic
   *  cap-bridge over the kernel's primitives. `appKey` defaults to the
   *  only loaded app; throws when more than one is loaded and no key is
   *  given. Throws for handler-only bundles (no guest source). */
  runGuest(entry: string, payload: Uint8Array, appKey?: string): Promise<Uint8Array>;
  /** Dispatch inbound request to the right app via protocol bindings (§12.10).
   *  For a guest app: calls the confined realm's `handle` synchronously.
   *  For a handler-only app: calls the kernel handler with senderPk ‖ payload.
   *  Returns the response bytes, or null if no bound app handles the protocol. */
  dispatch(from: PeerId, proto: string, payload: Uint8Array): Uint8Array | null;
  /** Wire transport.onRequest to the shell's dispatch. After this, every
   *  inbound frame resolves through the bindings table to its app (§12.10). */
  serve(): Promise<void>;
  close(): void;
}

/** One installed app. A handler-only app has no realm. */
interface AppSlot {
  loaded: LoadedBundle;
  realm: SafeRealm | null;
  /** Kernel handler name for handler-only dispatch — the manifest's declared `entry`
   *  module (§12.10), resolved once at load by `entryModuleOf`. Empty for a guest app,
   *  which dispatches itself. */
  handleName: string;
}

/** Assemble the platform-neutral shell. Every target calls this instead of
 *  re-implementing the kernel host, cap-bridge wiring, preamble assembly, realm
 *  creation, and transport routing. */
export function createShell(opts: CreateShellOptions & { platform: ShellPlatform }): Shell {
  const { platform } = opts;
  const sodium = platform.sodium;
  const host = platform.kernel;
  const bindings = new Bindings();

  const admit = opts.admit ?? denyAll;

  const peerId = toHex(platform.identity.publicKey);
  const transport = new Transport(peerId, platform.network, opts.timeoutMs ?? 2000);
  const livePeers = platform.livePeers ?? (() => []);

  const apps = new Map<string, AppSlot>();
  // The tail of every initiator `runGuest` call. close() defers realm disposal onto
  // this so a call parked mid-await (a repair pass waiting out an unreachable peer)
  // is never resumed into a freed realm — a QuickJS use-after-free (§2.1).
  let inFlight: Promise<unknown> = Promise.resolve();

  /** The one app that was loaded, when exactly one is installed. Throws when zero
   *  or multiple apps are present, so callers that omit an explicit appKey get a
   *  clear error rather than silent ambiguity. */
  const onlyApp = (): AppSlot => {
    if (apps.size === 0) throw new Error("shell: load a bundle first (loadBundleBlob)");
    if (apps.size > 1) throw new Error("shell: multiple apps loaded — supply appKey");
    return [...apps.values()][0];
  };

  /** The confined realm for `slot`, created lazily on first use through the
   *  platform's factory. Both roles share it: the async initiator (`runGuest` →
   *  realm.call) and the synchronous holder (`dispatch` → realm.callSync), so the
   *  holder can answer re-entrantly while an initiator is parked mid-await in the
   *  same realm (§2.1). Lazy because the JS factory pulls in a heavy engine, and
   *  because a node may serve for a long time before its first guest call. */
  const ensureRealm = async (slot: AppSlot): Promise<SafeRealm> => {
    if (slot.realm) return slot.realm;
    if (!platform.createRealm) {
      throw new Error("shell: this platform supplies no createRealm — it can install handler modules but not run a guest");
    }
    slot.realm = await platform.createRealm({
      source: guestFullSource(slot.loaded),
      bridge: buildBridge(slot.loaded),
      memoryLimitBytes: opts.realmMemoryBytes,
      deadlineMs: opts.guestDeadlineMs,
    });
    return slot.realm;
  };

  const buildBridge = (b: LoadedBundle): SafeRealmBridge => {
    const caps = new Set(b.manifest.guest?.caps ?? []);
    const modMap = Object.fromEntries(b.manifest.modules.map((m) => [m.name, kernelNameFor(b.author, b.manifest.app, m.name)]));
    return createCapBridge({
      sodium: platform.sodium,
      identity: platform.identity,
      callHandler: (name, p) => host.callHandler(name, p),
      transport, peers: livePeers,
      // Scoped to this app key, so `fs` grants reach over this app's own keyspace and
      // not the node's (fs.ts). Two admitted apps can no longer read, enumerate or
      // delete each other's data, which brings `fs` into line with the structural
      // ownership kernel names already have (§5.1).
      fs: caps.has("fs") && platform.fs
        ? scopedFs(platform.fs, appScopeFor(platform.sodium, b.author, b.manifest.app))
        : undefined,
      now: platform.now ?? (() => Date.now()),
      allowedOps: opsForCaps(caps),
      signScope: guestSignScope(b.author, b.manifest.app),
      modules: modMap,
    });
  };

  const guestFullSource = (b: LoadedBundle): string =>
    capPreamble()
    + bundlePreamble({
      app: b.manifest.app,
      author: b.author,
    })
    + `const APP = ${JSON.stringify({ ...(b.manifest.guest?.config ?? {}), ...(opts.config ?? {}) })};\n`
    + b.guestSource;

  const hasGuest = (b: LoadedBundle): boolean => b.guestSource.length > 0;

  const doUninstall = (appKey: string): boolean => {
    const removed = host.removePrefix(appKey + ":");
    bindings.removeApp(appKey);
    const slot = apps.get(appKey);
    if (slot) {
      slot.realm?.dispose();
      apps.delete(appKey);
    }
    return removed > 0;
  };

  const doDispatch = (from: PeerId, proto: string, payload: Uint8Array): Uint8Array | null => {
    const key = bindings.boundApp(proto);
    if (!key) return null;
    const slot = apps.get(key);
    if (!slot) return null;
    if (hasGuest(slot.loaded)) {
      if (!slot.realm) return null; // realm not yet created — serve() must be called first
      const senderBytes = fromHex(from);
      const input = new Uint8Array(senderBytes.length + payload.length);
      input.set(senderBytes, 0);
      input.set(payload, senderBytes.length);
      return slot.realm.callSync("handle", input);
    }
    if (!slot.handleName) return null;
    const senderBytes = fromHex(from);
    const input = new Uint8Array(senderBytes.length + payload.length);
    input.set(senderBytes, 0);
    input.set(payload, senderBytes.length);
    return host.callHandler(slot.handleName, input);
  };

  return {
    host,
    bindings,
    net: platform.network,
    transport,
    fs: platform.fs,
    sodium,
    async loadBundleBlob(blob) {
      const v = verifyBundle(sodium, blob);
      // Revocation before `admit`, not just inside installBundle. The predicate is
      // where an interactive shell puts its consent dialog (§12.4), so asking it
      // first would show a user the author and metadata of a bundle this host has
      // already decided to refuse, take their approval, and only then fail. A written-
      // off key should never reach the prompt. The check in installBundle stays as the
      // backstop for callers that reach it another way.
      if (platform.freshnessStore.isRevoked(v.author)) {
        throw new Error(`bundle: author ${toHex(v.author)} is revoked on this host — refusing ${v.manifest.app} v${v.manifest.version}`);
      }
      const ok = await admit(v);
      if (!ok) throw new Error("bundle: rejected by admission predicate");
      const loaded = installBundle(host, v, platform.freshnessStore);
      const key = appKeyFor(loaded.author, loaded.manifest.app);
      bindings.autoBind(key, handlesOf(loaded.manifest));
      // Which module receives inbound traffic is the manifest's `entry`, not the first
      // array element (§12.10). entryModuleOf throws on an ambiguous manifest, so the
      // load fails loudly rather than binding traffic to an arbitrary module.
      const entry = entryModuleOf(loaded.manifest);
      const handleName = entry ? kernelNameFor(loaded.author, loaded.manifest.app, entry) : "";
      apps.set(key, { loaded, realm: null, handleName });
      return loaded;
    },
    uninstall: doUninstall,
    revoke(authorHex) {
      const hex = authorHex.toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(hex)) {
        throw new Error(`shell: revoke expects a 64-character hex author key, got ${JSON.stringify(authorHex)}`);
      }
      // Persist FIRST, then tear down. The other order leaves a window in which the
      // apps are gone but nothing refuses the key, and the case this exists for is a
      // key that is actively publishing.
      platform.freshnessStore.revoke(fromHex(hex));
      const gone: string[] = [];
      for (const appKey of [...apps.keys()]) {
        // Every kernel name of an app begins with its author (§5.1), so one prefix
        // test finds every app this key ever landed — including ones this shell
        // loaded before the key went bad.
        if (appKey.startsWith(hex + ":")) { doUninstall(appKey); gone.push(appKey); }
      }
      return gone;
    },
    async runGuest(entry, payload, appKey) {
      const slot = appKey ? apps.get(appKey) : onlyApp();
      if (!slot) throw new Error(`shell: no app '${appKey}' loaded`);
      if (!hasGuest(slot.loaded)) throw new Error("shell: no guest source — this is a handler-only bundle");
      const r = await ensureRealm(slot);
      const call = r.call(entry, payload);
      inFlight = inFlight.then(() => call, () => call).catch(() => {});
      return call;
    },
    dispatch: doDispatch,
    async serve() {
      for (const slot of apps.values()) {
        if (hasGuest(slot.loaded)) await ensureRealm(slot);
      }
      transport.onRequest((from, proto, payload) => {
        return doDispatch(from, proto, payload);
      });
    },
    close() {
      transport.close();
      const dispose = () => {
        for (const slot of apps.values()) { slot.realm?.dispose(); }
        apps.clear();
      };
      inFlight.then(dispose, dispose);
    },
  };
}
