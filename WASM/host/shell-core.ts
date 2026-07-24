// The platform-neutral shell core — the §12.9 "move one level up". Everything that
// boot() in main.ts does EXCEPT the Node-specific parts (NodeFs, FileFreshnessStore,
// NodeNetwork) lives here. A target supplies the platform seam — { fs?, network,
// freshnessStore, identity, sodium } — exactly like NodeNetworkCore takes a
// ChannelFactory, and gets back a fully wired Shell.
//
// This is the ONE assemble path. Every current hand-rolled shell becomes "call
// createShell with a platform and loadBundle with a blob":
//
//   main-node.ts → boot() → NodeFs + FileFreshnessStore + NodeNetwork → createShell()
//   browser       → chat-shell.js → RtcNetwork + sessionStorage freshness → createShell()
//   native        → guest.go → Go-backed Fs + Go channel factory → createShell()
//   seedstore     → StorageNode → { MemoryFs, Network, FreshnessMarks } → createShell() + loadBundle(seedstore.skb)
//
// After this, installWasmHandler is no longer public API on the Shell and the raw-bind
// path dies — the only way code lands is via a signed bundle (§12.4), making the §3.1
// claim structurally true instead of true-by-convention.

import { KernelHost } from "./kernel-host.js";
import { denyAll, type AdmitPredicate } from "./policy.js";
import {
  kernelNameFor, appKeyFor, handlesOf, verifyBundle, installBundle,
  type BundleCrypto, type FreshnessStore, type LoadedBundle, type VerifiedBundle,
} from "./bundle.js";
import { Transport, type Network, type PeerId } from "./net.js";
import { createCapBridge, capPreamble, bundlePreamble, opsForCaps, guestSignScope, type CapSodium } from "./cap-bridge.js";
import { Bindings } from "./bindings.js";
// safe-js is imported for its *types* only. The QuickJS engine it wraps is a heavy
// wasm module with bare-specifier imports, so it is loaded lazily — a dynamic
// `import()` the first time a guest actually runs (runGuest/serve). A handler-only
// shell (the browser chat demo runs no guest) therefore never pulls the engine into
// its module graph, which is what lets shell-core load as plain ESM in the browser.
import type { SafeRealm, SafeRealmBridge } from "./safe-js.js";
import type { Fs } from "./fs.js";
import { toHex, fromHex } from "./util.js";

/** The crypto surface the shell needs: manifest verification + genesis hashing
 *  (BundleCrypto) plus the cap-bridge crypto ops (CapSodium). Any sumo libsodium
 *  build satisfies both. */
export type ShellSodium = BundleCrypto & CapSodium;

/** The platform seam — everything the shell needs that varies by target.
 *  `fs` is optional: handler-only shells (the browser chat-shell) need no
 *  filesystem backend. */
export interface ShellPlatform {
  sodium: ShellSodium;
  identity: { publicKey: Uint8Array; privateKey: Uint8Array };
  fs?: Fs;
  freshnessStore: FreshnessStore;
  network: Network;
  now?: () => number;
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
  peers?: PeerId[];
  timeoutMs?: number;
  /** Operator-supplied app config, merged *over* the bundle manifest's `config`
   *  into the guest's `const APP = …`. Opaque to the shell. */
  config?: Record<string, string | number>;
  /** QuickJS heap limit for the guest realm, in bytes. Omitted ⇒ the safe-js
   *  default (64 MiB). A target that streams large windows through the guest raises
   *  it to run without the realm OOMing (seedstore's `realmMemoryBytes`). */
  realmMemoryBytes?: number;
}

/** The handler table as exposed by the Shell — everything a caller needs to
 *  reach installed handlers, WITHOUT installWasmHandler AND WITHOUT
 *  removeHandler. The bind is the bundle loader's job (§12.4); the unbind
 *  is the shell's uninstall method (§12.5). Neither install nor remove is a
 *  public host method. */
export interface KernelTable {
  callHandler(name: string, payload: Uint8Array): Uint8Array | null;
  isBound(name: string): boolean;
}

export type { LoadedBundle, FreshnessStore, VerifiedBundle };
// Re-export the admission predicate constructors so a target that gates admission
// on consent (the browser) or on which bundle it was handed (a StorageNode) can
// reach them from the same module it gets createShell from.
export { denyAll, admitAll, authorAllowlist, policyFromJson } from "./policy.js";
export type { AdmitPredicate } from "./policy.js";
export { Bindings } from "./bindings.js";

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
  readonly peers: Set<PeerId>;
  addPeer(peerId: PeerId): void;
  removePeer(peerId: PeerId): void;
  /** Load a signed bundle blob: verify the manifest, run the admission predicate,
   *  integrity-check + install the modules, and return the guest source. This is
   *  the §12.4 load order — the ONE install path. */
  loadBundleBlob(blob: Uint8Array): Promise<LoadedBundle>;
  /** Uninstall an app: remove every kernel handler derived from `appKey`,
   *  drop every protocol binding for it, and dispose the confined realm if
   *  this was its last app. Returns true if any handlers were removed.
   *  The one uninstall path, symmetric with loadBundleBlob (§12.5). */
  uninstall(appKey: string): boolean;
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
  /** Wire transport.onRequest to the shell's dispatch. An optional `onResult`
   *  receives (appKey, result) after dispatch, before bytes go on the wire —
   *  a UI shell uses this to render the result into an iframe. */
  serve(onResult?: (appKey: string | null, result: Uint8Array | null) => void): Promise<void>;
  close(): void;
}

/** One installed app. A handler-only app has no realm. */
interface AppSlot {
  loaded: LoadedBundle;
  realm: SafeRealm | null;
  /** Kernel handler name for handler-only dispatch — the first module's name. */
  handleName: string;
}

/** Assemble the platform-neutral shell. Every target calls this instead of
 *  re-implementing the kernel host, cap-bridge wiring, preamble assembly, realm
 *  creation, and transport routing. */
export function createShell(opts: CreateShellOptions & { platform: ShellPlatform }): Shell {
  const { platform } = opts;
  const sodium = platform.sodium;
  const host = new KernelHost();
  const bindings = new Bindings();

  const admit = opts.admit ?? denyAll;

  const peerId = toHex(platform.identity.publicKey);
  const transport = new Transport(peerId, platform.network, opts.timeoutMs ?? 2000);
  const peers = new Set<PeerId>(opts.peers ?? []);

  const apps = new Map<string, AppSlot>();
  let wired = false;
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

  /** The confined realm for `slot`, created lazily on first use. Both roles share
   *  it: the async initiator (`runGuest` → realm.call) and the synchronous holder
   *  (`dispatch` → realm.callSync), so the holder can answer re-entrantly while an
   *  initiator is parked mid-await in the same realm (§2.1). safe-js is imported
   *  here, lazily, so a handler-only shell never loads it. */
  const ensureRealm = async (slot: AppSlot): Promise<SafeRealm> => {
    if (slot.realm) return slot.realm;
    const { createSafeRealm } = await import("./safe-js.js");
    slot.realm = await createSafeRealm({
      source: guestFullSource(slot.loaded),
      bridge: buildBridge(slot.loaded),
      memoryLimitBytes: opts.realmMemoryBytes,
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
      transport, peers: () => [...peers],
      fs: caps.has("fs") && platform.fs ? platform.fs : undefined,
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

  const doDispatch = (from: PeerId, proto: string, payload: Uint8Array): Uint8Array | null => {
    const key = bindings.boundApp(proto);
    if (!key) return null;
    const slot = apps.get(key);
    if (!slot) return null;
    if (hasGuest(slot.loaded)) {
      if (!slot.realm) return null; // realm not yet created — serve() must be called first
      return slot.realm.callSync("handle", payload);
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
    peers,
    addPeer(p) { if (p !== peerId) peers.add(p); },
    removePeer(p) { peers.delete(p); },
    async loadBundleBlob(blob) {
      const v = verifyBundle(sodium, blob);
      const ok = await admit(v);
      if (!ok) throw new Error("bundle: rejected by admission predicate");
      const loaded = installBundle(host, v, platform.freshnessStore);
      const key = appKeyFor(loaded.author, loaded.manifest.app);
      bindings.autoBind(key, handlesOf(loaded.manifest));
      const handleName = loaded.manifest.modules.length > 0
        ? kernelNameFor(loaded.author, loaded.manifest.app, loaded.manifest.modules[0].name)
        : "";
      apps.set(key, { loaded, realm: null, handleName });
      return loaded;
    },
    uninstall(appKey) {
      const removed = host.removePrefix(appKey + ":");
      bindings.removeApp(appKey);
      const slot = apps.get(appKey);
      if (slot) {
        slot.realm?.dispose();
        apps.delete(appKey);
      }
      return removed > 0;
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
    async serve(onResult) {
      for (const slot of apps.values()) {
        if (hasGuest(slot.loaded)) await ensureRealm(slot);
      }
      wired = true;
      transport.onRequest((from, proto, payload) => {
        const result = doDispatch(from, proto, payload);
        if (onResult) {
          const appKey = bindings.boundApp(proto);
          onResult(appKey, result);
        }
        return result;
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
