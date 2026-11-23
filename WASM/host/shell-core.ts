// Platform-neutral shell (§12.8). `bootShell` is the one assembly path: defaults, the slot
// table, load order, and which host services this node offers. Targets only swap platform
// members; signed bundles are the only way to fill a slot (§12.4).
import { denyAll, checkHostGates, type Admit } from "./policy.js";
import { appScopeFor, FreshnessMarks, genesisHash, reachesLink, verifyBundle, loadBundleModules, type FreshnessStore, type JsonObject, type LoadedBundle, type ManifestVerifier, type PureModuleLoader, type PureModules } from "./bundle.js";
import { createGuestSeam, GUEST_ENTRYPOINTS, KIND_ENTRYPOINTS, type SeamCrypto, type HostCall, type LocalCall } from "./guest-seam.js";
import { createSlotTable } from "./slot-table.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES, DEFAULT_MAX_OUTSTANDING_HOST_CALLS, DEFAULT_REALM_MEMORY_BYTES } from "./wasm-limits.js";
import { concatBytes, enc, fromHex, toHex, isHex64, isRecord, errMessage, EMPTY, CALLER_APP, CALLER_PEER, HOST_CALLER } from "./util.js";
import { sendProtocol } from "./op-frame.js";
import { type CausalClock, type Realm, type RealmFactory } from "./realm-queue.js";
import type { Keypair } from "./subkeys.js";
// The host services: `identity` and `timer` on every node, the others where offered.
import { identityService, lazyHybridKey, slotSignScope } from "../services/identity.js";
import type { MlDsa65Signer } from "./pq.js";
import { createRealmTimers, timerService, type RealmTimers } from "../services/timer.js";
import { fsService, scopedFs, validatedFs, type Fs } from "../services/fs.js";
import { linkService, TransportHost, type LinkBackend, type TransportHostOptions } from "../services/link.js";
import { hostService, type HostStaging } from "../services/host.js";

/** Neutral realm contracts exposed through the shell facade clients configure. */
export type { Realm, RealmOptions, RealmFactory } from "./realm-queue.js";

/** Observe a slot's own answer to a peer-inbound frame, after it resolves. */
export type InboundObserver = (claim: string, from: Uint8Array, answer: Uint8Array) => void;

/** The envelope's first byte for a peer's request; the occupant's attribution follows. */
const PEER_KIND = Uint8Array.of(CALLER_PEER);

/** One installed app. `realm` is null only while the install is still building it; a
 *  slot enters the table with its realm in place. */
interface AppSlot {
  verifiedBundle: LoadedBundle;
  /** Whether it requires `link` (`reachesLink`), read once: such a slot runs its own
   *  turns, signs under the link scope, and holds apps' sends to their claims. */
  links: boolean;
  pureModules: PureModules;
  fsScope?: Fs;
  /** The label's genesis hash, the 32-byte sender a local call from this slot carries. */
  appId: Uint8Array;
  /** The fs prefix this slot's view is scoped under (`appScopeFor`). */
  appScope: string;
  realm: Realm | null;
  /** Set once the freshness mark and claims have committed; until then the seam refuses
   *  every call (`seamFor`). */
  active: boolean;
  /** Per slot, so disposing a slot cancels only its own pending wake. */
  timers: RealmTimers;
  /** This install's answer observer; a replacement carries its own or none. */
  onInbound?: InboundObserver;
}

/** Manifest verification, the guest crypto ops, and ML-DSA-65 signing for the hybrid
 *  half of `identity` (services/identity.ts). The host's crypto (sodium-engine.ts) is all
 *  three. */
export type ShellSodium = ManifestVerifier & SeamCrypto & MlDsa65Signer;

/** This installation's settings for one install: the operator's, never the author's.
 *  The guest reads `localConfig` as `LOCAL`. */
export interface InstallOptions {
  /** The slot this install replaces, by its `app` label. If absent, the candidate needs a
   *  free label. If present, it must name an installed slot, which the candidate takes
   *  over atomically, across authors and labels. After boot, this is the only way to take
   *  `link`. */
  replaces?: string;
  localConfig?: JsonObject;
  /** QuickJS heap limit for this install's realm. Falls back to the shell's
   *  `realmMemoryBytes`, then `DEFAULT_REALM_MEMORY_BYTES`; a replacement never inherits
   *  the old value. */
  realmMemoryBytes?: number;
  /** Guest execution budget per invocation for this install, in ms. Falls back to the
   *  shell's `guestDeadlineMs`, then `DEFAULT_GUEST_DEADLINE_MS`; `Infinity` disables it. */
  guestDeadlineMs?: number;
  /** Observe this slot's answer to a peer-inbound frame, so an embedder can show what its
   *  app answered. Observation only: not called for a loopback `invoke` or a cross-realm
   *  call, and anything it throws is logged and ignored. */
  onInbound?: InboundObserver;
}

export interface Shell {
  /** Which app serves this claim, or null (§12.10): `protocols` first, then `services`. */
  resolve(claim: string): string | null;
  /** Every claim this node serves, as `[claim, owner]`, peer-reachable first. A snapshot. */
  routes(): [string, string][];
  /** Call the realm claiming this local service id with the host's caller id; `null` when
   *  nothing claims it. Resolves `services`, never `protocols`. This is how an embedder or
   *  the CLI asks the transport to wait for a cohort, list peers, or add an address. */
  call(serviceId: string, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array> | null;
  /** Absent on a node that does not offer `fs`, which refuses a bundle requiring it at
   *  install. */
  fs?: Fs;
  sodium: ShellSodium;
  /** The only way a bundle enters this node: verify, admit, build modules, start the
   *  guest, commit the slot. An install leaves a running app or nothing; a failed
   *  candidate leaves the slot it named exactly as it was. fs and signing namespaces follow
   *  the label, not the author. */
  install(blob: Uint8Array, opts?: InstallOptions): Promise<AppHandle>;
  /** Drop the slot's claims and dispose its realm, modules and timers. Its fs keys stay. */
  uninstall(app: string): boolean;
  /** Refuse everything this author key signs from now on, and uninstall its running apps.
   *  Returns the labels torn down. Permanent and host-local. */
  revoke(authorHex: string): string[];
  close(): void;
}

/** What an install returns: verified facts plus a slot-bound handle (§12.4). */
export interface AppHandle extends LoadedBundle {
  /** This app's fs view, already scoped. Absent on a node that does not offer `fs`. */
  fs?: Fs;
  /** The fs prefix this app's view is scoped under (`appScopeFor`), for reading the raw
   *  backend directly with `scopedFs(raw, appScope)`. */
  appScope: string;
  /** Loopback invoke into the slot this install created. Rejects once that slot is
   *  disposed, including by a replacement, which returns its own handle. */
  invoke(payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array>;
}

// Re-exported so a target gets admission constructors and the fs view from the same module
// as bootShell.
export { denyAll, admitAll, authorAllowlist, policyFromJson, type Admit } from "./policy.js";
export { scopedFs } from "../services/fs.js";

/** The host services this node offers beyond `identity` and `timer`, which every node has
 *  (§12.2). One left out is not offered: a bundle requiring it does not install. A relay
 *  is `{ transport }`, a node with no network `{ fs }`. */
export interface NodeServices {
  /** The store behind `fs`. Each app reaches only its own scope of it. */
  fs?: Fs;
  /** The sockets and the signed transport that occupies `link` (§12.6): given, the node
   *  offers `link` and installs the transport at boot. The object is kept, so live
   *  accessors keep working. */
  transport?: TransportOptions;
  /** The loader's host slots behind `host` (§12.9). */
  host?: HostStaging;
}

/** This node's network (§12.6). */
export interface TransportOptions extends TransportHostOptions {
  /** The signed transport to install at boot; selecting it authorizes `link`. A host's
   *  `standUp` defaults it to its blob's transport (platform.ts). */
  bundle?: Uint8Array;
  /** Installation-local configuration for the initial transport. */
  config?: JsonObject;
  /** Called each time the transport's standing changes, with its `link/status` bytes
   *  (§12.2), in the transport's own format. */
  onStatus?: (status: Uint8Array) => void;
}

/** Assembly options (§12.8). Everything except `sodium` and `identity` has a default;
 *  `services` defaults to none. */
export interface BootShellOptions {
  /** Core libsodium with the ML-DSA-65 verifier mixed in. */
  sodium: ShellSodium;
  /** The node's keypair: its public half is the peer id every realm reads as
   *  `HOST.identity`; the handshake and `identity/sign` both sign with it, and the
   *  ML-DSA-65 half of `identity/sign-hybrid` derives from it. */
  identity: Keypair;
  /** Admission for ordinary apps; deny-all when absent. `link` is authorized only by boot
   *  selection or by replacing its holder. Host gates apply to every bundle. */
  admit?: Admit;
  services?: NodeServices;
  /** Persisted bundle-freshness store (§12.4). Default: in-memory `FreshnessMarks`. */
  freshnessStore?: FreshnessStore;
  /** Builder for a bundle's private modules (§4). Default: the worker-backed `ModuleTable`. */
  modules?: PureModuleLoader;
  /** Confined realm factory (§12.3). Default: realms on WebAssembly (engine-web.ts), imported
   *  lazily. */
  createRealm?: RealmFactory;
  /** Default guest budget per invocation, in ms (`DEFAULT_GUEST_DEADLINE_MS`); `Infinity`
   *  disables the local ceiling. The operator's number, not the author's. */
  guestDeadlineMs?: number;
  /** Default QuickJS heap limit per realm (`DEFAULT_REALM_MEMORY_BYTES`); an install
   *  overrides it with `InstallOptions.realmMemoryBytes`. */
  realmMemoryBytes?: number;
}

export interface BootResult {
  shell: Shell;
  /** The channel adapter the platform drives (listeners, ports); the same object the shell
   *  holds. Null only on a node with no network. */
  transport: TransportHost | null;
}

/** Boot a node and install the selected signed transport through the shared installer. */
export async function bootShell(opts: BootShellOptions): Promise<BootResult> {
  /** One install's realm bounds: its own, else the node's, else the shared default.
   *  Checked here because an out-of-range value would silently lift a bound: a heap limit
   *  that truncates to 0 is no limit to the engine, nor is one of 2^32 or more on its
   *  32-bit memory, and a budget of 0 turns off the wake's pacing (services/timer.ts). */
  const boundsFor = (load: InstallOptions): { deadlineMs: number; memoryBytes: number } => {
    const deadlineMs = load.guestDeadlineMs ?? opts.guestDeadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
    const memoryBytes = load.realmMemoryBytes ?? opts.realmMemoryBytes ?? DEFAULT_REALM_MEMORY_BYTES;
    if (!(deadlineMs >= 1)) {
      throw new Error(`shell: guestDeadlineMs must be at least 1 ms, or Infinity (got ${deadlineMs})`);
    }
    if (!(memoryBytes >= 1 && memoryBytes < 2 ** 32)) {
      throw new Error(`shell: realmMemoryBytes must be at least 1 and below 2^32 (got ${memoryBytes})`);
    }
    return { deadlineMs, memoryBytes };
  };
  // A bad node-wide default fails the boot instead of every later install.
  boundsFor({});
  const sodium = opts.sodium;
  const offered = opts.services ?? {};
  // The one place the key rule is applied to a target's backend (`validatedFs`).
  const fs = offered.fs && validatedFs(offered.fs);
  // JS-target defaults are imported lazily so the native binary never loads them.
  const moduleLoader = opts.modules ?? new ((await import("./module-table.js")).ModuleTable)();
  const createRealm = opts.createRealm
    ?? (async (o) => (await import("./engine-web.js")).createWebRealm(o));
  const freshnessStore = opts.freshnessStore ?? new FreshnessMarks();
  const net = offered.transport;
  const netHost = net ? new TransportHost(net) : null;
  const appAdmit = opts.admit ?? denyAll;
  let closed = false;

  const table = createSlotTable<AppSlot>();
  /** A slot for `loaded`, without its realm yet. The wake reads `slot.realm` when it
   *  fires, so it enters whichever realm is there then. */
  const newSlot = (loaded: LoadedBundle, appId: Uint8Array, pureModules: PureModules,
    load: InstallOptions, deadlineMs: number): AppSlot => {
    let slot: AppSlot;
    const timers = createRealmTimers(
      // A host event under the host's caller id. There is no caller to reject to, so an
      // error is logged. The promise is returned because it gates the next wake
      // (services/timer.ts).
      (input, causalClock) => slot.realm!.call(input, undefined, causalClock).catch((err: unknown) => {
        console.error(`[shell] guest error in timer: ${errMessage(err)}`);
      }),
      deadlineMs,
    );
    const appScope = appScopeFor(appId);
    slot = {
      verifiedBundle: loaded,
      appId,
      links: reachesLink(loaded.manifest),
      pureModules,
      fsScope: fs ? scopedFs(fs, appScope) : undefined,
      appScope,
      realm: null,
      active: false,
      timers,
      onInbound: load.onInbound,
    };
    return slot;
  };
  /** Cancel the wake, then dispose the realm and modules. Every teardown path uses this. */
  const disposeSlot = (slot: AppSlot | undefined) => {
    if (!slot) return;
    slot.active = false;
    slot.timers.clearAll();
    slot.realm?.dispose();
    slot.pureModules.dispose();
  };
  /** A preamble constant built with JSON.parse instead of an object literal, so a
   *  `__proto__` key stays data. */
  const jsonPreamble = (name: string, value: JsonObject): string => {
    const json = JSON.stringify(value);
    return `const ${name} = JSON.parse(${JSON.stringify(json)});\n`;
  };
  /** Create one candidate realm. It stays out of the table until this and the freshness
   *  write both succeed. */
  const standRealm = async (slot: AppSlot, localConfig: JsonObject,
    bounds: { deadlineMs: number; memoryBytes: number }): Promise<void> => {
    const b = slot.verifiedBundle;
    const appConfig = b.manifest.guest.config ?? {};
    // The host's facts (§12.3): the key `identity/sign` signs with, and the budgets the realm
    // is held to, so a guest can pace its fan-out and settle a wait before its deadline.
    const hostFacts: JsonObject = {
      identity: toHex(opts.identity.publicKey),
      maxOutstandingHostCalls: DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
      maxOutstandingHostCallBytes: DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
      deadlineMs: bounds.deadlineMs === Infinity ? null : bounds.deadlineMs,
    };
    slot.realm = await createRealm({
      source: jsonPreamble("HOST", hostFacts) + jsonPreamble("APP", appConfig)
        + jsonPreamble("LOCAL", localConfig) + b.guestSource,
      hostCall: seamFor(slot),
      memoryLimitBytes: bounds.memoryBytes,
      deadlineMs: bounds.deadlineMs,
      // The link occupant writes state every caller shares, so its turns are its own.
      ownTurns: slot.links,
    });
  };
  /** Refuse a guest whose entrypoints cannot serve what its manifest claims (§12.3): a
   *  peer reaches it only at `onPeer`, the host's events and the embedder only at `onHost`,
   *  and a service is answered at `onApp` (another app) or `onHost` (the embedder's
   *  `Shell.call`). The preamble answers which are defined, without running guest code. */
  const checkEntrypoints = async (slot: AppSlot): Promise<void> => {
    const mask = (await slot.realm!.call(Uint8Array.of(KIND_ENTRYPOINTS)))[0] ?? 0;
    const has = (name: (typeof GUEST_ENTRYPOINTS)[number]) => (mask & (1 << GUEST_ENTRYPOINTS.indexOf(name))) !== 0;
    const m = slot.verifiedBundle.manifest;
    const missing: string[] = [];
    if (mask === 0) missing.push("entrypoint at all (onHost, onPeer or onApp)");
    if ((m.protocols ?? []).length > 0 && !has("onPeer")) missing.push("onPeer, which peers reach its protocols at");
    if ((m.services ?? []).length > 0 && !has("onApp") && !has("onHost")) {
      missing.push("onApp or onHost, which its services are answered at");
    }
    if (m.guest.requires.some((r) => r === "link" || r === "timer") && !has("onHost")) {
      missing.push("onHost, which the host's events arrive at");
    }
    if (missing.length > 0) throw new Error(`bundle: ${m.app}'s guest defines no ${missing.join(", and no ")}`);
  };
  /** Enter a committed slot as `caller`, the envelope's `[kind u8][caller 32]`, with
   *  `body`. Host events the host frames itself (a wake, a link event) and a peer request
   *  enter through `realm.call` directly. */
  const enter = (slot: AppSlot, caller: Uint8Array, body: Uint8Array,
    deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array> =>
    slot.realm!.call([caller, body], deadlineMs, causalClock);
  /** A local service id's claimant, entered as `caller` (`HOST_CALLER`, or an app's kind
   *  and id), resolved at call time so a service installed or replaced later is found. */
  const callLocal = (caller: Uint8Array): LocalCall => (id, payload, deadlineMs, causalClock) => {
    const slot = table.localClaimant(id);
    return slot ? enter(slot, caller, payload, deadlineMs, causalClock) : null;
  };
  /** A slot's calls to the link occupant send only under the protocols it claims, as a peer's
   *  frame reaches an app only under those: the id is all that says which app a frame is for
   *  at the far end (§12.10). */
  const sendsOwn = (app: string, protocols: readonly string[], call: LocalCall): LocalCall =>
    (id, payload, deadlineMs, causalClock) => {
      const protocol = table.localClaimant(id)?.links ? sendProtocol(payload) : null;
      if (protocol !== null && !protocols.includes(protocol)) {
        throw new Error(`shell: ${app} does not claim ${JSON.stringify(protocol)}, so it may not send under it`);
      }
      return call(id, payload, deadlineMs, causalClock);
    };
  /** The `link` backend: the driver's raw links, plus peer-inbound delivery looked up in
   *  the peer book only, so a peer can never reach a `services` claim (§12.10). A refused
   *  claim and a failed handler both answer empty. */
  const link: LinkBackend | undefined = netHost ? {
    ...netHost.rawNet(),
    deliver: (claim, framed, deadlineMs, causalClock) => {
      const slot = table.peerClaimant(claim);
      if (!slot) return Promise.resolve(EMPTY);
      // Kind 1: the host says this came through a `protocols` claim, from the peer the
      // occupant attributed.
      const answer = slot.realm!.call([PEER_KIND, framed], deadlineMs, causalClock);
      const onInbound = slot.onInbound;
      if (onInbound) {
        const attribution = framed.subarray(0, 32);
        // Two-arg `.then`, so a refused frame leaves no unhandled rejection on this branch.
        answer.then((bytes) => {
          try { onInbound(claim, attribution, bytes); }
          catch (err) { console.error(`[shell] the installer's onInbound threw: ${errMessage(err)}`); }
        }, () => {});
      }
      return answer.catch(() => EMPTY);
    },
    status: (status) => {
      try { net!.onStatus?.(status); }
      catch (err) { console.error(`[shell] the embedder's onStatus threw: ${errMessage(err)}`); }
    },
  } : undefined;
  // Node-wide services share one handler set; the rest are scoped per slot.
  const linkHandlers = link && linkService(link);
  // One ML-DSA-65 key per node, derived on the first hybrid call from any slot.
  const hybridKey = lazyHybridKey(sodium, opts.identity);
  const hostHandlers = offered.host && hostService(offered.host);
  /** Wire the `host.call` seam for one slot (guest-seam.ts): only the services its bundle
   *  declares. */
  const seamFor = (slot: AppSlot): HostCall => {
    const b = slot.verifiedBundle;
    const app = table.labelOf(slot);
    const fullSeam = createGuestSeam({
      sodium,
      // The signed list, unmodified: host services and local service ids.
      requires: b.manifest.guest.requires,
      services: {
        identity: identityService(sodium, slotSignScope(opts, app, slot.links), hybridKey),
        timer: timerService(slot.timers),
        fs: slot.fsScope && fsService(slot.fsScope),
        link: linkHandlers,
        host: hostHandlers,
      },
      // An app's calls arrive as kind 2 and its id, the label hashed, so the callee knows
      // they came from this node through its `services` claim, and from which app.
      callLocal: sendsOwn(app, b.manifest.protocols ?? [], callLocal(concatBytes([Uint8Array.of(CALLER_APP), slot.appId]))),
      modules: {
        names: new Set(b.manifest.modules.map((m) => m.name)),
        call: slot.pureModules.call,
      },
    });
    // A candidate's top level runs before commit, so every seam call is refused until the
    // slot is active, and disposing a failed candidate has nothing to undo. Top level can
    // still initialize from `HOST`, `APP` and `LOCAL`.
    const seam: HostCall = (name, payload, budget) => {
      if (!slot.active) {
        throw new Error(`shell: '${name}' is refused until this bundle's installation commits`);
      }
      return fullSeam(name, payload, budget);
    };
    seam.borrows = fullSeam.borrows;
    return seam;
  };
  const doUninstall = (app: string) => {
    const slot = table.remove(app);
    if (!slot) return false;
    // With nothing holding `link`, nothing may hear its events.
    if (!table.occupant("link")) netHost?.release();
    disposeSlot(slot);
    return true;
  };

  // One code path for every install: a free label, a named replacement and the boot
  // transport differ only in their target.
  const installBundle = async (blob: Uint8Array, load: InstallOptions = {},
    bootTransport = false): Promise<AppHandle> => {
    // Round-tripped, so it is exactly what `jsonPreamble` injects; a value JSON cannot
    // carry (a cycle, a function) fails here, before any candidate code runs.
    let localConfig: JsonObject | undefined;
    try { localConfig = JSON.parse(JSON.stringify(load.localConfig ?? {})); } catch { localConfig = undefined; }
    if (!isRecord(localConfig)) throw new Error("shell: localConfig must be a JSON object");
    const bounds = boundsFor(load);
    // Resolved to the exact slot now; commit refuses if a different slot holds the label
    // by then.
    const replacement = load.replaces === undefined ? undefined : table.get(load.replaces);
    if (load.replaces !== undefined && replacement === undefined) {
      throw new Error(`shell: '${load.replaces}' is not installed, so there is nothing for this bundle to replace`);
    }
    const v = verifyBundle(sodium, blob);
    checkHostGates(v, freshnessStore);
    // Who may take `link` is decided by the slot table (boot selection or holder
    // replacement), never by the admission predicate.
    const links = reachesLink(v.manifest);
    if (bootTransport && !links) throw new Error('shell: the boot transport must require "link"');
    if (!links && !(await appAdmit(v))) throw new Error("bundle: rejected by admission predicate");
    const loaded: LoadedBundle = {
      manifest: v.manifest, author: v.author, authorKeys: v.authorKeys,
      guestSource: v.guestSource,
    };
    const checkInstallation = () => {
      if (closed) throw new Error("shell: node is closed");
      table.refuseConflicts(loaded, replacement, bootTransport);
    };
    // Refuse a conflict before the candidate's code runs; checked again at commit, since
    // another install may take a free claim in the meantime.
    checkInstallation();
    const appId = genesisHash(sodium, enc.encode(v.manifest.app));
    const pureModules = await loadBundleModules(moduleLoader, v);
    const slot = newSlot(loaded, appId, pureModules, load, bounds.deadlineMs);
    // A guest that cannot compile, or does not define the entrypoints its claims are
    // reached through, fails the install, not the first frame.
    try {
      await standRealm(slot, localConfig, bounds);
      await checkEntrypoints(slot);
      // Synchronous from here to the end, so gates, conflict check, mark and claim handover
      // cannot interleave with another install or an uninstall. The gates are checked again
      // because a newer version or a `revoke` may have arrived; admission is not re-asked.
      checkHostGates(v, freshnessStore);
      checkInstallation();
      // A mark that cannot be persisted throws after rolling back; the running slot is
      // untouched.
      freshnessStore.set(loaded.author, loaded.manifest.app, loaded.manifest.version);
    } catch (err) {
      disposeSlot(slot);
      throw err;
    }
    table.commit(slot, replacement);
    // The driver follows the `link` claim. Links are session state of the outgoing realm,
    // so they are closed, after the handover so no `linkClosed` reaches the new realm; the
    // incoming guest redials from its own config (§12.10).
    const linkHolder = table.occupant("link");
    if (linkHolder === slot) {
      netHost?.activate((input) => slot.realm!.call(input));
    } else if (!linkHolder) {
      netHost?.release();
    }
    slot.active = true;
    disposeSlot(replacement);
    const handle: AppHandle = {
      ...loaded,
      fs: slot.fsScope,
      appScope: slot.appScope,
      invoke: (payload, deadlineMs) => slot.active
        ? enter(slot, HOST_CALLER, payload, deadlineMs)
        : Promise.reject(new Error(`shell: app '${loaded.manifest.app}' slot is no longer loaded`)),
    };
    return handle;
  };

  const shell: Shell = {
    resolve(name) {
      const slot = table.owner(name);
      return slot ? table.labelOf(slot) : null;
    },
    routes: table.routes,
    call: callLocal(HOST_CALLER),
    fs,
    sodium,
    install: (blob, load) => installBundle(blob, load),
    uninstall: doUninstall,
    revoke(authorHex) {
      const hex = authorHex.toLowerCase();
      if (!isHex64(hex)) {
        throw new Error(`shell: revoke expects a 64-character hex author key, got ${JSON.stringify(authorHex)}`);
      }
      // Persist first; the other order leaves a window where the key is not refused.
      freshnessStore.revoke(fromHex(hex));
      const gone = table.all()
        .filter((slot) => toHex(slot.verifiedBundle.author) === hex)
        .map(table.labelOf);
      for (const app of gone) doUninstall(app);
      return gone;
    },
    // A disposed realm fails whatever is pending in it (§12.3).
    close() {
      closed = true;
      netHost?.close();
      for (const slot of table.clear()) disposeSlot(slot);
    },
  };

  // A failed boot returns no handle, so it tears down what it started.
  try {
    if (netHost) {
      if (!net!.bundle) throw new Error("transport: no bundle to install");
      await installBundle(net!.bundle,
        net!.config === undefined ? undefined : { localConfig: net!.config }, true);
      await netHost.start();
    }
    return { shell, transport: netHost };
  } catch (err) {
    shell.close();
    throw err;
  }
}
