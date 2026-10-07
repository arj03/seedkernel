// Platform-neutral shell (§12.8). `bootShell` is the one assembly path: defaults, the slot
// table and load order. Targets only swap platform members; signed bundles are the only
// way to fill a slot (§12.4).
import { denyAll, checkHostGates, type Admit } from "./policy.js";
import { appScopeFor, FreshnessMarks, genesisHash, isJsonObject, reachesLink, verifyBundle, loadBundleModules, type FreshnessStore, type JsonObject, type LoadedBundle, type ManifestVerifier, type PureModuleLoader, type PureModules } from "./bundle.js";
import { createGuestSeam, slotSignScope, HOST_CALLER_ID, type SeamCrypto, type HostCall, type LinkBackend, type LocalCall } from "./guest-seam.js";
import { TransportHost, type TransportHostOptions } from "./transport-host.js";
import { transportBundleBytes } from "./transport-bundle.js";
import { type Fs } from "../services/fs.js";
import { validatedFs, scopedFs } from "./fs-view.js";
import { createRealmTimers } from "./realm-timers.js";
import { createSlotTable, type AppSlot, type InboundObserver } from "./slot-table.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES, DEFAULT_MAX_OUTSTANDING_HOST_CALLS, DEFAULT_REALM_MEMORY_BYTES } from "./wasm-limits.js";
import { enc, fromHex, toHex, isHex64, errMessage, concatBytes } from "../services/util.js";
import { sendProtocol } from "../services/op-frame.js";
import { type CausalClock, type RealmFactory } from "./realm-queue.js";
import type { Keypair } from "../services/subkeys.js";

/** Neutral realm contracts exposed through the shell facade clients configure. */
export type { Realm, RealmOptions, RealmFactory } from "./realm-queue.js";

const EMPTY = new Uint8Array(0);

/** Manifest verification plus the guest crypto ops; core libsodium satisfies both. */
export type ShellSodium = ManifestVerifier & SeamCrypto;

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
  /** Absent for a node with no disk, which refuses a bundle requiring `fs` at install. */
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
  /** This app's fs view, already scoped. Absent on a shell with no fs. */
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
export { scopedFs } from "./fs-view.js";

/** This node's network (§12.6). */
export interface TransportOptions extends TransportHostOptions {
  /** The signed transport to install at boot; selecting it authorizes `link`. Defaults to
   *  the bundle shipped with the package. */
  bundle?: Uint8Array;
  /** Installation-local configuration for the initial transport. */
  config?: JsonObject;
}

/** Assembly options (§12.8). Everything except `sodium` and `identity` has a default. */
export interface BootShellOptions {
  /** Core libsodium with the ML-DSA-65 verifier mixed in. */
  sodium: ShellSodium;
  /** The node's keypair: its public half is the peer id every realm reads as
   *  `HOST.identity`; the handshake and `node/sign` both sign with it. */
  identity: Keypair;
  /** Admission for ordinary apps; deny-all when absent. `link` is authorized only by boot
   *  selection or by replacing its holder. Host gates apply to every bundle. */
  admit?: Admit;
  /** Defaults to `MemoryFs`. `false` means a node with no fs backend at all. */
  fs?: Fs | false;
  /** Persisted bundle-freshness store (§12.4). Default: in-memory `FreshnessMarks`. */
  freshnessStore?: FreshnessStore;
  /** Builder for a bundle's private modules (§4). Default: the worker-backed `ModuleTable`. */
  modules?: PureModuleLoader;
  /** Confined realm factory (§12.3). Default: the lazily imported safe-js engine. */
  createRealm?: RealmFactory;
  /** Default guest budget per invocation, in ms (`DEFAULT_GUEST_DEADLINE_MS`); `Infinity`
   *  disables the local ceiling. The operator's number, not the author's. */
  guestDeadlineMs?: number;
  /** Default QuickJS heap limit per realm (`DEFAULT_REALM_MEMORY_BYTES`); an install
   *  overrides it with `InstallOptions.realmMemoryBytes`. */
  realmMemoryBytes?: number;
  /** The sockets and signed transport (§12.6). Omitted or `false` means no network. The
   *  object is kept, so live accessors keep working. */
  transport?: TransportOptions | false;
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
   *  Checked here because the engines disagree on out-of-range values: a heap limit that
   *  truncates to 0 is unlimited on JS and refused on native, 2^32 wraps, and a budget
   *  under 1 ms is no budget on native and refused on JS. */
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
  // JS-target defaults are imported lazily so the native binary never loads them.
  const backend = opts.fs === false ? undefined : opts.fs ?? new ((await import("../services/fs-memory.js")).MemoryFs)();
  // The one place the key rule is applied to a target's backend (fs-view.ts).
  const fs = backend ? validatedFs(backend) : undefined;
  const moduleLoader = opts.modules ?? new ((await import("./module-table.js")).ModuleTable)();
  const createRealm = opts.createRealm
    ?? (async (o) => (await import("./safe-js.js")).createSafeRealm(o));
  const freshnessStore = opts.freshnessStore ?? new FreshnessMarks();
  const net = opts.transport === false ? undefined : opts.transport;
  const netHost = net ? new TransportHost(net) : null;
  const transportBlob = netHost ? (net!.bundle ?? transportBundleBytes()) : null;
  const appAdmit = opts.admit ?? denyAll;
  let closed = false;

  const table = createSlotTable();
  /** A slot for `loaded`, without its realm yet. The wake reads `slot.realm` when it
   *  fires, so it enters whichever realm is there then. */
  const newSlot = (loaded: LoadedBundle, pureModules: PureModules, load: InstallOptions,
    deadlineMs: number): AppSlot => {
    let slot: AppSlot;
    const timers = createRealmTimers(
      // A host event under the host's caller id. There is no caller to reject to, so an
      // error is logged. The promise is returned because it gates the next wake
      // (realm-timers.ts).
      (input, causalClock) => slot.realm!.call(input, undefined, causalClock).catch((err: unknown) => {
        console.error(`[shell] guest error in timer: ${errMessage(err)}`);
      }),
      deadlineMs,
    );
    const appScope = appScopeFor(sodium, loaded.manifest.app);
    slot = {
      verifiedBundle: loaded,
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
    // The host's facts (§12.3): the key `node/sign` signs with, and the budgets the realm
    // is held to, so a guest can pace its fan-out.
    const hostFacts: JsonObject = {
      identity: toHex(opts.identity.publicKey),
      maxOutstandingHostCalls: DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
      maxOutstandingHostCallBytes: DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
    };
    slot.realm = await createRealm({
      source: jsonPreamble("HOST", hostFacts) + jsonPreamble("APP", appConfig)
        + jsonPreamble("LOCAL", localConfig) + b.guestSource,
      hostCall: seamFor(slot),
      memoryLimitBytes: bounds.memoryBytes,
      deadlineMs: bounds.deadlineMs,
      // The link occupant writes state every caller shares, so its turns are its own.
      ownTurns: reachesLink(slot.verifiedBundle.manifest),
    });
  };
  /** Enter a committed slot as `caller` with `body`. Host events the host frames itself
   *  (a wake, a link event, a peer request) enter through `realm.call` directly. */
  const enter = (slot: AppSlot, caller: Uint8Array, body: Uint8Array,
    deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array> =>
    slot.realm!.call(concatBytes([caller, body]), deadlineMs, causalClock);
  /** A local service id's claimant, entered as `caller`, resolved at call time so a
   *  service installed or replaced later is found. */
  const callLocal = (caller: Uint8Array): LocalCall => (id, payload, deadlineMs, causalClock) => {
    const slot = table.localClaimant(id);
    return slot ? enter(slot, caller, payload, deadlineMs, causalClock) : null;
  };
  /** A slot's calls to the link occupant send only under the protocols it claims, as a peer's
   *  frame reaches an app only under those: the id is all that says which app a frame is for
   *  at the far end (§12.10). */
  const sendsOwn = (app: string, protocols: readonly string[], call: LocalCall): LocalCall =>
    (id, payload, deadlineMs, causalClock) => {
      const callee = table.localClaimant(id);
      const protocol = callee && reachesLink(callee.verifiedBundle.manifest) ? sendProtocol(payload) : null;
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
      const answer = slot.realm!.call(framed, deadlineMs, causalClock);
      const onInbound = slot.onInbound;
      if (onInbound) {
        const attribution = framed.subarray(0, HOST_CALLER_ID.length);
        // Two-arg `.then`, so a refused frame leaves no unhandled rejection on this branch.
        answer.then((bytes) => {
          try { onInbound(claim, attribution, bytes); }
          catch (err) { console.error(`[shell] the installer's onInbound threw: ${errMessage(err)}`); }
        }, () => {});
      }
      return answer.catch(() => EMPTY);
    },
  } : undefined;
  /** Wire the `host.call` seam for one slot (guest-seam.ts): only the services its bundle
   *  declares. */
  const seamFor = (slot: AppSlot): HostCall => {
    const b = slot.verifiedBundle;
    const app = table.labelOf(slot);
    const fullSeam = createGuestSeam({
      sodium,
      // The signed list, unmodified: host services and local service ids.
      requires: b.manifest.guest.requires,
      backends: {
        node: slotSignScope(opts, app, reachesLink(b.manifest)),
        fs: slot.fsScope,
        timer: slot.timers,
        link,
      },
      // The label, hashed, so it has the same 32-byte shape as a peer's sender key. All
      // zeros is the host.
      callLocal: sendsOwn(app, b.manifest.protocols ?? [], callLocal(genesisHash(sodium, enc.encode(app)))),
      modules: {
        names: new Set(b.manifest.modules.map((m) => m.name)),
        call: slot.pureModules.call,
      },
    });
    // A candidate's top level runs before commit, so every seam call is refused until the
    // slot is active, and disposing a failed candidate has nothing to undo. Top level can
    // still initialize from `HOST`, `APP` and `LOCAL`.
    return (name, payload, budget) => {
      if (!slot.active) {
        throw new Error(`shell: '${name}' is refused until this bundle's installation commits`);
      }
      return fullSeam(name, payload, budget);
    };
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
    const localConfig = load.localConfig ?? {};
    if (!isJsonObject(localConfig)) throw new Error("shell: localConfig must be a JSON object");
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
    const pureModules = await loadBundleModules(moduleLoader, v);
    const slot = newSlot(loaded, pureModules, load, bounds.deadlineMs);
    // A guest that cannot compile fails the install, not the first frame.
    try {
      await standRealm(slot, localConfig, bounds);
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
        ? enter(slot, HOST_CALLER_ID, payload, deadlineMs)
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
    call: callLocal(HOST_CALLER_ID),
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
    if (netHost && transportBlob) {
      await installBundle(transportBlob,
        net!.config === undefined ? undefined : { localConfig: net!.config }, true);
      await netHost.start();
    }
    return { shell, transport: netHost };
  } catch (err) {
    shell.close();
    throw err;
  }
}
