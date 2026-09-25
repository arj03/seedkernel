// Platform-neutral shell (§12.9). `bootShell` is THE assembly path: defaults, the slot
// table and load order. Targets displace platform members only; signed bundles are the
// only way slots land (§12.4).
import { denyAll, checkHostGates, type Admit } from "./policy.js";
import { appScopeFor, FreshnessMarks, genesisHash, isJsonObject, reachesLink, verifyBundle, loadBundleModules, type FreshnessStore, type JsonObject, type LoadedBundle, type ManifestVerifier, type PureModuleLoader, type PureModules } from "./bundle.js";
import { createGuestSeam, slotSignScope, HOST_CALLER_ID, type SeamCrypto, type HostCall } from "./guest-seam.js";
import { TransportHost, type TransportHostOptions } from "./transport-host.js";
import { transportBundleBytes } from "./transport-bundle.js";
import { type Fs } from "../services/fs.js";
import { validatedFs, scopedFs } from "./fs-view.js";
import { createRealmTimers } from "./realm-timers.js";
import { createSlotTable, type AppSlot, type InboundObserver } from "./slot-table.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES, DEFAULT_MAX_OUTSTANDING_HOST_CALLS, DEFAULT_REALM_MEMORY_BYTES } from "./wasm-limits.js";
import { enc, fromHex, toHex, isHex64, errMessage, concatBytes } from "../services/util.js";
import { type CausalClock, type RealmFactory } from "./realm-queue.js";
import type { Keypair } from "../services/subkeys.js";

/** Neutral realm contracts exposed through the shell facade clients configure. */
export type { Realm, RealmOptions, RealmFactory } from "./realm-queue.js";

/** Manifest verification plus the guest crypto ops; core libsodium satisfies both. */
export type ShellSodium = ManifestVerifier & SeamCrypto;

/** This installation's settings for one install — the operator's, never the author's.
 *  The guest reads `localConfig` as `LOCAL`. */
export interface InstallOptions {
  /** The slot this install retires, by its `app` label. Absent, the candidate must land on
   *  a free label. Present, it must name a live slot, which the candidate takes over
   *  atomically, across authors and labels — the only way to take `link`. */
  replaces?: string;
  localConfig?: JsonObject;
  /** QuickJS heap limit for this load's realm. Omitted ⇒ the shell's `realmMemoryBytes`,
   *  then `DEFAULT_REALM_MEMORY_BYTES`; a replacement never inherits the outgoing value. */
  realmMemoryBytes?: number;
  /** Guest execution budget per invocation for this load, in ms. Omitted ⇒ the shell's
   *  `guestDeadlineMs`, then `DEFAULT_GUEST_DEADLINE_MS`; `Infinity` disables it. */
  guestDeadlineMs?: number;
  /** Observe this slot's own answer to a peer-inbound frame, so an embedder can paint what
   *  its app answered. Observation only: never consulted for a loopback `invoke` or a
   *  cross-realm call, and a throw from it is swallowed. */
  onInbound?: InboundObserver;
}

export interface Shell {
  /** Which app serves this claim, or null (§12.10): `protocols` first, then `services`. */
  resolve(claim: string): string | null;
  /** Every claim this node serves, as `[claim, owner]`, peer-reachable first. A snapshot. */
  routes(): [string, string][];
  /** Call the realm claiming this local service id with the host's caller id; `null` when
   *  nothing claims it. Resolves `services`, never `protocols`. How an embedder or the CLI
   *  asks the node's transport to wait for a cohort, list peers, or learn an address. */
  call(serviceId: string, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array> | null;
  /** Absent for a node with no disk; a bundle requiring `fs` then throws on its first call. */
  fs?: Fs;
  sodium: ShellSodium;
  /** THE way a bundle enters this node: verify, admit, build modules, stand the guest,
   *  commit the slot. An install leaves a running app or nothing — a failed candidate
   *  leaves the slot it named exactly as it was. fs and signing namespaces follow the
   *  label, not the author. */
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
   *  backend cold with `scopedFs(raw, appScope)`. */
  appScope: string;
  /** Loopback invoke into the slot this install stood. Rejects once that slot is
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
   *  the artifact-shipped bundle. */
  bundle?: Uint8Array;
  /** Installation-local configuration for the initial transport. */
  config?: JsonObject;
}

/** JS-target assembly options (§12.9). Everything but `sodium` and `identity` defaults. */
export interface BootShellOptions {
  /** Core libsodium with the ML-DSA-65 verifier mixed in. */
  sodium: ShellSodium;
  /** The node's keypair: its public half is the peer id every realm reads as
   *  `HOST.identity`; the handshake and `node/sign` both sign with it. */
  identity: Keypair;
  /** Admission for ordinary apps. Absent ⇒ deny-all. `link` is authorized only by boot
   *  selection or replacement of its holder; host gates apply to every bundle. */
  admit?: Admit;
  /** Default `MemoryFs`. `false` is a node with no disk: no backend at all. */
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
  /** The sockets and signed transport (§12.6). Omitted or `false`: no network. The object
   *  is retained, so live accessors keep working. */
  transport?: TransportOptions | false;
}

export interface BootResult {
  shell: Shell;
  /** The channel adapter the platform still drives (listeners, ports); the same object the
   *  shell holds. Null only on a node with no network. */
  transport: TransportHost | null;
}

/** Stand a node up and install the selected signed transport through the shared installer. */
export async function bootShell(opts: BootShellOptions): Promise<BootResult> {
  /** One load's realm bounds: this load's, else the node's, else the shared default.
   *  Checked here because the engines disagree on out-of-range values: a heap limit that
   *  truncates to 0 is unlimited on JS and refused natively, 2^32 wraps, and a budget under
   *  1 ms is none natively and refused on JS. */
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
  // A bad node-wide default fails the boot rather than every install after it.
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
  /** An empty slot for `loaded`. The wake reads `slot` at fire time, so it re-enters
   *  whichever realm is standing then. */
  const newSlot = (loaded: LoadedBundle, pureModules: PureModules, load: InstallOptions,
    deadlineMs: number): AppSlot => {
    let slot: AppSlot;
    const timers = createRealmTimers(
      // A host event under the host's caller id. No caller is left to reject, so a throw
      // is logged. The promise is returned: it gates the next wake (realm-timers.ts).
      (body, causalClock) => callSlot(slot, body, undefined, causalClock).catch((err: unknown) => {
        console.error(`[shell] guest error in timer: ${errMessage(err)}`);
      }),
      deadlineMs,
    );
    const appScope = appScopeFor(sodium, loaded.manifest.app);
    const scope = slotSignScope(opts, loaded.manifest.app, reachesLink(loaded.manifest));
    slot = {
      verifiedBundle: loaded,
      pureModules,
      fsScope: fs ? scopedFs(fs, appScope) : undefined,
      appScope,
      signingScope: scope,
      realm: null,
      active: false,
      timers,
      onInbound: load.onInbound,
    };
    return slot;
  };
  /** Cancel deadlines, then dispose realm. Every teardown path goes through this. */
  const disposeSlot = (slot: AppSlot | undefined) => {
    if (!slot) return;
    slot.active = false;
    slot.timers.clearAll();
    slot.realm?.dispose();
    slot.pureModules.dispose();
  };
  /** A preamble constant via JSON.parse rather than an object literal, so a `__proto__`
   *  key stays data. */
  const jsonPreamble = (name: string, value: JsonObject): string => {
    const json = JSON.stringify(value);
    return `const ${name} = JSON.parse(${JSON.stringify(json)});\n`;
  };
  /** Stand one candidate realm. It stays out of the table until this and the freshness
   *  write both succeed. */
  const standRealm = async (slot: AppSlot, localConfig: JsonObject,
    bounds: { deadlineMs: number; memoryBytes: number }): Promise<void> => {
    const b = slot.verifiedBundle;
    const appConfig = b.manifest.guest.config ?? {};
    // The host's own facts (§12.5): the key `node/sign` signs with, and the budgets the
    // realm will be held to, so a guest can window its fan-out. Change them together.
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
  /** Wire the `host.call` seam for one slot (guest-seam.ts). */
  const seamFor = (slot: AppSlot): HostCall => {
    const b = slot.verifiedBundle;
    const links = reachesLink(b.manifest);
    // The label, hashed: the same 32-byte shape as a peer's sender key. Zero is the host's.
    const callerId = genesisHash(sodium, enc.encode(table.labelOf(slot)));
    const fullSeam = createGuestSeam({
      platform: { sodium },
      grants: {
        // The signed list, unmodified: host services and local service ids.
        names: new Set(b.manifest.guest.requires),
        signScope: slot.signingScope,
        // Wired whenever the node has an fs; `names` alone decides whether `fs/*` resolves.
        fs: slot.fsScope,
        // Resolved at call time, so a service installed or replaced later is found.
        calls: { call: (id, payload, deadlineMs, causalClock) =>
          callClaimant(table.localClaimant(id), callerId, payload, deadlineMs, causalClock) },
        // Never wired for a bundle that does not require `link` (§1).
        rawNet: links ? netHost?.rawNet() : undefined,
        timers: slot.timers,
      },
      modules: {
        names: new Set(b.manifest.modules.map((m) => m.name)),
        call: slot.pureModules.call,
      },
    });
    // A candidate's top level runs before commit, so every seam call is refused until the
    // slot is active: disposing a failed candidate then has nothing to undo. Top level still
    // initializes from `HOST`, `APP` and `LOCAL`.
    return (name, payload, budget) => {
      if (!slot.active) {
        throw new Error(`shell: '${name}' is refused until this bundle's installation commits`);
      }
      return fullSeam(name, payload, budget);
    };
  };
  /** Enter a committed slot's guest with `[caller 32][body …]`. */
  const callSlot = (slot: AppSlot, input: Uint8Array, deadlineMs?: number, causalClock?: CausalClock) =>
    slot.realm!.call(input, deadlineMs, causalClock);
  const doUninstall = (app: string) => {
    const slot = table.remove(app);
    if (!slot) return false;
    // With nothing holding `link`, nothing may hear its events.
    if (!table.occupant("link")) netHost?.release();
    disposeSlot(slot);
    return true;
  };
  /** Enter a slot with `[attribution ‖ payload]`. */
  const callFramed = (slot: AppSlot, attribution: Uint8Array, payload: Uint8Array,
    deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array> =>
    callSlot(slot, concatBytes([attribution, payload]), deadlineMs, causalClock);
  /** An event the host writes into a slot. */
  const hostCallSlot = (slot: AppSlot, body: Uint8Array, deadlineMs?: number): Promise<Uint8Array> =>
    callFramed(slot, HOST_CALLER_ID, body, deadlineMs);
  /** Hand a request to a claimant, or answer `null` when nothing claims it. */
  const callClaimant = (slot: AppSlot | undefined, attribution: Uint8Array,
    payload: Uint8Array, deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array> | null =>
    slot ? callFramed(slot, attribution, payload, deadlineMs, causalClock) : null;
  /** Peer-inbound delivery (`link/deliver`): one lookup on the peer book, so a `services`
   *  claim is unreachable by a peer by construction. `framed` is already the realm
   *  argument. */
  const deliverInbound = (claim: string, framed: Uint8Array,
    deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array> | null => {
    const slot = table.peerClaimant(claim);
    if (!slot) return null;
    const answer = callSlot(slot, framed, deadlineMs, causalClock);
    if (slot.onInbound) {
      const onInbound = slot.onInbound;
      const attribution = framed.subarray(0, HOST_CALLER_ID.length);
      // Two-arg `.then`, so a refused frame leaves no unhandled rejection on this branch;
      // the caller already holds `answer`.
      answer.then((bytes) => {
        try { onInbound(claim, attribution, bytes); }
        catch (err) { console.error(`[shell] the installer's onInbound threw: ${errMessage(err)}`); }
      }, () => {});
    }
    return answer;
  };
  netHost?.routeInbound(deliverInbound);

  // One transaction for every install: a free label, a named replacement, and the boot
  // transport differ only in their target.
  const installBundle = async (blob: Uint8Array, load: InstallOptions = {},
    bootTransport = false): Promise<AppHandle> => {
    const localConfig = load.localConfig ?? {};
    if (!isJsonObject(localConfig)) throw new Error("shell: localConfig must be a JSON object");
    const bounds = boundsFor(load);
    // Resolved to the exact live slot now; commit refuses if a different slot holds the
    // label by then.
    const replacement = load.replaces === undefined ? undefined : table.get(load.replaces);
    if (load.replaces !== undefined && replacement === undefined) {
      throw new Error(`shell: '${load.replaces}' is not installed, so there is nothing for this bundle to replace`);
    }
    const v = verifyBundle(sodium, blob);
    checkHostGates(v, freshnessStore);
    // Taking `link` is the slot table's rule (boot selection or holder replacement), never
    // the admission predicate's.
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
    // Refuse a known loser before its code runs; asked again at commit, since another
    // load may take a free claim meanwhile.
    checkInstallation();
    const pureModules = await loadBundleModules(moduleLoader, v);
    const slot = newSlot(loaded, pureModules, load, bounds.deadlineMs);
    // A guest that cannot compile fails the install, not the first frame.
    try {
      await standRealm(slot, localConfig, bounds);
      // Synchronous from here to the end: gates, contest, mark and claim hand-over cannot
      // interleave with another load or an uninstall. The gates are asked again because a
      // newer version or a `revoke` may have landed meanwhile; admission consent is not.
      checkHostGates(v, freshnessStore);
      checkInstallation();
      // A mark that cannot persist throws after rolling itself back; the running slot is
      // untouched.
      freshnessStore.set(loaded.author, loaded.manifest.app, loaded.manifest.version);
    } catch (err) {
      disposeSlot(slot);
      throw err;
    }
    table.commit(slot, replacement);
    // The driver follows the `link` claim. Links are session state of the outgoing realm,
    // so they are torn down, after the hand-over so no `linkClosed` reaches the new realm;
    // the incoming guest redials from its own config (§12.10).
    const linkHolder = table.occupant("link");
    if (linkHolder === slot) {
      netHost?.activate((input) => callSlot(slot, input));
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
        ? hostCallSlot(slot, payload, deadlineMs)
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
    call: (serviceId, payload, deadlineMs) =>
      callClaimant(table.localClaimant(serviceId), HOST_CALLER_ID, payload, deadlineMs),
    fs,
    sodium,
    install: (blob, load) => installBundle(blob, load),
    uninstall: doUninstall,
    revoke(authorHex) {
      const hex = authorHex.toLowerCase();
      if (!isHex64(hex)) {
        throw new Error(`shell: revoke expects a 64-character hex author key, got ${JSON.stringify(authorHex)}`);
      }
      // Persist first: the other order leaves a window where nothing refuses the key.
      freshnessStore.revoke(fromHex(hex));
      const gone = table.all()
        .filter((slot) => toHex(slot.verifiedBundle.author) === hex)
        .map(table.labelOf);
      for (const app of gone) doUninstall(app);
      return gone;
    },
    // A disposed realm fails whatever is parked in it (§12.3).
    close() {
      closed = true;
      netHost?.close();
      for (const slot of table.clear()) disposeSlot(slot);
    },
  };

  // A failed boot returns no handle, so it tears down what it stood up.
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
