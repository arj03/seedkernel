// Platform-neutral shell (§12.9). `bootShell` is THE assembly path — defaults, the
// slot table and load order. Explicit replacement selects the owner to retire. Targets
// displace platform members only (main.ts, native-shim.ts, seedchat, seedstore). Signed
// bundles are the only way slots land (§12.4).
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

/** The crypto surface the shell needs: manifest verification + genesis hashing
 *  (ManifestVerifier) plus the remaining guest crypto ops (SeamCrypto). Core libsodium
 *  build satisfies both. */
export type ShellSodium = ManifestVerifier & SeamCrypto;

/** Configuration supplied by this installation for one particular install. Kept
 *  separate from the author's signed `APP`, and scoped to this call rather than to the
 *  shell, which may host unrelated apps at once. The guest receives it as `LOCAL` and owns
 *  any validation or precedence between the two values. The realm bounds ride here for the
 *  same reason, one level down: the operator's numbers ABOUT ONE APP. */
export interface InstallOptions {
  /** The slot this install RETIRES, by its `app` label — the whole difference
   *  between the two shapes an install has. Absent, the candidate must land on a FREE
   *  label and an occupied one is refused. Present, it must name a live slot, which the
   *  candidate takes over atomically — across authors and app names, and it is the only
   *  way to take `link`. Named, never inferred from the candidate's own label, so nothing
   *  is displaced that the caller did not choose. */
  replaces?: string;
  localConfig?: JsonObject;
  /** QuickJS heap limit for THIS load's realm, in bytes. Omitted ⇒ the shell's
   *  `realmMemoryBytes`, and failing that `DEFAULT_REALM_MEMORY_BYTES`. What a target
   *  streaming large windows through one guest raises (seedstore's storage bundle). A
   *  replacement load carries its own: a version installed without one is held to the
   *  node's default rather than inheriting the outgoing realm's. */
  realmMemoryBytes?: number;
  /** Budget of guest execution time per entrypoint invocation for THIS load, in ms.
   *  Omitted ⇒ the shell's `guestDeadlineMs`, and failing that
   *  `DEFAULT_GUEST_DEADLINE_MS`; `Infinity` disables it. */
  guestDeadlineMs?: number;
  /** Observe this slot's own answer to a PEER-inbound frame, after it resolves
   *  (`deliverInbound`). The one gap left once dispatch is a single claim → slot map: the
   *  link occupant consumes that answer on its way back out to the wire, so an embedder
   *  whose own mounted app must paint what it just answered has no other path to those
   *  bytes.
   *  Scoped to THIS load rather than the shell; a replacement load carries its own.
   *  Observation only: it cannot change what the caller receives, it is never consulted
   *  for a host loopback `invoke` or a cross-realm call, and a throw from it is swallowed. */
  onInbound?: InboundObserver;
}

export interface Shell {
  /** Which app serves this claim, or null (§12.10) — a peer-reachable `protocols` name
   *  first, then a locally reachable `services` one. A read of the projection the
   *  installed manifests define; there is nothing to write here. The one owner kind is a
   *  bundle slot. */
  resolve(claim: string): string | null;
  /** Every claim this node serves, as `[claim, owner]` — what an operator's console line
   *  or a shell's UI lists, peer-reachable names first. A snapshot, not the live maps. */
  routes(): [string, string][];
  /** Call the realm claiming this LOCAL service id, with the host's caller id; `null`
   *  when nothing claims it. The host half of the routing a co-resident guest reaches
   *  through `host.call`, so it resolves `services` and never `protocols`.
   *
   *  The third door into a realm, and the three have distinct audiences: `AppHandle.invoke`
   *  is slot-bound, this is local reach, `link/deliver` is peer reach. An embedder or the
   *  CLI composes the op frame (op-frame.ts) — this is how the node's own transport is
   *  asked to wait for a cohort, list peers, or learn an address. */
  call(serviceId: string, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array> | null;
  /** Filesystem backend, or absent for a node with no disk (a bundle declaring the
   *  `fs` cap then gets no backend wired — its first `fs/*` call throws). */
  fs?: Fs;
  sodium: ShellSodium;
  /** Install a signed bundle blob: verify the manifest, run the admission predicate,
   *  integrity-check + install the modules, stand the guest, commit the slot. THE one way
   *  a bundle enters this node, and `opts.replaces` is the only thing that varies — a
   *  free label when absent, the named slot retired atomically when present. App
   *  candidates require admission either way; a candidate reaching `link` is authorized
   *  only by replacing the current link owner. An install either leaves a running app
   *  behind or leaves nothing: the realm is built here, so a guest that cannot compile
   *  fails the install rather than the first frame, the freshness mark is advanced last,
   *  and a failed candidate leaves the slot it named exactly as it was. The fs and
   *  signing namespaces are the label's, not the author's: a replacement that keeps the
   *  label keeps both, and one that changes it moves to the new label's. */
  install(blob: Uint8Array, opts?: InstallOptions): Promise<AppHandle>;
  /** Uninstall the slot holding this label: drop its claims and dispose its realm,
   *  private modules and timers as one unit. The label's fs keys are data, not slot
   *  state — they stay for whatever installs the label next. */
  uninstall(app: string): boolean;
  /** Write off an author key: refuse everything it signs from now on, and uninstall every
   *  app of its already running. Returns the labels torn down. One call because the
   *  halves are useless apart: uninstalling alone leaves the thief's next bundle free to
   *  land again, refusing alone leaves the compromised code running.
   *  Permanent and host-local — recovery is a new author key, not an un-revoke. */
  revoke(authorHex: string): string[];
  close(): void;
}

/** What a load returns: verified facts plus a slot-bound handle (§12.4). */
export interface AppHandle extends LoadedBundle {

  /** This app's fs keyspace view (§12.2): `scopedFs(backend, appScope)` already applied
   *  by the shell, so reads/writes/lists over this handle can only reach this app's
   *  keys. Absent on a shell with no fs. */
  fs?: Fs;
  /** The fs keyspace prefix this app's view is scoped under — the derivation the shell
   *  computed (`appScopeFor`, bundle.ts). For a caller reading the raw backend cold
   *  (outside a running node), `scopedFs(raw, appScope)` (fs-view.ts) re-derives it. */
  appScope: string;
  /** Loopback invoke into this app's one `handle` entrypoint, bound to THE SLOT this
   *  load stood. A replacement stands a new slot, possibly under a different label. A handle
   *  taken before it keeps naming the version it was handed and rejects once that slot
   *  is disposed. The replacement load returns the new handle. */
  invoke(payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array>;
}

// Re-exported so a target reaches the admission constructors, and an app's fs view, from
// the same module it gets bootShell from — how the pieces are split across files here is
// not a client's problem. Pure-module builders remain target implementations, not shell API.
export { denyAll, admitAll, authorAllowlist, policyFromJson, type Admit } from "./policy.js";
export { scopedFs } from "./fs-view.js";

/** This node's network, whole (§12.6). */
export interface TransportOptions extends TransportHostOptions {
  /** The signed transport to install at boot. Selecting these bytes authorizes link.
   *  Defaults to the artifact-shipped bundle. Live changes install over it by name. */
  bundle?: Uint8Array;
  /** Installation-local configuration for the initial transport. */
  config?: JsonObject;
}

/** JS-target assembly options (§12.9). Every field but `sodium` and `identity` has a
 *  default; transport selection and the load order are part of standing a node up, which
 *  is why there is one assembly path and no way to reach the shell around it. */
export interface BootShellOptions {
  /** The crypto surface the shell needs — core libsodium with the ML-DSA-65 verifier
   *  mixed in (the one thing no target can default: main.ts loads it, a browser page
   *  readies it). */
  sodium: ShellSodium;
  /** The node's keypair (§12.9): its public half is this node's peer id and the one
   *  identity every realm reads as `HOST.identity`. The handshake and the seam's SIGN op
   *  both sign with it, under different domains and scopes. */
  identity: Keypair;
  /** Admission for ordinary apps: an author policy, consent dialog, or `admitAll`.
   *  Absent means deny-all for apps. Link is authorized by the selected boot transport
   *  or explicit replacement of its current owner. Host gates apply to every bundle. */
  admit?: Admit;
  /** The fs backend the `fs` service and every app's scoped view sit on.
   *  Default: `MemoryFs`. A disk-backed node (main.ts) passes its `NodeFs`.
   *
   *  `false` is "a node with no disk" (§12.2): no backend wired at all, so a bundle
   *  declaring the `fs` cap has its first `fs/*` call throw by name rather than resolve
   *  to a pretend store. Said rather than omitted, because omitting is what asks for the
   *  in-memory default. */
  fs?: Fs | false;
  /** The persisted bundle-freshness store (§12.4). Default: `FreshnessMarks`,
   *  in-memory. */
  freshnessStore?: FreshnessStore;
  /** The target-specific builder for a bundle's private pure modules (§4). Default:
   *  `ModuleTable`, the JS worker-backed builder; the native binary passes its Go-backed
   *  one. */
  modules?: PureModuleLoader;
  /** The confined realm factory (§12.3) — every app is a guest, so there is always one.
   *  Default: the lazy safe-js import, since the QuickJS engine is heavy and loads on the
   *  first realm. */
  createRealm?: RealmFactory;
  /** This node's DEFAULT guest execution and handoff budget per entrypoint invocation,
   *  in ms. Omitted ⇒ `DEFAULT_GUEST_DEADLINE_MS`; `Infinity` disables the local ceiling.
   *  A finite initiating caller still narrows an unbounded callee. The operator's number,
   *  not the author's: unlike
   *  the module memory ceiling (§4.3), how long this node spends on one message is a
   *  property of the deployment. */
  guestDeadlineMs?: number;
  /** This node's DEFAULT QuickJS heap limit for a guest realm, in bytes. Omitted ⇒
   *  `DEFAULT_REALM_MEMORY_BYTES`. The operator's node-wide answer (CLI `--guest-memory`);
   *  a single load raises or lowers it for its own realm with
   *  `InstallOptions.realmMemoryBytes`, where an appetite belonging to one app goes. */
  realmMemoryBytes?: number;
  /** This node's network (§12.6): the sockets and the signed transport that drives them.
   *  Omitted or `false` is a node with no network. The options object is retained to
   *  preserve live accessors. */
  transport?: TransportOptions | false;
}

/** What `bootShell` hands back: the shell, plus the channel adapter — the one piece the
 *  shell does not expose and a platform still has to drive (the listeners, the ports). The
 *  SAME object the shell holds, not a copy. */
export interface BootResult {
  shell: Shell;
  /** The channel adapter. Null ONLY on a node with no network (`transport` absent or
   *  `false`). The fs backend is not here: it is `shell.fs`, whether the caller passed one
   *  or took the default. */
  transport: TransportHost | null;
}

/** Stand a node up and install the selected signed transport through the shared installer. */
export async function bootShell(opts: BootShellOptions): Promise<BootResult> {
  /** One load's realm bounds (§12.3): this load's number, else the node's, else the shared
   *  one — never the author's. Resolved once for both owners measured against the deadline
   *  (the realm `standRealm` stands, and the clock its wake banks), and checked here because
   *  the engines read some numbers differently. Both truncate a fraction, but a heap limit
   *  that truncates to 0 (or is NaN) is no limit to the JS engine and a refused realm
   *  natively, 2^32 and up wraps on JS (both engines are 32-bit, so nothing that large bounds
   *  anything), and a budget under 1 ms is none at all natively and a refused realm on JS. */
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
  // A bad node-wide default fails the boot, before anything is built, rather than every
  // install after it.
  boundsFor({});
  const sodium = opts.sodium;
  // The defaults are imported lazily: they are JS-target parts (a worker-backed module
  // builder, the QuickJS realm engine), and the one target that never takes them (the
  // native binary, which supplies Go-backed equivalents) must not pay for them.
  // `false` is a node with no disk, the one member whose absence is NOT its default:
  // omitted asks for the in-memory backend, said-as-false asks for none.
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

  // ── what this node holds (slot-table.ts) ────────────────────────────────────
  const table = createSlotTable();
  /** An empty slot for `loaded`, with its realm wake already pointed at the realm the
   *  slot does not have yet. The cycle is tied by reading `holder.realm` at FIRE time,
   *  which is the correct reading anyway: the realm a deadline re-enters is the one
   *  standing when it fires (a transport handover replaces it while the slot stays). */
  const newSlot = (loaded: LoadedBundle, pureModules: PureModules, load: InstallOptions,
    deadlineMs: number): AppSlot => {
    let slot: AppSlot;
    const timers = createRealmTimers(
      // A host event, delivered like the link events (§12.2): the `wake` op under the
      // host's caller id, not a host authority, and `body` arrives pre-framed. A
      // throw has no caller left to reject — the arming call returned turns ago — so it
      // is reported and swallowed. The promise is RETURNED, not discarded: that is what
      // allows the next due wake to enter (realm-timers.ts).
      (body, causalClock) => callSlot(slot, body, undefined, causalClock).catch((err: unknown) => {
        console.error(`[shell] guest error in timer: ${errMessage(err)}`);
      }),
      // Banked against THIS slot's ceiling, not the node's default.
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
  /** Reify a JSON value through JSON.parse rather than as an object literal. Besides
   *  keeping strings safely quoted inside source, this preserves JSON's treatment of a
   *  key named `__proto__` as ordinary data instead of invoking object-literal prototype
   *  syntax. */
  const jsonPreamble = (name: string, value: JsonObject): string => {
    const json = JSON.stringify(value);
    return `const ${name} = JSON.parse(${JSON.stringify(json)});\n`;
  };
  /** Stand one candidate realm under this load's bounds (`boundsFor`). It stays out of the
   *  slot table until this and the freshness write both succeed. */
  const standRealm = async (slot: AppSlot, localConfig: JsonObject,
    bounds: { deadlineMs: number; memoryBytes: number }): Promise<void> => {
    const b = slot.verifiedBundle;
    // Absent ≡ `{}`, so `APP` is always an object to read names off (isValidManifest
    // already refused any non-object).
    const appConfig = b.manifest.guest.config ?? {};
    // The third preamble (§12.5): not what the author signed (`APP`) nor what the
    // operator set (`LOCAL`), but the host's own facts, fixed for this realm's life —
    // the node's public key, the same one `node/sign` signs with, and the budgets the
    // host will admit, told to the guest rather than discovered by being refused so it
    // can window its own fan-out. Anything that changes what the realm admits must change
    // what is advertised here with it.
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
  /** Wire the `host.call` seam one admitted bundle's realm runs against (guest-seam.ts),
   *  as the three things that own it: what this NODE is, what this REALM may reach
   *  (`grants`), and what this APP installed (`modules`). A bundle reaching `link` is
   *  wired with `rawNet`: without it a bundle is never handed a socket descriptor (§1,
   *  an ungranted service is never wired). Timers are NOT such a grant — `timer/*` is an ordinary
   *  host service, so every realm gets a table. */
  const seamFor = (slot: AppSlot): HostCall => {
    const b = slot.verifiedBundle;
    const links = reachesLink(b.manifest);
    // The 32 bytes this realm is attributed by when it calls another: its label,
    // hashed. The same shape as the sender key prepended to an inbound frame, so a
    // callee reads one field whether the caller was a peer or a co-resident app. Zero
    // is the HOST's own, and no label derives it.
    const callerId = genesisHash(sodium, enc.encode(table.labelOf(slot)));
    const fullSeam = createGuestSeam({
      platform: { sodium },
      grants: {
        // The signed list, unmodified: host services and local service ids. A
        // `host.call` naming a host method resolves iff the method's SERVICE is in it.
        // `crypto/*` and the bundle's own module names are exempt — a fixed catalog and
        // the app's own code, never grants.
        names: new Set(b.manifest.guest.requires),
        // What node/sign signs under: this slot's ONE scope, derived at load —
        // an ordinary app's own `DOMAIN_guest ‖ app`, the link slot's
        // `DOMAIN_link_scope` (§12.2). The host chooses what the
        // name means; the seam prefixes and never parses, so no op signs raw
        // bytes.
        signScope: slot.signingScope,
        // Scoped to this app's label, so `fs` grants reach this app's own keyspace, not
        // the node's — the same structural ownership module names have (§5).
        // Wired whenever the node has an fs at all, without consulting the
        // manifest: `names` already refuses every `fs/*` the bundle did not
        // declare, and a second test here would decide one grant in two places.
        fs: slot.fsScope,
        // The cross-realm call. Resolution happens at CALL time, not here: an app
        // may be installed before its service, and a later load may replace that
        // service — a claimant captured at seam construction would pin this realm
        // to whoever was there first.
        calls: { call: (id, payload, deadlineMs, causalClock) =>
          callClaimant(table.localClaimant(id), callerId, payload, deadlineMs, causalClock) },
        rawNet: links ? netHost?.rawNet() : undefined,
        // Unconditional for the same reason `fs` is.
        timers: slot.timers,
      },
      // This slot's private module value: no label lookup and no cross-app
      // namespace. The deadline is the calling guest's remaining segment (§4.3).
      modules: {
        names: new Set(b.manifest.modules.map((m) => m.name)),
        call: slot.pureModules.call,
      },
    });
    // A candidate's top level runs before its mark and claims commit, and the realm
    // factory runs it SYNCHRONOUSLY inside this seam (native-shim.ts) — so anything it
    // reaches for has already landed by the time the commit window decides. Authority
    // therefore begins at the first post-commit invocation: disposing a candidate is a
    // real undo because a candidate did nothing to undo. One rule over the whole
    // vocabulary and not a list of the names that bite, because the list is what goes
    // stale when a service is added. A top level still initializes — from `HOST`, `APP`
    // and `LOCAL`, never off this seam — which is how the transport stands its whole
    // routing state before it is first invoked (§12.6).
    // The refusal THROWS at the call site like every gate refusal (guest-seam.ts).
    return (name, payload, budget) => {
      if (!slot.active) {
        throw new Error(`shell: '${name}' is refused until this bundle's installation commits`);
      }
      return fullSeam(name, payload, budget);
    };
  };
  /** Enter a slot's guest. `input` is `[caller 32][body …]` — the host's attribution
   *  prefix, never the guest's own spelling. Every door here opens only once the install
   *  has committed — the table, the handle and the link binding hold committed slots, and
   *  `seamFor` refuses the timer a candidate would arm — so the realm is always standing. */
  const callSlot = (slot: AppSlot, input: Uint8Array, deadlineMs?: number, causalClock?: CausalClock) =>
    slot.realm!.call(input, deadlineMs, causalClock);
  const doUninstall = (app: string) => {
    const slot = table.remove(app);
    if (!slot) return false;
    // The driver follows the book: with nothing holding `link`, nothing may hear its events.
    if (!table.occupant("link")) netHost?.release();
    disposeSlot(slot);
    return true;
  };
  /** Frame `[attribution ‖ payload]` and enter a slot's guest — the one shape every door
   *  into a realm arrives as: a host event (the host's own zero caller id), a cross-realm
   *  call, and a peer-inbound frame. */
  const callFramed = (slot: AppSlot, attribution: Uint8Array, payload: Uint8Array,
    deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array> =>
    callSlot(slot, concatBytes([attribution, payload]), deadlineMs, causalClock);
  /** An event the HOST writes into a slot (loopback and socket events). */
  const hostCallSlot = (slot: AppSlot, body: Uint8Array, deadlineMs?: number): Promise<Uint8Array> =>
    callFramed(slot, HOST_CALLER_ID, body, deadlineMs);
  /** Hand a request to a claimant, or answer `null` when nothing claims it — an answer,
   *  rather than a promise no one will settle. */
  const callClaimant = (slot: AppSlot | undefined, attribution: Uint8Array,
    payload: Uint8Array, deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array> | null =>
    slot ? callFramed(slot, attribution, payload, deadlineMs, causalClock) : null;
  /** Inbound from outside this node (the link occupant's `link/deliver` call). One lookup
   *  on the PEER book, so a `services` claim is unreachable by a peer by construction
   *  rather than by a second test against the slot's manifest. The resolved answer also
   *  goes to the slot's `onInbound`, if its load named one. */
  const deliverInbound = (claim: string, framed: Uint8Array,
    deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array> | null => {
    const slot = table.peerClaimant(claim);
    if (!slot) return null;
    // Already framed by the occupant's own call (guest-seam.ts `link/deliver`), so this
    // door enters the realm directly rather than taking the frame apart to rebuild it.
    const answer = callSlot(slot, framed, deadlineMs, causalClock);
    if (slot.onInbound) {
      const onInbound = slot.onInbound;
      const attribution = framed.subarray(0, HOST_CALLER_ID.length);
      // Two-arg `.then`, not a bare call plus a stray `.catch`: this branch's own
      // Promise must settle either way, or a guest that refuses the frame leaves an
      // unhandled rejection behind that `answer` — the one the caller actually
      // holds — already reports. Nothing to do on a refusal: there is no answer to
      // observe.
      answer.then((bytes) => {
        try { onInbound(claim, attribution, bytes); }
        catch (err) { console.error(`[shell] the installer's onInbound threw: ${errMessage(err)}`); }
      }, () => {});
    }
    return answer;
  };
  // Inbound requests use current peer claims (§12.10).
  netHost?.routeInbound(deliverInbound);

  // One transaction for every install: a free label, a named replacement, and the
  // selected boot transport are the same sequence with a different target.
  const installBundle = async (blob: Uint8Array, opts: InstallOptions = {},
    bootTransport = false): Promise<AppHandle> => {
    const localConfig = opts.localConfig ?? {};
    if (!isJsonObject(localConfig)) throw new Error("shell: localConfig must be a JSON object");
    const bounds = boundsFor(opts);
    // The slot being retired, resolved to the exact live slot HERE, before any of the
    // candidate's code runs — the table then checks that same slot is still the one
    // installed when the commit lands, so a target that changed underneath fails rather
    // than silently retiring whatever took its place.
    const replacement = opts.replaces === undefined ? undefined : table.get(opts.replaces);
    if (opts.replaces !== undefined && replacement === undefined) {
      throw new Error(`shell: '${opts.replaces}' is not installed, so there is nothing for this bundle to replace`);
    }
    const v = verifyBundle(sodium, blob);
    checkHostGates(v, freshnessStore);
    // A candidate reaching `link` is not an app: whether it may take the binding is the
    // slot table's rule (boot selection or replacement of the holder), never consent.
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
    // Refuse a conflict already standing BEFORE the candidate's modules or guest
    // execute: a known loser is not worth a realm. The second check in the
    // synchronous commit window remains necessary, since another load may take a
    // free claim while this candidate is built.
    checkInstallation();
    const pureModules = await loadBundleModules(moduleLoader, v);
    const slot = newSlot(loaded, pureModules, opts, bounds.deadlineMs);
    // Stand the guest, before anything already standing is replaced. Every app is a
    // guest (§12.4), so a bundle whose guest will not compile has not loaded — and
    // discovering that at the first frame would leave the mark advanced for a
    // bundle that never ran a line.
    try {
      await standRealm(slot, localConfig, bounds);
      // The candidate is complete. EVERYTHING FROM HERE IS SYNCHRONOUS, which is
      // what makes the commit atomic: the gates below, the contest, the mark, and the
      // claim hand-over cannot be interleaved with another load or an uninstall.
      //
      // Admission read these before the modules and the guest's top level ran, and both
      // move: a newer version can land meanwhile, and `revoke` can name this author. NOT
      // the operator's predicate — consent is not withdrawn by losing a race.
      checkHostGates(v, freshnessStore);
      checkInstallation();
      // A mark that cannot be persisted throws, and the store has already rolled
      // itself back; the catch below disposes the candidate, so the running slot
      // is untouched.
      freshnessStore.set(loaded.author, loaded.manifest.app, loaded.manifest.version);
    } catch (err) {
      disposeSlot(slot);
      throw err;
    }
    table.commit(slot, replacement);
    // The outgoing guest's link state went with its realm (§4.3), so the sockets it
    // held are torn down here rather than left as channels nobody can speak for. So
    // did its address book, which is why the incoming guest redials from the peers
    // its own load named and not from anything retained here (§12.10). After the
    // claim hand-over above, so `onClose` finds the channels already gone and queues
    // no `linkClosed` at the new realm for links it never had. The driver follows the
    // `link` claim: this slot took it, or nothing holds it — a replacement that DROPS
    // `link` releases the binding the same way dropping a claim releases the claim.
    const linkHolder = table.occupant("link");
    if (linkHolder === slot) {
      // The driver builds the whole realm argument, caller id included (`TransportCall`),
      // so a socket read is not copied a second time behind that prefix here.
      netHost?.activate((input) => callSlot(slot, input));
    } else if (!linkHolder) {
      netHost?.release();
    }
    // The mark and every claim/link binding have landed, so this slot's writes and
    // cross-realm calls are now its own (`seamFor`).
    slot.active = true;
    disposeSlot(replacement);
    // The handle: the verified facts plus the bound slot — the scoped fs
    // view and the loopback invoke. One object, so a caller cannot derive half of
    // it from the manifest and half from the shell and have the two disagree.
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
    install: (blob, opts) => installBundle(blob, opts),
    uninstall: doUninstall,
    revoke(authorHex) {
      const hex = authorHex.toLowerCase();
      if (!isHex64(hex)) {
        throw new Error(`shell: revoke expects a 64-character hex author key, got ${JSON.stringify(authorHex)}`);
      }
      // Persist FIRST, then tear down. The other order leaves a window in which the
      // apps are gone but nothing refuses the key, and the case this exists for is a
      // key that is actively publishing.
      freshnessStore.revoke(fromHex(hex));
      const gone = table.all()
        .filter((slot) => toHex(slot.verifiedBundle.author) === hex)
        .map(table.labelOf);
      for (const app of gone) doUninstall(app);
      return gone;
    },
    // Disposal is immediate, as for an uninstall: a realm fails whatever is parked in it
    // before its engine is freed (§12.3), so no call resumes into a freed realm.
    close() {
      closed = true;
      netHost?.close();
      for (const slot of table.clear()) disposeSlot(slot);
    },
  };

  // The selected transport uses the ordinary verified install path. A failed boot
  // returns no handle, so tear down any resources it stood up.
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
