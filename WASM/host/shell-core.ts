// Platform-neutral shell (§12.9). `bootShell` is the one assembly path — pin, defaults,
// load order. Targets displace platform members only (main.ts, native-shim.ts, seedchat,
// seedstore). `createShell` is private: it would skip the transport author pin. Signed
// bundles are the only way slots land (§12.4).
import { denyAll, allOf, hostGates, type Admit, type AdmissionContext } from "./policy.js";
import { appKeyFor, appScopeFor, FreshnessMarks, genesisHash, isJsonObject, privilegesOf, verifyBundle, loadBundleModules, type BundleCrypto, type FreshnessStore, type JsonObject, type LoadedBundle, type PureModuleLoader, type PureModules } from "./bundle.js";
import { createGuestSeam, slotSignScope, opCall, type SeamCrypto, type SignScope, type HostCall, type HostTimers } from "./guest-seam.js";
import { TransportHost, type TransportHostOptions } from "./transport-host.js";
import { transportBundleBytes } from "./transport-bundle.js";
import { isSafeFsKey, isSafeFsScope, type Fs } from "../core/fs.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_MAX_LIVE_TIMERS, DEFAULT_REALM_MEMORY_BYTES } from "../core/wasm-limits.js";
import { isIrreversible, isReservedProtocol, PRIVILEGE_LINK, type Privilege } from "../core/domains.js";
import { enc, fromHex, toHex, writeU32BE, errMessage } from "../core/util.js";
import { type SafeRealm } from "./safe-js.js";
import { type PeerId } from "../core/socket-seam.js";
import type { Keypair } from "../core/subkeys.js";

/** The crypto surface the shell needs: manifest verification + genesis hashing
 *  (BundleCrypto) plus the guest seam's crypto ops (SeamCrypto). Any sumo libsodium
 *  build satisfies both. */
export type ShellSodium = BundleCrypto & SeamCrypto;

/** The one reason a bundle load is refused without being an error worth reporting: the
 *  policy predicate said no (§12.4). Shared so the transport's installers can read it as
 *  "a node without a network", a deliberate configuration rather than a failure. */
export const ADMISSION_REJECTED = "bundle: rejected by admission predicate";

/** What `resolve`/`routes` report as the owner of a claim the EMBEDDER registered
 *  ({@link PlatformClaims}) rather than a bundle. Unambiguous by construction: an app
 *  key is `<author hex>:<app>` and always carries a colon, which this cannot. */
export const PLATFORM_OWNER = "platform";

/** True iff a loadBundleBlob failure was the policy's refusal (see ADMISSION_REJECTED),
 *  whatever shape the thrown value took. */
export function isAdmissionRejected(err: unknown): boolean {
    return errMessage(err).includes(ADMISSION_REJECTED);
}

/** How a target creates the confined realm a guest runs in (§12.3): `createSafeRealm`
 *  (safe-js.ts) on the JS platforms, a quickjs-ng realm on Go's event loop (native/guest.go)
 *  on the native one. Same contract either way — one `call` that may await, invocations
 *  serialized per realm. The shell always supplies both bounds, so a factory never has to
 *  decide what "omitted" means. */
export type RealmFactory = (opts: {
    source: string;
    hostCall: HostCall;
    memoryLimitBytes?: number;
    /** Budget of guest execution time per entrypoint invocation, in ms. Omitted ⇒ the
     *  factory's own default (`DEFAULT_GUEST_DEADLINE_MS` on both targets). */
    deadlineMs?: number;
}) => Promise<SafeRealm>;

/** The platform seam — everything the shell needs that varies by target. `fs` is optional
 *  ("a node with no disk"): a bundle declaring `fs` on such a shell gets no backend wired,
 *  so its first `fs/*` call throws by name rather than resolving to a pretend store
 *  (§12.2). `createRealm` is required — every app is a guest.
 *
 *  The current channel adapter remains a platform resource. Its events are bound directly
 *  to the slot granted its raw-link capability; claim names play no part. */
interface ShellPlatform {
    sodium: ShellSodium;
    /** The node's keypair (§12.9): its public half is this node's peer id and the one
     *  identity every target reports through `node/identity`. The handshake and the seam's
     *  SIGN op both sign with it, under different domains and scopes. */
    identity: Keypair;
    /** Target-specific builder for a bundle's private pure modules (§4). */
    modules: PureModuleLoader;
    fs?: Fs;
    freshnessStore: FreshnessStore;
    createRealm: RealmFactory;
    now?: () => number;
    /** Which network this node belongs to — an isolation boundary, not a gate (§12.6);
     *  absent ⇒ the public network. Feeds the raw link configuration and the signing scope
     *  of the slot reaching `link` (`slotSignScope`).
     *
     *  The scope is the load-bearing use: `node/sign` prefixes and never parses, so it is
     *  the only binding of a link occupant's signature to this node's network that the
     *  slot occupant cannot choose. Drop it from the preimage and a transport on one
     *  network can mint transcripts another's verifier accepts. */
    networkKey?: Uint8Array;
    /** The concrete channel adapter: the sockets, the listeners and the address book, all
     *  the NODE's rather than any guest's. The platform CONSTRUCTS it, because every knob
     *  on it (which addresses to bind, how many conns per peer, the half-open budgets) is
     *  a deployment's answer — then hands it over, `shell.close()` closing it, so there is
     *  one teardown rather than a second thing every embedder must remember.
     *
     *  Absent for a shell with no raw links at all (a browser edge). */
    transportHost?: TransportHost;
}

interface CreateShellOptions {
    /** The operator's admission predicate (§12.5) — one `Admit` asked once per load,
     *  between verify and install. An allowlist, a consent dialog and "the bundle my
     *  operator handed me" are three constructors of this type; a deployment answering per
     *  capability composes `byPrivilege({ base, grants })`, as `policyFromJson` does.
     *  Absent ⇒ deny-all.
     *
     *  The host's own gates — revocation, the coherence rules, the downgrade guard — are
     *  composed AROUND whatever is passed here (`hostGates`), so no operator posture can be
     *  a way to lose them. */
    admit?: Admit;
    /** This node's DEFAULT QuickJS heap limit for a guest realm, in bytes. Omitted ⇒
     *  `DEFAULT_REALM_MEMORY_BYTES`. The operator's node-wide answer (CLI
     *  `--guest-memory`); a single load raises or lowers it for its own realm with
     *  `LoadBundleOptions.realmMemoryBytes`, where an appetite belonging to one app goes. */
    realmMemoryBytes?: number;
    /** This node's DEFAULT budget of guest execution time per entrypoint invocation, in ms.
     *  Omitted ⇒ `DEFAULT_GUEST_DEADLINE_MS`; `Infinity` disables it. Counts time the guest
     *  is *running*, not time parked on a host seam, so it bounds a wedged guest without
     *  penalising one awaiting the network. The operator's number, not the author's: unlike
     *  the module memory ceiling (§4.3), how long this node spends on one message is a
     *  property of the deployment. */
    guestDeadlineMs?: number;
    claims?: PlatformClaims;
}

/** Exact platform-owned claims. Same lookup and conflict rules as bundle claims;
 *  no wildcard. A `_`-led name is local-only whoever holds it (§12.10). */
export type PlatformClaims = Readonly<Record<string, (attribution: Uint8Array, payload: Uint8Array) => Promise<Uint8Array>>>;

/** Configuration supplied by this installation for one particular bundle load. Kept
 *  separate from the author's signed `APP`, and scoped to this call rather than to the
 *  shell, which may host unrelated apps at once. The guest receives it as `LOCAL` and owns
 *  any validation or precedence between the two values. An object for the same reason
 *  `guest.config` is one: the guest reads it by name.
 *
 *  The realm bounds ride here for the same reason, one level down: the operator's numbers
 *  ABOUT ONE APP. A shell-wide heap raised for a node's storage guest was also handed to
 *  the transport bundle sharing the shell, which needed none of it. */
export interface LoadBundleOptions {
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
}

export interface Shell {
    /** Which app serves this protocol, or null (§12.10). A read of the projection the
     *  installed manifests define — there is nothing to write here. `PLATFORM_OWNER` for a
     *  claim the embedder registered rather than a bundle. */
    resolve(proto: string): string | null;
    /** Every protocol this node serves, as `[proto, owner]` — what an operator's console
     *  line or a shell's UI lists. A snapshot, not the live map. */
    routes(): [string, string][];
    /** Filesystem backend, or absent for a node with no disk (a bundle declaring the
     *  `fs` cap then gets no backend wired — its first `fs/*` call throws). */
    fs?: Fs;
    sodium: ShellSodium;
    /** Load a signed bundle blob: verify the manifest, run the admission predicate,
     *  integrity-check + install the modules, stand the guest, and return the guest
     *  source. Every bundle takes this same §12.4 path.
     *
     *  A load either leaves a running app behind or leaves nothing: the realm is built
     *  here, so a guest that cannot compile fails the load rather than the first frame
     *  that reaches it, and the freshness mark — which records the highest version that
     *  actually RAN — is advanced last, once it has. */
    loadBundleBlob(blob: Uint8Array, opts?: LoadBundleOptions): Promise<AppHandle>;
    /** Uninstall the slot selected by its audit identity: drop its claims and dispose its
     *  realm, private modules, timers and scopes as one unit. */
    uninstall(appKey: string): boolean;
    /** Write off an author key: refuse everything it signs from now on, and uninstall every
     *  app of its already running. Returns the app keys torn down.
     *
     *  One call because the halves are useless apart: uninstalling alone leaves nothing to
     *  stop the thief's next bundle landing on the same derived names, refusing alone
     *  leaves the compromised code running. Permanent and host-local — recovery is a new
     *  author key, which derives new names and a fresh mark (§5.1), not an un-revoke. */
    revoke(authorHex: string): string[];
    /** Loopback into a loaded app's `handle` as the host (32 zero-byte caller id).
     *  Addressed by app key — whatever is installed under that identity now. */
    invoke(op: string, payload: Uint8Array, appKey: string): Promise<Uint8Array>;
    /** Dispatch an inbound request to the right app (§12.10): resolve the protocol to
     *  the app claiming it and invoke that app's guest `handle` entrypoint with
     *  `senderPk ‖ payload`. Null when nothing a peer may reach claims the protocol —
     *  which a bundle's `_`-led LOCAL service claim is not, however it is spelled.
     *
     *  Every app is a guest, so the answer is always the realm's — a Promise the transport
     *  driver resumes on, never raw bytes. */
    dispatch(from: PeerId, proto: string, payload: Uint8Array): Promise<Uint8Array> | null;
    close(): void;
}

/** What a load returns: verified facts plus a slot-bound handle (§12.4).
 *  `invoke` is bound to this slot; `Shell.invoke` re-resolves the key. */
export interface AppHandle extends LoadedBundle {
    /** `<author hex>:<app>` (§12.4) — the slot's audit identity, the freshness key and
     *  what `uninstall`/`revoke` address. */
    key: string;
    /** This app's fs keyspace view (§12.2): `scopedFs(backend, appScope)` already applied
     *  by the shell, so reads/writes/lists over this handle can only reach this app's
     *  keys. Absent on a shell with no fs. */
    fs?: Fs;
    /** The fs keyspace prefix this app's view is scoped under — the derivation the shell
     *  computed (`appScopeFor`, bundle.ts). For a caller reading the raw backend cold
     *  (outside a running node), `scopedFs(raw, appScope)` re-derives the same view. */
    appScope: string;
    /** Loopback invoke into this app's one `handle` entrypoint, bound to THE SLOT this
     *  load stood — not to the app key, which is what `Shell.invoke` re-resolves. The
     *  difference is an upgrade: a replacement load stands a new slot under the same key,
     *  so a handle taken before it keeps naming the version it was handed, and rejects
     *  once that slot is disposed. A caller meaning "whatever is installed now" holds the
     *  key and calls `Shell.invoke`. */
    invoke(op: string, payload: Uint8Array): Promise<Uint8Array>;
}

// Re-exported so a target reaches the admission constructors from the same module it gets
// bootShell from. Pure-module builders remain target implementations, not shell API.
export { denyAll, admitAll, authorAllowlist, byPrivilege, allOf, anyOf, policyFromJson, type Admit, type AdmissionContext } from "./policy.js";
/** A slot's realm. Nullable for exactly the window between the holder being made and the
 *  factory resolving, inside one `loadBundleBlob` — a slot only enters `slots` with its
 *  realm standing, and teardown reads the settled handle synchronously, because the
 *  callers that dispose are deciding right then what the node holds. */
interface AppSlot {
  verifiedBundle: LoadedBundle;
  pureModules: PureModules;
  fsScope?: Fs;
  /** The fs keyspace prefix this slot's view is scoped under (bundle.ts `appScopeFor`) —
   *  computed once per load and carried on the returned `AppHandle`, so a caller's cold
   *  read of the raw backend needs the derivation the shell already did. */
  appScope: string;
  /** THE one scope this slot's `node/sign`/`node/verify` are wired to (`slotSignScope`,
   *  guest-seam.ts): the slot's own `DOMAIN_guest ‖ author ‖ app` when it is an ordinary
   *  app, its `DOMAIN_link_scope ‖ networkKey` when it reaches `link` — a fact of the
   *  slot, not a second name. */
  signingScope: SignScope;
  realm: SafeRealm | null;
  /** Set once this slot's freshness mark and claims have committed; until then its seam
   *  refuses the calls disposing the slot could not take back (`seamFor`). */
  active: boolean;
  /** This realm's deadlines. Per SLOT rather than per shell, because a timer is a pending
   *  re-entry into one particular realm: the cap is then one guest's to spend, and
   *  disposing that realm cancels exactly its own (`disposeSlot`). */
  timers: RealmTimers;
}

/** Per-realm timer table. Cap live count; `clearAll` before realm disposal (§2.1). */
interface RealmTimers extends HostTimers {
  /** Cancel every live deadline. Called only from `disposeSlot`, before the realm goes. */
  clearAll(): void;
}

/** A timer table over `fire`, which is what a fired deadline re-enters the realm with.
 *  The table is the resource being spent, so the cap lives here rather than in the seam:
 *  the seam never learns that a timer fired, so a count kept there would only ever grow. */
function createRealmTimers(fire: (id: number) => void, max = DEFAULT_MAX_LIVE_TIMERS): RealmTimers {
    const live = new Map<number, ReturnType<typeof setTimeout>>();
    const clear = (id: number) => {
        const t = live.get(id);
        if (t !== undefined) { clearTimeout(t); live.delete(id); }
    };
    return {
        arm(id, ms) {
            // Counted before the re-arm, so replacing a live deadline is always allowed
            // and only a NEW id can be the one over the line.
            if (!live.has(id) && live.size >= max)
                throw new Error(`guest: too many live timers (cap ${max})`);
            clear(id);
            // Dropped from the table BEFORE the realm is re-entered, so a guest that
            // re-arms the same id from inside its own `timer` entrypoint arms the new
            // deadline rather than having it cleared out from under it on the way out.
            live.set(id, setTimeout(() => { live.delete(id); fire(id); }, ms));
        },
        clear,
        clearAll() {
            for (const t of live.values()) clearTimeout(t);
            live.clear();
        },
    };
}

// ── the fs key rule, applied once (core/fs.ts `isSafeFsKey`) ─────────────────
//
// The rule itself is a consensus predicate and lives in the core; the host applies it here,
// in the two places it must, over whichever backend the target supplied.

/** Apply the key rule over a backend. Rejected keys throw; `list`/`stat` exempt.
 *  Sits under `scopedFs` so the composite `scope + key` is checked. */
export function validatedFs(inner: Fs): Fs {
  const check = (key: string): string => {
    if (!isSafeFsKey(key)) throw new Error(`fs: unsafe key ${JSON.stringify(key)}`);
    return key;
  };
  // `async` so a refusal is a REJECTION, like every other failure on this seam. A
  // synchronous throw would reach a caller that only attached `.catch` as an exception.
  return {
    async get(key) { return inner.get(check(key)); },
    async put(key, bytes) { return inner.put(check(key), bytes); },
    async size(key) { return inner.size(check(key)); },
    list: (prefix) => inner.list(prefix),
    async delete(key) { return inner.delete(check(key)); },
    stat: () => inner.stat(),
  };
}

/** Scope a backend to one app's keyspace (§12.2). `scope` is `appScopeFor`'s
 *  fixed-length prefix. `stat()` is not scoped — it describes the physical backend. */
export function scopedFs(inner: Fs, scope: string): Fs {
  // The head of every key this app will ever reach, so it is checked at construction
  // rather than on the first `put`. Charset only (`isSafeFsScope`): the bare-dot and
  // device-name cases are about a complete name and do not apply to a prefix.
  if (!isSafeFsScope(scope)) throw new Error(`fs: unsafe scope ${JSON.stringify(scope)}`);
  const outward = (key: string): string => scope + key;
  return {
    get: (key) => inner.get(outward(key)),
    put: (key, bytes) => inner.put(outward(key), bytes),
    size: (key) => inner.size(outward(key)),
    // An absent prefix means everything in this scope and nothing else. Keys come back
    // stripped, so the guest only handles names it chose and the scope stays host-side.
    list: async (prefix) => (await inner.list(outward(prefix ?? ""))).map((k) => k.slice(scope.length)),
    delete: (key) => inner.delete(outward(key)),
    stat: () => inner.stat(),
  };
}

function createShell(opts: CreateShellOptions & {
    platform: ShellPlatform;
}): Shell {
    const { platform } = opts;
    const sodium = platform.sodium;
    // The key rule applied once, over whatever backend this target supplied, so every host
    // admits exactly the same key space — which is what decides the contents a node stores
    // and advertises.
    const fs = platform.fs ? validatedFs(platform.fs) : undefined;
    const moduleLoader = platform.modules;
    // THE admission predicate (§12.5). The host's own invariants come first and are
    // composed here rather than by the operator: an `admitAll` posture, or a consent
    // dialog that always says yes, must not be a way to lose revocation or the downgrade
    // guard.
    const admit: Admit = allOf(hostGates, opts.admit ?? denyAll);
    const slots: AppSlot[] = [];
    /** protocol claim → complete bundle slot (§12.10) — a projection of what is installed,
     *  structure of its own: every entry comes from some installed manifest's signed
     *  `protocols`, so there is nothing to write, persist, or keep in step. Materialized
     *  rather than scanned for because it is read once per inbound frame. */
    const claims = new Map<string, AppSlot>();
    const platformClaims = new Map(Object.entries(opts.claims ?? {}));
    /** The existing concrete channel adapter is supplied and owned by the platform. The
     *  shell may wire raw-link calls to it, but it is not part of the Shell API. */
    const netHost = platform.transportHost;
    // The tail of every initiator `invoke` call. close() defers realm disposal onto
    // this so a call parked mid-await (a repair pass waiting out an unreachable peer)
    // is never resumed into a freed realm — a QuickJS use-after-free (§2.1).
    let inFlight = Promise.resolve();
    const keyOf = (slot: AppSlot) => appKeyFor(slot.verifiedBundle.author, slot.verifiedBundle.manifest.app);
    const findSlot = (appKey: string) => slots.find((slot) => keyOf(slot) === appKey);
    const slotClaims = (slot: AppSlot) => slot.verifiedBundle.manifest.protocols ?? [];
    const reachesLink = (manifest: LoadedBundle["manifest"]) => privilegesOf(manifest).includes(PRIVILEGE_LINK);
    const hasLink = (slot: AppSlot) => reachesLink(slot.verifiedBundle.manifest);
    /** The slot the platform's raw-link events go to. Exclusive, like a claim: the driver
     *  has ONE event sink, so two holders are not a composition — the second would take
     *  the node's sockets off the first, silently. */
    let linkOwner: AppSlot | null = null;
    const releaseClaims = (slot: AppSlot) => {
        for (const claim of slotClaims(slot)) {
            if (claims.get(claim) === slot) claims.delete(claim);
        }
    };
    /** An empty slot for `loaded`, with its timer table already pointed at the realm the
     *  slot does not have yet. The cycle is tied by reading `holder.realm` at FIRE time,
     *  which is the correct reading anyway: the realm a deadline re-enters is the one
     *  standing when it fires (a transport handover replaces it while the slot stays). */
    const newSlot = (loaded: LoadedBundle, pureModules: PureModules): AppSlot => {
        let slot: AppSlot;
        const timers = createRealmTimers((id) => {
            const args = new Uint8Array(4);
            writeU32BE(args, 0, id);
            // A guest that arms a deadline without registering `timer` is refused by its
            // own realm, and an app's `timer` may legitimately throw. Neither has a caller
            // left to reject — the arming call returned turns ago — so report and swallow.
            void slot.realm?.call("timer", args).catch((err: unknown) => {
                console.error(`[shell] guest error in timer: ${errMessage(err)}`);
            });
        });
        const appScope = appScopeFor(platform.sodium, loaded.author, loaded.manifest.app);
        const scope = slotSignScope(platform, loaded.author, loaded.manifest.app, privilegesOf(loaded.manifest));
        slot = {
            verifiedBundle: loaded,
            pureModules,
            fsScope: fs ? scopedFs(fs, appScope) : undefined,
            appScope,
            signingScope: scope,
            realm: null,
            active: false,
            timers,
        };
        return slot;
    };
    /** Cancel deadlines, then dispose realm. Every teardown path goes through this. */
    const disposeSlot = (slot: AppSlot | null | undefined) => {
        slot?.timers.clearAll();
        slot?.realm?.dispose();
        slot?.pureModules.dispose();
    };
    /** Reify a JSON value through JSON.parse rather than as an object literal. Besides
     *  keeping strings safely quoted inside source, this preserves JSON's treatment of a
     *  key named `__proto__` as ordinary data instead of invoking object-literal prototype
     *  syntax. */
    const jsonPreamble = (name: string, value: JsonObject): string => {
        const json = JSON.stringify(value);
        return `const ${name} = JSON.parse(${JSON.stringify(json)});\n`;
    };
    /** Stand one candidate realm. It remains outside `slots` and `claims` until this and
     *  the freshness write both succeed. Both bounds resolve per load: this load's number,
     *  else the node's default, else the shared one — never the author's, since a bundle
     *  cannot ask for more of the host than the operator gave it. */
    const standRealm = async (slot: AppSlot, localConfig: JsonObject, load: LoadBundleOptions): Promise<void> => {
        const b = slot.verifiedBundle;
        // Absent ≡ `{}`, so `APP` is always an object to read names off (isValidManifest
        // already refused any non-object).
        const appConfig = b.manifest.guest.config ?? {};
        slot.realm = await platform.createRealm({
            source: jsonPreamble("APP", appConfig) + jsonPreamble("LOCAL", localConfig) + b.guestSource,
            hostCall: seamFor(slot),
            memoryLimitBytes: load.realmMemoryBytes ?? opts.realmMemoryBytes ?? DEFAULT_REALM_MEMORY_BYTES,
            deadlineMs: load.guestDeadlineMs ?? opts.guestDeadlineMs ?? DEFAULT_GUEST_DEADLINE_MS,
        });
    };
    /** Wire the `host.call` seam one admitted bundle's realm runs against (guest-seam.ts),
     *  as the three things that own it: what this NODE is (`platform`), what this REALM
     *  may reach (`grants`), and what this APP installed (`modules`). A bundle reaching
     *  `link` is wired with `rawNet`: without it a bundle is never handed a socket
     *  descriptor (§1, capability-by-non-wiring). Timers are NOT such a grant — `timer/*`
     *  is an ordinary `"app"` authority (core/domains.ts), so every realm gets a table. */
    const seamFor = (slot: AppSlot): HostCall => {
        const b = slot.verifiedBundle;
        const links = hasLink(slot);
        // The 32 bytes this realm is attributed by when it calls another: the app key,
        // hashed. The same shape as the sender key prepended to an inbound frame, so a
        // callee reads one field whether the caller was a peer or a co-resident app. Zero
        // is the HOST's own, and no app key derives it.
        const callerId = genesisHash(platform.sodium, enc.encode(keyOf(slot)));
        const fullSeam = createGuestSeam({
            platform: {
                sodium: platform.sodium,
                identity: platform.identity,
                now: platform.now ?? (() => Date.now()),
            },
            grants: {
                // The declared requires ARE the gate — a `host.call` resolves iff the name
                // is one of these. `crypto/*` and the bundle's own module names are exempt:
                // a fixed catalog and the app's own code, never grants.
                names: new Set(b.manifest.guest.requires),
                // What node/sign signs under: this slot's ONE scope, derived at load —
                // an ordinary app's own `DOMAIN_guest ‖ author ‖ app`, the link slot's
                // `DOMAIN_link_scope ‖ networkKey` (§12.2). The host chooses what the
                // name means; the seam prefixes and never parses, so no op signs raw
                // bytes.
                signScope: slot.signingScope,
                // Scoped to this app key, so `fs` grants reach this app's own keyspace, not
                // the node's — the same structural ownership module names have (§5.1).
                // Wired whenever the node has an fs at all, without consulting the
                // manifest: `names` already refuses every `fs/*` the bundle did not
                // declare, and a second test here would decide one grant in two places.
                fs: slot.fsScope,
                // The cross-realm call. Resolution happens at CALL time, not here: an app
                // may be installed before its service, and a later load may replace that
                // service — a claimant captured at seam construction would pin this realm
                // to whoever was there first.
                calls: { call: (id, payload) => crossRealmCall(callerId, id, payload) },
                rawNet: links ? netHost?.rawNet(slot) : undefined,
                // Unconditional for the same reason `fs` is.
                timers: slot.timers,
            },
            // This slot's private module value: no app-key lookup and no cross-app
            // namespace. The deadline is the calling guest's remaining segment (§4.3).
            modules: {
                names: new Set(b.manifest.modules.map((m) => m.name)),
                call: slot.pureModules.call,
            },
        });
        // A candidate's top level runs before its mark and claims commit, so until then the
        // seam refuses what disposing that candidate could not take back (`isIrreversible`).
        // Everything a guest initializes from stays open: its reads, `crypto/*` and its own
        // modules. The node facts a link occupant needs are never read OFF this seam — the
        // host invokes the freshly stood slot's `handle` once with them, as the `init`
        // op's payload (initLinkSlot), before the binding is published.
        return (name, payload, budget) => {
            if (!slot.active && isIrreversible(name)) {
                throw new Error(`shell: '${name}' is refused until this bundle's installation commits`);
            }
            return fullSeam(name, payload, budget);
        };
    };
    /** Enter a slot's guest. The null arm is reachable only from guest top-level code
     *  while its candidate realm is still being constructed. */
    const callSlot = (slot: AppSlot, input: Uint8Array) => slot.realm
        ? slot.realm.call("handle", input)
        : Promise.reject(new Error("shell: the guest's realm is not standing yet"));
    /** Loopback invoke with host caller id. Chained onto `inFlight` so `close()`
     *  waits for parked calls (§2.1). */
    const invokeSlot = (slot: AppSlot, op: string, payload: Uint8Array): Promise<Uint8Array> => {
        const call = callSlot(slot, opCall(op, payload));
        inFlight = inFlight.then(() => call, () => call).catch(() => { }) as Promise<void>;
        return call;
    };
    /** The one delivery of the node's immutable facts to a link occupant: an `init` op
     *  into the freshly stood slot's `handle`, with the host's caller id, before the
     *  binding is published and before any event. Constructor argument, not a capability:
     *  nothing here is re-readable, and what is mutable — the address book — arrives as
     *  `addr` events after publication. */
    const initLinkSlot = async (slot: AppSlot): Promise<void> => {
        const facts = netHost?.initialConfig();
        if (!facts)
            throw new Error(`shell: a bundle reaching "${PRIVILEGE_LINK}" has nowhere to go on a shell with no raw-link driver`);
        await invokeSlot(slot, "init", facts);
    };
    netHost?.route((payload) => {
        // The link occupant's `handle` return is the driver's to read: an inbound request
        // the occupant decoded is returned as a delivery frame, which the driver hands to
        // the shell's claim routing (`routeDeliver`) and answers back through `linkResp`.
        return linkOwner ? callSlot(linkOwner, payload) : null;
    }, () => linkOwner !== null, (claim, attribution, payload) => {
        // The driver normalizes the answer to empty before writing it back, so refusal
        // and silence are one fact at the boundary.
        return deliverInbound(claim, attribution, payload);
    });
    /** Cross-realm call by reserved id. Host prepends caller's 32-byte id. */
    const crossRealmCall = (callerId: Uint8Array, id: string, payload: Uint8Array): Promise<Uint8Array> | null => {
        return callLocal(id, callerId, payload);
    };
    /** Refuse a candidate contesting a claim or the raw-link binding another identity
     *  holds (§12.10). Asked before candidate code runs, then again in the commit window. */
    const refuseContested = (loaded: LoadedBundle, key: string) => {
        for (const claim of loaded.manifest.protocols ?? []) {
            if (platformClaims.has(claim)) {
                throw new Error(`shell: claim '${claim}' is already held by the platform`);
            }
            const incumbent = claims.get(claim);
            if (incumbent && keyOf(incumbent) !== key) {
                throw new Error(`shell: claim '${claim}' is already held by '${keyOf(incumbent)}'`);
            }
        }
        // Refused rather than shadowed for the same reason a claim is, and LOUDLY because
        // the alternative is a node that looks installed and is off the network: the
        // incumbent keeps its claims and its realm, and only its sockets stop answering.
        if (linkOwner && keyOf(linkOwner) !== key && reachesLink(loaded.manifest)) {
            throw new Error(`shell: the "${PRIVILEGE_LINK}" binding is already held by '${keyOf(linkOwner)}' — uninstall it before installing another bundle that reaches "${PRIVILEGE_LINK}"`);
        }
    };
    /** Persist freshness mark after the candidate stands, before claim commit. */
    const commitMark = (loaded: LoadedBundle, prev: number) => {
        const { author, manifest } = loaded;
        try {
            platform.freshnessStore.set(author, manifest.app, manifest.version);
        }
        catch (e) {
            platform.freshnessStore.resetMark(author, manifest.app, prev);
            throw new Error(
                `shell: the candidate ran but its freshness mark could not be persisted — the running slot was unchanged: ${errMessage(e)}. ` +
                "Fix the store and re-run the load.",
                { cause: e },
            );
        }
    };
    const doUninstall = (appKey: string) => {
        const i = slots.findIndex((slot) => keyOf(slot) === appKey);
        if (i < 0) return false;
        const [slot] = slots.splice(i, 1);
        const ownedLinks = linkOwner === slot;
        releaseClaims(slot);
        if (ownedLinks) {
            linkOwner = null;
            netHost?.release(slot);
        }
        disposeSlot(slot);
        return true;
    };
    /** Hand a request to the realm claiming `claim`. Answer is the realm's Promise. */
    const callClaimant = (claim: string, attribution: Uint8Array, payload: Uint8Array): Promise<Uint8Array> | null => {
        const slot = claims.get(claim);
        if (!slot) return null;
        const input = new Uint8Array(attribution.length + payload.length);
        input.set(attribution, 0);
        input.set(payload, attribution.length);
        return callSlot(slot, input);
    };
    /** Inbound from outside this node (the link occupant's delivery return, `dispatch`).
     *  `_`-led claims are local and refused here with no exception — platform claims
     *  included (§12.10). */
    const deliverInbound = (claim: string, attribution: Uint8Array, payload: Uint8Array): Promise<Uint8Array> | null => {
        if (isReservedProtocol(claim)) return null;
        const platformHandler = platformClaims.get(claim);
        if (platformHandler) return platformHandler(attribution, payload);
        return callClaimant(claim, attribution, payload);
    };
    /** The cross-realm call, from a co-resident guest. Only a reserved id is callable (the
     *  seam's grant gate), so this is the local half of the same table. */
    const callLocal = (claim: string, callerId: Uint8Array, payload: Uint8Array): Promise<Uint8Array> | null => {
        const platformHandler = platformClaims.get(claim);
        if (platformHandler) return platformHandler(callerId, payload);
        return callClaimant(claim, callerId, payload);
    };
    const doDispatch = (from: PeerId, proto: string, payload: Uint8Array) =>
        deliverInbound(proto, fromHex(from), payload);
    return {
        resolve: (proto) => {
            const slot = claims.get(proto);
            return slot ? keyOf(slot) : platformClaims.has(proto) ? PLATFORM_OWNER : null;
        },
        routes: () => [
            ...[...platformClaims.keys()].map((claim): [string, string] => [claim, PLATFORM_OWNER]),
            ...[...claims].map(([claim, slot]): [string, string] => [claim, keyOf(slot)]),
        ],
        fs,
        sodium,
        async loadBundleBlob(blob, loadOpts = {}) {
            const localConfig = loadOpts.localConfig ?? {};
            if (!isJsonObject(localConfig))
                throw new Error("shell: localConfig must be a JSON object");
            const v = verifyBundle(sodium, blob);
            // What this bundle REACHES, read off the requires and nothing else (§12.5):
            // there is no `role` field, because the requires are what the seam actually
            // wires and so are the fact that must be right anyway. An author cannot shed a
            // privilege by declaring one — adding `link/open` puts `link` in this set and
            // nothing takes it out.
            const privileges: Privilege[] = privilegesOf(v.manifest);
            // ADMISSION — one predicate, one call, one answer (§12.5), a pure function of
            // `(bundle, context)`, with the constraints' ordering (revocation before a
            // consent dialog, coherence before the operator is asked, the downgrade guard
            // before anything lands) stated once at construction. Nothing decides
            // admission beside the predicate, which is what makes "nothing has landed"
            // hold for the whole decision rather than most of it.
            const ctx: AdmissionContext = {
                privileges,
                highWater: platform.freshnessStore.get(v.author, v.manifest.app),
                revoked: platform.freshnessStore.isRevoked(v.author),
            };
            if (!(await admit(v, ctx)))
                throw new Error(ADMISSION_REJECTED);
            const loaded: LoadedBundle = {
                manifest: v.manifest, author: v.author, authorKeys: v.authorKeys,
                guestSource: v.guestSource,
            };
            const key = appKeyFor(loaded.author, loaded.manifest.app);
            // Refuse a conflict already standing BEFORE the candidate's modules or guest
            // execute: a known loser is not worth a realm. The second check in the
            // synchronous commit window remains necessary, since another load may take a
            // free claim while this candidate is built.
            refuseContested(loaded, key);
            const pureModules = await loadBundleModules(moduleLoader, v);
            const slot = newSlot(loaded, pureModules);
            // Stand the guest, before anything already standing is replaced. Every app is a
            // guest (§12.4), so a bundle whose guest will not compile has not loaded — and
            // discovering that at the first frame instead would leave the mark advanced for
            // a bundle that never ran a line, putting every version an operator can reach
            // below a floor a broken upgrade raised: rollback bricked by a failed upgrade.
            try {
                await standRealm(slot, localConfig, loadOpts);
                // The host invokes the link occupant once with the node facts — an init
                // op into its own `handle`, not a name it calls back later. A transport
                // that refuses its own boot arguments fails the load: nothing below has
                // been marked or claimed, so the candidate is simply disposed.
                if (hasLink(slot)) await initLinkSlot(slot);
                // The candidate is complete. EVERYTHING FROM HERE IS SYNCHRONOUS, which is
                // what makes the commit atomic: the contest below, the mark, and the claim
                // hand-over cannot be interleaved with another load or an uninstall.
                refuseContested(loaded, key);
                commitMark(loaded, ctx.highWater);
            }
            catch (err) {
                disposeSlot(slot);
                throw err;
            }
            const previousIndex = slots.findIndex((installed) => keyOf(installed) === key);
            const previous = previousIndex < 0 ? undefined : slots[previousIndex];
            const replacingLinkOwner = previous !== undefined && linkOwner === previous;
            if (previous) releaseClaims(previous);
            if (previousIndex < 0) slots.push(slot);
            else slots[previousIndex] = slot;
            for (const claim of slotClaims(slot)) claims.set(claim, slot);
            // The outgoing guest's link state went with its realm (§4.3), so the sockets it
            // held are torn down here rather than left as channels nobody can speak for. The
            // incoming guest redials from the address book, which is the NODE's. After the
            // claim hand-over above, so `onClose` finds the channels already gone and queues
            // no `linkClosed` at the new realm for links it never had. Only ever a free
            // binding or this identity's own: `refuseContested` turned any other candidate
            // away, and a version that DROPS `link/*` releases the binding the same way
            // dropping a claim releases the claim.
            if (hasLink(slot)) {
                netHost?.activate(slot);
                linkOwner = slot;
            } else if (replacingLinkOwner) {
                linkOwner = null;
                netHost?.release(previous!);
            }
            // The mark and every claim/link binding have landed, so this slot's writes and
            // cross-realm calls are now its own (`seamFor`).
            slot.active = true;
            // The address book is mutable node state, not part of the immutable facts the
            // occupant received at init. Publish first, then replay it through the
            // ordinary host-event path. No await in between: a concurrent add is either
            // in this replay or is announced directly to the newly published claimant.
            if (linkOwner === slot) netHost?.replayAddresses();
            disposeSlot(previous);
            // The handle: the verified facts plus the bound slot — the key, the scoped fs
            // view and the loopback invoke. One object, so a caller cannot derive half of
            // it from the manifest and half from the shell and have the two disagree.
            const handle: AppHandle = {
                ...loaded,
                key,
                fs: slot.fsScope,
                appScope: slot.appScope,
                invoke: (op, payload) => invokeSlot(slot, op, payload),
            };
            return handle;
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
            const gone = [];
            for (const slot of [...slots]) {
                if (toHex(slot.verifiedBundle.author) === hex) {
                    const appKey = keyOf(slot);
                    doUninstall(appKey);
                    gone.push(appKey);
                }
            }
            return gone;
        },
        async invoke(op, payload, appKey) {
            const slot = findSlot(appKey);
            if (!slot)
                throw new Error(`shell: no app '${appKey}' loaded`);
            // `AppHandle.invoke` is the same call with the slot already bound — see
            // `invokeSlot` for the framing and the close() chaining.
            return invokeSlot(slot, op, payload);
        },
        dispatch: doDispatch,
        close() {
            netHost?.close();
            const dispose = () => {
                for (const slot of slots) disposeSlot(slot);
                slots.length = 0;
                claims.clear();
            };
            inFlight.then(dispose, dispose);
        },
    };
}

/** JS-target assembly options (§12.9). Every field but `sodium` and `identity`
 *  has a default; the pin and load order are part of standing a node up. */
export interface BootShellOptions {
    /** The crypto surface the shell needs — sumo libsodium with the ML-DSA-65 verifier
     *  mixed in (the one thing no target can default: main.ts loads it, a browser page
     *  readies it). */
    sodium: ShellSodium;
    /** The node's keypair (§12.9): its public half is this node's peer id and the one
     *  identity every target reports through `node/identity`. */
    identity: Keypair;
    /** YOUR admission predicate (§12.5) — the one branch that is actually yours: an
     *  operator's policy, a consent dialog, or `() => true` for "the bundle my operator
     *  handed me IS the trust decision". The transport author pin is ANDed onto it here,
     *  and the host's own gates (`hostGates`) by the shell, so no posture can lose either.
     *  It is consulted for EVERY bundle, privileged ones included; a gate that only knows
     *  how to judge apps says so by admitting anything reaching a privilege and leaving
     *  that to the pin, which refuses on its own instead of waving it through. Absent ⇒
     *  deny-all: the node boots and serves, accepts no installs. */
    admit?: Admit;
    /** The fs backend the shell's `fs` capability and every app's scoped view sit on.
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
    /** The builder for a bundle's private pure modules (§4). Default: `ModuleTable`, the
     *  JS worker-backed builder; the native loader passes its Go-backed one. */
    modules?: PureModuleLoader;
    /** The confined realm factory (§12.3). Default: the lazy safe-js import — the QuickJS
     *  engine is heavy, so it loads on the first realm, which is why realm creation is a
     *  platform member rather than something the shared shell reaches for itself. */
    createRealm?: RealmFactory;
    now?: () => number;
    /** Platform-owned claims ({@link PlatformClaims}). */
    claims?: PlatformClaims;
    /** Which network this node belongs to (§12.6) — an isolation boundary, not a gate.
     *  Absent ⇒ the public network. */
    networkKey?: Uint8Array;
    guestDeadlineMs?: number;
    realmMemoryBytes?: number;
    /** The channel adapter. An OPTIONS object ⇒ bootShell constructs the `TransportHost`
     *  (identity and networkKey come from the top-level fields, never restated), admits
     *  the transport bundle under the pin, and starts its listeners. A `TransportHost`
     *  instance ⇒ the caller owns it — and its transport-bundle load (a browser edge loads
     *  lazily and re-loads to change its room secret), so bootShell neither loads nor
     *  starts. `false` or absent ⇒ a shell with no network: no adapter, no pin, no load. */
    transport?: Omit<TransportHostOptions, "identity" | "networkKey"> | TransportHost | false;
    /** The transport bundle to PIN — and, in the options case, load. Default: the
     *  artifact-shipped one (`transportBundleBytes`). */
    transportBundle?: Uint8Array;
}

/** What `bootShell` hands back: the shell, plus the channel adapter — the one piece the
 *  shell does not expose and a platform still has to drive (the address book, the
 *  listeners). The SAME object the shell holds, not a copy. */
export interface BootResult {
    shell: Shell;
    /** The channel adapter. Null ONLY on a node with no network (`transport` absent or
     *  `false`) — which the overloads below say in the type, so a caller that asked for a
     *  network does not assert its way past a null that cannot happen. The fs backend is
     *  not here: it is `shell.fs`, whether the caller passed one or took the default. */
    transport: TransportHost | null;
}

export async function bootShell(
    opts: BootShellOptions & { transport: Omit<TransportHostOptions, "identity" | "networkKey"> | TransportHost },
): Promise<BootResult & { transport: TransportHost }>;
export async function bootShell(opts: BootShellOptions): Promise<BootResult>;
export async function bootShell(opts: BootShellOptions): Promise<BootResult> {
    const sodium = opts.sodium;
    // The defaults are imported lazily: they are JS-target parts (a worker-backed module
    // builder, the QuickJS realm engine), and the one target that never takes them (the
    // native loader, which supplies Go-backed equivalents) must not pay for them.
    // `false` is a node with no disk, the one member whose absence is NOT its default:
    // omitted asks for the in-memory backend, said-as-false asks for none.
    const fs = opts.fs === false ? undefined : opts.fs ?? new ((await import("./fs-memory.js")).MemoryFs)();
    const modules = opts.modules ?? new ((await import("./module-table.js")).ModuleTable)();
    const createRealm = opts.createRealm
        ?? (async (o) => (await import("./safe-js.js")).createSafeRealm(o));
    const freshnessStore = opts.freshnessStore ?? new FreshnessMarks();
    // The channel adapter: CONSTRUCTED here when given options (identity + network key
    // are the NODE's, so they are taken from the top-level fields rather than restated),
    // accepted as-is when given an instance (a browser edge with a getter contact
    // secret), absent when false. `ownAdapter` is the adapter this assembly BUILT rather
    // than a flag about one, so "did we construct it" and "which one is it" cannot drift
    // apart — and it is what the transport load below is gated on: an instance's load is
    // its owner's.
    const ownAdapter = opts.transport && !(opts.transport instanceof TransportHost)
        ? new TransportHost({ ...opts.transport, identity: opts.identity, networkKey: opts.networkKey })
        : null;
    const transport = ownAdapter ?? (opts.transport instanceof TransportHost ? opts.transport : null);
    // The transport bundle this node pins, and (when constructed here) loads: the
    // caller's or the artifact-shipped one. Its author is DERIVED from the blob, never
    // restated — the pin is the whole of "only this author may be the network" (§12.5).
    const transportBlob = transport ? (opts.transportBundle ?? transportBundleBytes()) : null;
    let transportAuthorHex: string | null = null;
    if (transportBlob) {
        try {
            transportAuthorHex = toHex(verifyBundle(sodium, transportBlob).author);
        }
        catch { /* malformed blob — the load below refuses it by name */ }
    }
    // The implicit transport pin, composed AROUND the caller's predicate: a bundle
    // reaching `link` must be signed by the transport bundle's own author. An
    // operator's `policyFromJson` keeps the power to refuse a transport author — the
    // caller's predicate still has to admit as well — and nobody can LOSE the pin by
    // forgetting it: a caller whose admit is a plain consent gate is not also responsible
    // for the half that protects the network.
    //
    // It is keyed on the privileges the manifest reaches, and FAIL-CLOSED on the ones it
    // does not know. `PRIVILEGES` is derived from the capability catalog
    // (core/domains.ts), so a privileged name added there appears here as a privilege
    // with no branch — and a bundle reaching it is refused rather than waved through by
    // a caller whose gate says "privileged bundles are the pin's business". A new
    // privilege is taught to the assembly deliberately, in this one place, which is the
    // whole reason the assembly is an export.
    const admit: Admit = allOf(opts.admit ?? denyAll, (v, ctx) => {
        if (ctx.privileges.length === 0) return true;
        for (const priv of ctx.privileges) {
            if (priv !== PRIVILEGE_LINK) return false;
        }
        return transportAuthorHex !== null && toHex(v.author) === transportAuthorHex;
    });
    const shell = createShell({
        platform: {
            sodium, identity: opts.identity, modules, fs,
            freshnessStore, networkKey: opts.networkKey,
            transportHost: transport ?? undefined,
            createRealm, now: opts.now,
        },
        admit,
        claims: opts.claims,
        guestDeadlineMs: opts.guestDeadlineMs,
        realmMemoryBytes: opts.realmMemoryBytes,
    });
    // The transport bundle IS the node's network (§12.6): verify + govern under the
    // composed predicate, install, and the shell stands the driver up. A predicate that
    // refuses the transport author leaves the node without a network, which is a
    // deliberate configuration rather than an error. Only when bootShell constructed the
    // adapter: a caller that handed over an instance owns its load (a browser edge loads
    // lazily, and re-loads to change its room secret).
    //
    // A boot that throws returns no handle, so whatever it stood up must not leak: one
    // teardown, the shell's — which closes the adapter it was built with.
    try {
        if (ownAdapter && transport && transportBlob) {
            try {
                await shell.loadBundleBlob(transportBlob);
            }
            catch (err) {
                if (!isAdmissionRejected(err)) throw err;
                console.warn('  no transport: the policy does not grant this bundle the "link" privilege');
            }
            await transport.start();
        }
        return { shell, transport };
    }
    catch (err) {
        shell.close();
        throw err;
    }
}
