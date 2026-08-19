// The platform-neutral shell core (§12.9): everything standing a node up involves except
// what genuinely varies by target — the module table's owner, the guest-seam wiring, the
// preamble assembly, the realm lifecycle, the bundle load order, the socket driver and the
// inbound dispatch. A target hands in a `ShellPlatform` and gets back a wired Shell.
//
// This is the ONE assemble path, and the assembly ORDER is the point: it is the last thing
// two hosts could disagree about, so no target restates it.
//
//   main.ts       → boot()         → ModuleTable + NodeFs + FileFreshnessStore + NodeChannelFactory + safe-js → createShell()
//   browser       → chat-shell.js  → ModuleTable + RtcNetwork-style openLink edges + sessionStorage freshness  → createShell()
//   native        → native-shim.ts → Go module table + Go Fs + Go channels + Go realm                → createShell()
//   seedstore     → StorageNode    → { MemoryFs, FreshnessMarks }                  → createShell() + loadBundle(seedstore.skb)
//
// installWasmModule is not public API on the Shell and there is no raw-bind path — the
// only way code lands is via a signed bundle (§12.4), making the §3.1 claim structurally
// true instead of true-by-convention.
import { denyAll, allOf, hostGates, type Admit, type AdmissionContext } from "./policy.js";
import { appKeyFor, appScopeFor, genesisHash, privilegesOf, verifyBundle, installBundle, type BundleCrypto, type BundleHost, type FreshnessStore, type LoadedBundle, type VerifiedBundle } from "./bundle.js";
import { createGuestSeam, appSignScope, transportSignScope, opCall, readOp, type SeamCrypto, type HostCall, type HostTimers } from "./guest-seam.js";
import type { TransportHost } from "./transport-host.js";
import { isSafeFsKey, isSafeFsScope, type Fs } from "../core/fs.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_MAX_LIVE_TIMERS, DEFAULT_REALM_MEMORY_BYTES } from "../core/wasm-limits.js";
import { NET_PROTOCOL, PRIVILEGE_LINK, SHELL_PROTOCOL, type Privilege } from "../core/domains.js";
import { dec, enc, fromHex, toHex, readU32BE, writeU32BE, errMessage } from "../core/util.js";
import { type SafeRealm } from "./safe-js.js";
import { type PeerId } from "../core/socket-seam.js";
import type { Keypair } from "../core/subkeys.js";

/** The crypto surface the shell needs: manifest verification + genesis hashing
 *  (BundleCrypto) plus the guest seam's crypto ops (SeamCrypto). Any sumo libsodium
 *  build satisfies both. */
export type ShellSodium = BundleCrypto & SeamCrypto;

/** The one reason a bundle load is refused without being an error worth reporting: the
 *  policy predicate said no (§12.4). A shared constant rather than a string callers
 *  re-match — the transport's installers read it as "a node without a network", which is a
 *  deliberate configuration rather than a failure. */
export const ADMISSION_REJECTED = "bundle: rejected by admission predicate";

/** True iff a loadBundleBlob failure was the policy's refusal (see ADMISSION_REJECTED),
 *  whatever shape the thrown value took. */
export function isAdmissionRejected(err: unknown): boolean {
    return errMessage(err).includes(ADMISSION_REJECTED);
}

/** How a target creates the confined realm a guest runs in (§12.3): `createSafeRealm`
 *  (safe-js.ts) on the JS platforms, a quickjs-ng realm on Go's event loop
 *  (native/guest.go) on the native one. Same contract either way — one `call`, which may
 *  await, and invocations serialized per realm. The shell always supplies both bounds, so
 *  a factory never has to decide what "omitted" means. */
export type RealmFactory = (opts: {
    source: string;
    hostCall: HostCall;
    memoryLimitBytes?: number;
    /** Budget of guest *execution* time per entrypoint invocation, in ms. Omitted ⇒ the
     *  factory's own default (`DEFAULT_GUEST_DEADLINE_MS` on both targets). */
    deadlineMs?: number;
}) => Promise<SafeRealm>;

/** The module table as exposed by the Shell: reaching installed modules, without
 *  installWasmModule and without removeApp. The bind is the bundle loader's job (§12.4),
 *  the unbind the shell's `uninstall` (§12.5) — neither is a public host method.
 *
 *  `callModule` is async because a module call round-trips (the JS targets run a module in
 *  its own worker), and it carries a deadline under which the call is killed and respawned
 *  rather than holding the node's thread (§4.3). */
export interface ModuleLookup {
    callModule(appKey: string, module: string, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array | null>;
    isBound(appKey: string, module: string): boolean;
}

/** The §3 module table as the shell uses it: the one transactional install a bundle load
 *  needs (`BundleHost.bindAll`), plus reaching and releasing what landed. A platform
 *  primitive, not shell logic — `ModuleTable` over `WebAssembly` here, Go's wazero map
 *  behind its byte bridge natively (§12.9). Only who owns the instances differs, which is
 *  why both the all-or-none bind and the release live behind it rather than in the
 *  loader. */
export interface ModuleTableBackend extends BundleHost, ModuleLookup {
    /** Drop an app and every module it landed, returning how many went. One lookup is
     *  all `uninstall` needs: an app's modules are the value under its key (§5.1), so
     *  the unit of removal is the unit of install. */
    removeApp(appKey: string): number;
}

/** The platform seam — everything the shell needs that varies by target. `fs` is optional
 *  ("a node with no disk"): a bundle declaring `fs` on such a shell gets no backend wired,
 *  so its first `fs/*` call throws by name rather than resolving to a pretend store
 *  (§12.2). `createRealm` is required — every app is a guest.
 *
 *  The current channel adapter remains a platform resource. The shell only points it at
 *  whichever ordinary protocol claimant currently owns `_net`; it neither exposes the
 *  adapter nor gives that bundle a distinct lifecycle. */
export interface ShellPlatform {
    sodium: ShellSodium;
    /** The node's keypair (§12.9): its public half is this node's peer id and the one
     *  identity every target reports through `node/identity`. The handshake and the seam's
     *  SIGN op both sign with it, under different domains and scopes. */
    identity: Keypair;
    /** The module table this shell binds bundle modules into (§3). */
    table: ModuleTableBackend;
    fs?: Fs;
    freshnessStore: FreshnessStore;
    createRealm: RealmFactory;
    now?: () => number;
    /** OPTIONAL network key — which network this node belongs to. An isolation boundary,
     *  not a gate (§12.6); absent ⇒ the public network. Feeds the transport guest's INIT
     *  and the channel-signing scope granted to a bundle reaching `link`
     *  (`transportSignScope`).
     *
     *  The scope is the load-bearing use: `node/sign` prefixes and never parses, so it is
     *  the only binding of a channel signature to this node's network that the slot
     *  occupant cannot choose. Drop it from the preimage and a confined transport on one
     *  network can mint transcripts another network's verifier accepts. */
    networkKey?: Uint8Array;
    /** The concrete channel adapter: the sockets, the listeners and the address book, all
     *  of them the NODE's rather than any guest's. The platform CONSTRUCTS it, because
     *  every knob on it (which addresses to bind, how many conns per peer, the half-open
     *  budgets) is a deployment's answer and not the shell's — and then hands it over,
     *  shell.close() closing it, so there is one teardown rather than a second thing every
     *  embedder must remember.
     *
     *  The shell's whole part is pointing it at whichever bundle currently claims `_net`.
     *  Absent for a shell with no raw links at all (a browser edge), where a bundle
     *  claiming `_net` simply gets no sockets. */
    transportHost?: TransportHost;
}

export interface CreateShellOptions {
    /** The operator's admission predicate (§12.5) — one `Admit`, asked once per load,
     *  between verify and install. A file-backed author allowlist, a consent dialog and
     *  "the bundle my operator handed me" are three constructors of this one type; a
     *  deployment answering per capability composes `byPrivilege({ base, grants })`, as
     *  `policyFromJson` does. Absent ⇒ deny-all.
     *
     *  The host's own gates — revocation, the coherence rules, the downgrade guard — are
     *  composed AROUND whatever is passed here (`hostGates`), so no operator posture can
     *  be a way to lose them. */
    admit?: Admit;
    /** Operator-supplied app config, merged *over* the bundle manifest's `config`
     *  into the guest's `const APP = …`. Opaque to the shell. */
    config?: Record<string, string | number>;
    /** QuickJS heap limit for the guest realm, in bytes. Omitted ⇒
     *  `DEFAULT_REALM_MEMORY_BYTES`. A target that streams large windows through the guest
     *  raises it (seedstore's `realmMemoryBytes`). */
    realmMemoryBytes?: number;
    /** Budget of guest execution time per entrypoint invocation, in ms. Omitted ⇒
     *  `DEFAULT_GUEST_DEADLINE_MS`; `Infinity` disables it. Counts time the guest is
     *  *running*, not time parked on a host seam, so it bounds a wedged guest without
     *  penalising one legitimately awaiting the network.
     *
     *  The operator's number, not the author's: unlike the module memory ceiling (§4.3),
     *  how long this node will spend on one message is a property of the deployment. */
    guestDeadlineMs?: number;
    /** The SHELL's own protocols, answered ahead of the routing table (§12.10) — e.g.
     *  seedchat's `_offer`, which carries a bundle between two browsers before either has
     *  an app that could receive it.
     *
     *  `null` means "not mine" and falls through to the routing table, so a shell that
     *  answers one id does not shadow the apps. Consulted on INBOUND frames only: a
     *  co-resident app's cross-realm call carries an app key rather than a peer key, and an
     *  app addresses an app. */
    answer?: (from: PeerId, proto: string, payload: Uint8Array) => Promise<Uint8Array> | null;
}

export interface Shell {
    /** The module table: callModule to reach an app's installed modules, isBound to
     *  check occupancy. installWasmModule is NOT on this interface — code lands
     *  only via loadBundleBlob (§12.4). */
    host: ModuleLookup;
    /** Which app serves this protocol, or null (§12.10). A read of the projection the
     *  installed manifests define — there is nothing to write here. */
    resolve(proto: string): string | null;
    /** Every protocol this node serves, as `[proto, appKey]` — what an operator's console
     *  line or a shell's UI lists. A snapshot, not the live map. */
    routes(): [string, string][];
    /** Filesystem backend, or absent for a node with no disk (a bundle declaring the
     *  `fs` cap then gets no backend wired — its first `fs/*` call throws). */
    fs?: Fs;
    sodium: ShellSodium;
    /** Load a signed bundle blob: verify the manifest, run the admission predicate,
     *  integrity-check + install the modules, STAND THE GUEST, and return the guest source.
     *  Every bundle takes this same §12.4 path.
     *
     *  A load either leaves a running app behind or leaves nothing: the realm is built
     *  here, so a guest that cannot compile fails the load rather than the first frame that
     *  reaches it, and the freshness mark — which records the highest version that actually
     *  RAN — is advanced last, once it has. */
    loadBundleBlob(blob: Uint8Array): Promise<LoadedBundle>;
    /** Uninstall an app: remove every module derived from `appKey`,
     *  drop the protocols it claimed, and dispose the confined realm if
     *  this was its last app. Returns true if any modules were removed.
     *  The one uninstall path, symmetric with loadBundleBlob (§12.5). */
    uninstall(appKey: string): boolean;
    /** Write off an author key: refuse everything it signs from now on, and uninstall every
     *  app of its already running. Returns the app keys torn down.
     *
     *  One call because the halves are useless apart — uninstalling alone leaves nothing to
     *  stop the thief's next bundle landing on the same derived names, refusing alone
     *  leaves the compromised code running — and an operator doing it by hand can do half.
     *
     *  Permanent and host-local: the key stays refused across reboots and across later
     *  policy edits. Recovery is a new author key, which derives new names and a fresh mark
     *  (§5.1), not an un-revoke. */
    revoke(authorHex: string): string[];
    /** Invoke a loaded app's one entrypoint, `handle`, as the HOST itself: the shell writes
     *  `[caller 32][opLen u8][op][payload]`, the host's caller id (32 zero bytes) followed
     *  by the op envelope.
     *
     *  The op travels IN the payload, so an app has one op vocabulary whether a peer called
     *  it or the host did. The shell never reads the name but does own the FRAMING, since
     *  the guest half ships in the preamble (`readOp`, guest-seam.ts).
     *
     *  `appKey` defaults to the only loaded app and throws when more than one is loaded.
     *  Addressed by app key
     *  rather than protocol id because an initiator-only app claims no protocol
     *  (bundle.ts), and routing the loopback would force it to expose an inbound surface
     *  merely to be locally drivable. */
    invoke(op: string, payload: Uint8Array, appKey?: string): Promise<Uint8Array>;
    /** Dispatch an inbound request to the right app (§12.10): resolve the protocol to
     *  the app claiming it and invoke that app's guest `handle` entrypoint with
     *  `senderPk ‖ payload`. Null when no installed app claims the protocol.
     *
     *  Every app is a guest, so the answer is always the realm's — a Promise the transport
     *  driver resumes on, never raw bytes. */
    dispatch(from: PeerId, proto: string, payload: Uint8Array): Promise<Uint8Array> | null;
    close(): void;
}

// Re-exported so a target reaches the admission constructors — and `ModuleTable`, which
// every JS platform hands in as its `table` — from the same module it gets createShell
// from.
export { denyAll, admitAll, authorAllowlist, byPrivilege, allOf, anyOf, policyFromJson, type Admit, type AdmissionContext } from "./policy.js";
export { ModuleTable } from "./module-table.js";
/** An app's ONE inbound entrypoint (§12.10): the authenticated `senderPk ‖ payload` in,
 *  the response bytes out. Every app is a guest, so every entry resolves to its realm's
 *  `handle` and returns a Promise. There is no "this app answers nothing" case either —
 *  "nobody claims this id" is the absence of a SLOT, answered by the two callers that
 *  resolve one (`doDispatch`, `crossRealmCall`). */
type AppEntry = (input: Uint8Array) => Promise<Uint8Array>;

/** The answer to a `_host` op that reports rather than asks. */
const EMPTY = new Uint8Array(0);

/** A slot's realm. Nullable for exactly the window between the holder being made and the
 *  factory resolving, inside one `loadBundleBlob` — a slot only enters `apps` with its
 *  realm standing, and teardown reads the settled handle synchronously, because the callers
 *  that dispose are deciding right then what the node holds. */
interface RealmHolder {
  loaded: LoadedBundle;
  realm: SafeRealm | null;
  /** This realm's deadlines. Per SLOT rather than per shell, because a timer is a
   *  pending re-entry into one particular realm: the cap is then one guest's to
   *  spend, and disposing that realm is what cancels exactly its own (`disposeSlot`). */
  timers: RealmTimers;
}

interface AppSlot extends RealmHolder {
  entry: AppEntry;
}

/** A realm's timer table: the platform's event loop, handed to a guest that has none.
 *
 *  Everything here is the HOST's memory — a fresh QuickJS context has no `setTimeout` — so
 *  the live count is capped (an unbounded `timer/arm` loop is a guest spending host memory
 *  it is not charged for), and `clearAll` is not optional at teardown: a pending timeout
 *  holds a callback that re-enters the realm, so one surviving its realm's disposal is a
 *  call into a freed QuickJS context (§2.1), a crash rather than an error. Every disposal
 *  site goes through `disposeSlot`.
 *
 *  `id` is the guest's own throughout, so an arm on a live id re-arms it and `clear` is
 *  idempotent. */
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
// The rule itself is a consensus predicate and lives in the core; the two places the host
// APPLIES it are here, with their only production caller (createShell).

/** Apply the key rule over a backend, once, for every target.
 *
 *  A rejected key **throws** rather than reading as absent: an unrepresentable key is a
 *  caller bug, and `null`/`-1`/`false` would hide it on a read while `put` failed anyway.
 *  `list` is exempt — its argument is a prefix, and the empty prefix is exactly the call a
 *  key rule would wrongly refuse; `stat` names nothing.
 *
 *  Wrapped where a backend enters the shell, so it sits UNDER `scopedFs` and validates the
 *  composite `scope + key` the medium actually sees. */
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

/** Scope a backend to one app's private keyspace (§12.2), so two apps granted `fs` cannot
 *  read, enumerate or delete each other's keys. Ownership becomes structural here the same
 *  way it is for table names (§5.1): by derivation, not by a rule something enforces.
 *
 *  `scope` is the opaque prefix `appScopeFor` (bundle.ts) derives from the app key. Two
 *  properties come from that derivation: it lies inside the backend's key charset (checked
 *  below), and it is fixed-length, so distinct scopes cannot overlap however an author
 *  names the app.
 *
 *  `stat()` is deliberately NOT scoped — `used`/`available` describe the physical backend,
 *  and a per-app `available` would be a fiction. An app that wants its own footprint sums
 *  `size()` over its own `list()`. */
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

export function createShell(opts: CreateShellOptions & {
    platform: ShellPlatform;
}): Shell {
    const { platform } = opts;
    const sodium = platform.sodium;
    // The key rule applied once, over whatever backend this target supplied, so every host
    // admits exactly the same key space — which is what decides the contents a node stores
    // and advertises.
    const fs = platform.fs ? validatedFs(platform.fs) : undefined;
    const host = platform.table;
    // THE admission predicate (§12.5). The host's own invariants come first and are
    // composed here rather than by the operator: an `admitAll` posture, or a consent
    // dialog that always says yes, must not be a way to lose revocation or the downgrade
    // guard.
    const admit: Admit = allOf(hostGates, opts.admit ?? denyAll);
    const apps = new Map<string, AppSlot>();
    /** protocol id → app key (§12.10) — a PROJECTION of what is installed, never a
     *  structure of its own: every entry comes from some installed manifest's signed
     *  `protocols`, so there is nothing to write, persist, or keep in step. Materialized
     *  rather than scanned for because it is read once per inbound frame. */
    const routes = new Map<string, string>();
    /** The existing concrete channel adapter is supplied and owned by the platform. The
     *  shell may wire raw-link calls to it, but it is not part of the Shell API. */
    const netHost = platform.transportHost;
    // The tail of every initiator `invoke` call. close() defers realm disposal onto
    // this so a call parked mid-await (a repair pass waiting out an unreachable peer)
    // is never resumed into a freed realm — a QuickJS use-after-free (§2.1).
    let inFlight = Promise.resolve();
    /** The one app a bare `invoke` means, or an error naming what is ambiguous. */
    const onlyApp = () => {
        const loaded = [...apps.values()];
        if (loaded.length === 0)
            throw new Error("shell: load a bundle first (loadBundleBlob)");
        if (loaded.length > 1)
            throw new Error("shell: multiple apps loaded — supply appKey");
        return loaded[0];
    };
    /** An empty slot for `loaded`, with its timer table already pointed at the realm the
     *  slot does not have yet. The cycle is tied by reading `holder.realm` at FIRE time,
     *  which is the correct reading anyway: the realm a deadline re-enters is the one
     *  standing when it fires, and a transport handover replaces that realm while the slot
     *  stays. A timer only exists because a guest armed it, so `?.` covers the disposal
     *  race rather than a cold start. */
    const newHolder = (loaded: LoadedBundle): RealmHolder => {
        let holder: RealmHolder;
        const timers = createRealmTimers((id) => {
            const args = new Uint8Array(4);
            writeU32BE(args, 0, id);
            // A guest that arms a deadline without registering `timer` is refused by its
            // own realm, and an app's `timer` may legitimately throw. Neither has a caller
            // left to reject — the arming call returned turns ago — so it is reported and
            // swallowed.
            void holder.realm?.call("timer", args).catch((err: unknown) => {
                console.error(`[shell] guest error in timer: ${errMessage(err)}`);
            });
        });
        holder = { loaded, realm: null, timers };
        return holder;
    };
    /** Release a slot: cancel its deadlines, THEN dispose its realm. Every teardown
     *  path goes through this — uninstall, revoke, close, a transport handover — because
     *  the other order leaves a `setTimeout` holding a callback into a freed QuickJS
     *  context, which is a crash rather than an error (§2.1). */
    const disposeSlot = (slot: RealmHolder | null | undefined) => {
        slot?.timers.clearAll();
        slot?.realm?.dispose();
    };
    /** Stand `slot`'s confined realm — the one place a guest is built, reached once per
     *  load. Both roles share the result: `invoke` and `dispatch` each call `handle`, and
     *  the realm serializes them. */
    const standRealm = async (slot: AppSlot): Promise<void> => {
        slot.realm = await platform.createRealm({
            source: guestFullSource(slot.loaded),
            hostCall: seamFor(slot),
            memoryLimitBytes: opts.realmMemoryBytes ?? DEFAULT_REALM_MEMORY_BYTES,
            deadlineMs: opts.guestDeadlineMs ?? DEFAULT_GUEST_DEADLINE_MS,
        });
    };
    /** Wire the `host.call` seam one admitted bundle's realm runs against (guest-seam.ts),
     *  as the three things that own it: what this NODE is (`platform`), what this REALM
     *  may reach (`grants`), and what this APP installed (`modules`).
     *
     *  A bundle reaching `link` is wired with `rawNet`: a bundle without that capability
     *  cannot reach a socket descriptor because it is never handed one (§1,
     *  capability-by-non-wiring). Timers are NOT such a grant — `timer/*`
     *  is an ordinary `"app"` authority (core/domains.ts), so every realm gets a table. */
    const seamFor = (slot: AppSlot) => {
        const b = slot.loaded;
        const hasLink = privilegesOf(b.manifest).includes(PRIVILEGE_LINK);
        const appKey = appKeyFor(b.author, b.manifest.app);
        // The 32 bytes this realm is attributed by when it calls another: the app key,
        // hashed. The same shape as the sender key prepended to an inbound frame, so a
        // callee reads one field whether the caller was a peer or a co-resident app. Zero
        // is the HOST's own, and no app key derives it.
        const callerId = genesisHash(platform.sodium, enc.encode(appKey));
        return createGuestSeam({
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
                // What SIGN signs under is chosen HERE, by the slot the bundle occupies —
                // the one place that knows it (§12.2). Both slots sign with the node's one
                // key and the slot picks what the signature MEANS: the transport signs
                // transcripts under DOMAIN_channel ‖ networkKey, an app under DOMAIN_guest ‖
                // its own bundle's scope. The seam prefixes and never parses, so neither
                // can produce the other's signature and no op signs raw bytes.
                signScope: hasLink
                    ? transportSignScope(platform.identity, platform.networkKey)
                    : appSignScope(platform.identity, b.author, b.manifest.app),
                // Scoped to this app key, so `fs` grants reach this app's own keyspace and
                // not the node's — the same structural ownership module names have (§5.1).
                // Wired whenever the node has an fs at all, without consulting the
                // manifest: `names` already refuses every `fs/*` the bundle did not
                // declare, and a second test here would decide one grant in two places.
                fs: fs ? scopedFs(fs, appScopeFor(platform.sodium, b.author, b.manifest.app)) : undefined,
                // The cross-realm call. Resolution happens at CALL time, not here: an app
                // may be installed before the transport that answers its `_net`, and a
                // later load may take the id over, so a claimant captured at seam
                // construction would pin this realm to whoever was there first.
                calls: { call: (id, payload) => crossRealmCall(slot, callerId, id, payload) },
                rawNet: hasLink ? netHost?.rawNet() : undefined,
                // Unconditional for the same reason `fs` is.
                timers: slot.timers,
            },
            // Bound to THIS app's key, so a bare `host.call` name addresses its own module
            // map and has no way to name another app's (§12.2). The deadline passing
            // through is the calling guest's remaining execution segment (§4.3), so a
            // module call runs under it rather than under a fresh budget of its own.
            modules: {
                call: (name, p, deadlineMs) => host.callModule(appKey, name, p, deadlineMs),
                has: (name) => host.isBound(appKey, name),
            },
        });
    };
    const guestFullSource = (b: LoadedBundle) => `const APP = ${JSON.stringify({ ...(b.manifest.guest.config ?? {}), ...(opts.config ?? {}) })};\n`
        + b.guestSource;
    /** Resolve an app's one inbound entrypoint, ONCE, at install (§12.10): the confined
     *  realm's `handle` (§12.2). Every bundle declares a guest, so `dispatch` branches on
     *  nothing and re-derives nothing per frame.
     *
     *  It closes over the SLOT rather than over `slot.realm`, so a handover replaces the
     *  realm under a live entry. The null arm is not a cold start — a slot reaches `apps`
     *  with its realm standing — but the guest that called back into itself from its own
     *  top-level code, which gets a sentence instead of a TypeError. */
    const entryFor = (slot: AppSlot): AppEntry => {
        return (input) => slot.realm
            ? slot.realm.call("handle", input)
            : Promise.reject(new Error("shell: the guest's realm is not standing yet"));
    };
    /** The ONE cross-realm call (§12.10): a guest naming a reserved id reaches the realm
     *  that claims it, on a later turn, and gets back what that realm's `handle`
     *  returned. `null` when nothing claims it, which the seam reports by name.
     *
     *  The host's whole contribution is attribution and resolution: it prepends the
     *  CALLER's 32-byte id exactly as `doDispatch` prepends the authenticated sender's key,
     *  and the id is derived host-side from the admitted manifest, so it is no more
     *  forgeable than a sender key. `_host` is the exception the shell answers rather than
     *  routes. */
    const crossRealmCall = (caller: AppSlot, callerId: Uint8Array, id: string, payload: Uint8Array): Promise<Uint8Array> | null => {
        const input = new Uint8Array(callerId.length + payload.length);
        input.set(callerId, 0);
        input.set(payload, callerId.length);
        if (id === SHELL_PROTOCOL) return hostAnswer(caller, payload);
        const slot = apps.get(routes.get(id) ?? "");
        return slot ? slot.entry(input) : null;
    };
    /** The shell's own protocol (`_host`), answered ahead of dispatch. All three ops are
     *  the transport telling the host about something only the transport can see.
     *
     *  Restricted to the realm that claims `_net` structurally rather than by a field in
     *  the payload: `caller` is the slot whose seam this closure was built for, so there is
     *  nothing to spoof. An ordinary app that declared `_host` is refused by name. */
    const hostAnswer = (caller: AppSlot, payload: Uint8Array): Promise<Uint8Array> => {
        if (routes.get(NET_PROTOCOL) !== appKeyFor(caller.loaded.author, caller.loaded.manifest.app)) {
            return Promise.reject(new Error(`shell: ${SHELL_PROTOCOL} is reserved for the ${NET_PROTOCOL} claimant, and this realm does not claim it`));
        }
        // The same envelope every call in this system carries, read with the same
        // function the guest half writes with (`writeOp`, guest-seam.ts).
        const { op, args: a } = readOp(payload);
        switch (op) {
            // An inbound request the transport attributed: route it to the app claiming the
            // protocol and hand back its answer. Delivery and the reply are ONE call — the
            // transport does not await it (it must not; realm-queue.ts) but resumes on the
            // returned promise on a later turn, which is what an asynchronous app handler
            // needs.
            //
            // The shell's own protocols get first refusal (`opts.answer`); `null` and an
            // absent hook fall through to the routing table, so a shell answers an id of
            // its own and never shadows the apps.
            case "deliver": {
                const from = toHex(a.slice(0, 32));
                const protoLen = a[32];
                const proto = dec.decode(a.slice(33, 33 + protoLen));
                const body = a.slice(33 + protoLen);
                return opts.answer?.(from, proto, body)
                    ?? doDispatch(from, proto, body)
                    ?? Promise.resolve(EMPTY);
            }
            // A link this driver handed over (openLink) authenticated, or tore down.
            // Relayed to whoever passed the channel in; the shell forms no opinion.
            case "link-auth":
                netHost?.linkAuthed(readU32BE(a, 0), a.slice(4, 36));
                return Promise.resolve(EMPTY);
            case "link-down":
                netHost?.linkDown(readU32BE(a, 0), a[4]);
                return Promise.resolve(EMPTY);
            default:
                return Promise.reject(new Error(`shell: no ${SHELL_PROTOCOL} op '${op}'`));
        }
    };
    /** Point the concrete channel adapter at whatever claims `_net` now.
     *  Called after every routing rebuild, so the first transport and every replacement
     *  take the same path — there is no upgrade protocol, because the link ids, addresses
     *  and listeners are the node's rather than the outgoing guest's. A replacement is
     *  `attach` again: the incoming guest gets the same config turn and address book, and
     *  redials. Live links cannot survive — the session keys are in the outgoing guest's
     *  private memory (§4.3), which is what makes the occupant confineable — so an upgrade
     *  is a reconnect (§12.6).
     *
     *  Re-attaching only when the CLAIMANT CHANGED is load-bearing: `attach` on a driver
     *  that already has a transport tears every channel down, so doing it unconditionally
     *  would make installing an ORDINARY app disconnect the node.
     *
     *  The identity compared is the SLOT, not its app key: an in-place transport upgrade
     *  builds a new slot with a new realm under the same key, and that realm has never had
     *  the config turn — a key comparison would skip the case this exists for. */
    let attachedTransport: AppSlot | null = null;
    const retargetTransport = () => {
        const key = routes.get(NET_PROTOCOL);
        const slot = apps.get(key ?? "");
        if (!slot) {
            netHost?.detach();
            attachedTransport = null;
            return;
        }
        if (!netHost || attachedTransport === slot) return;
        attachedTransport = slot;
        // Through the routing rather than at the realm directly, so the driver follows a
        // later claimant without being told about it.
        netHost.attach((p) => {
            const s = apps.get(routes.get(NET_PROTOCOL) ?? "");
            return s ? s.entry(p) : null;
        });
    };
    /** Recompute the whole projection from the installed apps (§12.10), on every install and
     *  every uninstall. Never anything narrower: adding just the new app's claims would
     *  leave an UPDATE that dropped a protocol still serving it, and deleting just the
     *  leaving app's would leave a protocol an earlier-loaded app also claims permanently
     *  dark.
     *
     *  Order is load order — `apps` is insertion-ordered and an update re-`set`s an
     *  existing key, keeping its position — so the LAST app installed wins a contested id
     *  and an update never jumps ahead of an app loaded after it. */
    const rebuildRoutes = () => {
        routes.clear();
        for (const [key, slot] of apps) {
            for (const proto of slot.loaded.manifest.protocols ?? []) routes.set(proto, key);
        }
        // `_net` is a claim like any other, so the driver follows the same "last load
        // wins" rule — which is the whole of an in-place transport replacement.
        retargetTransport();
    };
    /** Advance the `(author, app)` freshness mark — the LAST step of a load, once the guest
     *  stands and its claims are routed (§12.4). It records the highest version that
     *  actually ran, which is why nothing earlier writes it: advancing it where the
     *  downgrade is DECIDED, or where the modules merely bound, would raise a floor for a
     *  bundle that never executed, and the known-good version below it could not be
     *  reinstalled. The flip side is unchanged: once a good newer version runs, reloading
     *  the older bundle is refused until an operator hand-edits the freshness file.
     *
     *  `prev` is the mark this load was admitted against (`AdmissionContext.highWater`) —
     *  read once, since nothing between there and here writes the store.
     *
     *  A persist that FAILS is a failed load: the modules landed but the mark did not, so
     *  the downgrade gate would be off on the next boot while the app looks installed. Roll
     *  the in-memory mark back, so a retry persists a fresh advance rather than no-op'ing
     *  against the stale value, and take the app back out.
     *
     *  That restores "nothing of this load was kept", NOT "the table as it was": `bindAll`
     *  REPLACES an app's module map, so on an upgrade the previous version is already gone
     *  and the app ends up uninstalled. An idempotent retry re-lands it once the store is
     *  fixed; until then the app is absent rather than silently ungated. */
    const commitMark = (loaded: LoadedBundle, prev: number) => {
        const { author, manifest } = loaded;
        try {
            platform.freshnessStore.set(author, manifest.app, manifest.version);
        }
        catch (e) {
            platform.freshnessStore.resetMark?.(author, manifest.app, prev);
            doUninstall(appKeyFor(author, manifest.app));
            throw new Error(
                `shell: the load succeeded but the freshness mark could not be persisted — nothing of it was kept: ${errMessage(e)}. ` +
                "Fix the store and re-run the load.",
                { cause: e },
            );
        }
    };
    const doUninstall = (appKey: string) => {
        const slot = apps.get(appKey);
        const removed = host.removeApp(appKey);
        if (slot) {
            disposeSlot(slot);
            apps.delete(appKey);
            // After the delete, so the app that just went cannot be re-projected — and so
            // whatever it was shadowing takes the protocol back.
            rebuildRoutes();
        }
        // An app is its modules AND its realm, and a guest-only bundle legitimately has no
        // modules (§12.4), so counting modules alone would report a successful uninstall
        // as a failure.
        return removed > 0 || slot !== undefined;
    };
    /** Route an inbound request to its app (§12.10): resolve the protocol to the app
     *  claiming it, prepend the authenticated sender, hand it to that app's one entrypoint.
     *
     *  No branch on how the app is implemented: every app presents the same
     *  `senderPk ‖ payload` shape and the same single entry, resolved at install
     *  (`entryFor`). The answer is the realm's — a Promise the transport resumes on a later
     *  turn rather than inline (transport-host.ts), which is what an asynchronous holder
     *  needs since `fs` is async. */
    const doDispatch = (from: PeerId, proto: string, payload: Uint8Array) => {
        const key = routes.get(proto);
        const slot = key ? apps.get(key) : undefined;
        if (!slot)
            return null;
        const senderBytes = fromHex(from);
        const input = new Uint8Array(senderBytes.length + payload.length);
        input.set(senderBytes, 0);
        input.set(payload, senderBytes.length);
        return slot.entry(input);
    };
    return {
        host,
        resolve: (proto) => routes.get(proto) ?? null,
        routes: () => [...routes],
        fs,
        sodium,
        async loadBundleBlob(blob) {
            const v = verifyBundle(sodium, blob);
            // WHAT THIS BUNDLE REACHES, read off the requires and nothing else (§12.5):
            // there is no `role` field, because the requires are what the seam actually
            // wires and so are the fact that must be right anyway. An author cannot shed a
            // privilege by declaring one — adding `link/open` puts `link` in this set and
            // nothing takes it out.
            const privileges: Privilege[] = privilegesOf(v.manifest);
            // ADMISSION — one predicate, one call, one answer (§12.5), a pure function of
            // `(bundle, context)`. The ordering constraints (revocation before a consent
            // dialog, coherence before the operator is asked, the downgrade guard before
            // anything lands) are the composition's, stated once at construction. Nothing
            // decides admission beside the predicate, which is what makes "nothing has
            // landed" hold for the whole decision rather than most of it.
            const ctx: AdmissionContext = {
                privileges,
                highWater: platform.freshnessStore.get(v.author, v.manifest.app),
                revoked: platform.freshnessStore.isRevoked(v.author),
            };
            if (!(await admit(v, ctx)))
                throw new Error(ADMISSION_REJECTED);
            const loaded = await installBundle(host, v);
            const key = appKeyFor(loaded.author, loaded.manifest.app);
            // Extended in place rather than spread into a new object: the holder's timer
            // table reads `slot.realm` off the object `newHolder` returned, so a copy would
            // leave every deadline firing into a slot that never gets a realm.
            const slot: AppSlot = Object.assign(newHolder(loaded), {
                // Replaced on the very next statement, with no yield in between.
                entry: (() => { throw new Error("shell: entry read before it was wired"); }) as AppEntry,
            });
            slot.entry = entryFor(slot);
            // STAND THE GUEST, before anything already standing is replaced. Every app is a
            // guest (§12.4), so a bundle whose guest will not compile has not loaded — and
            // discovering that at the first frame instead would leave the mark advanced for
            // a bundle that never ran a line, putting every version an operator can reach
            // below a floor a broken upgrade raised: rollback bricked by a failed upgrade.
            try {
                await standRealm(slot);
            }
            catch (err) {
                disposeSlot(slot);
                // `bindAll` REPLACED this app key's modules on the way in, so the app that
                // was here — if any — is already running against code from a bundle that
                // does not work. Take the key out whole rather than leave that: the mark
                // was never advanced, so the operator's reinstall is one command.
                doUninstall(key);
                throw err;
            }
            // An in-place upgrade replaces the map entry, and the slot it replaces is a
            // teardown like any other: left alive, its `RealmTimers` keep firing into the
            // OLD realm, so a superseded guest goes on running `timer` turns and arming
            // more of them.
            disposeSlot(apps.get(key));
            apps.set(key, slot);
            // The load admits the code AND claims the manifest's protocols (§12.10), so
            // there is no second operator step to forget and no "installed but unrouted"
            // state. Re-projecting rather than adding this app's ids is what makes an
            // update that DROPPED a protocol stop serving it.
            rebuildRoutes();
            commitMark(loaded, ctx.highWater);
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
            const gone = [];
            for (const appKey of [...apps.keys()]) {
                // Every table name of an app begins with its author (§5.1), so one prefix
                // test finds every app this key ever landed — including ones this shell
                // loaded before the key went bad.
                if (appKey.startsWith(hex + ":")) {
                    doUninstall(appKey);
                    gone.push(appKey);
                }
            }
            return gone;
        },
        async invoke(op, payload, appKey) {
            const slot = appKey ? apps.get(appKey) : onlyApp();
            if (!slot)
                throw new Error(`shell: no app '${appKey}' loaded`);
            // The loopback: the app's ONE entrypoint, called with the host's own caller id
            // (32 zero bytes) exactly as a remote frame carries its peer's key, so the app
            // reads one `handle` either way. The envelope is written by the seam that
            // defines it (`opCall`), never here.
            const call = slot.entry(opCall(op, payload));
            inFlight = inFlight.then(() => call, () => call).catch(() => { }) as Promise<void>;
            return call;
        },
        dispatch: doDispatch,
        close() {
            netHost?.close();
            const dispose = () => {
                for (const key of [...apps.keys()]) {
                    // On the JS targets an app's instances are module WORKERS, which only
                    // removeApp terminates — and a shell that is torn down is not coming
                    // back, so it must release them rather than leave them standing.
                    host.removeApp(key);
                    disposeSlot(apps.get(key));
                }
                apps.clear();
                routes.clear();
            };
            inFlight.then(dispose, dispose);
        },
    };
}
