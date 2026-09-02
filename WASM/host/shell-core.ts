// Platform-neutral shell (§12.9). `bootShell` is THE assembly path — defaults, the
// transport author pin, the claim maps, the load order — and the only way to a Shell, so
// there is no second constructor that could skip the pin. Targets displace platform members
// only (main.ts, native-shim.ts, seedchat, seedstore). Signed bundles are the only way slots
// land (§12.4).
import { denyAll, allOf, hostGates, type Admit, type AdmissionContext } from "./policy.js";
import { appKeyFor, appScopeFor, FreshnessMarks, genesisHash, isJsonObject, privilegesOf, verifyBundle, loadBundleModules, type FreshnessStore, type JsonObject, type LoadedBundle, type ManifestVerifier, type PureModuleLoader, type PureModules } from "./bundle.js";
import { createGuestSeam, slotSignScope, HOST_CALLER_ID, type SeamCrypto, type SignScope, type HostCall, type HostTimers } from "./guest-seam.js";
import { TransportHost, type TransportHostOptions } from "./transport-host.js";
import { transportBundleBytes } from "./transport-bundle.js";
import { isSafeFsKey, isSafeFsScope, type Fs } from "../core/fs.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_MAX_APP_SLOTS, DEFAULT_MAX_LIVE_TIMERS, DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES, DEFAULT_MAX_OUTSTANDING_HOST_CALLS, DEFAULT_MAX_TIMER_PAYLOAD_BYTES, DEFAULT_REALM_MEMORY_BYTES, SELF_INITIATED_CLOCK_DIVISOR } from "../core/wasm-limits.js";
import { isIrreversible, PRIVILEGE_LINK, type Privilege } from "../core/domains.js";
import { enc, fromHex, toHex, errMessage, concatBytes } from "../core/util.js";
import { monotonicMs } from "./realm-queue.js";
import { type SafeRealm } from "./safe-js.js";
import type { Keypair } from "../core/subkeys.js";

/** The crypto surface the shell needs: manifest verification + genesis hashing
 *  (ManifestVerifier) plus the remaining guest crypto ops (SeamCrypto). Core libsodium
 *  build satisfies both. */
export type ShellSodium = ManifestVerifier & SeamCrypto;

/** The one reason a bundle load is refused without being an error worth reporting: the
 *  policy predicate said no (§12.4). Shared so the transport's installers can read it as
 *  "a node without a network", a deliberate configuration rather than a failure. */
export const ADMISSION_REJECTED = "bundle: rejected by admission predicate";

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

/** Configuration supplied by this installation for one particular bundle load. Kept
 *  separate from the author's signed `APP`, and scoped to this call rather than to the
 *  shell, which may host unrelated apps at once. The guest receives it as `LOCAL` and owns
 *  any validation or precedence between the two values. The realm bounds ride here for the
 *  same reason, one level down: the operator's numbers ABOUT ONE APP. */
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
    /** Observe this slot's own answer to a PEER-inbound frame, after it resolves
     *  (`deliverInbound`). The one gap left once dispatch is a single claim → slot map: the
     *  link occupant consumes that answer on its way back out to the wire, so an embedder
     *  whose own mounted app must paint what it just answered has no other path to those
     *  bytes.
     *  Scoped to THIS load rather than the shell; a replacement load carries its own.
     *  Observation only: it cannot change what the caller receives, it is never consulted
     *  for a host loopback `invoke` or a cross-realm call, and a throw from it is swallowed. */
    onInbound?: (claim: string, from: Uint8Array, answer: Uint8Array) => void;
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
    /** Load a signed bundle blob: verify the manifest, run the admission predicate,
     *  integrity-check + install the modules, stand the guest. Every bundle takes this same
     *  §12.4 path. A load either leaves a running app behind or leaves nothing: the realm
     *  is built here, so a guest that cannot compile fails the load rather than the first
     *  frame, and the freshness mark is advanced last, once it has. */
    loadBundleBlob(blob: Uint8Array, opts?: LoadBundleOptions): Promise<AppHandle>;
    /** Uninstall the slot selected by its audit identity: drop its claims and dispose its
     *  realm, private modules, timers and scopes as one unit. */
    uninstall(appKey: string): boolean;
    /** Write off an author key: refuse everything it signs from now on, and uninstall every
     *  app of its already running. Returns the app keys torn down. One call because the
     *  halves are useless apart: uninstalling alone leaves the thief's next bundle landing
     *  on the same derived names, refusing alone leaves the compromised code running.
     *  Permanent and host-local — recovery is a new author key, not an un-revoke. */
    revoke(authorHex: string): string[];
    close(): void;
}

/** What a load returns: verified facts plus a slot-bound handle (§12.4). */
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
     *  load stood. A replacement load stands a new slot under the same key, so a handle
     *  taken before it keeps naming the version it was handed and rejects once that slot
     *  is disposed. The replacement load returns the new handle. */
    invoke(payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array>;
}

// Re-exported so a target reaches the admission constructors from the same module it gets
// bootShell from. Pure-module builders remain target implementations, not shell API.
export { denyAll, admitAll, authorAllowlist, byPrivilege, allOf, policyFromJson, type Admit, type AdmissionContext } from "./policy.js";
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
  /** THIS load's answer observer (`LoadBundleOptions.onInbound`), or absent. Carried on
   *  the slot rather than read from the load call's own options at call time, because a
   *  peer-inbound frame can land at any point after commit, long after that call
   *  returned. A replacement load's slot gets its own value or none — never the outgoing
   *  slot's, the same rule `realmMemoryBytes` follows. */
  onInbound?: LoadBundleOptions["onInbound"];
}

/** Per-realm timer table. Cap live count and retained bytes; `clearAll` before realm
 *  disposal (§12.3). */
interface RealmTimers extends HostTimers {
  /** Cancel every live deadline. Called only from `disposeSlot`, before the realm goes. */
  clearAll(): void;
}

/** A timer table over `fire`, which carries one body into its realm and answers when that
 *  invocation has settled.
 *  The table is the resource being spent, so the caps live here rather than in the seam:
 *  the seam never learns that a timer fired, so a count kept there would only ever grow.
 *
 *  What it retains is the REALM-ENTRY buffer — the caller-id prefix already framed in — not
 *  the guest's payload. One copy rather than two, and the charge is the bytes that actually
 *  enter the realm rather than a number 32 short of them.
 *
 *  Firing MOVES that custody, it does not end it: `realm.call` borrows the buffer and the
 *  entry queue counts depth alone (realm-queue.ts), so between the deadline and the answer
 *  this table is the only owner it has. Releasing at the deadline would leave the busiest
 *  moment — fired bodies queued behind a serialized realm — charged to nobody.
 *
 *  It owns this realm's share of the node's CLOCK because a fired deadline is the one FRESH
 *  invocation root a guest creates itself (§12.3). Peerless cross-realm calls are not fresh:
 *  they inherit the active root's deadline. Firing spends this share, and a deadline coming
 *  due with it spent is SLIPPED rather than failed. This paces self-created roots; it is not
 *  a bound on the node's clock, which external roots can occupy one bounded invocation after
 *  another.
 *
 *  What it measures is the WALL period across a fire, because handing the body over and being
 *  told the answer landed is all it sees. A body that parks on a host call is charged as if it
 *  had spun — a safe over-approximation because it can only pace that realm harder. */
export function createRealmTimers(
    fire: (payload: Uint8Array) => Promise<unknown> | void,
    max = DEFAULT_MAX_LIVE_TIMERS,
    maxPayloadBytes = DEFAULT_MAX_TIMER_PAYLOAD_BYTES,
    budgetMs = DEFAULT_GUEST_DEADLINE_MS,
    clockDivisor = SELF_INITIATED_CLOCK_DIVISOR,
): RealmTimers {
    const live = new Map<number, { timer: ReturnType<typeof setTimeout>; bodyBytes: number }>();
    /** Bodies waiting for their deadline. */
    let armedBytes = 0;
    /** Bodies handed to `fire` whose invocation has not settled. Held apart from
     *  `armedBytes` because a fired body has left the table's id space — it can no longer
     *  be cleared or re-armed — while its bytes are still this realm's. */
    let firingBytes = 0;
    /** Fired invocations still outstanding. The clock is charged for the ONE period any of
     *  them is open rather than per invocation: a serialized realm is occupied once. */
    let firing = 0;
    /** Banked clock, in ms. Capped at one invocation, so an idle app's deadline fires the
     *  moment it comes due; floored at minus the same, so one long fire cannot mortgage the
     *  table past `budgetMs * clockDivisor`. An unbudgeted realm banks `Infinity`. */
    let credit = budgetMs;
    let creditAt = monotonicMs();
    /** A realm that can run nothing has no clock to share, and pacing it would only spin a
     *  slip loop against invocations already late when the queue admits them. */
    const paced = budgetMs > 0;
    /** Spend the period since the last reading at the wall's own rate while busy, and earn it
     *  back at `1 / clockDivisor` throughout — so an always-busy table settles at exactly that
     *  share. Called BEFORE each transition, so a period is charged in the mode it ran in. */
    const accrue = (): void => {
        const now = monotonicMs();
        const elapsed = now - creditAt;
        creditAt = now;
        if (!(elapsed > 0)) return;
        credit += elapsed / clockDivisor - (firing > 0 ? elapsed : 0);
        credit = Math.max(-budgetMs, Math.min(budgetMs, credit));
    };
    const clear = (id: number) => {
        const entry = live.get(id);
        if (entry !== undefined) {
            clearTimeout(entry.timer);
            live.delete(id);
            armedBytes -= entry.bodyBytes;
        }
    };
    return {
        arm(id, ms, payload) {
            // Counted before the re-arm, so replacing a live deadline is always allowed
            // and only a NEW id can be the one over the line.
            if (!live.has(id) && live.size >= max)
                throw new Error(`guest: too many live timers (cap ${max})`);
            const previousBytes = live.get(id)?.bodyBytes ?? 0;
            const nextBytes = armedBytes - previousBytes + HOST_CALLER_ID.length + payload.byteLength;
            if (nextBytes + firingBytes > maxPayloadBytes)
                throw new Error(`guest: live timer payloads exceed byte cap ${maxPayloadBytes}`);
            // Copy only after both checks pass. The guest-call request buffer can then be
            // collected, and the table retains exactly the bytes it accounts for.
            const body = concatBytes([HOST_CALLER_ID, payload]);
            clear(id);
            /** The handle standing for this id. A slip replaces it, so the attempt behind the
             *  old one finds it changed and does nothing — as a re-arm of the id already does. */
            let handle: ReturnType<typeof setTimeout> | undefined;
            const attempt = (): void => {
                const entry = live.get(id);
                if (!entry || entry.timer !== handle) return;
                accrue();
                if (paced && credit <= 0) {
                    // Slipped, never failed or dropped: a share held against the node's other
                    // slots is not an error an honest app should have to handle. The wait is
                    // what buys a positive share back, capped to `setTimeout`'s range.
                    handle = setTimeout(attempt, Math.min(0x7fffffff, Math.ceil((1 - credit) * clockDivisor)));
                    live.set(id, { timer: handle, bodyBytes: entry.bodyBytes });
                    return;
                }
                // Dropped from the table BEFORE the realm is re-entered, so a guest that
                // re-arms the same id from inside its own `timer` entrypoint arms the new
                // deadline rather than having it cleared out from under it on the way out.
                live.delete(id);
                armedBytes -= entry.bodyBytes;
                firingBytes += entry.bodyBytes;
                firing += 1;
                let released = false;
                const release = () => {
                    if (released) return;
                    released = true;
                    firingBytes -= entry.bodyBytes;
                    // The busy period ends where the byte custody does: at the answer.
                    accrue();
                    firing -= 1;
                };
                let handed: Promise<unknown> | void;
                // A fire that throws, or that carried the body nowhere, ends its custody in
                // this turn rather than waiting for an answer nobody promised.
                try { handed = fire(body); } catch { handed = undefined; }
                if (handed) void handed.then(release, release);
                else release();
            };
            handle = setTimeout(attempt, ms);
            live.set(id, { timer: handle, bodyBytes: body.byteLength });
            armedBytes += body.byteLength;
        },
        clear,
        clearAll() {
            for (const { timer } of live.values()) clearTimeout(timer);
            live.clear();
            armedBytes = 0;
            // `firingBytes` and an open busy period drain on their own: disposal settles every
            // invocation still in flight (realm-queue.ts), and each fired body releases as its
            // answer lands.
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

/** This node's network, whole (§12.6). */
export interface TransportOptions extends Omit<TransportHostOptions, "networkKey"> {
    /** The transport bundle to PIN — and, unless `load` is false, to load. Default: the
     *  artifact-shipped one. The pin's author is DERIVED from this blob, so passing different
     *  bytes is a deliberate transport replacement. */
    bundle?: Uint8Array;
    /** Installation-local config for that load, through the ordinary `localConfig` path. */
    config?: JsonObject;
    /** Whether the boot loads the pinned bundle. Default true; `false` leaves the load to
     *  the caller, under the same pin. */
    load?: boolean;
}

/** JS-target assembly options (§12.9). Every field but `sodium` and `identity` has a
 *  default; the pin and the load order are part of standing a node up, which is why there
 *  is one assembly path and no way to reach the shell around it. */
export interface BootShellOptions {
    /** The crypto surface the shell needs — core libsodium with the ML-DSA-65 verifier
     *  mixed in (the one thing no target can default: main.ts loads it, a browser page
     *  readies it). */
    sodium: ShellSodium;
    /** The node's keypair (§12.9): its public half is this node's peer id and the one
     *  identity every target reports through `node/identity`. The handshake and the seam's
     *  SIGN op both sign with it, under different domains and scopes. */
    identity: Keypair;
    /** YOUR admission predicate (§12.5) — the one branch that is actually yours: an
     *  operator's policy, a consent dialog, or `() => true` for "the bundle my operator
     *  handed me IS the trust decision". The transport author pin is ANDed onto it here, and
     *  the host's own gates (`hostGates`) below, so no posture can lose either. Consulted for
     *  EVERY bundle, privileged ones included. Absent ⇒ deny-all. */
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
    /** The target-specific builder for a bundle's private pure modules (§4). Default:
     *  `ModuleTable`, the JS worker-backed builder; the native loader passes its Go-backed
     *  one. */
    modules?: PureModuleLoader;
    /** The confined realm factory (§12.3) — every app is a guest, so there is always one.
     *  Default: the lazy safe-js import, since the QuickJS engine is heavy and loads on the
     *  first realm. */
    createRealm?: RealmFactory;
    now?: () => number;
    /** Which network this node belongs to (§12.6) — an isolation boundary, not a gate;
     *  absent ⇒ the public network. It reaches BOTH the transport driver and the signing
     *  scope of the slot reaching `link` (`slotSignScope`).
     *
     *  The scope is the load-bearing use: `node/sign` prefixes and never parses, so it is
     *  the only binding of a link occupant's signature to this node's network that the slot
     *  occupant cannot choose. Drop it from the preimage and a transport on one network can
     *  mint transcripts another's verifier accepts. */
    networkKey?: Uint8Array;
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
     *  `LoadBundleOptions.realmMemoryBytes`, where an appetite belonging to one app goes. */
    realmMemoryBytes?: number;
    /** Optional node network. The options object is retained to preserve live accessors. */
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

/** Stand a node up: the platform parts, the transport author pin, the shell, and the load
 *  of the signed transport program that IS the node's network (§12.6). The one assembly
 *  path — a second way to a Shell would be one that skipped the pin. */
export async function bootShell(opts: BootShellOptions): Promise<BootResult> {
    const sodium = opts.sodium;
    // The defaults are imported lazily: they are JS-target parts (a worker-backed module
    // builder, the QuickJS realm engine), and the one target that never takes them (the
    // native loader, which supplies Go-backed equivalents) must not pay for them.
    // `false` is a node with no disk, the one member whose absence is NOT its default:
    // omitted asks for the in-memory backend, said-as-false asks for none.
    const backend = opts.fs === false ? undefined : opts.fs ?? new ((await import("./fs-memory.js")).MemoryFs)();
    // The key rule applied once, over whatever backend this target supplied, so every host
    // admits exactly the same key space — which is what decides the contents a node stores
    // and advertises.
    const fs = backend ? validatedFs(backend) : undefined;
    const moduleLoader = opts.modules ?? new ((await import("./module-table.js")).ModuleTable)();
    const createRealm = opts.createRealm
        ?? (async (o) => (await import("./safe-js.js")).createSafeRealm(o));
    const freshnessStore = opts.freshnessStore ?? new FreshnessMarks();
    const now = opts.now ?? (() => Date.now());
    const net = opts.transport === false ? undefined : opts.transport;
    const netHost = net
        ? new TransportHost(net, { networkKey: opts.networkKey })
        : null;
    // The author is DERIVED from the blob, never restated — the pin is the whole of "only
    // this author may be the network" (§12.5).
    const transportBlob = netHost ? (net!.bundle ?? transportBundleBytes()) : null;
    let transportAuthorHex: string | null = null;
    if (transportBlob) {
        try {
            transportAuthorHex = toHex(verifyBundle(sodium, transportBlob).author);
        }
        catch { /* malformed blob — the load below refuses it by name */ }
    }
    // THE admission predicate (§12.5): the host's own gates, then the caller's, then the
    // transport pin. Composed HERE so no posture can lose a member — an `admitAll`, or a
    // consent dialog that always says yes, must not shed revocation or the pin. The pin is a
    // VETO, never an appointment: it can only refuse.
    //
    // FAIL-CLOSED on a privilege it does not know: `PRIVILEGES` is derived from the
    // capability catalog, so a privileged name added there arrives here with no branch and
    // is refused rather than waved through. A new privilege is taught to the assembly
    // deliberately, in this one place.
    const admit: Admit = allOf(hostGates, opts.admit ?? denyAll, (v, ctx) => {
        if (ctx.privileges.length === 0) return true;
        for (const priv of ctx.privileges) {
            if (priv !== PRIVILEGE_LINK) return false;
        }
        return transportAuthorHex !== null && toHex(v.author) === transportAuthorHex;
    });

    // ── what this node holds ────────────────────────────────────────────────────
    const slots: AppSlot[] = [];
    /** Two audiences, two maps (§12.10): `peerClaims` from every installed manifest's
     *  `protocols`, `localClaims` from its `services`. Which map holds a name IS its reach,
     *  so an inbound frame is one lookup and nothing tests the manifest a second time. Both
     *  are projections of what is installed — nothing to write, persist or keep in step —
     *  and materialized rather than scanned because each is read once per delivery.
     *
     *  A name in both is a bundle saying "reachable either way", so uniqueness is enforced
     *  per map (`refuseContested`), never across them. */
    const peerClaims = new Map<string, AppSlot>();
    const localClaims = new Map<string, AppSlot>();
    // The tail of every host-initiated call into a realm. close() defers realm disposal onto
    // this, so a call parked mid-await (a repair pass on an unreachable peer, an operator
    // waiting for a cohort) is never resumed into a freed realm — a QuickJS
    // use-after-free (§12.3).
    let inFlight = Promise.resolve();
    const keyOf = (slot: AppSlot) => appKeyFor(slot.verifiedBundle.author, slot.verifiedBundle.manifest.app);
    /** Each signed list paired with the map it claims in, so every caller iterating a
     *  bundle's claims covers both audiences. */
    const booksOf = (manifest: LoadedBundle["manifest"]): readonly (readonly [Map<string, AppSlot>, readonly string[], string])[] => [
        [peerClaims, manifest.protocols ?? [], "protocols"],
        [localClaims, manifest.services ?? [], "services"],
    ];
    const reachesLink = (manifest: LoadedBundle["manifest"]) => privilegesOf(manifest).includes(PRIVILEGE_LINK);
    /** Whether `slot` holds the raw-link binding. Exclusive, like a claim: the driver has
     *  ONE event sink, so two holders are not a composition — the second would take the
     *  node's sockets off the first, silently. A pure function of the signed manifest, so
     *  there is nothing here to store or keep in step — `slots.find(hasLink)` IS the
     *  binding's holder. */
    const hasLink = (slot: AppSlot) => reachesLink(slot.verifiedBundle.manifest);
    const releaseClaims = (slot: AppSlot) => {
        for (const [book, names] of booksOf(slot.verifiedBundle.manifest)) {
            for (const claim of names) {
                if (book.get(claim) === slot) book.delete(claim);
            }
        }
    };
    /** This load's per-invocation ceiling: this load's number, else the node's, else the
     *  shared one (§12.3). One place, because two owners are measured against it — the realm
     *  `standRealm` stands, and the clock its timer table banks one invocation of. */
    const deadlineFor = (load: LoadBundleOptions): number =>
        load.guestDeadlineMs ?? opts.guestDeadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
    /** An empty slot for `loaded`, with its timer table already pointed at the realm the
     *  slot does not have yet. The cycle is tied by reading `holder.realm` at FIRE time,
     *  which is the correct reading anyway: the realm a deadline re-enters is the one
     *  standing when it fires (a transport handover replaces it while the slot stays). */
    const newSlot = (loaded: LoadedBundle, pureModules: PureModules, load: LoadBundleOptions): AppSlot => {
        let slot: AppSlot;
        const timers = createRealmTimers((body) =>
            // An ordinary host loopback, exactly like `invoke` (§12.2): a fired deadline is
            // an event the host delivers into the guest, not a host authority. The body is
            // already framed — the HOST's caller id followed by what `timer/arm` supplied,
            // built once by the table that retains it; event framing above that belongs to
            // the guest whose `handle` reads it. A guest's `handle` may throw on it; there
            // is no caller left to reject — the arming call returned turns ago — so report
            // and swallow. Returned rather than discarded: the table holds this body's
            // charge, and the clock it is spending, until the invocation settles, and a slot
            // whose realm is already gone releases both now by answering nothing.
            slot.realm?.call(body).catch((err: unknown) => {
                console.error(`[shell] guest error in timer: ${errMessage(err)}`);
            }),
            // Banked against THIS slot's ceiling, not the node's default.
            DEFAULT_MAX_LIVE_TIMERS, DEFAULT_MAX_TIMER_PAYLOAD_BYTES, deadlineFor(load));
        const appScope = appScopeFor(sodium, loaded.author, loaded.manifest.app);
        const scope = slotSignScope(opts, loaded.author, loaded.manifest.app, privilegesOf(loaded.manifest));
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
    const disposeSlot = (slot: AppSlot | null | undefined) => {
        if (slot) slot.active = false;
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
    /** Stand one candidate realm. It remains outside `slots` and the claim maps until this
     *  and the freshness write both succeed. Both bounds resolve per load: this load's
     *  number, else the node's default, else the shared one — never the author's, since a
     *  bundle cannot ask for more of the host than the operator gave it. */
    const standRealm = async (slot: AppSlot, localConfig: JsonObject, load: LoadBundleOptions): Promise<void> => {
        const b = slot.verifiedBundle;
        // Absent ≡ `{}`, so `APP` is always an object to read names off (isValidManifest
        // already refused any non-object).
        const appConfig = b.manifest.guest.config ?? {};
        // The third preamble (§12.5): not what the author signed (`APP`) nor what the
        // operator set (`LOCAL`), but what the host will admit — told to the guest rather
        // than discovered by being refused, so it can window its own fan-out. Anything
        // that changes what the realm admits must change what is advertised here with it.
        const hostBudgets: JsonObject = {
            maxOutstandingHostCalls: DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
            maxOutstandingHostCallBytes: DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
        };
        slot.realm = await createRealm({
            source: jsonPreamble("HOST", hostBudgets) + jsonPreamble("APP", appConfig)
                + jsonPreamble("LOCAL", localConfig) + b.guestSource,
            hostCall: seamFor(slot),
            memoryLimitBytes: load.realmMemoryBytes ?? opts.realmMemoryBytes ?? DEFAULT_REALM_MEMORY_BYTES,
            deadlineMs: deadlineFor(load),
        });
    };
    /** Wire the `host.call` seam one admitted bundle's realm runs against (guest-seam.ts),
     *  as the three things that own it: what this NODE is, what this REALM may reach
     *  (`grants`), and what this APP installed (`modules`). A bundle reaching `link` is
     *  wired with `rawNet`: without it a bundle is never handed a socket descriptor (§1,
     *  capability-by-non-wiring). Timers are NOT such a grant — `timer/*` is an ordinary
     *  `"app"` authority, so every realm gets a table. */
    const seamFor = (slot: AppSlot): HostCall => {
        const b = slot.verifiedBundle;
        const links = hasLink(slot);
        // As signed. Tells a bare `host.call` name from this bundle's own module
        // (guest-seam.ts dispatch), and feeds the irreversibility guard below.
        const localServices = new Set(b.manifest.guest.calls ?? []);
        // The 32 bytes this realm is attributed by when it calls another: the app key,
        // hashed. The same shape as the sender key prepended to an inbound frame, so a
        // callee reads one field whether the caller was a peer or a co-resident app. Zero
        // is the HOST's own, and no app key derives it.
        const callerId = genesisHash(sodium, enc.encode(keyOf(slot)));
        const fullSeam = createGuestSeam({
            platform: { sodium, identity: opts.identity, now },
            grants: {
                // The two signed lists, unmodified. A `host.call` naming a host method
                // resolves iff the method's SERVICE is in `requires`. `crypto/*` and the
                // bundle's own module names are exempt from both — a fixed catalog and the
                // app's own code, never grants.
                names: new Set(b.manifest.guest.requires),
                localServices,
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
                calls: { call: (id, payload, deadlineMs) => callClaimant(localClaims, id, callerId, payload, deadlineMs) },
                rawNet: links ? netHost?.rawNet() : undefined,
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
        // Everything a guest initializes from stays open. A link occupant receives the
        // node facts through its installation-local config, never by reading them off this
        // seam. The refusal THROWS at the call site like every gate refusal (guest-seam.ts).
        return (name, payload, budget) => {
            // A cross-realm call leaves something behind in the CALLEE the way `fs/put`
            // does here. Folded in at this slot rather than into `isIrreversible`, which
            // knows the dispatch catalog and nothing about one slot's `calls`.
            if (!slot.active && (isIrreversible(name) || localServices.has(name))) {
                throw new Error(`shell: '${name}' is refused until this bundle's installation commits`);
            }
            return fullSeam(name, payload, budget);
        };
    };
    /** Enter a slot's guest. `input` is `[caller 32][body …]` — the host's attribution
     *  prefix, never the guest's own spelling. The null arm is reachable only from guest
     *  top-level code while its candidate realm is still being constructed. */
    const callSlot = (slot: AppSlot, input: Uint8Array, deadlineMs?: number) => slot.realm
        ? slot.realm.call(input, deadlineMs)
        : Promise.reject(new Error("shell: the guest's realm is not standing yet"));
    /** Chain a host-initiated call onto `inFlight`, so `close()` waits for it rather than
     *  freeing the realm out from under it (§12.3). */
    const track = (call: Promise<Uint8Array>): Promise<Uint8Array> => {
        inFlight = inFlight.then(() => call, () => call).catch(() => { }) as Promise<void>;
        return call;
    };
    /** An event the HOST writes into a slot: `[32 zero bytes][driver body]` — the one
     *  caller id the shell holds (loopback and socket events). */
    const hostCallSlot = (slot: AppSlot, body: Uint8Array, deadlineMs?: number): Promise<Uint8Array> =>
        callSlot(slot, concatBytes([HOST_CALLER_ID, body]), deadlineMs);
    /** Add the host-owned network key to transport `LOCAL` (§12.10). */
    const configFor = (slot: AppSlot, localConfig: JsonObject): JsonObject => {
        if (!hasLink(slot)) return localConfig;
        const facts = netHost?.initialConfig();
        if (!facts)
            throw new Error(`shell: a bundle reaching "${PRIVILEGE_LINK}" has nowhere to go on a shell with no raw-link driver`);
        return { ...localConfig, ...facts };
    };
    /** Refuse a candidate contesting a claim or the raw-link binding another identity
     *  holds (§12.10). Asked before candidate code runs, then again in the commit window.
     *  Per MAP: the same name under `protocols` and `services` is two claims, not a
     *  contest. */
    /** Realms are the multiplicand every per-realm ceiling is multiplied by (§12.3), so an
     *  install list nobody counts would leave each of those ceilings a floor rather than a
     *  bound. A replacement takes the slot it already holds and is never refused here.
     *  Checked twice like the contest below, and for the same reason: this is the cheap
     *  early refusal, and the commit window re-checks what another load may have taken. */
    const refuseOverfull = (key: string) => {
        if (slots.length >= DEFAULT_MAX_APP_SLOTS && !slots.some((installed) => keyOf(installed) === key))
            throw new Error(`shell: this node already holds its ${DEFAULT_MAX_APP_SLOTS} app slots — uninstall one before installing another`);
    };
    const refuseContested = (loaded: LoadedBundle, key: string) => {
        for (const [book, names, audience] of booksOf(loaded.manifest)) {
            for (const claim of names) {
                const incumbent = book.get(claim);
                if (incumbent && keyOf(incumbent) !== key) {
                    throw new Error(`shell: ${audience} claim '${claim}' is already held by '${keyOf(incumbent)}'`);
                }
            }
        }
        // Refused rather than shadowed for the same reason a claim is, and LOUDLY because
        // the alternative is a node that looks installed and is off the network: the
        // incumbent keeps its claims and its realm, and only its sockets stop answering.
        const linkIncumbent = slots.find(hasLink);
        if (linkIncumbent && keyOf(linkIncumbent) !== key && reachesLink(loaded.manifest)) {
            throw new Error(`shell: the "${PRIVILEGE_LINK}" binding is already held by '${keyOf(linkIncumbent)}' — uninstall it before installing another bundle that reaches "${PRIVILEGE_LINK}"`);
        }
    };
    const doUninstall = (appKey: string) => {
        const i = slots.findIndex((slot) => keyOf(slot) === appKey);
        if (i < 0) return false;
        const [slot] = slots.splice(i, 1);
        releaseClaims(slot);
        if (hasLink(slot)) netHost?.release();
        disposeSlot(slot);
        return true;
    };
    /** Frame `[attribution ‖ payload]` and enter a slot's guest — the shape both a
     *  cross-realm call and a peer-inbound frame arrive as (`callClaimant`,
     *  `deliverInbound`). */
    const callFramed = (slot: AppSlot, attribution: Uint8Array, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array> => {
        const input = new Uint8Array(attribution.length + payload.length);
        input.set(attribution, 0);
        input.set(payload, attribution.length);
        return callSlot(slot, input, deadlineMs);
    };
    /** Hand a request to the realm claiming `claim` in `book`. `null` when nothing claims
     *  it — an answer, rather than a promise no one will settle. */
    const callClaimant = (book: Map<string, AppSlot>, claim: string, attribution: Uint8Array, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array> | null => {
        const slot = book.get(claim);
        return slot ? callFramed(slot, attribution, payload, deadlineMs) : null;
    };
    /** Inbound from outside this node (the link occupant's `link/deliver` call). One lookup
     *  on `peerClaims`, so a `services` claim is unreachable by a peer by construction
     *  rather than by a second test against the slot's manifest. The resolved answer also
     *  goes to the slot's `onInbound`, if its load named one. */
    const deliverInbound = (claim: string, attribution: Uint8Array, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array> | null => {
        const slot = peerClaims.get(claim);
        if (!slot) return null;
        const answer = callFramed(slot, attribution, payload, deadlineMs);
        if (slot.onInbound) {
            const onInbound = slot.onInbound;
            // Two-arg `.then`, not a bare call plus a stray `.catch`: this branch's own
            // Promise must settle either way, or a guest that refuses the frame leaves an
            // unhandled rejection behind that `answer` — the one the caller actually
            // holds — already reports. Nothing to do on a refusal: there is no answer to
            // observe.
            answer.then((bytes) => {
                try { onInbound(claim, attribution, bytes); }
                catch (err) { console.error(`[shell] the loader's onInbound threw: ${errMessage(err)}`); }
            }, () => { });
        }
        return answer;
    };
    // Inbound requests use current peer claims (§12.10).
    netHost?.routeInbound(deliverInbound);

    const shell: Shell = {
        resolve(name) {
            const slot = peerClaims.get(name) ?? localClaims.get(name);
            return slot ? keyOf(slot) : null;
        },
        routes: () => [...peerClaims, ...localClaims].map(([claim, slot]): [string, string] => [claim, keyOf(slot)]),
        call: (serviceId, payload, deadlineMs) => {
            const answer = callClaimant(localClaims, serviceId, HOST_CALLER_ID, payload, deadlineMs);
            return answer && track(answer);
        },
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
            // privilege by declaring one.
            const privileges: Privilege[] = privilegesOf(v.manifest);
            // ADMISSION — one predicate, one call, one answer (§12.5), a pure function of
            // `(bundle, context)`, with the constraints' ordering stated once at
            // construction. Nothing decides admission beside the predicate, which is what
            // makes "nothing has landed" hold for the whole decision.
            const ctx: AdmissionContext = {
                privileges,
                highWater: freshnessStore.get(v.author, v.manifest.app),
                revoked: freshnessStore.isRevoked(v.author),
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
            refuseOverfull(key);
            const pureModules = await loadBundleModules(moduleLoader, v);
            const slot = newSlot(loaded, pureModules, loadOpts);
            // Stand the guest, before anything already standing is replaced. Every app is a
            // guest (§12.4), so a bundle whose guest will not compile has not loaded — and
            // discovering that at the first frame would leave the mark advanced for a
            // bundle that never ran a line.
            try {
                await standRealm(slot, configFor(slot, localConfig), loadOpts);
                // The candidate is complete. EVERYTHING FROM HERE IS SYNCHRONOUS, which is
                // what makes the commit atomic: the contest below, the mark, and the claim
                // hand-over cannot be interleaved with another load or an uninstall.
                refuseContested(loaded, key);
                refuseOverfull(key);
                // A mark that cannot be persisted throws, and the store has already rolled
                // itself back; the catch below disposes the candidate, so the running slot
                // is untouched.
                freshnessStore.set(loaded.author, loaded.manifest.app, loaded.manifest.version);
            }
            catch (err) {
                disposeSlot(slot);
                throw err;
            }
            const previousIndex = slots.findIndex((installed) => keyOf(installed) === key);
            const previous = previousIndex < 0 ? undefined : slots[previousIndex];
            const replacingLinkOwner = previous !== undefined && hasLink(previous);
            if (previous) releaseClaims(previous);
            if (previousIndex < 0) slots.push(slot);
            else slots[previousIndex] = slot;
            for (const [book, names] of booksOf(loaded.manifest)) {
                for (const claim of names) book.set(claim, slot);
            }
            // The outgoing guest's link state went with its realm (§4.3), so the sockets it
            // held are torn down here rather than left as channels nobody can speak for. So
            // did its address book, which is why the incoming guest redials from the peers
            // its own load named and not from anything retained here (§12.10). After the
            // claim hand-over above, so `onClose` finds the channels already gone and queues
            // no `linkClosed` at the new realm for links it never had. Only ever a free
            // binding or this identity's own: `refuseContested` turned any other candidate
            // away, and a version that DROPS `link/*` releases the binding the same way
            // dropping a claim releases the claim.
            if (hasLink(slot)) {
                netHost?.activate((payload) => hostCallSlot(slot, payload));
            } else if (replacingLinkOwner) {
                netHost?.release();
            }
            // The mark and every claim/link binding have landed, so this slot's writes and
            // cross-realm calls are now its own (`seamFor`).
            slot.active = true;
            disposeSlot(previous);
            // The handle: the verified facts plus the bound slot — the key, the scoped fs
            // view and the loopback invoke. One object, so a caller cannot derive half of
            // it from the manifest and half from the shell and have the two disagree.
            const handle: AppHandle = {
                ...loaded,
                key,
                fs: slot.fsScope,
                appScope: slot.appScope,
                invoke: (payload, deadlineMs) => slot.active
                    ? track(hostCallSlot(slot, payload, deadlineMs))
                    : Promise.reject(new Error(`shell: app '${key}' slot is no longer loaded`)),
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
            freshnessStore.revoke(fromHex(hex));
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
        close() {
            netHost?.close();
            const dispose = () => {
                for (const slot of slots) disposeSlot(slot);
                slots.length = 0;
                peerClaims.clear();
                localClaims.clear();
            };
            inFlight.then(dispose, dispose);
        },
    };

    // The transport bundle IS the node's network (§12.6), admitted through the ordinary
    // load. A predicate that refuses its author leaves the node without one — a deliberate
    // configuration, not an error. A boot that throws returns no handle, so whatever it
    // stood up must not leak: one teardown, the shell's.
    try {
        if (netHost && transportBlob && net!.load !== false) {
            try {
                await shell.loadBundleBlob(transportBlob,
                    net!.config === undefined ? undefined : { localConfig: net!.config });
            }
            catch (err) {
                if (!isAdmissionRejected(err)) throw err;
                console.warn('  no transport: the policy does not grant this bundle the "link" privilege');
            }
            await netHost.start();
        }
        return { shell, transport: netHost };
    }
    catch (err) {
        shell.close();
        throw err;
    }
}
