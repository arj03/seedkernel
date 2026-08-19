// The platform-neutral shell core (§12.9): everything standing a node up involves except
// what genuinely varies by target — pure-module construction, the guest-seam wiring, the
// preamble assembly, the realm lifecycle, the bundle load order, the socket driver and the
// inbound dispatch. A target hands in a `ShellPlatform` and gets back a wired Shell.
//
// This is the ONE assemble path, and the assembly ORDER is the point: it is the last thing
// two hosts could disagree about, so no target restates it.
//
//   main.ts       → boot()         → ModuleTable + NodeFs + FileFreshnessStore + NodeChannelFactory + safe-js → createShell()
//   browser       → chat-shell.js  → ModuleTable + RtcNetwork-style openLink edges + sessionStorage freshness  → createShell()
//   native        → native-shim.ts → Go module slots + Go Fs + Go channels + Go realm                → createShell()
//   seedstore     → StorageNode    → { MemoryFs, FreshnessMarks }                  → createShell() + loadBundle(seedstore.skb)
//
// There is no raw module install path: signed bundles are the only way slots land (§12.4).
import { denyAll, allOf, hostGates, type Admit, type AdmissionContext } from "./policy.js";
import { appKeyFor, appScopeFor, genesisHash, privilegesOf, verifyBundle, loadBundleModules, type BundleCrypto, type FreshnessStore, type LoadedBundle, type PureModuleLoader, type PureModules } from "./bundle.js";
import { createGuestSeam, slotSignScope, opCall, readOp, type SeamCrypto, type SignScope, type HostCall, type HostTimers } from "./guest-seam.js";
import type { TransportHost } from "./transport-host.js";
import { isSafeFsKey, isSafeFsScope, type Fs } from "../core/fs.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_MAX_LIVE_TIMERS, DEFAULT_REALM_MEMORY_BYTES } from "../core/wasm-limits.js";
import { isReservedProtocol, NET_PROTOCOL, PRIVILEGE_LINK, SHELL_PROTOCOL, type Privilege } from "../core/domains.js";
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
    /** Target-specific builder for a bundle's private pure modules (§4). */
    modules: PureModuleLoader;
    fs?: Fs;
    freshnessStore: FreshnessStore;
    createRealm: RealmFactory;
    now?: () => number;
    /** OPTIONAL network key — which network this node belongs to. An isolation boundary,
     *  not a gate (§12.6); absent ⇒ the public network. Feeds the raw link configuration
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
     *  The shell wires it once to the generic claim lookup. Absent for a shell with no raw
     *  links at all (a browser edge), where a bundle claiming `_net` simply gets no
     *  sockets. */
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
     *  `null` means "not mine" and falls through to the routing table for an ordinary wire
     *  id, so a shell that answers one does not shadow the apps — but never to a bundle's
     *  reserved claim, which is a LOCAL service name no peer may reach (§12.10). Consulted
     *  on INBOUND frames only: a co-resident app's cross-realm call carries an app key
     *  rather than a peer key, and an app addresses an app. */
    answer?: (from: PeerId, proto: string, payload: Uint8Array) => Promise<Uint8Array> | null;
}

export interface Shell {
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
    /** Uninstall the slot selected by its audit identity: drop its claims and dispose its
     *  realm, private modules, timers and scopes as one unit. */
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

// Re-exported so a target reaches the admission constructors from the same module it gets
// createShell from. Pure-module builders remain target implementations, not shell API.
export { denyAll, admitAll, authorAllowlist, byPrivilege, allOf, anyOf, policyFromJson, type Admit, type AdmissionContext } from "./policy.js";
/** The answer to a `_host` op that reports rather than asks. */
const EMPTY = new Uint8Array(0);

/** A slot's realm. Nullable for exactly the window between the holder being made and the
 *  factory resolving, inside one `loadBundleBlob` — a slot only enters `slots` with its
 *  realm standing, and teardown reads the settled handle synchronously, because the callers
 *  that dispose are deciding right then what the node holds. */
interface AppSlot {
  verifiedBundle: LoadedBundle;
  pureModules: PureModules;
  fsScope?: Fs;
  signingScope: SignScope;
  realm: SafeRealm | null;
  /** This realm's deadlines. Per SLOT rather than per shell, because a timer is a
   *  pending re-entry into one particular realm: the cap is then one guest's to
   *  spend, and disposing that realm is what cancels exactly its own (`disposeSlot`). */
  timers: RealmTimers;
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
    /** The existing concrete channel adapter is supplied and owned by the platform. The
     *  shell may wire raw-link calls to it, but it is not part of the Shell API. */
    const netHost = platform.transportHost;
    // The tail of every initiator `invoke` call. close() defers realm disposal onto
    // this so a call parked mid-await (a repair pass waiting out an unreachable peer)
    // is never resumed into a freed realm — a QuickJS use-after-free (§2.1).
    let inFlight = Promise.resolve();
    /** The one app a bare `invoke` means, or an error naming what is ambiguous. */
    const onlyApp = () => {
        if (slots.length === 0)
            throw new Error("shell: load a bundle first (loadBundleBlob)");
        if (slots.length > 1)
            throw new Error("shell: multiple apps loaded — supply appKey");
        return slots[0];
    };
    const keyOf = (slot: AppSlot) => appKeyFor(slot.verifiedBundle.author, slot.verifiedBundle.manifest.app);
    const findSlot = (appKey: string) => slots.find((slot) => keyOf(slot) === appKey);
    const slotClaims = (slot: AppSlot) => slot.verifiedBundle.manifest.protocols ?? [];
    const hasLink = (slot: AppSlot) => privilegesOf(slot.verifiedBundle.manifest).includes(PRIVILEGE_LINK);
    const releaseClaims = (slot: AppSlot) => {
        for (const claim of slotClaims(slot)) {
            if (claims.get(claim) === slot) claims.delete(claim);
        }
    };
    /** An empty slot for `loaded`, with its timer table already pointed at the realm the
     *  slot does not have yet. The cycle is tied by reading `holder.realm` at FIRE time,
     *  which is the correct reading anyway: the realm a deadline re-enters is the one
     *  standing when it fires, and a transport handover replaces that realm while the slot
     *  stays. A timer only exists because a guest armed it, so `?.` covers the disposal
     *  race rather than a cold start. */
    const newSlot = (loaded: LoadedBundle, pureModules: PureModules): AppSlot => {
        let slot: AppSlot;
        const timers = createRealmTimers((id) => {
            const args = new Uint8Array(4);
            writeU32BE(args, 0, id);
            // A guest that arms a deadline without registering `timer` is refused by its
            // own realm, and an app's `timer` may legitimately throw. Neither has a caller
            // left to reject — the arming call returned turns ago — so it is reported and
            // swallowed.
            void slot.realm?.call("timer", args).catch((err: unknown) => {
                console.error(`[shell] guest error in timer: ${errMessage(err)}`);
            });
        });
        slot = {
            verifiedBundle: loaded,
            pureModules,
            fsScope: fs ? scopedFs(fs, appScopeFor(platform.sodium, loaded.author, loaded.manifest.app)) : undefined,
            signingScope: slotSignScope(platform, loaded.author, loaded.manifest.app, privilegesOf(loaded.manifest)),
            realm: null,
            timers,
        };
        return slot;
    };
    /** Release a slot: cancel its deadlines, THEN dispose its realm. Every teardown
     *  path goes through this — uninstall, revoke, close, a transport handover — because
     *  the other order leaves a `setTimeout` holding a callback into a freed QuickJS
     *  context, which is a crash rather than an error (§2.1). */
    const disposeSlot = (slot: AppSlot | null | undefined) => {
        slot?.timers.clearAll();
        slot?.realm?.dispose();
        slot?.pureModules.dispose();
    };
    /** Stand one candidate realm. It remains outside `slots` and `claims` until this and
     *  the freshness write both succeed. */
    const standRealm = async (slot: AppSlot): Promise<void> => {
        const b = slot.verifiedBundle;
        slot.realm = await platform.createRealm({
            source: `const APP = ${JSON.stringify({ ...(b.manifest.guest.config ?? {}), ...(opts.config ?? {}) })};\n` + b.guestSource,
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
        const b = slot.verifiedBundle;
        const links = hasLink(slot);
        // The 32 bytes this realm is attributed by when it calls another: the app key,
        // hashed. The same shape as the sender key prepended to an inbound frame, so a
        // callee reads one field whether the caller was a peer or a co-resident app. Zero
        // is the HOST's own, and no app key derives it.
        const callerId = genesisHash(platform.sodium, enc.encode(keyOf(slot)));
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
                // What SIGN signs under was chosen with the slot, from the privilege the
                // bundle reaches (`slotSignScope`, §12.2) — not here, and never by the
                // guest. Both slots sign with the node's one key and the slot picks what
                // the signature MEANS: the transport signs
                // transcripts under DOMAIN_channel ‖ networkKey, an app under DOMAIN_guest ‖
                // its own bundle's scope. The seam prefixes and never parses, so neither
                // can produce the other's signature and no op signs raw bytes.
                signScope: slot.signingScope,
                // Scoped to this app key, so `fs` grants reach this app's own keyspace and
                // not the node's — the same structural ownership module names have (§5.1).
                // Wired whenever the node has an fs at all, without consulting the
                // manifest: `names` already refuses every `fs/*` the bundle did not
                // declare, and a second test here would decide one grant in two places.
                fs: slot.fsScope,
                // The cross-realm call. Resolution happens at CALL time, not here: an app
                // may be installed before the transport that answers its `_net`, and a
                // later load may take the id over, so a claimant captured at seam
                // construction would pin this realm to whoever was there first.
                calls: { call: (id, payload) => crossRealmCall(slot, callerId, id, payload) },
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
    };
    /** Enter a slot's guest. The null arm is reachable only from guest top-level code
     *  while its candidate realm is still being constructed. */
    const callSlot = (slot: AppSlot, input: Uint8Array) => slot.realm
        ? slot.realm.call("handle", input)
        : Promise.reject(new Error("shell: the guest's realm is not standing yet"));
    netHost?.route((payload) => {
        const slot = claims.get(NET_PROTOCOL);
        return slot ? callSlot(slot, payload) : null;
    }, () => claims.has(NET_PROTOCOL));
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
        const slot = claims.get(id);
        return slot ? callSlot(slot, input) : null;
    };
    /** The shell's own protocol (`_host`), answered ahead of dispatch. All three ops are
     *  the transport telling the host about something only the transport can see.
     *
     *  Restricted to the realm that CLAIMS `_net`, not merely to one holding `link`. The
     *  privilege is the wider set — a link-capable bundle may claim nothing at all and be
     *  an ordinary initiator (§12.8) — and `deliver` is the difference: it hands the routing
     *  a frame with a `from` the caller writes, so anything reaching it can forge an inbound
     *  request attributed to any peer. Being the node's network is what earns that, and the
     *  claim is what says so.
     *
     *  The test is on the SLOT rather than its app key: an in-place transport upgrade builds
     *  a new slot under the same key, and the candidate has not taken the claim over while
     *  its realm is standing (`loadBundleBlob`) — a key comparison would let it answer as
     *  the network one turn early. `caller` is the slot whose seam this closure was built
     *  for, so there is nothing to spoof. */
    const hostAnswer = (caller: AppSlot, payload: Uint8Array): Promise<Uint8Array> => {
        if (claims.get(NET_PROTOCOL) !== caller) {
            return Promise.reject(new Error(`shell: ${SHELL_PROTOCOL} is answered only for the ${NET_PROTOCOL} claimant, and this realm does not claim it`));
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
            // absent hook fall through only for ordinary wire protocols, so a shell answers
            // an id of its own without exposing a bundle's local reserved claim to a peer.
            case "deliver": {
                const from = toHex(a.slice(0, 32));
                const protoLen = a[32];
                const proto = dec.decode(a.slice(33, 33 + protoLen));
                const body = a.slice(33 + protoLen);
                return opts.answer?.(from, proto, body)
                    // Reserved claims are LOCAL realm services. The shell's own inbound
                    // hook gets first refusal (e.g. a browser bootstrap `_offer`), but a
                    // peer may never fall through to a bundle's reserved claim: it has no
                    // manifest whose `requires` could grant that call.
                    ?? (isReservedProtocol(proto)
                        ? Promise.resolve(EMPTY)
                        : doDispatch(from, proto, body) ?? Promise.resolve(EMPTY));
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
    /** Refuse a candidate contesting a claim ANOTHER identity currently holds (§12.10): a
     *  claim has one active owner, and a load that took one over would be a route changing
     *  hands without its owner ever being uninstalled. This identity's own claims are not a
     *  contest — replacing them in place is what an update is.
     *
     *  Asked once before candidate code can execute, then again in the synchronous commit
     *  window. The first prevents a known loser from exercising irreversible authorities;
     *  the second is the guarantee, because a claim taken while modules and the realm build
     *  across yields would slip past the early decision. */
    const refuseContestedClaims = (loaded: LoadedBundle, key: string) => {
        for (const claim of loaded.manifest.protocols ?? []) {
            const incumbent = claims.get(claim);
            if (incumbent && keyOf(incumbent) !== key) {
                throw new Error(`shell: claim '${claim}' is already held by '${keyOf(incumbent)}'`);
            }
        }
    };
    /** Advance the `(author, app)` freshness mark after the candidate realm stands but
     *  before its synchronous claim commit. It records the highest version that actually
     *  ran while a failed write can still discard only the candidate.
     *
     *  `prev` is the mark this load was admitted against (`AdmissionContext.highWater`) —
     *  read once, since nothing between there and here writes the store.
     *
     *  A persist failure rolls the in-memory mark back so retry performs a fresh durable
     *  write; the caller then disposes the unpublished candidate. */
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
        // Read BEFORE the claims are released, and asked of the CLAIM rather than of the
        // `link` privilege: `reset` closes every channel the driver holds, so keying it on
        // the wider set would let uninstalling a link-capable initiator — a bundle that
        // never was the network — disconnect the node.
        const wasNetwork = claims.get(NET_PROTOCOL) === slot;
        releaseClaims(slot);
        if (wasNetwork) netHost?.reset();
        disposeSlot(slot);
        return true;
    };
    /** Route an inbound request to its app (§12.10): resolve the protocol to the app
     *  claiming it, prepend the authenticated sender, hand it to that app's one entrypoint.
     *
     *  No branch on how the app is implemented: every app presents the same
     *  `senderPk ‖ payload` shape and the same single entry, its slot's realm (`callSlot`).
     *  The answer is the realm's — a Promise the transport resumes on a later turn rather
     *  than inline (transport-host.ts), which is what an asynchronous holder needs since
     *  `fs` is async. */
    const doDispatch = (from: PeerId, proto: string, payload: Uint8Array) => {
        const slot = claims.get(proto);
        if (!slot)
            return null;
        const senderBytes = fromHex(from);
        const input = new Uint8Array(senderBytes.length + payload.length);
        input.set(senderBytes, 0);
        input.set(payload, senderBytes.length);
        return callSlot(slot, input);
    };
    return {
        resolve: (proto) => {
            const slot = claims.get(proto);
            return slot ? keyOf(slot) : null;
        },
        routes: () => [...claims].map(([claim, slot]) => [claim, keyOf(slot)]),
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
            const loaded: LoadedBundle = {
                manifest: v.manifest, author: v.author, authorKeys: v.authorKeys,
                guestSource: v.guestSource,
            };
            const key = appKeyFor(loaded.author, loaded.manifest.app);
            // Refuse a conflict already standing BEFORE the candidate's modules or guest
            // execute. The guest's top level can use every authority its admitted manifest
            // declares, and disposing a rejected candidate cannot undo an fs write or a raw
            // link it opened. The second check in the synchronous commit window remains
            // necessary: another load may take a free claim while this candidate is built.
            refuseContestedClaims(loaded, key);
            const pureModules = await loadBundleModules(moduleLoader, v);
            const slot = newSlot(loaded, pureModules);
            // STAND THE GUEST, before anything already standing is replaced. Every app is a
            // guest (§12.4), so a bundle whose guest will not compile has not loaded — and
            // discovering that at the first frame instead would leave the mark advanced for
            // a bundle that never ran a line, putting every version an operator can reach
            // below a floor a broken upgrade raised: rollback bricked by a failed upgrade.
            try {
                await standRealm(slot);
                // The candidate is complete. EVERYTHING FROM HERE IS SYNCHRONOUS, which is
                // what makes the commit atomic: the contest below, the mark, and the claim
                // hand-over cannot be interleaved with another load or an uninstall.
                refuseContestedClaims(loaded, key);
                commitMark(loaded, ctx.highWater);
            }
            catch (err) {
                disposeSlot(slot);
                throw err;
            }
            const previousIndex = slots.findIndex((installed) => keyOf(installed) === key);
            const previous = previousIndex < 0 ? undefined : slots[previousIndex];
            // Whether the slot being replaced WAS the network, read before its claims go.
            const replacingNetwork = previous !== undefined && claims.get(NET_PROTOCOL) === previous;
            if (previous) releaseClaims(previous);
            if (previousIndex < 0) slots.push(slot);
            else slots[previousIndex] = slot;
            for (const claim of slotClaims(slot)) claims.set(claim, slot);
            // The outgoing guest's link state went with its realm (§4.3), so the sockets it
            // held are torn down here rather than left as channels nobody can speak for. The
            // incoming guest redials from the address book, which is the NODE's. After the
            // claim hand-over above, so `onClose` finds the channels already gone and queues
            // no `linkClosed` at the new realm for links it never had.
            if (replacingNetwork) netHost?.reset();
            // The address book is mutable node state, not part of the candidate's static
            // `link/config` snapshot. Publish first, then replay it through the ordinary
            // host-event path. No await in between: a concurrent add is either in this
            // replay or is announced directly to the newly published claimant.
            if (slotClaims(slot).includes(NET_PROTOCOL)) netHost?.replayAddresses();
            disposeSlot(previous);
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
            const slot = appKey ? findSlot(appKey) : onlyApp();
            if (!slot)
                throw new Error(`shell: no app '${appKey}' loaded`);
            // The loopback: the app's ONE entrypoint, called with the host's own caller id
            // (32 zero bytes) exactly as a remote frame carries its peer's key, so the app
            // reads one `handle` either way. The envelope is written by the seam that
            // defines it (`opCall`), never here.
            const call = callSlot(slot, opCall(op, payload));
            inFlight = inFlight.then(() => call, () => call).catch(() => { }) as Promise<void>;
            return call;
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
