// The platform-neutral shell core — the §12.9 "move one level up". Everything that
// standing a node up involves EXCEPT the parts that genuinely vary by target lives
// here: the module table's owner, the guest-seam wiring, the preamble assembly, the
// realm's lifecycle, the bundle load order, the socket driver, and the inbound
// dispatch. A target supplies the platform seam — { sodium, identity, table, fs?,
// freshnessStore, channels?, listen?, wsListen?, createRealm } — exactly like the
// transport driver takes a ChannelFactory, and gets back a fully wired Shell.
//
// This is the ONE assemble path, and the assembly ORDER is the point: it is the last
// thing two hosts could disagree about, so no target restates it.
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
import { createGuestSeam, appSignScope, transportSignScope, type SeamCrypto, type HostCall, type HostTimers } from "./guest-seam.js";
import { TransportHost } from "./transport-host.js";
import { isSafeFsKey, isSafeFsScope, type Fs } from "../core/fs.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_MAX_LIVE_TIMERS, DEFAULT_REALM_MEMORY_BYTES } from "../core/wasm-limits.js";
import { NET_PROTOCOL, PRIVILEGE_LINK, SHELL_PROTOCOL, type Privilege } from "../core/domains.js";
import { dec, enc, fromHex, toHex, readU32BE, writeU32BE, errMessage } from "../core/util.js";
import { type SafeRealm } from "./safe-js.js";
import { type ChannelFactory, type PeerId } from "../core/socket-seam.js";
import type { Keypair } from "../core/subkeys.js";

/** The crypto surface the shell needs: manifest verification + genesis hashing
 *  (BundleCrypto) plus the guest seam's crypto ops (SeamCrypto). Any sumo libsodium
 *  build satisfies both. */
export type ShellSodium = BundleCrypto & SeamCrypto;

/** The one reason a bundle load is refused without being an error worth reporting:
 *  the policy predicate said no (§12.4). The transport's installers treat this
 *  as "a node without a network — a deliberate configuration", not a failure, so
 *  the message is a shared constant rather than a string the caller re-matches. */
export const ADMISSION_REJECTED = "bundle: rejected by admission predicate";

/** True iff a loadBundleBlob failure was the policy's refusal (see ADMISSION_REJECTED),
 *  whatever shape the thrown value took. */
export function isAdmissionRejected(err: unknown): boolean {
    return errMessage(err).includes(ADMISSION_REJECTED);
}

/** How a target creates the confined realm a guest runs in (§12.3). The JS platform's
 *  factory is `createSafeRealm` (safe-js.ts: QuickJS-over-wasm, driven by
 *  quickjs-emscripten's job pump); the native target's is a second quickjs-ng realm
 *  driven by Go's event loop (native/guest.go). Both honor the same contract — one
 *  `call`, which may await, and invocations serialized per realm — so the shell drives
 *  either without knowing which it holds. The shell always supplies both bounds (it
 *  resolves the shared defaults, core/wasm-limits.ts), so a factory never has to
 *  decide "omitted means what"; a factory that is called directly may still default. */
export type RealmFactory = (opts: {
    source: string;
    hostCall: HostCall;
    memoryLimitBytes?: number;
    /** Budget of guest *execution* time per entrypoint invocation, in ms. Omitted ⇒ the
     *  factory's own default — which is the shared `DEFAULT_GUEST_DEADLINE_MS` on both
     *  targets. Both resource bounds cross this seam, so a guard a factory implements
     *  is one the shell can actually reach. */
    deadlineMs?: number;
}) => Promise<SafeRealm>;

/** The module table as exposed by the Shell — everything a caller needs to
 *  reach installed modules, WITHOUT installWasmModule AND WITHOUT
 *  removeApp. The bind is the bundle loader's job (§12.4); the unbind
 *  is the shell's uninstall method (§12.5). Neither install nor remove is a
 *  public host method. */
export interface ModuleLookup {
    callModule(appKey: string, module: string, payload: Uint8Array): Uint8Array | null;
    isBound(appKey: string, module: string): boolean;
}

/** The §3 module table as the shell uses it: the one transactional install a bundle
 *  load needs (`BundleHost.bindAll`), plus reaching and releasing what landed. A
 *  platform primitive, not shell logic — `ModuleTable` is the JS implementation over
 *  `WebAssembly`, and the native target's is Go's wazero map behind its byte bridge
 *  (§12.9). The table is the same contract either way; only who owns the instances
 *  differs — which is precisely why both the all-or-none bind and the release live
 *  behind it rather than in the loader. */
export interface ModuleTableBackend extends BundleHost, ModuleLookup {
    /** Drop an app and every module it landed, returning how many went. One lookup is
     *  all `uninstall` needs: an app's modules are the value under its key (§5.1), so
     *  the unit of removal is the unit of install. */
    removeApp(appKey: string): number;
}

/** The platform seam — everything the shell needs that varies by target.
 *  `fs` is optional, and the reason is simply "a node with no disk": a bundle declaring
 *  the `fs` cap on such a shell gets no backend wired at all, so its first `fs/*` call
 *  throws by name rather than resolving to a pretend store (§12.2). `createRealm` is
 *  REQUIRED: every app is a guest (§12.4), so a shell that cannot run a guest cannot
 *  host an app.
 *
 *  The transport itself is a signed bundle (§12.6): the platform supplies the SOCKET
 *  seam (`channels`, `listen`/`wsListen`, the network key and contact secret) and the
 *  shell stands the driver up when some bundle claims `_net`. There is no `network`
 *  member to hand in — the bundle that claims that id IS the network. */
export interface ShellPlatform {
    sodium: ShellSodium;
    /** The node's keypair (§12.9) — its public half is this node's peer id, and the ONE
     *  identity every target reports through `node/identity`. The handshake and the guest
     *  seam's SIGN op both sign with it, under different domains and scopes. */
    identity: Keypair;
    /** The module table this shell binds bundle modules into (§3). */
    table: ModuleTableBackend;
    fs?: Fs;
    freshnessStore: FreshnessStore;
    createRealm: RealmFactory;
    now?: () => number;
    /** OPTIONAL network key — which network this node belongs to. An isolation
     *  boundary, not a gate (§12.6); absent ⇒ the public network. Feeds both the
     *  transport guest's INIT and the CHANNEL_SIGN root check. */
    networkKey?: Uint8Array;
    /** OPTIONAL contact secret for THIS node — 32 bytes of full entropy, published
     *  with our address; the gate a caller must produce before msg1 opens. Absent ⇒
     *  an open node. Per node, never per deployment (§12.6.3). */
    contactSecret?: Uint8Array;
    /** The socket seam: TCP/WS dialing and listening behind the RawLink shape
     *  (net-node's factory, the native loader's over Go sockets). Absent for a
     *  host-managed-transport-only node (a browser edge), which opens links through
     *  the driver's openLink() and lets DIAL actions go unanswered. */
    channels?: ChannelFactory;
    listen?: {
        host: string;
        port: number;
    };
    wsListen?: {
        host: string;
        port: number;
    };
    /** Parallel connections per dialed peer (default 1) — the transport's dial
     *  fan-out. */
    connsPerPeer?: number;
    /** The peers this node will talk to, as 32-byte channel keys — shipped to the transport
     *  at init and applied there. A LINT rather than a gate, and named as one: see
     *  `TransportHostOptions.admitPeers` for why a predicate the host applied to what the
     *  transport reported never gated anything against a hostile transport either. Absent ⇒ the
     *  node admits every peer that completes the handshake. */
    admitPeers?: Uint8Array[];
}

export interface CreateShellOptions {
    /** The operator's admission predicate (§12.5) — ONE `Admit`, asked once per load,
     *  between verify and install. `ctx.privileges` says which privileges this bundle's
     *  requires reach — nothing for an ordinary app, `link` for the node's transport —
     *  so a deployment that answers per capability composes
     *  `byPrivilege({ base, grants })`; `policyFromJson` already does.
     *  Absent ⇒ deny-all, nothing is admitted.
     *
     *  A file-backed author allowlist, a consent dialog, and "the bundle my operator
     *  handed me" are three constructors of this one type. The host's own gates —
     *  revocation, the two coherence rules, and the downgrade guard — are composed AROUND
     *  whatever is passed here (`hostGates`), so no posture supplied by an operator can be
     *  a way to lose them. */
    admit?: Admit;
    /** How long one net request may take before it settles as unreachable, in ms, for
     *  a caller that names no deadline of its own (§12.6). Omitted ⇒ the transport's
     *  `DEFAULT_REQUEST_DEADLINE_MS`. A deployment-wide fallback, not a policy — the
     *  caller of `transport.request` overrides it per call. */
    requestDeadlineMs?: number;
    /** Operator-supplied app config, merged *over* the bundle manifest's `config`
     *  into the guest's `const APP = …`. Opaque to the shell. */
    config?: Record<string, string | number>;
    /** QuickJS heap limit for the guest realm, in bytes. Omitted ⇒ the shared default
     *  (`DEFAULT_REALM_MEMORY_BYTES`, core/wasm-limits.ts — 64 MiB, the same ceiling
     *  as a module's declared memory). A target that streams large windows through
     *  the guest raises it to run without the realm OOMing (seedstore's
     *  `realmMemoryBytes`). */
    realmMemoryBytes?: number;
    /** Budget of guest execution time per entrypoint invocation, in ms. Omitted ⇒ the
     *  shared default (`DEFAULT_GUEST_DEADLINE_MS`, core/wasm-limits.ts — 5s, §16.1).
     *  Counts time the guest is *running*, not time
     *  it spends parked on a host seam, so it bounds a wedged guest without penalising
     *  one legitimately awaiting the network. `Infinity` disables it.
     *
     *  This is the operator's number, not the author's: unlike the module memory ceiling
     *  (§4.3), which a bundle declares in its signed manifest, how long this node is
     *  willing to spend on one message is a property of the deployment. */
    guestDeadlineMs?: number;
    /** The SHELL's own protocols, answered ahead of the routing table (§12.10).
     *
     *  A shell may serve protocols of its own — seedchat's `_offer`, which carries a
     *  bundle between two browsers before either has an app that could receive it — and
     *  the reservation has to be an explicit seam because there is nowhere else left to
     *  put it. An inbound frame reaches this shell as the transport's `_host` deliver op and
     *  goes straight to `doDispatch`; a host that wanted first refusal used to get it by
     *  wrapping the driver's `onRequest`, and that facade is gone (transport-host.ts).
     *
     *  `null` means "not mine" and falls through to the routing table, so a shell that
     *  answers one id does not shadow the apps. Consulted on INBOUND frames only: a
     *  co-resident app's cross-realm call carries an app key rather than a peer key, and
     *  handing one to a callback whose argument is named `from: PeerId` would be the
     *  attribution rules quietly disagreeing. An app addresses an app. */
    answer?: (from: PeerId, proto: string, payload: Uint8Array) => Promise<Uint8Array> | null;
    /** Half-open budgets for the transport slot: concurrent links that have not
     *  yet proven their contact credential (unverified), per source address, and proven-
     *  but-mid-handshake (verified). Defaults match the transport bundle's
     *  (1024 / 8 / 256); tests shrink them. Enforced inside the transport guest. */
    transportHalfOpen?: {
        unverified?: number;
        perSource?: number;
        verified?: number;
    };
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
    /** The transport bundle's driver, or `null` until one is loaded (§12.6).
     *
     *  ONE object, not one per face: `TransportHost implements Network, HostTransport`,
     *  so the endpoint vend, the request/response pair every app's `net` names reach,
     *  and the host-side address book a console line drives are all reached through
     *  this field. A shell that never admitted a transport bundle has no network at
     *  all, and the `null` is that answer — a caller that needs one says so with
     *  {@link requireTransport} rather than calling into a stub that throws. */
    transport: TransportHost | null;
    /** Filesystem backend, or absent for a node with no disk (a bundle declaring the
     *  `fs` cap then gets no backend wired — its first `fs/*` call throws). */
    fs?: Fs;
    sodium: ShellSodium;
    /** Load a signed bundle blob: verify the manifest, run the admission predicate,
     *  integrity-check + install the modules, and return the guest source. This is
     *  the §12.4 load order — the ONE install path, for apps and for the transport
     *  alike. A bundle naming the `link/*` names (§12.5) is governed by the
     *  `link` half of the policy and stood up as this shell's transport instead of
     *  bound as an app; replacing a standing transport is a staged handover, where the
     *  incoming guest stands before the outgoing driver is closed and links reconnect
     *  under the new guest. */
    loadBundleBlob(blob: Uint8Array): Promise<LoadedBundle>;
    /** Uninstall an app: remove every module derived from `appKey`,
     *  drop the protocols it claimed, and dispose the confined realm if
     *  this was its last app. Returns true if any modules were removed.
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
     *  guest seam over the host's primitives. `appKey` defaults to the
     *  only loaded app; throws when more than one is loaded and no key is
     *  given. */
    runGuest(entry: string, payload: Uint8Array, appKey?: string): Promise<Uint8Array>;
    /** Dispatch an inbound request to the right app (§12.10): resolve the protocol to
     *  the app claiming it and invoke that app's guest `handle` entrypoint with
     *  `senderPk ‖ payload`. Null when no installed app claims the protocol.
     *
     *  Every app is a guest, so the answer is always the realm's — a Promise the
     *  transport driver awaits — never raw bytes; there is no second, synchronous
     *  delivery shape. */
    dispatch(from: PeerId, proto: string, payload: Uint8Array): Promise<Uint8Array> | null;
    /** Pre-create every app's realm, so the first routed frame does not pay realm
     *  construction. Not a switch: an inbound frame reaches the shell as the transport's
     *  `_host` deliver op, so a node serves from the moment its transport bundle is
     *  loaded (§12.10). Throws if there is no transport to serve over. */
    serve(): Promise<void>;
    close(): void;
}

/** The transport driver, or a diagnosis of why there is none.
 *
 *  A node without a transport bundle is a legitimate configuration (§12.6) — the
 *  policy simply granted `link` to nobody — so `shell.transport` is nullable and
 *  every caller sees that in the type. This is for the callers that genuinely cannot
 *  proceed (a CLI dialing a peer): it turns the null into the sentence an operator
 *  can act on, naming the privilege and the halves a bundle must declare to hold it.
 *  Nothing on the Shell throws this on the caller's behalf — a stub that answers a
 *  `Network` shape and throws on use would be a transport that is not one. */
export function requireTransport(shell: Pick<Shell, "transport">, what: string): TransportHost {
    if (shell.transport) return shell.transport;
    throw new Error(`shell: ${what} — the transport bundle is not loaded (load one that reaches the "${PRIVILEGE_LINK}" privilege and claims ${NET_PROTOCOL}, first)`);
}

// Re-export the admission predicate constructors so a target that gates admission
// on consent (the browser) or on which bundle it was handed (a StorageNode) can
// reach them from the same module it gets createShell from. ModuleTable rides along
// for the same reason: the JS platforms all hand it in as their `table`, and a
// re-export keeps that a one-line seam rather than a second import.
export { denyAll, admitAll, authorAllowlist, byPrivilege, allOf, anyOf, policyFromJson, type Admit, type AdmissionContext } from "./policy.js";
export { ModuleTable } from "./module-table.js";
/** Assemble the platform-neutral shell. Every target calls this instead of
 *  re-implementing the module table, guest-seam wiring, preamble assembly, realm
 *  creation, and transport routing. */
/** An app's ONE inbound entrypoint (§12.10): the authenticated `senderPk ‖ payload`
 *  in, the response bytes out, or null for "this app answers nothing". Every app is a
 *  guest, so every entry resolves to its realm's `handle` and therefore returns a
 *  Promise — there is no second, synchronous shape. */
type AppEntry = (input: Uint8Array) => Promise<Uint8Array> | null;

/** The answer to a `_host` op that reports rather than asks. */
const EMPTY = new Uint8Array(0);

/** A slot's realm, in the two shapes the code needs it in. `realm` is the SETTLED
 *  handle, and it is what teardown reads — disposing has to be synchronous, because
 *  the callers that do it (uninstall, close, a transport handover) are deciding
 *  right then what the node holds. `realmP` is the in-flight construction, and it
 *  is the memo: `ensureRealm` is reached concurrently — two inbound frames for
 *  an app whose realm does not exist yet both arrive before either factory call
 *  resolves — so without a promise to share, each caller would build its own realm
 *  and every one but the last would be orphaned: never disposed, still holding its
 *  heap and its interpreter. Memoizing the RESULT is not enough; the window this
 *  closes is entirely before there is one. */
interface RealmHolder {
  loaded: LoadedBundle;
  realm: SafeRealm | null;
  realmP: Promise<SafeRealm> | null;
  /** This realm's deadlines. Per SLOT rather than per shell, because a timer is a
   *  pending re-entry into one particular realm: the cap is then one guest's to
   *  spend, and disposing that realm is what cancels exactly its own (`disposeSlot`). */
  timers: RealmTimers;
}

interface AppSlot extends RealmHolder {
  entry: AppEntry;
  /** Does this bundle reach the `link` privilege (§12.5)? Read off the manifest once,
   *  at install, because it decides two things about the seam this slot is wired with:
   *  whether sockets are in it, and what its signatures mean. Not a KIND of slot —
   *  there is one slot type now, and the transport is an app that claims `_net`. */
  isTransport: boolean;
}

/** A realm's timer table: the platform's event loop, handed to a guest that has none.
 *
 *  Everything here is the HOST's memory — a fresh QuickJS context has no `setTimeout`,
 *  so an armed deadline is an entry in this map and nothing in the guest's heap. Two
 *  consequences, and they are the whole of the type:
 *
 *  - the live count is **capped**, because a limit protecting a resource belongs to
 *    whoever owns the resource, and an unbounded `timer/arm` loop is otherwise a guest
 *    spending host memory it is not charged for;
 *  - `clearAll` is **not** optional at teardown. A pending `setTimeout` holds a callback
 *    that re-enters the realm, so a timer surviving its realm's disposal is a call into
 *    a freed QuickJS context (§2.1) — the one failure mode that is a crash rather than
 *    an error. Every disposal site goes through `disposeSlot` for that reason.
 *
 *  `id` is the guest's own throughout: the host keeps no name of its own for a deadline,
 *  so an arm on a live id re-arms it and `clear` is idempotent. */
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
// Which keys a node admits decides which blocks it stores and advertises, so the
// rule itself is a consensus predicate and lives in the core. What this file
// contributes is the two places the host APPLIES it. `validatedFs` wraps whatever
// backend a target supplies so every host admits exactly the same key space, and
// `scopedFs` scopes a backend to one app's private keyspace (README §12.2) so two
// apps sharing the domain still cannot read each other's keys. They are host
// mechanics rather than vocabulary, so they sit here with the only production
// caller (createShell). The argument each wraps is in core/fs.ts; see the scoping
// note in `appScopeFor` (bundle.ts) for why `scope` must be a fixed-length
// derived prefix.

/** Apply the key rule over a backend, once, for every target.
 *
 *  A rejected key **throws** rather than reading as absent. An unrepresentable key is a
 *  caller bug, and answering `null`/`-1`/`false` would hide it on a read while `put`
 *  failed anyway — so the one behaviour is the loud one, on every op that names a key.
 *  `list` is not one of them: its argument is a prefix, and the empty prefix ("every key
 *  I can see") is exactly the call a key rule would wrongly refuse. `stat` names nothing.
 *
 *  Wrapping happens where a backend enters the shell (`createShell`), so it sits UNDER
 *  `scopedFs` and therefore validates the composite `scope + key` a guest actually
 *  reaches — which is the string the medium sees. */
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

/** Scope a backend to one app's private keyspace (README §12.2).
 *
 *  Without this, every app granted the `fs` domain shares one flat keyspace: `fs/list`
 *  with an empty prefix enumerates every key on the node, `fs/get` reads any of them and
 *  `fs/delete` removes any of them. That is the one place the runtime's "ownership is
 *  structural" property (§5.1) did not hold — table *names* carry their author, so one
 *  app's modules are unreachable to another by construction, but fs *keys* carried
 *  nothing and were reachable to everyone. This closes that asymmetry the same way the
 *  names do: by derivation, not by a rule something has to enforce.
 *
 *  `scope` is an opaque prefix derived from the app key by `appScopeFor` (bundle.ts) —
 *  derived there rather than here because it needs a hash. Two properties matter and
 *  both come from that derivation: it lies inside the backend's key charset (checked
 *  below), and it is fixed-length, so distinct scopes cannot overlap however an author
 *  names the app. (An app name may itself contain `:`, so a plain `appKey + separator`
 *  prefix would let app `x` key `y:z` collide with app `x:y` key `z` — and would be
 *  rejected by both backends anyway.)
 *
 *  `stat()` is deliberately NOT scoped — `used`/`available` describe the physical
 *  backend, and reporting a per-app figure for `available` would be a fiction. An app
 *  that wants its own footprint sums `size()` over its own `list()` — exactly its own
 *  keys. */
export function scopedFs(inner: Fs, scope: string): Fs {
  // A scope prefix must survive the key rule — it is the head of every key this app
  // will ever reach — so it is checked here, at construction, rather than on the first
  // `put`. The charset only (core/fs.ts `isSafeFsScope`): a scope is not a whole key,
  // so the bare-dot and device-name cases (which are about a complete name) do not
  // apply to it.
  if (!isSafeFsScope(scope)) throw new Error(`fs: unsafe scope ${JSON.stringify(scope)}`);
  const outward = (key: string): string => scope + key;
  return {
    get: (key) => inner.get(outward(key)),
    put: (key, bytes) => inner.put(outward(key), bytes),
    size: (key) => inner.size(outward(key)),
    // An absent prefix means "everything I can see", which is everything in this
    // scope and nothing else. Keys come back stripped, so the guest only ever handles
    // the names it chose and the scope stays a host-side fact.
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
    // The key rule (core/fs.ts) applied once, here, over whatever backend this target
    // supplied — so every host admits exactly the same key space, which is what decides
    // the contents a node stores and advertises. Under `scopedFs` below, so what gets
    // checked is the composite key the medium actually sees.
    const fs = platform.fs ? validatedFs(platform.fs) : undefined;
    const host = platform.table;
    // THE admission predicate — one function, asked once per load (§12.5). The host's own
    // invariants come first and are composed here rather than by the operator: an
    // `admitAll` posture, or a consent dialog that always says yes, must not be a way to
    // lose revocation or the downgrade guard.
    const admit: Admit = allOf(hostGates, opts.admit ?? denyAll);
    const apps = new Map<string, AppSlot>();
    /** protocol id → app key (§12.10) — a PROJECTION of what is installed, never a
     *  structure of its own. Every entry comes from some installed manifest's signed
     *  `protocols`, so there is nothing here to write, to persist, or to keep in step
     *  with the app set: the routing IS the app set, read through one field. It is
     *  materialized rather than scanned for because it is read once per inbound frame
     *  (§12.10: one lookup, one guest call). */
    const routes = new Map<string, string>();
    /** The socket driver, standing once some bundle claims `_net`. It outlives the
     *  bundle: the driver holds link ids, the address book and the listeners, all of
     *  which belong to the NODE rather than to whichever guest is currently the
     *  transport — which is exactly why replacing a transport needs no handover. A
     *  replacement re-`attach`es this same object to the new claimant. */
    let netHost: TransportHost | null = null;
    // The tail of every initiator `runGuest` call. close() defers realm disposal onto
    // this so a call parked mid-await (a repair pass waiting out an unreachable peer)
    // is never resumed into a freed realm — a QuickJS use-after-free (§2.1).
    let inFlight = Promise.resolve();
    /** The one app that was loaded, when exactly one is installed. Throws when zero
     *  or multiple apps are present, so callers that omit an explicit appKey get a
     *  clear error rather than silent ambiguity. */
    const onlyApp = () => {
        if (apps.size === 0)
            throw new Error("shell: load a bundle first (loadBundleBlob)");
        if (apps.size > 1)
            throw new Error("shell: multiple apps loaded — supply appKey");
        return [...apps.values()][0];
    };
    /** An empty slot for `loaded`, with its timer table already pointed at the realm
     *  the slot does not have yet.
     *
     *  The knot — the table fires into the realm, the realm's seam is wired to the
     *  table — is tied by the closure reading `holder.realm` at FIRE time rather than
     *  capturing it now. That is not a trick to make the cycle compile: it is the
     *  correct reading either way, because the realm a deadline must re-enter is the
     *  one standing when it fires, and a transport handover replaces that realm while
     *  the slot stays. A timer only exists because a guest armed it, so there is always
     *  a realm by then; `?.` covers the disposal race rather than a cold start. */
    const newHolder = (loaded: LoadedBundle): RealmHolder => {
        let holder: RealmHolder;
        const timers = createRealmTimers((id) => {
            const args = new Uint8Array(4);
            writeU32BE(args, 0, id);
            // A guest that arms a deadline without registering `timer` is refused by its
            // own realm, and an app's `timer` may legitimately throw. Neither is the
            // shell's failure and neither has a caller to reject: the arming call
            // returned turns ago. Reported, so it is not silent, and swallowed.
            void holder.realm?.call("timer", args).catch((err: unknown) => {
                console.error(`[shell] guest error in timer: ${errMessage(err)}`);
            });
        });
        holder = { loaded, realm: null, realmP: null, timers };
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
    /** The confined realm for `slot`, created lazily on first use through the
     *  platform's factory. Both roles share it and both reach it the same way — the
     *  initiator (`runGuest`) and the holder (`dispatch`) each `realm.call`, and the
     *  realm serializes them, so one runs to completion before the next begins. Lazy
     *  because the JS factory pulls in a heavy engine, and because a node may serve for
     *  a long time before its first guest call.
     *
     *  Concurrency-safe by memoizing the PROMISE (`RealmHolder`): every caller past the
     *  first joins the construction already running rather than starting a second one.
     *  A failed construction clears the memo instead of caching the rejection, so a
     *  factory that failed on a transient (a heap the page could not spare yet) is
     *  retried on the next frame rather than making the app permanently dead. */
    const ensureRealm = (slot: AppSlot): Promise<SafeRealm> => {
        if (!slot.realmP) {
            slot.realmP = platform.createRealm({
                source: guestFullSource(slot.loaded),
                hostCall: seamFor(slot),
                memoryLimitBytes: opts.realmMemoryBytes ?? DEFAULT_REALM_MEMORY_BYTES,
                deadlineMs: opts.guestDeadlineMs ?? DEFAULT_GUEST_DEADLINE_MS,
            }).then((r) => { slot.realm = r; return r; },
                    (e) => { slot.realmP = null; throw e; });
        }
        return slot.realmP;
    };
    /** Wire the `host.call` seam one admitted bundle's realm runs against (guest-seam.ts),
     *  as the three things that own it: what this NODE is (`platform`), what this REALM
     *  may reach (`grants`), and what this APP installed (`modules`).
     *
     *  `driver` is passed ONLY for the transport bundle, and is what puts the
     *  two grants no app holds into that realm's set: the raw net capability (sockets)
     *  and the sink the transport reports its structured output through. Nothing else can
     *  reach a descriptor, at any point in the process's life, because nothing else is
     *  ever handed one (README §1, capability-by-non-wiring).
     *
     *  Timers are NOT among them, and the asymmetry is the point: a deadline is an
     *  ordinary authority in the catalog (`timer/*` is `"app"`, core/domains.ts), so
     *  every realm gets its own table and the transport is simply the first guest that
     *  happened to want one. */
    const seamFor = (slot: AppSlot) => {
        const b = slot.loaded;
        const appKey = appKeyFor(b.author, b.manifest.app);
        // The 32 bytes this realm is attributed by when it calls another: the app key,
        // hashed. Fixed-width and opaque, the same shape as the sender key prepended to
        // an inbound frame — which is the point, because a callee reads one field
        // whether the caller was a peer or a co-resident app. Zero is the HOST's own
        // (transport-host.ts), and no app key derives it.
        const callerId = genesisHash(platform.sodium, enc.encode(appKey));
        return createGuestSeam({
            platform: {
                sodium: platform.sodium,
                identity: platform.identity,
                now: platform.now ?? (() => Date.now()),
            },
            grants: {
                // The declared requires ARE the gate — a `host.call` resolves iff the name
                // itself is one of these (`crypto/*` and the bundle's own bare module names
                // exempt: never grants — a fixed catalog and the app's own code). The
                // vocabulary was checked at load (verifyManifest).
                names: new Set(b.manifest.guest.requires),
                // What SIGN signs under — and what VERIFY checks against — is chosen HERE,
                // by the slot the bundle occupies, the one place that knows it (§12.2). Both
                // slots sign with the node's one key, and the slot picks what that signature
                // MEANS: the transport signs handshake transcripts under DOMAIN_channel ‖
                // networkKey, every ordinary app under DOMAIN_guest ‖ its own bundle's scope.
                // The seam prefixes and never parses, so neither can produce the other's
                // signature and no op signs raw bytes — which is what keeps the purposes
                // apart now that one key serves both (core/subkeys.ts).
                signScope: slot.isTransport
                    ? transportSignScope(platform.identity, platform.networkKey)
                    : appSignScope(platform.identity, b.author, b.manifest.app),
                // Scoped to this app key, so `fs` grants reach over this app's own keyspace
                // and not the node's (fs.ts). Two admitted apps cannot read, enumerate or
                // delete each other's data — the same structural ownership module names
                // have (§5.1).
                //
                // Wired whenever the node has an fs at all, without consulting the manifest:
                // `names` refuses every `fs/*` name the bundle did not declare, so a second
                // test here would be the same grant decided in two places — and the one
                // that reads a prefix off a name, which is exactly what the name catalog
                // exists to stop.
                fs: fs ? scopedFs(fs, appScopeFor(platform.sodium, b.author, b.manifest.app)) : undefined,
                // The cross-realm call. Resolution happens at CALL time, not here: an app
                // may be installed before the transport that answers its `_net`, and a
                // later load may take the id over, so a claimant captured at seam
                // construction would pin this realm to whoever was there first.
                calls: { call: (id, payload) => crossRealmCall(slot, callerId, id, payload) },
                rawNet: slot.isTransport ? netHost?.rawNet() : undefined,
                // This realm's own table, wired for the same reason `fs` is: unconditionally,
                // because `names` already refuses `timer/*` for a bundle that did not declare
                // it, and a second test here would decide one grant in two places.
                timers: slot.timers,
            },
            // Bound to THIS app's key, so a bare `host.call` name addresses its own module
            // map by logical name and has no way to name another app's (§12.2).
            modules: {
                call: (name, p) => host.callModule(appKey, name, p),
                has: (name) => host.isBound(appKey, name),
            },
        });
    };
    const guestFullSource = (b: LoadedBundle) => `const APP = ${JSON.stringify({ ...(b.manifest.guest.config ?? {}), ...(opts.config ?? {}) })};\n`
        + b.guestSource;
    /** Resolve an app's one inbound entrypoint, ONCE, at install (§12.10).
     *
     *  An app has exactly one way in: the confined realm's `handle` entrypoint (§12.2).
     *  Every bundle declares a guest (§12.4), so there is no second mechanism to branch
     *  on — `dispatch` neither branches on how an app is implemented nor re-derives a
     *  table name for every inbound frame.
     *
     *  It closes over the SLOT, not over `slot.realm`: the entrypoint is fixed at
     *  install, but the realm behind it is created lazily, so the entry ensures it on
     *  first use (`ensureRealm`) rather than capturing today's `null`. `serve()`
     *  pre-creates every app's realm so the first routed frame does not pay realm
     *  construction, and an embedder that never calls `serve()` still gets a working
     *  dispatch instead of a silent empty answer. Concurrent frames arriving into that
     *  gap share one construction rather than racing (`ensureRealm`); the settled arm
     *  below is only the steady state, saving a microtask once there is a realm. */
    const entryFor = (slot: AppSlot): AppEntry => {
        return (input) => slot.realm
            ? slot.realm.call("handle", input)
            : ensureRealm(slot).then((r) => r.call("handle", input));
    };
    /** The ONE cross-realm call (§12.10): a guest naming a reserved id reaches the realm
     *  that claims it, on a later turn, and gets back what that realm's `handle`
     *  returned. `null` when nothing claims it, which the seam reports by name.
     *
     *  The host's whole contribution is attribution and resolution. It prepends the
     *  CALLER's 32-byte id, exactly as `doDispatch` prepends the authenticated sender's
     *  key, so a callee reads one shape whether the caller was a peer or a co-resident
     *  app — and the id is derived host-side from the admitted manifest, so it is no more
     *  forgeable than the sender key is.
     *
     *  `_host` is the exception, and it is the §12.10 reservation working as designed:
     *  the shell answers it rather than routing it. */
    const crossRealmCall = (caller: AppSlot, callerId: Uint8Array, id: string, payload: Uint8Array): Promise<Uint8Array> | null => {
        const input = new Uint8Array(callerId.length + payload.length);
        input.set(callerId, 0);
        input.set(payload, callerId.length);
        if (id === SHELL_PROTOCOL) return hostAnswer(caller, payload);
        const slot = apps.get(routes.get(id) ?? "");
        return slot ? slot.entry(input) : null;
    };
    /** The shell's own protocol (`_host`), answered ahead of dispatch. Three ops, and all
     *  three are the same thing: the transport telling the host about something only the
     *  transport can see, on the two edges where the host genuinely holds the other end.
     *
     *  Restricted to the realm that claims `_net`, and structurally rather than by a field
     *  in the payload: `caller` is the slot whose seam this closure was built for, so
     *  there is nothing here to spoof. An ordinary app that declared `_host` reaches this
     *  and is refused by name — the same answer as a protocol nobody claims. */
    const hostAnswer = (caller: AppSlot, payload: Uint8Array): Promise<Uint8Array> => {
        if (routes.get(NET_PROTOCOL) !== appKeyFor(caller.loaded.author, caller.loaded.manifest.app)) {
            return Promise.reject(new Error(`shell: ${SHELL_PROTOCOL} is the transport's, and this realm does not claim ${NET_PROTOCOL}`));
        }
        const nameLen = payload[0];
        const op = dec.decode(payload.slice(1, 1 + nameLen));
        const a = payload.slice(1 + nameLen);
        switch (op) {
            // An inbound request the transport attributed: route it to the app claiming the
            // protocol and hand back its answer. This is `transport/deliver` and the
            // `respond` entrypoint at once — the transport does not await it (it must not;
            // realm-queue.ts) but resumes on the returned promise, which is the same
            // later turn the old `respond` ran on.
            //
            // The shell's own protocols get first refusal (`opts.answer`), which is the
            // §12.10 reservation as a seam rather than as a wrapper around a driver
            // facade that no longer exists. `null` from the hook — and the absent hook —
            // fall through to the routing table, so this is a shell answering an id of
            // its own, never a shell shadowing the apps.
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
    /** Point the socket driver at whatever claims `_net` now, standing one up on first
     *  use. Called after every routing rebuild, so it covers the first transport and every
     *  replacement by the same path — there is no upgrade protocol, because there is
     *  nothing to hand over: the driver holds link ids, addresses and listeners, and all
     *  of those are the node's rather than the outgoing guest's.
     *
     *  A replacement is therefore `attach` again: the incoming guest gets the same config
     *  turn the first one got and the same address book, and redials. Live links do not
     *  survive and cannot — the session keys are in the outgoing guest's private memory
     *  (§4.3), which is what makes the occupant confineable — so an upgrade is a
     *  reconnect, which the record layer's clean-close discipline already covers (§12.6).
     *
     *  The driver is built lazily and torn down when the last claimant goes, so a node
     *  that never admitted a transport bundle holds no socket at all.
     *
     *  **Re-attaching only when the CLAIMANT CHANGED is load-bearing, not an
     *  optimization.** This runs after every routing rebuild — every install and every
     *  uninstall — and `attach` on a driver that already has a transport tears every channel
     *  down, because that is what a replacement means (the outgoing guest's session keys
     *  went with it). Doing it unconditionally would make installing an ORDINARY app
     *  disconnect the node: a browser accepting an offered chat app, or a shell loading
     *  its storage bundle after linking its cohort, would silently lose every live link
     *  and get no redial from a peer that never heard anything. The claim did not move,
     *  so neither should the driver.
     *
     *  The identity compared is the SLOT, not its app key: re-installing the same
     *  (author, app) — an in-place transport upgrade — builds a new slot with a new realm
     *  under the same key, and that realm has never had the config turn. A key comparison
     *  would skip exactly the case the re-attach exists for. */
    let attachedTransport: AppSlot | null = null;
    const retargetTransport = () => {
        const key = routes.get(NET_PROTOCOL);
        const slot = apps.get(key ?? "");
        if (!slot) {
            netHost?.close();
            netHost = null;
            attachedTransport = null;
            return;
        }
        if (netHost && attachedTransport === slot) return;
        attachedTransport = slot;
        netHost ??= new TransportHost({
            identity: platform.identity,
            networkKey: platform.networkKey,
            contactSecret: platform.contactSecret,
            requestDeadlineMs: opts.requestDeadlineMs,
            connsPerPeer: platform.connsPerPeer,
            admitPeers: platform.admitPeers,
            channels: platform.channels,
            listen: platform.listen,
            wsListen: platform.wsListen,
            maxHalfOpenUnverified: opts.transportHalfOpen?.unverified,
            maxHalfOpenPerSource: opts.transportHalfOpen?.perSource,
            maxHalfOpenVerified: opts.transportHalfOpen?.verified,
        });
        // Through the routing rather than at the realm directly, so the driver follows a
        // later claimant without being told about it.
        netHost.attach((p) => {
            const s = apps.get(routes.get(NET_PROTOCOL) ?? "");
            return s ? s.entry(p) : null;
        });
    };
    /** Recompute the whole projection from the installed apps (§12.10). Called on every
     *  install and every uninstall, and never anything narrower — the alternatives are
     *  all wrong in a way a recompute cannot be:
     *
     *  - Adding just the new app's claims would leave an UPDATE that dropped a protocol
     *    from its manifest still serving it, because the old entry pointed at the same
     *    app key and nothing would have cleared it.
     *  - Deleting just the leaving app's claims would leave a protocol an earlier-loaded
     *    app also claims permanently dark, when the honest answer is that the earlier
     *    claimant serves it again.
     *
     *  Order is load order — `apps` is insertion-ordered and an update re-`set`s an
     *  existing key, which keeps its original position — so the LAST app installed wins a
     *  contested id, and an update never jumps ahead of an app loaded after it. Nothing is
     *  stored to make that true; it is the map's own order. */
    const rebuildRoutes = () => {
        routes.clear();
        for (const [key, slot] of apps) {
            for (const proto of slot.loaded.manifest.protocols ?? []) routes.set(proto, key);
        }
        // `_net` is a claim like any other, so the driver follows the same rule the rest
        // of the routing does — including "the last load wins", which is the whole of an
        // in-place transport replacement.
        retargetTransport();
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
        // "Was there anything here": an app is its modules AND its realm, and a
        // guest-only bundle legitimately has no modules at all (§12.4), so counting
        // modules alone would report a successful uninstall as a failure.
        return removed > 0 || slot !== undefined;
    };
    /** Route an inbound request to its app (§12.10): resolve the protocol to the app
     *  claiming it, prepend the authenticated sender, hand it to that app's one entrypoint.
     *
     *  There is no branch on how the app is implemented — every app presents the same
     *  `senderPk ‖ payload` shape and the same single entry, resolved at install
     *  (`entryFor`). The answer is the realm's — a Promise, which the driver already
     *  expects from `RequestHandler` and answers through the `respond` entrypoint on a
     *  later turn rather than inline (transport-host.ts) — the seam an asynchronous
     *  holder needs, since `fs` is async (core/fs.ts). */
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
        // A getter, not a captured value: the slot is filled at load and REPLACED by
        // a handover (§12.6), so a caller reading this field always sees the driver
        // standing now rather than the one standing when it took the reference.
        get transport() { return netHost; },
        fs,
        sodium,
        async loadBundleBlob(blob) {
            const v = verifyBundle(sodium, blob);
            // WHAT THIS BUNDLE REACHES, read off the requires and nothing else. There is
            // no `role` field and there is no second entrypoint: the privileges are
            // exactly the ones its declared names carry in the catalog (§12.5), which the
            // manifest signature already covers and `verifyManifest` has already checked.
            // Restating that as a self-description, or as a choice of method, would be a
            // second place for the same fact to live — and the requires are the one that
            // must be right anyway, because they are what the seam actually wires.
            //
            // An author cannot shed a privilege by declaring one, which is the property
            // the whole scheme exists for: adding `link/open` puts `link` in this set and
            // nothing takes it out, so the derivation is safe in the only direction it can
            // be pushed.
            const privileges: Privilege[] = privilegesOf(v.manifest);
            // ADMISSION — one predicate, one call, one answer (§12.5). Everything a gate
            // needs is read here, once, and handed in: the privileges this bundle
            // reaches, the persisted `(author, app)` high-water mark, and whether this
            // host has written the author key off. The predicate is a pure function of
            // `(bundle, context)`; the ordering constraints — revocation before the
            // consent dialog (a written-off key must never reach a prompt), the
            // coherence gates before the operator is asked about a claim that is not
            // well formed, the downgrade guard before anything landed — are the
            // composition's (`allOf`, `byPrivilege`), stated once at construction.
            //
            // EVERY pure question about this bundle is in there, including the two
            // coherence rules that used to sit out here as inline throws (a privilege is
            // claimed in every half or none, a transport claims no protocol ids). Nothing
            // decides admission beside the predicate — which is what makes "nothing has
            // landed" hold for the whole decision rather than for most of it.
            const ctx: AdmissionContext = {
                privileges,
                highWater: platform.freshnessStore.get(v.author, v.manifest.app),
                revoked: platform.freshnessStore.isRevoked(v.author),
            };
            if (!(await admit(v, ctx)))
                throw new Error(ADMISSION_REJECTED);
            // A transport's load is not done when its modules bind — it is done when its
            // DRIVER stands, below — so its mark is deferred (`deferMark`) and advanced
            // only after. A guest that fails to compile then raises nothing, and the node,
            // still running the transport it had, can roll back to the previous version
            // (§12.4: the mark records the highest version that actually loaded).
            // The transport's mark is deferred: its realm is built eagerly below, so unlike
            // every other app its load can still fail after the modules bind, and a mark
            // raised by a bundle that never ran would brick the rollback (bundle.ts).
            const isTransport = privileges.includes(PRIVILEGE_LINK);
            const loaded = installBundle(host, v, platform.freshnessStore, isTransport);
            const key = appKeyFor(loaded.author, loaded.manifest.app);
            // The app's one inbound entrypoint, resolved here and not per message.
            // `entryFor` closes over the slot, so the slot is built first and its entry
            // attached immediately — nothing can observe the placeholder between the two
            // statements, since neither yields.
            // Extended in place rather than spread into a new object: the holder's timer
            // table reads `slot.realm` off the object `newHolder` returned, so a copy
            // would leave every deadline firing into a slot that never gets a realm.
            const slot: AppSlot = Object.assign(newHolder(loaded), {
                entry: (() => null) as AppEntry,
                isTransport,
            });
            slot.entry = entryFor(slot);
            apps.set(key, slot);
            // The load admits the code AND claims the manifest's protocols (§12.10) — one
            // act, because they were always one intent: nothing installs an app it does not
            // mean to serve. The claim is the author's and signed, so there is no second
            // operator step to forget, no id to retype into a typo whose only symptom is an
            // empty body forever, and no "installed but unrouted" state to be surprised by.
            // Re-projecting (rather than adding this app's ids) is what makes an update that
            // DROPPED a protocol stop serving it.
            rebuildRoutes();
            // The transport's realm is built HERE rather than at its first message, because the
            // node's network has to be up when this returns — `rebuildRoutes` has already
            // pointed the driver at it and sent the config turn. A guest that will not
            // compile therefore fails the LOAD, and the node keeps what it had: the slot
            // is removed and its mark, deliberately deferred above, was never raised.
            if (isTransport) {
                try {
                    await ensureRealm(slot);
                } catch (err) {
                    doUninstall(key);
                    throw err;
                }
                platform.freshnessStore.set(loaded.author, loaded.manifest.app, v.manifest.version);
            }
            // An app's marks were already advanced inside installBundle — nothing can fail
            // between that return and here.
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
        async runGuest(entry, payload, appKey) {
            const slot = appKey ? apps.get(appKey) : onlyApp();
            if (!slot)
                throw new Error(`shell: no app '${appKey}' loaded`);
            const r = await ensureRealm(slot);
            const call = r.call(entry, payload);
            inFlight = inFlight.then(() => call, () => call).catch(() => { }) as Promise<void>;
            return call;
        },
        dispatch: doDispatch,
        /** Pre-create every app's realm so the first routed frame does not pay realm
         *  construction. There is no dispatch sink to wire any more: an inbound frame
         *  reaches this shell as the transport's own `_host` deliver op, which `hostAnswer`
         *  routes — so a node is serving from the moment a transport bundle is loaded,
         *  and this is the warm-up rather than the switch. */
        async serve() {
            for (const slot of apps.values()) {
                await ensureRealm(slot);
            }
            if (!netHost)
                throw new Error("shell: the transport bundle is not loaded — serve() needs it");
        },
        close() {
            netHost?.close();
            netHost = null;
            const dispose = () => {
                for (const slot of apps.values()) {
                    disposeSlot(slot);
                }
                apps.clear();
                routes.clear();
            };
            inFlight.then(dispose, dispose);
        },
    };
}
