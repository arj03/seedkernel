// The platform-neutral shell core — the §12.9 "move one level up". Everything that
// standing a node up involves EXCEPT the parts that genuinely vary by target lives
// here: the handler table's owner, the cap-bridge wiring, the preamble assembly, the
// realm's lifecycle, the bundle load order, the transport slot, and the inbound
// dispatch. A target supplies the platform seam — { sodium, identity, kernel, fs?,
// freshnessStore, channels?, listen?, wsListen?, createRealm? } — exactly like the
// transport driver takes a ChannelFactory, and gets back a fully wired Shell.
//
// This is the ONE assemble path, and the assembly ORDER is the point: it is the last
// thing two hosts could disagree about, so no target restates it.
//
//   main.ts       → boot()         → KernelHost + NodeFs + FileFreshnessStore + NodeChannelFactory + safe-js → createShell()
//   browser       → chat-shell.js  → KernelHost + RtcNetwork-style openLink edges + sessionStorage freshness  → createShell()
//   native        → native-shim.ts → Go handler table + Go Fs + Go channels + Go realm                → createShell()
//   seedstore     → StorageNode    → { MemoryFs, LoopbackChannels, FreshnessMarks }                  → createShell() + loadBundle(seedstore.skb)
//
// installWasmHandler is not public API on the Shell and there is no raw-bind path — the
// only way code lands is via a signed bundle (§12.4), making the §3.1 claim structurally
// true instead of true-by-convention.
import { denyAll } from "./policy.js";
import { kernelNameFor, appKeyFor, appScopeFor, handlesOf, entryModuleOf, verifyBundle, installBundle, type BundleCrypto, type BundleHost, type FreshnessStore, type LoadedBundle, type VerifiedBundle } from "./bundle.js";
import { createCapBridge, capPreamble, bundlePreamble, opsForCaps, appSignScope, transportSignScope, type CapSodium } from "./cap-bridge.js";
import { Bindings } from "./bindings.js";
import { TransportHost, type HostTransport } from "./transport-host.js";
import { scopedFs, type Fs } from "../core/fs.js";
import { toHex, fromHex } from "../core/util.js";
import { type SafeRealm, type SafeRealmBridge } from "./safe-js.js";
import { type Network, type PeerId } from "../core/net.js";
import { type ChannelFactory } from "../core/socket-seam.js";

/** The crypto surface the shell needs: manifest verification + genesis hashing
 *  (BundleCrypto) plus the cap-bridge crypto ops (CapSodium). Any sumo libsodium
 *  build satisfies both. */
export type ShellSodium = BundleCrypto & CapSodium;

/** How a target creates the confined realm a guest runs in (§12.3). The JS platform's
 *  factory is `createSafeRealm` (safe-js.ts: QuickJS-over-wasm, driven by
 *  quickjs-emscripten's job pump); the native target's is a second quickjs-ng realm
 *  driven by Go's event loop (native/guest.go). Both honor the same contract — one
 *  `call`, which may await, and invocations serialized per realm — so the shell drives
 *  either without knowing which it holds. */
export type RealmFactory = (opts: {
    source: string;
    bridge: SafeRealmBridge;
    memoryLimitBytes?: number;
    /** Budget of guest *execution* time per entrypoint invocation, in ms. Omitted ⇒ the
     *  factory's own default (safe-js: 5s). Both resource bounds cross this seam, so a
     *  guard a factory implements is one the shell can actually reach — `deadlineMs`
     *  existed in safe-js before this field did and was therefore dead code, since the
     *  shell is the only caller and had no way to pass it. */
    deadlineMs?: number;
}) => Promise<SafeRealm>;

/** The handler table as exposed by the Shell — everything a caller needs to
 *  reach installed handlers, WITHOUT installWasmHandler AND WITHOUT
 *  removeHandler. The bind is the bundle loader's job (§12.4); the unbind
 *  is the shell's uninstall method (§12.5). Neither install nor remove is a
 *  public host method. */
export interface KernelTable {
    callHandler(name: string, payload: Uint8Array): Uint8Array | null;
    isBound(name: string): boolean;
}

/** The §3 handler table as the shell uses it: the two install powers a bundle load
 *  needs (`BundleHost`), plus reaching and releasing what landed. A platform
 *  primitive, not shell logic — `KernelHost` is the JS implementation over
 *  `WebAssembly`, and the native target's is Go's wazero map behind its byte bridge
 *  (§12.9). The table is the same contract either way; only who owns the instances
 *  differs. */
export interface KernelBackend extends BundleHost, KernelTable {
    /** Remove every handler whose name starts with `prefix`, returning how many went.
     *  One pass is all `uninstall` needs: every kernel name of an app shares its app
     *  key as a prefix (§5.1). */
    removePrefix(prefix: string): number;
}

/** The platform seam — everything the shell needs that varies by target.
 *  `fs` is optional: handler-only shells (the browser chat-shell) need no
 *  filesystem backend. `createRealm` is optional for the same reason — absent, the
 *  shell still verifies, admits and installs a bundle's modules, but running or
 *  serving a guest throws rather than silently doing nothing. `livePeers` feeds the
 *  NET_PEERS cap — the transport owns connectivity, the shell just passes the
 *  closure through to the cap-bridge.
 *
 *  The transport itself is now a signed bundle (phase 3): the platform supplies the
 *  SOCKET seam (`channels`, `listen`/`wsListen`, the network key and contact
 *  secret) and the shell stands the driver up when a bundle claiming the transport
 *  role is admitted. There is no `network` member to hand in any more — the driver
 *  IS the network. */
export interface ShellPlatform {
    sodium: ShellSodium;
    /** The CHANNEL keypair — its public half is this node's peer id. */
    identity: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    /** The GUEST signing keypair (§12.9), a sibling subkey. The cap-bridge SIGN op uses
     *  this and nothing else, so a guest can never elicit a channel signature. Defaults to
     *  `identity` for hosts that supply a single keypair. */
    guestIdentity?: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    /** The handler table this shell binds bundle modules into (§3). */
    kernel: KernelBackend;
    fs?: Fs;
    freshnessStore: FreshnessStore;
    createRealm?: RealmFactory;
    now?: () => number;
    livePeers?: () => PeerId[];
    /** OPTIONAL network key — which network this node belongs to. An isolation
     *  boundary, not a gate (§12.6); absent ⇒ the public network. Feeds both the
     *  transport guest's INIT and the CHANNEL_SIGN root check. */
    networkKey?: Uint8Array;
    /** OPTIONAL contact secret for THIS node — 32 bytes of full entropy, published
     *  with our address; the gate a caller must produce before msg1 opens. Absent ⇒
     *  an open node. Per node, never per deployment (§12.6.3). */
    contactSecret?: Uint8Array;
    /** The socket seam: TCP/WS dialing and listening behind the RawChannel shape
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
    /** Whitelist gate for the transport slot: called with a signature-verified peer
     *  key during the handshake and again before a link is routed. Absent ⇒ the
     *  node admits every peer that completes the handshake. */
    admitPeer?: (pk: Uint8Array) => boolean;
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
    timeoutMs?: number;
    /** Operator-supplied app config, merged *over* the bundle manifest's `config`
     *  into the guest's `const APP = …`. Opaque to the shell. */
    config?: Record<string, string | number>;
    /** QuickJS heap limit for the guest realm, in bytes. Omitted ⇒ the safe-js
     *  default (64 MiB). A target that streams large windows through the guest raises
     *  it to run without the realm OOMing (seedstore's `realmMemoryBytes`). */
    realmMemoryBytes?: number;
    /** Budget of guest execution time per entrypoint invocation, in ms. Omitted ⇒ the
     *  realm factory's default (5s, §16.1). Counts time the guest is *running*, not time
     *  it spends parked on a host bridge, so it bounds a wedged guest without penalising
     *  one legitimately awaiting the network. `Infinity` disables it.
     *
     *  This is the operator's number, not the author's: unlike the handler memory ceiling
     *  (§4.3), which a bundle declares in its signed manifest, how long this node is
     *  willing to spend on one message is a property of the deployment. */
    guestDeadlineMs?: number;
    /** Half-open budgets for the transport slot: concurrent links that have not
     *  yet proven whitelist membership (unverified), per source address, and proven-
     *  but-mid-handshake (verified). Defaults match the transport bundle's
     *  (1024 / 8 / 256); tests shrink them. Enforced inside the transport guest. */
    transportHalfOpen?: {
        unverified?: number;
        perSource?: number;
        verified?: number;
    };
    /** The absolute backstop for the transport's requests, as a multiple of
     *  timeoutMs (net.ts §12.6). Default 50. */
    transportMaxStallWindows?: number;
}

export interface Shell {
    /** The handler table: callHandler to reach installed handlers, isBound to
     *  check occupancy. installWasmHandler is NOT on this interface — code lands
     *  only via loadBundleBlob (§12.4). */
    host: KernelTable;
    /** Protocol bindings (§12.10): which app handles which protocol. */
    bindings: Bindings;
    /** The transport bundle's driver — the node's Network. Absent until a bundle
     *  claiming the transport role is admitted; a shell without one has no net. */
    net: Network;
    /** The request/response face of the same driver (the old Transport shape). */
    transport: HostTransport;
    /** Filesystem backend. Absent for handler-only shells. */
    fs?: Fs;
    sodium: ShellSodium;
    /** Load a signed bundle blob: verify the manifest, run the admission predicate,
     *  integrity-check + install the modules, and return the guest source. This is
     *  the §12.4 load order — the ONE install path. A bundle claiming the transport
     *  role additionally stands the transport driver up over its guest program. */
    loadBundleBlob(blob: Uint8Array): Promise<LoadedBundle>;
    /** Uninstall an app: remove every kernel handler derived from `appKey`,
     *  drop every protocol binding for it, and dispose the confined realm if
     *  this was its last app. Returns true if any handlers were removed.
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
     *  cap-bridge over the kernel's primitives. `appKey` defaults to the
     *  only loaded app; throws when more than one is loaded and no key is
     *  given. Throws for handler-only bundles (no guest source). */
    runGuest(entry: string, payload: Uint8Array, appKey?: string): Promise<Uint8Array>;
    /** Dispatch inbound request to the right app via protocol bindings (§12.10).
     *  For a guest app: calls the confined realm's `handle` synchronously.
     *  For a handler-only app: calls the kernel handler with senderPk ‖ payload.
     *  Returns the response bytes, or null if no bound app handles the protocol. */
    dispatch(from: PeerId, proto: string, payload: Uint8Array): Uint8Array | null;
    /** Wire transport.onRequest to the shell's dispatch. After this, every
     *  inbound frame resolves through the bindings table to its app (§12.10). */
    serve(): Promise<void>;
    close(): void;
}

// Re-export the admission predicate constructors so a target that gates admission
// on consent (the browser) or on which bundle it was handed (a StorageNode) can
// reach them from the same module it gets createShell from. KernelHost rides along
// for the same reason: the JS platforms all hand it in as their `kernel`, and a
// re-export keeps that a one-line seam rather than a second import.
export { denyAll, admitAll, authorAllowlist, roleAllowlist, allOf, anyOf, policyFromJson } from "./policy.js";
export { Bindings } from "./bindings.js";
export { KernelHost } from "../core/kernel-host.js";
/** Assemble the platform-neutral shell. Every target calls this instead of
 *  re-implementing the kernel host, cap-bridge wiring, preamble assembly, realm
 *  creation, and transport routing. */
interface AppSlot {
  loaded: LoadedBundle;
  realm: SafeRealm | null;
  handleName: string;
}

interface RoleSlot {
  loaded: LoadedBundle;
  realm: SafeRealm | null;
}

export function createShell(opts: CreateShellOptions & {
    platform: ShellPlatform;
}): Shell {
    const { platform } = opts;
    const sodium = platform.sodium;
    const host = platform.kernel;
    const bindings = new Bindings();
    const admit = opts.admit ?? denyAll;
    const peerId = toHex(platform.identity.publicKey);
    const apps = new Map();
    const roles = new Map();
    const roleKeys = new Map();
    /** The transport driver, standing once a bundle claiming the transport role is
     *  admitted. The app bridges and the shell's net/transport fields read this
     *  indirection, so the shell can be assembled before any bundle loads. */
    let netHost: TransportHost | null = null;
    const noTransport = (what: string): never => {
        throw new Error(`shell: ${what} — the transport bundle is not loaded (admit a signed bundle with role "transport" first)`);
    };
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
    /** The confined realm for `slot`, created lazily on first use through the
     *  platform's factory. Both roles share it and both reach it the same way — the
     *  initiator (`runGuest`) and the holder (`dispatch`) each `realm.call`, and the
     *  realm serializes them, so one runs to completion before the next begins. Lazy
     *  because the JS factory pulls in a heavy engine, and because a node may serve for
     *  a long time before its first guest call. */
    const ensureRealm = async (slot: AppSlot | RoleSlot) => {
        if (slot.realm)
            return slot.realm;
        if (!platform.createRealm) {
            throw new Error("shell: this platform supplies no createRealm — it can install handler modules but not run a guest");
        }
        slot.realm = await platform.createRealm({
            source: guestFullSource(slot.loaded),
            bridge: buildBridge(slot.loaded, null),
            memoryLimitBytes: opts.realmMemoryBytes,
            deadlineMs: opts.guestDeadlineMs,
        });
        return slot.realm;
    };
    /** The bridge for one admitted bundle. `driver` is passed ONLY for the bundle
     *  claiming the transport slot, and is what wires the three seams no app holds: the
     *  raw net capability (sockets), the platform's timers, and the sink the slot
     *  reports its structured output through. Nothing else can reach a descriptor, at
     *  any point in the process's life, because nothing else is ever handed one
     *  (README §1, capability-by-non-wiring). */
    const buildBridge = (b: LoadedBundle, driver: TransportHost | null) => {
        const caps = new Set(b.manifest.guest?.caps ?? []);
        const modMap = Object.fromEntries(b.manifest.modules.map((m) => [m.name, kernelNameFor(b.author, b.manifest.app, m.name)]));
        return createCapBridge({
            rawNet: driver?.rawNet(),
            timers: driver?.timerBackend(),
            transportSink: driver?.sink(),
            sodium: platform.sodium,
            identity: platform.guestIdentity ?? platform.identity,
            callHandler: (name, p) => host.callHandler(name, p),
            transport: netHost ?? undefined,
            peers: platform.livePeers ?? (() => netHost ? netHost.linkedPeers() : []),
            // Scoped to this app key, so `fs` grants reach over this app's own keyspace and
            // not the node's (fs.ts). Two admitted apps can no longer read, enumerate or
            // delete each other's data, which brings `fs` into line with the structural
            // ownership kernel names already have (§5.1).
            fs: caps.has("fs") && platform.fs
                ? scopedFs(platform.fs, appScopeFor(platform.sodium, b.author, b.manifest.app))
                : undefined,
            now: platform.now ?? (() => Date.now()),
            allowedOps: opsForCaps(caps),
            // What SIGN signs under is chosen HERE, by the slot the bundle occupies — the one
            // place that knows it (phase 3a, task 10). The transport slot signs handshake
            // transcripts under DOMAIN_channel with the node's channel key; every ordinary app
            // signs under DOMAIN_guest with the guest subkey, in its own bundle's scope. The
            // bridge prefixes and never parses, so neither can produce the other's signature
            // and no op signs raw bytes.
            signScope: b.manifest.role === "transport"
                ? transportSignScope(platform.identity, platform.networkKey)
                : appSignScope(platform.guestIdentity ?? platform.identity, b.author, b.manifest.app),
            modules: modMap,
        });
    };
    const guestFullSource = (b: LoadedBundle) => capPreamble()
        + bundlePreamble({
            app: b.manifest.app,
            author: b.author,
        })
        + `const APP = ${JSON.stringify({ ...(b.manifest.guest?.config ?? {}), ...(opts.config ?? {}) })};\n`
        + b.guestSource;
    const hasGuest = (b: LoadedBundle) => b.guestSource.length > 0;
    /** Stand a transport driver up over an admitted transport bundle's realm.
     *  The driver is the shell's Network: it answers the guest's DIAL actions
     *  through the platform's socket seam, and its request/response face is what
     *  every app's NET_SEND reaches.
     *
     *  It does NOT publish itself as `netHost` — the caller does, once it has decided
     *  what to do with whatever was there before. That separation is what makes
     *  replacing a standing occupant safe: this function can fail without the node
     *  losing the transport it already had. */
    const standTransport = async (slot: AppSlot | RoleSlot) => {
        if (!platform.createRealm) {
            throw new Error("shell: this platform supplies no createRealm — cannot run the transport bundle");
        }
        // The driver is built BEFORE the realm and attached after, because the realm's
        // bridge resolves the slot's ops here: the guest reaches sockets, timers and the
        // sink through the ordinary seam, so the object serving them has to exist first.
        // `attach` is what sends the one config turn.
        const driver = new TransportHost({
            identity: platform.identity,
            networkKey: platform.networkKey,
            contactSecret: platform.contactSecret,
            timeoutMs: opts.timeoutMs ?? 2000,
            connsPerPeer: platform.connsPerPeer,
            admitPeer: platform.admitPeer,
            channels: platform.channels,
            listen: platform.listen,
            wsListen: platform.wsListen,
            maxHalfOpenUnverified: opts.transportHalfOpen?.unverified,
            maxHalfOpenPerSource: opts.transportHalfOpen?.perSource,
            maxHalfOpenVerified: opts.transportHalfOpen?.verified,
            maxStallWindows: opts.transportMaxStallWindows,
        });
        slot.realm = await platform.createRealm({
            source: guestFullSource(slot.loaded),
            bridge: buildBridge(slot.loaded, driver),
            memoryLimitBytes: opts.realmMemoryBytes,
            deadlineMs: opts.guestDeadlineMs,
        });
        driver.attach(slot.realm);
        return driver;
    };
    /** Put an admitted transport bundle in the slot, replacing a standing occupant if
     *  there is one (§12.6).
     *
     *  The ordering is the whole of it, and each step exists because the other order
     *  is wrong:
     *
     *  1. Read the outgoing driver's host-side state **before** anything is torn down.
     *  2. Build the incoming realm and driver **while the old one is still serving**, so
     *     a guest that fails to compile leaves the node with the transport it had rather
     *     than with neither.
     *  3. Only then close the outgoing driver — which is what releases the listening
     *     port the incoming one is about to re-bind — and dispose its realm.
     *  4. Adopt: re-listen on the same port, re-wire the dispatch sink and peer hooks,
     *     re-seed the address book, and redial.
     *
     *  Live links do not survive, and cannot: session state is in the outgoing guest's
     *  private memory (see `TransportHandover`). An upgrade is a reconnect. */
    const installTransport = async (slot: AppSlot | RoleSlot) => {
        const outgoing = netHost;
        const state = outgoing?.handover() ?? null;
        const incoming = await standTransport(slot);
        if (outgoing) {
            outgoing.close();
            roles.get("transport")?.realm?.dispose();
        }
        netHost = incoming;
        if (state)
            await incoming.adopt(state);
    };
    const doUninstall = (appKey: string) => {
        // The transport slot is not an app, but it IS uninstallable: dropping it
        // stops the node's net.
        const roleKey = roleKeys.get("transport");
        if (roleKey === appKey) {
            netHost?.close();
            netHost = null;
            const slot = roles.get("transport");
            slot?.realm?.dispose();
            roles.delete("transport");
            roleKeys.delete("transport");
            return true;
        }
        const removed = host.removePrefix(appKey + ":");
        bindings.removeApp(appKey);
        const slot = apps.get(appKey);
        if (slot) {
            slot.realm?.dispose();
            apps.delete(appKey);
        }
        return removed > 0;
    };
    const doDispatch = (from: PeerId, proto: string, payload: Uint8Array) => {
        const key = bindings.boundApp(proto);
        if (!key)
            return null;
        const slot = apps.get(key);
        if (!slot)
            return null;
        if (hasGuest(slot.loaded)) {
            if (!slot.realm)
                return null; // realm not yet created — serve() must be called first
            const senderBytes = fromHex(from);
            const input = new Uint8Array(senderBytes.length + payload.length);
            input.set(senderBytes, 0);
            input.set(payload, senderBytes.length);
            // A Promise, which the driver already expects from `RequestHandler`: it
            // answers through the `respond` entrypoint on a later turn, never inline
            // (transport-host.ts). That was designed for exactly this — a holder that
            // reads fs now awaits, because fs is async (core/fs.ts).
            return slot.realm.call("handle", input);
        }
        if (!slot.handleName)
            return null;
        const senderBytes = fromHex(from);
        const input = new Uint8Array(senderBytes.length + payload.length);
        input.set(senderBytes, 0);
        input.set(payload, senderBytes.length);
        return host.callHandler(slot.handleName, input);
    };
    return {
        host,
        bindings,
        // Both fields are the transport driver, reached through the indirection so
        // the shell can be assembled before any bundle loads.
        get net() { return netHost ?? { endpoint: () => noTransport("net is unavailable") }; },
        get transport() {
            return netHost ?? {
                peerId,
                request: () => noTransport("request"),
                send: () => noTransport("send"),
                onRequest: () => noTransport("onRequest"),
                close: () => noTransport("close"),
            };
        },
        fs: platform.fs,
        sodium,
        async loadBundleBlob(blob) {
            const v = verifyBundle(sodium, blob);
            // Revocation before `admit`, not just inside installBundle. The predicate is
            // where an interactive shell puts its consent dialog (§12.4), so asking it
            // first would show a user the author and metadata of a bundle this host has
            // already decided to refuse, take their approval, and only then fail. A written-
            // off key should never reach the prompt. The check in installBundle stays as the
            // backstop for callers that reach it another way.
            if (platform.freshnessStore.isRevoked(v.author)) {
                throw new Error(`bundle: author ${toHex(v.author)} is revoked on this host — refusing ${v.manifest.app} v${v.manifest.version}`);
            }
            const ok = await admit(v);
            if (!ok)
                throw new Error("bundle: rejected by admission predicate");
            // A slot occupant's load is not "done" when its modules bind — the driver
            // must STAND — so its mark is deferred (installBundle `deferMark`) and
            // advanced only after installTransport below: a transport guest that fails
            // to compile raises nothing, and the node — still running the transport it
            // had — can still roll back to the previous version. The mark must record
            // the highest version that actually loaded (README §12.4).
            const loaded = installBundle(host, v, platform.freshnessStore, v.manifest.role !== undefined);
            const key = appKeyFor(loaded.author, loaded.manifest.app);
            const advanceMark = (): void => {
                platform.freshnessStore.set(loaded.author, loaded.manifest.app, v.manifest.version);
            };
            // A slot occupant is not an app: it binds no protocol ids (its handles
            // would claim a dispatch the runtime itself performs), receives no inbound
            // dispatch, and `transport` — the one slot today — is stood up as the
            // driver the rest of the shell consumes.
            if (v.manifest.role !== undefined) {
                const role = v.manifest.role;
                const slot = { loaded, realm: null };
                // The slot maps are written AFTER the driver is standing, not before: on a
                // failed upgrade the node keeps both the transport it had and the author key
                // that `revoke` needs in order to find what that key landed.
                if (role === "transport")
                    await installTransport(slot);
                roles.set(role, slot);
                roleKeys.set(role, key);
                advanceMark();
                return loaded;
            }
            bindings.autoBind(key, handlesOf(loaded.manifest));
            // Which module receives inbound traffic is the manifest's `entry`, not the first
            // array element (§12.10). entryModuleOf throws on an ambiguous manifest, so the
            // load fails loudly rather than binding traffic to an arbitrary module.
            const entry = entryModuleOf(loaded.manifest);
            const handleName = entry ? kernelNameFor(loaded.author, loaded.manifest.app, entry) : "";
            apps.set(key, { loaded, realm: null, handleName });
            // An app's marks were already advanced inside installBundle — nothing can fail
            // between that return and here — so the app path advances exactly as before.
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
            // Slot occupants too: a revoked transport author must lose the slot, not just
            // the apps. The driver is the slot's face — close it and the node has no net.
            for (const [role, appKey] of [...roleKeys]) {
                if (appKey.startsWith(hex + ":")) {
                    if (role === "transport") {
                        netHost?.close();
                        netHost = null;
                        roles.get("transport")?.realm?.dispose();
                        roles.delete("transport");
                    }
                    roleKeys.delete(role);
                    gone.push(appKey);
                }
            }
            for (const appKey of [...apps.keys()]) {
                // Every kernel name of an app begins with its author (§5.1), so one prefix
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
            if (!hasGuest(slot.loaded))
                throw new Error("shell: no guest source — this is a handler-only bundle");
            const r = await ensureRealm(slot);
            const call = r.call(entry, payload);
            inFlight = inFlight.then(() => call, () => call).catch(() => { }) as Promise<void>;
            return call;
        },
        dispatch: doDispatch,
        async serve() {
            for (const slot of apps.values()) {
                if (hasGuest(slot.loaded))
                    await ensureRealm(slot);
            }
            if (!netHost)
                throw new Error("shell: the transport bundle is not loaded — serve() needs it (admit a bundle with role \"transport\")");
            netHost.onRequest((from, proto, payload) => {
                return doDispatch(from, proto, payload);
            });
        },
        close() {
            netHost?.close();
            netHost = null;
            const dispose = () => {
                for (const slot of apps.values()) {
                    slot.realm?.dispose();
                }
                apps.clear();
                for (const slot of roles.values()) {
                    slot.realm?.dispose();
                }
                roles.clear();
            };
            inFlight.then(dispose, dispose);
        },
    };
}
