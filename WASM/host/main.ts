// seedkernel-shell — the NODE platform (README §12).
//
// `bootRuntime()` assembles a node out of this platform's parts — `NodeFs` on a data
// directory, a `node:net` channel factory, a file-backed freshness store — and hands them
// to the shared `bootShell`, which is the assembly (§12.9). It knows nothing about any app:
// everything arrives as a signed bundle (§12.4) whose author must clear the policy gate.
//
// The operator's side — flags, defaults, boot sequence, console lines — is `cli.ts`, which
// every target runs; `main-node.ts` binds it to this platform.
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { loadCrypto } from "./crypto-node.js";
import { policyFromJson } from "./policy.js";
import { FreshnessMarks, freshnessPathFor } from "./bundle.js";
import { NodeChannelFactory } from "./net-node.js";
import { NodeFs } from "./fs-node.js";
import { bootShell, type AppHandle, type LoadBundleOptions, type Shell as CoreShell, type ShellSodium } from "./shell-core.js";
import { type ChannelFactory } from "../core/socket-seam.js";
import type { Keypair } from "../core/subkeys.js";
import { type PeerId } from "../core/socket-seam.js";
import { type Fs } from "../core/fs.js";
import type { NodeRuntime as CliNodeRuntime } from "./cli.js";

export interface ShellOptions {
    /** Policy file contents (policy.ts). Omit ⇒ deny-all: the node boots and serves but
     *  accepts no installs. */
    policyJson?: string;
    /** Directory backing the fs.* capability. */
    dir: string;
    /** This node's keypair (README §12.6) — the derived channel keypair, whose public
     *  half is the peer id and the node's one identity (§12.9). */
    identity: Keypair;
    /** Optional deployment secret (§12.6.3). */
    contactSecret?: Uint8Array;
    listen?: {
        host: string;
        port: number;
    };
    wsListen?: {
        host: string;
        port: number;
    };
    /** Optional network key — which network this node belongs to (an isolation
     *  boundary, not a gate; §12.6). Absent ⇒ the public network. */
    networkKey?: Uint8Array;
    /** The socket seam the transport driver dials and listens through. Defaults to
     *  a NodeChannelFactory on listen/wsListen. */
    channels?: ChannelFactory;
    /** The signed transport bundle blob, defaulting to the artifact's own. This blob is
     *  what the node's transport author PIN is derived from, so it is how an operator runs
     *  a transport other than the shipped one; the policy must additionally grant that
     *  author the `link` privilege (never the plain `authors` list). A shell without an
     *  admitted transport bundle has no network. */
    transportBundle?: Uint8Array;
    /** Default per-request deadline in ms — how long one net request may take before
     *  it settles as unreachable, for a caller that names none of its own (§12.6). */
    requestDeadlineMs?: number;
    /** Budget of guest *execution* time per entrypoint invocation, in ms (§12.3). Counts
     *  time the guest is running, not time parked on a host seam, so it bounds a wedged
     *  guest without penalising one awaiting the network. `Infinity` disables it. Threaded
     *  through to the shell because a bound no target can set is a bound nobody has. */
    guestDeadlineMs?: number;
    /** QuickJS heap cap for the guest realm, in bytes (§12.3). Omitted ⇒ the 64 MiB
     *  default. Raise it for an app that streams large windows through the guest. */
    realmMemoryBytes?: number;
}

/** The Node-side Shell — the platform-neutral CoreShell plus a file-backed
 *  `loadBundle` and a guaranteed `fs` (Node always has a filesystem). */
export interface Shell extends CoreShell {
    fs: Fs;
    /** Load a signed bundle *file*: read it from disk then delegate to
     *  loadBundleBlob (§12.4). This is the Node convenience wrapper;
     *  cross-platform callers use loadBundleBlob directly. */
    loadBundle(file: string, opts?: LoadBundleOptions): Promise<AppHandle>;
}

/** The CLI's runtime pair, narrowed to this platform's shell — one declaration of the
 *  shape, so `standUp` returning it stays a compile-time fact rather than a coincidence. */
export interface NodeRuntime extends CliNodeRuntime {
    shell: Shell;
}

/** A `FreshnessStore` backed by one JSON file (`{ marks, revoked }`), kept OUTSIDE the
 *  guest-writable fs directory so a `fs`-capable guest cannot tamper with its own mark or
 *  the dead-key set beside it (§12.5). An operator rolls back a mark, or un-revokes a key,
 *  by editing this file out of band. The rules live in `FreshnessMarks` (bundle.ts); this
 *  adds only the Node persistence seam. */
export class FileFreshnessStore extends FreshnessMarks {
    path;
    constructor(path: string) {
        let json = null;
        try {
            json = readFileSync(path, "utf8");
        }
        catch { /* absent/unreadable ⇒ start empty (−∞ for every key) */ }
        super(json);
        this.path = path;
    }
    persist(json: string): void {
        // Temp + rename, because a bare writeFileSync truncates in place: a crash mid-write
        // leaves truncated JSON, which the constructor reads as "start empty" — every
        // downgrade mark silently discarded on the next boot (§12.4).
        const tmp = `${this.path}.${process.pid}.tmp`;
        writeFileSync(tmp, json);
        renameSync(tmp, this.path);
    }
}
// The realm factory (§12.3) is not stated here: bootShell's default IS the lazy safe-js
// import this platform wants — the engine is heavy, so it loads on the first realm — and
// a second copy of it would be the drift the assembly exists to remove.
/** Assemble the runtime on Node: build the platform seam, hand it to the shared
 *  `bootShell` — which admits the transport bundle, the signed program that IS the node's
 *  network (§12.6) — then wrap the core shell with the file-backed `loadBundle`. */
export async function bootRuntime(opts: ShellOptions): Promise<NodeRuntime> {
    const sodium = await loadCrypto();
    // ── Node platform seam ─────────────────────────────────────────────────────
    const fs = new NodeFs(opts.dir);
    const freshness = new FileFreshnessStore(freshnessPathFor(opts.dir));
    // Everything a boot can fail on — a bundle that does not verify, a listener whose
    // port is taken — happens inside bootShell, which tears down what it stood up when
    // it throws, so this function has no partial state to clean.
    const { shell: core, transport } = await bootShell({
        sodium: sodium as unknown as ShellSodium,
        identity: opts.identity,
        // The node's network (§12.6) — an isolation boundary, so it must reach BOTH the
        // adapter bootShell constructs and the shell's link signing scope. One field,
        // one place, because a node that forwards it to only one of the two is a node
        // whose links sign under a network it is not on.
        networkKey: opts.networkKey,
        fs,
        freshnessStore: freshness,
        transport: {
            contactSecret: opts.contactSecret,
            requestDeadlineMs: opts.requestDeadlineMs,
            channels: opts.channels ?? new NodeChannelFactory(),
            listen: opts.listen,
            wsListen: opts.wsListen,
        },
        transportBundle: opts.transportBundle,
        admit: policyFromJson(opts.policyJson),
        guestDeadlineMs: opts.guestDeadlineMs,
        realmMemoryBytes: opts.realmMemoryBytes,
    });
    // ── Node wrapper: add file-backed loadBundle ────────────────────────────────
    const shell: Shell = {
        resolve: core.resolve,
        routes: core.routes,
        // This platform always supplies an fs (Node always has a filesystem), so the
        // optional seam member is non-null here.
        fs: core.fs!,
        sodium: core.sodium,
        loadBundleBlob: core.loadBundleBlob,
        uninstall: core.uninstall,
        revoke: core.revoke,
        async loadBundle(file, loadOpts) {
            return core.loadBundleBlob(new Uint8Array(readFileSync(file)), loadOpts);
        },
        invoke: core.invoke,
        dispatch: core.dispatch,
        close() { core.close(); },
    };
    return { shell, transport };
}

