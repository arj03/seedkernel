// seedkernel-shell — the NODE platform (README §12).
//
// `bootNodeShell()` assembles a node out of this platform's parts — `NodeFs` on a data
// directory, a `node:net` channel factory, a file-backed freshness store — and hands them
// to the shared `bootShell`, which is the assembly (§12.9). It knows nothing about any app:
// everything arrives as a signed bundle (§12.4) whose author must clear the policy gate.
//
// The operator's side — flags, defaults, boot sequence, console lines — is `cli.ts`, which
// every target runs; `main-node.ts` binds it to this platform.
import { readFileSync } from "node:fs";
import { loadCrypto } from "./crypto-node.js";
import { policyFromJson } from "./policy.js";
import { FreshnessMarks, freshnessPathFor } from "./bundle.js";
import { NodeChannelFactory } from "./net-node.js";
import { NodeFs, writeFileAtomic } from "./fs-node.js";
import { bootShell, type AppHandle, type LoadBundleOptions, type Shell as CoreShell, type ShellSodium } from "./shell-core.js";
import { type ChannelFactory } from "../core/socket-seam.js";
import { type Fs } from "../core/fs.js";
import { errMessage } from "../core/util.js";
import type { NodeRuntime as CliNodeRuntime, NodeSetup } from "./cli.js";

/** What booting a node on THIS platform takes: everything the operator flow already reads
 *  from flags (`NodeSetup`, cli.ts), plus the one seam only a caller inside the process can
 *  hand over. Extending rather than restating it is what keeps `standUp` a pass-through. */
export interface NodeShellOptions extends NodeSetup {
    /** The socket seam the transport driver dials and listens through. Defaults to
     *  a NodeChannelFactory on listen/wsListen. */
    channels?: ChannelFactory;
}

/** The Node-side Shell — the platform-neutral CoreShell plus a file-backed
 *  `loadBundle` and a guaranteed `fs` (Node always has a filesystem). */
export interface NodeShell extends CoreShell {
    fs: Fs;
    /** Load a signed bundle *file*: read it from disk then delegate to
     *  loadBundleBlob (§12.4). This is the Node convenience wrapper;
     *  cross-platform callers use loadBundleBlob directly. */
    loadBundle(file: string, opts?: LoadBundleOptions): Promise<AppHandle>;
}

/** The CLI's runtime pair, narrowed to this platform's shell — one declaration of the
 *  shape, so `standUp` returning it stays a compile-time fact rather than a coincidence. */
export interface NodeShellRuntime extends CliNodeRuntime {
    shell: NodeShell;
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
        catch (e) {
            const code = (e as NodeJS.ErrnoException)?.code;
            if (code !== "ENOENT") {
                throw new Error(`freshness store: cannot read ${path}: ${errMessage(e)}`, { cause: e });
            }
            // A genuine missing file is the only first-boot case.
        }
        super(json);
        this.path = path;
    }
    persist(json: string): void {
        // Atomic (fs-node.ts): truncated JSON is what the constructor reads as "start
        // empty" — every downgrade mark silently discarded on the next boot (§12.4).
        writeFileAtomic(this.path, json);
    }
}
// The realm factory (§12.3) is deliberately not stated here: bootShell's default IS the
// lazy safe-js import this platform wants (the engine is heavy, so it loads on the first
// realm), and a second copy of it would be the drift the assembly exists to remove.
/** Assemble the runtime on Node: build the platform seam, hand it to the shared
 *  `bootShell` — which admits the transport bundle, the signed program that is the node's
 *  network (§12.6) — then wrap the core shell with the file-backed `loadBundle`. */
export async function bootNodeShell(opts: NodeShellOptions): Promise<NodeShellRuntime> {
    const sodium = await loadCrypto();
    // ── Node platform seam ─────────────────────────────────────────────────────
    const fs = new NodeFs(opts.dir);
    const freshness = new FileFreshnessStore(freshnessPathFor(opts.dir));
    // Everything a boot can fail on happens inside bootShell, which tears down what it stood
    // up when it throws, so this function has no partial state to clean.
    const { shell: core, transport } = await bootShell({
        sodium: sodium as unknown as ShellSodium,
        identity: opts.identity,
        // The node's network (§12.6): an isolation boundary, so it must reach BOTH the
        // adapter bootShell constructs and the link slot's signing scope (what the
        // link occupant's node/sign binds to). One field, one place — forwarding it to
        // only one of the two would sign links under a network the node is not on.
        networkKey: opts.networkKey,
        fs,
        freshnessStore: freshness,
        // The sockets and the signed program that drives them, in one object.
        transport: {
            channels: opts.channels ?? new NodeChannelFactory(),
            listen: opts.listen,
            wsListen: opts.wsListen,
            bundle: opts.transportBundle,
            config: opts.transportConfig,
        },
        admit: policyFromJson(opts.policyJson),
        guestDeadlineMs: opts.guestDeadlineMs,
        realmMemoryBytes: opts.realmMemoryBytes,
    });
    // ── Node wrapper: add file-backed loadBundle ────────────────────────────────
    const shell: NodeShell = {
        ...core,
        // This platform always supplies an fs (Node always has a filesystem), so the
        // optional seam member is non-null here.
        fs: core.fs!,
        async loadBundle(file, loadOpts) {
            return core.loadBundleBlob(new Uint8Array(readFileSync(file)), loadOpts);
        },
    };
    // This wrapper always supplies transport options above, so the core's nullable result
    // (needed for no-network bootShell callers) is non-null at this boundary.
    return { shell, transport: transport! };
}

