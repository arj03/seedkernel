// seedkernel-shell — the NODE platform (README §12).
//
// `bootNodeShell()` assembles a node out of this platform's parts — `NodeFs` on a data
// directory, a `node:net` channel factory, a file-backed freshness store — and hands them
// to the shared `bootShell`, which is the assembly (§12.9). It knows nothing about any app:
// everything arrives as a signed bundle (§12.4) whose author must clear the policy gate.
//
// The operator's side — flags, defaults, boot sequence, console lines — is `cli.ts`, which
// every target runs; `main-node.ts` binds it to this platform.
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { loadCrypto } from "./crypto-node.js";
import { policyFromJson } from "./policy.js";
import { NodeChannelFactory } from "../services/net-node.js";
import { NodeFs } from "../services/fs-node.js";
import { bootShell, type AppHandle, type InstallOptions, type Shell, type ShellSodium } from "./shell-core.js";
import { type Fs } from "../services/fs.js";
import { freshnessStoreFor, type CliFiles, type NodeRuntime as CliNodeRuntime, type NodeSetup } from "./cli.js";

/** Write a whole file or none: a temp beside the target, then a rename onto it. A bare
 *  `writeFileSync` truncates in place, so a crash mid-write leaves a partial file that the
 *  next boot reads as something else entirely. Sync, because what it writes is boot-time
 *  state a node cannot start without: the key file and the freshness marks. */
function writeFileAtomic(path: string, data: Uint8Array, mode?: number): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, data, mode === undefined ? undefined : { mode });
  renameSync(tmp, path);
}

/** This platform's `CliFiles` (cli.ts), for the operator flow (main-node.ts) and the
 *  freshness store below. Only a missing file reads as `null`, as natively: an
 *  unreadable one throws, or the `--key` first-boot branch would write over it. */
export const nodeFiles: CliFiles = {
  readFile(path) {
    try { return new Uint8Array(readFileSync(path)); }
    catch (e) {
      if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return null;
      throw e;
    }
  },
  writeFile: writeFileAtomic,
};

/** The Node-side Shell — the platform-neutral `Shell` plus a file-backed
 *  `installFile` and a guaranteed `fs` (Node always has a filesystem). */
export interface NodeShell extends Shell {
  fs: Fs;
  /** Install a signed bundle *file*: read it from disk then delegate to `install`
   *  (§12.4), `opts.replaces` included — a file on disk is as ordinary a source for a
   *  replacement as for a first install. This is the Node convenience wrapper;
   *  cross-platform callers hold the bytes and use `install` directly. */
  installFile(file: string, opts?: InstallOptions): Promise<AppHandle>;
}

/** The CLI's runtime pair, narrowed to this platform's shell — one declaration of the
 *  shape, so `standUp` returning it stays a compile-time fact rather than a coincidence. */
export interface NodeShellRuntime extends CliNodeRuntime {
  shell: NodeShell;
}

// The realm factory (§12.3) is deliberately not stated here: bootShell's default IS the
// lazy safe-js import this platform wants (the engine is heavy, so it loads on the first
// realm), and a second copy of it would be the drift the assembly exists to remove.
/** Assemble the runtime on Node: build the platform seam, hand it to the shared
 *  `bootShell` — which installs the selected transport bundle, the signed program that is
 *  the node's network (§12.6) — then wrap its shell with the file-backed `installFile`. */
export async function bootNodeShell(opts: NodeSetup): Promise<NodeShellRuntime> {
  const sodium = await loadCrypto();
  // ── Node platform seam ─────────────────────────────────────────────────────
  const fs = new NodeFs(opts.dir);
  const freshness = freshnessStoreFor(nodeFiles, opts.dir);
  // Everything a boot can fail on happens inside bootShell, which tears down what it stood
  // up when it throws, so this function has no partial state to clean.
  const { shell: base, transport } = await bootShell({
    sodium: sodium as unknown as ShellSodium,
    identity: opts.identity,
    fs,
    freshnessStore: freshness,
    // The network as configured, over node:net unless the caller brings its own sockets.
    transport: opts.transport && {
      ...opts.transport, channels: opts.transport.channels ?? new NodeChannelFactory(),
    },
    admit: policyFromJson(opts.policyJson),
    guestDeadlineMs: opts.guestDeadlineMs,
    realmMemoryBytes: opts.realmMemoryBytes,
  });
  // ── Node wrapper: add file-backed installFile ───────────────────────────────────
  const shell: NodeShell = {
    ...base,
    // This platform always supplies an fs (Node always has a filesystem), so the
    // optional seam member is non-null here.
    fs: base.fs!,
    async installFile(file, opts) {
      return base.install(new Uint8Array(readFileSync(file)), opts);
    },
  };
  return { shell, transport };
}
