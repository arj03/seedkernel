// The Node platform shell (§12).
//
// `bootNodeShell()` gathers this platform's parts (`NodeFs` on a data directory, a
// `node:net` channel factory, a file-backed freshness store) and hands them to the shared
// `bootShell`, which does the assembly (§12.8). It knows nothing about any app: every app
// arrives as a signed bundle (§12.4) whose author must pass the policy.
//
// The operator side (flags, defaults, boot sequence, console output) is `cli.ts`, shared by
// every target; `main-node.ts` binds it to this platform.
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { loadCrypto } from "./crypto-node.js";
import { policyFromJson } from "./policy.js";
import { NodeChannelFactory } from "../services/net-node.js";
import { NodeFs } from "../services/fs-node.js";
import { bootShell, type AppHandle, type InstallOptions, type Shell, type ShellSodium } from "./shell-core.js";
import { type Fs } from "../services/fs.js";
import { freshnessStoreFor, type CliFiles, type NodeRuntime as CliNodeRuntime, type NodeSetup } from "./cli.js";

/** Write a whole file or none: write a temp file beside the target, then rename it over.
 *  A plain `writeFileSync` truncates in place, so a crash mid-write leaves a partial file
 *  for the next boot to misread. Synchronous, because it writes state a node cannot boot
 *  without: the key file and the freshness marks. */
function writeFileAtomic(path: string, data: Uint8Array, mode?: number): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, data, mode === undefined ? undefined : { mode });
  renameSync(tmp, path);
}

/** This platform's `CliFiles` (cli.ts), for the operator flow (main-node.ts) and the
 *  freshness store below. Only a missing file reads as `null`, as on the native target;
 *  an unreadable one throws, or the `--key` first-boot path would overwrite it. */
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

/** The Node shell: the platform-neutral `Shell` plus `installFile` and a non-optional
 *  `fs`. */
export interface NodeShell extends Shell {
  fs: Fs;
  /** Read a signed bundle file from disk and pass it to `install` (§12.4), `opts.replaces`
   *  included. Cross-platform callers hold the bytes and call `install` directly. */
  installFile(file: string, opts?: InstallOptions): Promise<AppHandle>;
}

/** The CLI's runtime pair, narrowed to this platform's shell, so the compiler checks that
 *  `standUp` returns it. */
export interface NodeShellRuntime extends CliNodeRuntime {
  shell: NodeShell;
}

// No realm factory (§12.3) is passed: bootShell's default, a lazy safe-js import that
// loads the engine on the first realm, is what this platform wants.
/** Assemble the runtime on Node: build the platform seam, hand it to the shared
 *  `bootShell` (which installs the selected transport bundle, §12.6), then add the
 *  file-backed `installFile`. */
export async function bootNodeShell(opts: NodeSetup): Promise<NodeShellRuntime> {
  const sodium = await loadCrypto();
  // ── Node platform seam ─────────────────────────────────────────────────────
  const fs = new NodeFs(opts.dir);
  const freshness = freshnessStoreFor(nodeFiles, opts.dir);
  // Everything that can fail happens inside bootShell, which tears down what it built
  // when it throws, so there is no partial state to clean up here.
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
    // This platform always supplies an fs.
    fs: base.fs!,
    async installFile(file, opts) {
      return base.install(new Uint8Array(readFileSync(file)), opts);
    },
  };
  return { shell, transport };
}
