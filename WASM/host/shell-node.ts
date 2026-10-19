// The Node library shell (§12): a node in this process, on the same platform the Node
// loader runs a host blob on (platform-node.ts) and assembled by the same host code
// (platform.ts), with the package's own host blob for its engine and crypto. It knows
// nothing about any app: every app arrives as a signed bundle (§12.4) whose author must
// pass the policy.
import { readFileSync } from "node:fs";
import { nodePlatform } from "./platform-node.js";
import { platformHost, tcpChannels } from "./platform.js";
import { type ChannelFactory } from "../services/socket-seam.js";
import { type AppHandle, type InstallOptions, type Shell } from "./shell-core.js";
import { type Fs } from "../services/fs.js";
import { type NodeRuntime as CliNodeRuntime, type NodeSetup } from "./cli.js";

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

/** Assemble a node in this process through the host's own `standUp`, then add the
 *  file-backed `installFile`. */
export async function bootNodeShell(opts: NodeSetup): Promise<NodeShellRuntime> {
  const { shell: base, transport } = await platformHost(nodePlatform()).standUp(opts);
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

/** TCP over node:net and nothing else, the platform's own sockets: a `ChannelFactory` for
 *  a caller that assembles a node with `bootShell` itself. */
export function nodeChannels(): ChannelFactory {
  return tcpChannels(nodePlatform().net);
}
