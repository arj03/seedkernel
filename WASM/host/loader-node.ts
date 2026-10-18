// The Node loader (§12.9): runs a host blob's script on the Node platform
// (platform-node.ts), the same blob the native binary runs, booting the one the host slots
// choose (slots.ts, shared with the native loader). Everything a node does is in the blob,
// the checks on its successor included.
//
//   node build/host/loader-node.js --policy ./allowed-keys.json --dir ./data \
//        --listen 0.0.0.0:7000 [--guest-timeout 5000] [--guest-memory 64] [--host <blob>]

import { mkdirSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { runInThisContext } from "node:vm";
import { errMessage } from "../services/util.js";
import { nodeFiles, nodePlatform } from "./platform-node.js";
import { readHostBlob } from "./host-blob.js";
import { HostSlots, dataDirOf, loaderFlags, withoutOp, type SlotFiles } from "./slots.js";
import type { PlatformDispatchers } from "./abi.js";

/** The host script's dispatchers, once it has evaluated. */
const host = globalThis as unknown as PlatformDispatchers;

const flags = loaderFlags(process.argv.slice(2));
let hostArgs = flags.rest;
/** The running host blob. */
let blob!: Uint8Array;

/** The slots' files, answered in the call as the shared rules expect. */
const slotFiles: SlotFiles = {
  mkdir: (dir) => { mkdirSync(dir, { recursive: true, mode: 0o700 }); },
  read(path, maxBytes) {
    try { return statSync(path).size > maxBytes ? null : new Uint8Array(readFileSync(path)); } catch { return null; }
  },
  write: (path, bytes) => { nodeFiles.writeFile(path, bytes, 0o600); },
  remove(path) {
    try { unlinkSync(path); return true; } catch { return false; }
  },
  size(path) {
    try { return statSync(path).size; } catch { return -1; }
  },
};
const hostLog = (line: string) => { console.error("  host   " + line); };

const platform = nodePlatform({
  host: () => host,
  argv: () => JSON.stringify(hostArgs),
  hostBlob: () => blob,
  stageHost: (env) => {
    if (!hostSlots) throw new Error("host: updates are off on this node (--host-updates next|now)");
    if (!hostSlots.stage(env)) return;
    // Under "now", boot it once this turn has run; while the operator flow runs, once it
    // has ended (bootHost).
    if (serving) setImmediate(() => { void restart(); });
    else rebootWaiting = true;
  },
});

// ── run ──────────────────────────────────────────────────────────────────────
let hostSlots: HostSlots | null = null;
/** Set once the running host's operator flow has ended with the node serving. */
let serving = false;
/** A host staged under "now" during the operator flow, to boot once it ends. */
let rebootWaiting = false;

/** The host's timers, so a host that is replaced leaves none behind. The loader keeps the
 *  originals for its own. */
const hostTimers = new Set<ReturnType<typeof setTimeout>>();
const loaderSetTimeout = globalThis.setTimeout, loaderClearTimeout = globalThis.clearTimeout;

/** Release everything the running host holds, so the next one starts clean: what it holds
 *  through the platform, and its timers. */
function teardown(): void {
  serving = false;
  platform.teardown();
  for (const t of hostTimers) loaderClearTimeout(t);
  hostTimers.clear();
}

/** Run a blob's host script: the operator flow, which answers whether the node serves. */
async function runHost(env: Uint8Array): Promise<boolean> {
  blob = env;
  runInThisContext(new TextDecoder().decode(readHostBlob(env).script), { filename: "host.js" });
  const out = await host.runMain();
  hostArgs = withoutOp(hostArgs);
  return (JSON.parse(new TextDecoder().decode(out)) as { serving: boolean }).serving;
}

/** Boot the slots' choice (or --host), falling back to the committed host when a pending
 *  one fails before it is committed. */
async function bootHost(choose: () => Uint8Array): Promise<void> {
  for (;;) {
    let up: boolean;
    try {
      up = await runHost(choose());
    } catch (err) {
      teardown();
      if (hostSlots?.failed(errMessage(err))) continue;
      throw err;
    }
    const gen = hostSlots?.started(up) ?? null;
    if (gen !== null) loaderSetTimeout(() => hostSlots!.commit(gen), hostSlots!.windowMs).unref();
    if (up && rebootWaiting) {
      rebootWaiting = false;
      teardown();
      continue;
    }
    serving = up;
    return;
  }
}

let chooseHost!: () => Uint8Array;
const fatal = (e: unknown) => { console.error("ERROR: " + errMessage(e)); process.exit(1); };
async function restart(): Promise<void> {
  teardown();
  await bootHost(chooseHost).catch(fatal);
}

async function main(): Promise<void> {
  if (flags.hostFile !== undefined) {
    const chosen = new Uint8Array(readFileSync(flags.hostFile));
    chooseHost = () => chosen;
  } else {
    const genesis = new Uint8Array(readFileSync(new URL("../host.skb", import.meta.url)));
    hostSlots = new HostSlots(slotFiles, dataDirOf(hostArgs), flags.updates, genesis,
      process.env.SEEDKERNEL_HOST_HEALTH_MS, hostLog);
    chooseHost = () => hostSlots!.choose() ?? genesis;
  }
  Object.assign(globalThis, {
    bridge: platform.bridge, __fs: platform.fs, __net: platform.net, __udp: platform.udp,
    setTimeout: (fn: (...a: unknown[]) => void, ms?: number, ...args: unknown[]) => {
      const t = loaderSetTimeout(() => { hostTimers.delete(t); fn(...args); }, ms);
      hostTimers.add(t);
      return t;
    },
    clearTimeout: (t: ReturnType<typeof setTimeout>) => { hostTimers.delete(t); loaderClearTimeout(t); },
  });
  // A pending host that fails while it serves is dropped for the committed one, as a
  // failure at boot is; any other failure ends the process, as Node's default would.
  const onFailure = (err: unknown) => {
    if (hostSlots?.failed(errMessage(err))) void restart();
    else fatal(err);
  };
  process.on("uncaughtException", onFailure);
  process.on("unhandledRejection", onFailure);
  process.on("SIGINT", () => process.exit(0));
  await bootHost(chooseHost);
}

main().catch(fatal);
