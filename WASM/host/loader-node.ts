// The Node loader (§12.9): runs a host blob's script on the Node platform
// (platform-node.ts), the same blob the native binary runs, booting the one the shared
// loader rules choose (slots.ts, which the native loader runs too). Everything a node does
// is in the blob, the checks on its successor included.
//
//   node build/host/loader-node.js --policy ./allowed-keys.json --dir ./data \
//        --listen 0.0.0.0:7000 [--guest-timeout 5000] [--guest-memory 64] [--host <blob>]

import { mkdirSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { runInThisContext } from "node:vm";
import { errMessage } from "../services/util.js";
import { nodeFiles, nodePlatform } from "./platform-node.js";
import { readHostBlob } from "./host-blob.js";
import { Loader, type SlotFiles } from "./slots.js";
import type { PlatformDispatchers } from "./abi.js";

/** The host script's dispatchers, once it has evaluated. */
const host = globalThis as unknown as PlatformDispatchers;

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

/** The host's timers, so a host that is replaced leaves none behind. The loader keeps the
 *  originals for its own. */
const hostTimers = new Set<ReturnType<typeof setTimeout>>();
const loaderSetTimeout = globalThis.setTimeout, loaderClearTimeout = globalThis.clearTimeout;

const genesis = new Uint8Array(readFileSync(new URL("../host.skb", import.meta.url)));
let loader!: Loader;
/** The running host blob. */
let blob!: Uint8Array;
/** Set once the running host's operator flow has ended with the node serving. */
let serving = false;
/** A host staged under "now" during the operator flow, to boot once it ends. */
let rebootWaiting = false;

const platform = nodePlatform({
  host: () => host,
  argv: () => JSON.stringify(loader.hostArgs),
  hostBlob: () => blob,
  stageHost: (env) => {
    if (!loader.stage(env)) return;
    // Under "now", boot it once this turn has run; while the operator flow runs, once it
    // has ended (bootHost).
    if (serving) setImmediate(() => { void restart(); });
    else rebootWaiting = true;
  },
});

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
  return (JSON.parse(new TextDecoder().decode(out)) as { serving: boolean }).serving;
}

/** Boot the loader's choice, falling back to the committed host when a pending one fails
 *  before it is committed. */
async function bootHost(): Promise<void> {
  for (;;) {
    let up: boolean;
    try {
      up = await runHost(loader.choose() ?? genesis);
    } catch (err) {
      teardown();
      if (loader.failed(errMessage(err))) continue;
      throw err;
    }
    loader.ended(up);
    if (up && rebootWaiting) {
      rebootWaiting = false;
      teardown();
      continue;
    }
    serving = up;
    return;
  }
}

const fatal = (e: unknown) => { console.error("ERROR: " + errMessage(e)); process.exit(1); };
async function restart(): Promise<void> {
  teardown();
  await bootHost().catch(fatal);
}

async function main(): Promise<void> {
  loader = new Loader(slotFiles, process.argv.slice(2), genesis, process.env.SEEDKERNEL_HOST_HEALTH_MS,
    (line) => { console.error("  host   " + line); },
    (ms, fn) => { loaderSetTimeout(fn, ms).unref(); });
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
    if (loader.failed(errMessage(err))) void restart();
    else fatal(err);
  };
  process.on("uncaughtException", onFailure);
  process.on("unhandledRejection", onFailure);
  process.on("SIGINT", () => process.exit(0));
  await bootHost();
}

main().catch(fatal);
