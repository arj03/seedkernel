// The Node loader (§12.9): runs a host blob's script (host-blob.ts) on the Node platform
// (platform-node.ts), the same blob the native binary runs. Everything a node does is in
// the blob, the checks on its successor included; this file only keeps the slots that blob
// is staged in and boots the one they choose.
//
//   node build/host/loader-node.js --policy ./allowed-keys.json --dir ./data \
//        --listen 0.0.0.0:7000 [--guest-timeout 5000] [--guest-memory 64] [--host <blob>]

import { existsSync, mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { runInThisContext } from "node:vm";
import { errMessage } from "../services/util.js";
import { nodeFiles, nodePlatform } from "./platform-node.js";
import { readHostBlob, type HostBlob } from "./host-blob.js";
import { PLATFORM_ABI, type PlatformDispatchers } from "./abi.js";

/** The host script's dispatchers, once it has evaluated. */
const host = globalThis as unknown as PlatformDispatchers;

/** The loader's own flags, out of what the host sees, as `--name value` or
 *  `--name=value`:
 *  - `--host <file>` boots that blob instead of the slots' choice, by the operator's
 *    explicit choice, unchecked and from any author;
 *  - `--host-updates off|next|now` is whether a running host may stage a new one, and when
 *    it runs: refused (the default), at the next start, or at once. */
function loaderFlags(argv: string[]): { rest: string[]; hostFile?: string; updates: string } {
  const out: { rest: string[]; hostFile?: string; updates: string } = { rest: [], updates: "off" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.indexOf("=");
    const name = a.startsWith("--") ? a.slice(2, eq < 0 ? undefined : eq) : "";
    if (name !== "host" && name !== "host-updates") {
      out.rest.push(a);
      continue;
    }
    let value = eq < 0 ? undefined : a.slice(eq + 1);
    if (value === undefined) {
      if (i + 1 >= argv.length) throw new Error(`--${name} needs a value`);
      value = argv[++i];
    }
    if (name === "host") out.hostFile = value;
    else out.updates = value;
  }
  return out;
}
const flags = loaderFlags(process.argv.slice(2));
let hostArgs = flags.rest;

/** The arguments less `--op`: a host booted after an operator flow ran, in the same
 *  process, does not repeat its one-shot op. */
function withoutOp(args: string[]): string[] {
  return args.filter((a, i) => a !== "--op" && !a.startsWith("--op=") && args[i - 1] !== "--op");
}
/** The running host blob. */
let blob!: Loaded;

const platform = nodePlatform({
  host: () => host,
  argv: () => JSON.stringify(hostArgs),
  hostBlob: () => blob.env,
  stageHost: (env) => {
    if (!hostSlots) throw new Error("host: updates are off on this node (--host-updates next|now)");
    if (!hostSlots.stage(env)) return;
    // Under "now", boot it once this turn has run; while the operator flow runs, once it
    // has ended (bootHost).
    if (serving) setImmediate(() => { void restart(); });
    else rebootWaiting = true;
  },
});

// ── host slots ───────────────────────────────────────────────────────────────
// The rules the native loader keeps (native/hostslots.go): a floor, the committed host's
// version; a staged blob tried once, marked before it boots; committed after a health
// window it served through, and dropped if it fails before that. The running host checked
// a staged blob's author, ABI and version before handing it over. The slots sit beside the
// data directory: <dir>.host/committed.skb, pending.skb, tried.

const HEALTH_MS = Number(process.env.SEEDKERNEL_HOST_HEALTH_MS ?? 30_000);
const hostLog = (line: string) => { console.error("  host   " + line); };
type Loaded = HostBlob & { env: Uint8Array };
const loaded = (env: Uint8Array): Loaded => ({ ...readHostBlob(env), env });

class HostSlots {
  private trying = false;
  private gen = 0;
  constructor(private readonly dir: string, private readonly mode: string, private readonly genesis: Loaded) {
    if (!["off", "next", "now"].includes(mode)) throw new Error(`--host-updates must be off, next or now (got "${mode}")`);
  }
  private path(name: string) { return join(this.dir, name); }
  /** A slot's blob, or null when it is absent or not for this loader's ABI. */
  private load(name: string): Loaded | null {
    let env: Uint8Array;
    try { env = new Uint8Array(readFileSync(this.path(name))); } catch { return null; }
    try {
      const h = loaded(env);
      if (h.manifest.abi === PLATFORM_ABI) return h;
      hostLog(`ignored ${name}: it needs platform ABI ${h.manifest.abi}, this loader implements ${PLATFORM_ABI}`);
    } catch (err) {
      hostLog(`ignored ${name}: ${errMessage(err)}`);
    }
    return null;
  }
  /** The committed host when it is newer than the genesis blob, which a newer loader can be. */
  private base(): Loaded {
    const c = this.load("committed.skb");
    return c && c.manifest.version > this.genesis.manifest.version ? c : this.genesis;
  }
  private discard(reason: string) {
    rmSync(this.path("pending.skb"), { force: true });
    rmSync(this.path("tried"), { force: true });
    this.trying = false;
    hostLog(`discarded the pending host: ${reason}`);
  }
  /** The blob the next boot runs. */
  choose(): Loaded {
    this.gen++;
    this.trying = false;
    const base = this.base();
    if (!existsSync(this.path("pending.skb"))) return base;
    if (existsSync(this.path("tried"))) {
      this.discard("it was tried and never committed");
      return base;
    }
    const p = this.load("pending.skb");
    if (!p || p.manifest.version <= base.manifest.version) {
      this.discard("it is not above the floor");
      return base;
    }
    try {
      nodeFiles.writeFile(this.path("tried"), new Uint8Array(0), 0o600);
    } catch (err) {
      hostLog(`cannot mark v${p.manifest.version} tried, so it is not run: ${errMessage(err)}`);
      return base;
    }
    this.trying = true;
    hostLog(`trying v${p.manifest.version} (committed is v${base.manifest.version})`);
    return p;
  }
  /** Whether a failure is a pending host's, which is then dropped for the committed one. */
  failed(err: unknown): boolean {
    if (!this.trying) return false;
    this.discard(errMessage(err));
    return true;
  }
  /** A pending host that serves is committed once it has served for the window; one that
   *  only ran an op proved nothing, so it stays pending, untried. */
  started(serving: boolean) {
    if (!this.trying) return;
    if (!serving) {
      rmSync(this.path("tried"), { force: true });
      this.trying = false;
      return;
    }
    const gen = this.gen;
    loaderSetTimeout(() => {
      if (!this.trying || this.gen !== gen) return;
      try { renameSync(this.path("pending.skb"), this.path("committed.skb")); }
      catch (err) { hostLog(`cannot commit the pending host: ${errMessage(err)}`); return; }
      rmSync(this.path("tried"), { force: true });
      this.trying = false;
      hostLog(`committed after ${HEALTH_MS}ms`);
    }, HEALTH_MS).unref();
  }
  /** Keep a blob the running host checked as pending; answers whether to boot it now. */
  stage(env: Uint8Array): boolean {
    if (this.mode === "off") throw new Error("host: updates are off on this node (--host-updates next|now)");
    const h = loaded(env);
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    nodeFiles.writeFile(this.path("pending.skb"), env, 0o600);
    rmSync(this.path("tried"), { force: true });
    hostLog(`staged v${h.manifest.version}`);
    return this.mode === "now";
  }
}

/** The host's --dir, which the slots sit beside, or the CLI's default (cli.ts DEFAULT_DIR). */
function dataDirOf(args: string[]): string {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dir" && i + 1 < args.length) return args[i + 1];
    if (args[i].startsWith("--dir=")) return args[i].slice("--dir=".length);
  }
  return "./data";
}

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
async function runHost(env: Loaded): Promise<boolean> {
  blob = env;
  runInThisContext(new TextDecoder().decode(env.script), { filename: "host.js" });
  const out = await host.runMain();
  hostArgs = withoutOp(hostArgs);
  return (JSON.parse(new TextDecoder().decode(out)) as { serving: boolean }).serving;
}

/** Boot the slots' choice (or --host), falling back to the committed host when a pending
 *  one fails before it is committed. */
async function bootHost(choose: () => Loaded): Promise<void> {
  for (;;) {
    let up: boolean;
    try {
      up = await runHost(choose());
    } catch (err) {
      teardown();
      if (hostSlots?.failed(err)) continue;
      throw err;
    }
    hostSlots?.started(up);
    if (up && rebootWaiting) {
      rebootWaiting = false;
      teardown();
      continue;
    }
    serving = up;
    return;
  }
}

let chooseHost!: () => Loaded;
const fatal = (e: unknown) => { console.error("ERROR: " + errMessage(e)); process.exit(1); };
async function restart(): Promise<void> {
  teardown();
  await bootHost(chooseHost).catch(fatal);
}

async function main(): Promise<void> {
  if (flags.hostFile !== undefined) {
    const chosen = loaded(new Uint8Array(readFileSync(flags.hostFile)));
    chooseHost = () => chosen;
  } else {
    const genesis = loaded(new Uint8Array(readFileSync(new URL("../host.skb", import.meta.url))));
    hostSlots = new HostSlots(dataDirOf(hostArgs).replace(/[/\\]+$/, "") + ".host", flags.updates, genesis);
    chooseHost = () => hostSlots!.choose();
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
    if (hostSlots?.failed(err)) void restart();
    else fatal(err);
  };
  process.on("uncaughtException", onFailure);
  process.on("unhandledRejection", onFailure);
  process.on("SIGINT", () => process.exit(0));
  await bootHost(chooseHost);
}

main().catch(fatal);
