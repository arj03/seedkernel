// The Node loader (§12.9): checks a signed host blob (host-blob.ts) with its own crypto,
// implements the platform ABI (abi.ts) with Node's own modules, and runs the blob's host
// script on it, the same blob the native binary runs. Everything a node does is in the
// blob; this file is only the platform under it.
//
//   node build/host/loader-node.js --policy ./allowed-keys.json --dir ./data \
//        --listen 0.0.0.0:7000 [--guest-timeout 5000] [--guest-memory 64] [--host <blob>]

import { randomFillSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { createServer, connect as tcpConnect, type Server, type Socket } from "node:net";
import { runInThisContext } from "node:vm";
import { NodeFs } from "../services/fs-node.js";
import { FS_AVAILABLE_UNKNOWN } from "../services/fs.js";
import { nodeDatagrams } from "../services/udp/node.js";
import { errMessage, toHex } from "../services/util.js";
import { ModuleTable } from "./module-table.js";
import { nodeFiles } from "./shell-node.js";
import { wasiImports } from "./engine-web.js";
import { loadCrypto } from "./crypto-node.js";
import { verifyHostBlob, type VerifiedHost } from "./host-blob.js";
import type { ManifestVerifier, PureModules } from "./bundle.js";
import {
  PLATFORM_ABI,
  type PlatformBridge, type PlatformDispatchers, type PlatformFs, type PlatformNet, type PlatformUdp,
} from "./abi.js";

/** The host script's dispatchers, once it has evaluated. */
const host = globalThis as unknown as PlatformDispatchers;

/** The loader's own flags, out of what the host sees, as `--name value` or
 *  `--name=value`:
 *  - `--host <file>` boots that blob instead of the slots' choice, by the operator's
 *    explicit choice and from any author;
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
/** The running host blob, verified before it ran. */
let blob!: VerifiedHost;

// ── process, modules, engine ─────────────────────────────────────────────────
const moduleTable = new ModuleTable();
const slots = new Map<string, PureModules>();
const engines = new Map<number, { exports: Record<string, unknown>; memory: WebAssembly.Memory; fns: unknown[] }>();
let engineSeq = 0;
const compiled = new WeakMap<Uint8Array, WebAssembly.Module>();
const engineOf = (id: number) => {
  const e = engines.get(id);
  if (!e) throw new Error("engine: no such instance");
  return e;
};

const bridge: PlatformBridge = {
  abi: PLATFORM_ABI,
  banner: "seedkernel-shell",
  // A module call runs in a worker, outside the guest's segment.
  modulesInSegment: false,
  argv: () => JSON.stringify(hostArgs),
  readFile: (path) => nodeFiles.readFile(path),
  writeFile: (path, bytes, mode) => nodeFiles.writeFile(path, bytes, mode === 0 ? undefined : mode),
  log: (line) => { console.error(line); },
  stdout: (bytes) => { process.stdout.write(bytes); },
  // Whatever was piped in, or empty. Reading fd 0 throws instead of blocking when stdin is
  // an unredirected terminal, which also means no argument.
  stdin: () => {
    try { return new Uint8Array(readFileSync(0)); } catch { return new Uint8Array(0); }
  },
  async buildModules(slot, mods) {
    slots.set(slot, await moduleTable.build(mods));
  },
  callModule(slot, module, payload, deadlineMs) {
    const mods = slots.get(slot);
    return mods ? mods.call(module, payload, deadlineMs < 0 ? Infinity : deadlineMs) : null;
  },
  disposeModules(slot) {
    slots.get(slot)?.dispose();
    slots.delete(slot);
  },
  engineInstantiate(wasm, imports) {
    let mod = compiled.get(wasm);
    if (!mod) {
      mod = new WebAssembly.Module(wasm as BufferSource);
      compiled.set(wasm, mod);
    }
    let memory!: WebAssembly.Memory;
    const instance = new WebAssembly.Instance(mod, {
      ...imports, wasi_snapshot_preview1: wasiImports(mod, () => memory),
    } as WebAssembly.Imports);
    const exports = instance.exports as Record<string, unknown>;
    memory = Object.values(exports).find((v) => v instanceof WebAssembly.Memory) as WebAssembly.Memory;
    (exports._initialize as (() => void) | undefined)?.();
    engines.set(++engineSeq, { exports, memory, fns: [] });
    return engineSeq;
  },
  engineExport(id, name) {
    const e = engineOf(id);
    const fn = e.exports[name];
    if (typeof fn !== "function") throw new Error(`engine: no export "${name}"`);
    return e.fns.push(fn) - 1;
  },
  engineCall(id, fn, ...args) {
    return (engineOf(id).fns[fn] as (...args: number[]) => number)(...args);
  },
  engineGlobal(id, name) {
    const g = engineOf(id).exports[name];
    return g instanceof WebAssembly.Global ? Number(g.value) : null;
  },
  engineGrow(id, pages) {
    try { return engineOf(id).memory.grow(pages); } catch { return -1; }
  },
  engineRead: (id, ptr, len) => new Uint8Array(engineOf(id).memory.buffer, ptr, len).slice(),
  engineWrite: (id, ptr, bytes) => { new Uint8Array(engineOf(id).memory.buffer).set(bytes, ptr); },
  engineDispose: (id) => { engines.delete(id); },
  random: (n) => randomFillSync(new Uint8Array(n)),
  stageHost: (env) => {
    if (!hostSlots) throw new Error("host: updates are off on this node (--host-updates next|now)");
    if (!hostSlots.stage(env, blob)) return;
    // Under "now", boot it once this turn has run; while the operator flow runs, once it
    // has ended (bootHost).
    if (serving) setImmediate(() => { void restart(); });
    else rebootWaiting = true;
  },
  qjsWasm: () => blob.qjs,
  sodiumWasm: () => blob.sodium,
  mldsaWasm: () => blob.mldsa,
};

// ── files ────────────────────────────────────────────────────────────────────
let store: NodeFs | null = null;
const fs: PlatformFs = {
  open: (dir) => { store = new NodeFs(dir); },
  get: (key) => (store ? store.get(key) : null),
  put: (key, bytes) => {
    if (!store) throw new Error("fs: no store opened — a node writes only after --dir is read");
    return store.put(key, bytes);
  },
  size: (key) => (store ? store.size(key) : -1),
  list: async (prefix) => (store ? (await store.list(prefix)).join("\n") : ""),
  delete: (key) => (store ? store.delete(key) : false),
  stat: async () => {
    if (!store) return { used: 0, available: -1 };
    const s = await store.stat();
    return { used: s.used, available: s.available === FS_AVAILABLE_UNKNOWN ? -1 : s.available };
  },
};

// ── sockets ──────────────────────────────────────────────────────────────────
const sockets = new Map<number, Socket>();
const servers: Server[] = [];
let socketSeq = 0;
let limits: { maxLive: number; graceMs: number } | null = null;

/** One socket under the ABI's rules: the first read may start at once and each later one
 *  waits for `resume`, and only a close the host did not make is reported. */
function adopt(socket: Socket): number {
  const id = ++socketSeq;
  sockets.set(id, socket);
  socket.on("data", (chunk: Buffer) => {
    socket.pause();
    host.__netDeliver(id, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
  });
  const gone = () => {
    // A local close dropped the entry first, so it is not reported.
    if (sockets.get(id) !== socket) return;
    sockets.delete(id);
    host.__netClosed(id);
  };
  socket.on("close", gone);
  socket.on("error", gone);
  return id;
}

const net: PlatformNet = {
  install(maxLive, graceMs, maxInboundBytes, maxInboundSlices) {
    if (limits) throw new Error("net: socket limits already installed");
    if (!(maxLive > 0 && graceMs > 0 && maxInboundBytes > 0 && maxInboundSlices > 0)) {
      throw new Error("net: invalid socket limits");
    }
    // Reads arrive on this thread one at a time, so nothing is ever staged and the inbound
    // limits hold by construction.
    limits = { maxLive, graceMs };
  },
  connect: (host, port) => adopt(tcpConnect(port, host)),
  listen: (hostname, port) => new Promise<number>((resolve, reject) => {
    const server = createServer((socket) => {
      if (sockets.size >= limits!.maxLive) {
        socket.destroy();
        return;
      }
      // The IP alone: the transport's half-open budget groups by source IP.
      const remoteAddr = socket.remoteAddress ?? "";
      const id = adopt(socket);
      host.__netAccept(bound, id, remoteAddr);
    });
    let bound = 0;
    server.once("error", reject);
    server.listen(port, hostname, () => {
      server.removeListener("error", reject);
      bound = (server.address() as { port: number }).port;
      // A failed accept (EMFILE and the like) loses that connection, not the listener.
      server.on("error", (err) => { console.error(`[net] accept on ${hostname}:${bound}: ${errMessage(err)}`); });
      servers.push(server);
      resolve(bound);
    });
  }),
  send: (id, bytes) => { sockets.get(id)?.write(bytes); },
  buffered: (id) => sockets.get(id)?.writableLength ?? 0,
  resume: (id) => { sockets.get(id)?.resume(); },
  close(id, graceful) {
    const socket = sockets.get(id);
    if (!socket) return;
    sockets.delete(id);
    if (!graceful) {
      socket.destroy();
      return;
    }
    // end() flushes what is queued and sends FIN; the grace covers a peer that never
    // closes its side.
    socket.end();
    loaderSetTimeout(() => socket.destroy(), limits!.graceMs).unref();
  },
  closeListeners() {
    for (const server of servers.splice(0)) server.close();
  },
};

// ── datagrams ────────────────────────────────────────────────────────────────
/** An IPv6 address's text as its 16 bytes. */
function ipv6Bytes(text: string): Uint8Array {
  const out = new Uint8Array(16);
  let [head, tail] = text.includes("::") ? text.split("::") : [text, undefined];
  const words = (part: string | undefined): number[] => {
    if (!part) return [];
    const out: number[] = [];
    for (const w of part.split(":")) {
      if (w.includes(".")) {
        const [a, b, c, d] = w.split(".").map(Number);
        out.push((a << 8) | b, (c << 8) | d);
      } else {
        out.push(parseInt(w, 16));
      }
    }
    return out;
  };
  const front = words(head), back = words(tail);
  const all = tail === undefined ? front : [...front, ...new Array(8 - front.length - back.length).fill(0), ...back];
  all.forEach((w, i) => { out[2 * i] = w >> 8; out[2 * i + 1] = w & 255; });
  return out;
}

const udpSockets = new Map<number, { send(bytes: Uint8Array, port: number, host: string): void; close(): void }>();
let udpSeq = 0;
const udp: PlatformUdp = {
  async bind() {
    const { socket, port } = await nodeDatagrams.bind();
    const id = ++udpSeq;
    udpSockets.set(id, socket);
    socket.onMessage((bytes, from, fromPort) => {
      const ip = from.includes(":") ? ipv6Bytes(from) : Uint8Array.from(from.split(".").map(Number));
      const batch = new Uint8Array(1 + ip.length + 4 + bytes.length);
      batch[0] = ip.length;
      batch.set(ip, 1);
      const at = 1 + ip.length;
      batch[at] = fromPort >> 8;
      batch[at + 1] = fromPort & 255;
      batch[at + 2] = bytes.length >> 8;
      batch[at + 3] = bytes.length & 255;
      batch.set(bytes, at + 4);
      host.__udpDeliver(id, batch);
    });
    return { id, port };
  },
  send: (id, hostname, port, bytes) => { udpSockets.get(id)?.send(bytes, port, hostname); },
  close: (id) => { udpSockets.get(id)?.close(); udpSockets.delete(id); },
  addresses: () => nodeDatagrams.addresses().join("\n"),
};

// ── host slots ───────────────────────────────────────────────────────────────
// The rules the native loader keeps (native/hostslots.go): one author, the genesis blob's;
// a floor, the committed host's version; a staged blob tried once, marked before it boots;
// committed after a health window it served through, and dropped if it fails before that.
// The slots sit beside the data directory: <dir>.host/committed.skb, pending.skb, tried.

const HEALTH_MS = Number(process.env.SEEDKERNEL_HOST_HEALTH_MS ?? 30_000);
const hostLog = (line: string) => { console.error("  host   " + line); };
type Loaded = VerifiedHost & { env: Uint8Array };

class HostSlots {
  private trying = false;
  private gen = 0;
  constructor(private readonly dir: string, private readonly mode: string,
    private readonly genesis: Loaded, private readonly crypto: ManifestVerifier) {
    if (!["off", "next", "now"].includes(mode)) throw new Error(`--host-updates must be off, next or now (got "${mode}")`);
  }
  private path(name: string) { return join(this.dir, name); }
  private load(name: string): Loaded | null {
    let env: Uint8Array;
    try { env = new Uint8Array(readFileSync(this.path(name))); } catch { return null; }
    try {
      const h = verifyHostBlob(this.crypto, env);
      if (toHex(h.author) !== toHex(this.genesis.author)) {
        hostLog(`ignored ${name}: signed by ${toHex(h.author)}, not this loader's host author`);
        return null;
      }
      if (h.manifest.abi !== PLATFORM_ABI) {
        hostLog(`ignored ${name}: it needs platform ABI ${h.manifest.abi}, this loader implements ${PLATFORM_ABI}`);
        return null;
      }
      return { ...h, env };
    } catch (err) {
      hostLog(`ignored ${name}: ${errMessage(err)}`);
      return null;
    }
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
  /** Keep a blob a running host hands over as pending; answers whether to boot it now. */
  stage(env: Uint8Array, running: VerifiedHost): boolean {
    if (this.mode === "off") throw new Error("host: updates are off on this node (--host-updates next|now)");
    const h = verifyHostBlob(this.crypto, env);
    if (toHex(h.author) !== toHex(this.genesis.author)) {
      throw new Error(`host: signed by ${toHex(h.author)}, not this loader's host author`);
    }
    if (h.manifest.abi !== PLATFORM_ABI) {
      throw new Error(`host: the blob needs platform ABI ${h.manifest.abi}, this loader implements ${PLATFORM_ABI}`);
    }
    const floor = Math.max(this.base().manifest.version, running.manifest.version);
    if (h.manifest.version <= floor) throw new Error(`host: v${h.manifest.version} is not above v${floor}`);
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

/** Release everything the running host holds through the ABI, so the next one starts
 *  clean: sockets, listeners, datagram sockets, timers, modules, engines and the store. */
function teardown(): void {
  serving = false;
  for (const socket of sockets.values()) socket.destroy();
  sockets.clear();
  for (const server of servers.splice(0)) server.close();
  for (const socket of udpSockets.values()) socket.close();
  udpSockets.clear();
  for (const t of hostTimers) loaderClearTimeout(t);
  hostTimers.clear();
  for (const mods of slots.values()) mods.dispose();
  slots.clear();
  engines.clear();
  store = null;
  limits = null;
}

/** Check a blob and run its host script: the operator flow, which answers whether the
 *  node serves. */
async function runHost(env: Loaded): Promise<boolean> {
  if (env.manifest.abi !== PLATFORM_ABI) {
    throw new Error(`host: the blob needs platform ABI ${env.manifest.abi}, this loader implements ${PLATFORM_ABI}`);
  }
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
  // The loader's own crypto (crypto-node.ts), with ML-DSA-65 mixed in: none of a blob runs
  // before it is checked.
  const crypto = await loadCrypto() as unknown as ManifestVerifier;
  const verified = (env: Uint8Array): Loaded => ({ ...verifyHostBlob(crypto, env), env });
  if (flags.hostFile !== undefined) {
    const chosen = verified(new Uint8Array(readFileSync(flags.hostFile)));
    chooseHost = () => chosen;
  } else {
    const genesis = verified(new Uint8Array(readFileSync(new URL("../host.skb", import.meta.url))));
    hostSlots = new HostSlots(dataDirOf(hostArgs).replace(/[/\\]+$/, "") + ".host", flags.updates, genesis, crypto);
    chooseHost = () => hostSlots!.choose();
  }
  Object.assign(globalThis, {
    bridge, __fs: fs, __net: net, __udp: udp,
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
