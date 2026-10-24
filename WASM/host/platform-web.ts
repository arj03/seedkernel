// The platform over the Web APIs (§12.9): WebAssembly, workers and crypto.getRandomValues,
// which Node has too. The engine table over WebAssembly and `webBridge` are what the Node
// platform (platform-node.ts) shares with the browser's; `browserPlatform` is the browser's
// whole platform, and `browserHost` the page's loader.
//
// A page has no slots. The origin that serves it is its trust root, so it runs the host
// blob it is served and takes no updates. It has no TCP or UDP sockets: it stands its node
// up through the host's `standUp` (platform.ts) with its own channels (WebSocket, WebRTC).

import { ModuleTable } from "./module-table.js";
import { readHostBlob } from "./host-blob.js";
import { memoryRawFiles } from "../services/fs-memory.js";
import { dec, EMPTY } from "../services/util.js";
import type { PureModules } from "./bundle.js";
import type { EngineExport, EngineImports, EngineInstance } from "./engine-realm.js";
import type { RawFiles } from "../services/fs-files.js";
import type { Platform, PlatformHost } from "./platform.js";
import { PLATFORM_ABI, type PlatformBridge } from "./abi.js";

/** The parts of a host blob, unchecked: a page's own code can run on the blob's wasm
 *  without fetching it again (its libsodium.wasm, under its own glue). */
export { readHostBlob } from "./host-blob.js";

// ── the engine table over WebAssembly ─────────────────────────────────────────

/** WASI errno values, the spec's numbers. */
const ERRNO_SUCCESS = 0, ERRNO_INVAL = 28, ERRNO_NOSYS = 52;

/** The engine's WASI imports, answered as native answers them (native/qjs/qjs.go): the
 *  clock, and ENOSYS for everything else. */
function wasiImports(module: WebAssembly.Module, memory: () => WebAssembly.Memory): Record<string, () => number> {
  const fns: Record<string, (...args: never[]) => number> = {};
  for (const imp of WebAssembly.Module.imports(module)) {
    if (imp.module !== "wasi_snapshot_preview1" || imp.kind !== "function") continue;
    fns[imp.name] = () => ERRNO_NOSYS;
  }
  fns.clock_time_get = ((clockId: number, _precision: bigint, out: number): number => {
    let ns: bigint;
    if (clockId === 0) ns = BigInt(Math.round((performance.timeOrigin + performance.now()) * 1e6));
    else if (clockId === 1) ns = BigInt(Math.round(performance.now() * 1e6));
    else return ERRNO_INVAL;
    new DataView(memory().buffer).setBigUint64(out, ns, true);
    return ERRNO_SUCCESS;
  }) as never;
  fns.proc_exit = (() => { throw new Error("engine: proc_exit"); }) as never;
  return fns as Record<string, () => number>;
}

/** `imports` with the engine's WASI beside them, and the view of the instance they link. */
function link(mod: WebAssembly.Module, imports: EngineImports) {
  let memory!: WebAssembly.Memory;
  const all = { ...imports, wasi_snapshot_preview1: wasiImports(mod, () => memory) } as WebAssembly.Imports;
  const view = (instance: WebAssembly.Instance): EngineInstance => {
    const exports = instance.exports as Record<string, unknown>;
    memory = Object.values(exports).find((v) => v instanceof WebAssembly.Memory) as WebAssembly.Memory;
    // A reactor initializes wasi-libc once, before any other export.
    (exports._initialize as (() => void) | undefined)?.();
    return {
      exported: (name) => {
        const fn = exports[name];
        if (typeof fn !== "function") throw new Error(`engine: no export "${name}"`);
        return fn as (...args: number[]) => number;
      },
      grow: (pages) => { try { return memory.grow(pages); } catch { return -1; } },
      global: (name) => {
        const g = exports[name];
        return g instanceof WebAssembly.Global ? Number(g.value) : null;
      },
      read: (ptr, len) => new Uint8Array(memory.buffer, ptr, len).slice(),
      view: (ptr, len) => new Uint8Array(memory.buffer, ptr, len),
      write: (ptr, bytes) => { new Uint8Array(memory.buffer).set(bytes, ptr); },
      // Nothing to release: the instance goes with its last reference.
      dispose: () => {},
    };
  };
  return { all, view };
}

/** Compiled modules by their bytes, so a realm per app compiles the engine once. */
const compiled = new WeakMap<Uint8Array, WebAssembly.Module>();
/** The engine table over WebAssembly, synchronous as the platform ABI's is. Chromium
 *  compiles a module the size of qjs.wasm synchronously on a page's main thread. */
export const syncWebEngine = (wasm: Uint8Array, imports: EngineImports): EngineInstance => {
  let mod = compiled.get(wasm);
  if (!mod) {
    mod = new WebAssembly.Module(wasm as BufferSource);
    compiled.set(wasm, mod);
  }
  const { all, view } = link(mod, imports);
  return view(new WebAssembly.Instance(mod, all));
};

/** WebCrypto fills at most this much per `getRandomValues` call. */
const RANDOM_DRAW_BYTES = 65536;

/** `n` bytes from the platform CSPRNG (WebCrypto, on Node and in browsers): the entropy
 *  the host's crypto draws for libsodium's `randombytes_buf`, whose wasm build would
 *  otherwise draw one byte per call, and for ML-DSA-65's signing hedge. */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  const c = globalThis.crypto;
  if (!c?.getRandomValues) throw new Error("platform: no CSPRNG (globalThis.crypto.getRandomValues) available");
  for (let at = 0; at < n; at += RANDOM_DRAW_BYTES) c.getRandomValues(out.subarray(at, at + RANDOM_DRAW_BYTES));
  return out;
}

// ── the platform ─────────────────────────────────────────────────────────────

/** The bridge members the Node and browser platforms share. */
export type WebBridge = Pick<PlatformBridge,
  | "random" | "modules"
  | "engineInstantiate" | "engineExport" | "engineCall" | "engineGlobal" | "engineGrow"
  | "engineRead" | "engineView" | "engineWrite" | "engineDispose">;

/** Entropy, private modules in workers and the engine table over WebAssembly, and the
 *  release of every module and instance they hold. */
export function webBridge(): { bridge: WebBridge; teardown(): void } {
  const moduleTable = new ModuleTable();
  const built = new Set<PureModules>();
  const engines = new Map<number, { instance: EngineInstance; fns: EngineExport[] }>();
  let engineSeq = 0;
  const engineOf = (id: number) => {
    const e = engines.get(id);
    if (!e) throw new Error("engine: no such instance");
    return e;
  };
  return {
    bridge: {
      random: randomBytes,
      // Each module in a worker of its own (module-table.ts), the only way V8 stops a call.
      modules: {
        async build(mods) {
          const m = await moduleTable.build(mods);
          built.add(m);
          return { call: m.call, dispose() { built.delete(m); m.dispose(); } };
        },
      },
      engineInstantiate(wasm, imports) {
        engines.set(++engineSeq, { instance: syncWebEngine(wasm, imports), fns: [] });
        return engineSeq;
      },
      engineExport(id, name) {
        const e = engineOf(id);
        return e.fns.push(e.instance.exported(name)) - 1;
      },
      // A fixed arity, as platform.ts calls it, rather than a rest array per call.
      engineCall: (id, fn, a, b, c, d, e, f, g, h, i, j, k, l) =>
        engineOf(id).fns[fn](a, b, c, d, e, f, g, h, i, j, k, l),
      engineGlobal: (id, name) => engineOf(id).instance.global(name),
      engineGrow: (id, pages) => engineOf(id).instance.grow(pages),
      engineRead: (id, ptr, len) => engineOf(id).instance.read(ptr, len),
      engineView: (id, ptr, len) => engineOf(id).instance.view!(ptr, len),
      engineWrite: (id, ptr, bytes) => { engineOf(id).instance.write(ptr, bytes); },
      engineDispose: (id) => { engines.delete(id); },
    },
    teardown() {
      for (const m of built) m.dispose();
      built.clear();
      engines.clear();
    },
  };
}

export interface BrowserPlatformOptions {
  /** The host blob the page is served (build/host.skb): its realm engine and its crypto. */
  hostBlob: Uint8Array;
  /** Where the node keeps its files: its `fs`, and the freshness marks beside it. Default:
   *  memory, gone with the page. */
  files?: RawFiles;
}

/** A page's platform, and the release of every module and instance its host holds. */
export function browserPlatform(o: BrowserPlatformOptions): Platform & { teardown(): void } {
  const web = webBridge();
  const bridge: PlatformBridge = {
    abi: PLATFORM_ABI,
    banner: "seedkernel-browser",
    argv: () => "[]",
    log: (line) => { console.log(line); },
    stdout: () => {},
    stdin: () => EMPTY,
    ...web.bridge,
    hostBlob: () => o.hostBlob,
    stageHost: () => { throw new Error("host: a page runs the host it is served and takes no updates"); },
  };
  return { bridge, fs: o.files ?? memoryRawFiles(), teardown: web.teardown };
}

/** A page's loader: the host blob's own script, run on the browser platform as the Node
 *  loader runs it (loader-node.ts), so the page runs the host the Node and native nodes
 *  run. Evaluating it takes `'unsafe-eval'` in the page's `script-src`. A page that
 *  assembles its node with `bootShell` itself imports the host instead, and takes only the
 *  blob's engine and crypto: `platformHost(browserPlatform(...))`. */
export function browserHost(o: BrowserPlatformOptions): PlatformHost & { teardown(): void } {
  const platform = browserPlatform(o);
  // The loader's globals (abi.ts); a page has no sockets.
  Object.assign(globalThis, { bridge: platform.bridge, __fs: platform.fs, __net: undefined, __udp: undefined });
  // Indirect, so the script runs in global scope, as on every loader, and leaves its entry
  // there.
  (0, eval)(dec.decode(readHostBlob(o.hostBlob).script));
  const g = globalThis as unknown as Record<string, unknown>;
  return {
    runMain: g.runMain, standUp: g.standUp, createRealm: g.createRealm, sodium: g.sodium,
    channels: g.platformChannels, modules: g.platformModules, teardown: platform.teardown,
  } as PlatformHost & { teardown(): void };
}
