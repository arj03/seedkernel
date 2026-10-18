// The engine table on Node and the browser: WebAssembly itself. Guest realms run on it
// (engine-realm.ts) from the same qjs.wasm the native binary runs, so every target has one
// engine and one realm driver.

import { engineRealms, type Engine, type EngineImports, type EngineInstance } from "./engine-realm.js";
import type { RealmFactory } from "./realm-queue.js";

/** WASI errno values, the spec's numbers. */
const ERRNO_SUCCESS = 0, ERRNO_INVAL = 28, ERRNO_NOSYS = 52;

/** Compiled modules by their bytes, so a realm per app compiles the engine once. */
const compiled = new WeakMap<Uint8Array, Promise<WebAssembly.Module>>();

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
      write: (ptr, bytes) => { new Uint8Array(memory.buffer).set(bytes, ptr); },
      // Nothing to release: the instance goes with its last reference.
      dispose: () => {},
    };
  };
  return { all, view };
}

/** The engine table over WebAssembly. Instantiation is asynchronous because browsers refuse
 *  to compile or instantiate a large module synchronously on the main thread. */
export const webEngine: Engine = async (wasm, imports) => {
  let module = compiled.get(wasm);
  if (!module) {
    module = WebAssembly.compile(wasm as BufferSource);
    compiled.set(wasm, module);
  }
  const mod = await module;
  const { all, view } = link(mod, imports);
  return view(await WebAssembly.instantiate(mod, all));
};

const compiledSync = new WeakMap<Uint8Array, WebAssembly.Module>();
/** The same table, synchronous, where the platform may compile on its own thread (Node). */
export const syncWebEngine = (wasm: Uint8Array, imports: EngineImports): EngineInstance => {
  let mod = compiledSync.get(wasm);
  if (!mod) {
    mod = new WebAssembly.Module(wasm as BufferSource);
    compiledSync.set(wasm, mod);
  }
  const { all, view } = link(mod, imports);
  return view(new WebAssembly.Instance(mod, all));
};

let qjsBytes: Promise<Uint8Array> | undefined;
/** qjs.wasm, shipped beside the package's other wasm (browser/). */
function loadQjs(): Promise<Uint8Array> {
  const url = new URL("../../browser/qjs.wasm", import.meta.url);
  const node = (globalThis as { process?: { versions?: { node?: string } } }).process?.versions?.node;
  return qjsBytes ??= node
    ? import("node:fs/promises").then(({ readFile }) => readFile(url)).then((b) => new Uint8Array(b))
    : fetch(url).then((r) => {
      // A page that does not serve the file answers with an error page, which would
      // otherwise reach the compiler and fail there as a bad module.
      if (!r.ok) throw new Error(`engine: ${url.href} was not served (HTTP ${r.status})`);
      return r.arrayBuffer();
    }).then((b) => new Uint8Array(b));
}

/** This target's realm factory (§12.3). A module call is asynchronous here (a worker), so
 *  it is billed to the calling invocation. */
export const createWebRealm: RealmFactory = async (opts) =>
  engineRealms(webEngine, await loadQjs(), { billModules: true })(opts);
