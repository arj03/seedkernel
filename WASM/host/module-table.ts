// The JS target's private pure-module builder (§3, §4). Calls are bounded by killing the
// worker. The native target returns the same interface over a wazero handle.

import {
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_SCRATCH_SIZE,
} from "./wasm-limits.js";
import type { ModuleResult, PureModuleLoader, PureModules } from "./bundle.js";

// ─── module routing ─────────────────────────────────────────────────────

export interface ModuleTableOptions {
  /** Bound in ms on one module call, or one worker load at install, when the call carries
   *  no deadline of its own. A call from a guest carries that guest's remaining execution
   *  segment instead (§4.3). Defaults to the guest budget. On expiry the worker is killed
   *  and respawned and the call answers empty. `Infinity` disables it. */
  deadlineMs?: number;
}

/** What the table holds per module name. The instance lives in the worker; the host holds
 *  the verified bytes (to respawn after a kill), the live worker, and the state that runs
 *  one call at a time under a deadline. */
interface WasmModuleRef {
  /** The verified bytes, retained for the respawn after a kill (§4.3). */
  wasm: Uint8Array;
  /** The live worker, or null after a kill or crash, in which case the next call loads a
   *  fresh one. */
  worker: ModuleWorker | null;
  /** Set once the ref leaves the table (`teardown`). A load still in flight must then kill
   *  what it spawned instead of attaching it. */
  dead: boolean;
  /** One in-flight call per module (§4.3): calls chain on this, so a spinning module burns
   *  at most one core for at most one bound. */
  tail: Promise<unknown>;
  /** The module's scratch size, reported by the worker at load, so an oversized payload
   *  is refused without a round trip. */
  scratchSize: number;
  /** The call awaiting its worker's answer. Calls chain on `tail`, so there is at most one. */
  pending: ((r: ModuleResult) => void) | null;
}

/** Settle the call in flight on `ref`, if there is one. */
function answer(ref: WasmModuleRef, r: ModuleResult): void {
  const settle = ref.pending;
  ref.pending = null;
  settle?.(r);
}

/** The messages a module worker sends back to the table. */
type WorkerMsg =
  | { type: "ready"; scratchSize: number }
  | { type: "loadError"; message: string }
  | { type: "result"; bytes: ArrayBuffer | null; ms: number };

/** A worker as the table uses it: the part Node `worker_threads` and the browser's
 *  dedicated `Worker` have in common. */
interface ModuleWorker {
  onMessage(cb: (msg: WorkerMsg) => void): void;
  onError(cb: (err: unknown) => void): void;
  post(msg: object, transfer?: ArrayBuffer[]): void;
  /** Hold the host's event loop open, or stop. An idle worker must not keep a process
   *  alive, but one with a call in flight must, since an unbounded call arms no timer and
   *  the process would otherwise exit with the caller's promise unsettled. */
  keepAlive(on: boolean): void;
  kill(): void;
}

/** The worker script, one per module: instantiate on `load`, run `handle` on `call`, post
 *  the response back. The §4 ABI checks run here, in the isolate that holds the instance;
 *  a module that fails them reports `loadError` and the whole app is refused (§3.1). */
const moduleWorkerSrc = (): string => `"use strict";
// The module instance's state, one per worker. A kill and respawn resets it (§4.3).
let memory = null, scratch = 0, scratchSize = ${DEFAULT_SCRATCH_SIZE}, handle = null;
// Node's eval:true workers have no Web globals, so the port is parentPort via require. In
// a browser dedicated worker, self is the port.
const port = (typeof require === "function" ? require("node:worker_threads").parentPort : null) ?? self;
const fail = (message) => port.postMessage({ type: "loadError", message: String(message) });
port.onmessage = (e) => {
  const m = e.data;
  if (m.type === "load") {
    let instance;
    try {
      const mod = new WebAssembly.Module(m.wasm);
      // The three AssemblyScript runtime shims and nothing else, the same set every target
      // provides, so whether a module loads never depends on the target. \`seed\` is a
      // constant (a pure transform reads no clock, §4.2) and \`trace\` is a no-op.
      instance = new WebAssembly.Instance(mod, {
        env: {
          abort: (_m, _f, l, c) => { throw new Error("dynamic module abort at " + l + ":" + c); },
          seed: () => 0,
          trace: () => {},
        },
      });
    } catch (err) { fail(err && err.message !== undefined ? err.message : err); return; }
    const exps = instance.exports;
    if (!(exps.memory instanceof WebAssembly.Memory)) { fail("module missing export: memory"); return; }
    if (!(exps.scratch instanceof WebAssembly.Global)) { fail("module missing export: scratch"); return; }
    if (typeof exps.handle !== "function") { fail("module missing export: handle"); return; }
    const offset = exps.scratch.value;
    let size = ${DEFAULT_SCRATCH_SIZE};
    if (exps.scratchSize instanceof WebAssembly.Global) {
      const declared = exps.scratchSize.value;
      if (typeof declared !== "number" || declared < ${DEFAULT_SCRATCH_SIZE}) {
        fail("invalid scratchSize " + declared + " (must be >= ${DEFAULT_SCRATCH_SIZE})"); return;
      }
      size = declared;
    }
    if (typeof offset !== "number" || offset <= 0 || offset + size > exps.memory.buffer.byteLength) {
      fail("scratch offset " + offset + " out of bounds"); return;
    }
    memory = exps.memory; scratch = offset; scratchSize = size; handle = exps.handle;
    port.postMessage({ type: "ready", scratchSize });
    return;
  }
  if (m.type === "call") {
    // A trap, an oversized result or a negative length all give null, which the seam
    // rejects (§12.2); a zero-length answer is still a value. ms is the time spent inside
    // handle, excluding queue wait, and is what the caller's budget is billed (§12.3).
    let bytes = null, wipeLen = m.payload.byteLength;
    const t0 = performance.now();
    try {
      new Uint8Array(memory.buffer, scratch, m.payload.byteLength).set(new Uint8Array(m.payload));
      const len = handle(m.payload.byteLength);
      if (typeof len === "number" && len >= 0 && len <= scratchSize) {
        bytes = new Uint8Array(memory.buffer, scratch, len).slice().buffer;
        wipeLen = Math.max(wipeLen, len);
      }
    } catch { bytes = null; }
    finally {
      // The response has been copied out. Wipe the scratch window so neither the request
      // nor a secret-bearing response lingers in a long-lived instance.
      try { new Uint8Array(memory.buffer, scratch, wipeLen).fill(0); } catch { /* trapped/grown memory */ }
    }
    const ms = performance.now() - t0;
    port.postMessage({ type: "result", bytes, ms }, bytes === null ? [] : [bytes]);
  }
};
`;

let nodeWorkerCtor: Promise<{ new (code: string, opts: { eval: boolean }): ModuleWorkerPort }> | null = null;

/** The part of Node's `Worker` this file uses, typed structurally. */
interface ModuleWorkerPort {
  on(event: "message", cb: (msg: unknown) => void): unknown;
  on(event: "error", cb: (err: unknown) => void): unknown;
  postMessage(msg: unknown, transfer?: unknown[]): void;
  terminate(): Promise<number> | void;
  ref?(): void;
  unref?(): void;
}

/** The part of the DOM's `Worker` this file uses, typed structurally since this tsconfig
 *  has no DOM lib and the global is checked at runtime. */
interface BrowserWorkerLike {
  onmessage?: ((e: { data: unknown }) => void) | null;
  onerror?: ((e: { message?: string }) => void) | null;
  postMessage(msg: unknown, transfer?: unknown[]): void;
  terminate?(): void;
}

/** Start one module worker. Uses the browser `Worker` global when there is one, else Node
 *  `worker_threads`, imported lazily so the browser build never resolves `node:`. */
async function spawnWorker(src: string): Promise<ModuleWorker> {
  const browserCtor = (globalThis as { Worker?: { new (url: string): BrowserWorkerLike } }).Worker;
  if (typeof browserCtor === "function") {
    const url = URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
    const w = new browserCtor(url);
    // Nothing else revokes the blob URL, so without this it would leak one entry per
    // deadline kill for the life of the document.
    URL.revokeObjectURL(url);
    return {
      onMessage: (cb) => { w.onmessage = (e) => cb(e.data as WorkerMsg); },
      onError: (cb) => { w.onerror = () => cb(new Error("module worker failed")); },
      post: (msg, transfer) => w.postMessage(msg, transfer ?? []),
      keepAlive: () => {},
      kill: () => w.terminate?.(),
    };
  }
  if (!nodeWorkerCtor) {
    nodeWorkerCtor = import("node:worker_threads").then((wt) => wt.Worker as { new (code: string, opts: { eval: boolean }): ModuleWorkerPort });
  }
  const WorkerCtor = await nodeWorkerCtor;
  const w = new WorkerCtor(src, { eval: true });
  // An idle worker should not keep the process up; `keepAlive` re-refs it while a call is
  // in flight.
  w.unref?.();
  return {
    onMessage: (cb) => { w.on("message", (m) => cb(m as WorkerMsg)); },
    onError: (cb) => { w.on("error", (err) => cb(err)); },
    post: (msg, transfer) => w.postMessage(msg, transfer ?? []),
    keepAlive: (on) => { if (on) w.ref?.(); else w.unref?.(); },
    kill: () => { void w.terminate(); },
  };
}

export class ModuleTable implements PureModuleLoader {

  /** The default module-call bound (ModuleTableOptions.deadlineMs). */
  private readonly deadlineMs: number;

  constructor(opts: ModuleTableOptions = {}) {
    this.deadlineMs = opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
  }

  // ─── installing WASM modules ─────────────────────────────────────────

  /** Build one slot's modules, all or none (§3.1). A re-install replaces the whole map. */
  async build(mods: { name: string; wasm: Uint8Array }[]): Promise<PureModules> {
    const built = new Map<string, WasmModuleRef>();
    try {
      for (const m of mods) {
        if (m.name.length === 0) throw new Error("table: empty module name");
        if (built.has(m.name)) throw new Error(`table: duplicate module name ${m.name}`);
        built.set(m.name, await this.spawn(m.wasm));
      }
    }
    catch (e) {
      // Release what this attempt started, so a refused bundle leaves no orphaned workers.
      for (const ref of built.values()) this.teardown(ref);
      throw e;
    }
    return {
      call: (name, payload, deadlineMs) => this.callModule(built, name, payload, deadlineMs),
      dispose: () => {
        for (const ref of built.values()) this.teardown(ref);
        built.clear();
      },
    };
  }

  /** Start a module's worker. The load path has already applied the §4.3 memory ceiling
   *  to the bytes, before instantiation allocates anything. The §4 export checks run in
   *  the worker and report `loadError`. */
  private async spawn(wasmBytes: Uint8Array): Promise<WasmModuleRef> {
    if (wasmBytes.length === 0) throw new Error("table: empty wasm bytes");
    const ref: WasmModuleRef = {
      wasm: wasmBytes,
      worker: null,
      dead: false,
      tail: Promise.resolve(),
      scratchSize: 0,
      pending: null,
    };
    await this.load(ref);
    return ref;
  }

  /** Bring `ref`'s worker up: spawn, load, wait for `ready`, or fail. Bounded like a call,
   *  because instantiation runs the start section and could otherwise hang install. */
  private async load(ref: WasmModuleRef): Promise<ModuleWorker> {
    const worker = await spawnWorker(moduleWorkerSrc());
    // The ref may have been released while this was spawning; attaching the worker now
    // would leave it running with nothing able to kill it.
    if (ref.dead) { worker.kill(); throw new Error("table: module was released while it loaded"); }
    ref.worker = worker;
    // Keep the loop open during the load, as during a call: an unbounded table arms no
    // load timer, and the caller is waiting on it.
    worker.keepAlive(true);
    await new Promise<void>((resolve, reject) => {
      let loading = true;
      let timer: ReturnType<typeof setTimeout> | null = null;
      /** Fail the load once, killing the worker. */
      const fail = (err: Error): void => {
        if (!loading) return;
        loading = false;
        if (timer !== null) clearTimeout(timer);
        worker.kill();
        reject(err);
      };
      if (Number.isFinite(this.deadlineMs)) {
        timer = setTimeout(() => fail(new Error(`table: module failed to initialize within ${this.deadlineMs}ms`)),
          this.deadlineMs);
      }
      // One handler for both phases, since load and calls are sequential per module (a
      // call reaches a worker only after `ready`, and a reload runs inside the queued call).
      worker.onMessage((m) => {
        if (m.type === "result") {
          // Only the current worker may answer: a killed or crashed worker can still deliver
          // a late reply, which must not settle the next call.
          if (ref.worker === worker) answer(ref, { bytes: m.bytes === null ? null : new Uint8Array(m.bytes), ms: m.ms });
          return;
        }
        if (!loading) return;
        if (m.type === "ready") {
          loading = false;
          if (timer !== null) clearTimeout(timer);
          ref.scratchSize = m.scratchSize;
          resolve();
        }
        else if (m.type === "loadError") fail(new Error(`table: failed to instantiate wasm: ${m.message}`));
      });
      worker.onError((err) =>
        fail(new Error(`table: module worker failed during load: ${(err as Error)?.message ?? String(err)}`)));
      worker.post({ type: "load", wasm: ref.wasm });
    });
    // Loaded and idle, so stop holding the loop open. (Every failure path above killed the
    // worker.)
    worker.keepAlive(false);
    // Released while the load was in flight: `teardown` had no worker to kill, so kill it
    // here.
    if (ref.dead) { ref.worker = null; worker.kill(); throw new Error("table: module was released while it loaded"); }
    // After the load, an engine crash (not a wasm trap, which the worker reports as a null
    // result) fails the in-flight call with an empty answer, and the next call loads a
    // fresh worker.
    worker.onError(() => {
      if (ref.worker !== worker) return;
      ref.worker = null;
      answer(ref, { bytes: null, ms: 0 });
    });
    return worker;
  }

  // ─── public API ──────────────────────────────────────────────────────

  /** Invoke one module in this private set, returning its response bytes or null (§4).
   *  The set is already per slot, so lookup is by module name alone. `deadlineMs` is the
   *  call's whole budget; past it the call answers empty and the worker is killed and
   *  respawned, so a module that never returns fails like a trap. A guest's call carries
   *  its own remaining segment (§4.3). */
  private async callModule(modules: Map<string, WasmModuleRef>, module: string, payload: Uint8Array, deadlineMs?: number): Promise<ModuleResult> {
    const w = modules.get(module);
    if (!w) return { bytes: null, ms: 0 };
    if (payload.length > w.scratchSize) return { bytes: null, ms: 0 };
    const bound = deadlineMs ?? this.deadlineMs;
    // Payload bytes are accounted by the realm's `ActiveHostCalls` ledger under the
    // enclosing `host.call` (§12.3). Execution is accounted here: one in-flight call per
    // module, so a spinning module burns one core for one bound.
    const started = w.tail.then(() => this.call(w, payload, bound));
    w.tail = started.catch(() => {});
    return started;
  }

  /** Run one call on a module's worker, under `bound`. Never rejects: a dead worker, a
   *  failed reload and a deadline kill all give the same empty answer a trap does. */
  private async call(w: WasmModuleRef, payload: Uint8Array, bound: number): Promise<ModuleResult> {
    // After a kill or crash there is no worker, so load a fresh instance with clean state.
    // Calls chain on `tail`, so this is the only load in flight. A failed load has killed
    // what it spawned; this call answers empty and the next one retries.
    const worker = w.worker ?? await this.load(w).catch(() => null);
    if (worker === null) { w.worker = null; return { bytes: null, ms: 0 }; }
    // Own an exact-sized, transferable buffer even when the caller passed a Node Buffer.
    const input = new Uint8Array(payload);
    // Hold the loop open for the call, since an unbounded call arms no timer.
    worker.keepAlive(true);
    return new Promise<ModuleResult>((resolve) => {
      let timer: ReturnType<typeof setTimeout> | null = null;
      w.pending = (r) => {
        if (timer !== null) clearTimeout(timer);
        worker.keepAlive(false);
        resolve(r);
      };
      if (Number.isFinite(bound)) {
        timer = setTimeout(() => {
          // The module overran its bound. Kill the worker (the only interrupt that works
          // mid-loop), answer empty, and let the next call load a fresh one. The caller is
          // billed the full bound, so a guest looping on a wedged module exhausts its budget.
          // Every other path that retires this worker settles the call first and clears
          // this timer, so the worker here is still the current one.
          answer(w, { bytes: null, ms: bound });
          w.worker = null;
          worker.kill();
        }, bound);
      }
      worker.post({ type: "call", payload: input.buffer }, [input.buffer]);
    });
  }

  /** Kill a module's worker and settle any waiting call as empty, so no caller hangs. */
  private teardown(ref: WasmModuleRef): void {
    // Mark first: a load may be in flight, and when it finishes it must kill what it
    // spawned instead of attaching it.
    ref.dead = true;
    answer(ref, { bytes: null, ms: 0 });
    ref.worker?.kill();
    ref.worker = null;
  }
}
