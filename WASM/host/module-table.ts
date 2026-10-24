// The JS target's private pure-module builder (§3, §4). Calls are bounded by killing the
// worker. The native target returns the same interface over a wazero handle.

import {
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_SCRATCH_SIZE,
} from "./wasm-limits.js";
import { MODULE_FAILED, moduleSet, type ModuleResult, type PureModuleLoader, type PureModules } from "./bundle.js";
import { moduleShims, scratchModule } from "./pure-module.js";
import { errMessage } from "../services/util.js";
import type { Worker as NodeWorker } from "node:worker_threads";

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

/** The worker script, one per module: instantiate on `load`, run calls on `call`, post the
 *  response back. The §4 ABI is `scratchModule` (pure-module.ts), carried here by its
 *  source and run in the isolate that holds the instance; a module that fails it reports
 *  `loadError` and the whole app is refused (§3.1). */
const moduleWorkerSrc = (): string => `"use strict";
const scratchModule = ${scratchModule.toString()};
const moduleShims = ${moduleShims.toString()};
// The module, once loaded. A kill and respawn resets it (§4.3).
let module = null;
// Node's eval:true workers have no Web globals, so the port is parentPort via require. In
// a browser dedicated worker, self is the port.
const port = (typeof require === "function" ? require("node:worker_threads").parentPort : null) ?? self;
const fail = (message) => port.postMessage({ type: "loadError", message: String(message) });
port.onmessage = (e) => {
  const m = e.data;
  if (m.type === "load") {
    try {
      const exps = new WebAssembly.Instance(new WebAssembly.Module(m.wasm), moduleShims()).exports;
      const mem = exps.memory instanceof WebAssembly.Memory ? exps.memory : null;
      module = scratchModule({
        handle: typeof exps.handle === "function" ? exps.handle : undefined,
        global: (name) => (exps[name] instanceof WebAssembly.Global ? exps[name].value : null),
        memoryBytes: () => (mem ? mem.buffer.byteLength : -1),
        read: (ptr, len) => new Uint8Array(mem.buffer, ptr, len).slice(),
        write: (ptr, bytes) => { new Uint8Array(mem.buffer).set(bytes, ptr); },
        wipe: (ptr, len) => { new Uint8Array(mem.buffer, ptr, len).fill(0); },
      }, ${DEFAULT_SCRATCH_SIZE});
    } catch (err) { fail(err && err.message !== undefined ? err.message : err); return; }
    port.postMessage({ type: "ready", scratchSize: module.size });
    return;
  }
  if (m.type === "call") {
    // A trap gives null, which the seam rejects (§12.2); a zero-length answer is still a
    // value. ms is the time spent inside the call, excluding queue wait, and is what the
    // caller's budget is billed (§12.3).
    let bytes = null;
    const t0 = performance.now();
    try { const r = module.call(new Uint8Array(m.payload)); bytes = r === null ? null : r.buffer; }
    catch { bytes = null; }
    const ms = performance.now() - t0;
    port.postMessage({ type: "result", bytes, ms }, bytes === null ? [] : [bytes]);
  }
};
`;

let nodeWorkerCtor: Promise<typeof NodeWorker> | null = null;

/** One exchange with `worker`, a load or a call: hold the loop open until it ends, since an
 *  unbounded one arms no timer and its caller is waiting, and run `expire` once it has
 *  taken `ms` (`Infinity` never). Answers the release, which the answer calls. */
function exchange(worker: ModuleWorker, ms: number, expire: () => void): () => void {
  worker.keepAlive(true);
  const timer = Number.isFinite(ms) ? setTimeout(expire, ms) : undefined;
  return () => {
    clearTimeout(timer);
    worker.keepAlive(false);
  };
}

/** Start one module worker. Uses the browser `Worker` global when there is one, else Node
 *  `worker_threads`, imported lazily so the browser build never resolves `node:`. */
async function spawnWorker(src: string): Promise<ModuleWorker> {
  if (typeof Worker === "function") {
    const url = URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
    const w = new Worker(url);
    // Nothing else revokes the blob URL, so without this it would leak one entry per
    // deadline kill for the life of the document.
    URL.revokeObjectURL(url);
    return {
      onMessage: (cb) => { w.onmessage = (e) => cb(e.data as WorkerMsg); },
      onError: (cb) => { w.onerror = () => cb(new Error("module worker failed")); },
      post: (msg, transfer) => w.postMessage(msg, transfer ?? []),
      keepAlive: () => {},
      kill: () => w.terminate(),
    };
  }
  if (!nodeWorkerCtor) {
    nodeWorkerCtor = import("node:worker_threads").then((wt) => wt.Worker);
  }
  const w = new (await nodeWorkerCtor)(src, { eval: true });
  // An idle worker should not keep the process up; `keepAlive` re-refs it while a call is
  // in flight.
  w.unref();
  return {
    onMessage: (cb) => { w.on("message", (m) => cb(m as WorkerMsg)); },
    onError: (cb) => { w.on("error", cb); },
    post: (msg, transfer) => w.postMessage(msg, transfer ?? []),
    keepAlive: (on) => { if (on) w.ref(); else w.unref(); },
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

  /** Build one slot's modules, all or none (§3.1), their workers loading side by side, so a
   *  refused bundle leaves no orphaned workers. Names and bytes were checked at install
   *  (bundle.ts). */
  build(mods: { name: string; wasm: Uint8Array }[]): Promise<PureModules> {
    return moduleSet(mods, (wasm) => this.spawn(wasm),
      (ref, payload, deadlineMs) => this.callModule(ref, payload, deadlineMs),
      (ref) => this.teardown(ref));
  }

  /** Start a module's worker. The load path has already applied the §4.3 memory ceiling
   *  to the bytes, before instantiation allocates anything. The §4 export checks run in
   *  the worker and report `loadError`. */
  private async spawn(wasmBytes: Uint8Array): Promise<WasmModuleRef> {
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
    /** Kill what this load spawned once the ref is released, since nothing else can. */
    const released = () => {
      worker.kill();
      return new Error("table: module was released while it loaded");
    };
    // Released while this was spawning.
    if (ref.dead) throw released();
    ref.worker = worker;
    await new Promise<void>((resolve, reject) => {
      let loading = true;
      /** End the load once: loaded, or failed, which kills the worker. */
      const settle = (err?: Error): void => {
        if (!loading) return;
        loading = false;
        done();
        if (!err) return resolve();
        worker.kill();
        reject(err);
      };
      const done = exchange(worker, this.deadlineMs,
        () => settle(new Error(`table: module failed to initialize within ${this.deadlineMs}ms`)));
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
          ref.scratchSize = m.scratchSize;
          settle();
        }
        else if (m.type === "loadError") settle(new Error(`table: failed to instantiate wasm: ${m.message}`));
      });
      worker.onError((err) =>
        settle(new Error(`table: module worker failed during load: ${errMessage(err)}`)));
      worker.post({ type: "load", wasm: ref.wasm });
    });
    // Released while the load was in flight.
    if (ref.dead) {
      ref.worker = null;
      throw released();
    }
    // After the load, an engine crash (not a wasm trap, which the worker reports as a null
    // result) fails the in-flight call with an empty answer, and the next call loads a
    // fresh worker.
    worker.onError(() => {
      if (ref.worker !== worker) return;
      ref.worker = null;
      answer(ref, MODULE_FAILED);
    });
    return worker;
  }

  // ─── calls ───────────────────────────────────────────────────────────

  /** Invoke one module, returning its response bytes or null (§4). `deadlineMs` is the
   *  call's whole budget; past it the call answers empty and the worker is killed and
   *  respawned, so a module that never returns fails like a trap. A guest's call carries
   *  its own remaining segment (§4.3). */
  private async callModule(w: WasmModuleRef, payload: Uint8Array, deadlineMs?: number): Promise<ModuleResult> {
    if (payload.length > w.scratchSize) return MODULE_FAILED;
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
    // Released while this call waited its turn: loading would start a worker only to kill it.
    if (w.dead) return MODULE_FAILED;
    // After a kill or crash there is no worker, so load a fresh instance with clean state.
    // Calls chain on `tail`, so this is the only load in flight. A failed load has killed
    // what it spawned; this call answers empty and the next one retries.
    const worker = w.worker ?? await this.load(w).catch(() => null);
    if (worker === null) {
      w.worker = null;
      return MODULE_FAILED;
    }
    // Own an exact-sized, transferable buffer even when the caller passed a Node Buffer.
    const input = new Uint8Array(payload);
    return new Promise<ModuleResult>((resolve) => {
      const done = exchange(worker, bound, () => {
        // The module overran its bound. Kill the worker (the only interrupt that works
        // mid-loop), answer empty, and let the next call load a fresh one. The caller is
        // billed the full bound, so a guest looping on a wedged module exhausts its budget.
        // Every other path that retires this worker settles the call first and clears
        // this timer, so the worker here is still the current one.
        answer(w, { bytes: null, ms: bound });
        w.worker = null;
        worker.kill();
      });
      w.pending = (r) => {
        done();
        resolve(r);
      };
      worker.post({ type: "call", payload: input.buffer }, [input.buffer]);
    });
  }

  /** Kill a module's worker and settle any waiting call as empty, so no caller hangs. */
  private teardown(ref: WasmModuleRef): void {
    // Mark first: a load may be in flight, and when it finishes it must kill what it
    // spawned instead of attaching it.
    ref.dead = true;
    answer(ref, MODULE_FAILED);
    ref.worker?.kill();
    ref.worker = null;
  }
}
