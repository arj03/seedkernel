// The JS target's builder for one slot's private pure modules (README §3, §4). The native
// target returns the same interface over an opaque wazero-owned handle.
//
// **A module call is bounded here, by construction.** The JS platform's WebAssembly
// exposes no fuel or timeout, and a WASM call is one bytecode to QuickJS's interrupt
// handler, so no budget can land *inside* a call (§4.3). The bound is structural instead:
// each module lives in its own worker — a dedicated isolate, instantiated with the slot, so
// statics live there — and a call carries a deadline. On expiry the host kills the worker
// (`terminate` is the one interrupt JS exposes, and it works mid-loop), answers empty
// exactly as a trap does, and respawns. A spinning module burns at most one core for at
// most one budget. The native target holds the same contract at its own engine lever.
//
// A module is a PURE TRANSFORM (§4): it exports `memory`, a `scratch` global and
// `handle(input_len)`, imports nothing, and cannot call back. The table is the host's only
// slot construction, which is why nothing here touches crypto.

import {
  checkModuleMemory,
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_MAX_MODULE_MEMORY_BYTES,
  DEFAULT_SCRATCH_SIZE,
} from "../core/wasm-limits.js";
import type { PureModuleLoader, PureModules } from "./bundle.js";

// ─── module routing ─────────────────────────────────────────────────────

export interface ModuleTableOptions {
  /** Ceiling on a module's declared initial *and* maximum linear memory, in bytes.
   *  A module above it — or one declaring no maximum at all — is refused at install
   *  (§4.3). Defaults to the shared `DEFAULT_MAX_MODULE_MEMORY_BYTES` that
   *  `loadBundleModules` also applies; lower it to hold this target's builds to
   *  something tighter than the bundle path requires. */
  maxModuleMemoryBytes?: number;
  /** Bound on one module invocation — one call, and one worker load at install — in ms,
   *  for a call that carries no deadline of its own; a call from a GUEST carries that
   *  guest's remaining execution segment instead (§4.3). Defaults to the shared guest
   *  budget, one number for untrusted code wherever it runs. On expiry the worker is
   *  killed and respawned and the call answers empty. `Infinity` disables it. */
  deadlineMs?: number;
}

/** What the table holds at one name. The instance lives in the worker; the host holds the
 *  verified bytes (for the respawn after a kill), the live worker, and the bookkeeping that
 *  makes one call at a time answer within one deadline. */
interface WasmModuleRef {
  /** The verified bytes, retained for the respawn after a kill (§4.3). */
  wasm: Uint8Array;
  /** The live worker, or null while a killed module respawns. */
  worker: ModuleWorker | null;
  /** The respawn in progress, shared so concurrent callers wait on one. EVERY respawn is
   *  recorded here, including the one a deadline kill starts: a load does not adopt its
   *  worker until it has spawned, so a second load started in that window would stand up an
   *  orphan isolate — still spinning, which is what the bound exists to stop. */
  spawning: Promise<void> | null;
  /** Set once the ref leaves the table (`teardown`). A load in flight then must kill what
   *  it spawned rather than adopt it onto a ref nothing holds — the worker would be
   *  unreachable and unkillable. */
  dead: boolean;
  /** One in-flight call per module (§3's "one transform at a time"): calls chain on this,
   *  so a spinning module burns at most one core for at most one bound. */
  tail: Promise<unknown>;
  /** The module's scratch region, read off the worker's instance at load, so an oversized
   *  payload is refused without a worker round-trip. */
  scratchSize: number;
  /** Calls awaiting their worker's answer, by the id this host minted. */
  pending: Map<number, (bytes: Uint8Array | null) => void>;
}

/** One worker message, the whole protocol between the table and a module worker. */
type WorkerMsg =
  | { type: "ready"; scratchSize: number }
  | { type: "loadError"; message: string }
  | { type: "result"; id: number; bytes: ArrayBuffer | null };

/** A worker port as the table uses it — the subset the two platforms' workers share
 *  (Node `worker_threads` and the browser's dedicated `Worker`). */
interface ModuleWorker {
  onMessage(cb: (msg: WorkerMsg) => void): void;
  onError(cb: (err: unknown) => void): void;
  post(msg: object, transfer?: ArrayBuffer[]): void;
  /** Hold the host's event loop open, or stop holding it. An idle worker must never keep a
   *  process alive (a Node CLI that installed a bundle would never exit), but one with a
   *  call in flight must: an unbounded call arms no timer, so the process would exit
   *  mid-transform with its caller's promise unsettled. Node's ref/unref; a no-op in the
   *  browser. */
  keepAlive(on: boolean): void;
  kill(): void;
}

/** The worker script, one copy per module. It is the module's whole world: instantiate
 *  on `load`, run `handle` on `call`, post the response back. The §4 ABI validation runs
 *  HERE, in the isolate that holds the instance — a module that fails it reports
 *  `loadError` and the bind refuses the whole app (§3.1). */
const moduleWorkerSrc = (): string => `"use strict";
// The §4 ABI instance, one per worker: this is where the module's statics live, which
// is what a kill-and-respawn resets (§4.3).
let memory = null, scratch = 0, scratchSize = ${DEFAULT_SCRATCH_SIZE}, handle = null;
// Node's eval:true workers expose no Web globals — the port is parentPort, reached
// through require. A browser worker is a normal dedicated worker, where self is the
// port. One line, both platforms.
const port = (typeof require === "function" ? require("node:worker_threads").parentPort : null) ?? self;
const fail = (message) => port.postMessage({ type: "loadError", message: String(message) });
port.onmessage = (e) => {
  const m = e.data;
  if (m.type === "load") {
    let instance;
    try {
      const mod = new WebAssembly.Module(m.wasm);
      // The three AssemblyScript runtime shims and nothing else — the same set every
      // other target resolves (native/main.go), so "does this module load" never depends
      // on which target it landed on. All three are inert: \`seed\` is a constant, because
      // a pure transform reaches no clock (§4.2), and \`trace\` drops its arguments.
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
    // A trap, an oversized result, a negative length — all the same empty answer, the
    // shape a caller downstream already reads for a failed transform.
    let bytes = null;
    try {
      new Uint8Array(memory.buffer, scratch, m.payload.byteLength).set(new Uint8Array(m.payload));
      const len = handle(m.payload.byteLength);
      if (typeof len === "number" && len >= 0 && len <= scratchSize) {
        bytes = new Uint8Array(memory.buffer, scratch, len).slice().buffer;
      }
    } catch { bytes = null; }
    port.postMessage({ type: "result", id: m.id, bytes }, bytes === null ? [] : [bytes]);
  }
};
`;

let nodeWorkerCtor: Promise<{ new (code: string, opts: { eval: boolean }): ModuleWorkerPort }> | null = null;

/** The Node side of a worker, structurally — @types/node's `Worker` minus what this
 *  file never uses, so the table reads one shape regardless of platform. */
interface ModuleWorkerPort {
  on(event: "message", cb: (msg: unknown) => void): unknown;
  on(event: "error", cb: (err: unknown) => void): unknown;
  postMessage(msg: unknown, transfer?: unknown[]): void;
  terminate(): Promise<number> | void;
  ref?(): void;
  unref?(): void;
}

/** The browser side of a worker — the DOM's `Worker`, structurally, since this
 *  tsconfig carries no DOM lib and the global is checked at runtime. */
interface BrowserWorkerLike {
  onmessage?: ((e: { data: unknown }) => void) | null;
  onerror?: ((e: { message?: string }) => void) | null;
  postMessage(msg: unknown, transfer?: unknown[]): void;
  terminate?(): void;
}

/** Stand up one module worker. Browser first — the global `Worker` is the detection —
 *  Node `worker_threads` second, loaded lazily so the browser build never resolves the
 *  `node:` import. */
async function spawnWorker(src: string): Promise<ModuleWorker> {
  const browserCtor = (globalThis as { Worker?: { new (url: string): BrowserWorkerLike } }).Worker;
  if (typeof browserCtor === "function") {
    const url = URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
    const w = new browserCtor(url);
    // The worker has its script, and the URL is a document-lifetime blob-registry entry
    // nothing else revokes — a leak that would grow one entry per deadline kill.
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
  // An IDLE worker is never a reason for the process to stay up; one with work in flight
  // is, and `keepAlive` re-refs it for exactly that window.
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

  /** The §4.3 memory ceiling this host holds installs to. */
  private readonly maxModuleMemoryBytes: number;

  /** The default module-call bound (ModuleTableOptions.deadlineMs). */
  private readonly deadlineMs: number;

  /** Ids for calls in flight to this table's workers — one stream, so no two calls share
   *  an id and a worker's answer correlates with the call that asked. */
  private callSeq = 0;

  constructor(opts: ModuleTableOptions = {}) {
    this.maxModuleMemoryBytes = opts.maxModuleMemoryBytes ?? DEFAULT_MAX_MODULE_MEMORY_BYTES;
    this.deadlineMs = opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
  }

  // ─── installing WASM modules ─────────────────────────────────────────

  /** Build one slot's modules, all or none (§3.1) — the one way code arrives, and the
   *  only entry point that stands anything up; `dispose` on the returned value is the
   *  only one that takes it down.
   *
   *  Every module is spawned, instantiated and validated BEFORE anything is written, and
   *  the app's whole module map is built first and then assigned under its key — so the
   *  commit is ONE assignment, with no window in which some of an app's modules are the new
   *  version and the rest the old.
   *
   *  A re-install REPLACES the app's map rather than merging into it, so a bundle dropping
   *  a module from its manifest leaves nothing of the old one behind.
   *
   *  Async because each module stands up a worker; this returns when every one has reported
   *  `ready`, or throws on the first `loadError`. */
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
      // Nothing above touched the table; release what the attempt stood up, so a refused
      // bundle leaves no orphaned isolates behind.
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

  /** Stand up a module's worker. The §4.3 memory ceiling is read off the bytes HERE,
   *  before any worker exists, because instantiation is what allocates the declared initial
   *  memory (wasm-limits.ts, which also refuses an imported or shared memory); the §4 export
   *  checks run in the worker on the same load and report `loadError`. */
  private async spawn(wasmBytes: Uint8Array): Promise<WasmModuleRef> {
    if (wasmBytes.length === 0) throw new Error("table: empty wasm bytes");
    checkModuleMemory(wasmBytes, this.maxModuleMemoryBytes);
    const ref: WasmModuleRef = {
      wasm: wasmBytes,
      worker: null,
      spawning: null,
      dead: false,
      tail: Promise.resolve(),
      scratchSize: 0,
      pending: new Map(),
    };
    await this.load(ref);
    return ref;
  }

  /** Bring `ref`'s worker up: spawn, load, wait for `ready` — or fail. Bounded like a call,
   *  because instantiation RUNS the start section, so an unbounded load is a wedged node at
   *  install. */
  private async load(ref: WasmModuleRef): Promise<void> {
    const worker = await spawnWorker(moduleWorkerSrc());
    // The ref may have left its set while this was spawning (a disposed slot, a refused
    // bundle). Adopting the worker now would leave it unreachable,
    // unkillable, and still running whatever it was given.
    if (ref.dead) { worker.kill(); throw new Error("table: module was released while it loaded"); }
    ref.worker = worker;
    // A load holds the loop open for the same reason a call does: an unbounded table arms
    // no load timer, and a bind is something its caller is waiting on.
    worker.keepAlive(true);
    await new Promise<void>((resolve, reject) => {
      let loading = true;
      let timer: ReturnType<typeof setTimeout> | null = null;
      if (Number.isFinite(this.deadlineMs)) {
        timer = setTimeout(() => {
          if (!loading) return;
          loading = false;
          worker.kill();
          reject(new Error(`table: module failed to initialize within ${this.deadlineMs}ms`));
        }, this.deadlineMs);
      }
      // One handler for both phases: load and calls are strictly sequential per module (a
      // call reaches a worker only after `ready`, and a respawn holds the queue).
      worker.onMessage((m) => {
        if (m.type === "result") {
          const settle = ref.pending.get(m.id);
          if (settle) { ref.pending.delete(m.id); settle(m.bytes === null ? null : new Uint8Array(m.bytes)); }
          return;
        }
        if (!loading) return;
        if (m.type === "ready") {
          loading = false;
          if (timer !== null) clearTimeout(timer);
          ref.scratchSize = m.scratchSize;
          resolve();
        }
        else if (m.type === "loadError") {
          loading = false;
          if (timer !== null) clearTimeout(timer);
          worker.kill();
          reject(new Error(`table: failed to instantiate wasm: ${m.message}`));
        }
      });
      worker.onError((err) => {
        if (!loading) return;
        loading = false;
        if (timer !== null) clearTimeout(timer);
        worker.kill();
        reject(new Error(`table: module worker failed during load: ${(err as Error)?.message ?? String(err)}`));
      });
      worker.post({ type: "load", wasm: ref.wasm });
    });
    // Loaded and idle: it holds nothing open until a call is posted. (Every rejection path
    // above killed the worker.)
    worker.keepAlive(false);
    // A release that landed while the load was in flight: `teardown` had no worker to kill,
    // so this one must not be left standing.
    if (ref.dead) { ref.worker = null; worker.kill(); throw new Error("table: module was released while it loaded"); }
    // After the load settles, an engine crash — not a wasm trap, which the worker catches
    // and reports as a null result — fails the in-flight call with the same empty answer
    // and leaves the module to respawn.
    worker.onError(() => {
      if (ref.worker !== worker) return;
      for (const settle of ref.pending.values()) settle(null);
      ref.pending.clear();
      ref.worker = null;
    });
  }

  // ─── public API ──────────────────────────────────────────────────────

  /** Invoke one module in this private set, returning its response bytes or null. The
   *  scratch-region contract (§4) writes input at scratch, calls handle, and reads the
   *  response back. The set itself is the scope, so no app key participates in lookup.
   *
   *  Async (a call crosses an isolate) and BOUNDED: `deadlineMs` is the call's whole
   *  budget, and exceeding it answers empty with the worker killed and respawned, so a
   *  module that never returns fails like a trap instead of holding the node's thread. A
   *  guest's call carries its own remaining segment (§4.3). */
  private async callModule(modules: Map<string, WasmModuleRef>, module: string, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array | null> {
    const w = modules.get(module);
    if (!w) return null;
    if (payload.length > w.scratchSize) return null;
    const bound = deadlineMs ?? this.deadlineMs;
    // One in-flight call per module: the next call starts only when the previous one
    // settled, so a spinning module burns one core for one bound, not one per caller.
    const started = w.tail.then(() => this.call(w, payload, bound));
    w.tail = started.catch(() => {});
    return started;
  }

  /** Run one call on a module's worker, under `bound`. Never rejects: every failure —
   *  a dead worker, a respawn that could not stand up, a worker killed at the deadline
   *  — is the same empty answer a trap produces today, so nothing downstream changes. */
  private async call(w: WasmModuleRef, payload: Uint8Array, bound: number): Promise<Uint8Array | null> {
    // The previous call may have killed the worker; run on the fresh instance the kill
    // asked for, whose statics are gone — which is the point.
    if (w.worker === null) await this.respawn(w);
    const worker = w.worker;
    if (!worker) return null;
    const input = payload.slice();
    // Held open for the duration of the call: an unbounded call arms no timer, and the
    // caller is awaiting an answer only this worker can give.
    worker.keepAlive(true);
    return new Promise<Uint8Array | null>((resolve) => {
      const id = ++this.callSeq;
      let timer: ReturnType<typeof setTimeout> | null = null;
      w.pending.set(id, (bytes) => {
        if (timer !== null) clearTimeout(timer);
        worker.keepAlive(false);
        resolve(bytes);
      });
      if (Number.isFinite(bound)) {
        timer = setTimeout(() => {
          // The module did not return within its bound. Kill the isolate — the engine's
          // one interrupt, which works even mid-loop — answer empty, and respawn.
          w.pending.delete(id);
          resolve(null);
          if (w.worker === worker) {
            w.worker = null;
            worker.kill();
            // Recorded as THE respawn, not started loose: the call queued behind this one
            // resumes before the new worker has spawned, and a second load started there
            // would orphan an isolate running the code the kill was for.
            void this.respawn(w);
          }
        }, bound);
      }
      worker.post({ type: "call", id, payload: input.buffer }, [input.buffer]);
    });
  }

  /** Stand a killed module's worker back up — once, however many callers ask. The
   *  promise is parked on the ref so the deadline path and the next call share one
   *  load; it never rejects, because a module that cannot be respawned is simply a
   *  module whose calls answer empty until it is unbound. */
  private respawn(w: WasmModuleRef): Promise<void> {
    if (w.spawning === null) {
      // A load that failed leaves no usable worker behind (every failure path inside it
      // kills what it spawned), so the ref goes back to "no worker" and the next call
      // asks again.
      const done: Promise<void> = this.load(w)
        .catch(() => { w.worker = null; })
        .then(() => { if (w.spawning === done) w.spawning = null; });
      w.spawning = done;
    }
    return w.spawning;
  }

  /** Kill a module's worker and settle everything waiting on it as empty — the module
   *  is gone, and no caller may hang on a promise nothing can settle. */
  private teardown(ref: WasmModuleRef): void {
    // Marked first: a respawn may be mid-flight, and the load that finishes after this
    // returns has to kill what it spawned rather than adopt it onto a departed ref.
    ref.dead = true;
    for (const settle of ref.pending.values()) settle(null);
    ref.pending.clear();
    ref.worker?.kill();
    ref.worker = null;
  }
}
