// The module table (README §3, §4), as the JS targets implement it.
//
// **Host code, not core.** What is core about the table is the CONTRACT — the table,
// the §4 module ABI, the bind/unbind semantics, and the §4.3 memory ceiling
// (core/wasm-limits.ts). This file is one platform's implementation of it; the native
// target's is a wazero map in Go behind its byte bridge (native/main.go), and neither
// is more canonical than the other. It sits with the other backends — `fs-node.ts`,
// `safe-js.ts` — for the same reason they do.
//
// **A module call is bounded here, by construction.** The JS platform's WebAssembly
// exposes no fuel or timeout, and QuickJS ticks its interrupt handler between bytecode
// executions while a WASM call is one bytecode — so no budget can land *inside* a call
// (§4.3). The bound is structural instead: **each module lives in its own worker — a
// dedicated isolate, instantiated once at bind, so statics live there — and a call
// carries a deadline.** On expiry the host kills the worker (the engine destroys the
// isolate, even mid-loop; `terminate` is the one interrupt mechanism JS exposes),
// answers the call with an empty response exactly as a trap does, and respawns a fresh
// instance. A spinning module burns at most one core for at most one budget. The native
// target holds the same contract at its own engine lever (native/main.go,
// `SEEDKERNEL_MODULE_DEADLINE_MS`).
//
// The table is a **contract, not an artifact**: the table (`apps[appKey].get(module)`),
// the pure-transform module ABI (§4), and the bind/unbind semantics (§3.1). Its whole
// implementation is the two `Map`s below. The outer level is an INSTALL RECORD — what
// a bundle load created — and the inner level is the app's module map, which is what a
// call resolves: `apps[appKey].modules[name] = wasm_bytes`. There is nothing to
// instantiate beside it, no module-id indirection, and no second table to keep in sync
// with a first.
//
// **Two levels, because there are two things.** An app is what installs, what a binding
// points at and what `revoke` removes; a module is what a call resolves. Encoding both
// into one string key — `"<author hex>:<app>:<module>"` — bought a flat map at the cost of
// a codec: a charset rule so the module half could not contain the separator, a
// fixed-width author half so the app half could, a prefix scan for the unbind, and an
// argument about why the author hex must not be truncated lest one author grind their way
// onto another's names. Every one of those defends a shared namespace, and there is no
// shared namespace: a guest reaches only its own app's modules, the routing points at app
// keys, and a table name never leaves the host (§5.1). The outer key IS the ownership,
// visible without parsing anything.
//
// A module is a PURE TRANSFORM (§4): it exports `memory`, a `scratch` global, and
// `handle(input_len)`; the host stages input at `scratch`, calls `handle`, and reads the
// response back from `scratch`. Modules import nothing — no host seam, no I/O, no
// callback. Inbound delivery reaches an app's GUEST (§12.10), and the guest drives its
// modules by their bare name through the guest seam (README §12.2); a host-side
// embedder reaches the same path directly with `callModule`, and does all I/O and
// authorization itself. Every entry is an installed WASM module: a bundle is the one
// way code arrives (§12.4), so the table holds one kind of thing and `callModule` has
// one path through it.
//
// The table is the host's ONLY install state. There is no ownership register beside it,
// because ownership is the outer key (§5.1) — so who may bind a module is answered by
// where it sits, and nothing can fall out of step with the table. That is also why
// nothing here touches crypto: hashing belongs to the loader (`genesisHash`, bundle.ts),
// and this component is the `Map` §3 says it is.
//
// Authenticity is the transport's job (the AKE channel attributes every frame), not a
// per-message signature — so there is no signature wrapper and no signer scoping here.

import {
  checkModuleMemory,
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_MAX_MODULE_MEMORY_BYTES,
  DEFAULT_SCRATCH_SIZE,
} from "../core/wasm-limits.js";

// ─── module routing ─────────────────────────────────────────────────────

export interface ModuleTableOptions {
  /** Ceiling on a module's declared initial *and* maximum linear memory, in bytes.
   *  A module above it — or one declaring no maximum at all — is refused at install
   *  (§4.3). Defaults to the shared `DEFAULT_MAX_MODULE_MEMORY_BYTES` that
   *  `installBundle` also applies; lower it to hold this host's direct installs to
   *  something tighter than the bundle path requires. */
  maxModuleMemoryBytes?: number;
  /** Bound on one module invocation — one call, and one worker load at install — in
   *  milliseconds, for a call that carries no deadline of its own. A call from a
   *  GUEST carries the calling guest's remaining execution segment (§4.3, "charged to
   *  the calling guest's budget" made literal): the seam passes it through, so this
   *  default is what a host-side embedder's `callModule` gets, and it defaults to the
   *  shared guest budget (`DEFAULT_GUEST_DEADLINE_MS`) — one number for untrusted code
   *  wherever it runs. On expiry the module's worker is killed and respawned and the
   *  call answers empty, exactly as a trap would. `Infinity` disables the bound. */
  deadlineMs?: number;
}

/** What the table holds at one name: a module running in its own worker, reached by
 *  name through `callModule`. The instance itself lives in the worker — the host holds
 *  the verified bytes (for the respawn after a kill), the live worker, and the bookkeeping
 *  that makes one call at a time answer within one deadline. */
interface WasmModuleRef {
  /** The verified bytes, retained for the respawn after a kill (§4.3). */
  wasm: Uint8Array;
  /** The live worker, or null while a killed module respawns. */
  worker: ModuleWorker | null;
  /** The respawn in progress, shared so concurrent callers wait on one. EVERY respawn
   *  is recorded here, including the one a deadline kill starts on its own: a load does
   *  not adopt its worker until it has spawned, so a second load started in that window
   *  would stand up a worker nothing can reach — an orphan isolate, still spinning,
   *  which is exactly what the bound exists to stop. */
  spawning: Promise<void> | null;
  /** Set once the ref leaves the table (`teardown`). A load in flight at that moment
   *  must not adopt its worker onto a ref nothing holds any more — the worker would be
   *  unreachable and unkillable — so it kills what it spawned instead. */
  dead: boolean;
  /** One in-flight call per module (§3's "one transform at a time"): calls chain on
   *  this, so a spinning module burns at most one core, for at most one bound. */
  tail: Promise<unknown>;
  /** The module's scratch region, read off the worker's own instance at load — the
   *  host's copy of the §4.1 number, used to refuse an oversized payload without a
   *  worker round-trip. */
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
  /** Hold the host's event loop open, or stop holding it. An idle module worker must
   *  never keep a process alive (a Node CLI that installed a bundle would never exit),
   *  but one with a call in flight must: an unbounded call arms no timer, so nothing
   *  else would be pending and the process would exit mid-transform with its caller's
   *  promise unsettled. Node's ref/unref; a no-op in the browser, which has no such
   *  notion. */
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
      // other target resolves (native/main.go), so "does this module load" is never a
      // property of which target it landed on. All three are inert: \`seed\` is a constant
      // rather than Date.now(), because a pure transform is deterministic and reaches no
      // clock (§4.2), and \`trace\` drops its arguments rather than writing them where
      // anything could observe them (§4.3).
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
    // The worker has its script; the URL is a document-lifetime entry in the blob
    // registry and nothing revokes it later. A module respawns once per deadline kill,
    // so an unrevoked URL per spawn is a leak that grows with the thing it defends
    // against.
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
  // An IDLE module worker is host-owned bookkeeping, never a reason for the process to
  // stay up: an orphaned worker (a respawn racing a teardown) must not hold the node
  // alive. A worker with work in flight does — `keepAlive` re-refs it for exactly that
  // window.
  w.unref?.();
  return {
    onMessage: (cb) => { w.on("message", (m) => cb(m as WorkerMsg)); },
    onError: (cb) => { w.on("error", (err) => cb(err)); },
    post: (msg, transfer) => w.postMessage(msg, transfer ?? []),
    keepAlive: (on) => { if (on) w.ref?.(); else w.unref?.(); },
    kill: () => { void w.terminate(); },
  };
}

export class ModuleTable {
  /** The module table (README §3): app key → that app's modules by logical name. A
   *  module is bound exactly when it is a key in its app's map, so the §3.1 bind /
   *  unbind / resolve operations are `set` / `delete` / `get` and nothing else can
   *  disagree about what resolves. */
  private readonly apps = new Map<string, Map<string, WasmModuleRef>>();

  /** The §4.3 memory ceiling this host holds installs to. */
  private readonly maxModuleMemoryBytes: number;

  /** The default module-call bound (ModuleTableOptions.deadlineMs). */
  private readonly deadlineMs: number;

  /** Ids for calls in flight to this table's workers — one stream, so a worker can
   *  correlate an answer with the call that asked, and never two calls share an id. */
  private callSeq = 0;

  constructor(opts: ModuleTableOptions = {}) {
    this.maxModuleMemoryBytes = opts.maxModuleMemoryBytes ?? DEFAULT_MAX_MODULE_MEMORY_BYTES;
    this.deadlineMs = opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
  }

  // ─── installing WASM modules ─────────────────────────────────────────

  /** Land an app's modules on the table, all or none (§3.1) — the one way code arrives,
   *  and the only mutating entry point besides `removeApp`.
   *
   *  Every module is spawned, instantiated and validated BEFORE anything is written, so
   *  a bundle whose third module is malformed leaves the table exactly as it was rather
   *  than half-replaced. The atomicity is structural rather than argued: the app's whole
   *  module map is built first and then assigned under its key, so the commit is ONE
   *  assignment and there is no window in which some of an app's modules are the new
   *  version and the rest are the old.
   *
   *  A re-install REPLACES the app's map rather than merging into it, which is what a
   *  version of an app is: a bundle dropping a module from its manifest leaves nothing
   *  of the old one behind — the replaced map's workers are killed as the old map goes.
   *
   *  Async because each module now stands up a worker: the instance, its compile and its
   *  statics all land in a fresh isolate, and this returns when every one of them has
   *  reported `ready` (or throws on the first `loadError`). */
  async bindAll(appKey: string, mods: { name: string; wasm: Uint8Array }[]): Promise<void> {
    if (appKey.length === 0) throw new Error("table: empty app key");
    const built = new Map<string, WasmModuleRef>();
    try {
      for (const m of mods) {
        if (m.name.length === 0) throw new Error("table: empty module name");
        built.set(m.name, await this.spawn(m.wasm));
      }
    }
    catch (e) {
      // Nothing above touched the table; release the workers the attempt already stood
      // up so a refused bundle leaves no orphaned isolates behind.
      for (const ref of built.values()) this.teardown(ref);
      throw e;
    }
    const prev = this.apps.get(appKey);
    this.apps.set(appKey, built);
    if (prev) {
      for (const ref of prev.values()) this.teardown(ref);
    }
  }

  /** Stand up a module's worker: the §4.3 memory ceiling is read off the bytes HERE,
   *  before any worker exists (instantiation is what allocates the declared initial
   *  memory — wasm-limits.ts, which also refuses an imported or shared memory); the §4
   *  export checks run in the worker on the same load, and its `loadError` reports
   *  failure rather than binding a broken ref. */
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

  /** Bring `ref`'s worker up: spawn, load, wait for `ready` — or fail. Bounded like a
   *  call, because a module whose initialization never completes is the same bug as one
   *  whose `handle` never returns — instantiation RUNS the start section, so an
   *  unbounded load is a wedged node at install. */
  private async load(ref: WasmModuleRef): Promise<void> {
    const worker = await spawnWorker(moduleWorkerSrc());
    // The ref may have left the table while this was spawning (`removeApp`, a replacing
    // bind, a refused bundle). Adopting the worker now would hand it to a ref nothing
    // holds — unreachable, unkillable, and still running whatever it was given.
    if (ref.dead) { worker.kill(); throw new Error("table: module was released while it loaded"); }
    ref.worker = worker;
    // A load holds the loop open for the same reason a call does: an unbounded table
    // arms no load timer, and a bind is something its caller is waiting on.
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
      // One handler per worker, for both phases — load and calls are strictly
      // sequential per module (a call reaches a worker only after `ready`, and a
      // respawn holds the queue), so one dispatch covers both.
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
    // Loaded and idle: it holds nothing open until a call is posted. (Every rejection
    // path above killed the worker, so there is nothing to release there.)
    worker.keepAlive(false);
    // A release that landed while the load was in flight — the module is off the table
    // and `teardown` had no worker to kill, so this one must not be left standing.
    if (ref.dead) { ref.worker = null; worker.kill(); throw new Error("table: module was released while it loaded"); }
    // After the load settles, an engine crash (not a wasm trap — traps are caught
    // inside the worker and reported as a null result) fails whatever call is in
    // flight with the same empty answer and leaves the module to respawn.
    worker.onError(() => {
      if (ref.worker !== worker) return;
      for (const settle of ref.pending.values()) settle(null);
      ref.pending.clear();
      ref.worker = null;
    });
  }

  // ─── public API ──────────────────────────────────────────────────────

  /** Invoke one app's module with `payload`, returning its response bytes, or null if
   *  nothing is bound there or the module produced no response. This is the
   *  scratch-region contract (README §4): write input at the module's scratch offset,
   *  call handle(input_len), read the response back from the same offset. The generic
   *  "run a transform" primitive: the host uses it directly, and a guest reaches it
   *  through the guest seam by its bare name (README §12.2) — with the app key bound at
   *  seam construction, so `module` is the LOGICAL name from the guest's own manifest
   *  and a guest cannot address another app's modules by naming one. Modules cannot
   *  call back, so there is no re-entrancy.
   *
   *  Async since the JS targets run modules in a worker (a call crosses an isolate),
   *  and BOUNDED: `deadlineMs` (defaulting to this host's `deadlineMs`) is the call's
   *  whole budget. A call that exceeds it is answered empty — the worker killed, a
   *  fresh instance respawned — so a module that never returns fails like a trap
   *  instead of holding the node's thread (the §4.3 compute residual, closed at the
   *  engine). A guest's call carries the calling guest's remaining execution segment,
   *  passed through the seam, which is what makes "charged to the calling guest's
   *  budget" (§4.3) enforced rather than aspirational. */
  async callModule(appKey: string, module: string, payload: Uint8Array, deadlineMs?: number): Promise<Uint8Array | null> {
    const w = this.apps.get(appKey)?.get(module);
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
    // asked for. Its statics are gone, which is the point.
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
          // one interrupt, which works even mid-loop because it is the engine destroying
          // the worker — answer empty, and respawn a fresh instance for the next call.
          w.pending.delete(id);
          resolve(null);
          if (w.worker === worker) {
            w.worker = null;
            worker.kill();
            // Recorded as THE respawn, not started loose: the call already queued behind
            // this one resumes on the next microtask, well before the new worker has
            // spawned, and a second load started there would leave the first one's worker
            // reachable by nobody — an orphan isolate running the code the kill was for.
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

  /** Drop an app and everything it landed, returning how many modules went — the §3.1
   *  unbind, and the whole of it. The unit is an APP, which is simply the key: the
   *  shell's `uninstall` and `revoke` (§12.5) are the only callers, and both mean exactly
   *  this. Install and removal are visibly the same unit, so there is no asymmetry to
   *  explain.
   *
   *  There is no single-module remove. Nothing wants one — a module is not a unit anything
   *  installs or revokes — and with modules living inside their app there is no shared
   *  namespace for a freed one to be contended for, so there is nothing to keep in step
   *  and no tombstone to leave behind. */
  removeApp(appKey: string): number {
    const mods = this.apps.get(appKey);
    if (!mods) return 0;
    this.apps.delete(appKey);
    for (const ref of mods.values()) this.teardown(ref);
    return mods.size;
  }

  /** True if `module` is bound for `appKey` — the §3.1 resolve, as a predicate. A shell
   *  uses it to check that the modules it expects a bundle to have landed are bound. */
  isBound(appKey: string, module: string): boolean {
    return this.apps.get(appKey)?.has(module) ?? false;
  }

  /** Kill a module's worker and settle everything waiting on it as empty — the module
   *  is gone, and no caller may hang on a promise nothing can settle. */
  private teardown(ref: WasmModuleRef): void {
    // Marked before anything else: a respawn may be mid-flight, and the load that
    // finishes after this returns has to kill what it spawned rather than adopt it onto
    // a ref that has left the table.
    ref.dead = true;
    for (const settle of ref.pending.values()) settle(null);
    ref.pending.clear();
    ref.worker?.kill();
    ref.worker = null;
  }
}
