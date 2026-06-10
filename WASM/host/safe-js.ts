// safe-js — a zero-authority JavaScript sandbox. It runs untrusted/confined JS
// inside a QuickJS interpreter compiled to WASM (quickjs-emscripten, Asyncify
// build), driven from the host. A fresh QuickJS context has *only* the
// ECMAScript intrinsics, so the guest cannot even name `fs`/`net`/`Bun`/
// `process`/`fetch` — confinement is the default, not something we lock down
// (ShadowRealm was disqualified on exactly this; see the ShadowRealm probes).
// The single seam to the outside is one injected host function, `__host_call`,
// which funnels every capability access through a copy-model byte boundary, the
// same shape as the KernelHost handler bridges.
//
// Async seam: a guest is typically multi-step (each step awaits a host bridge).
// Asyncify lets the guest call `__host_call` *synchronously* from QuickJS's point
// of view while the host resolves it asynchronously — the VM stack unwinds on the
// call and is restored when the promise settles. So guest JS runs unchanged, with
// no host-driven step loop. The same `quickjs.wasm` is hosted by JSC here
// (Node/Bun) and by WAMR in the native engine later — one artifact for both
// runtimes (the runtime split). seedstore builds its Tier-2 confinement
// (README §2.1) on top of this generic primitive.
//
// A second factory, `createSyncSafeRealm`, runs the *non-Asyncify* QuickJS build:
// same ABI, but `host.call` resolves synchronously with no stack unwind. It exists
// for confined work that must complete without yielding — notably a request
// handler that has to run *while* an Asyncify realm is parked mid-await. Since the
// two are different WASM instances, the sync realm cannot disturb the async one's
// suspended state (the module-global Asyncify caveat). Its bridge must resolve
// every op synchronously (no net round trips).

import {
  newQuickJSAsyncWASMModule,
  newQuickJSWASMModule,
  type QuickJSAsyncWASMModule,
  type QuickJSAsyncContext,
  type QuickJSWASMModule,
  type QuickJSContext,
  type QuickJSHandle,
} from "quickjs-emscripten";

/** The one capability seam. `op` selects a host capability (net / store / crypto
 *  / clock / rand, mapped by the host); `payload`/return are opaque bytes, exactly
 *  like `kernel.call(name, payload) -> bytes`. The host implementation may be
 *  async (a real network round trip); Asyncify makes that transparent to the
 *  guest. */
export type SafeRealmBridge = (op: number, payload: Uint8Array) => Promise<Uint8Array> | Uint8Array;

export interface SafeRealmOptions {
  /** Guest source. Runs in the sandbox; registers entrypoints via the injected
   *  `register(name, fn)` (see the preamble below). */
  source: string;
  /** The single host capability funnel. */
  bridge: SafeRealmBridge;
  /** Hard cap on the realm's heap (default 64 MiB). A runaway guest hits this
   *  instead of the host's memory. */
  memoryLimitBytes?: number;
  /** Optional wall-clock budget per `call()` (ms). Coarse: it counts time spent
   *  awaiting host bridges too, so size it generously. The fine-grained CPU
   *  watchdog stays a host Worker concern (see BUN.md §2.1). */
  deadlineMs?: number;
}

export interface SafeRealm {
  /** Invoke a guest entrypoint registered with `register(name, fn)`. The arg and
   *  result cross as raw bytes (the copy model). Resolves when the guest promise
   *  settles — including all awaited host bridges. */
  call(entry: string, payload: Uint8Array): Promise<Uint8Array>;
  dispose(): void;
}

export interface SyncSafeRealm {
  /** Like SafeRealm.call but fully synchronous: the entrypoint runs to completion
   *  and returns its bytes directly (no Promise). The bridge it is built with must
   *  therefore resolve every op synchronously — a Promise (e.g. a net op) is a
   *  hard error. Used for re-entrant work that must finish without yielding, such
   *  as serving a request while an async realm is parked mid-await. */
  call(entry: string, payload: Uint8Array): Uint8Array;
  dispose(): void;
}

// The guest-side preamble. Defines the airtight ABI the guest is written against:
// `host.call(op, bytes) -> Promise<Uint8Array>` over the single seam, and
// `register`/`__invoke` for entrypoint dispatch. Pure JS — no authority.
const PREAMBLE = `
globalThis.host = {
  // Asyncify makes __host_call *block* the guest until the host promise settles,
  // returning the result bytes directly — it does NOT return a promise. So this
  // is synchronous from the guest's point of view. A guest's
  // 'await host.call(...)' still works unchanged (awaiting a plain value is a
  // no-op), but a 'Promise.all' fan-out serializes: Asyncify unwinds one VM stack
  // at a time, so concurrent host calls cannot overlap.
  call(op, bytes) {
    const ab = bytes instanceof ArrayBuffer
      ? bytes
      : (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength)
        ? bytes.buffer
        : bytes.slice().buffer;
    return new Uint8Array(__host_call(op, ab));
  },
};
globalThis.__entries = Object.create(null);
globalThis.register = (name, fn) => { globalThis.__entries[name] = fn; };
function __norm(out) {
  if (out instanceof ArrayBuffer) return out;
  if (out instanceof Uint8Array) {
    return (out.byteOffset === 0 && out.byteLength === out.buffer.byteLength)
      ? out.buffer : out.slice().buffer;
  }
  throw new Error("safe-js: entrypoint must return Uint8Array | ArrayBuffer");
}
globalThis.__invoke = (name, argBuf) => {
  const fn = globalThis.__entries[name];
  if (typeof fn !== "function") throw new Error("safe-js: no entrypoint '" + name + "'");
  // A synchronous entrypoint returns bytes directly (no guest promise). Because
  // host.call blocks via Asyncify, every host call inside a *synchronous* body is
  // reachable from the single evalCodeAsync expression and is driven correctly.
  // An async entrypoint returns a promise we settle host-side — but its host calls
  // must all occur before the first real await (see the note on the seam above).
  const out = fn(new Uint8Array(argBuf));
  return out && typeof out.then === "function" ? out.then(__norm) : __norm(out);
};
`;

let modulePromise: Promise<QuickJSAsyncWASMModule> | undefined;
/** The Asyncify QuickJS WASM module is loaded once and shared by all realms. */
function getModule(): Promise<QuickJSAsyncWASMModule> {
  return (modulePromise ??= newQuickJSAsyncWASMModule());
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength
    ? (u8.buffer as ArrayBuffer)
    : (u8.slice().buffer as ArrayBuffer);
}

// ── pieces shared by the async and sync factories ────────────────────────────

/** Heap cap + the optional per-call wall-clock deadline. Returns the hook each
 *  `call()` uses to re-arm the deadline. */
function configureRealm(ctx: QuickJSContext, opts: SafeRealmOptions): () => void {
  ctx.runtime.setMemoryLimit(opts.memoryLimitBytes ?? 64 * 1024 * 1024);
  let deadline = Infinity;
  if (opts.deadlineMs !== undefined) {
    ctx.runtime.setInterruptHandler(() => Date.now() > deadline);
  }
  return () => { if (opts.deadlineMs !== undefined) deadline = Date.now() + opts.deadlineMs; };
}

/** Stage the entrypoint argument as the realm global `__arg` (copy boundary). */
function stageArg(ctx: QuickJSContext, payload: Uint8Array): void {
  const argHandle = ctx.newArrayBuffer(toArrayBuffer(payload));
  ctx.setProp(ctx.global, "__arg", argHandle);
  argHandle.dispose();
}

/** Copy an op payload out of WASM memory (the buffer may move under us). */
function copyPayload(ctx: QuickJSContext, payloadHandle: QuickJSHandle): Uint8Array {
  const lt = ctx.getArrayBuffer(payloadHandle);
  const payload = lt.value.slice();
  lt.dispose();
  return payload;
}

/** Take ownership of a result handle and copy its bytes out (copy boundary). */
function takeBytes(ctx: QuickJSContext, handle: QuickJSHandle): Uint8Array {
  const lt = ctx.getArrayBuffer(handle);
  const out = lt.value.slice();
  lt.dispose();
  handle.dispose();
  return out;
}

const invokeSrc = (entry: string): string => `__invoke(${JSON.stringify(entry)}, __arg)`;

export async function createSafeRealm(opts: SafeRealmOptions): Promise<SafeRealm> {
  const mod = await getModule();
  const ctx: QuickJSAsyncContext = mod.newContext();
  const armDeadline = configureRealm(ctx, opts);

  // The single seam: an Asyncified host function. QuickJS calls it synchronously;
  // its stack unwinds while we await the bridge, then resumes with the result.
  const hostCall = ctx.newAsyncifiedFunction("__host_call", async (opHandle, payloadHandle) => {
    const op = ctx.getNumber(opHandle);
    const result = await opts.bridge(op, copyPayload(ctx, payloadHandle));
    return ctx.newArrayBuffer(toArrayBuffer(result));
  });
  ctx.setProp(ctx.global, "__host_call", hostCall);
  hostCall.dispose();

  // Load the ABI preamble, then the guest. Neither has authority. Each eval's
  // completion value (the trailing assignment) is an owned handle — dispose it so
  // nothing leaks past the context (the sync QuickJS build asserts on leaks).
  ctx.unwrapResult(await ctx.evalCodeAsync(PREAMBLE, "safe-js-preamble.js")).dispose();
  ctx.unwrapResult(await ctx.evalCodeAsync(opts.source, "safe-js-guest.js")).dispose();

  // Calls are serialized per realm: a call() parks mid-await on every host
  // bridge (Asyncify suspends the one shared VM), so a second concurrent call()
  // would clobber the shared `__arg` global and re-enter the suspended VM.
  let chain: Promise<unknown> = Promise.resolve();

  const callOnce = async (entry: string, payload: Uint8Array): Promise<Uint8Array> => {
    armDeadline();
    stageArg(ctx, payload);

    // evalCodeAsync drives the Asyncify suspensions for every host call that is
    // synchronously reachable inside the expression. The result is either the
    // bytes directly (sync entrypoint) or a guest promise (async entrypoint);
    // resolvePromise normalizes both, but it only settles once the job queue is
    // pumped — hence resolvePromise → executePendingJobs → await, in that order
    // (awaiting before the pump would deadlock).
    const evalResult = ctx.unwrapResult(
      await ctx.evalCodeAsync(invokeSrc(entry), "safe-js-invoke.js"),
    );
    const settledNative = ctx.resolvePromise(evalResult);
    ctx.runtime.executePendingJobs();
    const settled = await settledNative;
    evalResult.dispose();

    return takeBytes(ctx, ctx.unwrapResult(settled));
  };

  return {
    call(entry: string, payload: Uint8Array): Promise<Uint8Array> {
      const run = chain.then(() => callOnce(entry, payload));
      chain = run.catch(() => {}); // a failed call must not poison the queue
      return run;
    },
    dispose(): void {
      ctx.dispose();
    },
  };
}

let syncModulePromise: Promise<QuickJSWASMModule> | undefined;
/** The synchronous (non-Asyncify) QuickJS WASM module — the smaller ~491 KB
 *  build, loaded once and shared by all sync realms. */
function getSyncModule(): Promise<QuickJSWASMModule> {
  return (syncModulePromise ??= newQuickJSWASMModule());
}

/** A synchronous safe-js realm. Same airtight ABI and copy boundary as
 *  `createSafeRealm`, but with no Asyncify: `host.call` is a plain function and an
 *  entrypoint runs straight through to its bytes. Because there is no suspension,
 *  a `call()` here completes without ever yielding the event loop — so it can run
 *  *while* an Asyncify realm (a different WASM instance) is parked mid-host-call,
 *  the property the storage holder side needs (it answers from local fs + crypto,
 *  never net, so it has nothing to await). The bridge must resolve every op
 *  synchronously; a Promise return means an async op slipped into a sync realm. */
export async function createSyncSafeRealm(opts: SafeRealmOptions): Promise<SyncSafeRealm> {
  const mod = await getSyncModule();
  const ctx: QuickJSContext = mod.newContext();
  const armDeadline = configureRealm(ctx, opts);

  // The single seam — a plain host function. QuickJS calls it synchronously and
  // gets the result bytes back immediately; there is no stack unwind.
  const hostCall = ctx.newFunction("__host_call", (opHandle, payloadHandle) => {
    const op = ctx.getNumber(opHandle);
    const result = opts.bridge(op, copyPayload(ctx, payloadHandle));
    if (result && typeof (result as Promise<Uint8Array>).then === "function") {
      throw new Error("sync safe-js: bridge returned a Promise — a sync realm cannot host an async op (e.g. net)");
    }
    return ctx.newArrayBuffer(toArrayBuffer(result as Uint8Array));
  });
  ctx.setProp(ctx.global, "__host_call", hostCall);
  hostCall.dispose();

  // Dispose each eval's completion handle so nothing outlives the context — the
  // sync QuickJS build asserts on a non-empty GC list at runtime teardown.
  ctx.unwrapResult(ctx.evalCode(PREAMBLE, "safe-js-preamble.js")).dispose();
  ctx.unwrapResult(ctx.evalCode(opts.source, "safe-js-guest.js")).dispose();

  return {
    call(entry: string, payload: Uint8Array): Uint8Array {
      armDeadline();
      stageArg(ctx, payload);
      // A sync entrypoint returns bytes directly; __invoke yields the ArrayBuffer.
      // (An async entrypoint would return a guest promise here, which a sync realm
      // cannot settle — getArrayBuffer would then throw, by design.)
      return takeBytes(ctx, ctx.unwrapResult(ctx.evalCode(invokeSrc(entry), "safe-js-invoke.js")));
    },
    dispose(): void {
      ctx.dispose();
    },
  };
}
