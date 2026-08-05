// safe-js — a zero-authority JavaScript sandbox. It runs untrusted/confined JS
// inside a QuickJS interpreter compiled to WASM (quickjs-emscripten, the sync
// non-Asyncify build), driven from the host. A fresh QuickJS context has *only* the
// ECMAScript intrinsics, so the guest cannot even name `fs`/`net`/`Bun`/`process`/
// `fetch` — confinement is the default, not something we lock down (ShadowRealm was
// disqualified on exactly this; see the ShadowRealm probes). The single seam to the
// outside is one injected host function, `__host_call`, which funnels every capability
// access through a copy-model byte boundary, the same shape as the KernelHost handler
// bridges.
//
// Async seam: a guest is typically multi-step, and several steps genuinely round-trip.
// `host.call(name, bytes)` resolves a **sync name** (the primitive catalog, clock,
// module, the raw-link and transport names) to its bytes immediately, and a
// **round-tripping name** — `net/send` and every `fs/*` — to a real Promise the guest
// `await`s. The guest builds that Promise itself (the shared preamble parks it under a
// `callId`); this host returns `null` to say "started async", then settles it with
// `__netResolve`/`__netReject` and pumps `executePendingJobs()` so the awaiting
// continuation runs. Deliberately NOT
// quickjs-emscripten's `newPromise()` deferred: keeping the async half in plain
// ECMAScript is what lets this host and the native loader (guest.go, quickjs-ng over
// wazero, which has no promise primitive) share ONE preamble — see `guestPreamble` in
// cap-bridge.ts.
//
// There is no Asyncify and no host-driven step loop: a suspended async guest is just heap
// state. There is exactly ONE way in — `call` — serving both roles, the initiator that
// awaits the network and the holder that awaits `fs`. A synchronous second entry is not
// on offer, because a holder answers from local storage and storage does not answer in
// the same turn on a target whose backend is asynchronous (core/fs.ts). What a
// synchronous entry would have given for free — one entrypoint invocation running to
// completion before the next begins — is an explicit per-realm FIFO queue instead
// (realm-queue.ts). One `quickjs.wasm` build serves both roles. An app builds its own
// guest confinement on top of this generic primitive (README §12.3).

import {
  newQuickJSWASMModule,
  type QuickJSWASMModule,
  type QuickJSRuntime,
  type QuickJSContext,
  type QuickJSHandle,
} from "quickjs-emscripten";
// The shared §12.3 defaults — one copy on every target, so a guest meets the same
// ceiling and the same budget whether its realm is this one or the native target's
// (native/guest.go, whose bridge used to carry its own copies of these numbers).
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_REALM_MEMORY_BYTES } from "../core/wasm-limits.js";
import { errMessage } from "../core/util.js";
// Use the actively-maintained quickjs-ng build rather than quickjs-emscripten's default
// (original-Bellard) variant. Only the non-Asyncify (sync) flavour is needed now — net is
// a real Promise resolved by the host, not an Asyncify stack unwind.
//
// This variant package is CJS, so under `nodenext` TypeScript types its default export as
// the module namespace, whereas the runtime default import is the variant object itself
// (verified). Cast to the factory's own parameter type to bridge that interop gap.
import ngReleaseSyncMod from "@jitl/quickjs-ng-wasmfile-release-sync";
const ngReleaseSync = ngReleaseSyncMod as unknown as NonNullable<
  Parameters<typeof newQuickJSWASMModule>[0]
>;

// The guest-side ABI, shared with the native loader. See `guestPreamble` for the
// `__host_call` / `__netResolve` contract this file implements.
import { guestPreamble } from "./cap-bridge.js";
import { serializeCalls } from "./realm-queue.js";

/** The one capability seam. `name` addresses a host capability by its opaque name
 *  (net / fs / crypto / clock / rand, mapped by the host); `payload`/return are opaque
 *  bytes, exactly like `kernel.call(name, payload) -> bytes`. A sync name returns bytes
 *  directly; a round-tripping one — `net/send` and every `fs/*` — returns a Promise the
 *  guest awaits. */
export type SafeRealmBridge = (name: string, payload: Uint8Array) => Promise<Uint8Array> | Uint8Array;

export interface SafeRealmOptions {
  /** Guest source. Runs in the sandbox; registers entrypoints via the injected
   *  `register(name, fn)` (see the preamble below). */
  source: string;
  /** The single host capability funnel. */
  bridge: SafeRealmBridge;
  /** Hard cap on the realm's heap (default 64 MiB). A runaway guest hits this
   *  instead of the host's memory. */
  memoryLimitBytes?: number;
  /** Budget of guest *execution* time per entrypoint invocation, in ms
   *  (default `DEFAULT_DEADLINE_MS`). Exceeding it interrupts the guest, which
   *  surfaces to the caller as a thrown error.
   *
   *  This measures time the guest is actually **running**, not wall clock: the budget
   *  is stopped whenever the guest is parked awaiting a host bridge and resumed when
   *  its continuation runs (see `execClock`). That is what lets one number be correct
   *  for both roles — an initiator legitimately spends seconds parked on a network
   *  request without spending any of its budget, while a holder that loops forever
   *  burns it in one segment.
   *
   *  `Infinity` disables the guard. There is no "omitted ⇒ unbounded" case: the
   *  default is a real number, so a caller that forgets this field gets a bounded
   *  guest rather than an unbounded one. */
  deadlineMs?: number;
}

export interface SafeRealm {
  /** Invoke a guest entrypoint — the **only** way into the realm, for both roles: the
   *  initiator that may `await` net, and the holder answering an inbound request. The arg
   *  and result cross as raw bytes (the copy model). Resolves when the guest promise
   *  settles, including all awaited host bridges.
   *
   *  **Invocations are serialized per realm.** A call does not begin until the previous
   *  one has settled, so no two guest frames are ever in flight in one realm and neither
   *  can observe the other's half-updated state at an await point. Both roles can yield,
   *  so this is a queue rather than a property of the host's call stack (realm-queue.ts).
   *
   *  The cost is head-of-line blocking, and it is a real one: an initiator parked on a
   *  network round trip holds the queue, so an inbound request to the same app waits for
   *  it rather than being answered around. That is the price
   *  of the guarantee — the alternative is two frames interleaving at every `await`, which
   *  is exactly what a guest author has no way to reason about. An app that wants
   *  concurrency across the two roles wants two realms, which the shell can give it,
   *  rather than one realm with two frames inside it. */
  call(entry: string, payload: Uint8Array): Promise<Uint8Array>;
  dispose(): void;
}

let modulePromise: Promise<QuickJSWASMModule> | undefined;
/** The QuickJS WASM module is loaded once and shared by all realms. */
function getModule(): Promise<QuickJSWASMModule> {
  return (modulePromise ??= newQuickJSWASMModule(ngReleaseSync));
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength
    ? (u8.buffer as ArrayBuffer)
    : (u8.slice().buffer as ArrayBuffer);
}

/** The guest's execution-time accounting (README §4.3, §12.3).
 *
 *  A budget over *running* time rather than wall clock, kept by summing the segments
 *  during which guest code actually holds the thread. A segment opens when the host
 *  enters the realm — `evalCode` for an entrypoint, `callFunction` + `executePendingJobs`
 *  when settling a parked net op — and closes when control returns to the host. Time
 *  between segments, which is the host awaiting a bridge on the guest's behalf, is
 *  nobody's budget.
 *
 *  Without the split, one number cannot serve both roles: an initiator parked 2s on a
 *  network request would be killed by any budget tight enough to catch a holder's
 *  infinite loop.
 *
 *  There is no nested-budget case: invocations are serialized (see `call`), so exactly
 *  one budget window is open at a time and `reset` is the whole of it. */
interface ExecClock {
  /** Guest code is about to run. */
  begin(): void;
  /** Guest code has returned control to the host. */
  end(): void;
  /** Start a fresh budget — one entrypoint invocation. */
  reset(): void;
}

/** Heap cap, and the execution-time guard the clock above drives. */
function configureRealm(ctx: QuickJSContext, opts: SafeRealmOptions): ExecClock {
  ctx.runtime.setMemoryLimit(opts.memoryLimitBytes ?? DEFAULT_REALM_MEMORY_BYTES);
  const budgetMs = opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
  let consumedMs = 0;
  let segmentStart = 0;
  let running = false;
  // Installed unconditionally. QuickJS calls this periodically while guest code runs;
  // it reads false whenever the guest is not running, so a parked initiator is never
  // interrupted. `Infinity` makes the comparison never true, which is how the guard is
  // disabled — by a value, not by the handler's absence.
  ctx.runtime.setInterruptHandler(
    () => running && consumedMs + (Date.now() - segmentStart) > budgetMs,
  );
  return {
    begin() { segmentStart = Date.now(); running = true; },
    end() { if (running) { consumedMs += Date.now() - segmentStart; running = false; } },
    reset() { consumedMs = 0; },
  };
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

/** Take ownership of a result handle and copy its bytes out (copy boundary). The
 *  handle must go back even when the value is not an ArrayBuffer — a guest entrypoint
 *  that returns a non-bytes value must not leave an orphaned handle behind, because
 *  an orphaned handle keeps its object on the runtime's GC list, which aborts the
 *  module at runtime free. */
function takeBytes(ctx: QuickJSContext, handle: QuickJSHandle): Uint8Array {
  const lt = ctx.getArrayBuffer(handle);
  try {
    return lt.value.slice();
  } finally {
    lt.dispose();
    handle.dispose();
  }
}

const invokeSrc = (entry: string): string => `__invoke(${JSON.stringify(entry)}, __arg)`;

/** Release a settled `resolvePromise` result (a `DisposableResult` carrying a dup'd
 *  handle) that no invocation will ever consume. Best-effort: the handle may already
 *  be gone (e.g. `unwrapResult` disposed the error it threw), and a throw here would
 *  surface as an unhandled rejection long after the caller left. */
const disposeDisposableResult = (result: unknown): void => {
  try {
    const disposable = result as { alive?: boolean; dispose?: () => void } | null;
    if (disposable && disposable.dispose && disposable.alive !== false) disposable.dispose();
  } catch {
    // Nothing left to release — exactly the state this is for.
  }
};

/** A realm's QuickJS **runtime** is created separately from its context, and `dispose()`
 *  frees both: the context first, its runtime in the same deferred turn.
 *
 *  The ordering is required by `JS_FreeRuntime`, which asserts an empty GC object list
 *  (`list_empty(&rt->gc_obj_list)`): any object still referenced — for example by an
 *  undisposed host handle — aborts the whole wasm module, every other realm in the
 *  process with it. The realm releases every handle it owns before teardown, so nothing
 *  survives to the runtime's free.
 *
 *  Teardown is deferred one macrotask so a parked invocation's rejection continuation —
 *  the `finally` in `invoke` — can run as a microtask after `failPending` while the
 *  context is still alive. By the macrotask, nothing can re-enter (the queue fails on
 *  `disposed`), so the realm is quiescent when it dies. The context goes first because
 *  `JS_FreeRuntime`'s assertion is satisfiable only once the context and its GC objects
 *  are gone.
 *
 *  `dispose()` thus returns the realm's memory — roughly 1.2 MB per runtime — to the
 *  wasm heap. */
const newRuntime = (mod: QuickJSWASMModule): QuickJSRuntime => mod.newRuntime();

export async function createSafeRealm(opts: SafeRealmOptions): Promise<SafeRealm> {
  const mod = await getModule();
  // NOT `mod.newContext()`: that couples the runtime's lifetime to the context's, freeing
  // both in the same breath — the teardown order described above, which dispose() must
  // control itself.
  const runtime = newRuntime(mod);
  const ctx: QuickJSContext = runtime.newContext();
  const clock = configureRealm(ctx, opts);
  let disposed = false;

  // Drain the guest's job queue, surfacing a failure as a thrown error.
  //
  // `executePendingJobs` does NOT throw — it *returns* a result whose `error` is a live
  // QuickJS handle. Two consequences, both of which bit: an interrupted continuation
  // (the budget firing inside a queued job rather than in the call that started it) was
  // silently swallowed, and the undisposed error handle later aborted the whole wasm
  // module at dispose() time via QuickJS's `list_empty(&rt->gc_obj_list)` assertion.
  const pumpJobs = (): void => {
    const res = ctx.runtime.executePendingJobs();
    if (!res.error) return;
    let msg = "guest job failed";
    try {
      const d = ctx.dump(res.error) as { message?: unknown; name?: unknown };
      msg = d && typeof d === "object" && d.message !== undefined
        ? `${d.name ?? "Error"}: ${String(d.message)}`
        : String(d);
    } catch {
      // Reading the error can itself fail on an interrupted context; the handle still
      // has to go back, which is what the finally below is for.
    } finally {
      res.error.dispose();
    }
    throw new Error(msg);
  };

  // Rejectors for initiator calls currently awaiting a guest promise (README §12.3).
  //
  // A guest promise is settled from *inside* the realm, so anything that stops the realm
  // mid-flight — an execution-budget interrupt during a continuation, or dispose() while
  // a call is parked — leaves that promise permanently pending and its caller waiting on
  // it forever. The realm therefore tracks who is waiting and fails them explicitly. A
  // bound that converts a runaway guest into a hung host would not be much of a bound.
  const pending = new Set<(err: Error) => void>();
  const failPending = (err: Error): void => {
    for (const reject of [...pending]) {
      pending.delete(reject);
      reject(err);
    }
  };

  // Settle a parked host.call by calling the guest's own __netResolve/__netReject (the
  // preamble's half of the contract), then pump so the awaiting continuation runs.
  const settleNet = (fn: "__netResolve" | "__netReject", callId: number, arg: QuickJSHandle): void => {
    const settler = ctx.getProp(ctx.global, fn);
    const id = ctx.newNumber(callId);
    // The continuation of a parked `await` is guest code, so it runs on the guest's
    // budget — resumed here and suspended again when the job queue drains.
    //
    // Every handle is released in `finally`, and that is load-bearing rather than tidy:
    // this call can now be interrupted mid-flight by the execution budget, and QuickJS
    // asserts `list_empty(&rt->gc_obj_list)` when a runtime is freed with live handles —
    // an *abort of the whole wasm module*, i.e. the host process, at dispose() time. A
    // leak on the interrupt path is therefore a crash, not a leak.
    clock.begin();
    try {
      const res = ctx.unwrapResult(ctx.callFunction(settler, ctx.undefined, id, arg));
      res.dispose();
      pumpJobs();
    } catch (err) {
      // The guest was interrupted while resuming. Nothing inside the realm will ever
      // settle the initiator's promise now, so the realm has to fail it here — otherwise
      // `call()` awaits a promise that cannot settle and the caller hangs forever.
      failPending(err instanceof Error ? err : new Error(String(err)));
    } finally {
      clock.end();
      id.dispose();
      arg.dispose();
      settler.dispose();
    }
  };

  // The single seam. QuickJS calls it synchronously: a sync name resolves to its bytes
  // and we hand the ArrayBuffer straight back; a net/fs name genuinely round-trips, so
  // we return null — the preamble parks a Promise under callId — and settle it when the
  // bridge promise resolves. Returning null (rather than a host-created deferred) is
  // what keeps this seam identical to the native loader's; see guestPreamble.
  const hostCall = ctx.newFunction("__host_call", (nameHandle, callIdHandle, payloadHandle) => {
    const name = ctx.getString(nameHandle);
    const callId = ctx.getNumber(callIdHandle);
    const result = opts.bridge(name, copyPayload(ctx, payloadHandle));
    if (!result || typeof (result as Promise<Uint8Array>).then !== "function") {
      // Sync name — return the bytes directly (no promise, no job queue).
      return ctx.newArrayBuffer(toArrayBuffer(result as Uint8Array));
    }
    // Net/fs name — a genuine round trip. The guest holds the Promise; we settle it by callId.
    (result as Promise<Uint8Array>).then(
      (bytes) => {
        if (disposed || !ctx.alive) return;
        settleNet("__netResolve", callId, ctx.newArrayBuffer(toArrayBuffer(bytes)));
      },
      (err) => {
        if (disposed || !ctx.alive) return;
        settleNet("__netReject", callId, ctx.newString(errMessage(err)));
      },
    );
    return ctx.null;
  });
  ctx.setProp(ctx.global, "__host_call", hostCall);
  hostCall.dispose();

  // Load the ABI preamble, then the guest. Neither has authority. Each eval's completion
  // value (the trailing assignment) is an owned handle — dispose it so nothing leaks past
  // the context (the QuickJS build asserts on leaks).
  ctx.unwrapResult(ctx.evalCode(guestPreamble(), "guest-preamble.js")).dispose();
  ctx.unwrapResult(ctx.evalCode(opts.source, "safe-js-guest.js")).dispose();

  /** One entrypoint invocation, assuming the queue has already given it the realm. */
  const invoke = async (entry: string, payload: Uint8Array): Promise<Uint8Array> => {
    // Safe unconditionally because the queue guarantees nothing else is in flight: this
    // is one invocation's own budget window, from here to the moment it settles. If two
    // calls could overlap, this reset would be an escape hatch a guest's own traffic
    // could open — a second call clearing an in-flight call's accumulated time.
    clock.reset();
    stageArg(ctx, payload);
    // evalCode runs the entrypoint synchronously up to its first await; the completion
    // value is either the bytes (sync entrypoint) or a pending guest promise (async
    // entrypoint). resolvePromise normalizes both to a native promise, but it settles
    // only once the job queue is pumped — hence resolvePromise → executePendingJobs →
    // await, in that order (awaiting before the first pump would stall a sync entrypoint).
    // Awaits are then driven by each deferred's own executePendingJobs on settle.
    let evalResult: QuickJSHandle | undefined;
    let settledNative: Promise<unknown> | undefined;
    clock.begin();
    try {
      evalResult = ctx.unwrapResult(ctx.evalCode(invokeSrc(entry), "safe-js-invoke.js"));
      settledNative = ctx.resolvePromise(evalResult) as Promise<unknown>;
      pumpJobs();
    } finally {
      // Closed before the await below: everything past this point is the host
      // waiting on a bridge, which is not the guest's time to spend.
      clock.end();
      // resolvePromise has consumed the value; the eval handle is no longer needed
      // and must go back even when pumpJobs throws above — an orphaned handle keeps
      // its object on the runtime's GC list, which aborts the module at runtime free.
      evalResult?.dispose();
    }
    let rejectThis!: (err: Error) => void;
    const failed = new Promise<never>((_, reject) => { rejectThis = reject; });
    pending.add(rejectThis);
    let consumed = false;
    try {
      const settled = await Promise.race([settledNative as Promise<unknown>, failed]);
      consumed = true;
      return takeBytes(ctx, ctx.unwrapResult(settled as never));
    } finally {
      pending.delete(rejectThis);
      // An invocation that lost the race to failPending — a budget interrupt or
      // dispose() — has no consumer for the settled result. If the guest promise
      // still settles afterwards (a bridge op resolving after the interrupt), its
      // dup'd result handle would be orphaned, keeping the value on the runtime's
      // GC list and aborting the module at runtime free. Release it when it lands.
      // Safe by construction: `consumed` is set by the await continuation above,
      // which always runs before this finally.
      if (!consumed) {
        void (settledNative as Promise<unknown>).then(disposeDisposableResult);
      }
    }
  };

  return {
    call: serializeCalls(invoke, () =>
      (disposed || !ctx.alive) ? new Error("guest realm disposed") : null),
    dispose(): void {
      disposed = true;
      // Fail anyone still awaiting a guest promise before tearing the realm down: those
      // promises can only be settled from inside the realm, so disposing first would
      // strand every parked caller.
      failPending(new Error("guest realm disposed"));
      // ...but the engine must NOT die in the same turn. A parked invocation's
      // rejection continuation — the `finally` above — runs as a microtask after
      // failPending, and a handle released after its context died would abort the whole
      // wasm module. Deferring the teardown to a later macrotask runs it after every
      // microtask of the parked continuations, by which point nothing can re-enter (the
      // queue fails on `disposed`): the realm is quiescent when it dies. The context goes
      // first and its runtime in the same turn — JS_FreeRuntime's empty-GC-list assertion
      // is only satisfiable once the context is gone (see newRuntime above).
      const timer = setTimeout(() => {
        if (disposed && ctx.alive) {
          ctx.dispose();
          runtime.dispose();
        }
      }, 0) as unknown as { unref?: () => void };
      // Freeing a realm is housekeeping, so it must not be a reason for a process to stay
      // up: a host that disposes its last realm and exits should not wait a turn to
      // release memory the exit reclaims anyway. No-op off Node.
      timer.unref?.();
    },
  };
}
