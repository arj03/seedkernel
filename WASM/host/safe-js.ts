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
// Async seam: a guest is typically multi-step, and the net steps genuinely round-trip.
// `host.call` resolves a **sync op** (crypto/fs/clock/module) to its bytes immediately and
// a **net op** to a real Promise the guest `await`s. The guest builds that Promise itself
// (the shared preamble parks it under a `callId`); this host returns `null` to say "started
// async", then settles it with `__netResolve`/`__netReject` and pumps `executePendingJobs()`
// so the awaiting continuation runs. Deliberately NOT quickjs-emscripten's `newPromise()`
// deferred: keeping the async half in plain ECMAScript is what lets this host and the
// native loader (guest.go, quickjs-ng over wazero, which has no promise primitive) share
// ONE preamble — see `guestPreamble` in cap-bridge.ts.
//
// There is no Asyncify and no host-driven step loop: a suspended async guest is just heap
// state, so the same realm can be re-entered synchronously to serve a request (`callSync`,
// the holder path) while an initiator (`call`) is parked mid-`await`. One `quickjs.wasm`
// build serves both roles. An app builds its own guest confinement on top of this generic
// primitive (README §12.3).

import {
  newQuickJSWASMModule,
  type QuickJSWASMModule,
  type QuickJSContext,
  type QuickJSHandle,
} from "quickjs-emscripten";
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

/** The one capability seam. `op` selects a host capability (net / store / crypto / clock /
 *  rand, mapped by the host); `payload`/return are opaque bytes, exactly like
 *  `kernel.call(name, payload) -> bytes`. A sync op returns bytes directly; a net op — the
 *  only genuinely async one — returns a Promise the guest awaits. */
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
  /** Invoke a guest entrypoint as an *initiator* (may `await` net). The arg and result
   *  cross as raw bytes (the copy model). Resolves when the guest promise settles —
   *  including all awaited host bridges. Concurrent `call()`s on one realm are safe: the
   *  arg is consumed synchronously before the first `await`, so they never clobber. */
  call(entry: string, payload: Uint8Array): Promise<Uint8Array>;
  /** Invoke a guest entrypoint synchronously — the *holder* request side (README §12.8).
   *  The entrypoint runs straight through to its bytes without yielding, so it can run
   *  *while* an initiator `call()` is parked mid-`await` in the same realm (a suspended
   *  async function is heap state; this is an ordinary re-entrant JS call). The
   *  entrypoint must reach only sync ops — a net op returns a Promise a sync entrypoint
   *  cannot resolve, which surfaces as an error here by design. Never pumps the job
   *  queue, so a re-entrant holder call cannot advance a parked initiator's continuation
   *  out of order. */
  callSync(entry: string, payload: Uint8Array): Uint8Array;
  dispose(): void;
}

/** Default heap cap for a realm (README §16.1). */
const DEFAULT_REALM_MEMORY_BYTES = 64 * 1024 * 1024;

/** Default budget of guest execution time per entrypoint invocation (README §16.1).
 *  Generous for any real request — the storage guest's heaviest local pass is orders
 *  of magnitude under it — and short enough that a wedged guest frees the single
 *  host thread rather than holding it forever. */
const DEFAULT_DEADLINE_MS = 5000;

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
 *  infinite loop. */
interface ExecClock {
  /** Guest code is about to run. */
  begin(): void;
  /** Guest code has returned control to the host. */
  end(): void;
  /** Start a fresh budget — one top-level entrypoint invocation. */
  reset(): void;
  /** Suspend the current budget and start a fresh one, returning the suspended total.
   *  A re-entrant holder `callSync` runs while an initiator sits parked in the same
   *  realm; it gets its own budget rather than spending — or clearing — the
   *  initiator's. */
  enterNested(): number;
  /** Restore a budget suspended by `enterNested`. */
  exitNested(saved: number): void;
}

/** Heap cap, and the execution-time guard the clock above drives. */
function configureRealm(ctx: QuickJSContext, opts: SafeRealmOptions): ExecClock {
  ctx.runtime.setMemoryLimit(opts.memoryLimitBytes ?? DEFAULT_REALM_MEMORY_BYTES);
  const budgetMs = opts.deadlineMs ?? DEFAULT_DEADLINE_MS;
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
    enterNested() { const saved = consumedMs; consumedMs = 0; return saved; },
    exitNested(saved) { consumedMs = saved; },
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
  const ctx: QuickJSContext = mod.newContext();
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

  // Settle a parked net op by calling the guest's own __netResolve/__netReject (the
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

  // The single seam. QuickJS calls it synchronously: a sync op resolves to its bytes and
  // we hand the ArrayBuffer straight back; a net op genuinely round-trips, so we return
  // null — the preamble parks a Promise under callId — and settle it when the bridge
  // promise resolves. Returning null (rather than a host-created deferred) is what keeps
  // this seam identical to the native loader's; see guestPreamble.
  const hostCall = ctx.newFunction("__host_call", (opHandle, callIdHandle, payloadHandle) => {
    const op = ctx.getNumber(opHandle);
    const callId = ctx.getNumber(callIdHandle);
    const result = opts.bridge(op, copyPayload(ctx, payloadHandle));
    if (!result || typeof (result as Promise<Uint8Array>).then !== "function") {
      // Sync op — return the bytes directly (no promise, no job queue).
      return ctx.newArrayBuffer(toArrayBuffer(result as Uint8Array));
    }
    // Net op — a genuine round trip. The guest holds the Promise; we settle it by callId.
    (result as Promise<Uint8Array>).then(
      (bytes) => {
        if (disposed || !ctx.alive) return;
        settleNet("__netResolve", callId, ctx.newArrayBuffer(toArrayBuffer(bytes)));
      },
      (err) => {
        if (disposed || !ctx.alive) return;
        settleNet("__netReject", callId, ctx.newString(String((err && (err as Error).message) || err)));
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

  return {
    async call(entry: string, payload: Uint8Array): Promise<Uint8Array> {
      // Reset only when nothing else is in flight. The interrupt handler is per-realm and
      // cannot tell whose code is running, so concurrent initiator calls necessarily
      // share one budget window; resetting unconditionally would let a second call clear
      // an in-flight call's accumulated time, which is an escape hatch a guest's own
      // traffic could open. One idle realm ⇒ one fresh budget per busy period.
      if (pending.size === 0) clock.reset();
      stageArg(ctx, payload);
      // evalCode runs the entrypoint synchronously up to its first await; the completion
      // value is either the bytes (sync entrypoint) or a pending guest promise (async
      // entrypoint). resolvePromise normalizes both to a native promise, but it settles
      // only once the job queue is pumped — hence resolvePromise → executePendingJobs →
      // await, in that order (awaiting before the first pump would stall a sync entrypoint).
      // Net awaits are then driven by each deferred's own executePendingJobs on settle.
      let evalResult: QuickJSHandle;
      let settledNative: Promise<unknown>;
      clock.begin();
      try {
        evalResult = ctx.unwrapResult(ctx.evalCode(invokeSrc(entry), "safe-js-invoke.js"));
        settledNative = ctx.resolvePromise(evalResult) as Promise<unknown>;
        pumpJobs();
      } finally {
        // Closed before the await below: everything past this point is the host
        // waiting on a bridge, which is not the guest's time to spend.
        clock.end();
      }
      let rejectThis!: (err: Error) => void;
      const failed = new Promise<never>((_, reject) => { rejectThis = reject; });
      pending.add(rejectThis);
      try {
        const settled = await Promise.race([settledNative, failed]);
        return takeBytes(ctx, ctx.unwrapResult(settled as never));
      } finally {
        pending.delete(rejectThis);
        // In `finally` for the same reason as settleNet's handles: an interrupted or
        // failed call must not leave this alive, or dispose() aborts the module.
        if (ctx.alive) evalResult.dispose();
      }
    },
    callSync(entry: string, payload: Uint8Array): Uint8Array {
      const saved = clock.enterNested();
      stageArg(ctx, payload);
      // A sync (holder) entrypoint returns its ArrayBuffer directly. Deliberately no
      // executePendingJobs: a re-entrant holder call must not advance a parked
      // initiator's continuation. If a net op slipped in, the result is a guest promise
      // and getArrayBuffer throws — by design (a holder answers from local fs + crypto).
      clock.begin();
      try {
        return takeBytes(ctx, ctx.unwrapResult(ctx.evalCode(invokeSrc(entry), "safe-js-invoke.js")));
      } finally {
        clock.end();
        clock.exitNested(saved);
      }
    },
    dispose(): void {
      disposed = true;
      // Fail anyone still awaiting a guest promise before tearing the realm down: those
      // promises can only be settled from inside the realm, so disposing first would
      // strand every parked caller.
      failPending(new Error("guest realm disposed"));
      ctx.dispose();
    },
  };
}
