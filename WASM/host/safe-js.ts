// Zero-authority QuickJS realm (§12.3): ECMAScript intrinsics plus one injected
// `__host_call`. Every call parks and settles via `__netResolve`/`__netReject` in the
// shared preamble — not quickjs-emscripten's `newPromise()`, so this host and the
// native loader share one guest seam contract. Invocations are serialized
// (realm-queue.ts).

import {
  newQuickJSWASMModuleFromVariant,
  type QuickJSWASMModule,
  type QuickJSRuntime,
  type QuickJSContext,
  type QuickJSHandle,
} from "quickjs-emscripten-core";
// The shared §12.3 defaults — one copy on every target, so a guest meets the same
// ceiling and the same budget whether its realm is this one or the native target's.
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_REALM_MEMORY_BYTES } from "../core/wasm-limits.js";
import { errMessage } from "../core/util.js";
// The in-repo quickjs-ng build (quickjs/): the same v0.16.1 the native loader compiles,
// emscripten-built by quickjs/build-quickjs-ng.sh, whose glue serves node AND the browser.
// Only the non-Asyncify (sync) flavour is needed — net is a real Promise resolved by the
// host, not an Asyncify stack unwind. The cast bridges the ESM variant's typing gap.
import ngVariantMod from "seedkernel-wasm/quickjs";
const ngVariant = ngVariantMod as unknown as NonNullable<
  Parameters<typeof newQuickJSWASMModuleFromVariant>[0]
>;

// The guest-side ABI, shared with the native loader. See `guestPreamble` for the
// `__host_call` / `__netResolve` contract this file implements.
import { guestPreamble, type CallBudget } from "./guest-seam.js";
import {
  CausalContext, createActiveHostCallRegistry, createHandoffDeadlines, monotonicMs, serializeCalls,
  type CausalClock, type Invocation, type RealmFactory, type RealmOptions,
} from "./realm-queue.js";

let modulePromise: Promise<QuickJSWASMModule> | undefined;
/** The QuickJS WASM module is loaded once and shared by all realms. */
function getModule(): Promise<QuickJSWASMModule> {
  return (modulePromise ??= newQuickJSWASMModuleFromVariant(ngVariant));
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength
    ? (u8.buffer as ArrayBuffer)
    : (u8.slice().buffer as ArrayBuffer);
}

/** Guest execution-time accounting under the current invocation's handoff deadline (§12.3). */
interface ExecClock {
  /** Guest code is about to run. */
  begin(causalClock?: CausalClock): void;
  /** Guest code has returned control to the host. */
  end(): void;
  /** Start one invocation, narrowed by the handoff remainder that admitted it. */
  reset(deadlineMs?: number): void;
  /** The guest's remaining execution segment, in ms — read at the moment a call is made,
   *  and carried as a module call's deadline, so a module runs under the budget of the
   *  segment that called it (§4.3). Infinity for an unbounded realm. */
  remaining(): number;
  /** Add CPU the host burned ON THE GUEST'S BEHALF to this segment's spend — a module call,
   *  whose time is the guest's by §4.3 but is burned while the segment is closed. What it
   *  bounds that the handoff deadline cannot is CONCURRENT burn: a guest awaiting one module
   *  at a time spends wall clock at the same rate, so the deadline already stops it, but a
   *  guest fanning out to N workers burns N ms of CPU per ms of its own wait. Summing the
   *  measured burns is what holds that sum inside the window the invocation was admitted
   *  under, instead of multiplying it by however many modules the bundle ships. */
  charge(ms: number): void;
}

/** Heap cap, and the execution-time guard the clock above drives. */
function configureRealm(ctx: QuickJSContext, opts: RealmOptions): ExecClock {
  ctx.runtime.setMemoryLimit(opts.memoryLimitBytes ?? DEFAULT_REALM_MEMORY_BYTES);
  const configuredMs = opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
  let budgetMs = configuredMs;
  let wallDeadline = Infinity;
  let consumedMs = 0;
  let segmentStart = 0;
  let segmentClock: CausalClock | undefined;
  let running = false;
  // An unbounded realm can still receive a finite caller-owned handoff, so the interrupt
  // handler is installed for dynamic invocation limits rather than only for the default.
  ctx.runtime.setInterruptHandler(() => {
    if (!running) return false;
    const now = monotonicMs();
    return consumedMs + (now - segmentStart) > budgetMs || now >= wallDeadline;
  });
  return {
    begin(causalClock) { segmentStart = monotonicMs(); segmentClock = causalClock; running = true; },
    end() {
      if (!running) return;
      const elapsed = monotonicMs() - segmentStart;
      consumedMs += elapsed;
      running = false;
      const owner = segmentClock;
      segmentClock = undefined;
      owner?.charge(elapsed);
    },
    reset(deadlineMs = configuredMs) {
      if (deadlineMs !== Infinity && (!Number.isFinite(deadlineMs) || deadlineMs < 0)) {
        throw new Error("guest: invalid invocation handoff deadline");
      }
      budgetMs = Math.min(configuredMs, deadlineMs);
      wallDeadline = deadlineMs === Infinity ? Infinity : monotonicMs() + deadlineMs;
      consumedMs = 0;
    },
    remaining() {
      const now = monotonicMs();
      const spent = consumedMs + (running ? now - segmentStart : 0);
      return Math.max(0, Math.min(budgetMs - spent, wallDeadline - now));
    },
    charge(ms) { if (ms > 0) consumedMs += ms; },
  };
}

/** Stage the entrypoint argument as the realm global `__arg` (copy boundary). */
function stageArg(ctx: QuickJSContext, payload: Uint8Array): void {
  const argHandle = ctx.newArrayBuffer(toArrayBuffer(payload));
  ctx.setProp(ctx.global, "__arg", argHandle);
  argHandle.dispose();
}

/** Take ownership of a result handle and copy its bytes out (copy boundary). The handle
 *  must go back even when the value is not an ArrayBuffer: an orphaned handle keeps its
 *  object on the runtime's GC list, which aborts the module at runtime free. */
function takeBytes(ctx: QuickJSContext, handle: QuickJSHandle): Uint8Array {
  const lt = ctx.getArrayBuffer(handle);
  try {
    return lt.value.slice();
  } finally {
    lt.dispose();
    handle.dispose();
  }
}

const invokeSrc = `__invoke(__arg)`;

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

/** A realm's QuickJS **runtime** is created separately from its context, so `dispose()` can
 *  free both in the required order: the context first, its runtime in the same deferred turn.
 *  `JS_FreeRuntime` asserts an empty GC object list, so any object still referenced — an
 *  undisposed host handle, or a live context — aborts the whole wasm module and every other
 *  realm with it. Deferring one macrotask lets a parked invocation's rejection continuation
 *  run first, after which nothing can re-enter (the queue fails on `disposed`). */
const newRuntime = (mod: QuickJSWASMModule): QuickJSRuntime => mod.newRuntime();

export const createSafeRealm: RealmFactory = async (opts) => {
  const mod = await getModule();
  // NOT `mod.newContext()`: that couples the runtime's lifetime to the context's, freeing
  // both in the same breath — the teardown order described above, which dispose() must
  // control itself.
  const runtime = newRuntime(mod);
  const ctx: QuickJSContext = runtime.newContext();
  // Contexts quickjs-emscripten creates from a contextPointer that READ as undefined — the
  // phantom in `pumpJobs` below. Tracked from after the realm's own context, so that one is
  // not one of them. The test is `options` present with `contextPointer` undefined, not
  // `options?.`: passing no options at all is `getSystemContext()`, which CACHES its context
  // on the runtime — disposing that would be a use-after-free.
  const phantoms = new Set<QuickJSContext>();
  {
    const newContext = runtime.newContext.bind(runtime);
    runtime.newContext = (options?: Parameters<typeof newContext>[0]) => {
      const c = newContext(options);
      if (options !== undefined && options.contextPointer === undefined) phantoms.add(c);
      return c;
    };
  }
  /** Release every phantom context discovered since the previous drain. Best-effort: a
   *  context may already have been disposed while unwinding another engine operation. */
  const disposePhantoms = (): void => {
    for (const phantom of phantoms) {
      if (phantom.alive) {
        try { phantom.dispose(); } catch { /* already gone */ }
      }
    }
    phantoms.clear();
  };
  const clock = configureRealm(ctx, opts);
  let disposed = false;
  const causalContext = new CausalContext();
  const activeHostCalls = createActiveHostCallRegistry();
  // The wall-clock half of the same custody: one armed deadline per unsettled host call,
  // disposed with the realm so an abandoned timer cannot outlive it (realm-queue.ts).
  const handoffDeadlines = createHandoffDeadlines();

  // Drain the guest's job queue, surfacing a failure as a thrown error. `executePendingJobs`
  // does NOT throw — it *returns* a result whose `error` is a live QuickJS handle. Both
  // consequences bit: an interrupted continuation (the budget firing inside a queued job) was
  // silently swallowed, and the undisposed error handle later aborted the wasm module at
  // dispose() on the empty-GC-list assertion.
  const pumpJobs = (): void => {
    const res = ctx.runtime.executePendingJobs();
    try {
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
    } finally {
      // quickjs-emscripten's executePendingJobs can create a context nothing will dispose:
      // when the wasm heap grows mid-call its ctxPtrOut view detaches, ctxPtr reads
      // undefined, and the `?? newContext({contextPointer})` fallback fires. Such a context
      // keeps GC objects alive, aborting the module at runtime free. After the error handle,
      // not before: when a job throws in the same call that grew the heap, `res.error` is a
      // handle the phantom minted, so freeing the context first would turn the release above
      // into a throw on a dead Lifetime.
      disposePhantoms();
    }
  };

  // Rejectors for calls currently awaiting a guest promise (§12.3) — a DEFERRED entrypoint
  // included. Its handoff deadline supplies the wall-clock bound (realm-queue.ts). A guest promise
  // is settled from *inside* the realm, so anything that stops the realm mid-flight — a
  // budget interrupt during a continuation, or dispose() while a call is parked or deferred
  // — leaves it permanently pending. A bound that turns a runaway or silent guest into a
  // hung host is not much of a bound, so the realm fails them explicitly.
  const liveInvocations = new Set<(err: Error) => void>();
  const failInvocations = (err: Error): void => {
    for (const reject of liveInvocations) reject(err);
    liveInvocations.clear();
  };

  // Settle a parked host.call by calling the guest's own __netResolve/__netReject (the
  // preamble's half of the contract), then pump so the awaiting continuation runs.
  const settleNet = (fn: "__netResolve" | "__netReject", callId: number, arg: QuickJSHandle,
    causalClock?: CausalClock): void => {
    const settler = ctx.getProp(ctx.global, fn);
    const id = ctx.newNumber(callId);
    // The continuation of a parked `await` is guest code, so it runs on the guest's budget.
    // Every handle is released in `finally`, which is load-bearing rather than tidy: this
    // call can be interrupted mid-flight by the budget, and a runtime freed with live handles
    // aborts the whole wasm module at dispose() time.
    causalContext.run(causalClock, () => {
      clock.begin(causalClock);
      try {
        const res = ctx.unwrapResult(ctx.callFunction(settler, ctx.undefined, id, arg));
        res.dispose();
        pumpJobs();
      } catch (err) {
        // The guest was interrupted while resuming, so nothing inside the realm will ever
        // settle the caller's promise: fail it here, or `call()` hangs forever.
        failInvocations(err instanceof Error ? err : new Error(String(err)));
      } finally {
        clock.end();
        id.dispose();
        arg.dispose();
        settler.dispose();
      }
    });
  };

  // The single seam. QuickJS calls it synchronously; the answer never comes back this
  // way. `null` is the one return: the preamble parks a Promise under callId, and the
  // seam's Promise — every name is async now, refused names included — settles it here.
  // `Promise.resolve` flattens an inline answer too, so no continuation ever re-enters
  // the realm inside the frame that issued the call.
  const hostCallFn = ctx.newFunction("__host_call", (nameHandle, callIdHandle, payloadHandle) => {
    const name = ctx.getString(nameHandle);
    const callId = ctx.getNumber(callIdHandle);
    // Host plumbing, not ABI (`CallBudget`): `remainingMs` is read HERE while the segment is
    // live — what a module call runs under; `charge` bills a module's burn once it settles,
    // since the segment is closed by then (§4.3).
    const causalClock = causalContext.current;
    const budget: CallBudget = {
      remainingMs: clock.remaining(),
      charge: (ms) => { clock.charge(ms); causalClock?.charge(ms); },
      causalClock,
    };
    if (budget.remainingMs <= 0) throw new Error("guest: handoff deadline exhausted before host.call");
    // Inspect the borrowed view first, reserve both count and bytes, and only then copy.
    // `getArrayBuffer` owns a lifetime but not another payload-sized allocation.
    const [payload, activeCall] = (() => {
      const borrowed = ctx.getArrayBuffer(payloadHandle);
      try {
        const call = activeHostCalls.admit(callId, borrowed.value.byteLength);
        try { return [borrowed.value.slice(), call] as const; }
        catch (err) { call.release(); throw err; }
      } finally {
        borrowed.dispose();
      }
    })();
    let answer: Promise<Uint8Array> | Uint8Array;
    try {
      answer = opts.hostCall(name, payload, budget);
    } catch (err) {
      activeCall.release();
      throw err;
    }
    // Expiry arrives as an ordinary rejection, so the deadline needs no settlement path of
    // its own: the arm below is the only one, for a backend answer and a late one alike.
    void handoffDeadlines.race(budget.remainingMs, Promise.resolve(answer),
      "guest: host.call handoff deadline exceeded").then(
      (bytes) => {
        try {
          if (disposed || !ctx.alive) return;
          // Request and response coexist while copying the result into the guest. Reserve
          // that overlap and keep the call live through guest-side settlement.
          activeCall.reserve(bytes.byteLength);
          settleNet("__netResolve", callId, ctx.newArrayBuffer(toArrayBuffer(bytes)), causalClock);
        } catch (err) {
          if (!disposed && ctx.alive) {
            settleNet("__netReject", callId, ctx.newString(errMessage(err)), causalClock);
          }
        } finally {
          activeCall.release();
        }
      },
      (err) => {
        try {
          if (!disposed && ctx.alive) {
            settleNet("__netReject", callId, ctx.newString(errMessage(err)), causalClock);
          }
        } finally {
          activeCall.release();
        }
      },
    );
    return ctx.null;
  });
  ctx.setProp(ctx.global, "__host_call", hostCallFn);
  hostCallFn.dispose();

  // Load the ABI preamble, then the guest. Neither has authority. Each eval's completion
  // value is an owned handle — dispose it, since the QuickJS build asserts on leaks.
  ctx.unwrapResult(ctx.evalCode(guestPreamble(), "guest-preamble.js")).dispose();
  // Construction is the first path guest code runs on, so it gets the same fresh budget
  // as an entrypoint. Without this guard, a signed top-level `for (;;) {}` wedges the host
  // before installation can either commit or fail.
  clock.reset();
  clock.begin();
  try {
    ctx.unwrapResult(ctx.evalCode(opts.source, "safe-js-guest.js")).dispose();
  } catch (err) {
    // A candidate that cannot initialize never reaches the returned dispose seam. Free it
    // here, or repeated rejected installs turn a bounded guest into an unbounded host leak
    // — the custody of any call its source parked included, since nothing is left to
    // consume those answers and no handle survives to release them later.
    disposed = true;
    activeHostCalls.releaseAll();
    disposePhantoms();
    try {
      if (ctx.alive) ctx.dispose();
    } finally {
      runtime.dispose();
    }
    throw err;
  } finally {
    clock.end();
  }

  /** Did the entrypoint that just ran hand its answer over to a later turn (the
   *  preamble's `defer()`)? Read once, immediately after the synchronous segment, and
   *  cleared by `__invoke` rather than here — so the flag describes exactly the
   *  invocation that just ran. */
  const wasDeferred = (): boolean => {
    const flag = ctx.getProp(ctx.global, "__deferred");
    try {
      return ctx.dump(flag) === true;
    } finally {
      flag.dispose();
    }
  };

  /** One entrypoint invocation, assuming the queue has already given it the realm.
   *
   *  Not `async`: the queue needs the `Invocation` — and with it the release signal —
   *  the moment the synchronous segment ends, which is before the answer exists. */
  const invoke = (payload: Uint8Array, deadlineMs: number, causalClock?: CausalClock): Invocation => {
    // Safe unconditionally because the queue guarantees nothing else is RUNNING. A deferred
    // entrypoint has already ended its segment by the time the next one resets, so what it
    // spends settling later is charged to whichever window is open — which is whose turn
    // the guest code actually runs on.
    clock.reset(deadlineMs);
    stageArg(ctx, payload);
    // evalCode runs the entrypoint synchronously up to its first await; the completion value
    // is either the bytes (sync entrypoint) or a pending guest promise (async entrypoint).
    // resolvePromise normalizes both to a native promise, but it settles only once the job
    // queue is pumped — hence resolvePromise → executePendingJobs → await, in that order
    // (awaiting before the first pump would stall a sync entrypoint). Awaits are then driven
    // by each deferred's own executePendingJobs on settle.
    let evalResult: QuickJSHandle | undefined;
    let settledNative: Promise<unknown> | undefined;
    causalContext.run(causalClock, () => {
      clock.begin(causalClock);
      try {
        evalResult = ctx.unwrapResult(ctx.evalCode(invokeSrc, "safe-js-invoke.js"));
        settledNative = ctx.resolvePromise(evalResult) as Promise<unknown>;
        pumpJobs();
      } finally {
        // Closed before the await below: past this point the host is waiting on the seam,
        // which is not the guest's time to spend.
        clock.end();
        // resolvePromise has consumed the value; the eval handle must go back even when
        // pumpJobs throws, or it aborts the module at runtime free.
        evalResult?.dispose();
      }
    });
    // Read before anything awaits, so no later invocation's `__invoke` can have cleared it.
    const deferred = wasDeferred();
    let cancel = (_reason: Error): void => {};
    const result = (async () => {
      let rejectThis!: (err: Error) => void;
      const failed = new Promise<never>((_, reject) => { rejectThis = reject; });
      cancel = (reason) => rejectThis(reason);
      liveInvocations.add(rejectThis);
      let consumed = false;
      try {
        const settled = await Promise.race([settledNative as Promise<unknown>, failed]);
        consumed = true;
        return takeBytes(ctx, ctx.unwrapResult(settled as never));
      } finally {
        liveInvocations.delete(rejectThis);
        // An invocation that lost the race to failAll has no consumer for the settled
        // result, so if the guest promise still settles afterwards its dup'd handle would be
        // orphaned and abort the module at runtime free. Release it when it lands.
        if (!consumed) {
          void (settledNative as Promise<unknown>).then(disposeDisposableResult);
        }
      }
    })();
    // A deferred answer must not go unhandled while nothing is awaiting `released`:
    // the caller holds `result` and its real error, so the release arm swallows.
    return {
      result,
      released: deferred ? Promise.resolve() : result.catch(() => {}),
      cancel: (reason) => cancel(reason),
    };
  };

  return {
    call: serializeCalls(invoke, () =>
      (disposed || !ctx.alive) ? new Error("guest realm disposed") : null,
      opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS),
    dispose(): void {
      disposed = true;
      // Fail anyone still awaiting a guest promise before tearing the realm down: those
      // promises can only be settled from inside the realm, so disposing first would
      // strand every parked caller — a DEFERRED one included, whose answer would
      // otherwise never come (realm-queue.ts's time-bound invariant).
      failInvocations(new Error("guest realm disposed"));
      // And end custody of every call the host never answered: nothing inside this realm
      // will consume those answers now, so holding their charge would pin this realm's
      // allowance on one unanswering backend forever (realm-queue.ts `ActiveHostCall`).
      // Their deadlines go with them: a timer left waiting to reject a call this realm no
      // longer holds keeps the host's event loop alive for the whole of its remainder, so a
      // one-shot process would linger a full budget past the work it came to do.
      activeHostCalls.releaseAll();
      handoffDeadlines.disarmAll();
      // ...but the engine must NOT die in the same turn: a parked invocation's rejection
      // continuation runs as a microtask after failAll, and a handle released after its
      // context died would abort the whole wasm module. See `newRuntime` for the ordering
      // this deferral buys.
      const timer = setTimeout(() => {
        if (disposed && ctx.alive) {
          ctx.dispose();
          runtime.dispose();
        }
      }, 0) as unknown as { unref?: () => void };
      // Freeing a realm is housekeeping and must not keep a process up: a host that
      // disposes its last realm and exits reclaims the memory anyway. No-op off Node.
      timer.unref?.();
    },
  };
};
