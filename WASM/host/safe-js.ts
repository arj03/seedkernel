// Zero-authority QuickJS realm (§12.3): ECMAScript intrinsics plus the shared preamble's
// three host functions. The preamble's `__start` reports each invocation's answer through
// `__callDone`/`__callFail`, and every `__host_call` parks and settles via
// `__resolveHostCall`/`__rejectHostCall` — the contract the native binary implements too.
// Invocations are serialized (realm-queue.ts).

import {
  newQuickJSWASMModuleFromVariant,
  type QuickJSWASMModule,
  type QuickJSRuntime,
  type QuickJSContext,
  type QuickJSHandle,
} from "quickjs-emscripten-core";
// The shared §12.3 defaults, the same on every target.
import {
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
  DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  DEFAULT_REALM_MEMORY_BYTES,
} from "./wasm-limits.js";
import { errMessage } from "../services/util.js";
// The in-repo quickjs-ng build (quickjs/build-quickjs-ng.sh), the engine the native binary
// compiles, serving node and the browser. Sync flavour only: host calls are real Promises.
import ngVariantMod from "seedkernel-wasm/quickjs";
const ngVariant = ngVariantMod as unknown as NonNullable<
  Parameters<typeof newQuickJSWASMModuleFromVariant>[0]
>;

import { CallBudget, guestPreamble, type Spend } from "./guest-seam.js";
import {
  CausalContext, createRealmDeadlines, monotonicMs, serializeCalls, settleByDeadline,
  HOST_CALL_LATE, REALM_DISPOSED,
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
    : new Uint8Array(u8).buffer;
}

/** Custody of every guest-to-host copy, by guest-minted call id: the ledger native keeps in
 *  native/hostcalls.go, whose rules apply. This target admits after the copy out of the
 *  guest heap (`admitPayload`), native before it. */
export interface ActiveHostCalls {
  admit(callId: number, payloadBytes: number): void;
  reserve(callId: number, additionalBytes: number): void;
  release(callId: number): void;
  releaseAll(): void;
}

export function createActiveHostCallRegistry(
  maxCalls = DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  maxBytes = DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
): ActiveHostCalls {
  /** call id → bytes charged to it; `bytes` is the sum. */
  const live = new Map<number, number>();
  let bytes = 0;
  const charge = (additionalBytes: number): void => {
    if (additionalBytes > maxBytes - bytes) {
      throw new Error(`guest: too many outstanding host call payload bytes (cap ${maxBytes})`);
    }
    bytes += additionalBytes;
  };
  return {
    admit(callId, payloadBytes): void {
      if (!Number.isSafeInteger(callId)) throw new Error("guest: invalid host call id");
      if (live.has(callId)) throw new Error(`guest: duplicate live host call id ${callId}`);
      if (live.size >= maxCalls) {
        throw new Error(`guest: too many outstanding host calls (cap ${maxCalls})`);
      }
      charge(payloadBytes);
      live.set(callId, payloadBytes);
    },
    reserve(callId, additionalBytes): void {
      const owned = live.get(callId);
      if (owned === undefined) throw new Error("guest: host call is no longer active");
      charge(additionalBytes);
      live.set(callId, owned + additionalBytes);
    },
    release(callId): void {
      const owned = live.get(callId);
      if (owned === undefined) return;
      live.delete(callId);
      bytes -= owned;
    },
    releaseAll(): void {
      live.clear();
      bytes = 0;
    },
  };
}

/** One invocation's execution record. Each host call keeps the record it was made under
 *  and resumes on it, since a deferred invocation outlives its entry (§12.3). */
interface InvocationBudget extends Spend {
  budgetMs: number;
  wallDeadline: number;
  /** Fails this invocation while its answer is pending. */
  reject?: (err: Error) => void;
}

/** Guest execution-time accounting under the current invocation's handoff deadline (§12.3). */
interface ExecClock {
  /** Guest code is about to run. */
  begin(budget: InvocationBudget, causalClock?: CausalClock): void;
  /** Guest code has returned control to the host. */
  end(): void;
  /** Start one invocation, narrowed by the handoff remainder that admitted it. */
  create(deadlineMs?: number): InvocationBudget;
  /** The invocation whose code holds the thread, or last did. */
  readonly current: InvocationBudget;
  /** The remaining execution segment in ms, read when a call is made; a module call runs
   *  under it (§4.3). Infinity for an unbounded realm. */
  remaining(): number;
}

/** Heap cap, and the execution-time guard the clock above drives. */
function configureRealm(ctx: QuickJSContext, opts: RealmOptions): ExecClock {
  ctx.runtime.setMemoryLimit(opts.memoryLimitBytes ?? DEFAULT_REALM_MEMORY_BYTES);
  const configuredMs = opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
  let active: InvocationBudget;
  let segmentStart = 0;
  let segmentClock: CausalClock | undefined;
  let running = false;
  // Installed even for an unbounded realm: a caller can still hand it a finite deadline.
  ctx.runtime.setInterruptHandler(() => {
    if (!running) return false;
    const now = monotonicMs();
    return active.consumedMs + (now - segmentStart) > active.budgetMs || now >= active.wallDeadline;
  });
  return {
    begin(budget, causalClock) {
      active = budget;
      segmentStart = monotonicMs(); segmentClock = causalClock; running = true;
    },
    get current() { return active; },
    end() {
      if (!running) return;
      const elapsed = monotonicMs() - segmentStart;
      active.consumedMs += elapsed;
      running = false;
      const owner = segmentClock;
      segmentClock = undefined;
      owner?.charge(elapsed);
    },
    create(deadlineMs = configuredMs) {
      if (deadlineMs !== Infinity && (!Number.isFinite(deadlineMs) || deadlineMs < 0)) {
        throw new Error("guest: invalid invocation handoff deadline");
      }
      return {
        budgetMs: Math.min(configuredMs, deadlineMs),
        wallDeadline: deadlineMs === Infinity ? Infinity : monotonicMs() + deadlineMs,
        consumedMs: 0,
      };
    },
    remaining() {
      const now = monotonicMs();
      const spent = active.consumedMs + (running ? now - segmentStart : 0);
      return Math.max(0, Math.min(active.budgetMs - spent, active.wallDeadline - now));
    },
  };
}

export const createSafeRealm: RealmFactory = async (opts) => {
  const mod = await getModule();
  const runtime: QuickJSRuntime = mod.newRuntime();
  const ctx: QuickJSContext = runtime.newContext();
  // Phantom contexts (see `pumpJobs`): options present with `contextPointer` undefined.
  // Not `options?.` — no options at all is `getSystemContext()`, cached on the runtime, and
  // disposing it would be a use-after-free.
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
  const causalContext = new CausalContext();
  const activeHostCalls = createActiveHostCallRegistry();
  // The wall-clock half of the same custody (§12.3), one queue per tier.
  const deadlines = createRealmDeadlines();

  // Drain the job queue, throwing on failure. `executePendingJobs` returns its error as a
  // live handle instead of throwing: ignored, an interrupt is swallowed, and undisposed, it
  // aborts the wasm module at dispose().
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
        // Reading the error can fail on an interrupted context; the handle still goes back.
      } finally {
        res.error.dispose();
      }
      throw new Error(msg);
    } finally {
      // executePendingJobs can mint a context nothing disposes: heap growth detaches its
      // ctxPtrOut view and the `?? newContext(...)` fallback fires, and that context aborts
      // the module at runtime free. After the error handle, which that context may own.
      disposePhantoms();
    }
  };

  // Callers awaiting an invocation's answer (§12.3), by invocation id. Answers are reported
  // from inside the realm, so an interrupt or dispose() mid-flight would strand them: the
  // host fails them explicitly — dispose() all, an interrupted continuation its own.
  // Taken on settlement, so a late report finds nothing.
  const invocations = new Map<number, { resolve(bytes: Uint8Array): void; reject(err: Error): void }>();
  let invocationSeq = 0;
  const takeInvocation = (id: number) => {
    const invocation = invocations.get(id);
    invocations.delete(id);
    return invocation;
  };
  const failInvocations = (err: Error): void => {
    for (const invocation of invocations.values()) invocation.reject(err);
    invocations.clear();
  };

  // Settle a parked host.call through the preamble's __resolveHostCall/__rejectHostCall,
  // then pump. `made` is the invocation the call was made under.
  const settleHostCall = (fn: "__resolveHostCall" | "__rejectHostCall", callId: number,
    arg: QuickJSHandle, budget: CallBudget, made: InvocationBudget): void => {
    const settler = ctx.getProp(ctx.global, fn);
    const id = ctx.newNumber(callId);
    // Resume on the invocation that made the call, or on a fresh record for a detached one.
    const under = budget.detached ? clock.create() : made;
    // A continuation is guest code, on the guest's budget. Handles are released in
    // `finally` because an interrupt can land mid-call, and a leaked handle aborts the
    // module at dispose().
    causalContext.run(budget.causalClock, () => {
      clock.begin(under, budget.causalClock);
      try {
        const res = ctx.unwrapResult(ctx.callFunction(settler, ctx.undefined, id, arg));
        res.dispose();
        pumpJobs();
      } catch (err) {
        // Interrupted while resuming: nothing in the realm will settle the caller now.
        under.reject?.(err instanceof Error ? err : new Error(String(err)));
      } finally {
        clock.end();
        id.dispose();
        arg.dispose();
        settler.dispose();
      }
    });
  };

  /** Copy one call's payload out of the guest heap and admit it. `getArrayBuffer` already
   *  mallocs a copy outside setMemoryLimit, and `.slice()` must copy again since the view
   *  dies with its lifetime — so admission can only refuse after the first copy. */
  const admitPayload = (callId: number, handle: QuickJSHandle): Uint8Array => {
    const heapCopy = ctx.getArrayBuffer(handle);
    try {
      // A refused admission must not release: on a duplicate id that ends another's custody.
      activeHostCalls.admit(callId, heapCopy.value.byteLength);
      try { return heapCopy.value.slice(); }
      catch (err) { activeHostCalls.release(callId); throw err; }
    } finally {
      heapCopy.dispose();
    }
  };

  // The single seam. It always returns null; the answer settles the promise the preamble
  // parked under callId, never inside the frame that issued the call.
  const hostCallFn = ctx.newFunction("__host_call", (nameHandle, callIdHandle, payloadHandle) => {
    const name = ctx.getString(nameHandle);
    const callId = ctx.getNumber(callIdHandle);
    // The shared record, not a snapshot: concurrent calls charge the same spend.
    const made = clock.current;
    // Read while the segment is live (§4.3); none left throws at the guest's call site.
    const budget = new CallBudget(clock.remaining(), causalContext.current, made);
    const payload = admitPayload(callId, payloadHandle);
    let answer: Promise<Uint8Array> | Uint8Array;
    try {
      answer = opts.hostCall(name, payload, budget);
    } catch (err) {
      activeHostCalls.release(callId);
      throw err;
    }
    // One settlement either way, so a refused copy reads as a failure and custody ends
    // once (the same shape as native-shim.ts).
    const settle = (bytes: Uint8Array | null, error: unknown): void => {
      try {
        let failure = error;
        if (bytes !== null) {
          try {
            if (!ctx.alive) return;
            // Request and response coexist during the copy in, so reserve both.
            activeHostCalls.reserve(callId, bytes.byteLength);
            settleHostCall("__resolveHostCall", callId, ctx.newArrayBuffer(toArrayBuffer(bytes)), budget, made);
            return;
          } catch (err) {
            failure = err;
          }
        }
        if (ctx.alive) {
          settleHostCall("__rejectHostCall", callId, ctx.newString(errMessage(failure)), budget, made);
        }
      } finally {
        activeHostCalls.release(callId);
      }
    };
    settleByDeadline(deadlines.hostCall, budget.remainingMs, Promise.resolve(answer), HOST_CALL_LATE, settle);
    return ctx.null;
  });
  ctx.setProp(ctx.global, "__host_call", hostCallFn);
  hostCallFn.dispose();

  // The preamble's two reports. The answer crosses as bytes; no guest handle outlives them.
  const callDoneFn = ctx.newFunction("__callDone", (idHandle, bytesHandle) => {
    const answer = ctx.getArrayBuffer(bytesHandle);
    let bytes: Uint8Array;
    try { bytes = answer.value.slice(); } finally { answer.dispose(); }
    takeInvocation(ctx.getNumber(idHandle))?.resolve(bytes);
  });
  const callFailFn = ctx.newFunction("__callFail", (idHandle, messageHandle) => {
    takeInvocation(ctx.getNumber(idHandle))?.reject(new Error(ctx.getString(messageHandle)));
  });
  ctx.setProp(ctx.global, "__callDone", callDoneFn);
  callDoneFn.dispose();
  ctx.setProp(ctx.global, "__callFail", callFailFn);
  callFailFn.dispose();

  // Load the preamble, then the guest; dispose each completion value (leaks assert).
  ctx.unwrapResult(ctx.evalCode(guestPreamble(), "guest-preamble.js")).dispose();
  // Top level runs on a fresh budget too, or `for (;;) {}` would wedge the install.
  clock.begin(clock.create());
  try {
    ctx.unwrapResult(ctx.evalCode(opts.source, "safe-js-guest.js")).dispose();
  } catch (err) {
    // No dispose seam is returned for a guest that failed to initialize, so free it here,
    // custody of any calls it parked included, or rejected installs leak.
    activeHostCalls.releaseAll();
    deadlines.disarmAll();
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

  /** The preamble's entrypoint, retained once for every dispatch. */
  const start = ctx.getProp(ctx.global, "__start");

  /** One invocation, once the queue has given it the realm. Not `async`: the queue needs
   *  the `Invocation` when the synchronous segment ends, before the answer exists. */
  const invoke = (payload: Uint8Array, deadlineMs: number, causalClock?: CausalClock): Invocation => {
    // Kept through every host-call settlement; a later entry gets its own.
    const invocationBudget = clock.create(deadlineMs);
    const id = ++invocationSeq;
    const result = new Promise<Uint8Array>((resolve, reject) => { invocations.set(id, { resolve, reject }); });
    const fail = (err: Error): void => { takeInvocation(id)?.reject(err); };
    invocationBudget.reject = fail;
    let deferred = false;
    causalContext.run(causalClock, () => {
      clock.begin(invocationBudget, causalClock);
      let argument: QuickJSHandle | undefined;
      let idHandle: QuickJSHandle | undefined;
      try {
        argument = ctx.newArrayBuffer(toArrayBuffer(payload));
        idHandle = ctx.newNumber(id);
        // Runs `handle` to its first await; the pump runs the queued continuations.
        const flag = ctx.unwrapResult(ctx.callFunction(start, ctx.undefined, idHandle, argument));
        deferred = ctx.getNumber(flag) === 1;
        flag.dispose();
        pumpJobs();
      } catch (err) {
        // Interrupt or engine fault: nothing inside will report. A reported answer stands.
        fail(err instanceof Error ? err : new Error(String(err)));
      } finally {
        // Past this point the host waits on the seam, which is not the guest's time.
        clock.end();
        idHandle?.dispose();
        argument?.dispose();
      }
    });
    return { result, deferred, cancel: fail };
  };

  return {
    call: serializeCalls(deadlines.entry, invoke, () =>
      ctx.alive ? null : new Error(REALM_DISPOSED),
    opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS, opts.ownTurns),
    dispose(): void {
      // Fail every waiting caller first: answers only come from inside the realm.
      failInvocations(new Error(REALM_DISPOSED));
      // Nothing will consume unanswered calls now, so end their custody and deadlines.
      activeHostCalls.releaseAll();
      deadlines.disarmAll();
      // Context before runtime; `start` is the only handle held between calls, and one live
      // handle would abort the whole wasm module.
      if (!ctx.alive) return;
      start.dispose();
      ctx.dispose();
      runtime.dispose();
    },
  };
};
