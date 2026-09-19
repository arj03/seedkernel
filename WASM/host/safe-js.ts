// Zero-authority QuickJS realm (§12.3): ECMAScript intrinsics plus the shared preamble's
// three host functions. The preamble's `__start` reports each invocation's answer through
// `__callDone`/`__callFail`, and every `__host_call` parks and settles via
// `__resolveHostCall`/`__rejectHostCall` — the contract the native loader implements too.
// Invocations are serialized (realm-queue.ts).

import {
  newQuickJSWASMModuleFromVariant,
  type QuickJSWASMModule,
  type QuickJSRuntime,
  type QuickJSContext,
  type QuickJSHandle,
} from "quickjs-emscripten-core";
// The shared §12.3 defaults — one copy on every target, so a guest meets the same
// ceiling and the same budget whether its realm is this one or the native target's.
import {
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
  DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  DEFAULT_REALM_MEMORY_BYTES,
} from "../core/wasm-limits.js";
import { errMessage } from "../core/util.js";
// The in-repo quickjs-ng build (quickjs/): the same v0.16.2 the native loader compiles,
// emscripten-built by quickjs/build-quickjs-ng.sh, whose glue serves node AND the browser.
// Only the non-Asyncify (sync) flavour is needed — net is a real Promise resolved by the
// host, not an Asyncify stack unwind. The cast bridges the ESM variant's typing gap.
import ngVariantMod from "seedkernel-wasm/quickjs";
const ngVariant = ngVariantMod as unknown as NonNullable<
  Parameters<typeof newQuickJSWASMModuleFromVariant>[0]
>;

// The guest-side ABI, shared with the native loader. See `guestPreamble` for the
// `__start` / `__host_call` contract this file implements.
import { guestPreamble, type CallBudget } from "./guest-seam.js";
import {
  CausalContext, createDeadlineQueue, monotonicMs, raceDeadline, serializeCalls, REALM_DISPOSED,
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

function checkedBytes(bytes: number): number {
  if (!Number.isSafeInteger(bytes) || bytes < 0) {
    throw new Error("guest: payload width is not a non-negative safe integer");
  }
  return bytes;
}

/** One active call's custody, held from admission through settlement. */
export interface ActiveHostCall {
  reserve(bytes: number): void;
  release(): void;
}

/** Own every guest-to-host copy and promise slot from admission through settlement. This
 *  target's own: native admits the same numbers in Go, before the copy (native/hostcalls.go). */
export function createActiveHostCallRegistry(
  maxCalls = DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  maxBytes = DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
): {
  admit(callId: number, payloadBytes: number): ActiveHostCall;
  releaseAll(): void;
} {
  const active = new Map<number, ActiveHostCall>();
  let bytes = 0;
  return {
    releaseAll(): void {
      for (const call of [...active.values()]) call.release();
    },
    admit(callId: number, payloadBytes: number): ActiveHostCall {
      if (!Number.isSafeInteger(callId)) throw new Error("guest: invalid host call id");
      if (active.has(callId)) throw new Error(`guest: duplicate live host call id ${callId}`);
      checkedBytes(payloadBytes);
      if (active.size >= maxCalls) {
        throw new Error(`guest: too many outstanding host calls (cap ${maxCalls})`);
      }
      if (payloadBytes > maxBytes - bytes) {
        throw new Error(`guest: too many outstanding host call payload bytes (cap ${maxBytes})`);
      }
      bytes += payloadBytes;
      let owned = payloadBytes;
      let live = true;
      const call: ActiveHostCall = {
        reserve(additionalBytes: number): void {
          if (!live) throw new Error("guest: host call is no longer active");
          checkedBytes(additionalBytes);
          if (additionalBytes > maxBytes - bytes) {
            throw new Error(`guest: too many outstanding host call payload bytes (cap ${maxBytes})`);
          }
          bytes += additionalBytes;
          owned += additionalBytes;
        },
        release(): void {
          if (!live) return;
          live = false;
          active.delete(callId);
          bytes -= owned;
        },
      };
      active.set(callId, call);
      return call;
    },
  };
}

/** One entrypoint invocation's execution record. A deferred invocation outlives its entry,
 *  so each host call keeps the record it was made under and resumes on it (§12.3). */
interface InvocationBudget {
  budgetMs: number;
  wallDeadline: number;
  consumedMs: number;
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
  charge(budget: InvocationBudget, ms: number): void;
}

/** Heap cap, and the execution-time guard the clock above drives. */
function configureRealm(ctx: QuickJSContext, opts: RealmOptions): ExecClock {
  ctx.runtime.setMemoryLimit(opts.memoryLimitBytes ?? DEFAULT_REALM_MEMORY_BYTES);
  const configuredMs = opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
  let active: InvocationBudget;
  let segmentStart = 0;
  let segmentClock: CausalClock | undefined;
  let running = false;
  // An unbounded realm can still receive a finite caller-owned handoff, so the interrupt
  // handler is installed for dynamic invocation limits rather than only for the default.
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
    charge(budget, ms) { if (ms > 0) budget.consumedMs += ms; },
  };
}

export const createSafeRealm: RealmFactory = async (opts) => {
  const mod = await getModule();
  const runtime: QuickJSRuntime = mod.newRuntime();
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
  // The wall-clock half of the same custody (§12.3): one wake for the host calls this realm
  // has not answered, one for the invocations waiting to enter it — never merged, and both
  // disarmed with the realm (realm-queue.ts).
  const hostCallDeadlines = createDeadlineQueue();
  const entryDeadlines = createDeadlineQueue();

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

  // Callers awaiting an invocation's answer (§12.3), by invocation id — a DEFERRED entrypoint
  // included; its handoff deadline supplies the wall-clock bound (realm-queue.ts). The answer
  // is reported from *inside* the realm (`__callDone`/`__callFail`), so anything that stops
  // the realm mid-flight — a budget interrupt during a continuation, or dispose() while a
  // call is parked or deferred — would leave it pending. A bound that turns a runaway or
  // silent guest into a hung host is not much of a bound, so the realm fails them explicitly
  // — dispose() all of them, an interrupted continuation only its own
  // (`InvocationBudget.reject`). Taken on settlement, so a stray or late report finds nothing.
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

  // Settle a parked host.call by calling the guest's own __resolveHostCall/__rejectHostCall
  // (the preamble's half of the contract), then pump so the awaiting continuation runs.
  const settleHostCall = (fn: "__resolveHostCall" | "__rejectHostCall", callId: number, arg: QuickJSHandle,
    invocationBudget: InvocationBudget, causalClock?: CausalClock): void => {
    const settler = ctx.getProp(ctx.global, fn);
    const id = ctx.newNumber(callId);
    // The continuation of a parked `await` is guest code, so it runs on the guest's budget.
    // Every handle is released in `finally`, which is load-bearing rather than tidy: this
    // call can be interrupted mid-flight by the budget, and a runtime freed with live handles
    // aborts the whole wasm module at dispose() time.
    causalContext.run(causalClock, () => {
      clock.begin(invocationBudget, causalClock);
      try {
        const res = ctx.unwrapResult(ctx.callFunction(settler, ctx.undefined, id, arg));
        res.dispose();
        pumpJobs();
      } catch (err) {
        // The guest was interrupted while resuming, so nothing inside the realm will ever
        // settle the caller's promise: fail it here, or `call()` hangs forever.
        invocationBudget.reject?.(err instanceof Error ? err : new Error(String(err)));
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
    // Retain the invocation's shared accounting record, not a snapshot of its
    // remainder: concurrent calls must charge the same accumulated spend.
    const invocationBudget = clock.current;
    let detached = false;
    const budget: CallBudget = {
      remainingMs: clock.remaining(),
      charge: (ms) => { clock.charge(invocationBudget, ms); causalClock?.charge(ms); },
      causalClock,
      detach: () => { detached = true; },
    };
    /** What the answer resumes under: the invocation that made the call, or — detached — a
     *  new turn's own record, minted as the answer lands. */
    const resumeUnder = (): InvocationBudget => (detached ? clock.create() : invocationBudget);
    if (budget.remainingMs <= 0) throw new Error("guest: handoff deadline exhausted before host.call");
    // `getArrayBuffer` reads as a borrow but is not one: QTS_GetArrayBuffer mallocs a
    // payload-sized copy (libc, so outside setMemoryLimit) that the lifetime frees, and
    // `.slice()` must still copy again — the view dies with the lifetime and detaches on
    // heap growth. So admission refuses an over-budget call AFTER that copy, not before.
    const [payload, activeCall] = (() => {
      const heapCopy = ctx.getArrayBuffer(payloadHandle);
      try {
        const call = activeHostCalls.admit(callId, heapCopy.value.byteLength);
        try { return [heapCopy.value.slice(), call] as const; }
        catch (err) { call.release(); throw err; }
      } finally {
        heapCopy.dispose();
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
    void raceDeadline(hostCallDeadlines, budget.remainingMs, Promise.resolve(answer),
      "guest: host.call handoff deadline exceeded").then(
      (bytes) => {
        try {
          if (disposed || !ctx.alive) return;
          // Request and response coexist while copying the result into the guest. Reserve
          // that overlap and keep the call live through guest-side settlement.
          activeCall.reserve(bytes.byteLength);
          settleHostCall("__resolveHostCall", callId, ctx.newArrayBuffer(toArrayBuffer(bytes)), resumeUnder(), causalClock);
        } catch (err) {
          if (!disposed && ctx.alive) {
            settleHostCall("__rejectHostCall", callId, ctx.newString(errMessage(err)), resumeUnder(), causalClock);
          }
        } finally {
          activeCall.release();
        }
      },
      (err) => {
        try {
          if (!disposed && ctx.alive) {
            settleHostCall("__rejectHostCall", callId, ctx.newString(errMessage(err)), resumeUnder(), causalClock);
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

  // The preamble's two reports (`__start`). The answer is copied out before its invocation
  // is taken, so it reaches the caller as bytes and no guest handle outlives the report.
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

  // Load the ABI preamble, then the guest. Neither has authority. Each eval's completion
  // value is an owned handle — dispose it, since the QuickJS build asserts on leaks.
  ctx.unwrapResult(ctx.evalCode(guestPreamble(), "guest-preamble.js")).dispose();
  // Construction is the first path guest code runs on, so it gets the same fresh budget
  // as an entrypoint. Without this guard, a signed top-level `for (;;) {}` wedges the host
  // before installation can either commit or fail.
  clock.begin(clock.create());
  try {
    ctx.unwrapResult(ctx.evalCode(opts.source, "safe-js-guest.js")).dispose();
  } catch (err) {
    // A candidate that cannot initialize never reaches the returned dispose seam. Free it
    // here, or repeated rejected installs turn a bounded guest into an unbounded host leak
    // — the custody of any call its source parked included, since nothing is left to
    // consume those answers and no handle survives to release them later.
    disposed = true;
    activeHostCalls.releaseAll();
    hostCallDeadlines.disarmAll();
    entryDeadlines.disarmAll();
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

  /** The preamble's entrypoint, retained once: the dispatch path enters through it per
   *  invocation. */
  const start = ctx.getProp(ctx.global, "__start");

  /** One entrypoint invocation, assuming the queue has already given it the realm.
   *
   *  Not `async`: the queue needs the `Invocation` — and with it the release signal —
   *  the moment the synchronous segment ends, which is before the answer exists. */
  const invoke = (payload: Uint8Array, deadlineMs: number, causalClock?: CausalClock): Invocation => {
    // A deferred invocation keeps this record through every host-call settlement.
    // A later entry gets its own allowance and cannot replace the parked one's.
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
        // `__start` runs the entrypoint up to its first await and reports a synchronous
        // answer within the call; the pump then runs the continuations it queued.
        const flag = ctx.unwrapResult(ctx.callFunction(start, ctx.undefined, idHandle, argument));
        deferred = ctx.getNumber(flag) === 1;
        flag.dispose();
        pumpJobs();
      } catch (err) {
        // The realm failed the entry itself — the budget interrupt, or an engine fault — so
        // nothing inside it will report. An answer already reported stands.
        fail(err instanceof Error ? err : new Error(String(err)));
      } finally {
        // Closed here: past this point the host is waiting on the seam, which is not the
        // guest's time to spend.
        clock.end();
        idHandle?.dispose();
        argument?.dispose();
      }
    });
    return { result, deferred, cancel: fail };
  };

  return {
    call: serializeCalls(entryDeadlines, invoke, () =>
      (disposed || !ctx.alive) ? new Error(REALM_DISPOSED) : null,
    opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS, opts.ownTurns),
    dispose(): void {
      disposed = true;
      // Fail anyone still awaiting an answer before tearing the realm down: answers are
      // only ever reported from inside the realm, so disposing first would strand every
      // parked caller — a DEFERRED one included, whose answer would otherwise never come
      // (realm-queue.ts's time-bound invariant).
      failInvocations(new Error(REALM_DISPOSED));
      // And end custody of every call the host never answered: nothing inside this realm
      // will consume those answers now, so holding their charge would pin this realm's
      // allowance on one unanswering backend forever (`ActiveHostCall` above).
      // Their armed deadlines go with them (`disarmAll`).
      activeHostCalls.releaseAll();
      hostCallDeadlines.disarmAll();
      entryDeadlines.disarmAll();
      // Then the engine, context before runtime. `JS_FreeRuntime` asserts an empty GC object
      // list, so one live handle would abort the whole wasm module and every realm with it;
      // `start` is the only one held between calls, since answers cross as bytes.
      if (!ctx.alive) return;
      start.dispose();
      ctx.dispose();
      runtime.dispose();
    },
  };
};
