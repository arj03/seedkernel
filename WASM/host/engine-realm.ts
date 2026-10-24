// Zero-authority QuickJS realms (§12.3) on any platform's engine table: one qjs.wasm
// instance per realm, driven through its R_* exports (native/qjs/csrc/realm.c) with numbers
// and bytes only. The shared preamble's `__start` reports each invocation's answer through
// the `realm.callDone`/`realm.callFail` imports; a `__host_call` arrives as
// `realm.hostCall`, answered in its frame when the handler already has the answer, and
// otherwise settled later through R_Settle. Invocations are serialized (realm-queue.ts).
//
// What runs on every call (the deadline, the job drain, the host-call ledger) is in
// realm.c, compiled, so this side stays small: on the native target it is interpreted.

import {
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
  DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  DEFAULT_REALM_MEMORY_BYTES,
} from "./wasm-limits.js";
import { dec, enc, errMessage } from "../services/util.js";
import { CallBudget, guestPreamble, type Spend } from "./guest-seam.js";
import {
  CausalContext, createRealmDeadlines, monotonicMs, serializeCalls, settleByDeadline,
  HOST_CALL_LATE, REALM_DISPOSED,
  type CausalClock, type Invocation, type RealmFactory,
} from "./realm-queue.js";

/** One instance from the platform's engine table. Numbers cross as JS numbers (the table
 *  carries i32 and f64, never i64), bytes through linear memory. A call that traps throws,
 *  and the instance is unusable after it. */
export interface EngineInstance {
  /** An export, resolved once and called with up to twelve numbers. */
  exported(name: string): EngineExport;
  /** Grow linear memory by `pages` of 64 KiB, answering its size before, or -1 when it
   *  cannot grow; 0 pages reads the size. */
  grow(pages: number): number;
  /** An exported global's value, or `null` when there is none by that name. */
  global(name: string): number | null;
  read(ptr: number, len: number): Uint8Array;
  /** Where the platform can lend one: a view of memory without a copy, valid until the
   *  instance next runs. */
  view?(ptr: number, len: number): Uint8Array;
  write(ptr: number, bytes: Uint8Array): void;
  dispose(): void;
}

export type EngineExport = (...args: number[]) => number;

/** Import handlers by module and name, as WebAssembly's importObject. A handler that throws
 *  traps the export that called it. */
export type EngineImports = Record<string, Record<string, (...args: number[]) => number | void>>;

/** The platform's engine table: instantiate wasm bytes with these imports. */
export type Engine = (wasm: Uint8Array, imports: EngineImports) => EngineInstance | Promise<EngineInstance>;

/** How a `realm.hostCall` answer is packed: `(len << 2) | kind` (realm.c). */
const PARKED = 0, ANSWERED = 1, REFUSED = 3;
/** An R_* entry whose deadline fired (realm.c). */
const INTERRUPTED = -1;

/** One invocation's execution record. Each host call keeps the record it was made under
 *  and resumes on it, since a deferred invocation outlives its entry (§12.3). */
interface InvocationBudget extends Spend {
  budgetMs: number;
  wallDeadline: number;
  /** Fails this invocation while its answer is pending. */
  reject?: (err: Error) => void;
}

/** A realm factory over `engine`, running each realm on `qjs` (qjs.wasm). */
export function engineRealms(engine: Engine, qjs: Uint8Array): RealmFactory {
  return async (opts) => {
    const configuredMs = opts.deadlineMs ?? DEFAULT_GUEST_DEADLINE_MS;
    const causalContext = new CausalContext();
    // The wall-clock deadlines (§12.3), one queue per tier.
    const deadlines = createRealmDeadlines();
    let alive = true;

    // Callers awaiting an invocation's answer (§12.3), by invocation id. Removed on
    // settlement, so a late report finds nothing.
    const invocations = new Map<number, { resolve(bytes: Uint8Array): void; reject(err: Error): void }>();
    let invocationSeq = 0;
    const takeInvocation = (id: number) => {
      const invocation = invocations.get(id);
      invocations.delete(id);
      return invocation;
    };

    // The invocation whose code holds the thread, or last did.
    let active: InvocationBudget;
    const create = (deadlineMs = configuredMs): InvocationBudget => {
      if (deadlineMs !== Infinity && (!Number.isFinite(deadlineMs) || deadlineMs < 0)) {
        throw new Error("guest: invalid invocation handoff deadline");
      }
      return {
        budgetMs: Math.min(configuredMs, deadlineMs),
        wallDeadline: deadlineMs === Infinity ? Infinity : monotonicMs() + deadlineMs,
        consumedMs: 0,
      };
    };

    // ── the instance ─────────────────────────────────────────────────────────
    let inst!: EngineInstance;
    let R_Buf!: EngineExport, R_Invoke!: EngineExport, R_Settle!: EngineExport;
    // The exchange buffer's address, and the most this side has grown it to. It moves only
    // when it grows, and realm.c passes the address with every import that grew it.
    let bufPtr = 0;
    let bufLen = -1;
    /** Stage bytes in the exchange buffer, answering their length. */
    const stage = (bytes: Uint8Array): number => {
      if (bytes.length > bufLen) {
        const ptr = R_Buf(bytes.length);
        if (ptr === 0) throw new Error("guest: realm out of memory");
        bufPtr = ptr;
        bufLen = bytes.length;
      }
      if (bytes.length > 0) inst.write(bufPtr, bytes);
      return bytes.length;
    };

    // One entry into the realm under `budget`'s clock. realm.c arms the engine's interrupt
    // for what is left, so an overrun fails the invocation, not the realm.
    const enter = (budget: InvocationBudget, causalClock: CausalClock | undefined,
      entry: (deadlineNs: number) => number): number => {
      active = budget;
      const start = monotonicMs();
      const left = Math.min(budget.budgetMs - budget.consumedMs, budget.wallDeadline - start);
      let r: number;
      try {
        r = entry(left === Infinity ? 0 : Math.max(1, Math.floor(left * 1e6)));
      } finally {
        const elapsed = monotonicMs() - start;
        budget.consumedMs += elapsed;
        causalClock?.charge(elapsed);
      }
      if (r >= 0) return r;
      if (r === INTERRUPTED) throw new Error(`guest realm: invocation deadline of ${budget.budgetMs}ms exceeded`);
      throw new Error(dec.decode(inst.read(bufPtr, -2 - r)));
    };

    // Settle a parked host.call and run its continuation, on the invocation that made the
    // call, or on a fresh one for a detached call.
    const settle = (callId: number, bytes: Uint8Array | null, error: unknown,
      budget: CallBudget, made: InvocationBudget): void => {
      if (!alive) return;
      const under = budget.detached ? create() : made;
      causalContext.run(budget.causalClock, () => {
        try {
          const len = stage(bytes ?? enc.encode(errMessage(error)));
          enter(under, budget.causalClock, (deadlineNs) => R_Settle(callId, bytes ? 1 : 0, len, deadlineNs));
        } catch (err) {
          // Interrupted while resuming: nothing in the realm will settle the caller now.
          under.reject?.(err instanceof Error ? err : new Error(String(err)));
        }
      });
    };

    const imports: EngineImports = {
      // The Go bridge's import (shim.c); a realm driven through R_* never reaches it.
      env: { callGo: () => { throw new Error("guest realm: env.callGo is not served"); } },
      realm: {
        // The single seam, after realm.c admitted the call. Never throws: a throw would trap
        // the engine mid-frame. A refusal goes back as REFUSED, which the guest sees thrown
        // at its call site.
        hostCall: (callId, remainingMs, buf, nameLen, payloadLen) => {
          try {
            if (buf !== bufPtr) {
              bufPtr = buf;
              bufLen = -1;
            }
            const nameBytes = nameLen < 0 ? -nameLen : nameLen;
            const lent = inst.view?.(buf, nameBytes + payloadLen);
            let bytes = lent ?? inst.read(buf, nameBytes + payloadLen);
            const name = nameLen >= 0
              ? String.fromCharCode.apply(null, bytes.subarray(0, nameLen) as unknown as number[])
              : dec.decode(bytes.subarray(0, nameBytes));
            // A fresh buffer per call is most of what a large argument costs on V8, so a
            // handler that is done with its payload when it returns borrows the realm's.
            if (lent && !opts.hostCall.borrows?.(name)) bytes = lent.slice();
            // The shared record, not a snapshot: concurrent calls charge the same spend.
            const made = active;
            // With no time left in the segment, this refuses.
            const budget = new CallBudget(remainingMs < 0 ? Infinity : remainingMs, causalContext.current, made);
            const result = opts.hostCall(name, bytes.subarray(nameBytes), budget);
            if (result instanceof Uint8Array) return (stage(result) << 2) | ANSWERED;
            settleByDeadline(deadlines.hostCall, budget.remainingMs, result, HOST_CALL_LATE,
              (answer, error) => settle(callId, answer, error, budget, made));
            return PARKED;
          } catch (err) {
            return (stage(enc.encode(errMessage(err))) << 2) | REFUSED;
          }
        },
        // The preamble's two reports. The id is taken first: a guest can call these
        // globals itself, and a made-up id must not buy a host copy.
        callDone: (id, ptr, len) => {
          const invocation = takeInvocation(id);
          invocation?.resolve(inst.read(ptr, len));
        },
        callFail: (id, ptr, len) => {
          takeInvocation(id)?.reject(new Error(dec.decode(inst.read(ptr, len))));
        },
      },
    };

    const discard = (reason = REALM_DISPOSED): void => {
      if (!alive) return;
      alive = false;
      for (const invocation of invocations.values()) invocation.reject(new Error(reason));
      invocations.clear();
      deadlines.disarmAll();
      inst.dispose();
    };
    inst = await engine(qjs, imports);
    // An export that throws trapped, and a trapped engine is unusable: the realm goes with it.
    const guarded = (name: string): EngineExport => {
      const fn = inst.exported(name);
      return (a, b, c, d) => {
        try {
          return fn(a, b, c, d);
        } catch (err) {
          discard(`guest realm failed: ${errMessage(err)}`);
          throw err;
        }
      };
    };
    try {
      R_Buf = guarded("R_Buf");
      R_Invoke = guarded("R_Invoke");
      R_Settle = guarded("R_Settle");
      const R_Eval = guarded("R_Eval");
      if (guarded("R_Init")(opts.memoryLimitBytes ?? DEFAULT_REALM_MEMORY_BYTES,
        DEFAULT_MAX_OUTSTANDING_HOST_CALLS, DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES) !== 0) {
        throw new Error("guest: the engine could not create a realm");
      }
      const preamble = stage(enc.encode(guestPreamble()));
      enter(create(Infinity), undefined, () => R_Eval(preamble, 1, 0));
      // Top level runs on a fresh budget too, or `for (;;) {}` would wedge the install.
      const len = stage(enc.encode(opts.source));
      enter(create(), undefined, (deadlineNs) => R_Eval(len, 0, deadlineNs));
    } catch (err) {
      discard();
      throw err;
    }

    /** One invocation, once the queue has given it the realm. Not `async`, because the
     *  queue needs the `Invocation` when the synchronous part ends, before the answer exists. */
    const invoke = (payload: Uint8Array, deadlineMs: number, causalClock?: CausalClock): Invocation => {
      // Kept through every host-call settlement; a later entry gets its own.
      const budget = create(deadlineMs);
      const id = ++invocationSeq;
      const answer = Promise.withResolvers<Uint8Array>();
      invocations.set(id, answer);
      const fail = (err: Error): void => { takeInvocation(id)?.reject(err); };
      budget.reject = fail;
      let deferred = false;
      causalContext.run(causalClock, () => {
        try {
          const len = stage(payload);
          // Runs `handle` to its first await and drains the continuations it queued.
          deferred = enter(budget, causalClock, (deadlineNs) => R_Invoke(id, len, deadlineNs)) === 1;
        } catch (err) {
          // Interrupt or engine fault: nothing inside will report. An answer already
          // reported stands.
          fail(err instanceof Error ? err : new Error(String(err)));
        }
      });
      return { result: answer.promise, deferred, cancel: fail };
    };

    return {
      call: serializeCalls(deadlines.entry, invoke, () => (alive ? null : new Error(REALM_DISPOSED)),
        configuredMs, opts.ownTurns),
      dispose: () => discard(),
    };
  };
}
