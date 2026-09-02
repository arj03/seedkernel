// Per-realm host-side owners shared by the JS and native realm factories: active
// guest-to-host calls and serialized entry into one confined realm.

import {
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
  DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
} from "../core/wasm-limits.js";

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

/** Own every guest-to-host copy and promise slot from admission through settlement. */
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

/** One entrypoint invocation, split into its answer and queue-release moments. */
export interface Invocation {
  result: Promise<Uint8Array>;
  released: Promise<unknown>;
  /** Drop host-side settlement state if the handoff deadline wins. */
  cancel?(reason: Error): void;
}

/** Monotonic milliseconds. A deadline here is the distance between two readings, so a wall
 *  clock is the wrong source: a step backwards expires every live one at once and a step
 *  forwards extends them all. Node, Bun and the browsers answer natively; the native host
 *  realm is given it beside `setTimeout` (native/loop.go). */
export const monotonicMs = (): number => performance.now();

/** Convert a live remainder into the absolute deadline that crosses this handoff. */
const deadlineAt = (remainingMs: number): number => {
  if (remainingMs === Infinity) return Infinity;
  if (!Number.isFinite(remainingMs) || remainingMs < 0) {
    throw new Error("guest: handoff deadline must be a non-negative finite duration or Infinity");
  }
  return monotonicMs() + remainingMs;
};

/** An absolute deadline as the REJECTION its owner races the real answer against. That shape
 *  is the whole of the "exactly one settlement" rule here — `Promise.race` already grants it,
 *  so no owner needs a claim flag of its own, and expiry arrives at every call site as
 *  ordinary failure rather than a second settlement path. `disarm` ends it, since a timer
 *  nobody awaits still holds the host's event loop open. Re-armed in pieces for a ceiling
 *  past `setTimeout`'s range, which fires at once if handed over whole; the Error costs
 *  nothing unless it lands. */
const expiryAt = (at: number, message: string): { rejects: Promise<never>; disarm(): void } => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let reject!: (err: Error) => void;
  const rejects = new Promise<never>((_, rj) => { reject = rj; });
  const arm = (): void => {
    const left = at - monotonicMs();
    if (left <= 0) return reject(new Error(message));
    timer = setTimeout(arm, Math.min(left, 0x7fffffff));
  };
  if (at !== Infinity) arm();
  return { rejects, disarm: () => clearTimeout(timer) };
};

/** Every handoff deadline a realm has armed for a call it has not settled — the wall-clock
 *  half of the custody the active-call registry keeps in bytes, ended by the same three
 *  events. `disarmAll` is not tidiness: nothing inside a disposed realm will consume those
 *  answers, and each abandoned timer holds the host's event loop for the rest of its
 *  remainder, so a one-shot process would linger a full budget past its work. */
export function createHandoffDeadlines(): {
  /** `answer`, or the deadline's rejection — whichever lands first. */
  race<T>(remainingMs: number, answer: Promise<T>, message: string): Promise<T>;
  disarmAll(): void;
} {
  const armed = new Set<() => void>();
  return {
    race(remainingMs, answer, message) {
      const at = deadlineAt(remainingMs);
      if (at === Infinity) return answer;
      const { rejects, disarm } = expiryAt(at, message);
      const drop = (): void => { armed.delete(drop); disarm(); };
      armed.add(drop);
      return Promise.race([answer, rejects]).finally(drop);
    },
    disarmAll(): void {
      for (const drop of [...armed]) drop();
    },
  };
}

/** Serialize realm entry under one deadline that starts at admission.
 *
 * Payload bytes are borrowed from a longer-lived upstream owner. Queue depth is likewise
 * derived from those bounded callers rather than capped by an unrelated number here. The
 * absolute deadline covers queue wait, guest execution, and a deferred answer. */
export function serializeCalls(
  invoke: (payload: Uint8Array, deadlineMs: number) => Invocation,
  notReady: () => Error | null,
  defaultDeadlineMs = DEFAULT_GUEST_DEADLINE_MS,
): (payload: Uint8Array, deadlineMs?: number) => Promise<Uint8Array> {
  const LATE = "guest: realm invocation handoff deadline exceeded";
  let tail: Promise<unknown> = Promise.resolve();
  return (payload, suppliedDeadlineMs) => {
    const admissionError = notReady();
    if (admissionError) return Promise.reject(admissionError);

    let at: number;
    // A callee may tighten its configured ceiling, never mint time for the caller.
    try { at = deadlineAt(Math.min(suppliedDeadlineMs ?? defaultDeadlineMs, defaultDeadlineMs)); }
    catch (err) { return Promise.reject(err); }
    const { rejects, disarm } = expiryAt(at, LATE);
    let invocation: Invocation | undefined;
    // Drop the host-side settlement state of an invocation the deadline overtook mid-flight.
    void rejects.catch((err: Error) => invocation?.cancel?.(err));

    // Stay behind the predecessor even when the caller times out while queued: a
    // caller-facing race used as `tail` would break serialization. The clock is re-read at
    // the front rather than trusting a flag, so a late timer cannot admit an expired entry.
    const started = tail.then(() => {
      if (monotonicMs() >= at) throw new Error(LATE);
      const err = notReady();
      if (err) throw err;
      invocation = invoke(payload, at === Infinity ? Infinity : Math.max(0, at - monotonicMs()));
      return invocation;
    });
    tail = Promise.race([started.then((inv) => inv.released), rejects]).catch(() => {});
    return Promise.race([started.then((inv) => inv.result), rejects]).finally(disarm);
  };
}
