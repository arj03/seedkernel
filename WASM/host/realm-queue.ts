// Per-realm host-side owners shared by the JS and native realm factories: active
// guest-to-host calls and serialized entry into one confined realm.

import {
  DEFAULT_GUEST_DEADLINE_MS,
  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
  DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
} from "../core/wasm-limits.js";
import { Fifo } from "../core/util.js";
import type { HostCall } from "./guest-seam.js";

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

/** One entrypoint invocation. Settling `result` normally releases the realm for the next
 *  one; a DEFERRED entrypoint (`__deferred`) ended its execution segment before its answer
 *  exists, so it releases the realm at once and answers under the same deadline later. */
export interface Invocation {
  result: Promise<Uint8Array>;
  deferred?: boolean;
  /** The handoff deadline won: drop the host-side settlement state and reject `result`
   *  with `reason`, so nothing is left holding an answer the queue has stopped waiting for. */
  cancel(reason: Error): void;
}

/** The clock owner of one causally-related tree of work. A timer fire mints one and
 * realms carry it through every continuation and cross-realm call. Waiting costs
 * nothing; only a realm execution segment or module burn calls `charge`. */
export interface CausalClock {
  charge(ms: number): void;
}

/** Everything a target needs to construct one confined guest realm. */
export interface RealmOptions {
  /** Guest source. Runs in the sandbox; must declare the one `handle(arg)` entrypoint. */
  source: string;
  /** The seam this realm calls out through — its whole view of the host. */
  hostCall: HostCall;
  /** Hard cap on this realm's heap. Omitted means the target's shared default. */
  memoryLimitBytes?: number;
  /** Guest execution and handoff budget per entrypoint, in ms. `Infinity` disables it;
   * omitted means the target's shared default. */
  deadlineMs?: number;
}

/** One confined guest realm, independent of the target that implements it. */
export interface Realm {
  /** Invoke the guest's `handle` with `[caller 32][body …]`. Calls are serialized per realm.
   * An omitted deadline means a host-initiated call and uses this realm's configured ceiling. */
  call(payload: Uint8Array, deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array>;
  dispose(): void;
}

/** How a platform constructs its implementation of a confined realm. */
export type RealmFactory = (opts: RealmOptions) => Promise<Realm>;

/** The causal clock active while host code synchronously enters or resumes one realm.
 * Nested entries restore their caller's clock, including when the inner operation throws. */
export class CausalContext {
  private active: CausalClock | undefined;

  get current(): CausalClock | undefined { return this.active; }

  run<T>(clock: CausalClock | undefined, fn: () => T): T {
    const previous = this.active;
    this.active = clock;
    try { return fn(); }
    finally { this.active = previous; }
  }
}

/** Monotonic milliseconds. A deadline here is the distance between two readings, so a wall
 *  clock is the wrong source: a step backwards expires every live one at once and a step
 *  forwards extends them all. Node, Bun and the browsers answer natively; the native host
 *  realm is given it beside `setTimeout` (native/loop.go). */
export const monotonicMs = (): number => performance.now();

/** What a settled queue entry's payload field is replaced by — one shared empty view, so
 *  letting go of borrowed bytes allocates nothing and the field stays non-optional. */
const NO_PAYLOAD = new Uint8Array(0);

/** Convert a live remainder into the absolute deadline that crosses this handoff. */
const deadlineAt = (remainingMs: number): number => {
  if (remainingMs === Infinity) return Infinity;
  if (!Number.isFinite(remainingMs) || remainingMs < 0) {
    throw new Error("guest: handoff deadline must be a non-negative finite duration or Infinity");
  }
  return monotonicMs() + remainingMs;
};

/** One deadline a realm is holding time against. `expire` settles the thing it guards; it
 *  may not touch this queue's other records, which every caller here honours by rejecting
 *  a promise or posting a microtask rather than reaching back in. */
export interface Deadline {
  at: number;
  expire(): void;
}

/** The deadlines a realm has armed for work it has not settled, sharing one physical timer
 *  — the wall-clock half of the custody the active-call registry keeps in bytes (§12.3).
 *  Unsorted: the scan for the earliest runs when the timer fires, never on the call path.
 *  The wake is retained between fires rather than cycled per call — on native, two host
 *  calls through the trampoline for a deadline a fast dispatch never reaches — which is
 *  safe because `timerAt` is only ever EARLIER than anything pending: an unneeded wake
 *  re-arms, and none can fire late.
 *
 *  ONE PER TIER — invocations, and the host calls made under them — never folded together.
 *  Those deadlines are NESTED, not peers: a host call is admitted with what is left of its
 *  invocation, so it is always a hair earlier and would jostle the wake the outer deadline
 *  waits on. That one then fires late by the host timer clock's coarseness and loses the
 *  race against the guest budget derived from it, which is what it exists to backstop. */
export function createDeadlineQueue(): {
  add(deadline: Deadline): void;
  drop(deadline: Deadline): void;
  disarmAll(): void;
} {
  const pending = new Set<Deadline>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let timerAt = Infinity;
  const clear = (): void => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
    timerAt = Infinity;
  };
  /** Expire what is due, then re-arm for the earliest that is left — in pieces, since a
   *  ceiling past `setTimeout`'s range fires at once if handed over whole. "Due" is
   *  anything inside a millisecond, which is all `setTimeout` resolves: a host whose timer
   *  clock is not this one's wakes a hair early often enough, and re-arming for that
   *  remainder buys a whole further tick. Early is the conservative side of a custody bound;
   *  a tick late hands the guest time it was never granted. */
  const arm = (): void => {
    clear();
    const now = monotonicMs();
    let soonest = Infinity;
    for (const deadline of pending) {
      if (deadline.at - now >= 1) soonest = Math.min(soonest, deadline.at);
      else { pending.delete(deadline); deadline.expire(); }
    }
    if (soonest === Infinity) return;
    timerAt = Math.min(soonest, now + 0x7fffffff);
    timer = setTimeout(arm, timerAt - now);
  };
  return {
    add(deadline) {
      pending.add(deadline);
      // Only for a wake a whole tick better: re-arming restarts the host's coarser timer,
      // so a sub-millisecond gain costs the standing wake's accuracy — and a guest calling
      // out under its invocation's deadline would pay that once per host call.
      if (timer === undefined || deadline.at < timerAt - 1) arm();
      else (timer as ReturnType<typeof setTimeout> & { ref?(): void }).ref?.();
    },
    drop(deadline) {
      if (!pending.delete(deadline)) return;
      // Nothing is waiting on the retained wake now, so it must not hold a process up on
      // its own account; `add` refs it back. No-op off Node, whose loop is explicit.
      if (pending.size === 0) {
        (timer as (ReturnType<typeof setTimeout> & { unref?(): void }) | undefined)?.unref?.();
      }
    },
    /** Disposal ends the wake with the realm (§12.3): nothing is left to consume those
     *  answers, and a retained one would hold the host's loop for its whole remainder. */
    disarmAll(): void {
      clear();
      pending.clear();
    },
  };
}

/** `answer`, or this deadline's REJECTION — whichever lands first. That shape is the whole
 *  "exactly one settlement" rule here: no owner needs a claim flag, and expiry arrives at
 *  every call site as ordinary failure rather than a second settlement path. */
export function raceDeadline<T>(deadlines: { add(d: Deadline): void; drop(d: Deadline): void },
  remainingMs: number, answer: Promise<T>, message: string): Promise<T> {
  const at = deadlineAt(remainingMs);
  if (at === Infinity) return answer;
  return new Promise<T>((resolve, reject) => {
    const deadline: Deadline = { at, expire: () => reject(new Error(message)) };
    deadlines.add(deadline);
    answer.then(
      (value) => { deadlines.drop(deadline); resolve(value); },
      (err: unknown) => { deadlines.drop(deadline); reject(err); },
    );
  });
}

/** Serialize realm entry under one deadline that starts at admission.
 *
 * Payload bytes are borrowed from a longer-lived upstream owner. Queue depth is likewise
 * derived from those bounded callers rather than capped by an unrelated number here. The
 * absolute deadline covers queue wait, guest execution, and a deferred answer. */
export function serializeCalls(
  deadlines: { add(d: Deadline): void; drop(d: Deadline): void },
  invoke: (payload: Uint8Array, deadlineMs: number, causalClock?: CausalClock) => Invocation,
  notReady: () => Error | null,
  defaultDeadlineMs = DEFAULT_GUEST_DEADLINE_MS,
): (payload: Uint8Array, deadlineMs?: number, causalClock?: CausalClock) => Promise<Uint8Array> {
  const LATE = "guest: realm invocation handoff deadline exceeded";
  interface Entry extends Deadline {
    payload: Uint8Array;
    causalClock?: CausalClock;
    resolve(value: Uint8Array): void;
    reject(reason: unknown): void;
    invocation?: Invocation;
    settled: boolean;
  }
  // A FIFO and an explicit occupant, not a promise chain: a chain waits by RESOLVING one
  // promise with another, and each of those hops is a wake of the native target's loop.
  const waiting = new Fifo<Entry>();
  let running: Entry | undefined;
  let pumping = false;
  const settled = Promise.resolve();

  /** Settle the caller once, from whichever arm reaches it first, and let go of the payload
   *  in the same breath: those bytes are BORROWED (§12.3), and an entry the deadline
   *  overtook stays in the FIFO until the front reaches it — so a predecessor that never
   *  answers would otherwise root every follower's payload behind it. */
  const finish = (entry: Entry, ok: boolean, value: unknown): void => {
    if (entry.settled) return;
    entry.settled = true;
    entry.payload = NO_PAYLOAD;
    deadlines.drop(entry);
    if (ok) entry.resolve(value as Uint8Array);
    else entry.reject(value);
  };
  /** Give the realm to whoever is next, on a fresh turn. */
  const pump = (): void => {
    if (pumping || running !== undefined || waiting.size === 0) return;
    pumping = true;
    void settled.then(enterNext);
  };
  /** Hand the realm on. The DEADLINE does this too, so an answer that never comes cannot
   *  hold the realm past the budget its invocation was admitted under. */
  const release = (entry: Entry): void => {
    if (running !== entry) return;
    running = undefined;
    pump();
  };
  /** Shared by every entry rather than closed over one, so admission allocates the record
   *  and nothing else. `this` is the entry the queue is expiring. */
  function expire(this: Entry): void {
    const err = new Error(LATE);
    finish(this, false, err);
    this.invocation?.cancel(err);
    release(this);
  }
  const enterNext = (): void => {
    pumping = false;
    while (running === undefined && waiting.size > 0) {
      const entry = waiting.shift() as Entry;
      if (entry.settled) continue;              // its deadline overtook it while it queued
      // Read at the FRONT rather than trusting a flag, so a late timer cannot admit an
      // expired entry — and spent as this invocation's remainder, so it is read only once.
      const now = monotonicMs();
      if (now >= entry.at) { entry.expire(); continue; }
      const err = notReady();
      if (err) { finish(entry, false, err); continue; }
      running = entry;
      try {
        entry.invocation = invoke(entry.payload,
          entry.at === Infinity ? Infinity : entry.at - now, entry.causalClock);
      } catch (thrown) { running = undefined; finish(entry, false, thrown); continue; }
      entry.invocation.result.then(
        (value) => { finish(entry, true, value); release(entry); },
        (thrown: unknown) => { finish(entry, false, thrown); release(entry); });
      // A deferred entrypoint ended its execution segment before its answer exists, so the
      // realm is free now and the answer lands later under this same deadline.
      if (entry.invocation.deferred) void settled.then(() => release(entry));
    }
  };

  return (payload, suppliedDeadlineMs, causalClock) => {
    const admissionError = notReady();
    if (admissionError) return Promise.reject(admissionError);

    let at: number;
    // A callee may tighten its configured ceiling, never mint time for the caller.
    try { at = deadlineAt(Math.min(suppliedDeadlineMs ?? defaultDeadlineMs, defaultDeadlineMs)); }
    catch (err) { return Promise.reject(err); }
    return new Promise<Uint8Array>((resolve, reject) => {
      const entry: Entry = { at, payload, causalClock, resolve, reject, settled: false, expire };
      if (at !== Infinity) deadlines.add(entry);
      // `add` expires a deadline already inside the host timer's one-tick resolution
      // synchronously. Do not turn that already-settled call into a FIFO tombstone.
      if (!entry.settled) {
        waiting.push(entry);
        pump();
      }
    });
  };
}
