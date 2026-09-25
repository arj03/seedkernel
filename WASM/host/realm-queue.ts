// The realm contract and the per-realm host-side owners both realm factories build on
// (safe-js.ts, native-shim.ts): serialized entry into one confined realm, and the deadlines
// that bound it. Unanswered host calls are counted per target — after the copy out of the
// guest heap on JS (safe-js.ts), before it natively (native/hostcalls.go).

import { Fifo } from "../services/util.js";
import type { HostCall } from "./guest-seam.js";

/** What a disposed realm fails every in-flight and queued caller with, on every target.
 *  `TransportHost` reads it to tell its own teardown from a real failure. */
export const REALM_DISPOSED = "guest realm disposed";

/** The two clock refusals, one wording on every target. SPENT: no time left to make the
 *  call, thrown at the guest's call site. LATE: the handoff deadline overtook the call,
 *  arriving as an ordinary failure (`settleByDeadline`). */
export const HOST_CALL_SPENT = "guest: handoff deadline exhausted before host.call";
export const HOST_CALL_LATE = "guest: host.call handoff deadline exceeded";

/** One entrypoint invocation. Settling `result` releases the realm; a `deferred` one
 *  released it when its synchronous segment ended and answers later under the same
 *  deadline. */
export interface Invocation {
  result: Promise<Uint8Array>;
  deferred?: boolean;
  /** The handoff deadline won: drop settlement state and reject `result` with `reason`. */
  cancel(reason: Error): void;
}

/** The clock owner of one causally related tree of work. A timer fire mints one and it
 *  follows every continuation and cross-realm call. Only execution calls `charge`;
 *  waiting is free. */
export interface CausalClock {
  charge(ms: number): void;
}

/** Everything a target needs to construct one confined guest realm. */
export interface RealmOptions {
  /** Guest source. Must declare the one `handle(arg)` entrypoint. */
  source: string;
  /** The seam this realm calls out through — its whole view of the host. */
  hostCall: HostCall;
  /** Hard cap on this realm's heap. Omitted means the target's shared default. */
  memoryLimitBytes?: number;
  /** Guest execution and handoff budget per entrypoint, in ms. `Infinity` disables it;
   *  omitted means the target's shared default. */
  deadlineMs?: number;
  /** Run every turn on this realm's own ceiling; a caller's remainder still bounds its
   *  wait. For the link occupant, where one caller running out must not cut a record in
   *  half (§12.3). */
  ownTurns?: boolean;
}

/** One confined guest realm, independent of the target that implements it. */
export interface Realm {
  /** Invoke `handle` with `[caller 32][body …]`, serialized per realm. An omitted
   *  deadline is a host-initiated call on this realm's own ceiling. */
  call(payload: Uint8Array, deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array>;
  dispose(): void;
}

/** How a platform constructs its implementation of a confined realm. */
export type RealmFactory = (opts: RealmOptions) => Promise<Realm>;

/** The causal clock active while host code synchronously enters or resumes one realm.
 *  Nested entries restore their caller's clock, including when the inner one throws. */
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

/** Monotonic milliseconds: a wall-clock step would expire or extend every live deadline
 *  at once. The native host realm gets it beside `setTimeout` (native/loop.go). */
export const monotonicMs = (): number => performance.now();

/** A settled queue entry's payload, so letting go of borrowed bytes allocates nothing. */
const NO_PAYLOAD = new Uint8Array(0);

/** Convert a live remainder into the absolute deadline that crosses this handoff. */
const deadlineAt = (remainingMs: number): number => {
  if (remainingMs === Infinity) return Infinity;
  if (!Number.isFinite(remainingMs) || remainingMs < 0) {
    throw new Error("guest: handoff deadline must be a non-negative finite duration or Infinity");
  }
  return monotonicMs() + remainingMs;
};

/** One deadline a realm holds time against. `expire` must only reject a promise or post a
 *  microtask, never touch the queue's other records. */
export interface Deadline {
  at: number;
  expire(): void;
}

/** One tier's queue: what a realm arms against, and what disposal ends. */
export interface DeadlineQueue {
  add(deadline: Deadline): void;
  drop(deadline: Deadline): boolean;
  disarmAll(): void;
}

/** The deadlines a realm holds for unsettled work, sharing one physical timer (§12.3).
 *  Unsorted: the earliest is found when the timer fires, never on the call path. The timer
 *  is kept between fires rather than cycled per call (on native that is two host calls per
 *  dispatch); that is safe because it is never later than anything pending.
 *
 *  One queue per tier, never merged: a host call's deadline is always a hair earlier than
 *  its invocation's, and sharing a timer would make the outer one fire late by the timer's
 *  coarseness and lose the race to the guest budget it backstops. */
export function createDeadlineQueue(): DeadlineQueue {
  const pending = new Set<Deadline>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let timerAt = Infinity;
  const clear = (): void => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
    timerAt = Infinity;
  };
  /** Expire what is due, then re-arm for the earliest left, in pieces past `setTimeout`'s
   *  range. "Due" is within a millisecond, all `setTimeout` resolves: early is the safe side
   *  of a custody bound, a tick late hands the guest time it was never granted. */
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
      // Re-arm only for a whole tick's gain: re-arming costs the standing wake accuracy,
      // and a guest would pay that per host call.
      if (timer === undefined || deadline.at < timerAt - 1) arm();
      else (timer as ReturnType<typeof setTimeout> & { ref?(): void }).ref?.();
    },
    drop(deadline) {
      if (!pending.delete(deadline)) return false;
      // An idle retained wake must not hold a Node process up; `add` refs it back.
      if (pending.size === 0) {
        (timer as (ReturnType<typeof setTimeout> & { unref?(): void }) | undefined)?.unref?.();
      }
      return true;
    },
    /** Disposal ends the wake with the realm (§12.3). */
    disarmAll(): void {
      clear();
      pending.clear();
    },
  };
}

/** The two queues one realm arms, and the teardown every realm-ending path must run. */
export function createRealmDeadlines(): { hostCall: DeadlineQueue; entry: DeadlineQueue; disarmAll(): void } {
  const hostCall = createDeadlineQueue();
  const entry = createDeadlineQueue();
  return {
    hostCall,
    entry,
    disarmAll(): void { hostCall.disarmAll(); entry.disarmAll(); },
  };
}

/** Settle a host call's `answer` through `settle`, unless the deadline lands first, which
 *  settles it with `message`: exactly once either way. The deadline's membership in its
 *  queue is the claim — an answer that finds it dropped lost the race.
 *
 *  A callback rather than a racing promise because every promise costs on the native loop.
 *  Expiry settles on a microtask: `add` can expire synchronously, inside the guest frame
 *  that issued the call, and settling re-enters the realm. */
export function settleByDeadline(deadlines: { add(d: Deadline): void; drop(d: Deadline): boolean },
  remainingMs: number, answer: Promise<Uint8Array>, message: string,
  settle: (bytes: Uint8Array | null, error: unknown) => void): void {
  const at = deadlineAt(remainingMs);
  if (at === Infinity) {
    void answer.then((bytes) => settle(bytes, null), (err: unknown) => settle(null, err));
    return;
  }
  const deadline: Deadline = { at, expire: () => queueMicrotask(() => settle(null, new Error(message))) };
  deadlines.add(deadline);
  void answer.then(
    (bytes) => { if (deadlines.drop(deadline)) settle(bytes, null); },
    (err: unknown) => { if (deadlines.drop(deadline)) settle(null, err); },
  );
}

/** Serialize realm entry under one deadline that starts at admission, covering queue wait,
 *  execution and a deferred answer — or, with `ownTurns`, wait and answer while the turn
 *  runs on the realm's own ceiling. Payloads are borrowed from bounded upstream owners, so
 *  queue depth needs no cap of its own. */
export function serializeCalls(
  deadlines: { add(d: Deadline): void; drop(d: Deadline): void },
  invoke: (payload: Uint8Array, deadlineMs: number, causalClock?: CausalClock) => Invocation,
  notReady: () => Error | null,
  defaultDeadlineMs: number,
  ownTurns = false,
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
  // A FIFO and an explicit occupant, not a promise chain: each chain hop is a wake of the
  // native loop.
  const waiting = new Fifo<Entry>();
  let running: Entry | undefined;
  let pumping = false;
  const settled = Promise.resolve();

  /** Settle the caller once and drop the borrowed payload, which an expired entry would
   *  otherwise root until the queue front reaches it. */
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
  /** Hand the realm on. The deadline does this too, so a missing answer cannot hold it. */
  const release = (entry: Entry): void => {
    if (running !== entry) return;
    running = undefined;
    pump();
  };
  /** Shared by every entry, so admission allocates only the record. `this` is the entry. */
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
      // Read at the front, so a late timer cannot admit an expired entry.
      const now = monotonicMs();
      if (now >= entry.at) { entry.expire(); continue; }
      const err = notReady();
      if (err) { finish(entry, false, err); continue; }
      running = entry;
      try {
        entry.invocation = invoke(entry.payload,
          ownTurns ? defaultDeadlineMs : entry.at === Infinity ? Infinity : entry.at - now, entry.causalClock);
      } catch (thrown) { running = undefined; finish(entry, false, thrown); continue; }
      entry.invocation.result.then(
        (value) => { finish(entry, true, value); release(entry); },
        (thrown: unknown) => { finish(entry, false, thrown); release(entry); });
      if (entry.invocation.deferred) void settled.then(() => release(entry));
    }
  };

  return (payload, suppliedDeadlineMs, causalClock) => {
    const admissionError = notReady();
    if (admissionError) return Promise.reject(admissionError);

    let at: number;
    // A callee may tighten its ceiling, never mint time for the caller.
    try { at = deadlineAt(Math.min(suppliedDeadlineMs ?? defaultDeadlineMs, defaultDeadlineMs)); }
    catch (err) { return Promise.reject(err); }
    return new Promise<Uint8Array>((resolve, reject) => {
      const entry: Entry = { at, payload, causalClock, resolve, reject, settled: false, expire };
      if (at !== Infinity) deadlines.add(entry);
      // `add` may already have expired it; do not queue a tombstone.
      if (!entry.settled) {
        waiting.push(entry);
        pump();
      }
    });
  };
}
