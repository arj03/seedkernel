// The realm contract and the per-realm pieces both realm factories (safe-js.ts,
// native-shim.ts) build on: serialized entry into one confined realm, and the deadlines
// that bound it. Unanswered host calls are counted per target: after the copy out of the
// guest heap on JS (safe-js.ts), before it on native (native/hostcalls.go).

import { Fifo } from "../services/util.js";
import type { HostCall } from "./guest-seam.js";

/** What a disposed realm fails every in-flight and queued caller with, on every target.
 *  `TransportHost` reads it to tell its own teardown from a real failure. */
export const REALM_DISPOSED = "guest realm disposed";

/** The two deadline errors, worded the same on every target. SPENT: no time left to make
 *  the call, thrown at the guest's call site. LATE: the deadline passed before the call
 *  answered, delivered as an ordinary failure (`settleByDeadline`). */
export const HOST_CALL_SPENT = "guest: handoff deadline exhausted before host.call";
export const HOST_CALL_LATE = "guest: host.call handoff deadline exceeded";

/** One entrypoint invocation. Settling `result` releases the realm. A `deferred` one
 *  released the realm when its synchronous part ended and answers later under the same
 *  deadline. */
export interface Invocation {
  result: Promise<Uint8Array>;
  deferred?: boolean;
  /** The deadline passed: drop settlement state and reject `result` with `reason`. */
  cancel(reason: Error): void;
}

/** The clock for one causally related tree of work. A wake creates one, and it follows
 *  every continuation and cross-realm call. Only execution calls `charge`; waiting is
 *  free. */
export interface CausalClock {
  charge(ms: number): void;
}

/** Everything a target needs to construct one confined guest realm. */
export interface RealmOptions {
  /** Guest source. Must declare the one `handle(arg)` entrypoint. */
  source: string;
  /** The seam this realm calls out through: its whole view of the host. */
  hostCall: HostCall;
  /** Hard cap on this realm's heap. Omitted means the target's shared default. */
  memoryLimitBytes?: number;
  /** Guest execution and handoff budget per entrypoint, in ms. `Infinity` disables it;
   *  omitted means the target's shared default. */
  deadlineMs?: number;
  /** Run every turn on this realm's own ceiling; a caller's remainder still bounds its
   *  wait. For the link occupant, where one caller running out of time must not cut a
   *  record in half (§12.3). */
  ownTurns?: boolean;
}

/** One confined guest realm, independent of the target that implements it. */
export interface Realm {
  /** Invoke `handle` with `[caller 32][body ...]`, serialized per realm. An omitted
   *  deadline means a host-initiated call on this realm's own ceiling. */
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

/** Monotonic milliseconds, since a wall-clock step would expire or extend every live
 *  deadline at once. The native host realm gets it from native/loop.go. */
export const monotonicMs = (): number => performance.now();

/** A settled queue entry's payload, so dropping borrowed bytes allocates nothing. */
const NO_PAYLOAD = new Uint8Array(0);

/** Convert a remaining duration into an absolute deadline. */
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

/** One tier's deadline queue. */
export interface DeadlineQueue {
  add(deadline: Deadline): void;
  drop(deadline: Deadline): boolean;
  disarmAll(): void;
}

/** The deadlines a realm holds for unsettled work, sharing one timer (§12.3). Unsorted:
 *  the earliest is found when the timer fires, not on the call path. The timer is kept
 *  between fires instead of being reset per call (on native that would cost two host calls
 *  per dispatch); that is safe because it never fires later than anything pending.
 *
 *  One queue per tier, never merged: a host call's deadline is always slightly earlier
 *  than its invocation's, and a shared timer would make the outer one fire late by the
 *  timer's granularity and lose the race to the guest budget it backs up. */
export function createDeadlineQueue(): DeadlineQueue {
  const pending = new Set<Deadline>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let timerAt = Infinity;
  const clear = (): void => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
    timerAt = Infinity;
  };
  /** Expire what is due, then re-arm for the earliest remaining (in steps, beyond
   *  `setTimeout`'s range). "Due" means within a millisecond, `setTimeout`'s resolution:
   *  firing early is safe, while a tick late gives the guest time it was never granted. */
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
      // Re-arm only when it moves the timer by a whole tick, since re-arming has a cost
      // the guest would pay on every host call.
      if (timer === undefined || deadline.at < timerAt - 1) arm();
      else (timer as ReturnType<typeof setTimeout> & { ref?(): void }).ref?.();
    },
    drop(deadline) {
      if (!pending.delete(deadline)) return false;
      // An idle timer must not keep a Node process alive; `add` refs it again.
      if (pending.size === 0) {
        (timer as (ReturnType<typeof setTimeout> & { unref?(): void }) | undefined)?.unref?.();
      }
      return true;
    },
    /** Disposal clears the timer with the realm (§12.3). */
    disarmAll(): void {
      clear();
      pending.clear();
    },
  };
}

/** The two queues one realm uses, and the teardown every realm-ending path must run. */
export function createRealmDeadlines(): { hostCall: DeadlineQueue; entry: DeadlineQueue; disarmAll(): void } {
  const hostCall = createDeadlineQueue();
  const entry = createDeadlineQueue();
  return {
    hostCall,
    entry,
    disarmAll(): void { hostCall.disarmAll(); entry.disarmAll(); },
  };
}

/** Settle a host call's `answer` through `settle`, unless the deadline passes first, in
 *  which case it settles with `message`. Exactly once either way: whoever removes the
 *  deadline from its queue wins.
 *
 *  A callback instead of a racing promise, because every promise costs on the native loop.
 *  Expiry settles on a microtask because `add` can expire synchronously, inside the guest
 *  frame that issued the call, and settling re-enters the realm. */
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

/** Serialize realm entry under one deadline that starts at admission and covers queue
 *  wait, execution and a deferred answer. With `ownTurns`, the deadline covers wait and
 *  answer while the turn itself runs on the realm's own ceiling. Payloads are borrowed
 *  from bounded upstream owners, so the queue needs no depth cap of its own. */
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
  // A FIFO and an explicit occupant instead of a promise chain, since each chain hop costs
  // a native loop turn.
  const waiting = new Fifo<Entry>();
  let running: Entry | undefined;
  let pumping = false;
  const settled = Promise.resolve();

  /** Settle the caller once and drop the borrowed payload, which an expired entry would
   *  otherwise hold until it reaches the front of the queue. */
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
  /** Pass the realm to the next entry. The deadline does this too, so a missing answer
   *  cannot hold it. */
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
      if (entry.settled) continue;              // expired while queued
      // Check the clock here too, so a late timer cannot admit an expired entry.
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
      // `add` may already have expired it; if so, do not queue it.
      if (!entry.settled) {
        waiting.push(entry);
        pump();
      }
    });
  };
}
