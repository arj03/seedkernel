// `timer` (§12.3): one replaceable wake per realm, delivered as the `wake` host event.
// Every node offers it. Deadline tables belong in the guest heap.
import { OpArgs } from "../host/op-frame.js";
import { DEFAULT_GUEST_DEADLINE_MS, SELF_INITIATED_CLOCK_DIVISOR } from "../host/wasm-limits.js";
import { EMPTY, HOST_CALLER_ID, readU32BE } from "../host/util.js";
import type { ServiceHandlers } from "../host/guest-seam.js";
import { monotonicMs, type CausalClock } from "../host/realm-queue.js";

/** One replaceable wake. */
export interface HostTimers {
  arm(ms: number): void;
  /** Cancel the armed wake; a wake already in flight cannot be retracted. */
  clear(): void;
}

export interface RealmTimers extends HostTimers {
  /** Permanently dispose the wake when its slot goes away. */
  clearAll(): void;
}

/** Every wake is the `wake` event from the host's caller id, with no args. Built fresh
 *  per fire, since the realm owns what it is handed. */
const wakeBody = (): Uint8Array => new OpArgs("wake").build(HOST_CALLER_ID);

/** At most one armed wake and one in flight. A due wake waits for the previous
 *  invocation to settle, which bounds what the host holds even when the guest defers its
 *  answer and keeps re-arming. Clearing or re-arming cannot retract a wake already handed
 *  to the realm, so the guest checks its own clock for a wake with nothing due. */
export function createRealmTimers(
  fire: (payload: Uint8Array, causalClock: CausalClock) => Promise<unknown> | void,
  budgetMs = DEFAULT_GUEST_DEADLINE_MS,
  clockDivisor = SELF_INITIATED_CLOCK_DIVISOR,
): RealmTimers {
  let live: { timer: ReturnType<typeof setTimeout> | undefined; attempt: () => void } | undefined;
  let firing = false;
  let disposed = false;
  let credit = budgetMs;
  let creditAt = monotonicMs();
  const paced = budgetMs > 0;
  const accrue = (): void => {
    const now = monotonicMs();
    const elapsed = now - creditAt;
    creditAt = now;
    if (!(elapsed > 0)) return;
    credit = Math.max(-budgetMs, Math.min(budgetMs, credit + elapsed / clockDivisor));
  };
  const newCausalClock = (): CausalClock => ({
    charge(ms) {
      if (!(Number.isFinite(ms) && ms > 0)) return;
      accrue();
      credit = Math.max(-budgetMs, credit - ms);
    },
  });
  const clear = () => {
    if (live?.timer !== undefined) clearTimeout(live.timer);
    live = undefined;
  };
  const release = () => {
    firing = false;
    if (live && live.timer === undefined) live.attempt();
  };
  return {
    arm(ms) {
      if (disposed) throw new Error("guest: wake disposed");
      if (!Number.isInteger(ms) || ms < 0 || ms > 0x7fffffff)
        throw new Error("guest: wake requires a delay in 0..2147483647");
      clear();
      /** Fire the wake, unless a newer arm replaced it, one is in flight, or the pace
       *  holds it back. */
      const attempt = (): void => {
        if (live !== entry) return;
        entry.timer = undefined;
        if (firing) return;
        accrue();
        if (paced && credit <= 0) {
          entry.timer = setTimeout(attempt, Math.min(0x7fffffff, Math.ceil((1 - credit) * clockDivisor)));
          return;
        }
        live = undefined;
        firing = true;
        let handed: Promise<unknown> | void;
        try { handed = fire(wakeBody(), newCausalClock()); } catch { handed = undefined; }
        if (handed) void handed.then(release, release);
        else release();
      };
      const entry: NonNullable<typeof live> = { timer: setTimeout(attempt, ms), attempt };
      live = entry;
    },
    clear,
    clearAll() { disposed = true; clear(); },
  };
}

export function timerService(timers: HostTimers): ServiceHandlers<"timer"> {
  return {
    "timer/arm": (payload) => {
      if (payload.byteLength !== 4) throw new Error("guest: timer/arm requires [ms u32]");
      timers.arm(readU32BE(payload, 0));
      return EMPTY;
    },
    "timer/clear": (payload) => {
      if (payload.byteLength !== 0) throw new Error("guest: timer/clear requires an empty body");
      timers.clear();
      return EMPTY;
    },
  };
}
