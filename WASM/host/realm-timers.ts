// One replaceable wake per realm (§12.3). Deadline tables belong in the guest heap.
import { OpArgs } from "../services/op-frame.js";
import { DEFAULT_GUEST_DEADLINE_MS, SELF_INITIATED_CLOCK_DIVISOR } from "./wasm-limits.js";
import { HOST_CALLER_ID, type HostTimers } from "./guest-seam.js";
import { monotonicMs, type CausalClock } from "./realm-queue.js";

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
      const entry = { timer: undefined as ReturnType<typeof setTimeout> | undefined, attempt: () => {
        if (live !== entry) return;
        entry.timer = undefined;
        if (firing) return;
        accrue();
        if (paced && credit <= 0) {
          entry.timer = setTimeout(entry.attempt, Math.min(0x7fffffff, Math.ceil((1 - credit) * clockDivisor)));
          return;
        }
        live = undefined;
        firing = true;
        let handed: Promise<unknown> | void;
        try { handed = fire(wakeBody(), newCausalClock()); } catch { handed = undefined; }
        if (handed) void handed.then(release, release);
        else release();
      } };
      live = entry;
      entry.timer = setTimeout(entry.attempt, ms);
    },
    clear,
    clearAll() { disposed = true; clear(); },
  };
}
