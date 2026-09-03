// Per-realm deadline table (§12.3): what the guest's own `timer/arm` gets, bounded in
// count and bytes and paced against this realm's share of the node's clock.
import { concatBytes } from "../core/util.js";
import { DEFAULT_GUEST_DEADLINE_MS, DEFAULT_MAX_LIVE_TIMERS, DEFAULT_MAX_TIMER_PAYLOAD_BYTES, SELF_INITIATED_CLOCK_DIVISOR } from "../core/wasm-limits.js";
import { HOST_CALLER_ID, type HostTimers } from "./guest-seam.js";
import { monotonicMs, type CausalClock } from "./realm-queue.js";

/** Per-realm timer table. */
export interface RealmTimers extends HostTimers {
  /** Cancel every live deadline. Called only from `disposeSlot`, before the realm goes. */
  clearAll(): void;
}

/** A timer table over `fire`, which carries one body into its realm and answers when that
 *  invocation has settled.
 *
 *  The caps live here rather than in the seam because the seam never learns that a timer
 *  fired, so a count kept there would only ever grow. What is retained is the REALM-ENTRY
 *  buffer — the caller id already framed in — so there is one copy rather than two and the
 *  charge is the bytes that actually enter the realm.
 *
 *  Firing MOVES that custody, it does not end it: `realm.call` borrows the buffer and the
 *  entry queue counts depth alone (realm-queue.ts), so between the deadline and the answer
 *  this table is the body's only owner. Releasing at the deadline would leave the busiest
 *  moment — fired bodies queued behind a serialized realm — charged to nobody.
 *
 *  It owns this realm's share of the node's CLOCK because a fired deadline is the one FRESH
 *  invocation root a guest creates itself (§12.3); peerless cross-realm calls inherit the
 *  active root's deadline instead. Firing spends that share, and a deadline coming due with
 *  it spent is SLIPPED rather than failed. This paces self-created roots; it is not a bound
 *  on the node's clock, which external roots can occupy one invocation after another.
 *
 *  Each fire mints a causal clock carried through guest continuations, host-service and
 *  module calls, and cross-realm delivery. Those sites debit their measured burn, so time
 *  parked on I/O costs nothing and returning early cannot detach descendants from the root. */
export function createRealmTimers(
  fire: (payload: Uint8Array, causalClock: CausalClock) => Promise<unknown> | void,
  max = DEFAULT_MAX_LIVE_TIMERS,
  maxPayloadBytes = DEFAULT_MAX_TIMER_PAYLOAD_BYTES,
  budgetMs = DEFAULT_GUEST_DEADLINE_MS,
  clockDivisor = SELF_INITIATED_CLOCK_DIVISOR,
): RealmTimers {
  const live = new Map<number, { timer: ReturnType<typeof setTimeout>; bodyBytes: number }>();
  /** Bodies waiting for their deadline. */
  let armedBytes = 0;
  /** Bodies handed to `fire` whose invocation has not settled. Held apart from
     *  `armedBytes` because a fired body has left the table's id space — it can no longer
     *  be cleared or re-armed — while its bytes are still this realm's. */
  let firingBytes = 0;
  /** Banked execution, in ms. Capped at one invocation, so an idle app's deadline fires the
     *  moment it comes due; floored at minus the same, so one costly root cannot mortgage the
     *  table past `budgetMs * clockDivisor`. An unbudgeted realm banks `Infinity`. */
  let credit = budgetMs;
  let creditAt = monotonicMs();
  /** A realm that can run nothing has no clock to share, and pacing it would only spin a
     *  slip loop against invocations already late when the queue admits them. */
  const paced = budgetMs > 0;
  /** Earn at `1 / clockDivisor` in real time. Execution is debited separately by the
     *  causal clock passed into a fire, so a root parked on I/O earns while it waits. */
  const accrue = (): void => {
    const now = monotonicMs();
    const elapsed = now - creditAt;
    creditAt = now;
    if (!(elapsed > 0)) return;
    credit += elapsed / clockDivisor;
    credit = Math.max(-budgetMs, Math.min(budgetMs, credit));
  };
  const newCausalClock = (): CausalClock => ({
    charge(ms) {
      if (!(Number.isFinite(ms) && ms > 0)) return;
      accrue();
      credit = Math.max(-budgetMs, credit - ms);
    },
  });
  const clear = (id: number) => {
    const entry = live.get(id);
    if (entry !== undefined) {
      clearTimeout(entry.timer);
      live.delete(id);
      armedBytes -= entry.bodyBytes;
    }
  };
  return {
    arm(id, ms, payload) {
      // Counted before the re-arm, so replacing a live deadline is always allowed
      // and only a NEW id can be the one over the line.
      if (!live.has(id) && live.size >= max)
        throw new Error(`guest: too many live timers (cap ${max})`);
      const previousBytes = live.get(id)?.bodyBytes ?? 0;
      const nextBytes = armedBytes - previousBytes + HOST_CALLER_ID.length + payload.byteLength;
      if (nextBytes + firingBytes > maxPayloadBytes)
        throw new Error(`guest: live timer payloads exceed byte cap ${maxPayloadBytes}`);
      // Copied only after both checks pass, so the table retains exactly what it counted.
      const body = concatBytes([HOST_CALLER_ID, payload]);
      clear(id);
      /** The handle standing for this id. A slip replaces it, so the attempt behind the
             *  old one finds it changed and does nothing — as a re-arm of the id already does. */
      let handle: ReturnType<typeof setTimeout> | undefined;
      const attempt = (): void => {
        const entry = live.get(id);
        if (!entry || entry.timer !== handle) return;
        accrue();
        if (paced && credit <= 0) {
          // Slipped, never failed or dropped: a share held against the node's other
          // slots is not an error an honest app should have to handle. The wait is
          // what buys a positive share back, capped to `setTimeout`'s range.
          handle = setTimeout(attempt, Math.min(0x7fffffff, Math.ceil((1 - credit) * clockDivisor)));
          live.set(id, { timer: handle, bodyBytes: entry.bodyBytes });
          return;
        }
        // Dropped from the table BEFORE the realm is re-entered, so a guest re-arming
        // the same id from inside its own `timer` entrypoint arms the new deadline
        // rather than having it cleared out from under it on the way out.
        live.delete(id);
        armedBytes -= entry.bodyBytes;
        firingBytes += entry.bodyBytes;
        let released = false;
        const release = () => {
          if (released) return;
          released = true;
          firingBytes -= entry.bodyBytes;
        };
        let handed: Promise<unknown> | void;
        // A fire that throws, or that carried the body nowhere, ends its custody in
        // this turn rather than waiting for an answer nobody promised.
        try { handed = fire(body, newCausalClock()); } catch { handed = undefined; }
        if (handed) void handed.then(release, release);
        else release();
      };
      handle = setTimeout(attempt, ms);
      live.set(id, { timer: handle, bodyBytes: body.byteLength });
      armedBytes += body.byteLength;
    },
    clear,
    clearAll() {
      for (const { timer } of live.values()) clearTimeout(timer);
      live.clear();
      armedBytes = 0;
      // `firingBytes` drains on its own: disposal settles every invocation still in
      // flight (realm-queue.ts), and each fired body releases as its answer lands.
    },
  };
}
