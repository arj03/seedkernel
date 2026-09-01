// The per-realm boundary owners shared by both realm factories (safe-js.ts on the JS
// platform, native-shim.ts over Go's quickjs-ng): active guest-to-host calls, and the
// serialized entry of payloads into the guest.
//
// Every owner here is scoped to ONE realm and none is shared between realms. The node's
// total is what these admit times `DEFAULT_MAX_APP_SLOTS` (core/wasm-limits.ts), which is
// the same bound a pool held in common would give — without the pool's standing channel
// for a busy app to refuse a quiet one's calls.

import {
  DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
  DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  DEFAULT_MAX_QUEUED_REALM_INVOCATIONS,
} from "../core/wasm-limits.js";

function checkedBytes(bytes: number): number {
  if (!Number.isSafeInteger(bytes) || bytes < 0) {
    throw new Error("guest: payload width is not a non-negative safe integer");
  }
  return bytes;
}

/** One active call's custody, held from admission through settlement. Further host copies
 * are reserved before they are made, and everything reserved stays owned until the response
 * has been delivered or the call has terminally failed.
 *
 * Bounded in TIME as well as size (§12.3): the host's answer releases it, and disposal
 * releases whatever never answered — the guest that would have consumed it is gone, so what
 * a still-pending backend holds is the host's own memory, not this realm's. Without that
 * second path one unanswering backend pins the realm's allowance for good. */
export interface ActiveHostCall {
  reserve(bytes: number): void;
  release(): void;
}

/** Own every guest-to-host copy and promise slot from admission through settlement (§12.3).
 * Id, count slot and actual source width are admitted atomically. The id is the guest's own,
 * so it is checked here rather than trusted: guest.go must key its parked calls by it to
 * route settlements, and a target that admitted a duplicate where the other refuses one
 * would be the two engines disagreeing about the guest's ABI. No operation name reaches here
 * either: policy elsewhere is legitimately name-keyed (`MemoryFs`'s quota, `isIrreversible`),
 * but a name may only TIGHTEN what an owner admits, and this owner has no exemption to
 * give — the resource's owner decides, never the dispatcher that routed the call. */
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

/** One entrypoint invocation, in the two moments that are not always the same. */
export interface Invocation {
  /** The entrypoint's answer, which is what the caller of `call` receives. A deferred
   *  entrypoint (`__deferred`) hands it to an arbitrary later turn under no wall-clock
   *  bound, so only dispose can guarantee it settles — hence `InvocationSettler`. */
  result: Promise<Uint8Array>;
  /** Settles when this realm is free for the next invocation. */
  released: Promise<unknown>;
}

/** Rejectors for invocations whose `result` has not settled, owned by the realm engine
 *  (safe-js.ts, native-shim.ts) and never by this queue: only the realm knows how its own
 *  `result` is produced, so only it can force one terminal. `failAll` on dispose is what
 *  makes `ActiveHostCall`'s time bound hold against a guest that defers and never answers. */
export interface InvocationSettler {
  /** Register one in-flight rejector; call the returned function once that invocation
   *  settles on its own, or spent rejectors accumulate for the realm's lifetime. */
  track(reject: (err: Error) => void): () => void;
  /** Reject every still-tracked invocation. Rejecting an already-settled promise is a
   *  no-op, so racing a natural settlement never double-reports. */
  failAll(err: Error): void;
}

export function createInvocationSettler(): InvocationSettler {
  const live = new Set<(err: Error) => void>();
  return {
    // Each invocation registers a rejector of its own, so untracking is idempotent by
    // being a set deletion — nothing here needs a spent flag to guard it.
    track(reject) {
      live.add(reject);
      return () => live.delete(reject);
    },

    failAll(err) {
      for (const reject of [...live]) {
        live.delete(reject);
        reject(err);
      }
    },
  };
}

/** Serialize realm entry, bounding the DEPTH of what waits on the Promise chain.
 *
 * Depth only, and the payload is BORROWED, not copied — both follow from the same fact:
 * every payload reaching here is already owned for a period that contains this one (§12.3),
 * by the link that read it, by the calling realm's `ActiveHostCall`, or by the host caller
 * that allocated it. Counting or copying those bytes again would double the memory the
 * ownership rule exists to bound. Depth is this queue's own: waiting invocations are
 * objects on a chain nobody else counts. */
export function serializeCalls(
  invoke: (payload: Uint8Array) => Invocation,
  notReady: () => Error | null,
  maxQueuedCalls = DEFAULT_MAX_QUEUED_REALM_INVOCATIONS,
): (payload: Uint8Array) => Promise<Uint8Array> {
  let tail: Promise<unknown> = Promise.resolve();
  let queued = 0;
  return (payload) => {
    // Closed owners stop admission immediately. Already accepted work checks again when it
    // reaches the front because teardown can overtake it while it waits.
    const admissionError = notReady();
    if (admissionError) return Promise.reject(admissionError);
    if (queued >= maxQueuedCalls) {
      return Promise.reject(new Error(`guest: too many queued realm invocations (cap ${maxQueuedCalls})`));
    }
    queued++;
    const started = tail.then(() => {
      try {
        const err = notReady();
        if (err) throw err;
        return invoke(payload);
      } finally {
        queued--;
      }
    });
    // A failed invocation must not poison later work. The caller owns the real rejection;
    // this internal tail consumes both outcomes.
    tail = started.then((inv) => inv.released, () => {}).then(() => {}, () => {});
    return started.then((inv) => inv.result);
  };
}
