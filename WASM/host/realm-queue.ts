// The two per-realm boundary owners shared by the JS and native realm factories:
// active guest-to-host calls, and serialized payloads waiting to enter the guest.

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

/** One active call's custody. Further host copies are reserved before creation and all
 * capacity remains owned until response delivery or terminal failure has completed.
 *
 * Bounded in TIME as well as size (§12.3): the host's answer releases it, and disposal
 * releases whatever never answered — the guest that would have consumed it is gone, so
 * what a still-pending backend holds is the host's own memory, not this realm's. Without
 * that second path one unanswering backend pins the node pool for good. */
export interface ActiveHostCall {
  reserve(bytes: number): void;
  release(): void;
}

/** A parent owner used to compose finite child allowances without exposing counters. */
export interface CustodyAllowance {
  reserve(objects: number, bytes: number): () => void;
}

export function createCustodyAllowance(maxObjects: number, maxBytes: number): CustodyAllowance {
  let objects = 0;
  let bytes = 0;
  return {
    reserve(additionalObjects: number, additionalBytes: number): () => void {
      if (!Number.isSafeInteger(additionalObjects) || additionalObjects < 0) {
        throw new Error("guest: invalid custody object count");
      }
      checkedBytes(additionalBytes);
      if (additionalObjects > maxObjects - objects || additionalBytes > maxBytes - bytes) {
        throw new Error("guest: node custody allowance exceeded");
      }
      objects += additionalObjects;
      bytes += additionalBytes;
      let live = true;
      return () => {
        if (!live) return;
        live = false;
        objects -= additionalObjects;
        bytes -= additionalBytes;
      };
    },
  };
}

/** Own every guest-to-host copy and promise slot from admission through settlement (§12.3).
 * Id, count slot and actual source width are admitted atomically. No operation name reaches
 * here: policy elsewhere is legitimately name-keyed (`MemoryFs`'s quota, `isIrreversible`),
 * but a name may only TIGHTEN what an owner admits, and this owner has no exemption to
 * give — the resource's owner decides, never the dispatcher that routed the call. */
export function createActiveHostCallRegistry(
  maxCalls = DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  maxBytes = DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
  parent?: CustodyAllowance,
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
      const parentReleases: (() => void)[] = [];
      if (parent) parentReleases.push(parent.reserve(1, payloadBytes));
      bytes += payloadBytes;
      let ownedBytes = payloadBytes;
      let live = true;
      const call: ActiveHostCall = {
        reserve(additionalBytes: number): void {
          if (!live) throw new Error("guest: host call is no longer active");
          checkedBytes(additionalBytes);
          if (additionalBytes > maxBytes - bytes) {
            throw new Error(`guest: too many outstanding host call payload bytes (cap ${maxBytes})`);
          }
          if (parent) parentReleases.push(parent.reserve(0, additionalBytes));
          bytes += additionalBytes;
          ownedBytes += additionalBytes;
        },
        release(): void {
          if (!live) return;
          live = false;
          if (active.get(callId) === call) active.delete(callId);
          bytes -= ownedBytes;
          for (const release of parentReleases) release();
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
    track(reject) {
      live.add(reject);
      let tracked = true;
      return () => {
        if (!tracked) return;
        tracked = false;
        live.delete(reject);
      };
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
  parent?: CustodyAllowance,
): (payload: Uint8Array) => Promise<Uint8Array> {
  let tail: Promise<unknown> = Promise.resolve();
  let queuedCalls = 0;
  return (payload) => {
    // Closed owners stop admission immediately. Already accepted work checks again when it
    // reaches the front because teardown can overtake it while it waits.
    const admissionError = notReady();
    if (admissionError) return Promise.reject(admissionError);
    if (queuedCalls >= maxQueuedCalls) {
      return Promise.reject(new Error(`guest: too many queued realm invocations (cap ${maxQueuedCalls})`));
    }
    let releaseParent: (() => void) | undefined;
    try {
      releaseParent = parent?.reserve(1, 0);
    } catch (err) {
      return Promise.reject(err);
    }
    queuedCalls++;
    let owned = true;
    const releaseEntry = () => {
      if (!owned) return;
      owned = false;
      queuedCalls--;
      releaseParent?.();
    };
    const started = tail.then(() => {
      try {
        const err = notReady();
        if (err) throw err;
        return invoke(payload);
      } finally {
        releaseEntry();
      }
    });
    // A failed invocation must not poison later work. The caller owns the real rejection;
    // this internal tail consumes both outcomes.
    tail = started.then((inv) => inv.released, () => {}).then(() => {}, () => {});
    return started.then((inv) => inv.result);
  };
}
