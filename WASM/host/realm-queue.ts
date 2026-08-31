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
 * Bounded in TIME as well as size: a `release()` nothing is committed to calling bounds
 * only until the freeing event fails to happen. Here that commitment is the realm's own
 * settlement path (§12.3) — the answer promise this is charged against settles on the
 * realm's clock, or failing that on dispose (`InvocationSettler` below). */
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

/** Own every guest-to-host copy and promise slot from admission through settlement.
 * Operation names are intentionally absent HERE — not because resource policy is
 * "name-blind" in general (it is not: `MemoryFs`'s quota and `isIrreversible` are both
 * legitimately keyed on the operation), but because the rule is narrower than that. A name
 * may TIGHTEN what an owner admits, never relax one, and a bound is enforced by the OWNER
 * of the resource — this registry, for an active host call — never by the dispatcher that
 * routed the call here. This owner has no name-keyed exemption to give, so it takes none.
 * The live id, count slot, and actual source width are admitted atomically. */
export function createActiveHostCallRegistry(
  maxCalls = DEFAULT_MAX_OUTSTANDING_HOST_CALLS,
  maxBytes = DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES,
  parent?: CustodyAllowance,
): { admit(callId: number, payloadBytes: number): ActiveHostCall } {
  const active = new Map<number, ActiveHostCall>();
  let bytes = 0;
  return {
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
 * Deliberately no byte ceiling of its own. Every payload reaching here is already owned for
 * a period that strictly contains this one: an inbound read by its link, from arrival until
 * the invocation settles (transport-host.ts); a guest-issued call by the calling realm's
 * `ActiveHostCall`; a local host caller's by whoever allocated it. A second byte counter
 * over the same bytes would bound nothing and would reject work the real owner had already
 * admitted — which is failure dressed as a limit, since a rejected invocation is an error
 * to its caller and not backpressure. Depth is this queue's own: waiting invocations are
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
    let queuedPayload: Uint8Array;
    try {
      queuedPayload = payload.slice();
    } catch (err) {
      queuedCalls--;
      releaseParent?.();
      throw err;
    }
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
        return invoke(queuedPayload);
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
