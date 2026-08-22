// The per-realm serialization queue — one implementation, shared by both realm factories
// (safe-js.ts on the JS platform, native-shim.ts over Go's quickjs-ng).
//
// An invocation does not begin until the previous one has settled, so no two guest frames
// are ever in flight in one realm. Both roles a realm serves can yield — an initiator
// awaits the network, a holder awaits `fs` — so ordering does not fall out of the host's
// call stack; without the queue, a holder invoked while an initiator is parked resumes
// interleaved with it at every `await`, in an order neither the guest author nor the host
// chose. The cost is head-of-line blocking, and an app that wants both at once wants two
// realms.
//
// A frame is in flight while the guest is parked mid-frame, which for an ordinary guest
// coincides with "the invocation has not settled". It does not for a guest whose answer
// arrives through its own realm: the transport replies to a send by reading bytes off a
// link, and reading them is another invocation of this same realm, so waiting would hold
// the queue against the only event that could settle it. Such a guest calls `defer()`
// (guest-seam.ts) instead of awaiting; `Invocation` is that distinction made explicit.

/** One entrypoint invocation, in the two moments that are not always the same. */
export interface Invocation {
  /** The entrypoint's answer, which is what the caller of `call` receives. */
  result: Promise<Uint8Array>;
  /** Settles when this realm is free for the next invocation: with `result` for an
   *  ordinary entrypoint, and as soon as the synchronous segment ends for a deferred
   *  one. Its VALUE is never read and its rejection is swallowed here — the caller holds
   *  `result` and with it the real error. */
  released: Promise<unknown>;
}

/** Wrap a per-invocation function so calls run one at a time, in acceptance order.
 *
 *  `notReady` is consulted at the moment an invocation reaches the front of the queue,
 *  never when it is accepted: a call queued behind others can be overtaken by a
 *  `dispose`, and entering a torn-down realm is what aborts the whole wasm module. It
 *  returns the error to fail with, or `null` to proceed. */
export function serializeCalls(
  invoke: (entry: string, payload: Uint8Array) => Invocation,
  notReady: () => Error | null,
): (entry: string, payload: Uint8Array) => Promise<Uint8Array> {
  // The tail of the chain accepted so far. A new call attaches to it and becomes the
  // new tail.
  let tail: Promise<unknown> = Promise.resolve();
  return (entry, payload) => {
    const started = tail.then(() => {
      const err = notReady();
      if (err) throw err;
      return invoke(entry, payload);
    });
    // Both outcomes swallowed, load-bearing twice: a failed invocation must not poison
    // every later one, and an unhandled rejection on this internal chain would be reported
    // against the host rather than the caller, who holds the real error. The rejected arm
    // is an invocation that never started, which releases the realm at once.
    tail = started.then((inv) => inv.released, () => {}).then(() => {}, () => {});
    return started.then((inv) => inv.result);
  };
}
