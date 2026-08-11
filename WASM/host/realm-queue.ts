// The per-realm serialization queue — one implementation, shared by both realm
// factories (safe-js.ts on the JS platform, native-shim.ts over Go's quickjs-ng).
//
// **What it guarantees.** An invocation does not begin until the previous one has
// settled, so no two guest frames are ever in flight in one realm.
//
// **Why that needs a queue at all.** Both roles a realm serves can yield: an initiator
// awaits the network, and a holder awaits `fs`, because a synchronous `get` is a shape no
// browser backend can implement (core/fs.ts) and the seam is one shape on every target.
// So there is no arrangement in which one entry is synchronous and the ordering falls out
// of the host's call stack. Without the queue, a holder invoked while an initiator is
// parked runs *interleaved* with it — the two frames resuming into each other at every
// `await`, in an order neither the guest author nor the host chose. That is not a
// performance question but a correctness one: a guest keeping state across an await
// (which is the whole reason a guest exists rather than a pure-transform module) has no
// way to reason about it.
//
// **The cost, stated plainly.** Head-of-line blocking: a parked initiator delays an
// inbound request to the same app rather than it being answered around. An app that
// genuinely wants both at once wants two realms, not one realm with two frames inside it.
//
// **What "in flight" means, and the one guest for which it is not the answer.** A frame
// is in flight while the guest is PARKED — suspended mid-frame on a host call, with local
// state half-updated across the await. That is the state this queue exists to keep two of
// from coexisting, and for every ordinary guest it coincides exactly with "the invocation
// has not settled". It does not coincide for a guest whose answer arrives through its own
// realm: the transport replies to an app's send by reading bytes off a link, and
// reading those bytes is another invocation of this same realm. Waiting for its answer
// would hold the queue against the only event that could settle it — a deadlock, not a
// delay. Such a guest calls `defer()` (guest-seam.ts) instead of awaiting: its entrypoint
// runs to completion and hands back a promise it will settle later, so there is no frame
// left to interleave with and the realm is genuinely free. `Invocation` is that
// distinction made explicit — `released` is when the realm is free, `result` is when the
// caller has an answer, and they are the same promise except in the deferred case.
//
// It lives in its own file, rather than in either realm factory, for the reason every
// shared rule in this tree does: a guarantee that held on one target and not the other
// would be a guarantee nobody has.

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
    // Both outcomes swallowed, and that is load-bearing twice: a failed invocation must
    // not poison every later one, and an unhandled rejection on this internal chain
    // would be reported against the host rather than against the caller, who holds the
    // real promise and its real error. An invocation that never started — `notReady`, or
    // a throw out of `invoke` before it produced anything — releases the realm at once,
    // which is what the rejected arm says.
    tail = started.then((inv) => inv.released, () => {}).then(() => {}, () => {});
    return started.then((inv) => inv.result);
  };
}
