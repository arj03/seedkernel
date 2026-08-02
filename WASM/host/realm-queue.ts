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
// (which is the whole reason a guest exists rather than a pure-transform handler) has no
// way to reason about it.
//
// **The cost, stated plainly.** Head-of-line blocking: a parked initiator delays an
// inbound request to the same app rather than it being answered around. An app that
// genuinely wants both at once wants two realms, not one realm with two frames inside it.
//
// It lives in its own file, rather than in either realm factory, for the reason every
// shared rule in this tree does: a guarantee that held on one target and not the other
// would be a guarantee nobody has.

/** Wrap a per-invocation function so calls run one at a time, in acceptance order.
 *
 *  `notReady` is consulted at the moment an invocation reaches the front of the queue,
 *  never when it is accepted: a call queued behind others can be overtaken by a
 *  `dispose`, and entering a torn-down realm is what aborts the whole wasm module. It
 *  returns the error to fail with, or `null` to proceed. */
export function serializeCalls(
  invoke: (entry: string, payload: Uint8Array) => Promise<Uint8Array>,
  notReady: () => Error | null,
): (entry: string, payload: Uint8Array) => Promise<Uint8Array> {
  // The tail of the chain accepted so far. A new call attaches to it and becomes the
  // new tail.
  let tail: Promise<unknown> = Promise.resolve();
  return (entry, payload) => {
    const run = tail.then(() => {
      const err = notReady();
      if (err) throw err;
      return invoke(entry, payload);
    });
    // Both outcomes swallowed, and that is load-bearing twice: a failed invocation must
    // not poison every later one, and an unhandled rejection on this internal chain
    // would be reported against the host rather than against the caller, who holds the
    // real promise and its real error.
    tail = run.then(() => {}, () => {});
    return run;
  };
}
