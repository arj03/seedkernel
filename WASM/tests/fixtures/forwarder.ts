// Test fixture: a minimal, valid PURE-TRANSFORM handler (README §4). It exports
// `memory`, a `scratch` global, and `handle`, and imports nothing from the runtime —
// no `kernel.*` seam, only its own language runtime's shims (§4.2). The tests use it
// as a generic installable module: something real to drive install policy, bundle
// loading, and the §4.1 scratch clamp without pulling in a full app.
//
// It echoes its input: the host stages bytes at `scratch`, calls `handle`, and reads
// the response back from `scratch` (README §4). Returning `input_len` hands the same
// bytes straight back — so a caller reaching it by name (host `callModule`, or a
// guest through the cap-bridge module/call, §12.2) gets its payload returned.
//
// Not a chat module: the chat-shell demo has its own modules under
// assembly/chat-app-v*.

// Reserved past the AssemblyScript runtime's own low memory at module instantiation
// (top-level statements run in the implicit start function). Reserving two buffers
// keeps the module's memory comfortably larger than `scratch + SCRATCH_SIZE`, so the
// §4.1 clamp test can prove an over-default payload is refused by the reservation and
// not merely by the module's memory bounds.
const SCRATCH_SIZE: i32 = 0x20000; // 128 KB — the §4.1 default

export let scratch: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;
heap.alloc(SCRATCH_SIZE); // headroom past scratch (see above)

// The input is already at `scratch`; returning its length echoes it back from the same
// region. A negative or oversized return would be a failure (README §4); `input_len` is
// neither, so the host reads exactly the bytes it staged.
export function handle(input_len: i32): i32 {
  // Carries the *whole* AssemblyScript shim set — `abort`, `seed`, `trace` — rather
  // than just `abort`, so every host that instantiates this fixture proves it resolves
  // all three (§4.2). A host resolving a subset instantiates real AS handlers only by
  // luck: one `trace()` or `Math.random()` anywhere in a module makes the difference
  // between loading and a missing-import failure, and that must not be a property of
  // which target the module landed on. The guard never fires — `handle` is only ever
  // called with a length the host staged — but the optimizer cannot prove that, so the
  // imports survive `--optimizeLevel 3`.
  if (input_len < 0) trace("unreachable", 1, Math.random());
  return input_len;
}
