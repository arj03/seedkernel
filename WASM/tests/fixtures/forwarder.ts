// Test fixture: a minimal, valid PURE-TRANSFORM module (README §4). It exports
// `memory`, a `scratch` global, and `handle`, and imports nothing from the runtime —
// no host seam at all, only its own language runtime's shims (§4.2). The tests use it
// as a generic installable module: something real to drive install policy, bundle
// loading, and the §4.1 scratch clamp without pulling in a full app.
//
// It echoes its input: the host stages bytes at `scratch`, calls `handle` and reads the
// response back from the same region, so returning `input_len` hands the payload straight
// back to whoever called it by name.

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
  // Carries the WHOLE AssemblyScript shim set — `abort`, `seed`, `trace` — so every host
  // instantiating this fixture proves it resolves all three (§4.2): a host resolving a
  // subset loads real AS modules only by luck, and that must not depend on which target a
  // module landed on. The guard never fires, but the optimizer cannot prove it, so the
  // imports survive `--optimizeLevel 3`.
  if (input_len < 0) trace("unreachable", 1, Math.random());
  return input_len;
}
