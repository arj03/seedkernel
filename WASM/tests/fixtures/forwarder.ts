// Test fixture: a minimal valid pure-transform module (§4). It exports `memory`, a
// `scratch` global and `handle`, and imports nothing from the runtime, only its language
// runtime's shims (§4.2). Tests use it as a generic installable module for install
// policy, bundle loading and the §4.1 scratch clamp, without a full app.
//
// It echoes its input: the host writes bytes at `scratch`, calls `handle` and reads the
// response from the same region, so returning `input_len` returns the payload.

// Reserved after the AssemblyScript runtime's own low memory at instantiation (top-level
// statements run in the implicit start function). Two buffers keep the module's memory
// larger than `scratch + SCRATCH_SIZE`, so the §4.1 clamp test shows an over-default
// payload is refused by the scratch size, not just by the memory bounds.
const SCRATCH_SIZE: i32 = 0x20000; // 128 KB, the §4.1 default

export let scratch: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;
heap.alloc(SCRATCH_SIZE); // headroom past scratch (see above)

// The input is already at `scratch`; returning its length echoes it. A negative or
// oversized return would be a failure (§4); `input_len` is neither, so the host reads
// back exactly the bytes it wrote.
export function handle(input_len: i32): i32 {
  // Imports the whole AssemblyScript shim set (`abort`, `seed`, `trace`), so every host
  // instantiating this fixture shows it provides all three (§4.2); a host providing a
  // subset would load real AS modules only by luck. The guard never fires, but the
  // optimizer cannot prove it, so the imports survive `--optimizeLevel 3`.
  if (input_len < 0) trace("unreachable", 1, Math.random());
  return input_len;
}
