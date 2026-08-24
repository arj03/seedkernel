// Regression fixture for the pure-module adapters' scratch erasure. A normal call records
// its length and returns empty. A later one-byte zero request returns that old span without
// rewriting it, exposing whatever the host left behind after the first call.
const SCRATCH_SIZE: i32 = 0x20000;

export let scratch: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;

let previous: i32 = 0;

export function handle(input_len: i32): i32 {
  if (input_len == 1 && load<u8>(scratch) == 0 && previous > 1) return previous;
  if (input_len == 1 && load<u8>(scratch) == 1) {
    previous = 64;
    memory.fill(scratch, 0xa5, previous);
    return previous;
  }
  previous = input_len;
  return 0;
}
