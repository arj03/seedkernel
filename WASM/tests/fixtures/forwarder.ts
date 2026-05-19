// Test fixture: a minimal WASM handler installed via a signed install
// message routed to the install handler (README §3.2). Exercises the
// scratch-region handler contract (README §4) and the kernel.call
// cross-module primitive (§4.4).
//
// Despite living near the test runner, this is not a chat module — the
// chat-shell demo uses its own modules under assembly/chat-app-v*. This
// fixture is a generic forwarder used purely by tests/run.mjs.
//
// Payload format (handler protocol):
//   [target_schema_len u8][target_schema ..][forward_payload ..]
// On each message the handler forwards `forward_payload` to `target_schema`
// via kernel.call and stores whatever response comes back so the test can
// inspect it.

@external("kernel", "call")
declare function kernelCall(
  schemaPtr: i32, schemaLen: i32,
  payloadPtr: i32, payloadLen: i32
): i32;

const SCRATCH_SIZE: i32 = 0x20000; // 128 KB

// Reserved at module instantiation (top-level statements run in the
// implicit start function). The host reads `scratch` once after load to
// learn where to deliver inputs and read responses.
export let scratch: i32 = 0;
let _private: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;
_private = heap.alloc(SCRATCH_SIZE) as i32;

// Test inspection accessors — the saved response from the most recent
// kernel.call lives in private memory so it survives the next dispatch.
let savedRespLen: i32 = 0;
export function last_resp_ptr(): i32 { return _private; }
export function last_resp_len(): i32 { return savedRespLen; }

export function handle(input_len: i32): i32 {
  if (input_len < 1) return 0;

  const schLen = load<u8>(scratch) as i32;
  if (input_len < 1 + schLen) return 0;
  const fwdLen = input_len - 1 - schLen;

  // kernel.call will overwrite our scratch with the response. Stage the
  // name and forward payload in private memory first; pass pointers into
  // private memory to kernel.call (any caller-memory location works).
  const stagedSch = _private + 0x10000; // 64 KB into private buffer
  const stagedFwd = stagedSch + schLen;
  memory.copy(stagedSch, scratch + 1, schLen);
  memory.copy(stagedFwd, scratch + 1 + schLen, fwdLen);

  const responseLen = kernelCall(stagedSch, schLen, stagedFwd, fwdLen);
  if (responseLen < 0) {
    savedRespLen = 0;
    return 0;
  }

  // Response is now at scratch (overwriting our input). Copy to private
  // memory so the test can inspect it after the handler returns.
  memory.copy(_private, scratch, responseLen);
  savedRespLen = responseLen;

  return 0; // the fixture itself produces no outbound response
}
