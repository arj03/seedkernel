// Constants only — decoding is done by kernel.wasm; encoding is host-side.

export const MAGIC = 0x5344;
export const CURRENT_VERSION = 0x01;
// Hard upper bound on the total envelope (README §2.2). Enforced at decode
// by kernel.wasm and at encode by the host.
export const MAX_ENVELOPE_BYTES = 65536;
