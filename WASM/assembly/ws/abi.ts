// The ws.wasm ABI constants, compiled into the module itself (assembly/ws/index.ts). The
// transport bundle's framers use this ABI from the other side; their copy of the op
// numbers is in transport/src/framing.js, because the guest is one self-contained source
// and imports nothing.
//
// Keep this free of imports and of any host or runtime API: it is compiled into the wasm,
// which may import nothing but the AS shims (§4.2).
//
// Plain `export const`s without type annotations: asc infers i32 / string and tsc infers
// number / string, so one file works for both compilers (an AS `: i32` would not
// type-check under tsc).

// Request ABI ops (see assembly/ws/index.ts `handle()`).
export const OP_ENCODE = 1;
export const OP_DECODE_ONE = 2;
export const OP_ACCEPT = 3;
export const OP_BASE64 = 4;

// RFC 6455 §4.2.2 handshake GUID.
export const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// One WS frame must fit the scratch region, so this holds the largest transport message
// (MAX_FRAME_BYTES, scripts/transport-config.mjs) plus header and mask overhead. Both
// framings must have the same cap, or a message that works over TCP tears down a WS link.
//
// Keep this in step with MAX_FRAME_BYTES; it is the upper limit for that cap. The scratch
// is allocated at module init, so every node pays for it, and a `maxFrameBytes` above the
// compiled-in size would hand this module a frame it has no room for.
export const SCRATCH_SIZE = (2 << 20) + (1 << 12); // 2 MB + 4 KB overhead slack
export const MAX_FRAME_PAYLOAD = SCRATCH_SIZE - 16;
