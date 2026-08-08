// The ws.wasm ABI constants, compiled into the module itself
// (assembly/ws/index.ts). The transport bundle's framers speak this ABI from the other
// side; their copy of the op numbers is in transport/src/framing.js, because a zero-authority
// guest is one self-contained concatenated source and imports nothing.
//
// Keep this free of imports and of any host or runtime API — it is compiled into the
// wasm, which may import nothing but the AS shims (§4.2).
//
// Plain `export const`s with NO type annotations on purpose: asc infers i32 / string,
// tsc infers number / string, so the one file satisfies both compilers (an AS `: i32`
// would not type-check under tsc).

// Request ABI ops (see assembly/ws/index.ts `handle()`).
export const OP_ENCODE = 1;
export const OP_DECODE_ONE = 2;
export const OP_ACCEPT = 3;
export const OP_BASE64 = 4;

// RFC 6455 §4.2.2 handshake GUID.
export const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// One WS frame must fit the scratch region. Sized so the largest transport message
// (MAX_FRAME_BYTES, 2 MiB, net-limits.ts) also fits in a single WS frame plus
// header/mask overhead — the two transports must cap identically, or a message that
// succeeds over TCP would tear down a WS link. The AS module heap.allocs exactly
// SCRATCH_SIZE; the host caps every request against it.
//
// **Keep this in step with MAX_FRAME_BYTES, and know that it is the floor on the cap.**
// The scratch is allocated at module init, and the module is in the transport bundle, so
// every shell pays it — loopback and TCP-only nodes that will never frame a WS byte
// included. That is why the cap is 2 MiB and not the 16 MiB it was: a host may lower its
// own `maxFrameBytes` below this, but raising it above what is compiled in here would let
// the transport hand this module a frame it has no room to stage.
export const SCRATCH_SIZE = (2 << 20) + (1 << 12); // 2 MB + 4 KB overhead slack
export const MAX_FRAME_PAYLOAD = SCRATCH_SIZE - 16;
