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

// One WS frame must fit the scratch region, so this is sized to hold the largest transport
// message (MAX_FRAME_BYTES, net-limits.ts) plus header/mask overhead — the two transports
// must cap identically, or a message that succeeds over TCP tears down a WS link.
//
// **Keep this in step with MAX_FRAME_BYTES: it is the FLOOR on that cap.** The scratch is
// allocated at module init and the module ships in the transport bundle, so every shell
// pays it, TCP-only nodes included. A host may lower its own `maxFrameBytes` below this,
// but raising it above what is compiled in here would hand this module a frame it has no
// room to stage.
export const SCRATCH_SIZE = (2 << 20) + (1 << 12); // 2 MB + 4 KB overhead slack
export const MAX_FRAME_PAYLOAD = SCRATCH_SIZE - 16;
