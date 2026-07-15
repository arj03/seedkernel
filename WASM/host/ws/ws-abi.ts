// Shared ws.wasm ABI constants — the single source of truth for both the
// AssemblyScript codec (assembly/ws/index.ts, which compiles into ws.wasm) and
// the host driver (ws-codec.ts), the same cross-unit sharing kernel/envelope.ts
// does within the AS tree. It lives under host/ because the host tsc build's
// rootDir is host/ (it can't reach into assembly/); the AS module reaches the
// other way and pulls this file into ws.wasm via a relative import. So keep it
// free of imports and any host/runtime API — it is compiled into the wasm too.
//
// Plain `export const`s with NO type annotations on purpose: asc infers i32 /
// string, tsc infers number / string, so the one file satisfies both compilers
// (an AS `: i32` would not type-check under tsc).

// Request ABI ops (see assembly/ws/index.ts `handle()`).
export const OP_ENCODE = 1;
export const OP_DECODE_ONE = 2;
export const OP_ACCEPT = 3;
export const OP_BASE64 = 4;

// RFC 6455 §4.2.2 handshake GUID.
export const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// One WS frame must fit the scratch region. Sized so the largest TCP transport
// message (MAX_FRAME_BYTES, 16 MiB, net-link.ts) also fits in a single WS frame
// plus header/mask overhead — the two transports must cap identically, or a
// message that succeeds over TCP would tear down a WS link. The AS module
// heap.allocs exactly SCRATCH_SIZE; the host caps every request against it.
export const SCRATCH_SIZE = (16 << 20) + (1 << 12); // 16 MB + 4 KB overhead slack
export const MAX_FRAME_PAYLOAD = SCRATCH_SIZE - 16;
