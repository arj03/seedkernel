// Public transport barrel (exported as `seedkernel-wasm/net`). Bundles the
// neutral, platform-independent transport surface only: the Network contract +
// Transport/LoopbackNetwork (net.ts) and the channel identity handshake
// (net-link.ts). This is the raw-byte `net` capability — bytes to/from an opaque
// peer id — and nothing structural. WebSocket framing is *not* part of it: it is
// a no-cap byte-transform module (ws.wasm, driven by host/ws/) exported
// separately as `seedkernel-wasm/ws`. The node-only fabric that binds this to
// real sockets is the separate `seedkernel-wasm/net-node` export (NodeNetwork).
// See the runtime split (raw-byte caps in the kernel, structure in modules).
export * from "./net.js";
export * from "./net-link.js";
