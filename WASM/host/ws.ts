// Public WS module barrel (exported as `seedkernel-wasm/ws`). WebSocket framing
// is a no-capability byte transform — structurally identical to codec.wasm — not
// a transport capability, so it lives outside the `net` barrel (see
// the runtime split: "WebSocket framing is ws.wasm, not host code"). The host
// driver in ws/ pumps bytes through the lazily-instantiated ws.wasm; the kernel
// owns the socket and RNG and knows nothing about WS. net-node consumes ws/
// directly for its socket pump; this barrel is the surface for any other consumer
// (e.g. RFC 6455 conformance tests).
export * from "./ws/ws-codec.js";
