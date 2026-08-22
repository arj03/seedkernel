// The inbound flood bounds (§12.6.2, §16.1). Host-side rather than in the transport
// bundle because a limit protecting a resource is declared by whoever owns the resource;
// the bundle's framers apply them and learn both numbers at init. (MAX_QUEUE_BYTES is the
// same rule pointed the other way and stays in the bundle: it bounds the module's own
// memory.) Neither cap is negotiated or per-suite — TCP, WebSocket and WebRTC cap alike.
/** Hard cap on one link frame (§16.1), checked against the declared length — the TCP
 *  length prefix, the WS frame header — before the body is buffered. It is a
 *  *pre-allocation* bound: what a peer can make a node reserve from a single prefix.
 *
 *  Raising it means rebuilding ws.wasm (assembly/ws/abi.ts), which stages a whole frame in
 *  a scratch region allocated at module init; forget, and `tests/transport.test.mjs` says
 *  so by name rather than a WS link tearing down on the first big frame while TCP carries
 *  it. Lowering one host's cap needs no rebuild (`TransportHostOptions.maxFrameBytes`). */
export const MAX_FRAME_BYTES = 2 * 1024 * 1024; // 2 MiB
/** The frame cap that applies BEFORE a link authenticates; the bundle raises its framers
 *  to `MAX_FRAME_BYTES` on authentication. Applying the full cap pre-auth is a
 *  memory-exhaustion hole: a stranger who knows only host:port declares a full-size frame,
 *  dribbles the body and holds that much memory — times the half-open budget.
 *
 *  8 KiB rather than 512 because an ML-KEM-768 encapsulation key is 1,184 bytes: a tighter
 *  cap would be the one remaining reason a PQ handshake still needed a core rev (§14.1).
 *  It still holds pre-authentication buffering to 8 MiB against the unverified budget. */
export const MAX_HANDSHAKE_FRAME_BYTES = 8 * 1024;
