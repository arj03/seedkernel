// A test-only driver for ws.wasm's 4-op ABI (assembly/ws/index.ts).
//
// RFC 6455 framing is content, so the codec runs in the transport bundle's guest over
// this module, reached by its bare name. What is reachable from the host side is the
// module itself, and its conformance is worth testing directly rather than only through
// a live link — a bad mask direction or a fragmented control frame is far easier to
// provoke here than over a socket.
//
// This is deliberately the whole driver: stage a request at `scratch`, call
// handle(len), read the response back. It is the §4 module ABI, so the host drives
// it identically in production.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const OP_ENCODE = 1, OP_DECODE_ONE = 2, OP_ACCEPT = 3, OP_BASE64 = 4;
export const WS_OP = { BINARY: 0x2, CLOSE: 0x8, PING: 0x9, PONG: 0xa };

const wasm = new Uint8Array(readFileSync(join(root, "build/ws.wasm")));
const inst = new WebAssembly.Instance(new WebAssembly.Module(wasm), {
  env: { abort: () => { throw new Error("ws.wasm abort"); }, seed: () => Date.now(), trace: () => {} },
});
const exp = inst.exports;
const scratch = exp.scratch.value;

/** The module's declared scratch — read from the export rather than restated, since
 *  that export is exactly what tells the host how much it may stage. */
export const SCRATCH_SIZE = exp.scratchSize.value;

function call(req) {
  if (req.length > SCRATCH_SIZE) throw new Error("ws: request exceeds scratch");
  new Uint8Array(exp.memory.buffer, scratch, req.length).set(req);
  const len = exp.handle(req.length);
  if (len <= 0) return new Uint8Array(0);
  return new Uint8Array(exp.memory.buffer, scratch, len).slice();
}

/** base64(sha1(key ‖ GUID)) — the server's answer to Sec-WebSocket-Key. */
export function wsAcceptKey(key) {
  const k = new TextEncoder().encode(key);
  const req = new Uint8Array(1 + k.length);
  req[0] = OP_ACCEPT; req.set(k, 1);
  const out = call(req);
  if (out.length === 0) throw new Error("ws: accept failed");
  return new TextDecoder().decode(out);
}

export function wsBase64(bytes) {
  const req = new Uint8Array(1 + bytes.length);
  req[0] = OP_BASE64; req.set(bytes, 1);
  return new TextDecoder().decode(call(req));
}

/** Encode one frame. `mask` is 4 bytes for a client frame, null for a server one. */
export function encodeFrame(opcode, payload, mask) {
  const maskLen = mask ? 4 : 0;
  const req = new Uint8Array(3 + maskLen + payload.length);
  req[0] = OP_ENCODE; req[1] = opcode & 0x0f; req[2] = mask ? 1 : 0;
  if (mask) req.set(mask.subarray(0, 4), 3);
  req.set(payload, 3 + maskLen);
  const out = call(req);
  if (out.length === 0) throw new Error("ws: encode failed");
  return out;
}

/** Decode exactly one whole frame. Returns null on a protocol error, or
 *  `{ fin, opcode, payload }`. `expectMasked` enforces the RFC's directionality. */
export function decodeOne(frame, expectMasked) {
  const req = new Uint8Array(2 + frame.length);
  req[0] = OP_DECODE_ONE; req[1] = expectMasked ? 1 : 0;
  req.set(frame, 2);
  const r = call(req);
  if (r.length === 0 || r[0] !== 1) return null;
  const payloadLen = (r[6] << 24 | r[7] << 16 | r[8] << 8 | r[9]) >>> 0;
  return { fin: (r[1] & 0x80) !== 0, opcode: r[1] & 0x0f, payload: r.slice(10, 10 + payloadLen) };
}
