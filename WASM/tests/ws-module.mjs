// Test-only driver for RFC 6455 framing as the transport bundle does it: headers from
// transport/src/framing.js (`wsFrame`, `wsHead`), run as guest source in a vm, and the
// per-byte work from ws.wasm (assembly/ws/index.ts) through the same §4 module ABI the
// host uses: write a request at `scratch`, call handle(len), read the response back.
// Testing the codec directly makes a bad mask direction or a fragmented control frame far
// easier to provoke than over a socket.
import vm from "node:vm";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { guestOpFraming } from "./fixtures.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const OP_MASK = 1, OP_ACCEPT = 2, OP_BASE64 = 3;
export const WS_OP = { BINARY: 0x2, CLOSE: 0x8, PING: 0x9, PONG: 0xa };

const wasm = new Uint8Array(readFileSync(join(root, "build/ws.wasm")));
const inst = new WebAssembly.Instance(new WebAssembly.Module(wasm), {
  env: { abort: () => { throw new Error("ws.wasm abort"); }, seed: () => Date.now(), trace: () => {} },
});
const exp = inst.exports;
const scratch = exp.scratch.value;

/** The module's declared scratch size, read from the same export the host reads. */
export const SCRATCH_SIZE = exp.scratchSize.value;

function call(req) {
  if (req.length > SCRATCH_SIZE) throw new Error("ws: request exceeds scratch");
  new Uint8Array(exp.memory.buffer, scratch, req.length).set(req);
  const len = exp.handle(req.length);
  if (len <= 0) return new Uint8Array(0);
  return new Uint8Array(exp.memory.buffer, scratch, len).slice();
}

// framing.js's own functions, in the lexical scope util.js gives them in the bundle.
const guest = vm.createContext({ Uint8Array });
new vm.Script(
  readFileSync(join(root, "transport/src/util.js"), "utf8").replace("/* @seedkernel-op-frame */", guestOpFraming()) + "\n" +
  readFileSync(join(root, "transport/src/framing.js"), "utf8") + "\n" +
  "globalThis.codec = { wsFrame, wsHead, Pieces };",
).runInContext(guest);
const { wsFrame, wsHead, Pieces } = guest.codec;

/** base64(sha1(key ‖ GUID)): the server's answer to Sec-WebSocket-Key. */
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
  const f = wsFrame(opcode, payload, mask);
  if (!mask) return f;
  const out = call(f);
  if (out.length === 0) throw new Error("ws: masking failed");
  return out;
}

/** Decode exactly one whole frame. Returns null on a protocol error or a short frame, or
 *  `{ fin, opcode, payload }`. `expectMasked` enforces the RFC's directionality. */
export function decodeOne(frame, expectMasked) {
  const p = new Pieces();
  p.push(frame);
  const h = wsHead(p, expectMasked, Infinity);
  if (!h || frame.length < h.head + h.len) return null;
  const whole = frame.subarray(0, h.head + h.len);
  let clear = whole;
  if (expectMasked) {
    const req = new Uint8Array(1 + whole.length);
    req[0] = OP_MASK; req.set(whole, 1);
    clear = call(req);
  }
  return { fin: h.fin, opcode: h.opcode, payload: clear.slice(h.head) };
}
