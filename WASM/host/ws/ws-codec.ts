// Host driver for the no-cap ws.wasm (RFC 6455 framing + handshake). It presents
// the same API the former pure-JS ws-frame.ts did — wsAcceptKey / wsClientKey /
// encodeFrame / WsParser / WS_OPCODES — but every byte transform now runs inside
// the WASM module (the runtime split). The module is instantiated
// lazily on first use (sync compile from inlined bytes), so a pure node↔node
// deployment that never speaks WebSocket — and the browser, which uses the
// platform WebSocket — never compile it. The host owns the socket and the RNG
// and pumps bytes through; the module holds no per-connection state (the WsParser
// host object keeps the residual buffer).

import { WS_WASM_B64 } from "./ws-wasm.js";

const OP_ENCODE = 1, OP_DECODE_ONE = 2, OP_ACCEPT = 3, OP_BASE64 = 4;

export const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
export const OP_BINARY = 0x2;
const OP_CLOSE = 0x8, OP_PING = 0x9, OP_PONG = 0xa;
export const WS_OPCODES = { OP_BINARY, OP_CLOSE, OP_PING, OP_PONG } as const;

// Must match SCRATCH_SIZE - 16 in assembly/ws/index.ts.
const SCRATCH_MAX = (4 << 20) - 16;

interface WsExports {
  memory: WebAssembly.Memory;
  scratch: WebAssembly.Global;
  handle(input_len: number): number;
}
interface WsMod { exp: WsExports; scratch: number; }

let mod: WsMod | null = null;

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function ws(): WsMod {
  if (mod) return mod;
  const inst = new WebAssembly.Instance(new WebAssembly.Module(b64ToBytes(WS_WASM_B64) as BufferSource), {
    env: {
      abort: () => { throw new Error("ws.wasm abort"); },
      seed: () => Date.now(),
      trace: () => {},
    },
  });
  const exp = inst.exports as unknown as WsExports;
  mod = { exp, scratch: exp.scratch.value as number };
  return mod;
}

function write(m: WsMod, bytes: Uint8Array): number {
  new Uint8Array(m.exp.memory.buffer, m.scratch, bytes.length).set(bytes);
  return bytes.length;
}
function read(m: WsMod, len: number): Uint8Array {
  return new Uint8Array(m.exp.memory.buffer, m.scratch, len).slice();
}
function readU32BE(b: Uint8Array, o: number): number {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export interface WsFrame { opcode: number; payload: Uint8Array; }

/** Encode one frame. `mask` true for client→server (RFC requires it), false for
 *  server→client; the 4-byte mask, when present, is supplied by the caller so the
 *  module stays free of any RNG dependency. */
export function encodeFrame(opcode: number, payload: Uint8Array, mask: Uint8Array | null): Uint8Array {
  const m = ws();
  const maskLen = mask ? 4 : 0;
  const req = new Uint8Array(3 + maskLen + payload.length);
  req[0] = OP_ENCODE; req[1] = opcode & 0x0f; req[2] = mask ? 1 : 0;
  if (mask) req.set(mask.subarray(0, 4), 3);
  req.set(payload, 3 + maskLen);
  const len = m.exp.handle(write(m, req));
  if (len <= 0) throw new Error("ws: encode failed");
  return read(m, len);
}

/** server accept value for a client's Sec-WebSocket-Key (RFC 6455 §4.2.2). */
export function wsAcceptKey(secWebSocketKey: string): string {
  const m = ws();
  const key = enc.encode(secWebSocketKey);
  const req = new Uint8Array(1 + key.length);
  req[0] = OP_ACCEPT; req.set(key, 1);
  const len = m.exp.handle(write(m, req));
  if (len <= 0) throw new Error("ws: accept failed");
  return dec.decode(read(m, len));
}

/** A fresh client Sec-WebSocket-Key plus the accept value it must hear back. */
export function wsClientKey(rand16: Uint8Array): { key: string; expectAccept: string } {
  const m = ws();
  const req = new Uint8Array(1 + 16);
  req[0] = OP_BASE64; req.set(rand16.subarray(0, 16), 1);
  const len = m.exp.handle(write(m, req));
  if (len <= 0) throw new Error("ws: base64 failed");
  const key = dec.decode(read(m, len));
  return { key, expectAccept: wsAcceptKey(key) };
}

/** Incremental frame reader. `expectMasked` enforces the RFC's directionality:
 *  a server feeds client bytes (must be masked); a client feeds server bytes
 *  (must be unmasked). Holds the residual buffer host-side and parses one frame
 *  at a time through the stateless module; throws on a protocol violation so the
 *  channel tears down. */
export class WsParser {
  private buf = new Uint8Array(0);
  constructor(private readonly expectMasked: boolean) {}

  push(chunk: Uint8Array): WsFrame[] {
    const m = ws();
    const merged = new Uint8Array(this.buf.length + chunk.length);
    merged.set(this.buf, 0); merged.set(chunk, this.buf.length);
    this.buf = merged;
    const out: WsFrame[] = [];
    while (this.buf.length >= 2) {
      const view = this.buf.length <= SCRATCH_MAX ? this.buf : this.buf.subarray(0, SCRATCH_MAX);
      const req = new Uint8Array(2 + view.length);
      req[0] = OP_DECODE_ONE; req[1] = this.expectMasked ? 1 : 0; req.set(view, 2);
      const r = read(m, m.exp.handle(write(m, req)));
      const status = r[0];
      if (status === 0) {
        if (this.buf.length >= SCRATCH_MAX) throw new Error("ws: oversize frame");
        break;
      }
      if (status === 2) throw new Error("ws: protocol error");
      const opcode = r[1];
      const consumed = readU32BE(r, 2);
      const payloadLen = readU32BE(r, 6);
      out.push({ opcode, payload: r.slice(10, 10 + payloadLen) });
      this.buf = this.buf.slice(consumed);
    }
    return out;
  }
}
