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
import { concatBytes, readU32BE, ByteQueue } from "../util.js";

const OP_ENCODE = 1, OP_DECODE_ONE = 2, OP_ACCEPT = 3, OP_BASE64 = 4;

export const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
export const OP_BINARY = 0x2;
const OP_CONT = 0x0, OP_CLOSE = 0x8, OP_PING = 0x9, OP_PONG = 0xa;
export const WS_OPCODES = { OP_BINARY, OP_CLOSE, OP_PING, OP_PONG } as const;

// Must match SCRATCH_SIZE / SCRATCH_SIZE - 16 in assembly/ws/index.ts.
const SCRATCH_SIZE = (16 << 20) + (1 << 12);
const SCRATCH_MAX = SCRATCH_SIZE - 16;

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
  // Bound against the module's scratch *region*, not just the end of linear
  // memory — an overrun would silently corrupt the shared singleton instance.
  if (bytes.length > SCRATCH_SIZE) throw new Error("ws: request exceeds scratch");
  new Uint8Array(m.exp.memory.buffer, m.scratch, bytes.length).set(bytes);
  return bytes.length;
}
function read(m: WsMod, len: number): Uint8Array {
  return new Uint8Array(m.exp.memory.buffer, m.scratch, len).slice();
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
  if (payload.length > SCRATCH_MAX) throw new Error("ws: payload exceeds frame cap");
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
 *  channel tears down. Fragmented data messages (FIN=0 + continuation frames —
 *  e.g. a browser's platform WebSocket splitting a large send()) are reassembled
 *  here, bounded by the same cap as a single frame; control frames may interleave
 *  mid-fragmentation per RFC 6455 §5.4. */
export class WsParser {
  private readonly q = new ByteQueue();
  // In-flight fragmented message: the first fragment's opcode (-1 = none) and
  // the accumulated fragment payloads.
  private fragOpcode = -1;
  private frags: Uint8Array[] = [];
  private fragBytes = 0;
  constructor(private readonly expectMasked: boolean) {}

  push(chunk: Uint8Array): WsFrame[] {
    const m = ws();
    this.q.push(chunk);
    const out: WsFrame[] = [];
    for (;;) {
      // Wait for one complete frame before staging it for the module, so a big
      // frame arriving in many chunks is copied once, not once per chunk.
      const total = this.frameLength();
      if (total < 0) break;
      if (total > SCRATCH_MAX) throw new Error("ws: oversize frame");
      if (this.q.length < total) break;
      const frame = this.q.take(total)!;
      const req = new Uint8Array(2 + frame.length);
      req[0] = OP_DECODE_ONE; req[1] = this.expectMasked ? 1 : 0; req.set(frame, 2);
      const r = read(m, m.exp.handle(write(m, req)));
      // The module saw exactly one whole frame; anything but "frame" (1) is a
      // protocol violation (bad mask direction, fragmented control, bad length).
      if (r[0] !== 1) throw new Error("ws: protocol error");
      const fin = (r[1] & 0x80) !== 0;
      const opcode = r[1] & 0x0f;
      const payloadLen = readU32BE(r, 6);
      const payload = r.slice(10, 10 + payloadLen);

      if (opcode === OP_CONT) {
        // continuation of an in-flight fragmented message
        if (this.fragOpcode < 0) throw new Error("ws: protocol error");
        this.fragBytes += payload.length;
        if (this.fragBytes > SCRATCH_MAX) throw new Error("ws: oversize frame");
        this.frags.push(payload);
        if (fin) {
          const whole = concatBytes(this.frags);
          const first = this.fragOpcode;
          this.fragOpcode = -1; this.frags = []; this.fragBytes = 0;
          out.push({ opcode: first, payload: whole });
        }
      } else if (!fin) {
        // first fragment of a data message (the module rejects fragmented
        // control frames before we get here)
        if (this.fragOpcode >= 0) throw new Error("ws: protocol error");
        this.fragOpcode = opcode;
        this.frags = [payload];
        this.fragBytes = payload.length;
      } else {
        // unfragmented frame; a *data* frame may not preempt an in-flight
        // fragmented message, but control frames interleave freely (§5.4)
        if (opcode < 0x8 && this.fragOpcode >= 0) throw new Error("ws: protocol error");
        out.push({ opcode, payload });
      }
    }
    return out;
  }

  /** Total byte length of the next frame, read from the (unvalidated) header —
   *  or -1 if too few bytes are buffered to know yet. All real validation stays
   *  in ws.wasm; this only sizes the wait. */
  private frameLength(): number {
    const h = this.q.peek(2);
    if (!h) return -1;
    const masked = (h[1] & 0x80) !== 0;
    const len7 = h[1] & 0x7f;
    let headerLen = 2, payloadLen = len7;
    if (len7 === 126) {
      const e = this.q.peek(4);
      if (!e) return -1;
      headerLen = 4;
      payloadLen = (e[2] << 8) | e[3];
    } else if (len7 === 127) {
      const e = this.q.peek(10);
      if (!e) return -1;
      if (readU32BE(e, 2) !== 0) throw new Error("ws: oversize frame"); // > 4 GiB
      headerLen = 10;
      payloadLen = readU32BE(e, 6);
    }
    return headerLen + (masked ? 4 : 0) + payloadLen;
  }
}
