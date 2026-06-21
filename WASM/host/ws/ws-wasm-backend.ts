// The WebAssembly backend for the ws codec (node / Bun / browser). It instantiates
// the inlined ws.wasm lazily on first use (sync compile from base64, no fs read)
// and exposes the 4-op `handle(req) -> resp` ABI ws-codec.ts drives. The Go loader
// uses a different backend (ws.wasm over wazero, __ws) — same .wasm, same bytes.
//
// Split out of ws-codec.ts so the codec carries no WebAssembly reference or the
// ~1 MiB base64 blob: the native loader bundles ws-codec.ts (and net-frame.ts)
// into QuickJS without dragging this file in.

import { WS_WASM_B64 } from "./ws-wasm.js";
import { setWsHandle, SCRATCH_SIZE } from "./ws-codec.js";

interface WsExports {
  memory: WebAssembly.Memory;
  scratch: WebAssembly.Global;
  handle(input_len: number): number;
}

let exp: WsExports | null = null;
let scratch = 0;

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function ws(): WsExports {
  if (exp) return exp;
  const inst = new WebAssembly.Instance(new WebAssembly.Module(b64ToBytes(WS_WASM_B64) as BufferSource), {
    env: {
      abort: () => { throw new Error("ws.wasm abort"); },
      seed: () => Date.now(),
      trace: () => {},
    },
  });
  exp = inst.exports as unknown as WsExports;
  scratch = exp.scratch.value as number;
  return exp;
}

/** Stage `req` at the module's scratch offset, run handle(), and copy out the
 *  response. An overrun would silently corrupt the shared singleton instance, so
 *  bound the request against the scratch *region*. */
function wasmHandle(req: Uint8Array): Uint8Array {
  const e = ws();
  if (req.length > SCRATCH_SIZE) throw new Error("ws: request exceeds scratch");
  new Uint8Array(e.memory.buffer, scratch, req.length).set(req);
  const len = e.handle(req.length);
  if (len <= 0) return new Uint8Array(0); // module-reported error / need-more
  return new Uint8Array(e.memory.buffer, scratch, len).slice();
}

let installed = false;

/** Make the WebAssembly ws.wasm the codec backend. Idempotent; the module itself
 *  is still instantiated lazily, on the first frame. */
export function installWasmWsBackend(): void {
  if (installed) return;
  installed = true;
  setWsHandle(wasmHandle);
}
