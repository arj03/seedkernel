// bench-module-call.mjs — the §4.3 module-call path, measured the way the native target's
// bound is: same workload, with and without the interrupt mechanism, as a ratio. Native
// cost (SECURITY §14.1) is MULTIPLICATIVE (a termination check per loop: 2.8x RS encode,
// 4.8x decode, 2.6x XChaCha20, 1.65x Ed25519); the JS worker model is ADDITIVE — one
// fixed isolate round-trip per call, quantified here on ws.wasm. Run after `npm run build`.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);
const { ModuleTable } = await imp("build/host/module-table.js");

const wasm = new Uint8Array(readFileSync(join(root, "build/ws.wasm")));
const OP_ENCODE = 1, OP_DECODE_ONE = 2;

// A masked binary frame request, built once per size: [op][opcode][maskFlag][mask 4][payload].
const frameReq = (payloadLen, mask) => {
  const req = new Uint8Array(3 + (mask ? 4 : 0) + payloadLen);
  req[0] = OP_ENCODE; req[1] = 0x2; req[2] = mask ? 1 : 0;
  if (mask) req.fill(0x5a, 3, 7);
  req.fill(0x33, 3 + (mask ? 4 : 0));
  return req;
};

/** Time one op on an in-thread instance: stage at scratch, call handle, read back. */
function timeInThread(inst, reqs, iters) {
  const exps = inst.exports;
  const mem = exps.memory.buffer;
  const scratch = exps.scratch.value;
  const handle = exps.handle;
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) {
    const r = reqs[i % reqs.length];
    new Uint8Array(mem, scratch, r.length).set(r);
    const len = handle(r.length);
    if (len <= 0) throw new Error("ws: module error");
  }
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

/** Time the same ops through the worker-per-module table. */
async function timeWorker(table, reqs, iters) {
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) {
    const r = await table.call("ws", reqs[i % reqs.length]);
    if (r === null || r.length === 0) throw new Error("ws: module error");
  }
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

const mod = new WebAssembly.Module(wasm);
const inst = new WebAssembly.Instance(mod, { env: { abort: () => {}, seed: () => 0, trace: () => {} } });
const table = new ModuleTable({ deadlineMs: 60_000 });
const modules = await table.build([{ name: "ws", wasm }]);

console.log("module-call cost, in-thread vs worker-per-module — ws.wasm (RFC 6455 codec)\n");
console.log(`${"workload".padEnd(38)}${"in-thread".padStart(12)}${"worker".padStart(12)}${"ratio".padStart(8)}`);
console.log("-".repeat(70));

for (const [name, payloadLen, iters] of [
  ["encode 64 KiB frame (masked)", 64 * 1024, 2000],
  ["encode 1 KiB frame (masked)", 1024, 5000],
  ["encode 32 B control frame", 32, 20000],
]) {
  const reqs = [frameReq(payloadLen, true)];
  const tIn = timeInThread(inst, reqs, iters);
  const tW = await timeWorker(modules, reqs, iters);
  console.log(`${name.padEnd(38)}${(tIn / iters * 1000).toFixed(1).padStart(10)} us${(tW / iters * 1000).toFixed(1).padStart(10)} us${(tW / tIn).toFixed(2).padStart(7)}x`);
}

// Decode-one of a ~64 KiB frame — the inbound record path. A real masked frame, built
// by hand: [FIN|opcode 0x82][mask|len7 0xfe][u16 BE length][mask 4][payload …].
{
  const payloadLen = 65535;
  const frame = new Uint8Array(8 + payloadLen);
  frame[0] = 0x82; frame[1] = 0xfe; frame[2] = (payloadLen >>> 8) & 0xff; frame[3] = payloadLen & 0xff;
  frame.fill(0x5a, 4, 8); // mask
  frame.fill(0x33, 8);
  const dec = new Uint8Array(2 + frame.length);
  dec[0] = OP_DECODE_ONE; dec[1] = 1; dec.set(frame, 2); // expectMasked, whole frame
  const iters = 2000;
  const tIn = timeInThread(inst, [dec], iters);
  const tW = await timeWorker(modules, [dec], iters);
  console.log(`${"decode 64 KiB frame".padEnd(38)}${(tIn / iters * 1000).toFixed(1).padStart(10)} us${(tW / iters * 1000).toFixed(1).padStart(10)} us${(tW / tIn).toFixed(2).padStart(7)}x`);
}

// The one-time cost: stand a worker up (spawn + compile + instantiate), paid at bind
// and once more per kill-and-respawn (§4.3).
{
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < 10; i++) {
    const t = new ModuleTable();
    const built = await t.build([{ name: "ws", wasm }]);
    built.dispose();
  }
  console.log(`\nbind (worker spawn + compile): ${(Number(process.hrtime.bigint() - t0) / 1e6 / 10).toFixed(1)} ms/module`);
}
modules.dispose();
