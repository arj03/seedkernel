// The §4.3 module-call path, measured like the native target's bound: the same workload
// with and without the interrupt mechanism, as a ratio. The native cost (§14.1) is
// multiplicative (a termination check per loop: 2.8x RS encode, 4.8x decode, 2.6x
// XChaCha20, 1.65x Ed25519); the JS worker model's is additive, one fixed isolate round
// trip per call, measured here on ws.wasm. Run after `npm run build`.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);
const { ModuleTable } = await imp("build/host/module-table.js");

const wasm = new Uint8Array(readFileSync(join(root, "build/ws.wasm")));
const OP_MASK = 1;

/** A masking request for one masked binary frame, built once per size: [op][frame], the
 *  frame's header in its shortest length form. */
const frameReq = (payloadLen) => {
  const ext = payloadLen < 126 ? 0 : payloadLen < 65536 ? 2 : 8;
  const req = new Uint8Array(1 + 2 + ext + 4 + payloadLen);
  req[0] = OP_MASK;
  req[1] = 0x82;
  req[2] = 0x80 | (ext === 0 ? payloadLen : ext === 2 ? 126 : 127);
  if (ext === 2) { req[3] = payloadLen >>> 8; req[4] = payloadLen & 0xff; }
  else if (ext === 8) new DataView(req.buffer).setUint32(7, payloadLen);
  req.fill(0x5a, 3 + ext, 7 + ext); // the key
  req.fill(0x33, 7 + ext);
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
    if (r.bytes === null || r.bytes.length === 0) throw new Error("ws: module error");
  }
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

const mod = new WebAssembly.Module(wasm);
const inst = new WebAssembly.Instance(mod, { env: { abort: () => {}, seed: () => 0, trace: () => {} } });
const table = new ModuleTable({ deadlineMs: 60_000 });
const modules = await table.build([{ name: "ws", wasm }]);

console.log("module-call cost, in-thread vs worker-per-module — ws.wasm (RFC 6455 masking)\n");
console.log(`${"workload".padEnd(38)}${"in-thread".padStart(12)}${"worker".padStart(12)}${"ratio".padStart(8)}`);
console.log("-".repeat(70));

for (const [name, payloadLen, iters] of [
  ["mask 64 KiB frame", 64 * 1024, 2000],
  ["mask 1 KiB frame", 1024, 5000],
  ["mask 32 B frame", 32, 20000],
]) {
  const reqs = [frameReq(payloadLen)];
  const tIn = timeInThread(inst, reqs, iters);
  const tW = await timeWorker(modules, reqs, iters);
  console.log(`${name.padEnd(38)}${(tIn / iters * 1000).toFixed(1).padStart(10)} us${(tW / iters * 1000).toFixed(1).padStart(10)} us${(tW / tIn).toFixed(2).padStart(7)}x`);
}

// The one-time cost of starting a worker (spawn, compile, instantiate), paid at install
// and again per kill and respawn (§4.3).
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
