import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const wasmRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const { createWebRealm } = await import(pathToFileURL(join(wasmRoot, "build/host/engine-web.js")).href);

// The guest swaps every preamble entry point for a getter that never returns. Read after
// the guest ran, one would spin outside the budget and hold this process forever.
const realm = await createWebRealm({
  source: `
    for (const name of ["__start", "__settleHostCall"])
      Object.defineProperty(globalThis, name, { get() { for (;;) {} } });
    async function handle(arg) {
      try { return await host.call(arg[0] === 1 ? "fail" : "park", new Uint8Array()); }
      catch { return new Uint8Array([8]); }
    }`,
  hostCall: (name) => name === "fail" ? Promise.reject(new Error("refused")) : Promise.resolve(new Uint8Array([7])),
  deadlineMs: 300,
});
const answers = [(await realm.call(new Uint8Array([0])))[0], (await realm.call(new Uint8Array([1])))[0]];
realm.dispose();
if (answers[0] !== 7 || answers[1] !== 8) {
  console.error(`parked calls settled wrongly: ${answers}`);
  process.exitCode = 2;
}
