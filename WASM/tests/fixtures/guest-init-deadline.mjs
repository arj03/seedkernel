import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const wasmRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const { createWebRealm } = await import(pathToFileURL(join(wasmRoot, "build/host/engine-web.js")).href);

try {
  await createWebRealm({
    source: "for (;;) {}",
    hostCall: async () => new Uint8Array(),
    deadlineMs: 100,
  });
  console.error("top-level guest loop unexpectedly completed");
  process.exitCode = 2;
} catch {
  // Expected: construction itself is budgeted.
}
