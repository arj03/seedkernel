// Bun standalone entry for the seedkernel-shell. Identical node logic as main.ts,
// but the two genesis modules are embedded into the compiled binary (wasm-bun.ts)
// instead of read from a build dir, so `bun build --compile` yields a
// self-contained runtime.
//
//   bun build host/main-bun.ts --compile --outfile seedkernel-shell
//   ./seedkernel-shell --policy ./allowed-keys.json --dir ./data --listen 0.0.0.0:7000

import { main } from "./main.js";
import { loadKernelWasmEmbedded } from "./wasm-bun.js";

main(loadKernelWasmEmbedded).catch((e) => { console.error(e); process.exit(1); });
