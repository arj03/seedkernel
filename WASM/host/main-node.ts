// Node CLI entry for the seedkernel-shell — the explicit twin of main-bun.ts,
// so main.ts stays a pure library module with no argv-sniffing auto-run guard.
//
//   node build/host/main-node.js --policy ./allowed-keys.json --dir ./data \
//        --listen 0.0.0.0:7000

import { main } from "./main.js";

main().catch((e) => { console.error(e); process.exit(1); });
