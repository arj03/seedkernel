# The public surface (and who consumes it)

This repo is the runtime only. Every app lives outside it and reaches the runtime through the entry points in `WASM/package.json` `exports` — so **an export with no in-repo caller is not dead code**, it is surface some other repo depends on. Check this table before deleting or moving anything below.

| Entry point | [seed store](https://github.com/arj03/seedstore) | [seedchat](https://github.com/arj03/seedchat) |
| --- | :---: | :---: |
| `.` (Node host) | ✓ | ✓ |
| `./shell`, `./shell-core` | ✓ | `shell-core` |
| `./bundle` | ✓ | ✓ |
| `./guest-seam` | ✓ | |
| `./safe-js` | ✓ | ✓ |
| `./transport-host` | ✓ | |
| `./transport-bundle` | ✓ | ✓ |
| `./fs`, `./fs-memory`, `./fs-node` | ✓ | |
| `./net-node`, `./net-ws` | ✓ | |
| `./net-rtc` | ✓ (browser **and** console) | ✓ |
| `./net-rtc-node` | ✓ | |
| `./pq` | ✓ | ✓ |
| `./libsodium` | ✓ | ✓ |
| `./libsodium-core`, `./libsodium.wasm` | *(no direct importer — `libsodium-wrappers.mjs` resolves both relative to its own URL, so all three must stay in one directory, and a consumer staging one into a web root stages all three)* | |

**Two things are reached that are not exports at all**, both by resolving a path straight off the filesystem under `node_modules` and bypassing `exports` entirely. Both work only because `package.json` has no `files` field, and **adding one without listing these would silently break the consumer's build**:

- `seedkernel-wasm/assembly/seedkernel/handler` — the guest half of the module ABI (§4), imported by seedchat's WASM modules and resolved by AssemblyScript. Nothing inside this repo imports that file either, so it looks like an orphan from in here and is not.
- `seedkernel-wasm/build/transport.skb` — the built transport bundle, read by `seedchat/scripts/smoke.mjs`. Sharper than the first: `build/` is gitignored, so this is a dependency on *output*, and a consumer that has never run `npm run build:transport-bundle` in this repo finds nothing there.

Two traps this table exists to prevent:

- **WebRTC is not chat's.** `host/net-rtc.ts` and `host/net-rtc-node.ts` are neither shared-logic (they are absent from the `build:loader-bundles` list) nor app-specific. seed store drives `RtcNetwork` from the browser (`WASM/browser/p2p.html`) *and* from the console over werift (`WASM/scripts/serve-rtc-holder.mjs`, `smoke-rtc.mjs`), so both files outlive any one app.
- **`loadCrypto` is Node-only.** It lives in `host/crypto-node.ts` and pulls the npm package, so it is not reachable from a browser page — it is the whole reason both consumers import the bare `.` entry, and each does so only from a Node script. Browsers take `./libsodium`, both consumers do, and neither should ship a second sumo build: that export is the *same artifact* the Go loader embeds, so one crypto binary serves all three targets.
- **A browser consumer resolves these through an import map, and Node cannot tell you it is wrong.** Every `seedkernel-wasm/*` above is a bare specifier: Node finds it through `node_modules`, a browser page only through a hand-written `<script type="importmap">`. So an export that a consumer's *host* code starts importing is invisibly missing from its *pages* until one is loaded — the Node suite stays green throughout. `./fs-memory` broke seed store's demo exactly that way. Seed store's `scripts/build-browser-demo.mjs` now walks each page's module graph at stage time and fails on an unmapped specifier; adding an export here is a good moment to check the consumer's map.

Apps vendor the built host into their own web root and resolve `seedkernel-wasm/*` through an import map — see `WASM/browser/p2p.html` in seed store or `browser/chat-shell.html` in seedchat. Anything shipped to a browser therefore needs `npm run build:host:min` to be current; a stale `build-min` is the easiest cross-repo breakage to miss.
