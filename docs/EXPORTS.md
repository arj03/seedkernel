# The public surface (and who consumes it)

This repo is the runtime only. Every app lives outside it and reaches the runtime through the entry points in `WASM/package.json` `exports` — so **an export with no in-repo caller is not dead code**, it is surface some other repo depends on. Check this table before deleting or moving anything below.

| Entry point | [seed store](https://github.com/arj03/seedstore) | [seedchat](https://github.com/arj03/seedchat) |
| --- | :---: | :---: |
| `.` (Node host) | ✓ | ✓ |
| `./shell`, `./shell-core` | ✓ | `shell-core` |
| `./bundle` | ✓ | ✓ |
| `./cap-bridge` | ✓ | |
| `./safe-js` | ✓ | ✓ |
| `./transport-host` | ✓ | |
| `./transport-bundle` | ✓ | ✓ |
| `./fs`, `./fs-node` | ✓ | |
| `./net`, `./net-node`, `./net-ws` | ✓ | |
| `./net-rtc` | ✓ (browser **and** console) | ✓ |
| `./net-rtc-node` | ✓ | |
| `./pq` | ✓ | ✓ |
| `./libsodium` | | ✓ |
| `./libsodium-core`, `./libsodium.wasm` | *(no direct importer — `libsodium-wrappers.mjs` resolves both relative to its own URL, so all three must stay in one directory)* | |

**Two things are reached that are not exports at all**, both by resolving a path straight off the filesystem under `node_modules` and bypassing `exports` entirely. Both work only because `package.json` has no `files` field, and **adding one without listing these would silently break the consumer's build**:

- `seedkernel-wasm/assembly/seedkernel/handler` — the guest half of the handler ABI (§4), imported by seedchat's WASM modules and resolved by AssemblyScript. Nothing inside this repo imports that file either, so it looks like an orphan from in here and is not.
- `seedkernel-wasm/build/transport.skb` — the built transport bundle, read by `seedchat/scripts/smoke.mjs`. Sharper than the first: `build/` is gitignored, so this is a dependency on *output*, and a consumer that has never run `npm run build:transport-bundle` in this repo finds nothing there.

Two traps this table exists to prevent:

- **WebRTC is not chat's.** `host/net-rtc.ts` and `host/net-rtc-node.ts` are neither shared-logic (they are absent from the `build:loader-bundles` list) nor app-specific. seed store drives `RtcNetwork` from the browser (`WASM/browser/p2p.html`) *and* from the console over werift (`WASM/scripts/serve-rtc-holder.mjs`, `smoke-rtc.mjs`), so both files outlive any one app.
- **`loadSodium` is Node-only.** It lives in `host/node.ts` and pulls the npm package, so it is not reachable from a browser page — it is the whole reason both consumers import the bare `.` entry, and each does so only from a Node script. Browsers take `./libsodium` instead, which seedchat does and seed store does not: seed store vendors its own copy under `WASM/browser/vendor/`, so the two consumers answer the same question differently.

Apps vendor the built host into their own web root and resolve `seedkernel-wasm/*` through an import map — see `WASM/browser/p2p.html` in seed store or `browser/chat-shell.html` in seedchat. Anything shipped to a browser therefore needs `npm run build:host:min` to be current; a stale `build-min` is the easiest cross-repo breakage to miss.
