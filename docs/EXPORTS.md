# The public surface (and who consumes it)

This repo is the runtime only. Every app lives outside it and reaches the runtime through the entry points in `WASM/package.json` `exports` — so **an export with no in-repo caller is not dead code**, it is surface some other repo depends on. Check this table before deleting or moving anything below.

| Entry point | [seed store](https://github.com/arj03/seedstore) | [seedchat](https://github.com/arj03/seedchat) |
| --- | :---: | :---: |
| `.` (Node host) | ✓ | |
| `./browser` | ✓ | |
| `./shell`, `./shell-core` | ✓ | `shell-core` |
| `./bundle` | ✓ | ✓ |
| `./cap-bridge` | ✓ | |
| `./safe-js` | ✓ | |
| `./fs`, `./fs-node` | ✓ | |
| `./net`, `./net-node`, `./net-ws` | ✓ | |
| `./net-rtc` | ✓ (browser **and** console) | ✓ |
| `./net-rtc-node` | ✓ | |
| `./libsodium` | | ✓ |
| `./libsodium-core`, `./libsodium.wasm` | *(no direct importer — `libsodium-wrappers.mjs` resolves both relative to its own URL, so all three must stay in one directory)* | |
| `./ws` | | |

One consumer reaches something that is **not** an export: seedchat's WASM modules import `seedkernel-wasm/assembly/seedkernel/handler` — the guest half of the handler ABI (§4). AssemblyScript resolves that straight off the filesystem under `node_modules`, bypassing `exports` entirely, so it works today only because `package.json` has no `files` field and `assembly/` is not gitignored. **Adding a `files` field without including `assembly/` would silently break every app's build.** Nothing inside this repo imports that file either, so it looks like an orphan from in here and is not.

Two traps this table exists to prevent:

- **WebRTC is not chat's.** `host/net-rtc.ts` and `host/net-rtc-node.ts` are neither shared-logic (they are absent from the `build:loader-bundles` list) nor app-specific. seed store drives `RtcNetwork` from the browser (`p2p.html:136`) *and* from the console over werift (`serve-rtc-holder.mjs`, `smoke-rtc.mjs`), so both files outlive any one app.
- **`loadSodium` is Node-only.** It lives in `host/node.ts` and pulls the npm package, so it is not reachable from a browser page. Browsers take `./libsodium` instead. seed store currently sources its browser libsodium from a CDN, which predates that export and could now move in-repo.

Apps vendor the built host into their own web root and resolve `seedkernel-wasm/*` through an import map — see `p2p.html` in seed store or `chat-shell.html` in seedchat. Anything shipped to a browser therefore needs `npm run build:host:min` to be current; a stale `build/host-min` is the easiest cross-repo breakage to miss.
