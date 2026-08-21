# The public surface (and who consumes it)

This repo is the runtime only. Every app lives outside it and reaches the runtime through the entry points in `WASM/package.json` `exports` — so **an export with no in-repo caller is not dead code**, it is surface some other repo depends on. Check this table before deleting or moving anything below.

| Entry point | [seed store](https://github.com/arj03/seedstore) | [seedchat](https://github.com/arj03/seedchat) |
| --- | :---: | :---: |
| `.` (Node host) | ✓ (`loadSodium` — the ML-DSA-mixed `loadCrypto`) | ✓ (`smoke.mjs`'s `loadCrypto`) |
| `./shell` | ✓ (`boot`/`bootRuntime`, the shell-run tests) | |
| `./shell-core` | ✓ `bootShell`, `AppHandle`, `scopedFs` (storage-node, net.test) | ✓ `bootShell` (chat-shell, smoke) |
| `./bundle` | ✓ (build-bundle, storage-bundle, tests, `verifyManifest` in p2p.html) | ✓ (chat-shell **authors and signs bundles at runtime**: `signManifest`, `packBundle`, `hybridAuthorKeysFromSeed`; smoke) |
| `./guest-seam` | ✓ `appSigner`/`guestSignScope` (manifest.ts), `GUEST_ABI_VERSION` (storage-bundle) | ✓ `GUEST_ABI_VERSION` (chat-shell, smoke, chat-app) |
| `./safe-js` | ✓ (import maps; bootShell's default realm factory) | ✓ (chat-shell passes `createSafeRealm`; import map) |
| `./transport-host` | ✓ (`StorageNode` type, import maps, the RTC/WS drivers) | ✓ (chat-shell constructs the adapter instance; smoke) |
| `./transport-bundle` | ✓ `transportBundleBytes` (holder-guest, shell-run tests) | ✓ `transportBundleBytes` (chat-shell, smoke) |
| `./module-table` | ✓ (import maps — bootShell's default module builder) | ✓ (import map only) |
| `./quickjs` | ✓ (import maps + the browser-demo staging) | ✓ (import map) |
| `./fs`, `./fs-memory`, `./fs-node` | ✓ | |
| `./net-node`, `./net-ws` | ✓ | |
| `./net-rtc` | ✓ (browser **and** console) | ✓ (`media-rtc.js`'s `RtcNetwork`) |
| `./net-rtc-node` | ✓ | |
| `./pq` | ✓ (p2p.html's `withMlDsa65`) | ✓ (chat-shell's `withMlDsa65`/`loadMlDsa65` — the browser's substitute for Node's `loadCrypto`) |
| `./libsodium` | ✓ | ✓ |
| `./libsodium-core`, `./libsodium.wasm` | *(no direct importer — `libsodium-wrappers.mjs` resolves both relative to its own URL, so all three must stay in one directory, and a consumer staging one into a web root stages all three)* | |

**The assembly is an export.** `bootShell` (`./shell-core`) is the ONE node-assembly (§12.9): platform members defaulted (module-table, an in-memory fs and freshness store, lazy safe-js), the channel adapter built from options or accepted as an instance, the transport bundle admitted under an **implicit author pin** derived from the blob itself — so the pin and the load order are the assembly's, not a consumer's to restate. All four targets enter here — Node, browser, native loader, seed store — and differ only in which defaults they displace; `createShell` underneath is the wired shell without the assembly, which in practice only this repo's tests drive. A load returns an **`AppHandle`** — the app key, the app's fs scope and the scoped view over it, and a bound `invoke` — so a caller drives the slot through the derivations shell-core already made. `appSigner` (`./guest-seam`) is one slot's scoped sign/verify pair for a host-side mirror; `transportBundleBytes` (`./transport-bundle`) is the shipped transport artifact as bytes.

The pin is ANDed onto the caller's predicate, never substituted for it: an operator's `policyFromJson` still has to admit, so a deny-all node has no network, and a consent dialog that admits anything privileged defers to the pin rather than waving it through. That makes an operator's `grants.link` a veto over the blob the node booted rather than an appointment — running a different transport means passing a different `transportBundle`, which is what the pin is derived from. The pin is **fail-closed on a privilege it does not know** — `PRIVILEGES` is derived from the capability catalog, so a privileged name added to `core/domains.ts` appears here as a privilege with no branch and its bundles are refused until the assembly is taught about it. That is what makes "privileged bundles are the pin's business" safe for a consumer to write, and it is the one place a new privilege is taught.

**Two reaches are not exports and cannot be**, so `files` is what keeps them working: `build`, `build-min`, `browser`, `quickjs/dist`, `assembly/seedkernel`, `guest-handler.ts`, `native/host-shell.gen.js`. **Before adding an export, check the file it points at is covered; before adding a path a consumer reads off disk, add it to `files` in the same change.**

- `seedkernel-wasm/guest-handler` — the guest half of the module ABI (§4), imported by chat's AssemblyScript. asc (0.28) resolves a bare specifier by joining the subpath and ignores `exports` entirely, so an entry point cannot serve it: what serves it is the root-level `guest-handler.ts` shim, shipped under `files`. There is no `./guest-handler` export — an entry changes nothing for asc, and hands a JS consumer a subpath resolving to `i32`-typed source it cannot parse.
- `seedkernel-wasm/build-min/**` — the minified host, vendored into a web root by *both* consumers (`seedstore/WASM/scripts/build-browser-demo.mjs`, `seedchat/scripts/vendor.mjs`). A dependency on *output*: `build-min` is gitignored, so a consumer that has never run `npm run build:host:min` in this repo stages nothing.

Three traps this table exists to prevent:

- **WebRTC is not chat's.** `host/net-rtc.ts` and `host/net-rtc-node.ts` are neither shared-logic (they are absent from the `build:loader-bundles` list) nor app-specific. seed store drives `RtcNetwork` from the browser (`WASM/browser/p2p.html`) *and* from the console over werift (`WASM/scripts/serve-rtc-holder.mjs`, `smoke-rtc.mjs`), so both files outlive any one app.
- **`loadCrypto` is Node-only.** It lives in `host/crypto-node.ts` and pulls the npm package, so it is not reachable from a browser page — it is the whole reason both consumers import the bare `.` entry, and each does so only from a Node script. Browsers take `./libsodium`, both consumers do, and neither should ship a second sumo build: that export is the *same artifact* the Go loader embeds, so one crypto binary serves all three targets. Browsers take `./pq` for the ML-DSA-65 half of the same story.
- **A browser consumer resolves these through an import map, and Node cannot tell you it is wrong.** Every `seedkernel-wasm/*` above is a bare specifier: Node finds it through `node_modules`, a browser page only through a hand-written `<script type="importmap">`. So an export that a consumer's *host* code starts importing is invisibly missing from its *pages* until one is loaded — the Node suite stays green throughout. Seed store's `scripts/build-browser-demo.mjs` walks each page's module graph at stage time and fails on an unmapped specifier; adding an export here is a good moment to check the consumer's map.

Apps vendor the built host into their own web root and resolve `seedkernel-wasm/*` through an import map — see `WASM/browser/p2p.html` in seed store or `browser/chat-shell.html` in seedchat. Anything shipped to a browser therefore needs `npm run build:host:min` to be current; a stale `build-min` is the easiest cross-repo breakage to miss.
