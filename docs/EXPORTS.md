# The public surface (and who consumes it)

This repo is the runtime only. Every app lives outside it and reaches the runtime through the entry points in `WASM/package.json` `exports`, grouped below into three: an **authoring API** (build and sign the bundle format), a **runtime API** (boot a node and drive the shell), and **platform adapters** (the target-specific pieces a caller selects and hands to the runtime API) — so **an export with no in-repo caller is not dead code**, it is surface some other repo depends on. Check these tables before deleting or moving anything below.

### Authoring API

Building, signing, packing, and verifying the app-bundle format (§12.4). `authorBundle` (hash, assemble, sign, pack) and its mirror `verifyBundle` (unpack, verify, hash-check) are the one call each side should make — both apps' offline builds author with it now, and no runtime shell signs anything, only verifies. `verifyManifest` stays exported for `p2p.html`, which fetches a bare envelope with no container to unpack. The remaining lower-level primitives stay exported for seedkernel's own hardening tests and seedchat's `smoke.mjs`, which deliberately reach below the typed wrapper — not the path an external consumer should use.

| Entry point | [seed store](https://github.com/arj03/seedstore) | [seedchat](https://github.com/arj03/seedchat) |
| --- | :---: | :---: |
| `./bundle` | ✓ (`authorBundle` in build-bundle/storage-bundle, `verifyBundle` in build-bundle reading back a prior version, `verifyManifest` in p2p.html — see above, tests reach the lower-level primitives directly) | ✓ (`authorBundle` in `scripts/build-app-bundle.mjs`, `verifyBundle` in chat-shell's `peekMeta`, `hybridAuthorId`/`hybridAuthorKeysFromSeed` for message identity, smoke signs directly with `signManifest`/`packBundle` to exercise those primitives) |

### Runtime API

Booting a node and driving the shell — the ONE node-assembly (§12.9) described below.

| Entry point | [seed store](https://github.com/arj03/seedstore) | [seedchat](https://github.com/arj03/seedchat) |
| --- | :---: | :---: |
| `./shell` | ✓ (`boot`/`bootRuntime`, the shell-run tests) | |
| `./shell-core` | ✓ `bootShell`, `AppHandle`, `scopedFs` (storage-node, net.test) | ✓ `bootShell` (chat-shell, smoke) |
| `./guest-seam` | ✓ `appSigner`/`guestSignScope` (manifest.ts), `GUEST_ABI_VERSION` (storage-bundle) | ✓ `GUEST_ABI_VERSION` (chat-shell, smoke, chat-app) |
| `./transport-bundle` | ✓ `transportBundleBytes` (holder-guest, shell-run tests) | ✓ `transportBundleBytes` (chat-shell, smoke) |
| `./transport-host` | ✓ (`StorageNode` type, import maps, the RTC/WS drivers) | ✓ (chat-shell constructs the adapter instance; smoke) |
| `./module-table` | ✓ (import maps — bootShell's default module builder) | ✓ (import map only) |

`GUEST_ABI_VERSION` straddles both groups — an author declares it in `guest.abi` when signing a manifest, and the shell checks it at load — but it names the *runtime* seam's version, so it lives here rather than in the authoring API.

### Platform adapters

Target-specific implementations a caller selects and hands to the runtime API above — a deliberate per-target choice (Node vs. browser, WS vs. RTC, memory-fs vs. node-fs), not internals leaking out.

| Entry point | [seed store](https://github.com/arj03/seedstore) | [seedchat](https://github.com/arj03/seedchat) |
| --- | :---: | :---: |
| `.` (Node host) | ✓ (`loadSodium` — the ML-DSA-mixed `loadCrypto`) | ✓ (`smoke.mjs`'s `loadCrypto`) |
| `./safe-js` | ✓ (import maps; bootShell's default realm factory) | ✓ (chat-shell passes `createSafeRealm`; import map) |
| `./quickjs` | ✓ (import maps + the browser-demo staging) | ✓ (import map) |
| `./fs`, `./fs-memory`, `./fs-node` | ✓ | |
| `./net-node`, `./net-ws` | ✓ | |
| `./net-rtc` | ✓ (browser **and** console) | ✓ (`media-rtc.js`'s `RtcNetwork`) |
| `./net-rtc-node` | ✓ | |
| `./crypto-browser` | ✓ (`index.html`, `p2p.html` — both call `loadCrypto` directly) | ✓ (chat-shell's `loadCrypto`) |
| `./libsodium` | ✓ | ✓ |
| `./libsodium-core`, `./libsodium.wasm` | *(no direct importer — `libsodium-wrappers.mjs` resolves both relative to its own URL, so all three must stay in one directory, and a consumer staging one into a web root stages all three)* | |

**The assembly is an export.** `bootShell` (`./shell-core`) is the ONE node-assembly (§12.9): platform members defaulted (module-table, an in-memory fs and freshness store, lazy safe-js), the channel adapter built from options or accepted as an instance, the transport bundle admitted under an **implicit author pin** derived from the blob itself — so the pin and the load order are the assembly's, not a consumer's to restate. All four targets enter here — Node, browser, native loader, seed store — and differ only in which defaults they displace; `createShell` underneath is the wired shell without the assembly, which in practice only this repo's tests drive. A load returns an **`AppHandle`** — the app key, the app's fs scope and the scoped view over it, and a bound `invoke` — so a caller drives the slot through the derivations shell-core already made. `appSigner` (`./guest-seam`) is one slot's scoped sign/verify pair for a host-side mirror; `transportBundleBytes` (`./transport-bundle`) is the shipped transport artifact as bytes.

The pin is ANDed onto the caller's predicate, never substituted for it: an operator's `policyFromJson` still has to admit, so a deny-all node has no network, and a consent dialog that admits anything privileged defers to the pin rather than waving it through. That makes an operator's `grants.link` a veto over the blob the node booted rather than an appointment — running a different transport means passing a different `transportBundle`, which is what the pin is derived from. The pin is **fail-closed on a privilege it does not know** — `PRIVILEGES` is derived from the capability catalog, so a privileged name added to `core/domains.ts` appears here as a privilege with no branch and its bundles are refused until the assembly is taught about it. That is what makes "privileged bundles are the pin's business" safe for a consumer to write, and it is the one place a new privilege is taught.

**Two reaches are not exports and cannot be**, so `files` is what keeps them working: `build`, `build-min`, `browser`, `quickjs/dist`, `assembly/seedkernel`, `guest-handler.ts`, `native/host-shell.gen.js`. **Before adding an export, check the file it points at is covered; before adding a path a consumer reads off disk, add it to `files` in the same change.**

- `seedkernel-wasm/guest-handler` — the guest half of the module ABI (§4), imported by chat's AssemblyScript. asc (0.28) resolves a bare specifier by joining the subpath and ignores `exports` entirely, so an entry point cannot serve it: what serves it is the root-level `guest-handler.ts` shim, shipped under `files`. There is no `./guest-handler` export — an entry changes nothing for asc, and hands a JS consumer a subpath resolving to `i32`-typed source it cannot parse.
- `seedkernel-wasm/build-min/**` — the minified host, vendored into a web root by *both* consumers (`seedstore/WASM/scripts/build-browser-demo.mjs`, `seedchat/scripts/vendor.mjs`). A dependency on *output*: `build-min` is gitignored, so a consumer that has never run `npm run build:host:min` in this repo stages nothing.

Three traps this table exists to prevent:

- **WebRTC is not chat's.** `host/net-rtc.ts` and `host/net-rtc-node.ts` are neither shared-logic (they are absent from the `build:loader-bundles` list) nor app-specific. seed store drives `RtcNetwork` from the browser (`WASM/browser/p2p.html`) *and* from the console over werift (`WASM/scripts/serve-rtc-holder.mjs`, `smoke-rtc.mjs`), so both files outlive any one app.
- **`loadCrypto` has a Node build and a browser build, not one shared function.** Node's (`.` / `host/crypto-node.ts`) pulls the npm package and reads both `.wasm` files off disk; the browser's (`./crypto-browser` / `host/crypto-browser.ts`) fetches them by URL onto a caller-supplied sumo instance instead. Browsers take `./libsodium`, both consumers do, and neither should ship a second sumo build: that export is the *same artifact* the Go loader embeds, so one crypto binary serves all three targets. `./pq` and `./kem` are internal-only now — both `loadCrypto`s import them by relative path.
- **A browser consumer resolves these through an import map, and Node cannot tell you it is wrong.** Every `seedkernel-wasm/*` above is a bare specifier: Node finds it through `node_modules`, a browser page only through a hand-written `<script type="importmap">`. So an export that a consumer's *host* code starts importing is invisibly missing from its *pages* until one is loaded — the Node suite stays green throughout. Seed store's `scripts/build-browser-demo.mjs` walks each page's module graph at stage time and fails on an unmapped specifier; adding an export here is a good moment to check the consumer's map.

Apps vendor the built host into their own web root and resolve `seedkernel-wasm/*` through an import map — see `WASM/browser/p2p.html` in seed store or `browser/chat-shell.html` in seedchat. Anything shipped to a browser therefore needs `npm run build:host:min` to be current; a stale `build-min` is the easiest cross-repo breakage to miss.
