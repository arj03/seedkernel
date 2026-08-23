# Writing a client on seedkernel

This repo is the **runtime**. Every app lives outside it and reaches the runtime only through the entry points in `WASM/package.json` `exports` — that list is the whole API, and a bare `seedkernel-wasm/*` specifier is the only way in. Two clients exist today and are the worked examples: **[seed store](https://github.com/arj03/seedstore)**, a p2p storage node with a Node CLI, a browser page and an offline bundle build, and **[seedchat](https://github.com/arj03/seedchat)**, a browser chat shell with consent-gated app install. Every file named below is in one of those two.

A client does three things, in this order: **author** the signed bundle that carries its app, **boot** a node and load it, and select the **platform adapters** for the target it runs on — which is how the tables are grouped.

### 1. Authoring — build and sign the bundle format (§12.4)

`authorBundle` (hash, assemble, validate, sign, pack — the blob, the manifest and the derived author id all come back on the value) and its mirror `verifyBundle` (unpack, verify, hash-check) are the one call each side, and the only two an app should make. `authorBundle` runs the same checks the verifier refuses, so an unverifiable bundle cannot be shipped, and the author id it returns is the id every consumer of your app pins. No runtime shell signs anything; a shell only verifies.

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `./bundle` | `authorBundle` at build time; `verifyBundle` wherever a blob arrives — a build reading back a prior version, a page reading a fetched `.skb`; `hybridAuthorKeysFromSeed` and `hybridAuthorId` for the author identity you pin, `genesisHash` for content ids, `moduleFile` for a module's name inside the container | authoring: seedstore `WASM/scripts/storage-bundle.mjs`, seedchat `scripts/build-app-bundle.mjs` — verifying: seedstore `WASM/browser/p2p.html` (reads the cohort's author off the staged `./seedstore.skb`), seedchat `browser/chat-shell.js` |

The module also carries the lower-level primitives that pair is built from. They stay exported for the runtime's own hardening tests and for a consumer that deliberately forges or tampers with a bundle to prove the verifier rejects it — not a path a client should take. Author with `authorBundle`, verify with `verifyBundle`.

### 2. Runtime — boot a node and drive the shell

`bootShell` is the ONE node-assembly (§12.9) and the one entry a client uses; everything else here is something you hand it or something it hands back.

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `./shell-core` | `bootShell` — the assembly. `AppHandle`, what a load hands back. `scopedFs`, to re-derive an app's fs view over a raw backend outside a running node. The admission constructors (`policyFromJson`, `admitAll`, `authorAllowlist`, `allOf`, …) are re-exported here too, so your `admit` comes from the same module | seedchat `browser/chat-shell.js` (a consent gate, and the `contactSecret` getter it passes as `transport` options), seedstore `WASM/host/storage-node.ts` (a whole node wrapped as a class) |
| `./shell` | The Node platform already assembled: `bootRuntime` wires `NodeFs` on a data directory, a `node:net` channel factory and a file-backed freshness store into `bootShell` for you, and hands back the shell and the channel adapter. A client that owns its own platform wiring skips this and calls `bootShell` | seedstore `WASM/tests/shell-run.test.mjs` |
| `./transport-bundle` | `transportBundleBytes()` — the shipped signed transport program, the blob that *is* the node's network. `bootShell` defaults to it; import it when you want to pass it explicitly, or to hash or inspect it | seedchat `browser/chat-shell.js` |
| `./guest-seam` | `appSigner` and `guestSignScope` for a host-side mirror of one slot's scoped sign/verify pair, so host code and guest code sign the same bytes | seedstore `WASM/host/manifest.ts` (the mirror) |

### 3. Platform adapters — the target-specific pieces you choose and hand to §2

A deliberate per-target choice (Node vs. browser, WS vs. RTC, memory-fs vs. node-fs), not internals leaking out.

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `.` (root) | Node's `loadCrypto` — sumo libsodium with ML-DSA-65 and ML-KEM-768 mixed in, read off disk. The `sodium` every other call takes | seedstore `WASM/host/sodium.ts`, `WASM/scripts/build-bundle.mjs` |
| `./crypto-browser` | The browser's `loadCrypto` — the same mix, fetched by URL onto a sumo instance you supply | seedstore `WASM/browser/index.html` and `p2p.html`, seedchat `browser/chat-shell.js` |
| `./libsodium` | That sumo instance: the runtime's own prebuilt browser libsodium. Do not ship a second one — this is the same binary the Go loader embeds | the three pages above |
| `./quickjs` | Nothing you call. It is the QuickJS engine `safe-js` names by bare specifier, so a **browser** client must carry it in its import map even though its own code never mentions it | the import map in seedstore `WASM/browser/p2p.html` |
| `./fs`, `./fs-memory`, `./fs-node` | The `Fs` interface, and the two backends: in-memory (`bootShell`'s default) or a directory on disk | seedstore `WASM/host/storage-node.ts`, `WASM/tests/bench-holder.mjs` |
| `./net-node` | `NodeChannelFactory` — TCP over `node:net`, plus the peer-spec parsers | seedstore `WASM/tests/net.test.mjs` |
| `./net-ws` | `WsNetwork` — dial known, natively-reachable nodes straight at their `--ws-listen` port; no relay, no STUN | seedstore `WASM/scripts/p2p-cli.mjs`, `WASM/browser/p2p.html` |
| `./net-rtc` | `RtcNetwork` and `relaySignaling` — WebRTC with a signaling rendezvous. Browser **and** Node | seedstore `WASM/browser/p2p.html`, seedchat `browser/media-rtc.js` (subclassed for audio/video) |
| `./net-rtc-node` | `weriftPeerConnectionFactory` — the peer-connection implementation that lets `RtcNetwork` run on the console | seedstore `WASM/scripts/serve-rtc-holder.mjs` |

**The WebRTC seam is the runtime's, not any one app's.** seed store drives `RtcNetwork` from a browser page *and* from the console over werift; seedchat subclasses it to carry live media. Treat it as a first-class adapter on either target, and subclass it rather than fork it when you need more than raw bytes.

**`loadCrypto` has a Node build and a browser build, not one shared function.** Node's (`.`) pulls the npm package and reads both PQ `.wasm` files off disk; the browser's (`./crypto-browser`) fetches them by URL onto a caller-supplied sumo instance instead. A browser client takes that instance from `./libsodium` and should not ship a second sumo build. `./pq` and `./kem` are internal — both `loadCrypto`s reach them relatively, and an app gets their primitives through the capability catalog, never by importing them.

## The assembly is an export

`bootShell` (`./shell-core`) is the ONE node-assembly (§12.9), and entering it is how a client gets a node that is correct by construction. Every field but `sodium` and `identity` has a default — the module table, an in-memory fs and freshness store, a lazily-imported safe-js realm factory — so you state only what you genuinely own. One default is a decision rather than a convenience: `admit` absent is **deny-all** — the node boots and serves but installs nothing, the transport bundle included, so a client that states no gate has no network. All four targets enter here (Node, browser, the native loader, seed store) and differ only in which defaults they displace.

Two things it does *for* you, which is why you should not try to reproduce them:

- **The transport author pin is ANDed onto your predicate, never substituted for it.** The transport bundle is admitted under a pin derived from the blob itself, so "only this author may be the network" is the assembly's business, not something you can lose by forgetting it. Your `admit` still has to admit as well — a deny-all node has no network, and an operator keeps the power to refuse a transport author, because AND means both. Running a different transport means passing a different `transportBundle`, which is what the pin is derived from.
- **It is fail-closed on a privilege it does not know.** `PRIVILEGES` is derived from the capability catalog, so a privileged name added to `core/domains.ts` appears here as a privilege with no branch, and bundles reaching it are refused until the assembly is taught about it. That is what makes "privileged bundles are the pin's business" a safe thing for your consent dialog to assume.

A load returns an **`AppHandle`**: the app key, the app's fs scope and the scoped view over it, and an `invoke` already bound to that slot — so you drive the app through derivations the shell has already made. Take the handle; do not re-derive its parts.

The handle's `invoke` is bound to the slot this load stood, while `Shell.invoke(op, payload, appKey)` re-resolves the key. The difference shows up on an upgrade: a replacement load stands a NEW slot under the same key, so a handle taken before it keeps naming the version it was handed and rejects once that slot is disposed. Drive an app you just loaded through its handle; hold the key and call `Shell.invoke` when you mean whatever is installed under that identity now. The key is always stated — a node hosts unrelated apps, so there is no "the only loaded app" to default to.

## One reach that is not an export

It is real and both clients use it, and it cannot be an entry point — so `files` is what keeps it working: `build`, `build-min`, `browser`, `quickjs/dist`, `native/host-shell.gen.js`.

- `seedkernel-wasm/build-min/**` — the minified browser host, vendored into a web root by both clients (seedstore `WASM/scripts/build-browser-demo.mjs`, seedchat `scripts/vendor.mjs`). This is a dependency on *output*: `build-min` is gitignored, so a checkout of this repo that has never run `npm run build:host:min` stages nothing.

## Two traps a browser client hits

- **Bare specifiers resolve through a hand-written import map, and Node cannot tell you it is wrong.** Node finds `seedkernel-wasm/*` through `node_modules`; a browser page finds it only through `<script type="importmap">`. So an entry point your *host* code starts importing is invisibly missing from your *pages* until one is loaded — your Node suite stays green throughout. Map only what your graph actually names: `bootShell` pulls its module table and its safe-js realm in by relative import, so neither needs an entry, while `safe-js.js` names `seedkernel-wasm/quickjs` and does. seedstore's `WASM/scripts/build-browser-demo.mjs` walks each page's real module graph at stage time and exits non-zero on an unmapped specifier — worth copying.
- **A stale `build-min` is the easiest cross-repo breakage to miss.** The browser runs the minified tree; Node tests run `build/`. When `build:host` reruns and `build:host:min` does not, the two diverge silently: tests pass against fresh code while the page serves old code. Anything you ship to a browser needs `npm run build:host:min` here to be current, and a staging step is the right place to assert it (seedstore's does, for both repos).

Both clients vendor the built host into their own web root and resolve `seedkernel-wasm/*` from there — see `WASM/browser/p2p.html` in seed store or `browser/chat-shell.html` in seedchat for a map to start from.
