# Writing a client on Seedkernel

This repo is the **runtime**. Every app lives outside it and reaches the runtime only through the entry points in [`WASM/package.json`](../WASM/package.json) `exports`; a bare `seedkernel-wasm` or `seedkernel-wasm/*` specifier is the only supported way in. Two clients exist today and are the worked examples: **[seed store](https://github.com/arj03/seedstore)**, a P2P storage node with a Node CLI, a browser page and an offline bundle build, and **[seedchat](https://github.com/arj03/seedchat)**, a browser chat shell with consent-gated app installation.

This is a task-oriented guide to the client-facing surface, not a symbol-by-symbol reference. The export map is the API boundary, and the generated `.d.ts` file behind each entry point is the exhaustive contract. The tables below name the calls a normal client is expected to use.

A client has two flows. Offline, it **authors** the signed bundle that carries its app. At runtime, it selects its **platform adapters while booting** a node, then loads and invokes the bundle. The sections follow that order.

## Use the package from a sibling checkout

`seedkernel-wasm` is currently a private package, so both example clients consume it as a local file dependency. With the repositories checked out beside one another, add this to the client's `package.json`:

```json
{
  "dependencies": {
    "seedkernel-wasm": "file:../seedkernel/WASM"
  }
}
```

Build the runtime before installing or staging the client:

```sh
cd ../seedkernel/WASM
npm install
npm run build

cd ../../your-client
npm install
```

The browser artifacts require the additional `npm run build:browser` build described in the [main README](../README.md#build-variants-and-client-api).

## 1. Authoring — build and sign the bundle format (§12.4)

`authorBundle` (hash, assemble, validate, sign, pack — the blob, the manifest and the derived author id all come back on the value) and its mirror `verifyBundle` (unpack, verify, hash-check) are the one call each side, and the only two an app should make. `authorBundle` runs the same checks the verifier refuses, so an unverifiable bundle cannot be shipped, and the author id it returns is the id every consumer of your app pins. No runtime shell signs anything; a shell only verifies.

A minimal authoring function looks like this. `authorSeed` is a persisted 32-byte secret; do not generate a new one for each release, because it determines the author id consumers pin. `version` must increase monotonically for each `(author, app)` pair.

```js
import { writeFile } from "node:fs/promises";
import { loadCrypto } from "seedkernel-wasm";
import { authorBundle, hybridAuthorKeysFromSeed } from "seedkernel-wasm/bundle-author";

export async function buildBundle({ authorSeed, version, wasm, guestSource }) {
  const sodium = await loadCrypto();
  const keys = hybridAuthorKeysFromSeed(sodium, authorSeed);
  const authored = authorBundle(sodium, keys, {
    app: "example",
    version,
    protocols: ["example/v1"],
    modules: [{ name: "codec", wasm }],
    guestSource,
    guestRequires: [],
  });

  await writeFile("example.skb", authored.blob);
  return authored; // { blob, manifest, author }
}
```

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `./bundle-author` | `authorBundle` and `hybridAuthorKeysFromSeed` in offline build scripts; lower-level `signManifest` and `packBundle` for verifier hardening tests | [seedstore `storage-bundle.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/storage-bundle.mjs), [seedchat `build-app-bundle.mjs`](https://github.com/arj03/seedchat/blob/main/scripts/build-app-bundle.mjs) |
| `./bundle` | `verifyBundle` wherever a blob arrives — a build reading back a prior version, a page reading a fetched `.skb`; `hybridAuthorId` for the author identity you pin, `genesisHash` for content ids, `moduleFile` for a module's name inside the container | [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html), [seedchat `chat-shell.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.js) |

The authoring module also carries the lower-level signing and packing primitives. They stay exported for hardening tests and for a consumer that deliberately forges or tampers with a bundle to prove the verifier rejects it — not a path a client should take. Author with `authorBundle`, verify with `verifyBundle`. Runtime shells import only `./bundle`, which has no signing surface.

## 2. Runtime — boot a node and drive the shell

`bootShell` is the one shared node assembly (§12.9). Browser and custom-platform clients call it directly; Node clients may use `bootNodeShell`, the convenience wrapper that supplies Node's adapters and then enters the same assembly.

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `./shell-core` | `bootShell` — the assembly. `AppHandle`, what a load hands back. `scopedFs`, to re-derive an app's fs view over a raw backend outside a running node. The admission constructors (`denyAll`, `admitAll`, `authorAllowlist`, `byPrivilege`, `allOf`, `anyOf`, `policyFromJson`) are re-exported here too, so your `admit` comes from the same module | [seedchat `chat-shell.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.js) (a consent gate and a `contactSecret` getter), [seedstore `storage-node.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/storage-node.ts) (a whole node wrapped as a class) |
| `./op-frame` | The shared optional `[opLen u8][op ascii][args …]` client codec: `writeOp` for a host loopback, `readOp`/`callerOf` in a guest, and `guestOpFraming` for build tools that inline those readers into signed source. This is a leaf helper over opaque `invoke` bytes; `shell-core`, timers, and the guest seam do not import or interpret it | [seedchat `chat-shell.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.js), [seedchat `chat-app.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-app.js), [seedstore `storage-node.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/storage-node.ts), [seedstore `build-guest.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-guest.mjs) |
| `./shell-node` | The Node platform adapter: `bootNodeShell` wires `NodeFs` on a data directory, a `node:net` channel factory and a file-backed freshness store into `bootShell`, then hands back the shell and channel adapter. This is a Node convenience, not a second kernel assembly; a client that owns its platform wiring calls `bootShell` | [seedstore `shell-run.test.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/tests/shell-run.test.mjs) |
| `./transport-bundle` | `transportBundleBytes()` — the shipped signed transport program, the blob that *is* the node's network. When networking is configured, `bootShell` uses this blob by default; import it to pass a replacement explicitly, derive the policy pin, hash it, or inspect it | [seedchat `chat-shell.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.js) |
| `./guest-seam` | `appSigner` and `guestSignScope` for a host-side mirror of one slot's scoped sign/verify pair, so host code and guest code sign the same bytes | [seedstore `manifest.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/manifest.ts) |

For a conventional Node process, `bootNodeShell` is the shortest complete path. The policy must admit ordinary app authors under `authors` and the shipped transport author under `grants.link`:

```js
import { readFile } from "node:fs/promises";
import { loadCrypto, generateKeyPair } from "seedkernel-wasm";
import { verifyBundle } from "seedkernel-wasm/bundle";
import { bootNodeShell } from "seedkernel-wasm/shell-node";
import { transportBundleBytes } from "seedkernel-wasm/transport-bundle";

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const sodium = await loadCrypto();
const appBlob = new Uint8Array(await readFile("example.skb"));
const transportBlob = transportBundleBytes();

const runtime = await bootNodeShell({
  dir: "./data",
  identity: generateKeyPair(),
  policyJson: JSON.stringify({
    authors: [hex(verifyBundle(sodium, appBlob).author)],
    grants: { link: [hex(verifyBundle(sodium, transportBlob).author)] },
  }),
});

try {
  const app = await runtime.shell.loadBundleBlob(appBlob);
  const answer = await app.invoke(new Uint8Array());
  console.log(answer);
} finally {
  runtime.shell.close();
}
```

## 3. Platform adapters — the target-specific pieces you choose and hand to §2

A deliberate per-target choice (Node vs. browser, WS vs. RTC, memory-fs vs. node-fs), not internals leaking out.

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `.` (root) | Node's `loadCrypto` — the host trust root read off disk: core libsodium with ML-DSA-65 mixed in. It also exports `ensureCrypto`, `generateKeyPair`, and `generatePqKeyPair`. What is promised here is the trust root, not every symbol the returned object carries (below) | [seedstore `sodium.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/sodium.ts), [seedstore `build-bundle.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-bundle.mjs) |
| `./crypto-browser` | The browser's `loadCrypto` — the same host trust-root mix, fetched by URL onto a core instance you supply | [seedstore `index.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/index.html), [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html), [seedchat `chat-shell.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.js) |
| `./libsodium` | That core instance: the runtime's prebuilt browser libsodium, identical to the binary the Go loader embeds | the three pages above |
| `./quickjs` | Nothing you call. It is the QuickJS engine `safe-js` names by bare specifier, so a **browser** client must carry it in its import map even though its own code never mentions it | the import map in [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html) |
| `./fs`, `./fs-memory`, `./fs-node` | The `Fs` interface and safe-key checks, plus the two backends: in-memory (`bootShell`'s default) or a directory on disk | [seedstore `storage-node.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/storage-node.ts), [seedstore `bench-holder.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/tests/bench-holder.mjs) |
| `./net-node` | `NodeChannelFactory` — TCP over `node:net` — plus `parsePeerSpec`, `parsePeerRef`, `parseHostPort`, and `isHex64` | [seedstore `net.test.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/tests/net.test.mjs) |
| `./net-ws` | `WsNetwork` — dial known, natively-reachable nodes straight at their `--ws-listen` port; `parseWsPeer` parses its peer specification. No relay or STUN | [seedstore `p2p-cli.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/p2p-cli.mjs), [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html) |
| `./net-rtc` | `RtcNetwork` and `relaySignaling` — WebRTC with a signaling rendezvous. Browser natively; Node/Bun by supplying `peerConnectionFactory` | [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html), [seedchat `media-rtc.js`](https://github.com/arj03/seedchat/blob/main/browser/media-rtc.js) (subclassed for audio/video) |

**The WebRTC *seam* is the runtime's; the console peer-connection is the app's.** `RtcNetwork` manages negotiation and hands each data channel to `openLink()` — that is raw I/O, and it belongs here. What sits underneath is one implementation of a byte duplex: the browser has `RTCPeerConnection` as a global, and a Node/Bun console peer passes `peerConnectionFactory` wrapping a pure-JS WebRTC library to the same W3C subset (see [seedstore `werift-pc.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/werift-pc.mjs), which drives [`serve-rtc-holder.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/serve-rtc-holder.mjs)). The runtime does not depend on any ICE/DTLS stack, so a client that never opens a console peer carries none. Subclass `RtcNetwork` rather than fork it when you need more than raw bytes.

**`loadCrypto` has a Node build and a browser build, not one shared function.** Node's (`.`) pulls the core npm package and reads the ML-DSA verifier off disk; the browser's (`./crypto-browser`) fetches that verifier onto a caller-supplied core instance. ML-KEM is not part of either surface: it is a private module of the signed transport bundle. `./pq` is internal.

**What the root export promises is the trust root, not all of libsodium.** `loadCrypto` resolves to a core instance with ML-DSA-65 mixed onto it, so every libsodium symbol is reachable there — but what this package maintains is the trust root: BLAKE2b (`crypto_generichash`), Ed25519 (`crypto_sign_*`), ML-DSA-65, `randombytes_buf`, and the transforms the guest seam exposes (`SeamCrypto`, from `./guest-seam`). Those are what verifies a manifest and stands a realm, and they are what a version bump here will not move. Anything else you reach on that object is libsodium's own surface travelling under libsodium's compatibility promise rather than this one's — legitimate to use, and seed store does, but declare the subset you depend on (its `Sodium` interface is the pattern) or take libsodium as your own dependency, so a core swap here is a compile error on your side rather than a silent one.

The smallest browser boot has no network. It loads the browser crypto surface, chooses an app-author policy, and lets `bootShell` default the in-memory filesystem, freshness store, module table, and realm factory:

```js
import sodiumCore from "seedkernel-wasm/libsodium";
import { loadCrypto } from "seedkernel-wasm/crypto-browser";
import { authorAllowlist, bootShell } from "seedkernel-wasm/shell-core";

// The base URL is the directory containing mldsa65.wasm.
const sodium = await loadCrypto(sodiumCore, "./");
const { shell } = await bootShell({
  sodium,
  identity: sodium.crypto_sign_keypair(),
  admit: authorAllowlist(["<trusted hybrid author id in hex>"]),
});

// Add `transport` options to enable networking; see the transport modes below.
const response = await fetch("./example.skb");
const fetchedBundleBytes = new Uint8Array(await response.arrayBuffer());
const app = await shell.loadBundleBlob(fetchedBundleBytes);
const answer = await app.invoke(new Uint8Array());
window.addEventListener("pagehide", () => shell.close(), { once: true });
```

## The assembly is an export

`bootShell` (`./shell-core`) is the ONE node-assembly (§12.9), and entering it is how a client gets a node that is correct by construction. Every field but `sodium` and `identity` has a default — the module table, an in-memory fs and freshness store, a lazily-imported safe-js realm factory — so you state only what you genuinely own. One default is a decision rather than a convenience: `admit` absent is **deny-all** — the node boots but installs nothing, the transport bundle included, so a client that states no gate has no network. Browser and Node clients, the native loader, and seedstore's wrapper all enter through this assembly; they differ only in which defaults they displace.

Transport behavior has three deliberate modes:

| Configuration | Adapter | Transport bundle |
| --- | --- | --- |
| `transport` omitted or `false` | No `TransportHost`; `BootResult.transport` is `null` | Not loaded. The node has no network. |
| `transport: { …options }` | `bootShell` constructs and returns the adapter, filling in the top-level `identity` and `networkKey` | The shipped bundle—or `transportBundle` when supplied—is pinned and offered for admission during boot. If admitted, it is loaded; listeners are then started. |
| `transport: { …options }`, `transportLoad: false` | `bootShell` constructs and returns the adapter | Loading is deferred. The caller later passes the selected bundle to `shell.loadBundleBlob`; this is seedchat's lazy-first-connect mode. The options object is retained, so accessors such as seedchat's live `contactSecret` getter survive. |

`transportBundle` selects both the blob loaded in the automatic case and the blob whose author is pinned. It defaults to `transportBundleBytes()`. Passing different transport bytes is therefore a deliberate transport replacement, not just a different boot payload.

Two things it does *for* you, which is why you should not try to reproduce them:

- **The transport author pin is ANDed onto your predicate, never substituted for it.** The transport bundle is admitted under a pin derived from the blob itself, so "only this author may be the network" is the assembly's business, not something you can lose by forgetting it. Your `admit` still has to admit as well — a deny-all node has no network, and an operator keeps the power to refuse a transport author, because AND means both. Running a different transport means passing a different `transportBundle`, which is what the pin is derived from.
- **It is fail-closed on a privilege it does not know.** `PRIVILEGES` is derived from the capability catalog, so a privileged name added to `core/domains.ts` appears here as a privilege with no branch, and bundles reaching it are refused until the assembly is taught about it. That is what makes "privileged bundles are the pin's business" a safe thing for your consent dialog to assume.

A load returns an **`AppHandle`**: the app key, the app's fs scope and the scoped view over it, and an `invoke` already bound to that slot — so you drive the app through derivations the shell has already made. Take the handle; do not re-derive its parts.

`loadBundleBlob(blob, options)` also accepts installation-local `localConfig`, per-app `realmMemoryBytes` and `guestDeadlineMs` bounds, and an `onInbound` observer. None of those values becomes author-signed bundle content; they belong to this installation and this load.

The handle's `invoke` is bound to the slot this load stood. On an upgrade, a replacement load stands a NEW slot under the same key and returns its own handle; a handle taken before it keeps naming the version it was handed and rejects once that slot is disposed. There is no second key-addressed invoke on `Shell`: callers retain the handle returned by the load they intend to drive.

## Browser build artifacts are not package entry points

Clients also depend on generated files: package entry points resolve into `build`, while browser staging copies `build-min`, `browser`, and `quickjs/dist`. These trees are outputs behind the public entry points, not additional entry points of their own. The sibling `file:` dependencies used today are directory links; the package's `files` list records the corresponding trees that a packed distribution must carry.

- `seedkernel-wasm/build-min/**` is the minified browser host, vendored into a web root by [seedstore's staging script](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-browser-demo.mjs) and [seedchat's vendor script](https://github.com/arj03/seedchat/blob/main/scripts/vendor.mjs). This is a dependency on *output*: `build-min` is gitignored, so a checkout of this repo that has never run `npm run build:host:min` stages nothing.

## Two traps a browser client hits

- **Bare specifiers resolve through a hand-written import map, and Node cannot tell you it is wrong.** Node finds `seedkernel-wasm/*` through `node_modules`; a browser page finds it only through `<script type="importmap">`. So an entry point your *host* code starts importing is invisibly missing from your *pages* until one is loaded — your Node suite stays green throughout. Map only what your graph actually names: `bootShell` pulls its module table and its safe-js realm in by relative import, so neither needs an entry, while `safe-js.js` names `seedkernel-wasm/quickjs` and does. [Seedstore's staging script](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-browser-demo.mjs) walks each page's real module graph at stage time and exits non-zero on an unmapped specifier — worth copying.
- **A stale `build-min` is the easiest cross-repo breakage to miss.** The browser runs the minified tree; Node tests run `build/`. When `build:host` reruns and `build:host:min` does not, the two diverge silently: tests pass against fresh code while the page serves old code. Anything you ship to a browser needs `npm run build:host:min` here to be current, and a staging step is the right place to assert it ([seedstore's does](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-browser-demo.mjs), for both repos).

Both clients vendor the built host into their own web root and resolve `seedkernel-wasm/*` from there. Start with [seedstore's import map](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html) or [seedchat's import map](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.html).
