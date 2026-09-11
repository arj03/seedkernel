# Writing bundles and clients on Seedkernel

An app starts with a plain JavaScript function, `handle(bytes)`, running in a confined guest. WASM modules are optional: add them for computation the guest should delegate. A build script signs the guest and its modules into a bundle; a host program loads that bundle and connects it to a CLI, browser UI, or peers.

| You write | Seedkernel supplies |
| --- | --- |
| Guest logic, payload formats, validation, and application authorization | A confined JS realm, caller attribution, serialized invocation, and execution limits |
| A manifest naming the app's modules, claims, and required services | Hashing, hybrid signing, bundle verification, policy enforcement, and atomic installation |
| Optional WASM transforms with the scratch-buffer ABI | Private module loading, bounded execution, and byte transfer through `host.call` |
| Host integration: UI or CLI, trusted authors, persistence, and peer configuration | Node/browser adapters and the shared shell; the shipped transport handles authenticated encrypted links |

The work Seedkernel saves is runtime and transport plumbing. Your application still owns its data model, access rules, recovery, and user experience. The main constraints are explicit byte interfaces, declared service access, and a guest environment without Node or browser APIs.

Start with [package setup](#use-the-package-from-a-sibling-checkout), then [build and run the first bundle](#1-build-and-run-a-bundle). The later sections cover node boot, platform adapters, networking, and browser staging. Apps use only the `seedkernel-wasm` and `seedkernel-wasm/*` entry points exported by [`WASM/package.json`](../WASM/package.json); their generated `.d.ts` files are the API reference.

## How much code?

These examples show different amounts of application work. The figures are ballpark, from a snapshot of the named sources rather than whole repositories, and nothing in this repo maintains them:

| Example | Guest JS | WASM source | Additional app code |
| --- | --- | --- | --- |
| [seedchat](https://github.com/arj03/seedchat), text chat | a couple of dozen lines of app logic emitted by [`chatGuestSource`](https://github.com/arj03/seedchat/blob/main/browser/chat-app.js), plus a similar amount of shared framing from `guestOpFraming()` | about thirty AssemblyScript lines in the [v1 text handler](https://github.com/arj03/seedchat/blob/main/assembly/chat-app-v1/index.ts) | Browser shell, HTML UI, installation consent, contacts, signaling, and build scripts |
| [seedstore](https://github.com/arj03/seedstore), storage | on the order of a thousand lines in [`tier2-guest.orchestration.js`](https://github.com/arj03/seedstore/blob/main/WASM/host/tier2-guest.orchestration.js), plus shared helpers assembled by [`build-guest.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-guest.mjs) | Separate codec and reputation modules | Storage policy, CLI/browser integration, configuration, and build scripts |

Chat's guest mostly dispatches sends to the transport and incoming messages to its private renderer. Seedstore implements placement, repair, and storage coordination, so its guest is larger by more than an order of magnitude. Neither app implements the channel handshake or bundle verifier.

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

The browser artifacts require the additional `npm run build:browser` build described in the [main README](../README.md#build-this-repo).

## 1. Build and run a bundle

Save this as `counter.mjs` in your client directory and run `node counter.mjs` after package setup. It builds a signed bundle, boots a local shell, installs the bundle, and invokes it twice, printing `1` and `2`. The guest is seven lines; the rest is authoring and host setup. The app itself needs no WASM build or network configuration.

The source inside `guestSource` runs in the sandbox. The imports, signing, and shell calls run in Node outside it.

```js
import { loadCrypto, generateKeyPair } from "seedkernel-wasm";
import { authorBundle, hybridAuthorKeysFromSeed } from "seedkernel-wasm/bundle-author";
import { authorAllowlist, bootShell } from "seedkernel-wasm/shell-core";

const guestSource = `
let count = 0;
function handle(input) {
  if (input.length !== 32) throw new Error("counter takes no payload");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, count = (count + 1) >>> 0);
  return out;
}
`;

const sodium = await loadCrypto();
const keys = hybridAuthorKeysFromSeed(sodium, sodium.randombytes_buf(32));
const { blob, author } = authorBundle(sodium, keys, {
  app: "counter",
  version: 1,
  modules: [],
  guestSource,
  guestRequires: [],
});

const { shell } = await bootShell({
  sodium,
  identity: generateKeyPair(),
  admit: authorAllowlist([Buffer.from(author).toString("hex")]),
});
try {
  const app = await shell.loadBundleBlob(blob);
  for (let i = 0; i < 2; i++) {
    const answer = await app.invoke(new Uint8Array());
    console.log(new DataView(answer.buffer, answer.byteOffset, answer.byteLength).getUint32(0));
  }
} finally {
  shell.close();
}
```

Each guest invocation receives `[caller 32 bytes][payload]`. `app.invoke` supplies the host's all-zero caller id, so an empty payload reaches this handler as 32 bytes. A peer call carries its authenticated key; a local guest call carries the calling app's id. Return only response bytes. An `async function handle` may await `host.call(name, bytes)`, which returns a promise even for a private WASM transform.

This counter wraps at 2³² and keeps its state only in the guest heap. Reloading the bundle resets it. It declares no protocol or service claims, so only the host's returned `AppHandle` can invoke it. The demo deliberately creates fresh author and node keys on each run and uses in-memory storage and freshness tracking.

### Turn the demo into a release

Keep a private 32-byte author seed across releases and pass it to `hybridAuthorKeysFromSeed`; it determines the author id consumers pin. Increase `version` for each release of the same `(author, app)`. Run `authorBundle` in your offline build and save its `blob` as a `.skb` file, for example `await writeFile("example.skb", blob)` using `node:fs/promises`. The deployed host needs the bundle and the approved author id; it does not need the author seed. Keep a stable node identity and persistent freshness storage when running a lasting node (see §2).

`authorBundle` hashes the guest and modules, validates the manifest, signs, and packs the result. `shell.loadBundleBlob` verifies the bytes, applies admission policy, and builds the running slot. Signing does not prove that your guest compiles or that its WASM meets the runtime ABI: exercise a load and invocation before publishing. Use `verifyBundle` when inspecting a blob outside a running shell.

### Add only the interfaces your app needs

| Need | Bundle declaration and guest code |
| --- | --- |
| A private WASM transform | Add `{ name: "codec", wasm }` to `modules`; call `await host.call("codec", bytes)`. The module exports `memory`, `scratch`, and `handle`, declares a memory maximum, and imports no capabilities ([ABI §4](PROTOCOL.md#4-the-wasm-module-abi)). |
| Receive peer requests | Add a claim such as `protocols: ["counter/v1"]`. A networked host routes requests for that protocol to `handle`; your guest validates the payload and decides what the caller may do. |
| Provide a local service | Add `services: ["counter-local"]`. The host calls it through `shell.call`; another guest also declares it in its own `guestCalls`. |
| Send through the shipped transport | Add `guestCalls: ["_net"]`, then call `host.call("_net", encodedRequest)` using the transport's message format. The host must have configured and admitted the transport (§2). |
| Use app-scoped storage | Add `guestRequires: ["fs"]`, then use the `fs/*` byte formats in [RUNTIME §12.2](RUNTIME.md). Durable storage requires a persistent host backend. |

`guestRequires` names host **services**, such as `fs`, rather than methods such as `fs/get`. `guestCalls` names co-resident services; `protocols` and `services` declare who may call *you*. Private modules need no entry in either call list.

Guests are plain scripts with ECMAScript intrinsics and four supplied globals: `host`, `HOST` (the host-call budget this load admits — `maxOutstandingHostCalls` and `maxOutstandingHostCallBytes`, advertised so a guest can window its own fan-out instead of being refused), `APP` (signed config), and `LOCAL` (installation config). They have no `fetch`, DOM, Node APIs, or runtime package imports. Bundle compatible dependencies into flat guest source; keep UI and platform code in the host client. For a multi-operation byte API, `guestOpFraming()` supplies the same `callerOf`/`readOp`/`writeOp` helpers used by host callers, so you need not write two codecs.

Execution is serialized per realm and bounded. Long work must fit the deployment's budgets, and small WASM calls on JS targets pay a worker hop ([measured overhead](../README.md#the-overhead-measured)). Module memory can be discarded after a deadline failure; guest state is discarded on replacement. Persist data and design recovery around those lifetimes.

### Authoring API reference

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `./bundle-author` | `authorBundle` and `hybridAuthorKeysFromSeed` in offline build scripts; `guestOpFraming` for a build tool that inlines the op-frame codec into guest source before it is signed; lower-level `signManifest` and `packBundle` for verifier hardening tests | [seedstore `storage-bundle.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/storage-bundle.mjs), [seedchat `build-app-bundle.mjs`](https://github.com/arj03/seedchat/blob/main/scripts/build-app-bundle.mjs), [seedstore `build-guest.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-guest.mjs) |
| `./bundle` | `verifyBundle` wherever a blob arrives — a build reading back a prior version, a page reading a fetched `.skb`; `hybridAuthorId` for the author identity you pin, `genesisHash` for content ids, `moduleFile` for a module's name inside the container | [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html), [seedchat `chat-shell.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.js) |

The authoring module also carries the lower-level signing and packing primitives. They stay exported for hardening tests and for a consumer that deliberately forges or tampers with a bundle to prove the verifier rejects it — not a path a client should take. Author with `authorBundle`, verify with `verifyBundle`. Runtime shells import only `./bundle`, which has no signing surface.

## 2. Runtime — boot a node and drive the shell

`bootShell` is the one shared node assembly (§12.9). Browser and custom-platform clients call it directly; Node clients may use `bootNodeShell`, the convenience wrapper that supplies Node's adapters and then enters the same assembly.

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `./shell-core` | `bootShell` — the assembly. `AppHandle`, what a load hands back. `scopedFs`, to re-derive an app's fs view over a raw backend outside a running node. The admission constructors (`denyAll`, `admitAll`, `authorAllowlist`, `byPrivilege`, `allOf`, `policyFromJson`) are re-exported here too, so your `admit` comes from the same module | [seedchat `chat-shell.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.js) (consent and contact-secret rotation), [seedstore `storage-node.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/storage-node.ts) (a whole node wrapped as a class) |
| `./op-frame` | The shared optional `[opLen u8][op ascii][args …]` client codec: `writeOp` for a host loopback, `readOp`/`callerOf` in a guest, and `OpArgs` for an op whose arguments are structured (`u8`/`u32`/length-prefixed `blob`/`text` fields, built in one pass). This is a leaf helper over opaque `invoke` bytes; `shell-core`, timers, and the guest seam do not import or interpret it. A guest that cannot import takes the same codec as flat source from `./bundle-author`'s `guestOpFraming`, which stays out of this runtime module so a browser shell does not vendor a source emitter | [seedchat `chat-shell.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.js), [seedchat `chat-app.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-app.js), [seedstore `storage-node.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/storage-node.ts) |
| `./shell-node` | The Node platform adapter: `bootNodeShell` wires `NodeFs` on a data directory, a `node:net` channel factory and a file-backed freshness store into `bootShell`, then hands back the shell and channel adapter. This is a Node convenience, not a second kernel assembly; a client that owns its platform wiring calls `bootShell` | [seedstore `shell-run.test.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/tests/shell-run.test.mjs) |
| `./transport-bundle` | `transportBundleBytes()` — the shipped signed transport program, the blob that *is* the node's network. When networking is configured, `bootShell` uses this blob by default; import it to pass a replacement explicitly, derive the policy pin, hash it, or inspect it. `TRANSPORT_SERVICE` beside it is the local service id that blob claims (`"_net"`), which is what you hand `shell.call` to reach the running transport | [seedchat `chat-shell.js`](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.js) |
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
| `./net-node` | `NodeChannelFactory` — TCP over `node:net`, and nothing else | [seedstore `net.test.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/tests/net.test.mjs) |
| `./peer-addr` | The `pk[.secret]@dest` grammar — `parsePeerRef`, `peersConfig`, `parseDest`, `parseHostPort` — with no socket adapter under it. The one place a client takes the parser from, whether or not it opens a socket. `parsePeerRef(spec, "ws")` yields `{ peerId, contactSecret, dest }`, which a client hands to an `addr` call through `shell.call(...)` or, at boot, to `peersConfig(specs)` for the load's `transport.config.peers`. It takes `pk[.secret]@[wss://]host:port[/path]`, so a scheme asks for TLS and a path reaches a peer behind a reverse proxy; `parseDest` is the other half, the one a `ChannelFactory` uses to decide what it can route | the in-repo caller is [`cli.ts`](../WASM/host/cli.ts) |
| `./net-ws` | `WsNetwork` — a `ChannelFactory` that dials the `ws://`/`wss://` destinations `link/open` names, at a peer's `--ws-listen` port. No relay or STUN. Which peers, and how many links each, is the transport bundle's signed policy over its own address book, not this file's | [seedstore `p2p-cli.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/p2p-cli.mjs), [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html) |
| `./net-rtc` | `RtcNetwork` — an accept-only `ChannelFactory` over WebRTC and an application-supplied opaque-string `Signaling` seam. Browser natively; Node/Bun by also supplying `peerConnectionFactory` | [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html), [seedchat `media-rtc.js`](https://github.com/arj03/seedchat/blob/main/browser/media-rtc.js) (subclassed for audio/video) |

**The WebRTC *seam* is the runtime's; the console peer-connection is the app's.** `RtcNetwork` manages negotiation and hands each established data channel to the driver as an ordinary `RawLink` — it *is* the node's `ChannelFactory`, so you construct it before `bootShell` and pass it as `transport.channels`. That is raw I/O, and it belongs here. What sits underneath is one implementation of a byte duplex: the browser has `RTCPeerConnection` as a global, and a Node/Bun console peer passes `peerConnectionFactory` wrapping a pure-JS WebRTC library to the same W3C subset (see [seedstore `werift-pc.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/werift-pc.mjs), which drives [`serve-rtc-holder.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/serve-rtc-holder.mjs)). The runtime does not depend on any ICE/DTLS stack, so a client that never opens a console peer carries none. Subclass `RtcNetwork` rather than fork it when you need more than raw bytes.

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
| `transport: { …options }` | `bootShell` constructs and returns the adapter, with identity available to the transport through `node/identity` | The shipped bundle—or `transport.bundle` when supplied—is pinned and offered for admission during boot. If admitted, it is loaded with `transport.config` as that load's `localConfig`; listeners are then started. |
| `transport: { …options, load: false }` | `bootShell` constructs and returns the adapter | Loading is deferred. The caller later passes the selected bundle to `shell.loadBundleBlob(blob, { localConfig })`; this is seedchat's lazy-first-connect mode. The options object is retained, so a getter-backed member stays live — pass the object itself rather than a spread of it. |

Everything about the node's network is that one object: the socket-side members (`channels`, `listen`, `wsListen`, `maxRawLinks`, `onLinkClosed`) plus `bundle`, `config` and `load`. They are one decision — the blob whose author is *pinned* is the blob that gets *loaded*, under the configuration that load is given — so they are one field rather than four siblings that can disagree.

`transport.bundle` selects both the blob loaded in the automatic case and the blob whose author is pinned. It defaults to `transportBundleBytes()`. Passing different transport bytes is therefore a deliberate transport replacement, not just a different boot payload. The transport's defaults are signed in its `guest.config`; `transport.config` is the automatic-load convenience for operator overrides and reaches the guest as `LOCAL`, exactly like any other one-bundle `localConfig`.

Two things it does *for* you, which is why you should not try to reproduce them:

- **The transport author pin is ANDed onto your predicate, never substituted for it.** The transport bundle is admitted under a pin derived from the blob itself, so "only this author may be the network" is the assembly's business, not something you can lose by forgetting it. Your `admit` still has to admit as well — a deny-all node has no network, and an operator keeps the power to refuse a transport author, because AND means both. Running a different transport means passing a different `transport.bundle`, which is what the pin is derived from.
- **It is fail-closed on a privilege it does not know.** `PRIVILEGES` is derived from the capability catalog, so a privileged name added to `core/domains.ts` appears here as a privilege with no branch, and bundles reaching it are refused until the assembly is taught about it. That is what makes "privileged bundles are the pin's business" a safe thing for your consent dialog to assume.

**Pinning claim owners is yours, not the assembly's.** Protocol claims select the app receiving decrypted peer input; service claims select the app receiving local call arguments. Neither adds a host capability, but both decide who sees your data and whose answers your callers trust — and the JSON policy reserves no names (§12.5). Compose an owner check onto your predicate, reading the verified `(author, app)` and the signed claim lists `admit` is already handed:

```js
import { allOf, policyFromJson } from "seedkernel-wasm/shell-core";
import { appKeyFor } from "seedkernel-wasm/bundle";

// Replace these placeholders with approved 64-character lowercase author ids.
const appAuthor = "<approved app author id in hex>";
const transportAuthor = "<approved transport author id in hex>";

const basePolicy = policyFromJson(JSON.stringify({
  authors: [appAuthor],
  grants: { link: [transportAuthor] },
}));
const protocolOwners = new Map([
  ["private-chat-v1", `${appAuthor}:private-chat`],
]);
const serviceOwners = new Map([
  ["private-chat-local", `${appAuthor}:private-chat`],
  ["_net", `${transportAuthor}:transport`],
]);

const approvedClaims = (v) => {
  const owner = appKeyFor(v.author, v.manifest.app);
  const matches = (claims, pins) => (claims ?? []).every(
    (claim) => !pins.has(claim) || pins.get(claim) === owner,
  );
  return matches(v.manifest.protocols, protocolOwners)
    && matches(v.manifest.services, serviceOwners);
};

// Pass as bootShell({ ...platformOptions, admit }).
const admit = allOf(basePolicy, approvedClaims);
```

Keep the pins in operator-controlled configuration rather than reading them off the candidate, and name the approved bundles' actual app labels and service ids — `transport` and `_net` are the shipped transport's. The two maps are independent audiences, so a name needing protection in both is pinned in both, and a claim in neither is judged by `basePolicy` alone. `allOf` applies the check to every candidate, including one judged by a capability grant rather than `byPrivilege`'s `base`; the shell still supplies revocation, freshness and the transport author pin around whatever you compose.

A load returns an **`AppHandle`**: the app key, the app's fs scope and the scoped view over it, and an `invoke` already bound to that slot — so you drive the app through derivations the shell has already made. Take the handle; do not re-derive its parts.

`loadBundleBlob(blob, options)` also accepts installation-local `localConfig`, per-app `realmMemoryBytes` and `guestDeadlineMs` bounds, and an `onInbound` observer. None becomes signed bundle content. For every app, including the transport, `localConfig` becomes `LOCAL` unchanged. The transport's `networkKey` is ordinary `LOCAL` config: 64 lowercase hex characters when supplied, with absence selecting the public network's zero key. For example, `transport: { config: { networkKey: "7a".repeat(32) } }` selects a network. The transport reads identity through `node/identity`. Its contact secret is ordinary `LOCAL` config: `contactSecret` is 64 lowercase hex, absence means open, and the `contact` op rotates it at runtime.

The handle's `invoke` is bound to the slot this load stood. On an upgrade, a replacement load stands a NEW slot under the same key and returns its own handle; a handle taken before it keeps naming the version it was handed and rejects once that slot is disposed. There is no second key-addressed invoke on `Shell`: callers retain the handle returned by the load they intend to drive.

## Reaching a claim from the host

`shell.call(serviceId, payload)` calls the realm claiming that LOCAL service id, with the host's caller id — the host half of the same routing a co-resident guest reaches through `host.call`. It answers `null` when nothing claims the name, which is how "this node has no transport" is said. It resolves `services` claims and never `protocols`: a name a *peer* may reach is a peer's to reach.

That is the door to the node's own network. Waiting for a cohort, listing linked peers and teaching an address are ordinary calls on the id the transport bundle claims (`TRANSPORT_SERVICE` from `./transport-bundle`, `"_net"` for the shipped one), composed with the codec both ends already share:

```js
import { OpArgs } from "seedkernel-wasm/op-frame";
import { TRANSPORT_SERVICE } from "seedkernel-wasm/transport-bundle";

// Teach the running transport one peer: [peer 32][secret 32][dest utf8], each blob-framed.
const taught = shell.call(TRANSPORT_SERVICE, new OpArgs("addr")
  .blob(peerId).blob(contactSecret ?? new Uint8Array(32)).text(dest).build());
if (!taught) throw new Error("this node has no transport");
await taught;

// Rotate this node's contact secret; an empty blob opens it.
await shell.call(TRANSPORT_SERVICE, new OpArgs("contact").blob(newSecret).build());

// Wait for the cohort, or the deadline — the op settles either way.
await shell.call(TRANSPORT_SERVICE, new OpArgs("ready").u32(5000).build());
```

The op names and their argument order are the transport bundle's own content, not a kernel ABI — a replacement transport may spell them differently, which is why its service id travels with its blob. `BootResult.transport` keeps only what is genuinely the host's: the bound ports, `start()`, `reset()` and `close()`.

## Browser build artifacts are not package entry points

Clients also depend on generated files: package entry points resolve into `build`, while browser staging copies `build-min`, `browser`, and `quickjs/dist`. These trees are outputs behind the public entry points, not additional entry points of their own. The sibling `file:` dependencies used today are directory links; the package's `files` list records the corresponding trees that a packed distribution must carry.

- `seedkernel-wasm/build-min/**` is the minified browser host — the compiled `core/` and `host/` trees and nothing else — vendored into a web root by [seedstore's staging script](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-browser-demo.mjs) and [seedchat's vendor script](https://github.com/arj03/seedchat/blob/main/scripts/vendor.mjs). This is a dependency on *output*: `build-min` is gitignored, so a checkout of this repo that has never run `npm run build:host:min` stages nothing.

## Two traps a browser client hits

- **Bare specifiers resolve through a hand-written import map, and Node cannot tell you it is wrong.** Node finds `seedkernel-wasm/*` through `node_modules`; a browser page finds it only through `<script type="importmap">`. So an entry point your *host* code starts importing is invisibly missing from your *pages* until one is loaded — your Node suite stays green throughout. Map only what your graph actually names: `bootShell` pulls its module table and its safe-js realm in by relative import, so neither needs an entry, while `safe-js.js` names `seedkernel-wasm/quickjs` and does. [Seedstore's staging script](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-browser-demo.mjs) walks each page's real module graph at stage time and exits non-zero on an unmapped specifier — worth copying.
- **A stale `build-min` is the easiest cross-repo breakage to miss.** The browser runs the minified tree; Node tests run `build/`. When `build:host` reruns and `build:host:min` does not, the two diverge silently: tests pass against fresh code while the page serves old code. Anything you ship to a browser needs `npm run build:host:min` here to be current, and a staging step is the right place to assert it ([seedstore's does](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-browser-demo.mjs), for both repos).

Both clients vendor the built host into their own web root and resolve `seedkernel-wasm/*` from there. Start with [seedstore's import map](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html) or [seedchat's import map](https://github.com/arj03/seedchat/blob/main/browser/chat-shell.html).
