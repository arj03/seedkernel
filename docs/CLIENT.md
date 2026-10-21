# seedkernel: writing bundles and clients

An app starts with a plain JavaScript function, `handle(bytes)`, running in a confined guest. WASM modules are optional: add them for computation the guest should delegate. A build script signs the guest and its modules into a bundle; a host program loads that bundle and connects it to a CLI, browser UI, or peers.

| You write | Seedkernel supplies |
| --- | --- |
| Guest logic, payload formats, validation, and application authorization | A confined JS realm, caller attribution, serialized invocation, and execution limits |
| A manifest naming the app's modules, claims, and required services | Hashing, hybrid signing, bundle verification, policy enforcement, and atomic installation |
| Optional WASM transforms with the scratch-buffer ABI | Private module loading, bounded execution, and byte transfer through `host.call` |
| Host integration: UI or CLI, trusted authors, persistence, and peer configuration | Node/browser adapters and the shared host; the shipped transport handles authenticated encrypted links |

The work Seedkernel saves is runtime and transport plumbing. Your application still owns its data model, access rules, recovery, and user experience. The main constraints are explicit byte interfaces, declared service access, and a guest environment without Node or browser APIs.

Start with [package setup](#use-the-package-from-a-sibling-checkout), then [build and run the first bundle](#1-build-and-run-a-bundle). The later sections cover node boot, platform adapters, networking, and browser staging. Apps use only the `seedkernel-wasm` and `seedkernel-wasm/*` entry points exported by [`WASM/package.json`](../WASM/package.json); their generated `.d.ts` files are the API reference.

## How much code?

These examples show different amounts of application work. The figures are ballpark, from a snapshot of the named sources rather than whole repositories, and nothing in this repo maintains them:

| Example | Guest JS | WASM source | Additional app code |
| --- | --- | --- | --- |
| [seedshell](https://github.com/arj03/seedshell)'s chat app, text and images | about forty lines of app logic in [`chat-app/guest.js`](https://github.com/arj03/seedshell/blob/main/assembly/chat-app/guest.js), plus a similar amount shared with its other apps in [`guest-lib/`](https://github.com/arj03/seedshell/tree/main/assembly/guest-lib) and the framing from `guestOpFraming()` | about twenty AssemblyScript lines in [`chat-app/index.ts`](https://github.com/arj03/seedshell/blob/main/assembly/chat-app/index.ts) | Browser page, HTML UI, installation consent, contacts, signaling, and build scripts |
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

Save this as `counter.mjs` in your client directory and run `node counter.mjs` after package setup. It builds a signed bundle, boots a local host, installs the bundle, and invokes it twice, printing `1` and `2`. The guest is seven lines; the rest is authoring and host setup. The app itself needs no WASM build or network configuration.

The source inside `guestSource` runs in the sandbox. The imports, signing, and `shell.*` calls run in Node outside it.

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
  const app = await shell.install(blob);
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

`authorBundle` validates the manifest, assembles the manifest, guest and modules into one body, and signs its BLAKE2b-256 hash together with the domain, suite and keys. `shell.install` verifies the bytes, applies admission policy, and builds the running slot. Signing does not prove that your guest compiles or that its WASM meets the runtime ABI: exercise an install and invocation before publishing. Use `verifyBundle` when inspecting a blob outside a running host.

### Add only the interfaces your app needs

| Need | Bundle declaration and guest code |
| --- | --- |
| A private WASM transform | Add `{ name: "codec", wasm }` to `modules`; call `await host.call("codec", bytes)`. The module exports `memory`, `scratch`, and `handle`, declares a memory maximum, and imports nothing from the host ([ABI §4](PROTOCOL.md#4-the-wasm-module-abi)). |
| Receive peer requests | Add a claim such as `protocols: ["counter/v1"]`. A networked host routes requests for that protocol to `handle`; your guest validates the payload and decides what the caller may do. |
| Provide a local service | Add `services: ["counter-local"]`. The host calls it through `shell.call`; another guest also declares it in its own `guestRequires`. |
| Send through the shipped transport | Add `"_net"` to `guestRequires`, then call `host.call("_net", encodedRequest)` using the transport's message format. The host must have configured and admitted the transport (§2). |
| Use app-scoped storage | Add `guestRequires: ["fs"]`, then use the `fs/*` byte formats in [RUNTIME §12.2](RUNTIME.md). Durable storage requires a persistent host backend. |

`guestRequires` is everything your guest reaches: host **services**, such as `fs` rather than methods such as `fs/get`, and the co-resident services it calls, such as `_net`. `protocols` and `services` declare who may call *you*. Private modules, the `crypto/*` transforms (entropy included, as `crypto/random`) and time (`Date.now()`) need no entry.

Guests are plain scripts with ECMAScript intrinsics and four supplied globals: `host`; `HOST`, the host's own facts (`identity`, the node's public key in hex, and the host-call budget this load admits, `maxOutstandingHostCalls` and `maxOutstandingHostCallBytes`, advertised so a guest can window its own fan-out instead of being refused, and `deadlineMs`, each invocation's handoff deadline, `null` when unbounded); `APP`, the signed config; and `LOCAL`, the installation config. They have no `fetch`, DOM, Node APIs, or runtime package imports. Bundle compatible dependencies into flat guest source; keep UI and platform code in the host client. For a multi-operation byte API, `guestOpFraming()` supplies the same `callerOf`/`readOp`/`writeOp` helpers used by host callers, so you need not write two codecs.

Execution is serialized per realm and bounded. Long work must fit the deployment's budgets, and small WASM calls on JS targets pay a worker hop ([SECURITY §14](SECURITY.md#14-security-considerations)). Module memory can be discarded after a deadline failure; guest state is discarded on replacement. Persist data and design recovery around those lifetimes.

### Authoring API reference

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `./bundle-author` | `authorBundle` and `hybridAuthorKeysFromSeed` in offline build scripts; `guestOpFraming` for a build tool that inlines the op-frame codec into guest source before it is signed; lower-level `signBundle` and `encodeBundleBody` for verifier hardening tests | [seedstore `storage-bundle.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/storage-bundle.mjs), [seedshell `build-app-bundle.mjs`](https://github.com/arj03/seedshell/blob/main/scripts/build-app-bundle.mjs), [seedstore `build-guest.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-guest.mjs) |
| `./bundle` | `verifyBundle` wherever a blob arrives (a build reading back a prior version, a page reading a fetched `.skb`); `hybridAuthorId` for the author identity you pin, `genesisHash` for content ids | [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html), [seedshell `shell.js`](https://github.com/arj03/seedshell/blob/main/browser/shell.js) |

The authoring module also carries the lower-level signing and packing primitives. They stay exported for hardening tests and for a consumer that deliberately forges or tampers with a bundle to prove the verifier rejects it; that is not a path a client should take. Author with `authorBundle`, verify with `verifyBundle`. Runtime shells import only `./bundle`, which has no signing surface.

## 2. Runtime: boot a node and drive the host

`bootShell` is the one shared node assembly (§12.8). Browser and custom-platform clients call it directly; Node clients may use `bootNodeShell`, the convenience wrapper that supplies Node's adapters and then enters the same assembly.

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `./shell-core` | `bootShell`, the assembly. `AppHandle`, what a load hands back. `scopedFs`, to re-derive an app's fs view over a raw backend outside a running node. The admission constructors (`denyAll`, `admitAll`, `authorAllowlist`, `policyFromJson`) are re-exported here too, so your `admit` comes from the same module | [seedshell `shell.js`](https://github.com/arj03/seedshell/blob/main/browser/shell.js) (consent and contact-secret rotation), [seedstore `storage-node.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/storage-node.ts) (a whole node wrapped as a class) |
| `./op-frame` | The shared `[opLen u8][op ascii][args …]` codec in `services/op-frame.ts`: `writeOp` for a host loopback, `readOp`/`callerOf` in a guest, and `OpArgs` for structured arguments (`u8`/`u32`/length-prefixed `blob`/`text` fields, built in one pass). The socket driver uses it to encode the host's raw-link event ABI; the event field layouts are specified in [RUNTIME §12.2](RUNTIME.md#122-the-guest-seam-the-guest-name-abi). Application and local-service bodies may use it as an optional convention; routing and timers keep those bodies opaque. A guest that cannot import takes the same codec as flat source from `./bundle-author`'s `guestOpFraming`, which stays out of this runtime module so a browser client does not vendor a source emitter | [seedshell `shell.js`](https://github.com/arj03/seedshell/blob/main/browser/shell.js), [seedshell `chat-app/guest.js`](https://github.com/arj03/seedshell/blob/main/assembly/chat-app/guest.js), [seedstore `storage-node.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/storage-node.ts) |
| `./shell-node` | The Node platform adapter: `bootNodeShell` stands a node up in this process on the platform the Node loader runs (§12.9), with its store on a data directory, the platform's TCP and UDP sockets and a file-backed freshness store, then hands back the `Shell` and channel adapter. This is a Node convenience, not a second assembly; a client that owns its platform wiring calls `bootShell`. `nodeChannels` is that platform's TCP over `node:net` and nothing else, as a `ChannelFactory` for such a client, and `nodeDatagrams` its UDP sockets, for `bootShell`'s `transport.datagrams`: the transport then punches a direct path through NATs with STUN at the relay, which it offers before WebRTC (§12.7) | [seedstore `shell-run.test.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/tests/shell-run.test.mjs), [seedstore `net.test.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/tests/net.test.mjs) |
| `./transport-bundle` | `transportBundleBytes()`: the shipped signed transport program, the blob that *is* the node's network. When networking is configured, `bootShell` uses this blob by default; import it to pass a replacement explicitly, hash it, or inspect it. `TRANSPORT_SERVICE` beside it is the local service id that blob claims (`"_net"`), which is what you hand `shell.call` to reach the running transport | [seedshell `smoke.mjs`](https://github.com/arj03/seedshell/blob/main/scripts/smoke.mjs) |
| `./guest-seam` | `appSigner` and `guestSignScope` for a host-side mirror of one slot's scoped sign/verify pair, so host code and guest code sign the same bytes | [seedstore `descriptor.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/descriptor.ts) |

For a conventional Node process, `bootNodeShell` is the shortest complete path. The policy lists ordinary app authors. This node has no network; `transport` options, as `bootShell` takes them, give it one:

```js
import { readFile } from "node:fs/promises";
import { loadCrypto, generateKeyPair } from "seedkernel-wasm";
import { verifyBundle } from "seedkernel-wasm/bundle";
import { bootNodeShell } from "seedkernel-wasm/shell-node";

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const sodium = await loadCrypto();
const appBlob = new Uint8Array(await readFile("example.skb"));

const runtime = await bootNodeShell({
  dir: "./data",
  identity: generateKeyPair(),
  policyJson: JSON.stringify({
    authors: [hex(verifyBundle(sodium, appBlob).author)],
  }),
});

try {
  const app = await runtime.shell.install(appBlob);
  const answer = await app.invoke(new Uint8Array());
  console.log(answer);
} finally {
  runtime.shell.close();
}
```

## 3. Platform adapters: the target-specific pieces you choose and hand to §2

A deliberate per-target choice (Node vs. browser, WS vs. RTC, memory-fs vs. node-fs), not internals leaking out.

| Entry point | What you import it for | Where to look |
| --- | --- | --- |
| `.` (root) | Node's `loadCrypto`, the host trust root out of the package's own host blob (`build/host.skb`): its libsodium and ML-DSA-65 on WebAssembly, with ML-DSA-65 signing for bundle authors. It also exports `generateKeyPair` and `generatePqKeyPair`. It carries the trust root and nothing more | [seedstore `sodium.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/sodium.ts), [seedstore `build-bundle.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-bundle.mjs) |
| `./platform-web`, `./host.skb` | A page's node: `browserHost`, the page's loader, runs the host blob's own script on `browserPlatform` (the blob's realm engine and crypto on `WebAssembly`, private modules in workers, an in-memory store by default, no sockets) and answers its host: `standUp`, `sodium` and the rest of `PlatformHost`. Evaluating the script takes `'unsafe-eval'` in the page's `script-src`. `readHostBlob` hands a page the blob's parts, so its own libsodium glue can run the blob's `libsodium.wasm` without fetching it again. `./host.skb` is the blob the page serves beside itself | [seedshell `shell.js`](https://github.com/arj03/seedshell/blob/main/browser/shell.js), [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html) |
| `./platform` | `platformHost` over a platform you build, importing the host instead of evaluating it: an in-process host on Node with the blob's engine and crypto and no sockets of its own, as seedstore's in-process cohorts stand each node up | [seedstore `node.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/node.ts) |
| `./fs`, `./fs-memory`, `./fs-node` | The `Fs` interface and safe-key checks, plus the two backends: in-memory (`bootShell`'s default) or `NodeFs`, a directory on disk | [seedstore `storage-node.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/storage-node.ts), [seedstore `bench-holder.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/tests/bench-holder.mjs) |
| `./peer-addr` | `parseDest` and `parseHostPort`: destination and bind-address parsing for socket edges, with no socket adapter under it. `parseDest` takes `scheme://host:port[/path]`, the string a `ChannelFactory` reads to decide what it can route; an IPv6 host is written in brackets and returned without them. How a *peer* is spelled is the transport's: the shipped one takes `pk[.secret]@dest` strings in `transport.config.peers`, and an `addr` call through `shell.call(...)` takes `[peer][secret][dest]` | [`cli.ts`](../WASM/host/cli.ts), [seedstore `loopback.ts`](https://github.com/arj03/seedstore/blob/main/WASM/host/loopback.ts) |
| `./socket-seam` | The socket ABI a factory implements (`RawLink`, `ChannelFactory`, `ListenAddress`, `Arrival`) and `combineChannels`, which puts several factories behind one driver: a destination goes to the first that routes it | [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html), [seedshell `shell.js`](https://github.com/arj03/seedshell/blob/main/browser/shell.js) |
| `./net-ws` | `WsNetwork`: a `ChannelFactory` that dials the `ws://`/`wss://` destinations `link/open` names: a peer's `ws`-labelled listener, or a relay. No STUN. Which peers, and how many links each, is the transport bundle's signed policy over its own address book, not this file's | [seedstore `p2p-cli.mjs`](https://github.com/arj03/seedstore/blob/main/WASM/scripts/p2p-cli.mjs), [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html), [seedshell `node/shell.mjs`](https://github.com/arj03/seedshell/blob/main/node/shell.mjs) (on Node 22's WebSocket) |
| `./net-rtc` | `RtcNetwork`, the `ChannelFactory` for `rtc:` destinations: it holds each `RTCPeerConnection` and passes the W3C verbs through as bytes (§12.7). Browser natively; Node by also supplying `peerConnectionFactory`. Put it beside a factory that reaches the relay with `combineChannels` | [seedstore `p2p.html`](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html), [seedshell `shell.js`](https://github.com/arj03/seedshell/blob/main/browser/shell.js) |

**The WebRTC *seam* is the runtime's, signaling is the transport's, and the console peer-connection is the app's.** `RtcNetwork` holds the peer connections and nothing else. Construct it before `bootShell` and pass it, beside a factory that can reach the relay, as `transport.channels` (`combineChannels(new WsNetwork(), new RtcNetwork())` in a browser), then register on the relay with the transport's `relay` op through `shell.call`, and hand the transport the peers you meet (in a room, with seedrelay's `rooms.mjs`) through its `addr` op. That is raw I/O, and it belongs here. What sits underneath is one implementation of a byte duplex: the browser has `RTCPeerConnection` as a global, and a Node console peer may pass `peerConnectionFactory` wrapping a WebRTC library to the same W3C subset. The runtime does not depend on any ICE/DTLS stack, and no shipped client brings one: a console node takes the UDP path (`bootShell`'s `transport.datagrams`) to another console node, and stays on the relay with a browser. An app that wants audio or video opens its own peer connection and signals it over its own protocol; the transport's connections carry its bytes only.

**`loadCrypto` is Node's.** It reads the host blob this package was built with, so a Node process signs and verifies with the bytes its hosts run. A page's host crypto is the blob it is served, on the browser platform (the host's `sodium`); for anything else it computes, a page brings its own library, as seedstore's pages bring libsodium-wrappers over the blob's own `libsodium.wasm` (pinned to the same libsodium build, since emscripten glue runs only its own wasm). ML-KEM is not part of either surface: it is a private module of the signed transport bundle. `./pq` is internal.

**The root export is the trust root, not libsodium.** `loadCrypto` resolves to the host's own crypto object, which carries what this package maintains and nothing else: BLAKE2b (`crypto_generichash`), Ed25519 (`crypto_sign_*`), X25519 (`crypto_scalarmult`), ChaCha20-Poly1305 (`crypto_aead_chacha20poly1305_ietf_*`), ML-DSA-65, and `randombytes_buf` (the platform CSPRNG under libsodium's name: a length in, bytes out, none of libsodium's output formats). Those verify a manifest, stand a realm and back the transforms the guest seam exposes (`SeamCrypto`, from `./guest-seam`). An application that needs more of libsodium (seedstore's sealed boxes, say) takes libsodium as its own dependency.

The smallest browser boot has no network. It runs the host blob's own script on the browser platform, stands the node up through the same `standUp` the Node and native nodes boot through, and admits one app author; the platform supplies the in-memory store and freshness marks, the module table and the realm engine:

```js
import { browserHost } from "seedkernel-wasm/platform-web";

// seedkernel-wasm/host.skb, served beside the page: the host script, its realm engine and
// its crypto.
const hostBlob = new Uint8Array(await (await fetch("./host.skb")).arrayBuffer());
const host = browserHost({ hostBlob });
const TRUSTED = "<trusted hybrid author id in hex>";
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const { shell } = await host.standUp({
  dir: "app",
  identity: host.sodium.crypto_sign_keypair(),
  admit: (bundle) => hex(bundle.author) === TRUSTED,
});

// Add `transport` options to enable networking; see the transport modes below.
const response = await fetch("./example.skb");
const fetchedBundleBytes = new Uint8Array(await response.arrayBuffer());
const app = await shell.install(fetchedBundleBytes);
const answer = await app.invoke(new Uint8Array());
window.addEventListener("pagehide", () => shell.close(), { once: true });
```

## The assembly is an export

Every `bootShell` field but `sodium` and `identity` has a default (the module table, an in-memory fs and freshness store, a lazily imported realm factory that runs the package host blob's `qjs.wasm` on WebAssembly), so you state only what you genuinely own. An absent `admit` denies ordinary app installs (§12.5).

Transport startup has two modes:

| Configuration | Adapter | Transport bundle |
| --- | --- | --- |
| `transport` omitted or `false` | No `TransportHost`; `BootResult.transport` is `null` | Not loaded. The node has no network. |
| `transport: { …options }` | `bootShell` constructs and returns the adapter, with the node's identity available to the transport in `HOST` | The shipped bundle (or `transport.bundle` when supplied) is explicitly selected and installed during boot, with revocation and freshness enforced. It is loaded with `transport.config` as that load's `localConfig`; listeners are then started. |

The transport options carry the socket adapter, listeners, selected `bundle`, and initial `config`. The default blob is `transportBundleBytes()`. The options object is retained, so live accessors stay live. A selected transport must declare `link`; verification, revocation, freshness, and installation failures fail boot.

Live changes are the same `install`, naming the slot they retire, for ordinary apps and the transport alike:

```js
// A slot is named by its app label.
const chat = await shell.install(newChatBlob, { replaces: "chat", localConfig: chatConfig });

// Use the current transport's declared service id to find its owner.
const oldTransport = shell.resolve(TRANSPORT_SERVICE);
if (oldTransport === null) throw new Error("No transport is installed");
const transportApp = await shell.install(newTransportBlob, {
  replaces: oldTransport,
  localConfig: transportConfig,
});
```

An installer that may be seeing either a first install or an upgrade decides with one field, since the app label is a fact of the signed manifest and so is known before the install:

```js
import { verifyBundle } from "seedkernel-wasm/bundle";

const app = verifyBundle(sodium, blob).manifest.app;   // the label the host will install under
await shell.install(blob, { replaces: installed.has(app) ? app : undefined });
```

The incoming author and app name may differ from the slot being retired. What a replacement may take, what `link` requires, and what a failure leaves running are §12.5; scopes follow the label (§5). A transport replacement keeps the node identity and listeners but discards links, session keys and the address book, so supply its configuration again (§12.10).

`bootNodeShell` and the native binary's `standUp` take `bootShell`'s own `transport` option, so omitting it stands a node without a network, whose returned `transport` is then `null`; the platform supplies the socket adapter when the options name none.

**Pinning claim owners is yours, not the assembly's.** Protocol claims select the app receiving decrypted peer input; service claims select the app receiving local call arguments. Both decide who sees your data and whose answers your callers trust (§14), and the JSON policy reserves no names (§12.5). Compose an owner check onto your predicate, reading the verified author, `app` label and the signed claim lists `admit` is already handed:

```js
import { policyFromJson } from "seedkernel-wasm/shell-core";

// Replace these placeholders with approved 64-character lowercase author ids.
const appAuthor = "<approved app author id in hex>";
const transportAuthor = "<approved transport author id in hex>";

const basePolicy = policyFromJson(JSON.stringify({
  authors: [appAuthor],
}));
// Each pinned claim names the one author and app label allowed to hold it.
const protocolOwners = new Map([
  ["private-chat-v1", `${appAuthor}:private-chat`],
]);
const serviceOwners = new Map([
  ["private-chat-local", `${appAuthor}:private-chat`],
  ["_net", `${transportAuthor}:transport`],
]);

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const approvedClaims = (v) => {
  const owner = `${hex(v.author)}:${v.manifest.app}`;
  const matches = (claims, pins) => (claims ?? []).every(
    (claim) => !pins.has(claim) || pins.get(claim) === owner,
  );
  return matches(v.manifest.protocols, protocolOwners)
    && matches(v.manifest.services, serviceOwners);
};

// Pass as bootShell({ ...platformOptions, admit }).
const admit = async (v) => (await basePolicy(v)) && approvedClaims(v);
```

Keep the claim pins in operator-controlled configuration and name the approved bundles' actual app labels and service ids. The maps are independent audiences; a claim in neither is judged by `basePolicy` alone. These checks apply to ordinary app candidates, including an app trying to claim `_net`; bundles requiring `link` bypass the predicate (§12.5).

**Admitting is the whole permission.** The host confines a guest to its `guest.requires` and holds its sends to the protocol ids it claims (§12.10), but does not contain it within a service it was granted. Where a user decides what to install, show the bundle's `guest.requires` and `protocols` (§14).

A load returns an **`AppHandle`**: the verified manifest and author, the app's fs scope and the scoped view over it, and an `invoke` already bound to that slot, so you drive the app through derivations the host has already made. Take the handle; do not re-derive its parts.

`install(blob, options)` also accepts installation-local `localConfig`, per-app `realmMemoryBytes` and `guestDeadlineMs` bounds (§12.3), and an `onInbound` observer (§12.10). None becomes signed bundle content; `localConfig` becomes `LOCAL` unchanged, for the transport too, whose keys are listed in §12.6. For example, `transport: { config: { networkKey: "7a".repeat(32) } }` selects a network.

The handle's `invoke` is bound to the slot this install stood. On an upgrade, the replacing install stands a NEW slot under the same key and returns its own handle; a handle taken before it keeps naming the version it was handed and rejects once that slot is disposed. There is no second key-addressed invoke on `Shell`: callers retain the handle returned by the install they intend to drive.

## Reaching a claim from the host

`shell.call(serviceId, payload)` calls the realm claiming that local service id with the host's caller id, and answers `null` when nothing claims it, which is how "this node has no transport" is said (§12.10).

That is the door to the node's own network. Waiting for a cohort, listing linked peers and teaching an address are ordinary calls on the id the transport bundle claims (`TRANSPORT_SERVICE` from `./transport-bundle`, `"_net"` for the shipped one), composed with the codec both ends already share:

```js
import { OpArgs } from "seedkernel-wasm/op-frame";
import { TRANSPORT_SERVICE } from "seedkernel-wasm/transport-bundle";

// Teach the running transport one peer: [peer 32][secret][dest utf8], each blob-framed, the
// secret empty for a peer that has none.
const taught = shell.call(TRANSPORT_SERVICE, new OpArgs("addr")
  .blob(peerId).blob(contactSecret ?? new Uint8Array(0)).text(dest).build());
if (!taught) throw new Error("this node has no transport");
await taught;

// Rotate this node's contact secret; an empty blob opens it.
await shell.call(TRANSPORT_SERVICE, new OpArgs("contact").blob(newSecret).build());

// Welcome these peers, [key 32]* in one blob, room-mates or a list of friends the app keeps:
// their calls through a relay need no contact secret. The whole set each time. And forget
// one peer: its address and its links.
await shell.call(TRANSPORT_SERVICE, new OpArgs("welcome").blob(welcomedKeys).build());
await shell.call(TRANSPORT_SERVICE, new OpArgs("forget").blob(peerId).build());

// Wait for the cohort or the deadline; the op settles either way. Or dial one peer: [1] once
// it is linked, [0] when it cannot be reached.
await shell.call(TRANSPORT_SERVICE, new OpArgs("ready").u32(5000).build());
const [linked] = await shell.call(TRANSPORT_SERVICE, new OpArgs("dial").blob(peerId).u32(5000).build());
```

The op names and their argument order are the transport bundle's own content, not a host ABI: a replacement transport may spell them differently, which is why its service id travels with its blob. `BootResult.transport` keeps only what is genuinely the host's: the bound ports, `start()`, `reset()` and `close()`.

## Browser build artifacts are not package entry points

Clients also depend on generated files: package entry points resolve into `build`, while browser staging copies `build-min` and the host blob (`build/host.skb`, also exported as `./host.skb`): a page on the browser platform passes the blob to its host, and a page that assembles with `bootShell` itself serves it beside the staged `host/` directory, where the default realm factory fetches it. These trees are outputs behind the public entry points, not additional entry points of their own. The sibling `file:` dependencies used today are directory links; the package's `files` list records the corresponding trees that a packed distribution must carry.

- `seedkernel-wasm/build-min/**` is the minified browser host (the compiled `services/` and `host/` modules a page can reach, and nothing else), vendored into a web root by [seedstore's staging script](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-browser-demo.mjs) and [seedshell's vendor script](https://github.com/arj03/seedshell/blob/main/scripts/vendor.mjs). This is a dependency on *output*: `build-min` is gitignored, so a checkout of this repo that has never run `npm run build:host:min` stages nothing.

## Two traps a browser client hits

- **Bare specifiers resolve through a hand-written import map, and Node cannot tell you it is wrong.** Node finds `seedkernel-wasm/*` through `node_modules`; a browser page finds it only through `<script type="importmap">`. So an entry point your *host* code starts importing is invisibly missing from your *pages* until one is loaded, while your Node suite stays green throughout. Map only what your graph actually names: `bootShell` pulls its module table and its realm factory in by relative import, so neither needs an entry. On the browser platform the realm engine comes from the host blob; under `bootShell`'s own default the realm factory fetches the host blob relative to itself, from `../host.skb`. [Seedstore's staging script](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-browser-demo.mjs) walks each page's real module graph at stage time and exits non-zero on an unmapped specifier, which is worth copying.
- **A stale `build-min` is the easiest cross-repo breakage to miss.** The browser runs the minified tree; Node tests run `build/`. When `build:host` reruns and `build:host:min` does not, the two diverge silently: tests pass against fresh code while the page serves old code. Anything you ship to a browser needs `npm run build:host:min` here to be current, and a staging step is the right place to assert it ([seedstore's does](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-browser-demo.mjs), for both repos).

Both clients vendor the built host into their own web root and resolve `seedkernel-wasm/*` from there. Start with [seedstore's import map](https://github.com/arj03/seedstore/blob/main/WASM/browser/p2p.html) or [seedshell's import map](https://github.com/arj03/seedshell/blob/main/browser/shell.html).
