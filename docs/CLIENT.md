# seedkernel: writing bundles and clients

*How to build an app as a signed bundle, and how to host it: from a runnable first bundle to booting a node, the CLI, the entry points, and the browser. For an embedder or an operator.*

> **Part of the [seedkernel](../README.md) spec.** Section numbers are global across the doc set, so a `(§X.Y)` reference points to whichever file holds that section:
>
> [README](../README.md) §1, §10 · [ARCHITECTURE](ARCHITECTURE.md) §2, §3, §5, §12, §12.6.2b, §16.1 · [BUNDLE](BUNDLE.md) §3.1, §4, §12.4, §12.5, §16 · [GUEST](GUEST.md) §12.2, §12.3 · [TRANSPORT](TRANSPORT.md) §12.6.1, §12.6.2, §12.6.3 · [SECURITY](SECURITY.md) §13, §14 · **CLIENT §12.8**
>
> This is a guide, not a contract: the APIs here are this package's, and their generated `.d.ts` files are the reference.

---

## Overview

An app is a plain JavaScript function, `handle(bytes)`, running in a confined guest, plus optional WASM modules for computation the guest delegates. A build script signs the guest and its modules into a bundle. A **client** is the program that boots a node, installs bundles into it, and connects it to a UI, a CLI or peers.

| You write | Seedkernel supplies |
| --- | --- |
| Guest logic, payload formats, validation, application authorization | A confined JS realm, caller attribution, serialized invocation, execution limits |
| A manifest naming the app's modules, claims and required services | Signing, verification, admission policy, atomic installation |
| Optional WASM transforms | Private module loading, bounded execution, byte transfer through `host.call` |
| Host integration: UI or CLI, trusted authors, persistence, peers | The shared host, platform adapters, and an authenticated, encrypted transport |

Your application still owns its data model, access rules, recovery and user experience. The constraints are explicit byte interfaces, declared service access, and a guest without Node or browser APIs.

This file goes from first bundle to deployment: package setup, a runnable bundle, the node assembly and the CLI (§12.8), the entry points, and the browser.

## How much code?

Ballpark figures from a snapshot of the named sources:

- [seedshell](https://github.com/arj03/seedshell)'s chat app (text and images): about forty lines of guest logic in [`chat-app/guest.js`](https://github.com/arj03/seedshell/blob/main/assembly/chat-app/guest.js), as much again shared with its other apps, and about twenty AssemblyScript lines in [`chat-app/index.ts`](https://github.com/arj03/seedshell/blob/main/assembly/chat-app/index.ts). The rest of seedshell is the browser page, UI, consent, contacts and build scripts.
- [seedstore](https://github.com/arj03/seedstore)'s storage node: on the order of a thousand lines of guest in [`tier2-guest.orchestration.js`](https://github.com/arj03/seedstore/blob/main/WASM/host/tier2-guest.orchestration.js), with separate codec and reputation modules, since it implements placement, repair and storage coordination.

Neither implements the channel handshake or the bundle verifier.

## Use the package from a sibling checkout

`seedkernel-wasm` is a private package, consumed as a local file dependency. With the repositories side by side, add to the client's `package.json`:

```json
{ "dependencies": { "seedkernel-wasm": "file:../seedkernel/WASM" } }
```

and build the runtime before installing the client:

```sh
cd ../seedkernel/WASM && npm install && npm run build
cd ../../your-client && npm install
```

Browser artifacts need the additional `npm run build:browser` ([README](../README.md#build-this-repo)).

## Build and run a bundle

Save this as `counter.mjs` in your client directory and run `node counter.mjs`. It signs a bundle, boots a local node, installs the bundle and invokes it twice, printing `1` and `2`. The string in `guestSource` runs in the sandbox; everything else runs in Node.

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

Every invocation receives `[caller 32][payload]`; `app.invoke` supplies the host's all-zero caller, so an empty payload arrives as 32 bytes (§12.3). The counter keeps its state only in the guest heap, so reinstalling resets it, and it claims no protocol or service, so only the returned handle can invoke it. The demo makes fresh author and node keys each run and keeps everything in memory.

### Turn the demo into a release

Keep a private 32-byte author seed across releases and pass it to `hybridAuthorKeysFromSeed`: it fixes the author id operators pin. Raise `version` for each release. Run `authorBundle` in your offline build and save `blob` as a `.skb` file; a node needs the bundle and your author id, never the seed. `authorBundle` strips the guest's comments, so write them freely. Signing does not prove that the guest compiles or that a module meets the ABI, so install and invoke it before publishing. `verifyBundle` inspects a blob outside a running node.

### Add only the interfaces your app needs

- **A private WASM transform**: add `{ name: "codec", wasm }` to `modules` and call `await host.call("codec", bytes)`. The module ABI is §4.
- **Receive peer requests**: add `protocols: ["counter"]`. A networked node routes requests for that protocol to `handle`; your guest decides what the caller may do.
- **Provide a local service**: add `services: ["counter-local"]`. The embedder reaches it with `shell.call`, and another guest by declaring it in its own `guestRequires`.
- **Send through the transport**: add `"_net"` to `guestRequires` and call it with the transport's `send` op (TRANSPORT, Local interface). A send may name only a protocol in your own `protocols`, so an app that only sends claims it too (§12.10).
- **App-scoped storage**: add `"fs"` to `guestRequires` and use the `fs/*` names (§12.2). Durable storage needs a node with a disk backend.

`guestRequires` is everything the guest reaches: host services by service name (`fs`, not `fs/get`) and the co-resident services it calls. `protocols` and `services` say who may call you. Modules, `crypto/*` and `Date.now()` need no entry.

A guest is a plain script with the engine's built-ins and the globals `host`, `HOST`, `APP` and `LOCAL` (§12.3): no `fetch`, DOM, Node APIs or imports. Bundle dependencies into flat guest source and keep UI and platform code in the client. For a multi-operation byte API, `guestOpFraming()` gives the guest the same `[opLen u8][op][args]` codec host code imports from `./op-frame`. Work must fit the deployment's heap and deadline; module memory can be lost after a failed call and guest state on replacement, so persist what matters and design for recovery.

---

## 12.8 The shell: node assembly and the CLI

### The assembly is an export

`bootShell(opts)` is the one node assembly: it stands the host up, installs the transport if asked, and returns a `Shell`. Every client reaches it, directly or through a wrapper: `bootNodeShell` is Node's convenience with its adapters and a data directory, a page calls a platform host's `standUp`, and the CLI calls the same. There is no layer beneath it to reach: transport selection, the services a node offers and load order are part of standing a node up, not steps a caller may skip.

Every field but `sodium` and `identity` has a default, so you state only what you own. An absent `admit` refuses every ordinary app (§12.5).

`services` names what the node offers beyond `node` and `timer`, which every node has. A service left out is not offered, and a bundle requiring it does not install:

- **`fs: backend`**: storage, each app scoped to its label over the backend (`MemoryFs`, `NodeFs`, or any `Fs`).
- **`transport: { … }`**: the network. `bootShell` installs the transport bundle at boot, with revocation and freshness enforced, passes `transport.config` as its `LOCAL`, and starts listeners. The options carry the socket adapter (`channels`), listeners, the `bundle` (a platform's `standUp` defaults to its blob's, and `transportBundleBytes()` gives it on Node), the `config`, and optionally `datagrams` for UDP paths. Without it, `BootResult.transport` is `null` and the node has no network.
- **`host: staging`**: the loader's host slots, for self-update (§12.9).

A relay is `{ transport }`, a node with no network `{ fs }`. `bootNodeShell` and the CLI always offer `fs` on their data directory and `host`.

**Pinning claim owners is yours.** Protocol claims decide which app receives decrypted peer input, and service claims which app receives local call arguments (§14); a JSON policy reserves no names. Compose an owner check onto your predicate:

```js
import { policyFromJson } from "seedkernel-wasm/shell-core";

const appAuthor = "<approved app author id in hex>";
const basePolicy = policyFromJson(JSON.stringify({ authors: [appAuthor] }));
// Each pinned claim names the one author:app allowed to hold it; null reserves it from all apps.
const protocolOwners = new Map([["private-chat", `${appAuthor}:private-chat`]]);
const serviceOwners = new Map([["private-chat-local", `${appAuthor}:private-chat`], ["_net", null]]);

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const approvedClaims = (v) => {
  const owner = `${hex(v.author)}:${v.manifest.app}`;
  const ok = (claims, pins) => (claims ?? []).every((c) => !pins.has(c) || pins.get(c) === owner);
  return ok(v.manifest.protocols, protocolOwners) && ok(v.manifest.services, serviceOwners);
};

const admit = async (v) => (await basePolicy(v)) && approvedClaims(v);   // bootShell({ ..., admit })
```

A transport requires `link` and bypasses the predicate (§12.5), so pinning `_net` to nobody stops an ordinary app from claiming it. Where a user decides what to install, show the bundle's `guestRequires` and `protocols`: admitting is the whole permission (§14).

### Installing, replacing and calling

`shell.install(blob, options)` returns an **`AppHandle`**: the verified manifest and author, the app's fs view, and an `invoke` bound to that slot. Keep the handle; an upgrade stands a new slot and returns a new handle, and the old one rejects once its slot is gone. The options are:

- `replaces`: the app label of the slot this install retires (§12.5). Without it, the label must be free.
- `localConfig`: the guest's `LOCAL`, unsigned and passed unchanged.
- `realmMemoryBytes`, `guestDeadlineMs`: this install's heap and deadline, overriding the node's.
- `onInbound(claim, sender, answer)`: called once a peer request to this slot is answered, for observation only. It exists because the transport consumes the answer, so an embedder that must paint what its app just answered (seedshell relaying render bytes to an app's view) has no other path to it.

```js
// Upgrade an app: name the slot it retires.
await shell.install(newChatBlob, { replaces: "chat", localConfig: chatConfig });

// Replace the transport: find the slot holding its service id.
const old = shell.resolve(TRANSPORT_SERVICE);
await shell.install(newTransportBlob, { replaces: old, localConfig: transportConfig });

// First install or upgrade: the label is in the signed manifest, so it is known up front.
const label = verifyBundle(sodium, blob).manifest.app;
await shell.install(blob, { replaces: installed.has(label) ? label : undefined });
```

A transport replacement keeps the node identity and listeners and discards links, session keys and the address book, so supply its configuration again (§12.10).

**`shell.call(serviceId, payload)`** calls the app claiming a local service id, with the host's zero caller id, and returns `null` when nothing claims it. That is the door to the node's network:

```js
import { OpArgs } from "seedkernel-wasm/op-frame";
import { TRANSPORT_SERVICE } from "seedkernel-wasm/transport-bundle";

// Teach one peer: [peer 32][secret][dest], each a blob, the secret empty for none.
const taught = shell.call(TRANSPORT_SERVICE, new OpArgs("addr")
  .blob(peerId).blob(contactSecret ?? new Uint8Array(0)).text(dest).build());
if (!taught) throw new Error("this node has no transport");
await taught;

// This node's contact secret, for its address pk.secret@dest.
const mySecret = await shell.call(TRANSPORT_SERVICE, new OpArgs("contact").build());

// Wait for the cohort, or dial one peer: [1] once linked, [0] if it cannot be reached.
await shell.call(TRANSPORT_SERVICE, new OpArgs("ready").u32(5000).build());
const [linked] = await shell.call(TRANSPORT_SERVICE, new OpArgs("dial").blob(peerId).u32(5000).build());
```

The op names belong to the transport bundle, not the host: a replacement may spell them differently, which is why its service id travels with it. Transport configuration keys and their signed defaults are in [`scripts/transport-config.mjs`](../WASM/scripts/transport-config.mjs); for example `transport: { config: { networkKey: "7a".repeat(32) } }` selects a network.

### Limits

Each install's heap and deadline resolve from its own option, then the `bootShell` default, then the shared default (64 MiB and 5 s, `host/wasm-limits.ts`); a replacement resolves its own rather than inheriting. They are the operator's numbers, never the manifest's (§12.3). `bootShell` refuses a heap under 1 byte or from 2³², and a deadline under 1 ms, so a mistyped value cannot silently lift a bound. A node holds at most 8 slots.

### The CLI

Both loaders take the same command line; `seedkernel` (the native binary) stands in for `node build/host/loader-node.js`:

```sh
seedkernel --policy ./allowed-keys.json --dir ./data --key ./node.key \
     --listen 0.0.0.0:7000,ws=0.0.0.0:7001 \
     --bundle ./app.skb [--local-config ./app.json] \
     [--transport ./transport.skb] [--transport-config ./transport.json] \
     [--peers <pk>.<secret>@host:port,…] [--contact-secret ./contact.hex] \
     [--relay ws://<key>.<secret>@host:port [--relay-secret ./relay.secret]] \
     [--revoke <author hex,…>] [--uninstall <app,…>] \
     [--op name [--app name] < argument > response] \
     [--guest-timeout <ms>] [--guest-memory <MiB>] \
     [--host ./host.skb] [--host-updates off|next|now]
```

- **`--policy`** is `{ "authors": ["<64 hex author id>", …] }`. Without it, every app install is refused; an enabled transport still runs. Malformed ids, unknown keys and bad JSON fail boot.
- **`--dir`** (default `./data`) is the data directory; **`--key`** (default `./seedkernel.key`) the 32-byte master seed, created on first run with owner-only permissions.
- **`--listen [label=][tcp://|udp://]host:port,…`** binds one listener per entry, labelled with its kind when unnamed; IPv6 goes in brackets. The label reaches the transport unread, which reads `ws` as WebSocket and a `udp` listener labelled `quic` as a QUIC listener (`--listen quic=udp://:7000`).
- **`--transport`** boots a transport bundle from disk instead of the built-in one; a relay node runs seedrelay's this way. **`--transport-config`** is a JSON object that becomes the transport's `LOCAL`.
- **`--peers`**, **`--contact-secret`**, **`--relay`**, **`--relay-secret`** go to the transport unread, so a replacement transport can spell addresses and secrets its own way; the shell refuses only a `wss://` destination, which no console socket reaches. Secrets are given as file names, never on the command line, because an argument is visible in `ps` and shell history. With `--peers`, the CLI waits for the cohort; with `--relay`, it registers there and reports whether that took.
- **`--revoke`** writes off authors and uninstalls what they installed; **`--uninstall`** removes apps alone (§12.5).
- **`--op name`** invokes the `--bundle` just loaded: stdin is the argument, stdout the response, logs go to stderr. One flag with stdin and stdout, because an op travels inside `handle`'s bytes and a flag per operation would have to know each app's argument shape.
- **`--guest-timeout`** (`0` means no deadline) and **`--guest-memory`** set the node's guest limits.
- **`--host`** boots a specific host blob, unchecked, by the operator's explicit choice; **`--host-updates`** (`off` by default, `next`, `now`) allows the running host to stage its successor (§12.9). Both are the loader's; the host never sees them.

Networking is enabled only by `--listen`, `--peers` or `--relay`; the transport flags are refused without one of them.

**The control endpoint.** A node serving a directory listens on a local socket beside it, `<dir>.control`, and nowhere else. An `--op` for a directory a node already serves goes to that node instead of booting a second one, since a store assumes it is its directory's only writer; such an `--op` takes only `--app`, and any other flag is refused rather than half obeyed. The socket is owner-only, so being the user the node runs as is the operator authority it asks for; a port would need a credential of its own. On Windows, Node uses a named pipe named by that file. Library callers use `./control`.

The CLI is shared code in the host script, so both loaders make every decision identically: the flag set, defaults, order (remedies, then the bundle, then one-shots, then serve) and every printed line.

---

## Entry points

Apps import only `seedkernel-wasm` and `seedkernel-wasm/*`, as [`WASM/package.json`](../WASM/package.json) exports them.

**Authoring**
- `./bundle-author`: `authorBundle`, `hybridAuthorKeysFromSeed`, `guestOpFraming`, for offline build scripts. Its lower-level signing primitives exist for verifier hardening tests.
- `./bundle`: `verifyBundle`, `hybridAuthorId`, `genesisHash`, wherever a blob arrives. It has no signing surface.

**Running a node**
- `./shell-core`: `bootShell`, `AppHandle`, `scopedFs`, and the admission constructors `denyAll`, `admitAll`, `authorAllowlist`, `policyFromJson`.
- `./shell-node`: `bootNodeShell`, `nodeChannels` (TCP), `nodeDatagrams` (UDP), `nodeLocalChannels`.
- `./transport-bundle`: `transportBundleBytes()`, the shipped transport, and `TRANSPORT_SERVICE` (`"_net"`).
- `./op-frame`: the `[opLen u8][op][args]` codec, `writeOp`, `readOp`, `callerOf`, `OpArgs`.
- `./control`: `controlInvoke`, `controlServes`, `serveControl`.
- `./node`: `appSigner`, a host-side mirror of one app's scoped sign and verify.
- `./subkeys`: `deriveNodeKey`, the node keypair from a master seed (§12.6.2b).
- `.`: Node's `loadCrypto` and `generateKeyPair`. `loadCrypto` is the host's own trust root from the package's host blob (BLAKE2b, Ed25519, X25519, ChaCha20-Poly1305, ML-DSA-65, randomness) and nothing more; an app needing more of libsodium takes its own.

**Platforms**
- `./platform`, `./platform-web`, `./host-web.skb`: a host over a platform; the browser platform; the blob a page serves.
- `./fs`, `./fs-memory`, `./fs-node`: the storage interface and its two backends.
- `./socket-seam`, `./net-ws`, `./net-rtc`, `./peer-addr`: the socket interface a factory implements, `combineChannels`, WebSocket and WebRTC factories, and destination parsing.
- `./ws.wasm`: the transport's WebSocket module, for a bundle of your own.

[seedstore](https://github.com/arj03/seedstore) and [seedshell](https://github.com/arj03/seedshell) use every one of these and are the worked examples.

## The browser

The smallest browser node has no network. It stands up on the browser platform through the same `standUp` the other targets use:

```js
import { browserPlatform } from "seedkernel-wasm/platform-web";
import { platformHost } from "seedkernel-wasm/platform";

// seedkernel-wasm/host-web.skb, served beside the page: the realm engine and the host's crypto.
const hostBlob = new Uint8Array(await (await fetch("./host-web.skb")).arrayBuffer());
const host = platformHost(browserPlatform({ hostBlob }));
const TRUSTED = "<trusted author id in hex>";
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const { shell } = await host.standUp({
  dir: "app",
  identity: host.sodium.crypto_sign_keypair(),
  admit: (bundle) => hex(bundle.author) === TRUSTED,
});

const app = await shell.install(new Uint8Array(await (await fetch("./example.skb")).arrayBuffer()));
const answer = await app.invoke(new Uint8Array());
window.addEventListener("pagehide", () => shell.close(), { once: true });
```

To network it, pass `transport` with `channels: combineChannels(new WsNetwork(), new RtcNetwork())`, register on a relay with the transport's `relay` op, and teach it the peers you meet with `addr`. The page holds the `RTCPeerConnection`s; signaling is the transport's. A console node has no WebRTC: it takes a UDP path to another console node and stays on the relay with a browser. An app that wants audio or video opens its own peer connection and signals it over its own protocol.

A page's crypto is the blob it is served. For anything else it computes, it brings its own library, as seedstore's pages bring libsodium-wrappers over the blob's own `libsodium.wasm`.

**Build artifacts are not entry points.** A page vendors `seedkernel-wasm/build-min/**`, the minified browser host, and serves `host-web.skb` beside it. `build-min` is gitignored output, so a checkout that never ran `npm run build:host:min` stages nothing.

**Two traps.**

- **The import map is hand-written, and Node cannot tell you it is wrong.** Node finds `seedkernel-wasm/*` through `node_modules`; a page finds it only through its `<script type="importmap">`, so an entry point your host code starts importing is silently missing from your pages while your Node tests stay green. [Seedstore's staging script](https://github.com/arj03/seedstore/blob/main/WASM/scripts/build-browser-demo.mjs) walks each page's module graph and fails on an unmapped specifier, which is worth copying.
- **A stale `build-min` is the easiest cross-repo breakage to miss.** The browser runs the minified tree and Node tests run `build/`. When `build:host` reruns and `build:host:min` does not, tests pass against fresh code while the page serves old code. A staging step is the place to assert it is current.
