# seedkernel: a sandboxed host that grows from apps

Seedkernel runs signed apps in a sandbox (JavaScript or WebAssembly) across browsers, Node and a small native executable. It gives an app controlled access to storage and to authenticated, encrypted peer connections. Every app, the transport included, arrives as a signed bundle on top of a minimal host.

That suits three kinds of work:

- **Hosting third-party extensions.** The operator controls which authors can install code and what each extension can access. Extensions run isolated, without direct access to the host's file system, sockets or process.
- **Distributing app updates as signed bundles.** A release is one blob under the author's signatures, verified on install, refused if older than what is installed, and swapped in atomically. Updates travel over the same peer network as app data. The runtime verifies the author's signatures without needing to trust the peer delivering the bundle.
- **Building peer applications on a shared runtime.** [seedstore](https://github.com/arj03/seedstore) and the apps in [seedshell](https://github.com/arj03/seedshell) get the same app interface, the same authenticated channel and the same storage in a browser tab, on a Node CLI and inside the native binary.

**Build an app: [Writing bundles and clients](docs/CLIENT.md).** For scale, the guest of seedshell's chat app is a few dozen lines of app logic over a small AssemblyScript module, while seedstore's storage orchestration runs to roughly a thousand. Neither implements the channel handshake or the bundle verifier. [The guide](docs/CLIENT.md#how-much-code) breaks that down and includes a runnable first bundle.

## What it costs

- **More machinery than you need** for an ordinary web app, a single-purpose server, or anything whose author and operator are the same party. A process boundary or a container is the cheaper answer there.
- **An app is sandboxed JavaScript, not Node or a browser.** Dependencies are bundled in and must work without Node APIs, the DOM or `fetch`, and work has to fit a per-app heap and time budget ([CLIENT](docs/CLIENT.md#add-only-the-interfaces-your-app-needs)).
- **You still write everything above the runtime.** Authorization rules, data model and persistence design, recovery after the host restarts your app, user key management, and the whole UI. What Seedkernel saves you is the runtime and transport plumbing.

## Status

Beta: it works on all three targets, and everything measured below was measured on running code, but the only apps exercising it are [seedstore](https://github.com/arj03/seedstore) and those in [seedshell](https://github.com/arj03/seedshell), written alongside it. The guest seam, bundle format and channel suite still change, and a change there means re-signing an app's bundles.

There has been no external audit, and no cryptographer has reviewed the design ([SECURITY §14.2](docs/SECURITY.md#142-post-quantum-exposure-and-remaining-limits)); constant-time behaviour of the built post-quantum paths is an open item, since passing functional vectors does not establish it. Treat the security properties as design intent, not as verified. Which roles are post-quantum, and why, is [below](#post-quantum-by-role).

## 1. The model

*Seedkernel* is the project; *the host* is the runtime it builds. The host admits *bundles*, each an app, and runs each in its own *slot*: the app's private code, state and storage. A bundle reaches the host's facilities, its *host services*, only as granted. Whoever embeds the host drives it through a *shell*: `bootShell` (§12.8) returns the `Shell` handle a client or the CLI uses to install, call, revoke and close.

```
+-------------------------+  +-------------------------+
| Application bundle      |  | Transport bundle        |
| JS guest + optional     |  | JS guest + private      |
| private WASM modules    |  | WASM modules            |
+-------------------------+  +-------------------------+
             ↕                            ↕
+------------------------------------------------------+
| Host                                                 |
| Admission, confinement, guest calls and routing      |
| Host services: raw I/O, storage, wakes and signing,  |
| each within its resource limits                      |
+------------------------------------------------------+
```

| Component | Role |
| --- | --- |
| **Host** | The runtime outside installed bundles: one signed host blob that a small fixed loader runs, natively or on Node, or that a page imports (§12.9). It verifies and admits bundles, builds their slots, confines execution, and routes calls. A bundle cannot verify its own admission or enforce its own confinement, so this is the host's job. |
| ↳ **Host services** | What a confined app cannot obtain for itself, the `HOST_SERVICES` set (§12.1): `node` (signing with the node's private key), `fs` (storage), `timer` (the realm's wake), `link` (sockets) and `host` (staging a new host blob). They move raw bytes under opaque link ids and storage keys, protect the key, and enforce limits on the resources they hold. A guest reaches only the services its signed manifest declares. |
| **Bundle** | The unit of installation (§12.4) and the app itself: a manifest, a guest JS program, optional WASM modules, and hybrid author signatures over the whole set. The host checks policy (§12.5), builds a private slot, and atomically replaces its claims. |
| ↳ **Guest** | The app's state and logic in a JS realm with no ambient authority (§12.2). Its interface is `host.call(name, …)` out and `handle(bytes)` in. Invocations are serialized per realm and bounded in heap, execution, and handoff time (§12.3). |
| ↳ **Modules** | The app's private library of restartable WASM transforms (§4), called by bare name through its guest. They have **no host imports** and no I/O, and their names are private to the slot (§3). |

The operator chooses which authors may install code and which host services they may receive; the host enforces those grants at admission and at the guest seam. Application-level authorization and behaviour live in the bundles.

There is one app shape, one install path (§12.4) and one guest seam (§12.2). The transport uses them like any other app: it reaches sockets by name, and the host and every app reach it through a local service id (§12.10).

## What a guest looks like

A guest is plain JavaScript that defines `handle`. This one counts its invocations:

```js
let count = 0;
function handle(input) {
  if (input.length !== 32) throw new Error("counter takes no payload");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, count = (count + 1) >>> 0);
  return out;
}
```

Every invocation receives `[caller 32][payload]` and answers with the bytes it returns. The caller is the peer's key for a peer request, the calling app's id for a local call, and zeros for the host. Everything else goes through `await host.call(name, bytes)`: a method of a host service the manifest declares (`fs/get` under `fs`), another app's service id it declares, one of the bundle's own modules by bare name, or a `crypto/*` transform. A build step signs the guest into a bundle, and a host installs and invokes it; [CLIENT §1](docs/CLIENT.md#1-build-and-run-a-bundle) is the whole runnable program.

## The shape of it

An incoming request passes through the host and the transport bundle before reaching the app:

```
Host receives bytes from a socket
        ↓
Transport bundle decrypts the message
and identifies the sending peer
        ↓
Host routes by protocol to the app's guest,
including the sender identity supplied by the transport
        ↓
Guest handles the request,
calling its private WASM modules if needed
        ↓
Response returns through the transport bundle
for encryption, then through the host's socket
```

**Claims** decide which app receives what. A manifest claims the ids its app answers: `protocols` for requests from peers, `services` for calls from co-resident guests and the host. Each id has one owner, and routing is one lookup (§12.10): the transport has already authenticated and decoded the frame, so the host needs no wire parser or per-message signature scheme of its own. A guest calls another app's service id the way it calls a host service, by naming it in `guest.requires`. A claim grants no authority, but it selects which admitted app receives decrypted input (§14).

Guest limits bound individual requests; continuous peer traffic has no aggregate CPU guarantee ([execution and resource limits](docs/RUNTIME.md#123-zero-authority-js-realms), [trust boundaries](docs/SECURITY.md#14-security-considerations)).

## What belongs in the host

The host provides what a bundle cannot supply for itself; bundles implement everything else. The host writes bytes to a socket and decides which guest may use it; the transport bundle decides how to authenticate a peer and encrypt a message. The host stores bytes under opaque keys in a private namespace per app; the app defines its records, content hashes and encryption at rest. The host signs with the node's key, derived from a stored master seed, choosing the signing domain and the caller's scope without reading the payload. Because the host never interprets these bytes, bundles can change their wire and storage formats through a signed update while the host enforces the same boundaries. A bug in a bundle reaches only its own slot, never the host, the node key or another app.

The host is one signed blob, and the loader that runs it is the only code fixed when a node is deployed. Bundles can be replaced within a running host; they cannot replace the host.

## The transport is a bundle

The handshake, framing, record encryption and link routing run in a signed bundle, admitted by the same install path as any other app. The shipped transport opens each link with a mutually-authenticated hybrid X25519 + ML-KEM-768 handshake that conceals both identities, then seals every frame under forward-secret ChaCha20-Poly1305 keys, with the same protocol over TCP, WebSocket, WebRTC and UDP (QUIC) ([TRANSPORT](docs/TRANSPORT.md)). The node's signing key stays in the host.

This makes the **protocol replaceable without a fork**: a deployment can change its handshake, framing or dial policy by selecting a new transport bundle. A running node can atomically replace its transport, even across authors. An upgrade is a **reconnect**: the old links, session state and address book are discarded, and the embedder supplies peers in the replacement's configuration. The node keeps its listeners active (§12.10).

Choosing the transport grants it access to sockets, session keys and plaintext. The initial transport is selected at boot, and live changes must explicitly replace the current transport; ordinary app installation cannot acquire `link`. The transport must therefore be trusted with the traffic it handles ([SECURITY §14](docs/SECURITY.md#14-security-considerations)).

**The first transport ships inside the host artifact**; later versions arrive over the transport already running, like any other bundle. A node with no transport still runs apps, just without peers.

## What runs today

- **Three targets, one implementation.** Seedkernel runs in the browser, on Node or as a single native binary, with the same admission and confinement on each. Every target runs the same host blob and runs guests on the same QuickJS build, so nothing about the protocol is written twice ([one implementation, three targets](#one-implementation-three-targets)).
- **The native node is one 5.2 MiB file.** A cgo-free, cross-compiled Go binary: a loader with a wasm engine, carrying the host blob it starts with. The bulk is the wasm compiler backend and the Go runtime; the protocol's own footprint is tens of KiB ([RUNTIME §10.2, §12.9](docs/RUNTIME.md)).
- **The host updates itself, when the operator allows it.** An app can hand the host a newer host blob from the host author, fetched over the node's own network. The running host checks it as it checks an app bundle and hands it to the loader, which tries it once and commits it after a health window; one that fails first is dropped for the host it replaced (§12.9).
- **The engine is fast enough for real storage.** In seedstore's tested network configurations, transfer rate and latency dominated, not the engine ([seedstore's performance notes](https://github.com/arj03/seedstore/blob/main/docs/PERFORMANCE.md)).
- **Code really does arrive only as a bundle.** The chat demo installs its whole UI and logic at runtime, and so does [seedstore](https://github.com/arj03/seedstore), a real high performance storage layer.

## Post-quantum by role

Each cryptographic role is protected according to when a quantum attacker could use it. Every hybrid construction requires both halves, so the classical algorithm still protects each role if the post-quantum one turns out to be flawed while it is young ([SECURITY §14.1, §14.2](docs/SECURITY.md#141-cryptographic-suites-and-update-boundaries)).

| Role | Algorithm | Why |
| --- | --- | --- |
| Session keys | X25519 **+ ML-KEM-768** | Traffic recorded today must stay sealed against a future quantum computer ("harvest now, decrypt later"). Both identities travel under the same hybrid secret, so a recording does not reveal who talked either. |
| Bundle signatures | Ed25519 **+ ML-DSA-65** | A bundle is a long-lived artifact that spreads peer to peer. The author id is a hash over both public keys, so forging one half does not impersonate the author. |
| Peer authentication | Ed25519 | Verified live, during the handshake. A recorded handshake gives a future attacker nothing to forge; only one holding a quantum computer at connection time could impersonate a node. |
| App signatures (`node/sign`) | Ed25519 | Enough for anything verified once. An app that keeps signed records for years adds its own post-quantum signature or an external checkpoint inside the record (§14.2). |

This matches TLS, Signal (PQXDH) and OpenSSH: hybrid post-quantum key exchange, classical authentication, since post-quantum signatures cost kilobytes per handshake. Peer authentication can move to post-quantum later through an ordinary transport and host update, without a fork.

## One implementation, three targets

All three targets share bundle admission, policy and routing, and a networked node on any of them runs the same signed transport bundle. Each supplies its own platform adapters. The native binary embeds the shared JavaScript host and runs it in QuickJS. The tables separate shared code from platform code; `npm run loc` in `WASM/` computes the figures.

**Shared: one implementation for all three targets (3,917 LOC)**

The core, which every node runs:

| Concern | Where | LOC |
| --- | --- | --- |
| Bundle format, admission policy and resource limits (§12.4, §12.5, §4.1, §12.3), the module ABI (§4), the host blob, the check on a host's successor and the slots it is staged in (§12.9) | `host/bundle.ts`, `host/policy.ts`, `host/wasm-limits.ts`, `host/host-blob.ts`, `host/slots.ts`, `host/pure-module.ts` | 787 |
| Guest seam (§12.2): the call surface, which wires only the host services a node offers, and the serialized realm queue | `host/guest-seam.ts`, `host/realm-queue.ts` | 389 |
| Node assembly and claim routing (§12.8, §12.10): the boot assembly, which names the services a node offers, and the installed set and the claim books over it | `host/shell-core.ts`, `host/slot-table.ts` | 406 |
| Guest realms and the host's crypto (§12.3, §12.9): the realm driver over the platform's engine table, and libsodium and ML-DSA-65 on the same table | `host/engine-realm.ts`, `host/sodium-engine.ts`, `host/pq.ts` | 418 |
| The host's side of the platform ABI (§12.9): the ABI's types, the adapter from its primitives to `bootShell`, the host script's entry, and the Web globals QuickJS lacks | `host/platform.ts`, `host/abi.ts`, `host/host-main.ts`, `host/native-polyfills.ts` | 350 |
| The shared vocabulary: the `HOST_SERVICES` table and signing domains, the master-seed subkey derivation (§12.6.2b), the raw-link event codec (`host/op-frame.ts`, also available to clients) and byte helpers | `host/domains.ts`, `host/subkeys.ts`, `host/op-frame.ts`, `host/util.ts`, `host/utf8.ts` | 271 |

The host services (§12.2), one row each. A node offers `node` and `timer` always and the others only where `bootShell`'s `services` names them; the code ships either way. Their platform backends are per-target, below:

| Service | Where | LOC |
| --- | --- | --- |
| `node` and `timer`: signing under the calling slot's scope, and the realm's one replaceable wake | `services/node.ts`, `services/timer.ts` | 137 |
| `fs`: one app's scoped view, the key rule, and the one directory-backed store | `services/fs.ts`, `services/fs-files.ts` | 157 |
| `link`: the transport driver, channels by link id and listeners behind three socket events, and the datagram sockets the transport's UDP paths run over (§12.7); the socket contract, destination parsing and flood bounds. No protocol, no state machine, no address book, nothing peer-shaped | `services/link.ts`, `services/socket-seam.ts`, `services/datagrams.ts`, `services/peer-addr.ts`, `services/net-limits.ts` | 622 |
| `host`: hand the loader a successor host blob (§12.9) | `services/host.ts` | 10 |

The operator front-end, on Node and native only:

| Concern | Where | LOC |
| --- | --- | --- |
| Node startup, the operator flow (§12.8): the flag set and its defaults, which services and boot transport a node gets, the order it boots in, what it prints, and the control endpoint an `--op` reaches a serving node through | `host/cli.ts`, `host/control.ts` | 370 |

Sharing this code keeps admission and confinement rules consistent across targets. Platform adapters connect it to each target's I/O and execution engines.

**Per-target: the loaders and the platform backends**

| Target | What | LOC |
| --- | --- | --- |
| **JS** (browser + Node) | the Node platform (the platform ABI over `node:net`, `node:dgram` and `node:fs`) and the Node loader on it, the browser platform, the WebAssembly engine table, sockets (TCP and UDP on Node, WS and WebRTC wherever the runtime offers them), the `fs` backend, worker-backed private modules, Node's crypto seam, entry points | 1,058 TS |
| **Native** (Go) | the loader: the realm the shared host slots run in, QuickJS embedding, the event loop, the engine table over wazero with its bounded instances for private modules, raw net, fs and UDP | 1,497 Go |

The transport bundle sits outside these host totals: 3,002 lines of `transport/src/*.js` plus its private modules `ws.wasm`, `mlkem768.wasm` and `quic.wasm` (ngtcp2) (§12.7). The host's crypto, `libsodium.wasm` and `mldsa65.wasm`, ships inside the host blob, the same on every target.

## Build this repo

```sh
cd WASM
npm install
npm run build    # ws.wasm + the transport bundle + the shared host
npm test         # the full suite
```

This repo is the runtime only. Apps live outside it and consume `seedkernel-wasm`: [seedstore](https://github.com/arj03/seedstore) (a P2P storage node) and [seedshell](https://github.com/arj03/seedshell) (browser and headless shells hosting apps, the chat demo of §11 among them). `npm run build:browser` produces the browser artifacts they vendor. The relay they meet through is [seedrelay](https://github.com/arj03/seedrelay), a bundle a node runs as its transport.

## The rest of the spec

This file is §1; the rest of the spec lives in `docs/`, split by concern. README, PROTOCOL, RUNTIME, TRANSPORT and SECURITY share one global numbering of stable ids the source cites, so an unused number (§6–§9, §15) stays unused and a `(§X.Y)` reference resolves to exactly one of them. DESIGN mirrors RUNTIME's §12 numbers; CLIENT numbers its own sections and is cited by name (CLIENT §2):

| Doc | Sections | Contents |
| --- | --- | --- |
| [PROTOCOL](docs/PROTOCOL.md) | §2–§5, §16 | Bundle slots, atomic claim replacement, the restartable WASM module ABI, names and hashes, and protocol constants. |
| [RUNTIME](docs/RUNTIME.md) | §10–§12 | Distribution size, the app layer (chat as the worked example), and the host's normative surface: host services, the guest-seam ABI, zero-authority JS realms, signed bundles and how the host admits them under policy, the host's side of the node↔node transport, the Go/native binary, routing. Rules and ABI tables only, each stated once. |
| [DESIGN](docs/DESIGN.md) | §12 | Why RUNTIME §12 is shaped the way it is, under the same section numbers. |
| [TRANSPORT](docs/TRANSPORT.md) | §12.6.1–§12.6.3 | The shipped transport bundle, rules and rationale together: the concealed-identity handshake, records, half-open budgets, the contact secret, network key and peer list, configuration ops, relays, WebRTC and UDP paths, prior art, limits and the invariants its tests pin. |
| [SECURITY](docs/SECURITY.md) | §13–§14 | A byte-by-byte worked example and the collected trust model. |
| [CLIENT](docs/CLIENT.md) | — | How to write a bundle and the client that hosts it: a runnable first bundle, the manifest declarations an app adds as it grows, dependency setup, node boot, platform adapters, loading and invocation, browser integration traps, and the two existing clients as worked examples. Build guide, not protocol. |

To read the spec as one document, concatenate the files in that order: `cat README.md docs/{PROTOCOL,RUNTIME,TRANSPORT,SECURITY}.md`. DESIGN and CLIENT sit outside that sequence: the first is rationale, the second the guide to building on the runtime.

## Background

This project was inspired by the [8k-demo](https://github.com/ssbc/8k-demo) P2P project built on top of secure scuttlebutt running in the browser. The goal was to strip it down to the bare essentials and make the host as small as possible, moving functionality into bundles to be distributed in whatever fashion.
