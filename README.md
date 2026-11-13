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

Every invocation receives `[caller 32][payload]` and answers with the bytes it returns. The caller is the peer's key for a peer request, the calling app's id for a local call, and zeros for the host. Everything else goes through `await host.call(name, bytes)`: a method of a host service the manifest declares (`fs/get` under `fs`), another app's service id it declares, one of the bundle's own modules by bare name, or a `crypto/*` transform. A build step signs the guest into a bundle, and a host installs and invokes it; [CLIENT](docs/CLIENT.md#build-and-run-a-bundle) is the whole runnable program.

## The shape of it

An incoming request crosses the host twice: the host reads bytes off a socket, the transport bundle decrypts them and names the sending peer, and the host routes them by protocol to the app's guest, whose answer returns the same way ([ARCHITECTURE](docs/ARCHITECTURE.md#overview) has the layers, [SECURITY §13](docs/SECURITY.md#13-end-to-end-worked-example) the full trace).

**Claims** decide which app receives what. A manifest claims the ids its app answers: `protocols` for requests from peers, `services` for calls from co-resident guests and the host. Each id has one owner, and routing is one lookup (§12.10): the transport has already authenticated and decoded the frame, so the host needs no wire parser or per-message signature scheme of its own. A guest calls another app's service id the way it calls a host service, by naming it in `guest.requires`. A claim grants no authority, but it selects which admitted app receives decrypted input (§14).

Guest limits bound individual requests; continuous peer traffic has no aggregate CPU guarantee ([execution and resource limits](docs/GUEST.md#123-zero-authority-js-realms), [trust boundaries](docs/SECURITY.md#14-security-considerations)).

## What belongs in the host

The host provides what a bundle cannot supply for itself; bundles implement everything else. The host writes bytes to a socket and decides which guest may use it; the transport bundle decides how to authenticate a peer and encrypt a message. The host stores bytes under opaque keys in a private namespace per app; the app defines its records, content hashes and encryption at rest. The host signs with the node's key, derived from a stored master seed, choosing the signing domain and the caller's scope without reading the payload. Because the host never interprets these bytes, bundles can change their wire and storage formats through a signed update while the host enforces the same boundaries. A bug in a bundle reaches only its own slot, never the host, the node key or another app.

The host is one signed blob, and the loader that runs it is the only code fixed when a node is deployed. Bundles can be replaced within a running host; they cannot replace the host.

## The transport is a bundle

The handshake, framing, record encryption and link routing run in a signed bundle, admitted by the same install path as any other app. The shipped transport opens each link with a mutually-authenticated hybrid X25519 + ML-KEM-768 handshake that conceals both identities, then seals every frame under forward-secret ChaCha20-Poly1305 keys, with the same protocol over TCP, WebSocket, WebRTC and UDP (QUIC) ([TRANSPORT](docs/TRANSPORT.md)). The node's signing key stays in the host.

This makes the **protocol replaceable without a fork**: a deployment changes its handshake, framing or dial policy by selecting a new transport bundle, and a running node can replace its transport atomically, even across authors. An upgrade is a **reconnect**: listeners stay, while links, session state and the address book go with the old transport (§12.10). The first transport ships inside the host artifact; later versions arrive over the one already running. A node with no transport still runs apps, just without peers.

The transport holds sockets, session keys and plaintext, so it must be trusted with the traffic it handles. It is selected at boot or by explicitly replacing the current one; ordinary app installation cannot acquire `link` ([SECURITY §14](docs/SECURITY.md#14-security-considerations)).

## What runs today

- **Three targets, one implementation.** Seedkernel runs in the browser, on Node or as a single native binary, with the same admission and confinement on each. Every target runs the same host blob and runs guests on the same QuickJS build, so nothing about the protocol is written twice ([one implementation, three targets](#one-implementation-three-targets)).
- **The native node is one 5.2 MiB file.** A cgo-free, cross-compiled Go binary: a loader with a wasm engine, carrying the host blob it starts with. The wasm engine and the Go runtime are four fifths of it; the host blob, transport included, is 0.6 MiB gzipped (§10.2, [ARCHITECTURE §12.9](docs/ARCHITECTURE.md#129-loaders-and-the-host-blob)).
- **The host updates itself, when the operator allows it.** An app can hand the host a newer host blob from the host author, fetched over the node's own network. The running host checks it as it checks an app bundle and hands it to the loader, which tries it once and commits it after a health window; one that fails first is dropped for the host it replaced (§12.9).
- **The engine is fast enough for real storage.** In seedstore's tested network configurations, transfer rate and latency dominated, not the engine ([seedstore's performance notes](https://github.com/arj03/seedstore/blob/main/docs/PERFORMANCE.md)).
- **Code really does arrive only as a bundle.** [seedshell](https://github.com/arj03/seedshell)'s chat app installs its whole UI and logic at runtime, and [seedstore](https://github.com/arj03/seedstore)'s storage node is the host plus a signed bundle.

## Post-quantum by role

Each cryptographic role is protected according to when a quantum attacker could use it. What a recording could later break is hybrid: session keys are X25519 + ML-KEM-768, which also conceals both identities, and bundle signatures are Ed25519 + ML-DSA-65, with both halves required. What is verified live stays classical: peer authentication and `node/sign` are Ed25519, as in TLS, Signal (PQXDH) and OpenSSH, since post-quantum signatures cost kilobytes per handshake. An app that keeps signed records for years adds its own post-quantum signature. The table and the reasoning are [SECURITY §14.1 and §14.2](docs/SECURITY.md#141-cryptographic-suites-and-update-boundaries).

## 10. Performance

The message path does no asymmetric cryptography: routing a frame is one AEAD open, one claim lookup and one guest invocation (§13). Public-key cryptography runs per link, in the handshake, and per bundle load, where one BLAKE2b-256 hash and both manifest signatures are checked (§12.4). The host's libsodium and ML-DSA-65 ship in the host blob and run on the platform's wasm engine on every target (§12.9); ML-KEM-768 and QUIC are the transport bundle's own modules.

Application throughput is the apps' to measure: seedstore keeps its figures in [its performance notes](https://github.com/arj03/seedstore/blob/main/docs/PERFORMANCE.md). The native target's `*_bench_test.go` benchmarks cover the host's hot paths.

### 10.2 Distribution Size

Native and Node:

| Component | Size |
|---|---|
| **Host blob** (`build/host.skb`), which the native and Node loaders run | 1.43 MiB |
| of which the host script (`build/host.js`) | 222 KiB |
| of which `qjs.wasm`, the realm engine, built for size | 624 KiB |
| of which `libsodium.wasm` | 217 KiB |
| of which `mldsa65.wasm` | 16 KiB |
| of which the transport bundle (`build/transport.skb`): its guest, `ws.wasm`, `mlkem768.wasm` (12 KiB) and `quic.wasm` (247 KiB) | 378 KiB |
| **Native binary** per `GOOS`/`GOARCH`, built with `-tags wazero_nointerp,wazero_nodwarf -ldflags="-s -w"`: wazero with its compiler backend (~2.9 MiB), the Go runtime (~1.3 MiB), the host blob above, gzipped (~0.6 MiB), and the loader itself (~0.4 MiB) | ~5.2 MiB |

Browser:

| Component | Size |
|---|---|
| **Web host blob** (`build/host-web.skb`): no script, since a page imports the host, and a 132 KiB transport without `quic.wasm` | 994 KiB |
| Host modules a page imports beside it, minified (`build-min`) | ~142 KiB |
| **Total browser deployment** | **~1.11 MiB (~470 KiB gzipped)** |

## One implementation, three targets

All three targets share bundle admission, policy and routing, and a networked node on any of them runs the same signed transport bundle; each supplies only its own platform adapters. `npm run loc` in `WASM/` computes these figures and fails on drift.

| Code | What | LOC |
| --- | --- | --- |
| **Shared** (all three targets) | bundle format and admission, resource limits, the module ABI, the host blob and its slots, the guest seam and realm queue, node assembly and claim routing, guest realms, the host's crypto, the host's side of the platform ABI, the host services (`node`, `timer`, `fs`, `link`, `host`), the CLI and its control endpoint (Node and native) | 3,922 TS |
| **JS** (browser + Node) | the Node platform and loader, the browser platform, the WebAssembly engine table, sockets, the `fs` backend, worker-backed modules, entry points | 1,058 TS |
| **Native** (Go) | the loader: QuickJS embedding, the event loop, the engine table over wazero, raw net, fs and UDP | 1,508 Go |

The transport bundle sits outside these totals: 3,013 lines of `transport/src/*.js` plus its private modules `ws.wasm`, `mlkem768.wasm` and `quic.wasm` (ngtcp2).

## Build this repo

```sh
cd WASM
npm install
npm run build    # ws.wasm + the transport bundle + the shared host
npm test         # the full suite
```

This repo is the runtime only. Apps live outside it and consume `seedkernel-wasm`: [seedstore](https://github.com/arj03/seedstore) (a P2P storage node) and [seedshell](https://github.com/arj03/seedshell) (browser and headless shells hosting apps, a chat app among them). `npm run build:browser` produces the browser artifacts they vendor. The relay they meet through is [seedrelay](https://github.com/arj03/seedrelay), a bundle a node runs as its transport.

## The rest of the spec

This file is §1 and §10; the rest lives in `docs/`, one file per reader. Section numbers are stable ids the source cites, global across the files, so a `(§X.Y)` reference resolves to exactly one of them wherever it sits, and an unused number stays unused. Three surfaces are exact, because something outside this codebase must match them byte for byte: the wire (TRANSPORT), bundle bytes (BUNDLE) and the guest and module ABI (GUEST, BUNDLE). Everything else is design, stated with its reason.

| Doc | Reader | Sections | Contents |
| --- | --- | --- | --- |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | everyone, read end to end | §2, §3, §5, §12, §12.6.2b, §16.1 | How the host is structured and why: messages, slots, names, the resource laws, host services, the transport's place, the node identity, loaders and the host blob, routing, and the host constants. |
| [BUNDLE](docs/BUNDLE.md) | bundle author, signer | §3.1, §4, §12.4, §12.5, §16 | The signed envelope and manifest, admission and revocation, atomic loading, and the WASM module ABI. |
| [GUEST](docs/GUEST.md) | guest author, transport author | §12.2, §12.3 | Every name a guest calls and its bytes, the host events, and the realm and its bounds. |
| [TRANSPORT](docs/TRANSPORT.md) | peer implementer | §12.6.1, §12.6.2, §12.6.3 | The shipped transport's wire: framing, the handshake, records, requests, secrets, relays, direct paths and QUIC, with limits and prior art. |
| [SECURITY](docs/SECURITY.md) | auditor | §13, §14 | A message traced through a node, the trust model, and the cryptography's post-quantum exposure. |
| [CLIENT](docs/CLIENT.md) | embedder, operator | §12.8 | A runnable first bundle, booting a node, the CLI, the entry points and the browser. |

To read the spec as one document: `cat README.md docs/{ARCHITECTURE,BUNDLE,GUEST,TRANSPORT,SECURITY,CLIENT}.md`.

## Glossary

- **Host**: the runtime, one signed host blob a small loader runs (§12.9).
- **Loader**: the only code fixed at deployment: the native binary, the Node loader, or a page importing the host.
- **Bundle**: a signed app: manifest, guest and modules (§12.4).
- **Slot**: an installed bundle's private code, state and storage, keyed by its app label (§3).
- **Guest**: a bundle's JS program, confined in its own realm (§12.3).
- **Module**: a bundle's private WASM transform, with no imports (§4).
- **Host service**: what a guest can reach only through the host: `node`, `fs`, `timer`, `link`, `host` (§12.1).
- **Claim**: a protocol id or service id a manifest says its app answers (§12.10).
- **Transport**: the bundle holding `link`, the node's sockets; it runs the channel (§12.6).
- **Link occupant**: the slot holding `link`, normally the transport.
- **Shell**: what an embedder drives a node through, from `bootShell` (§12.8).
- **Peer id**: a node's Ed25519 public key, derived from its master seed (§12.6.2b).
- **Contact secret**: the per-node secret a caller must hold to reach a node (§12.6.3).
- **Author id**: the hash of an author's two public keys, which policy names (§12.4).

## Background

This project was inspired by the [8k-demo](https://github.com/ssbc/8k-demo) P2P project built on top of secure scuttlebutt running in the browser. The goal was to strip it down to the bare essentials and make the host as small as possible, moving functionality into bundles to be distributed in whatever fashion.
