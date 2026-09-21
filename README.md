# Seed kernel: a sandboxed app runtime that grows from signed bundles

Seedkernel runs signed apps in a sandbox (JavaScript or WebAssembly) across browsers, Node and a small native executable. It gives an app controlled access to storage and to authenticated, encrypted peer connections. Apps extends a minimal kernel and arrives only as a signed bundle.

That suits three kinds of work:

- **Hosting third-party extensions.** The operator controls which authors can install code and what each extension can access. Extensions run in isolated slots without direct access to the host's file system, sockets or process.
- **Distributing app updates as signed bundles.** A release is one blob — manifest, guest and modules under hybrid author signatures — verified at admission, checked against a version floor, and landed as one atomic slot commit. Updates travel over the same peer network as app data. The runtime verifies the author's signatures without needing to trust the peer delivering the bundle.
- **Building peer applications on a shared runtime.** [seed store](https://github.com/arj03/seedstore) and [seedchat](https://github.com/arj03/seedchat) get the same guest seam, the same authenticated channel and the same storage interface in a browser tab, on a Node CLI and inside the native binary.

**Build an app: [Writing bundles and clients](docs/CLIENT.md).** For scale, seedchat's guest is a couple of dozen lines of app logic over a small AssemblyScript text handler, while seedstore's storage orchestration runs to roughly a thousand — neither implements the channel handshake or the bundle verifier. [The guide](docs/CLIENT.md#how-much-code) breaks that down and includes a runnable first bundle.

## What it costs

- **More machinery than you need** for an ordinary web app, a single-purpose server, or anything whose author and operator are the same party. A process boundary or a container is the cheaper answer there.
- **A guest is not a Node or browser environment.** It has ECMAScript intrinsics, four injected globals and one `host.call` seam — no Node APIs, no DOM, no `fetch`, no runtime package imports. Dependencies have to be bundled into flat guest source and must not want any of those. Execution is serialized per realm and bounded in heap and time, so bursty or long work has to fit the deployment's budget ([CLIENT](docs/CLIENT.md#add-only-the-interfaces-your-app-needs)).
- **You still write everything above the runtime.** Authorization rules, data model and persistence design, recovery after a realm is discarded, user key management, and the whole UI. What Seedkernel saves you is the runtime and transport plumbing.

## Status

Beta: it works, on all three targets, and everything measured below was measured on running code — but the only apps exercising it are [seed store](https://github.com/arj03/seedstore) and [seedchat](https://github.com/arj03/seedchat), written alongside it. The guest seam, bundle format and channel suite still change, and a change there means re-signing an app's bundles. There has been no external audit, and no cryptographer has reviewed the design ([SECURITY §14.2](docs/SECURITY.md#142-post-quantum-exposure-and-remaining-limits)); constant-time behaviour of the built post-quantum paths is an open item, since passing functional vectors does not establish it. Treat the security properties as design intent, not as verified.

## What runs today

- **Three targets, one implementation.** Seedkernel runs in the browser, on Node/Bun or as a single native binary. A large part of the implementation is shared between all platforms including a transport bundle and crypto blobs. Nothing about the protocol is written twice ([one implementation, three targets](#one-implementation-three-targets)).
- **The native node is one 7.5 MB file.** A cgo-free, cross-compiled Go binary with embedded QuickJS and a wasm engine. It is a tenth of what a Bun binary alone costs (~70 MB). The bulk is the wasm compiler backend and the Go runtime; the protocol's own footprint is tens of KB ([RUNTIME §10.2, §12.9](docs/RUNTIME.md)).
- **Bundles are sandboxed on every target.** Modules receive no I/O capabilities. A guest can access only the host services and local calls declared in its signed manifest, its private modules, and a fixed set of host transforms. Native deadline checks added 7–21% to execution time on the tested storage transforms; JS targets incur a worker round trip per module call ([SECURITY §14](docs/SECURITY.md)).
- **Confinement has workload-dependent overhead.** The measured storage workload encrypts, hashes and RS-encodes at ~186 MiB/s on one thread and reads back at ~2.6 GiB/s. Its tested network configurations were limited by transfer rate and latency ([the overhead, measured](#the-overhead-measured)).
- **Network buffers have explicit limits.** Socket write backlogs, reads waiting on a busy guest, and queued signaling messages are bounded by both byte size and item count. Data remains accounted for as it moves between buffers. The host pauses reads where possible; when limits are exceeded, it drops signaling messages or closes the affected link ([every host-side byte has an owner](#the-shape-of-it)).
- **Code really does arrive only as a bundle.** Even the transport is one, so that it can be upgraded: it opens each link with a mutually-authenticated hybrid X25519 + ML-KEM-768 handshake that conceals both identities, then carries every frame as a forward-secret ChaCha20-Poly1305 record — the same protocol over TCP, WebSocket and WebRTC. It does not rely on TLS for its security properties, although WSS and WebRTC add TLS/DTLS underneath ([CHANNEL](docs/CHANNEL.md)). The chat demo installs its whole UI and logic at runtime, and so does [seed store](https://github.com/arj03/seedstore), a real high performance storage layer.
- **Bundles are post-quantum signed.** The manifest suite is hybrid Ed25519 + ML-DSA-65. The host includes the verifier and requires both signatures before accepting a bundle.
- **Channels combine hybrid key establishment with Ed25519 authentication.** X25519 + ML-KEM-768 protects recorded traffic under the hybrid scheme's assumptions. Breaking Ed25519 later does not reveal earlier session keys, but peer authentication must be upgraded before attackers can forge live handshakes. That requires updating the host's signing interface and the transport bundle. The runtime's `node/sign` operation also remains Ed25519; long-lived signed app records need separate consideration ([security limits](docs/SECURITY.md#142-post-quantum-exposure-and-remaining-limits)).

## 1. The model

The model has two parts, a host and the bundles it admits:

| Component | Role |
| --- | --- |
| **Host** | The runtime outside installed bundles: shared JS plus platform adapters (§12.9). It admits bundles, confines execution, routes calls, and owns sockets, storage, entropy, the clock, and the node identity key. |
| **Bundle** | The unit of installation (§12.4) and the app itself: a manifest, a guest JS program, optional WASM modules, and hybrid author signatures over the whole set. The host checks policy (§12.5), builds a private slot, and atomically replaces its claims. The transport uses this same format. |
| ↳ **Guest** | The app's state and logic in a JS realm with no ambient authority (§12.2). Its interface is `host.call(name, …)` out and `handle(bytes)` in. Invocations are serialized per realm and bounded in heap, execution, and handoff time (§12.3). |
| ↳ **Modules** | The app's private library of restartable WASM transforms (§4), called by bare name through its guest. They have three required exports and **no capability imports**, only the fixed inert language-runtime shims in §4.2. The host stages input at `scratch`, calls `handle`, and reads the result. Modules have no I/O and no public routing claims, and their names are private to the slot rather than entries in a shared namespace (§3). |

The operator chooses which authors may install code and which capabilities they may receive; the host enforces those grants at admission and at the guest seam. Application-level authorization and behaviour live in the bundles.

There is one app shape, one install path (§12.4), one guest seam (§12.2) and one post-handshake frame plane (§12.6). The transport uses all four like any other app: it reaches sockets by name, and it is reached — by the host and by every app — through the protocol id it claims.

The transport authenticates and decodes incoming frames before handing them to host dispatch. Dispatch then resolves the protocol claim and invokes the app's guest (§12.10); it needs no separate wire parser or per-message signature scheme.

## What belongs in the core

The **core provides platform capabilities**, the **host manages bundle execution**, and **bundles implement application behaviour**. The core is part of the host; bundles run under the host's control.

| Level | Responsibility |
| --- | --- |
| **Core** | Access to resources a confined app cannot obtain for itself: sockets, storage, entropy, time, and signing with the node's private key. It moves raw bytes, protects the key, and enforces limits on the resources it holds (§12.1). |
| **Host** | The full runtime outside installed bundles, including the core. It shares code for admission, policy enforcement, the guest call interface and routing across Node, browser and native targets, with adapters for platform-specific operations. It starts the node, verifies and admits bundles, builds their private slots, and confines execution through its sandbox engines and platform adapters. |
| **Bundles** | Signed, replaceable apps: a manifest, one JS guest and optional private WASM modules. They implement protocols, data formats and application policy using the capabilities the host grants them. The transport is a bundle too. |

These responsibilities put different work in each level. The core writes bytes to a socket; the host decides which installed guest can use that socket capability; the transport bundle decides how to authenticate a peer and encrypt a message. For storage, the core reads and writes bytes under opaque keys, the host gives each app a private namespace, and the app defines its records, content hashes and encryption at rest.

The core stays small because it supplies facilities an app cannot create inside its sandbox. The rest of the host supplies the machinery needed to install and run apps safely: a bundle cannot verify its own admission or enforce its own confinement. Functionality that can operate within those boundaries belongs in bundles, where it can change through a signed update.

The core and the rest of the host are deployed together. Upgrading either requires building and deploying a new host version. Bundles can be replaced within a running host; they cannot upgrade the host itself.

Core interfaces leave application meaning to bundles. `link` uses opaque link ids, and `fs` uses flat storage keys. A signing request uses the node's private key, derived from a stored master seed; the host selects the signing domain and the caller's scope without interpreting the payload. This lets bundles change their wire and storage formats while the host continues to enforce the same boundaries.

The fixed `crypto/*` transforms are a compatibility and performance exception. They reuse primitives already shipped with the host, avoiding duplicate implementations and extra module calls on existing paths. New computation ships in the bundle that needs it.

## The transport is a bundle

The handshake, framing, record encryption and link routing run in a signed bundle, admitted by the same loader as any other app. Its **guest** holds session state across calls and reaches sockets through the host. The node's private signing key stays in the host. Computation runs in the bundle's private WASM modules: RFC 6455 framing in `ws.wasm` and ML-KEM-768 in `mlkem768.wasm`.

This makes the **protocol replaceable without a fork**: a deployment can change its handshake, framing or dial policy by selecting a new transport bundle. A running node can atomically replace its transport, even across authors. An upgrade is a **reconnect**: the old links, session state and address book are discarded, and the embedder supplies peers in the replacement's configuration. The node keeps its listeners active (§12.10).

Choosing the transport grants it access to sockets, session keys and plaintext. The initial transport is selected at boot, and live changes must explicitly replace the current transport; ordinary app installation cannot acquire `link`. The transport must therefore be trusted with the traffic it handles ([SECURITY §14](docs/SECURITY.md#14-security-considerations)).

**The first transport ships inside the host artifact**, because a node needs a transport before it can fetch anything. Later versions can arrive over the transport already running, like any other bundle.

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

The application and transport are both bundles. The host runs them in separate slots and controls their access to its facilities:

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
+------------------------------------------------------+
| Core — part of the host                              |
| Raw I/O, resource limits, entropy, time and signing  |
+------------------------------------------------------+
```

The host limits guest access, execution time and retained memory. Buffered data remains accounted for as it passes between components. These limits bound individual requests, but continuous peer traffic has no aggregate CPU guarantee. The transport authenticates the immediate peer; apps that relay messages must establish the original author's identity themselves. See [execution and resource limits](docs/RUNTIME.md#123-zero-authority-js-realms) and [trust boundaries](docs/SECURITY.md#14-security-considerations).

## One implementation, three targets

All three targets share bundle admission, policy and routing, and run the same signed transport bundle. Each supplies its own platform adapters. The native binary embeds the shared JavaScript host and runs it in QuickJS. The tables separate shared code from platform code; `npm run loc` in `WASM/` computes the figures.

**Shared — compiled once, run by all three targets (2,347 LOC)**

| Concern | Where | LOC |
| --- | --- | --- |
| Bundle format and admission policy (§12.4, §12.5) | `host/bundle.ts`, `host/policy.ts` | 337 |
| Transport driver — channels by link id and listeners, behind three socket events. No protocol, no state machine, no address book, nothing peer-shaped | `host/transport-host.ts` | 332 |
| Guest seam — the guest ABI seam (§12.2): the call surface, the serialized realm queue, the realm wake and an app's `fs` view | `host/guest-seam.ts`, `host/realm-queue.ts`, `host/realm-timers.ts`, `host/fs-view.ts` | 643 |
| Shell, node assembly and claim routing (§12.9, §12.10) — the boot assembly, and the installed set with the two claim books that route into it | `host/shell-core.ts`, `host/slot-table.ts` | 369 |
| Node startup — the operator flow: the flag set and its defaults, the order a node boots in (§12.5), what it prints | `host/cli.ts`, `host/peer-addr.ts` | 251 |
| Core contracts and fixed host vocabulary — the socket/`fs` contracts, the key space and flood bounds, domain prefixes, the master-seed subkey derivation (§12.6.2b), the manifest suite id, host-call names and raw-link event codec (`core/op-frame.ts`, also available to clients) | `core/*.ts` (8 files) | 415 |

Sharing this code keeps admission and confinement rules consistent across targets. Platform adapters connect it to each target's I/O and execution engines.

**Per-target platform — the seam, written once per target**

| Target | What | LOC |
| --- | --- | --- |
| **JS** (browser + Node) | sockets (TCP/WS/WebRTC), the `fs` backend, safe-js realms, worker-backed private modules, manifest-verifier plumbing, entry points, key derivation | 1,483 TS |
| **Native** (Go) | QuickJS embedding, event loop, libsodium and private modules over wazero, raw net and fs — plus `native-shim.ts` (296) and `native-polyfills.ts` (67), both TypeScript and riding in the shared bundle | 2,240 Go + 363 TS |

The transport bundle sits outside these host totals: 1,471 lines of `transport/src/*.js` plus a 5 KB `ws.wasm`. It handles TCP framing and RFC 6455 across the targets that support those transports.

All targets carry the same `libsodium.wasm` and `mldsa65.wasm` host artifacts, including verification for manifest suite `0x02`. They also run the same `mlkem768.wasm`, delivered inside the signed transport bundle as a private module. Native runs these WASM artifacts through wazero.

## The overhead, measured

The [seed store](https://github.com/arj03/seedstore) measurements below describe specific workloads, not a general throughput guarantee. Native deadline checks measured 1.07–1.21× execution time on the tested transforms; JS module calls added a worker hop of ~30 µs for small calls and ~160 µs for a 64 KiB transfer both ways (§14). That fixed hop can dominate small transforms; larger calls amortize it, and transfer rate and latency dominated the network configurations measured below:

- **The compute-only write pipeline — encrypt, name every block, RS-encode — measured 177–189 MiB/s** in three runs on 2026-09-17 (100 MiB, RS(10,6), 64 KiB blocks, Node 20.11.1). ChaCha20-Poly1305 sealing measured 393–395 MiB/s, author-bound BLAKE2b block IDs 720–733 MiB/s, and SIMD RS encode 1,447–1,482 MiB/s. This benchmark calls host crypto and the codec directly; it does not measure guest scheduling, signing, storage, or transport overhead.
- **A read with every block present needs no GF(2⁸) work:** the compute benchmark's concatenation measured 2,339–2,926 MiB/s; reconstructing one missing block measured 1,465–1,682 MiB/s in those runs. These are component measurements, not complete GET rates.
- **End-to-end throughput depends on framing and concurrency:** three fresh-process runs measured 7.6–8.2 MiB/s PUT and 15.7–16.9 MiB/s GET over a modelled 10 ms request/response RTT (4 MiB, RS(2,2), 32 KiB blocks, 256 KiB logical message cap split into 48 KiB physical chunks, fanoutWindow 32). These runs use the signed transport bundle over an in-process latency fabric, not a bandwidth-limited physical WebRTC link.
- **Seedstore's codec, reputation module, and guest total ~14 KiB of WASM plus ~15 KiB of gzipped guest JS**, excluding the shared kernel and bundle metadata. They reuse the libsodium the runtime already loads rather than bundling a second copy of a crypto library. From seedstore's `WASM/` directory, `node tests/bench.mjs` measures compute and `node tests/bench-net.mjs 10 4 32 256 48 32` measures the framed PUT/GET configuration in a fresh process (omit the final `32` for a fanout sweep). The old `node tests/bench-net.mjs 10 4 32` command explicitly defaults to a 48 KiB logical cap, regardless of application default changes. Rates above use binary MiB even though the scripts label them MB. Rebuild with `npm run build` before comparing changed seedstore sources.

## Build this repo

```sh
cd WASM
npm install
npm run build    # ws.wasm + the transport bundle + the shared host
npm test         # the full suite
```

This repo is the runtime only. Apps live outside it and consume the published surface of `seedkernel-wasm`: [seed store](https://github.com/arj03/seedstore) (a P2P storage node) and [seedchat](https://github.com/arj03/seedchat) (the browser P2P chat demo, §11). `npm run build:browser` produces the browser artifacts they vendor. The WebRTC signaling rendezvous both use is a deployment concern rather than runtime surface, so it lives with the apps — `npm run relay` in seedchat, which seed store also points at — and its kernel seam carries only opaque encoded strings, never JavaScript message objects.

## The rest of the spec

This file is §1; the rest of the spec lives in `docs/`, split by concern. Section numbers are global across the set — any `(§X.Y)` reference resolves to exactly one file:

| Doc | Sections | Contents |
| --- | --- | --- |
| [PROTOCOL](docs/PROTOCOL.md) | §2–§5, §16 | Bundle slots, atomic claim replacement, the restartable WASM module ABI, layering, and protocol constants. |
| [RUNTIME](docs/RUNTIME.md) | §10–§12 | Distribution size, the app layer (chat as the worked example), and the shell: capability backends, the guest-seam ABI, zero-authority JS realms, signed bundles and how the loader admits them under policy, the node↔node transport, the Go/native binary. |
| [SECURITY](docs/SECURITY.md) | §13–§14 | A byte-by-byte worked example and the collected trust model. |
| [CHANNEL](docs/CHANNEL.md) | §12.6.2 | The concealed-identity channel handshake: what the four messages do, the three secrets and their different jobs, why one identity key signs for both purposes, and where the design sits against Noise, WireGuard and Secret Handshake. Normative text stays in RUNTIME §12.6; this is the *why*. |
| [CLIENT](docs/CLIENT.md) | — | How to write a bundle and the client that hosts it: a runnable first bundle, the manifest declarations an app adds as it grows, dependency setup, node boot, platform adapters, loading and invocation, browser integration traps, and the two existing clients as worked examples. Build guide, not protocol. |

To read the spec as one document, concatenate the files in that order: `cat README.md docs/{PROTOCOL,RUNTIME,SECURITY}.md`. CHANNEL and CLIENT sit outside that sequence — one is rationale, the other the guide to building on the runtime.

## 15. Background

This project was inspired by the [8k-demo](https://github.com/ssbc/8k-demo) P2P project built on top of secure scuttlebutt running in the browser. The goal was to strip it down to the bare essentials and make the core as small as possible, moving functionality into modules to be distributed in whatever fashion.
