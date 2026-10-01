# seedkernel: a sandboxed host that grows from apps

Seedkernel runs signed apps in a sandbox (JavaScript or WebAssembly) across browsers, Node and a small native executable. It gives an app controlled access to storage and to authenticated, encrypted peer connections. Every app, the transport included, arrives as a signed bundle on top of a minimal host.

That suits three kinds of work:

- **Hosting third-party extensions.** The operator controls which authors can install code and what each extension can access. Extensions run in isolated slots without direct access to the host's file system, sockets or process.
- **Distributing app updates as signed bundles.** A release is one blob (manifest, guest and modules under hybrid author signatures), verified at admission, checked against a version floor, and landed as one atomic slot commit. Updates travel over the same peer network as app data. The runtime verifies the author's signatures without needing to trust the peer delivering the bundle.
- **Building peer applications on a shared runtime.** [seedstore](https://github.com/arj03/seedstore) and [seedchat](https://github.com/arj03/seedchat) get the same guest seam, the same authenticated channel and the same storage interface in a browser tab, on a Node CLI and inside the native binary.

**Build an app: [Writing bundles and clients](docs/CLIENT.md).** For scale, seedchat's guest is a couple of dozen lines of app logic over a small AssemblyScript text handler, while seedstore's storage orchestration runs to roughly a thousand. Neither implements the channel handshake or the bundle verifier. [The guide](docs/CLIENT.md#how-much-code) breaks that down and includes a runnable first bundle.

## What it costs

- **More machinery than you need** for an ordinary web app, a single-purpose server, or anything whose author and operator are the same party. A process boundary or a container is the cheaper answer there.
- **A guest is not a Node or browser environment.** It has ECMAScript intrinsics, four injected globals and one `host.call` seam: no Node APIs, no DOM, no `fetch`, no runtime package imports. Dependencies have to be bundled into flat guest source and must not want any of those. Execution is serialized per realm and bounded in heap and time, so bursty or long work has to fit the deployment's budget ([CLIENT](docs/CLIENT.md#add-only-the-interfaces-your-app-needs)).
- **You still write everything above the runtime.** Authorization rules, data model and persistence design, recovery after a realm is discarded, user key management, and the whole UI. What Seedkernel saves you is the runtime and transport plumbing.

## Status

Beta: it works on all three targets, and everything measured below was measured on running code, but the only apps exercising it are [seedstore](https://github.com/arj03/seedstore) and [seedchat](https://github.com/arj03/seedchat), written alongside it. The guest seam, bundle format and channel suite still change, and a change there means re-signing an app's bundles.

There has been no external audit, and no cryptographer has reviewed the design ([SECURITY §14.2](docs/SECURITY.md#142-post-quantum-exposure-and-remaining-limits)); constant-time behaviour of the built post-quantum paths is an open item, since passing functional vectors does not establish it. Peer authentication and `node/sign` are Ed25519 alone: breaking Ed25519 later would not reveal earlier session keys, which rest on the hybrid X25519 + ML-KEM-768 exchange, but it would let an attacker forge live handshakes until the host's signing interface and the transport bundle are upgraded, and long-lived signed app records need separate consideration. Treat the security properties as design intent, not as verified.

## 1. The model

The model has two parts, a host and the bundles it admits. The host runs each bundle in its own slot and controls its access to the host's facilities:

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
| **Host** | The runtime outside installed bundles: shared JS plus platform adapters, deployed as one artifact per target (§12.9). It verifies and admits bundles, builds their private slots, confines execution through its sandbox engines, and routes calls. A bundle cannot verify its own admission or enforce its own confinement, so this is the host's job. |
| ↳ **Host services** | What a confined app cannot obtain for itself, the `HOST_SERVICES` set (§12.1): `node` (signing with the node's private key), `fs` (storage), `timer` (the realm's wake) and `link` (sockets). They move raw bytes under opaque link ids and storage keys, protect the key, and enforce limits on the resources they hold. A guest reaches only the services its signed manifest declares. |
| **Bundle** | The unit of installation (§12.4) and the app itself: a manifest, a guest JS program, optional WASM modules, and hybrid author signatures over the whole set. The host checks policy (§12.5), builds a private slot, and atomically replaces its claims. |
| ↳ **Guest** | The app's state and logic in a JS realm with no ambient authority (§12.2). Its interface is `host.call(name, …)` out and `handle(bytes)` in. Invocations are serialized per realm and bounded in heap, execution, and handoff time (§12.3). |
| ↳ **Modules** | The app's private library of restartable WASM transforms (§4), called by bare name through its guest. They have three required exports and **no host imports**, only the fixed inert language-runtime shims in §4.2. The host stages input at `scratch`, calls `handle`, and reads the result. Modules have no I/O and no public routing claims, and their names are private to the slot rather than entries in a shared namespace (§3). |

**Claims** decide which app receives what. A manifest claims the ids its app answers: `protocols` for requests from peers, `services` for calls from co-resident guests and the host. Each id has one owner, and routing is one lookup (§12.10). A guest calls another app's service id the way it calls a host service, by naming it in `guest.requires`. A claim grants no authority, but it selects which admitted app receives decrypted input (§14).

The operator chooses which authors may install code and which host services they may receive; the host enforces those grants at admission and at the guest seam. Application-level authorization and behaviour live in the bundles.

There is one app shape, one install path (§12.4), one guest seam (§12.2) and one post-handshake frame plane (§12.6). The transport uses all four like any other app: it reaches sockets by name, and the host and every app reach it through the local service id it claims (§12.10).

**Names.** *Seedkernel* is the project; *the host* is the runtime it builds. The host offers *host services* to guests and a *shell* to whoever embeds it: `bootShell` (§12.8) returns the `Shell` handle a client or the CLI uses to install, call, revoke and close. The native binary (§12.9) is the same host in one executable. The source follows the table: `WASM/services/` holds the host services (the `HOST_SERVICES` table, their contracts and their platform backends), and `WASM/host/` holds admission, confinement, routing and the shell. `host/` imports `services/`, never the reverse.

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

Routing is one protocol-claim lookup (§12.10): the transport has already authenticated and decoded the frame, so the host needs no wire parser or per-message signature scheme of its own.

The host limits guest access, execution time and retained memory. These limits bound individual requests, but continuous peer traffic has no aggregate CPU guarantee. The transport authenticates the immediate peer; apps that relay messages must establish the original author's identity themselves. See [execution and resource limits](docs/RUNTIME.md#123-zero-authority-js-realms) and [trust boundaries](docs/SECURITY.md#14-security-considerations).

## What belongs in the host

The host provides what a bundle cannot supply for itself; bundles implement everything else. The host writes bytes to a socket, and decides which installed guest may use that socket; the transport bundle decides how to authenticate a peer and encrypt a message. For storage, the host reads and writes bytes under opaque keys and gives each app a private namespace; the app defines its records, content hashes and encryption at rest.

Host services leave application meaning to bundles. `link` uses opaque link ids, and `fs` uses flat storage keys. A signing request uses the node's private key, derived from a stored master seed; the host selects the signing domain and the caller's scope without interpreting the payload. This lets bundles change their wire and storage formats while the host continues to enforce the same boundaries. Functionality that can operate within those boundaries belongs in bundles, where it can change through a signed update.

The host is one deployed artifact: upgrading it means building and deploying a new host version. Bundles can be replaced within a running host; they cannot upgrade the host itself.

The fixed `crypto/*` transforms are a compatibility and performance exception. They reuse primitives already shipped with the host, avoiding duplicate implementations and extra module calls on existing paths. New computation ships in the bundle that needs it.

## The transport is a bundle

The handshake, framing, record encryption and link routing run in a signed bundle, admitted by the same install path as any other app. The shipped transport opens each link with a mutually-authenticated hybrid X25519 + ML-KEM-768 handshake that conceals both identities, then carries every frame as a forward-secret ChaCha20-Poly1305 record. The protocol is the same over TCP, WebSocket and WebRTC, and does not rely on TLS for its security properties, although WSS and WebRTC add TLS/DTLS underneath ([CHANNEL](docs/CHANNEL.md)).

Its **guest** holds session state across calls and reaches sockets through the host; the node's private signing key stays in the host. Computation runs in the bundle's private WASM modules: RFC 6455 framing in `ws.wasm` and ML-KEM-768 in `mlkem768.wasm`.

This makes the **protocol replaceable without a fork**: a deployment can change its handshake, framing or dial policy by selecting a new transport bundle. A running node can atomically replace its transport, even across authors. An upgrade is a **reconnect**: the old links, session state and address book are discarded, and the embedder supplies peers in the replacement's configuration. The node keeps its listeners active (§12.10).

Choosing the transport grants it access to sockets, session keys and plaintext. The initial transport is selected at boot, and live changes must explicitly replace the current transport; ordinary app installation cannot acquire `link`. The transport must therefore be trusted with the traffic it handles ([SECURITY §14](docs/SECURITY.md#14-security-considerations)).

**The first transport ships inside the host artifact**, because a node needs a transport before it can fetch anything. Later versions can arrive over the transport already running, like any other bundle.

## What runs today

- **Three targets, one implementation.** Seedkernel runs in the browser, on Node/Bun or as a single native binary, with the same admission and confinement on each. A large part of the implementation is shared between all platforms, including a transport bundle and crypto blobs. Nothing about the protocol is written twice ([one implementation, three targets](#one-implementation-three-targets)).
- **The native node is one 7.5 MB file.** A cgo-free, cross-compiled Go binary with embedded QuickJS and a wasm engine. It is a tenth of what a Bun binary alone costs (~70 MB). The bulk is the wasm compiler backend and the Go runtime; the protocol's own footprint is tens of KB ([RUNTIME §10.2, §12.9](docs/RUNTIME.md)).
- **Confinement has a measured cost.** On the JS targets each module call is a worker round trip (~25 µs; ~110 µs moving 64 KiB each way), which dominates tiny transforms and fades on large ones. Native checks deadlines inline instead, slowing app-module compute by 7–21% (§14).
- **The engine is fast enough for real storage.** Seedstore's write pipeline encrypts, hashes and RS-encodes at ~186 MiB/s on one thread and decodes at ~2.6 GiB/s when every block is present, measured on the same WASM outside the guest. In its tested network configurations, transfer rate and latency dominated ([the overhead, measured](#the-overhead-measured)).
- **Network buffers have explicit limits.** Socket write backlogs and reads waiting on a busy guest are bounded by both byte size and item count. Data remains accounted for as it moves between buffers. The host pauses reads where possible; when limits are exceeded, it closes the affected link ([RUNTIME §12.3](docs/RUNTIME.md#123-zero-authority-js-realms)).
- **Code really does arrive only as a bundle.** The chat demo installs its whole UI and logic at runtime, and so does [seedstore](https://github.com/arj03/seedstore), a real high performance storage layer.
- **Bundles are post-quantum signed.** The manifest suite is hybrid Ed25519 + ML-DSA-65. The host includes the verifier and requires both signatures before accepting a bundle.

## One implementation, three targets

All three targets share bundle admission, policy and routing, and run the same signed transport bundle. Each supplies its own platform adapters. The native binary embeds the shared JavaScript host and runs it in QuickJS. The tables separate shared code from platform code; `npm run loc` in `WASM/` computes the figures.

**Shared: one implementation for all three targets (2,376 LOC)**

| Concern | Where | LOC |
| --- | --- | --- |
| Bundle format, admission policy and resource limits (§12.4, §12.5, §4.1, §12.3) | `host/bundle.ts`, `host/policy.ts`, `host/wasm-limits.ts` | 480 |
| Transport driver: channels by link id and listeners, behind three socket events. No protocol, no state machine, no address book, nothing peer-shaped | `host/transport-host.ts` | 318 |
| Guest seam (§12.2): the call surface, the serialized realm queue, the realm wake and an app's `fs` view | `host/guest-seam.ts`, `host/realm-queue.ts`, `host/realm-timers.ts`, `host/fs-view.ts` | 654 |
| Node assembly and claim routing (§12.8, §12.10): the boot assembly, and the installed set and the claim books over it | `host/shell-core.ts`, `host/slot-table.ts` | 379 |
| Node startup, the operator flow on Node and native (§12.8): the flag set and its defaults, the order a node boots in, what it prints | `host/cli.ts` | 221 |
| Host services: the `HOST_SERVICES` table and signing domains, the socket/`fs` contracts, the key space and flood bounds, the master-seed subkey derivation (§12.6.2b), destination parsing and the raw-link event codec (`services/op-frame.ts`, also available to clients). Their platform backends are per-target, below | `services/*.ts` (8 shared files) | 324 |

Sharing this code keeps admission and confinement rules consistent across targets. Platform adapters connect it to each target's I/O and execution engines.

**Per-target platform: the seam, written once per target**

| Target | What | LOC |
| --- | --- | --- |
| **JS** (browser + Node) | sockets (TCP/WS/WebRTC), the `fs` backend, safe-js realms, worker-backed private modules, manifest-verifier plumbing, entry points, key derivation | 1,281 TS |
| **Native** (Go) | QuickJS embedding, event loop, libsodium and private modules over wazero, raw net and fs, plus `native-shim.ts` (290) and `native-polyfills.ts` (67), both TypeScript and riding in the shared bundle | 2,214 Go + 357 TS |

The transport bundle sits outside these host totals: 1,867 lines of `transport/src/*.js` plus a 6 KB `ws.wasm`. It handles TCP framing, RFC 6455, relays and WebRTC signaling across the targets that support them.

All targets carry the same `libsodium.wasm` and `mldsa65.wasm` host artifacts, including verification for manifest suite `0x02`. They also run the same `mlkem768.wasm`, delivered inside the signed transport bundle as a private module. Native runs these WASM artifacts through wazero.

## The overhead, measured

The [seedstore](https://github.com/arj03/seedstore) measurements below describe specific workloads, not a general throughput guarantee. Confinement itself costs a per-call worker hop on the JS targets and inline deadline checks on native, measured in §14. The fixed hop can dominate small transforms; larger calls amortize it, and transfer rate and latency dominated the network configurations measured below:

- **The compute-only write pipeline (encrypt, name every block, RS-encode) measured 177–189 MiB/s** in three runs on 2026-09-17 (100 MiB, RS(10,6), 64 KiB blocks, Node 20.11.1). ChaCha20-Poly1305 sealing measured 393–395 MiB/s, author-bound BLAKE2b block IDs 720–733 MiB/s, and SIMD RS encode 1,447–1,482 MiB/s. This benchmark calls host crypto and the codec directly; it does not measure guest scheduling, signing, storage, or transport overhead.
- **A read with every block present needs no GF(2⁸) work:** the compute benchmark's concatenation measured 2,339–2,926 MiB/s; reconstructing one missing block measured 1,465–1,682 MiB/s in those runs. These are component measurements, not complete GET rates.
- **End-to-end throughput depends on framing and concurrency:** three fresh-process runs measured 7.6–8.2 MiB/s PUT and 15.7–16.9 MiB/s GET over a modelled 10 ms request/response RTT (4 MiB, RS(2,2), 32 KiB blocks, 256 KiB logical message cap split into 48 KiB physical chunks, fanoutWindow 32). These runs use the signed transport bundle over an in-process latency fabric, not a bandwidth-limited physical WebRTC link.
- **Seedstore's codec, reputation module, and guest total ~14 KiB of WASM plus ~15 KiB of gzipped guest JS**, excluding the shared host and bundle metadata. They reuse the libsodium the runtime already loads rather than bundling a second copy of a crypto library. From seedstore's `WASM/` directory, `node tests/bench.mjs` measures compute and `node tests/bench-net.mjs 10 4 32 256 48 32` measures the framed PUT/GET configuration in a fresh process (omit the final `32` for a fanout sweep). Rates above use binary MiB even though the scripts label them MB. Rebuild with `npm run build` before comparing changed seedstore sources.

## Build this repo

```sh
cd WASM
npm install
npm run build    # ws.wasm + the transport bundle + the shared host
npm test         # the full suite
```

This repo is the runtime only. Apps live outside it and consume the published surface of `seedkernel-wasm`: [seedstore](https://github.com/arj03/seedstore) (a P2P storage node) and [seedchat](https://github.com/arj03/seedchat) (the browser P2P chat demo, §11). `npm run build:browser` produces the browser artifacts they vendor. The relay both use, where nodes register their keys and reach each other before moving to a direct link, and where the apps meet peers in rooms, is a deployment concern rather than runtime surface, so it lives outside this repo: [seedrelay](https://github.com/arj03/seedrelay), which seedchat's `npm run relay` starts. The transport bundle speaks its wire; the host holds only the sockets and peer connections (§12.7).

## The rest of the spec

This file is §1; the rest of the spec lives in `docs/`, split by concern. README, PROTOCOL, RUNTIME and SECURITY share one global numbering of stable ids the source cites, so an unused number (§6–§9, §15) stays unused and a `(§X.Y)` reference resolves to exactly one of them. DESIGN mirrors RUNTIME's §12 numbers; CHANNEL and CLIENT number their own sections and are cited by name (CHANNEL §7):

| Doc | Sections | Contents |
| --- | --- | --- |
| [PROTOCOL](docs/PROTOCOL.md) | §2–§5, §16 | Bundle slots, atomic claim replacement, the restartable WASM module ABI, names and hashes, and protocol constants. |
| [RUNTIME](docs/RUNTIME.md) | §10–§12 | Distribution size, the app layer (chat as the worked example), and the host's normative surface: host services, the guest-seam ABI, zero-authority JS realms, signed bundles and how the host admits them under policy, the node↔node transport, the Go/native binary, routing. Rules and ABI tables only, each stated once. |
| [DESIGN](docs/DESIGN.md) | §12 | Why RUNTIME §12 is shaped the way it is, under the same section numbers. |
| [SECURITY](docs/SECURITY.md) | §13–§14 | A byte-by-byte worked example and the collected trust model. |
| [CHANNEL](docs/CHANNEL.md) | — | The concealed-identity channel handshake: what the three messages do, the three secrets and their different jobs, why one identity key signs for both purposes, and where the design sits against Noise, WireGuard and Secret Handshake. Normative text stays in RUNTIME §12.6; this is the *why*. |
| [CLIENT](docs/CLIENT.md) | — | How to write a bundle and the client that hosts it: a runnable first bundle, the manifest declarations an app adds as it grows, dependency setup, node boot, platform adapters, loading and invocation, browser integration traps, and the two existing clients as worked examples. Build guide, not protocol. |

To read the spec as one document, concatenate the files in that order: `cat README.md docs/{PROTOCOL,RUNTIME,SECURITY}.md`. DESIGN, CHANNEL and CLIENT sit outside that sequence: the first two are rationale, the last the guide to building on the runtime.

## Background

This project was inspired by the [8k-demo](https://github.com/ssbc/8k-demo) P2P project built on top of secure scuttlebutt running in the browser. The goal was to strip it down to the bare essentials and make the host as small as possible, moving functionality into bundles to be distributed in whatever fashion.
