# Seed kernel: a sandboxed app runtime that grows from signed bundles

Seedkernel runs signed apps in a sandbox — JavaScript, plus WebAssembly for the computation that needs it — across browsers, Node and a small native executable. It gives an app controlled access to storage and to authenticated, encrypted peer connections, and nothing it was not granted. Code arrives only as a signed bundle.

That suits three kinds of work:

- **Hosting separately trusted extensions.** A product runs third-party logic in its own slot, where the operator decides which authors may install and what each may reach — without giving that logic the host's file system, sockets or process.
- **Distributing app updates as signed bundles.** A release is one blob — manifest, guest and modules under hybrid author signatures — verified at admission, checked against a version floor, and installed by atomically replacing the slot. It travels over the same network as everything else, because what admits it is the signature and not the route.
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
- **The native node is one 7.5 MB file.** A cgo-free Go cross-compiled binary embedding its own QuickJS, its own wasm engine. It is a tenth of what a Bun binary alone costs (~70 MB). The bulk is the wasm compiler backend and the Go runtime; the protocol's own footprint is tens of KB ([RUNTIME §10.2, §12.9](docs/RUNTIME.md)).
- **Bundles are run in a trusted sandbox on every target.** A module receives no capability imports, so there is no I/O to gate; a guest reaches its signed services, local calls, and private modules, plus only the fixed host transform table. Native deadline checks measured 1.07–1.21× execution time on the tested storage transforms; JS targets instead incur a worker hop per module call ([SECURITY §14](docs/SECURITY.md)).
- **Confinement has workload-dependent overhead.** The measured storage workload encrypts, hashes and RS-encodes at ~270 MB/s on one thread and reads back at ~2.8 GB/s. Its tested network configurations were limited by transfer rate and latency ([the overhead, measured](#the-overhead-measured)).
- **The network is metered, not merely encrypted.** Every byte the host retains for a peer — a socket's write backlog, a read waiting on a busy guest, a queued signaling message — has one finite owner, bounded in bytes *and* count, with no gap between owners. Backpressure where it is free, refusal where it is not ([every host-side byte has an owner](#the-shape-of-it)).
- **Code really does arrive only as a bundle.** Even the transport is one, so that it can be upgraded: it opens each link with a mutually-authenticated hybrid X25519 + ML-KEM-768 handshake that conceals both identities, then carries every frame as a forward-secret ChaCha20-Poly1305 record — the same protocol over TCP, WebSocket and WebRTC. It does not rely on TLS for its security properties, although WSS and WebRTC add TLS/DTLS underneath ([CHANNEL](docs/CHANNEL.md)). The chat demo installs its whole UI and logic at runtime, and so does [seed store](https://github.com/arj03/seedstore), a real high performance storage layer.
- **Bundles are post-quantum signed.** The one manifest suite is hybrid Ed25519 + ML-DSA-65 with both signatures required. Its verifier ships with the host so admission itself has post-quantum protection. The default channel handshake is hybrid X25519 + ML-KEM-768 ([Post-quantum posture](#post-quantum-posture)).

## 1. The model

A minimal runtime: a **host** admits signed **bundles**, and every bundle is an app with exactly one shape — a confined JS **guest** (the app's logic) plus, optionally, any number of restartable WASM **modules** that serve as the app's library. The guest is the only thing an inbound frame reaches: the host resolves the protocol to an app, invokes the guest's one `handle` entrypoint, and the guest drives its own modules by name when it needs a transform.

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

Three terms describe different responsibilities:

| Term | Meaning here |
| --- | --- |
| **Host** | The full runtime that admits and runs bundles, including its shared implementation and platform adapters. Changing host code requires a rebuild. |
| **Core** | The host facilities an app cannot supply for itself (§12.1): `link` sends and receives bytes over opaque link ids, and `fs` gets, puts, sizes, lists, deletes, and stats bytes under opaque flat keys — plus their flood limits, entropy, a clock, and access to the private node key. The host enforces the flood limits where it holds the descriptors, and peer identity is supplied by the transport. |
| **Trust root** | The basis for admitting code: the host's manifest verifier and the operator's policy of trusted app authors, the selected transport author, and version floors. The verifier must ship with the host to check the first bundle; policy is operator-controlled configuration. |

The guest seam, execution limits, boot assembly and claim routing are host code without being core: an app could implement each for itself, but each is what would have to admit or confine its own replacement. The trusted base is wider still, since it also includes the execution engines and the platform adapters.

Seedkernel uses this placement test to keep application functionality out of the core:

> **A function belongs in the core only if an app cannot correctly implement it for itself.**

This is Seedkernel's design discipline, not a quotation or requirement from the original end-to-end paper. Saltzer, Reed, and Clark explicitly allow lower-layer mechanisms justified by performance tradeoffs ([“Performance aspects”](https://web.mit.edu/6.033/2002/wwwdocs/papers/endtoend.pdf)). The residual host crypto table below is an explicit compatibility and performance exception.

Framing, ordering, correlation, network routing, and channel encryption can run in bundles. Content-addressing, storage quotas, and encryption at rest belong to the app storing the bytes. Raw I/O stays in the core because a confined app cannot acquire a socket or file descriptor: the host must move the bytes on its behalf. Confinement gives a guest no ambient authority (§12.2), so this holds for whatever is installed later as well — the host owns the descriptor for the life of the process, which is what makes raw I/O permanently core rather than core for now.

**The placement test** decides *which side* of the line a function is on. A second rule decides *what shape the line has*:

> **A core interface is a flat map over opaque names. If the core must understand what a name *means* in order to serve it, the meaning is content that leaked in.**

Four things follow:

- **One seam, name-addressed.** A guest reaches host authority and its own private modules through `host.call`: `host.call("node/random", …)`, `host.call("mlkem", …)`. The small `crypto/*` table reuses primitives already shipped with the host for verification and the current transport. It is a frozen compatibility and performance exception; new transforms ship as bundle modules.
- **A transform is not a capability.** A function of bytes the guest already holds is computation it could have done itself. It ships as a module of the bundle that needs it. Authorities are the calls that reach something no endpoint module can hold: the node key, entropy source, clock, sockets and disk.
- **Signing is domain separation, not parsing.** The node's Ed25519 key never leaves the host, so a guest that needs a signature asks for one — and the host signs `DOMAIN ‖ scope ‖ opaque`, choosing both from the asking bundle's slot (one scope per slot, derived at load), over a suffix it does not read.
- **Raw net is one capability; attributed delivery is one of its names.** The transport exposes its API as a local service (`_net` in the bundled setup), listed in the manifest's `services`. Peers can reach only names in the separate `protocols` list. The host grants raw-link access to one slot, whose transport attributes incoming messages through `link/deliver` under that same capability. This call names no link; the host relies on the transport's attribution. The signed claim lists keep local services unreachable by peers (§12.10).

## The transport is a bundle

The wire codec, the channel handshake, the record layer, link routing and the request/response frame codec are the guest program of a signed bundle, admitted by the same loader as any other app. It is a **guest** rather than a WASM module for a structural reason: a §4 module is a synchronous transform with no capability imports and disposable state (§4.3), which an AKE carrying session keys across round trips cannot be. So the session state lives in the guest's own heap, keyed by a host-supplied link id, and the node key never enters it. Where computation *is* a bare transform it ships as one — RFC 6455 is `ws.wasm` and ML-KEM-768 is `mlkem768.wasm`, both no-capability modules of that same bundle.

What this buys is that the **protocol** is replaceable without a fork: handshake, transcript, record framing and dial policy are all content, and a deployment that wants different ones selects that signed bundle as its transport instead of patching the runtime. It can even be swapped under a running node: `replaceBundle(oldAppKey, blob)` builds a complete replacement for its selected slot, even across authors, then atomically replaces that slot, its ordinary service claim, and its raw-link binding. Nothing of the outgoing realm survives — not the live links, whose session keys are in its private memory (exactly what makes the transport confineable), and not the address book, which is the guest's own. So an upgrade is a **reconnect**, and the embedder names the peers again in the new load's config (§12.10). The node keeps its listeners, so it accepts throughout.

Two things keep that safe. The initial transport is selected at boot, and live changes explicitly replace its current owner; ordinary app loading cannot acquire `link`. Who may *be* the network is a decision apart from who may ship an app (§12.5). The transport holds session keys and plaintext, so confinement does not protect those from the transport itself ([SECURITY §14](docs/SECURITY.md#14-security-considerations)). And a link speaks exactly one suite, named by a byte both ends fold into what they sign, so a mixed period is a rollout rather than a corruption and an in-path downgrade is a dead link (§12.6).

**The first transport ships inside the host artifact,** because a node has no network until it has a transport (§12.6). What travels is the *next* one: a replacement arrives over the transport already running, like any other bundle, but its signature alone does not trigger installation: the caller explicitly selects which owner it replaces.

## The shape of it

Installation flow:

```
signed bundle (manifest + WASM + guest JS + signature)
        │
        ▼
loadBundle (host admin path)                         §12.4
        │
        ▼
policy check — author trusted? version >= floor?     §12.5
        │
        ▼
build complete slot off to the side                  §3.1
        │
        ▼
atomically replace every claim the bundle owns       §3.1
```

Request flow:

```
socket delivers bytes                    host: raw net + flood limits
        │
        ▼
transport bundle: record open, attribute to peer      §12.6
        │
        ▼
host resolves the app that claims the protocol,
prepends the authenticated sender key        §12.10
        │
        ▼
app's guest `handle` entrypoint — under the
guest execution / handoff deadline (§12.3)    §12.2
        │
        ▼
the guest drives its modules:
host.call("codec", …) → restartable transform at scratch  §3, §4
        │
        ▼
host frames response through the transport bundle
```

The reference composition separates application logic, dispatch, transport, and raw I/O (§5). The host provides the guest seam, dispatch, and raw I/O; the transport runs between them as a bundle. This diagram shows their roles in the composition, while the request flow above shows delivery order:

```
┌─────────────────────────────────────┐
│   App                               │
│   guest (confined JS) +             │
│   restartable WASM modules          │
├─────────────────────────────────────┤
│   Guest seam — host code            │
│   host.call and capability checks   │
├─────────────────────────────────────┤
│   Dispatch — host code              │
│   bundle slots + claim routing,     │
│   guest invocation                  │
├─────────────────────────────────────┤
│   Transport — a signed bundle       │
│   wire codec, AKE, record layer,    │
│   link routing                      │
├─────────────────────────────────────┤
│   Core facilities — host code       │
│   net: send(link,bytes)/onData      │
│   fs: operations over a flat key    │
│   flood limits, entropy, clock,     │
│   node key                          │
└─────────────────────────────────────┘
```

**Execution and trust boundaries:**

- **Position in the stack is not core-ness.** The diagram orders who may call whom; core-ness is what a rebuild is needed to change. The transport sits below dispatch and is still an ordinary signed bundle.
- **Confinement and boundedness answer different questions.** Confinement restricts what downloaded code can reach: a guest receives only its wired capabilities. Boundedness restricts what work admitted from that guest can consume. The executors have outer limits—a WASM module must declare an acceptable linear-memory ceiling, and a JS realm has a heap cap—but those limits alone do not bound the calls, queues, buffers, and descendant work created when the code runs.
- **Every invocation creates a causal work tree.** A peer or the host may trigger admission, but the receiving runtime creates the root and assigns its bounded deadline; a guest can create a fresh root only through a timer. Calls across host services, modules, queues, and other realms are descendants of that root. Three quantities in the tree compose differently and therefore need three separate laws:
  - **Retained space — continuous custody.** Every host-side byte caused by admitted work is charged to a finite owner from creation until destruction. A handoff reserves in the receiver before releasing the sender; a bound on the number of owners makes the node's memory total a sum that is checked against a real machine.
  - **Causal lifetime — a monotone deadline.** One absolute deadline starts at an invocation root and can only shrink as calls cross queues, realms, modules and socket output. A callee cannot mint time by parking or handing work onward.
  - **Initiation rate — explicit scheduling.** A bound on bytes or work in flight says nothing about how quickly completed work can be replaced. A timer fire is the one fresh root a guest can create for itself, so it receives a causal clock carried through continuations, modules, and cross-realm descendants. That root spends measured execution, not time parked on I/O, from a per-realm share; returning without awaiting a child does not make the child free. Network-originated application roots arrive only over mutually authenticated links, giving the replaceable transport a stable peer identity on which a later version can impose per-peer pacing or fair queuing. Authentication is attribution, not trust: an authenticated peer may still be hostile. Until the transport schedules that ingress, externally supplied roots remain bounded individually, not in aggregate; the runtime makes no node-wide CPU guarantee (§12.3, §12.6).
- The channel authenticates one hop, not the whole path. An app that **relays** messages through intermediaries cannot lean on the channel to attribute the *original* author, so it layers its own scheme on top. Bundles already work this way, which is why they need no channel at all.

## One implementation, three targets

All three targets share bundle admission, policy and routing, and run the same signed transport bundle; each supplies its own platform adapters. The shared host set is the file list `build:loader-bundles` compiles into `host-shell.gen.js`, which the Go binary embeds and runs in QuickJS. `WASM/core/` holds core contracts and fixed host vocabulary, including manifest constants; `WASM/host/` implements the surrounding runtime, and `WASM/transport/` builds the signed transport bundle. The directory names group source files; the tables below distinguish shared code from platform code (`npm run loc` in `WASM/` computes the figures).

**Shared — compiled once, run by all three targets (2,565 LOC)**

| Concern | Where | LOC |
| --- | --- | --- |
| Bundle format and admission policy (§12.4, §12.5) | `host/bundle.ts`, `host/policy.ts` | 468 |
| Transport driver — channels by link id and listeners, behind three socket events. No protocol, no state machine, no address book, nothing peer-shaped | `host/transport-host.ts` | 320 |
| Guest seam — the guest ABI seam (§12.2): the call surface, the serialized realm queue, the timer table and an app's `fs` view | `host/guest-seam.ts`, `host/realm-queue.ts`, `host/realm-timers.ts`, `host/fs-view.ts` | 725 |
| Shell, node assembly and claim routing (§12.9, §12.10) — the boot assembly, and the installed set with the two claim books that route into it | `host/shell-core.ts`, `host/slot-table.ts` | 379 |
| Node startup — the operator flow: the flag set and its defaults, the order a node boots in (§12.5), what it prints | `host/cli.ts`, `host/peer-addr.ts` | 255 |
| Core contracts and fixed host vocabulary — the socket/`fs` contracts, the key space and flood bounds, domain prefixes, the master-seed subkey derivation (§12.6.2b), the manifest suite id, host-call names and raw-link event codec (`core/op-frame.ts`, also available to clients) | `core/*.ts` (8 files) | 418 |

Sharing these rows keeps admission and confinement rules consistent across targets and avoids duplicating adapters and client codecs. Claim routing still follows each node's own installed set (§12.10); the operator decides which app owns each claim ([SECURITY §14](docs/SECURITY.md#14-security-considerations)).

The transport driver holds link ids and listeners and exposes three events: `linkOpen`, `linkBytes`, and `linkClosed`. Peer, address, and contact policy live in the bundle, reached through ordinary local-service calls via `Shell.call`. `link/open` passes an opaque destination to the platform's socket factory; listener lifecycle follows host configuration.

**Per-target platform — the seam, written once per target**

| Target | What | LOC |
| --- | --- | --- |
| **JS** (browser + Node) | sockets (TCP/WS/WebRTC), the `fs` backend, safe-js realms, worker-backed private modules, manifest-verifier plumbing, entry points, key derivation | 1,562 TS |
| **Native** (Go) | QuickJS embedding, event loop, libsodium and private modules over wazero, raw net and fs — plus `native-shim.ts` (406) and `native-polyfills.ts` (83), both TypeScript and riding in the shared bundle | 2,296 Go + 489 TS |

Each socket implementation reaches the driver as a `RawLink` through the `ChannelFactory` seam ([RUNTIME §12.1](docs/RUNTIME.md)). TCP length-prefixing and RFC 6455 belong to the transport bundle — 1,558 lines of `transport/src/*.js` plus a 5 KB `ws.wasm`, outside the host tables above.

The host artifact carries `libsodium.wasm` and `mldsa65.wasm` for its cryptographic operations, including manifest suite `0x02` verification. `mlkem768.wasm` is byte-identical across targets too, but arrives inside the signed transport bundle and uses the ordinary private-module loader. The Go platform embeds the two host WASM artifacts and drives them over wazero, while its event loop runs the shared JS host in QuickJS. Manifest admission, routing, and policy logic stay in the shared implementation.

## The overhead, measured

The [seed store](https://github.com/arj03/seedstore) measurements below describe specific workloads, not a general throughput guarantee. Native deadline checks measured 1.07–1.21× execution time on the tested transforms; JS module calls added a worker hop of ~30 µs for small calls and ~160 µs for a 64 KiB transfer both ways (§14). That fixed hop can dominate small transforms; larger calls amortize it, and transfer rate and latency dominated the network configurations measured below:

- **The compute-only write pipeline — encrypt, name every block, RS-encode — measured 151–170 MiB/s** in three runs on 2026-09-07 (100 MiB, RS(10,6), 64 KiB blocks, Node 20.11.1). ChaCha20-Poly1305 sealing measured 330–359 MiB/s, author-bound BLAKE2b block IDs 553–680 MiB/s, and SIMD RS encode 1,256–1,310 MiB/s. This benchmark calls host crypto and the codec directly; it does not measure guest scheduling, signing, storage, or transport overhead.
- **A read with every block present needs no GF(2⁸) work:** the compute benchmark's concatenation measured 1,921–2,588 MiB/s; reconstructing one missing block measured 1,235–1,537 MiB/s in those runs. These are component measurements, not complete GET rates.
- **End-to-end throughput depends on framing and concurrency:** two fresh-process runs measured 7.1–7.3 MiB/s PUT and 14.5–15.9 MiB/s GET over a modelled 10 ms request/response RTT (4 MiB, RS(2,2), 32 KiB blocks, 256 KiB logical message cap split into 48 KiB physical chunks, fanoutWindow 32). These runs use the signed transport bundle over an in-process latency fabric, not a bandwidth-limited physical WebRTC link.
- **Seedstore's codec, reputation module, and guest total ~14 KiB of WASM plus ~15 KiB of gzipped guest JS**, excluding the shared kernel and bundle metadata. They reuse the libsodium the runtime already loads rather than bundling a second copy of a crypto library. From seedstore's `WASM/` directory, `node tests/bench.mjs` measures compute and `node tests/bench-net.mjs 10 4 32 256 48 32` measures the framed PUT/GET configuration in a fresh process (omit the final `32` for a fanout sweep). The old `node tests/bench-net.mjs 10 4 32` command explicitly defaults to a 48 KiB logical cap, regardless of application default changes. Rates above use binary MiB even though the scripts label them MB. Rebuild with `npm run build` before comparing changed seedstore sources.

## Post-quantum posture

The manifest verifier ships with the host; the channel implementation ships in the signed transport bundle. Updating them requires a host rebuild and a bundle rollout respectively.

**Manifest suite `0x02` uses hybrid Ed25519 + ML-DSA-65 signatures.** Both must verify, and the author id binds both public keys (§12.4). The verifier is part of the host's trusted base because it decides which bundles may be admitted.

**Channel suite `0x03` combines ephemeral X25519 with ML-KEM-768.** Every handshake key from msg2 onward and both session keys derive from both secrets. The KEM is the transport bundle's private `mlkem` module, tested against NIST ACVP vectors. Msg1 is 1,265 bytes and msg2 is 1,168 bytes; the record layer uses ChaCha20-Poly1305.

Channel AUTH remains Ed25519: hybrid key establishment protects recorded ciphertext under the assumptions in [SECURITY §14.2](docs/SECURITY.md), but does not provide post-quantum peer authentication. Long-lived application signatures need their own protection.

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
