# Seed kernel: a sandboxed app runtime that grows from signed bundles

*Every app is a confined JS guest over a library of pure-transform WASM modules; code arrives only as a signed bundle, and untrusted code runs sandboxed anywhere from a browser tab to a single native binary.*

## What runs today

- **Three targets, one implementation.** Seedkernel runs in the browser, on Node/Bun or as a single native binary. A large part of the implementation is shared between all platforms including a transport bundle and crypto blobs. Nothing about the protocol is written twice ([one implementation, three targets](#one-implementation-three-targets)).
- **The native node is one 7.5 MB file.** A cgo-free Go cross-compiled binary embedding its own QuickJS, its own wasm engine. It is a tenth of what a Bun binary alone costs (~70 MB). The bulk is the wasm compiler backend and the Go runtime; the protocol's own footprint is tens of KB ([RUNTIME §10.2, §12.9](docs/RUNTIME.md)).
- **Bundles are run in a trusted sandbox on every target.** A module imports no runtime seam at all, so there is no I/O to gate; a guest reaches exactly the names its signed manifest declares. The sandbox overhead is quite minimal, on the order of 1.07–1.21x slower ([SECURITY §14](docs/SECURITY.md)).
- **Confinement costs no throughput.** A real storage layer over this seam encrypts, hashes and RS-encodes at ~270 MB/s on one thread and reads back at ~2.8 GB/s; end to end the link bounds it, not the runtime ([the overhead, measured](#the-overhead-measured)).
- **Code really does arrive only as a bundle.** Even the transport is one, so that it can be upgraded: it opens each link with a mutually-authenticated hybrid X25519 + ML-KEM-768 handshake that conceals both identities, then carries every frame as a forward-secret ChaCha20-Poly1305 record — the same over TCP, WebSocket and WebRTC, with no TLS underneath ([CHANNEL](docs/CHANNEL.md)). The chat demo installs its whole UI and logic at runtime, and so does [seed store](https://github.com/arj03/seedstore), a real high performance storage layer.
- **Bundles are post-quantum signed.** The one manifest suite is hybrid Ed25519 + ML-DSA-65 with both signatures required, because a PQ verifier is the one thing that can never arrive as a bundle. The default channel handshake is hybrid X25519 + ML-KEM-768 ([Post-quantum posture](#post-quantum-posture)).

## 1. The model

A minimal runtime: a **host** admits signed **bundles**, and every bundle is an app with exactly one shape — a confined JS **guest** (the app's logic) plus, optionally, any number of pure-transform WASM **modules** that serve as the app's library. The guest is the only thing an inbound frame reaches: the host resolves the protocol to an app, invokes the guest's one `handle` entrypoint, and the guest drives its own modules by name when it needs a transform.

**The whole runtime is five components.** Everything after this table is detail:

| Component | Role |
| --- | --- |
| **Bundles** | The only way code arrives (§12.4): a manifest, a guest JS program, any number of WASM modules, and one author signature over the whole set. The host checks that signature against the operator's policy (§12.5), builds a complete private slot, and atomically replaces its claims. **The transport is one of these.** |
| **Guests** | Every app's logic (§12.2): a zero-authority QuickJS realm holding only the ECMAScript intrinsics, whose entire seam is `host.call(name, …)` out and `realm.call(entry, bytes)` in — serialized per realm and bounded in heap and execution time (§12.3). Inbound delivery is an entrypoint invocation on the app's guest; everything a synchronous pure transform cannot be — session state, app logic, the transport's AKE — lives here, and the modules are the library it drives by name. |
| **Modules** | An app's *library*: pure-transform WASM modules (§4), reached by the guest by their bare name through `host.call` (§12.2). The host stages input at the module's `scratch` offset, calls `handle`, and reads the response back. They import **nothing from the runtime** — no host seam, no I/O of their own — so the sandbox is an absence of wiring rather than a rule. Any language that compiles to WASM qualifies; the contract is three exports and no imports. A module runs only when its app's guest calls it. |
| **Host** | The runtime: the same shared JS on every target (browser, Node, or QuickJS inside the native binary, §12.9). It owns the platform seam — sockets, entropy, the clock, the node identity key — the bundle slots and direct claim routing (§3), the inbound dispatch (§12.10), and `loadBundle`, the single admin path that admits new code (§12.4). |
| **Raw I/O** | Two capabilities of the same shape: `link` is `send(link, bytes)` / `onData` over an opaque link id, `fs` is get/put/size/list/delete/stat over an opaque flat key (§12.1). Raw bytes over an opaque name, plus the flood limits that must sit with whoever holds the descriptor. A *link*, not a peer: a peer id is an attributed identity, which is the transport's output rather than the platform's contribution. |

**Authorization, capability gating and application logic are none of them.** They are layers that compose around the guest seam without the host knowing what any of them mean, so a node bootstraps from one trusted policy — the authors it will install, or none — into arbitrarily complex behaviour.

**The dispatch path stays small because attribution happens below it.** By the time a frame reaches an app it has already been attributed to a peer's key, so there is no envelope to parse, no per-message signature to verify, no signer state to carry across a call and no size cap to enforce. Delivery gets to be one routing lookup and one guest call *because* a layer beneath it did that work. But being beneath the app is not the same as being in the trusted base: the layer that attributes frames is an ordinary signed bundle. Signing survives where it must — over the **bundle** that installs code (§12.4), which authenticates its author across any number of relays and any number of hostile hops.

There are no special cases and exactly one way to do everything: one app shape (every app is a guest, §12.4), one install path (signed bundles, §12.4), one guest seam (`host.call` out, entrypoint invocation in, §12.2), one post-handshake frame plane (§12.6). The transport is no exception, and that is the load-bearing part: it reaches sockets through names, and it is reached — by the host and by every app — through the protocol id it claims, exactly as an app is.

## What belongs in the core

The core is what a rebuild is needed to change, so it is worth naming in one line: **two raw I/O seams — a socket and an `fs`, each bytes in and out over an opaque name — their flood limits, an entropy source, a clock, a private key, and direct claim-to-slot routing.** Plus the two things no test could remove, because they are what would admit their own replacement: the manifest verifier and a policy file with a version floor. That is a seed. Everything else is content, and one test is what emptied it out — Saltzer, Reed and Clark's:

> **A function belongs in a lower layer only if it cannot be correctly implemented at the endpoints.**

Almost nothing usually called "the network" survives it, because almost all of it has an endpoint substitute: authenticity of code is the bundle signature that travels with it, and of a relayed message the relaying app's own signature; confidentiality is the endpoints holding the keys; framing, ordering, correlation and routing are state machines over whole messages; content-addressing, quota and encryption at rest belong to whichever app stores the bytes. All of it is content. **Moving bytes from A to B, or to disk and back, has no substitute — there is no such thing.** That is the argument for raw I/O being core: not bootstrapping, not convenience, not that the crypto is already linked in. There is nowhere else to put it.

The end-to-end test decides *which side* of the line a function is on. A second rule decides *what shape the line has*:

> **A core interface is a flat map over opaque names. If the core must understand what a name *means* in order to serve it, the meaning is content that leaked in.**

Four things follow:

- **One seam, name-addressed.** A guest reaches host authority by name through `host.call` and reaches its own pure modules through that same call: `host.call("node/random", …)`, `host.call("mlkem", …)`. There is no algorithm-provisioning catalog. The small `crypto/*` table is legacy host vocabulary already used by the current transport and trust root; it is frozen and shrinking, not an extension point.
- **A pure transform is not a capability.** A function of bytes the guest already holds is computation it could have done itself. It ships as a module of the bundle that needs it. Authorities are the calls that reach something no endpoint module can hold: the node key, entropy source, clock, sockets and disk.
- **Signing is domain separation, not parsing.** The node's Ed25519 key never leaves the host, so a module that needs a signature asks for one — and the host signs `DOMAIN ‖ scope ‖ opaque`, choosing both from the asking bundle's slot (one scope per slot, derived at load), over a suffix it does not read.
- **Raw net is one capability; attributed delivery is a return convention of it.** The transport bundle consumes opaque links and provides its structured API under an ordinary local service name selected by composition (`_net` in the bundled setup) — declared in the manifest's `services` list, a co-resident guest's to reach, never its `protocols` list, which is what a peer may reach. Inbound requests reach the host's claim routing as the link slot's own delivery return — the occupant that sees the plaintext is the one that attributes it, and only one slot ever holds the sockets, so there is no second privilege to grant or forget. Public reach and local reach are two signed lists, read at the claim rather than parsed off its spelling, so no delivery lets a peer reach a name only a co-resident guest may call (§12.10).

**And the core cannot grow back.** A confined module holds no ambient authority by construction (§12.2), so it can never hold a file descriptor — at any point in the process's life, whatever has already been installed. The host owns the socket forever, which is what makes raw I/O core permanently rather than for now.

## The transport is a bundle

The wire codec, the channel handshake, the record layer, link routing and the request/response frame codec are the guest program of a signed bundle, admitted by the same loader as any other app. It is a **guest** rather than a WASM module for a structural reason: a §4 module is a synchronous pure transform that imports nothing, which an AKE carrying session state cannot be. So the session state lives in the guest's own heap, keyed by a host-supplied link id, and the node key never enters it. Where computation *is* a pure transform it ships as one — RFC 6455 is `ws.wasm` and ML-KEM-768 is `mlkem768.wasm`, both no-capability modules of that same bundle.

What this buys is that the **protocol** is replaceable without a fork: handshake, transcript, record framing and dial policy are all content, and a deployment that wants different ones boots that signed bundle as its transport and grants its author `link`, instead of patching the runtime. It can even be swapped under a running node: an update builds a complete replacement for its slot, then atomically replaces that slot, its ordinary service claim, and its raw-link binding. The new guest redials from the address book the *node* owns. Live links do not survive, since the session keys are in the outgoing guest's private memory — exactly what makes the transport confineable — so an upgrade is a **reconnect** (§12.10).

Two things keep that safe. Policy is keyed on the **capability** rather than on a kind of bundle, so who may *be* the network — the holder sees all plaintext and holds the session keys — is a decision the operator makes apart from who may ship an app (§12.5). And a link speaks exactly one suite, named by a byte both ends fold into what they sign, so a mixed period is a rollout rather than a corruption and an in-path downgrade is a dead link (§12.6).

**The first transport ships inside the host artifact,** because a node has no network until it has a transport (§12.6). What travels is the *next* one: a replacement arrives over the transport already running, like any other bundle, since what admits it is the manifest signature and not the route it took.

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
guest execution budget (§12.3)               §12.2
        │
        ▼
the guest drives its modules:
host.call("codec", …) → pure transform at scratch  §3, §4
        │
        ▼
host frames response through the transport bundle
```

The reference composition stacks the layers so each depends only on the layers below it (§5). Only the bottom row is core:

```
┌─────────────────────────────────────┐
│   App                               │
│   guest (confined JS) +             │
│   pure-transform WASM modules       │
├─────────────────────────────────────┤
│   Guest seam                        │
│   the guest's host.call seam —      │
│   its only reach to real I/O        │
├─────────────────────────────────────┤
│   Host                              │
│   bundle slots + claim routing,     │
│   dispatch, the platform seam       │
├─────────────────────────────────────┤
│   Transport — a signed bundle       │
│   wire codec, AKE, record layer,    │
│   link routing. beneath the host,   │
│   but content: replaceable          │
├─────────────────────────────────────┤
│   Raw I/O                           │
│   net: send(link,bytes)/onData      │
│   fs:  get/put over a flat key      │
│   limits, entropy, node key         │
│   CORE — no endpoint substitute     │
└─────────────────────────────────────┘
```

**Design principles:**

- **The core is what the endpoints cannot do for themselves.** Authenticity, confidentiality, framing and routing all have endpoint substitutes and are therefore content. Transmission does not, and is therefore core.
- **Lower is not the same as core.** Layering says who may call whom; core-ness says what cannot be replaced without a rebuild. The transport sits beneath the host and is still an ordinary bundle.
- **Not-core is not the same as replaceable.** The bundle verifier, the guest seam and the shell's assembly order all fail the end-to-end test — an endpoint could check a signature perfectly well — and are still permanently compiled in, because each is what would have to admit its own replacement. Core-ness bounds what the design owes the endpoints; the trust root bounds what a rebuild can avoid. They are different sets, and a component outside the core can still be stuck.
- The host's dispatch does exactly one thing: resolve the protocol to an app and invoke its guest. No built-in policies, I/O, or dispatch loop beyond the seam it is handed. Lower layers gate higher layers; each layer sees only downward.
- Untrusted code is **bounded** as well as confined. A WASM module declares its linear-memory ceiling in the module bytes and the loader reads it there, before instantiating, refusing anything unbounded or over budget; a JS guest runs under a heap cap *and* an operator-set execution budget (5 s by default), enforced on every target by QuickJS's interrupt handler. A module call carries a deadline — the calling guest's remaining execution segment — and a call that burns it is killed at the engine and answered empty, exactly as a trap is (§4.3, §14). It is one step from the wire either way: a module is only ever reached by a guest calling it by name, under that guest's budget.
- Node-to-node links are confidential by default — the transport bundle opens each connection with an authenticated key exchange, then carries every frame as a forward-secret, individually-authenticated encrypted record, uniform across TCP, WebSocket and WebRTC and needing no external TLS or Noise tunnel.
- The channel authenticates one hop, not the whole path. An app that **relays** messages through intermediaries cannot lean on the channel to attribute the *original* author, so it layers its own scheme on top. Bundles already work this way, which is why they need no channel at all.
- Modules are private slot values, not a shell namespace. JS may use a map and native an opaque Go handle, but neither is part of routing or the shell API (§3).

## One implementation, three targets

The runtime runs in a browser tab, on Node/Bun, and as a single native binary. Anything two nodes could *disagree* about is compiled once and shared; only the platform seam is written per target. The tree says which is which — `WASM/core/` is what has no endpoint substitute, `WASM/host/` is the runtime around it, `WASM/transport/` is signed content — but the line that matters is **shared vs per-target**: the shared set is exactly the file list `build:loader-bundles` compiles into `host-shell.gen.js`, which the Go binary embeds and runs in QuickJS. Everything else is one target's plumbing (`npm run loc` in `WASM/` computes the figures below).

**Shared — compiled once, run by all three targets (2,267 LOC)**

| Concern | Where | LOC |
| --- | --- | --- |
| Bundle format and admission policy (§12.4, §12.5) | `host/bundle.ts`, `host/policy.ts` | 501 |
| Transport driver — channels by link id, outbound promises, the address book. No protocol, no state machine | `host/transport-host.ts` | 435 |
| Guest seam — the guest ABI seam (§12.2) | `host/guest-seam.ts`, `host/realm-queue.ts` | 382 |
| Shell and protocol routing (§12.10) | `host/shell-core.ts` | 428 |
| Node startup and client framing — the operator flow: the flag set and its defaults, the order a node boots in (§12.5), what it prints; the optional named-op codec shared with clients | `host/cli.ts`, `host/op-frame.ts` | 244 |
| Core seam and vocabulary — the socket/`fs` contracts, the key space and flood bounds, domain prefixes, the master-seed subkey derivation (§12.6.2b), the manifest suite id and the host-call names | `core/*.ts` (7 files) | 277 |

**Four reasons a row is shared**, and which reason applies decides whether it could ever leave the set:

- **Trust root** — the bundle format and admission policy, the guest seam, the shell's assembly order. Whatever verifies a bundle, confines a guest or orders the load cannot itself arrive as a bundle. None of it is core by the end-to-end test; all of it is stuck.
- **Vocabulary** — the domain prefixes, manifest suite id, authority names and flood bounds in `core/`. Core is the vocabulary a bundle's own signature is verified under; a bundle defining that vocabulary would be circular. A codec nothing verifies is not core. Pure transforms do not enter it either: seed store and the transport both ship their computations as modules and add no host name.
- **A stable adapter** — the transport driver holds link ids, listeners and the address book, while raw-link events target the slot/platform binding that owns that capability. Listener lifecycle follows host configuration, not claim lifecycle or service spelling.
- **Reuse** — protocol routing carries no security property and two nodes disagreeing about one is harmless (§12.10), so that row is shared to keep one rule on every target, not because agreement is load-bearing. The optional op codec likewise stays shared so clients and guest build tools do not each restate it.

**Per-target platform — the seam, written once per target**

| Target | What | LOC |
| --- | --- | --- |
| **JS** (browser + Node) | sockets (TCP/WS/WebRTC), the `fs` backend, safe-js realms, worker-backed pure modules, manifest-verifier plumbing, entry points, key derivation | 1,410 TS |
| **Native** (Go) | QuickJS embedding, event loop, libsodium and pure modules over wazero, raw net and fs — plus `native-shim.ts` (408) and `native-polyfills.ts` (93), both TypeScript and riding in the shared bundle | 1,960 Go + 501 TS |

What differs is only the object that moves bytes, and wrapping it is host code on every target, because a confined guest never holds a socket. Whatever the object, it lands in the driver's `openLink` and the bundle cannot tell the transports apart ([RUNTIME §12.1](docs/RUNTIME.md)). Wire framing is in neither table: length-prefixing a TCP stream and RFC 6455 are content by the end-to-end test, so they belong to the transport bundle — 1,526 lines of `transport/src/*.js` plus a 5 KB `ws.wasm`, signed content rather than host code at all.

Each target therefore runs the same shared host over its own plumbing, and nothing on the wire is any of it. The host artifact carries `libsodium.wasm` core and `mldsa65.wasm`, the `0x02` manifest verifier. `mlkem768.wasm` is byte-identical across targets too, but it arrives inside the signed transport bundle and is instantiated by the ordinary private-module loader. The Go platform embeds the two host artifacts, owns an event loop, and drives them over wazero; it is a bridge, not a second runtime — no manifest verification, routing or policy logic lives in Go.

## The overhead, measured

The fair follow-up to all these seams is whether confinement costs throughput. The proof that it does not is [seed store](https://github.com/arj03/seedstore): a complete storage layer including client-side encryption, Reed–Solomon erasure coding, content addressing, repair shipped as two WASM modules and a confined guest. Its measured numbers are the answer:

- **The full write path — encrypt, hash every block, RS-encode — runs at ~270 MB/s on one thread** (100 MB, RS(10,6), 64 KB blocks, Node 20.11, a Ryzen 7 PRO 7840U), balanced across its three pieces: xchacha20 at ~550 MB/s, BLAKE2b block-ids at ~1.1 GB/s, SIMD RS encode at ~1.45 GB/s. Those are the codec's own computations and they dominate — the runtime's seam between guest and module is not where the time goes.
- **A read with every block present is ~2.8 GB/s** — the code is systematic, so a full read is a concatenation with no GF(2⁸) work at all; only a missing block pays a decode, at ~1.6 GB/s.
- **End to end, the link bounds throughput, not the runtime:** ~4.5 MB/s PUT and ~10 MB/s GET over a fully modelled 10 ms request/response RTT, WebRTC-sized messages and a 32-request window, and ~13 MB/s browser-to-browser — all through the same signed transport bundle every app gets. The former ~11/~17 MB/s figures charged latency only on the inbound request, not on its response, and are not comparable to a real 10 ms RTT.
- **The whole layer ships as ~15 KB of WASM plus ~8 KB of gzipped guest JS**, reusing the libsodium the runtime already loads rather than bundling a second copy of a crypto library. In the seedstore repo, `node tests/bench.mjs` reproduces the compute numbers and `node tests/bench-net.mjs 10 4 32` reproduces the latency-bearing PUT/GET sweep.

## Post-quantum posture

The two migrations are on independent clocks, because their delivery mechanisms differ: moving the manifest suite is a rebuild, moving the channel suite is a bundle rollout. So they are scheduled on opposite principles.

**The manifest suite has already moved,** because it is the one that can never get cheaper: a PQ verifier cannot be delivered as a bundle, since the classical verifier would be the thing admitting it. The one manifest suite, `0x02`, is **hybrid Ed25519 + ML-DSA-65**, and **both** signatures must verify — so a flaw in the young half fails closed (valid bundles rejected) rather than open. An author is a key-set identity derived from both keys rather than the Ed25519 half (§12.4), and the artifact ships hybrid from the first build: the transport bundle, the one signed bundle every deployment loads, is signed under `0x02`.

**The channel suite has moved.** The default transport speaks `0x03`, combining ephemeral X25519 with ML-KEM-768 before either identity is revealed and deriving every later handshake and session key from both secrets. The KEM is the bundle's own `mlkem` module, pinned to NIST ACVP vectors; it added no host name and no native KEM driver. Msg1 is 1,265 bytes and msg2 is 1,168 bytes, while the ChaCha20-Poly1305 record layer is unchanged. A transport upgrade remains a signed bundle swap, not a host rebuild.

The symmetric half needs no migration: ChaCha20-Poly1305 and BLAKE2b are already PQ-safe. Transcript signatures stay Ed25519 because a forgery matters only while a handshake is live; recorded ciphertext confidentiality is the part that could not be repaired later, and `0x03` now closes that clock. [SECURITY §14.2](docs/SECURITY.md) has the field-by-field shape and cost.

## Get started

```sh
cd WASM
npm install
npm run build    # ws.wasm + the transport bundle + the shared host
npm test         # the full suite
```

This repo is the runtime only. Apps live outside it and consume the published surface of `seedkernel-wasm`: [seed store](https://github.com/arj03/seedstore) (a P2P storage node) and [seedchat](https://github.com/arj03/seedchat) (the browser P2P chat demo, §11). `npm run build:browser` produces the browser artifacts they vendor. [CLIENT](docs/CLIENT.md) is where a new client starts: dependency setup, bundle authoring, node boot, platform adapters, loading and invocation, with seed store and seedchat as the worked examples. The WebRTC signaling rendezvous both use is a deployment concern rather than runtime surface, so it lives with the apps — `npm run relay` in seedchat, which seed store also points at.

`npm run build:pq` rebuilds the two PQ modules from the pinned `pq/mldsa-native` and `pq/mlkem-native` submodules; it needs `git submodule update --init` and a clang with the wasm32 target.

## The rest of the spec

This file is §1 (and §15); the rest of the spec lives in `docs/`, split by concern. Section numbers are global across the set — any `(§X.Y)` reference resolves to exactly one file:

| Doc | Sections | Contents |
| --- | --- | --- |
| [PROTOCOL](docs/PROTOCOL.md) | §2–§5, §16 | Bundle slots, atomic claim replacement, the pure-transform WASM module ABI, layering, and protocol constants. |
| [RUNTIME](docs/RUNTIME.md) | §10–§12 | Distribution size, the app layer (chat as the worked example), and the shell: capability backends, the guest-seam ABI, zero-authority JS realms, signed bundles and how the loader admits them under policy, the node↔node transport, the Go/native binary. |
| [SECURITY](docs/SECURITY.md) | §13–§14 | A byte-by-byte worked example and the collected trust model. |
| [CHANNEL](docs/CHANNEL.md) | §12.6.2 | The concealed-identity channel handshake: what the four messages do, the three secrets and their different jobs, why one identity key signs for both purposes, and where the design sits against Noise, WireGuard and Secret Handshake. Normative text stays in RUNTIME §12.6; this is the *why*. |
| [CLIENT](docs/CLIENT.md) | — | How to write a client on the runtime: dependency setup, bundle authoring, node boot, platform adapters, loading and invocation, browser integration traps, and the two existing clients as worked examples. Client guide, not protocol. |

To read the spec as one document, concatenate the files in that order: `cat README.md docs/{PROTOCOL,RUNTIME,SECURITY}.md`. CHANNEL and CLIENT sit outside that sequence — one is rationale, the other the client guide for building on the runtime.

## 15. Background

This project was inspired by the [8k-demo](https://github.com/ssbc/8k-demo) P2P project built on top of secure scuttlebutt running in the browser. The goal was to strip it down to the bare essentials and make the core as small as possible, moving functionality into modules to be distributed in whatever fashion. The end-to-end argument is that goal made decidable: *core* is what the endpoints cannot do for themselves, everything else is a module, and it turns out that leaves the network in the core — but only the part of it that actually moves bytes.
