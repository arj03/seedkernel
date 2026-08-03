# Seed kernel: a tiny handler-table kernel that bootstraps into a sandboxed app runtime

*A simple kernel grows from a signed message handler bundle into arbitrary behaviour — untrusted code runs sandboxed (WASM handlers or confined JS), anywhere from a browser tab to a single native binary.*

## 1. Vision

A minimal runtime built around a kernel that does one thing: look up a **name** in `handlers` and run the handler bound there as a **pure transform** — bytes in and bytes out. Authorization, capability gating, confinement and application logic are the **host** and its **modules** — layers that compose around the table without the kernel knowing what any of them mean. Installing a handler is nothing more than `handlers[name] = wasm_bytes`; code arrives as a signed **bundle** and the host binds each module into the table under a policy. The system bootstraps from one trusted policy (the authors it will install, or none) into arbitrarily complex behaviour.

**The kernel is small because attribution happens below it.** By the time a frame reaches the table it has already been attributed to a peer's key, so there is no envelope to parse, no per-message signature to verify, no signer state to carry across a call and no size cap to enforce. The kernel gets to be two operations *because* a layer beneath it did that work. But being beneath the kernel is not the same as being in the trusted base: the layer that attributes frames is an ordinary signed bundle.

Signing survives where it must — over the **bundle** that installs code (§12.4), which authenticates its author across any number of relays and any number of hostile hops.

**The whole runtime is six components.** Everything after this table is detail:

| Component | Role |
| --- | --- |
| **Kernel** | Routes names to handlers: a flat `handlers[name]` table (§3). It is a *contract*, not an artifact — the table, the handler ABI and the bind/unbind semantics — implemented as one map inside each host. Handlers are pure transforms; there is no dispatch loop, no signature logic, no I/O. |
| **Raw I/O** | Two capabilities of the same shape: `net` is `send(link, bytes)` / `onBytes` over an opaque link id, `fs` is get/put/size/list/delete over an opaque flat key (§12.1). Raw bytes over an opaque name, plus the flood limits that must sit with whoever holds the descriptor. A *link*, not a peer: a peer id is an attributed identity, which is the transport's output rather than the platform's contribution. |
| **Host** | The runtime around the table: the same shared JS on every target (browser, Node, or QuickJS inside the native binary, §12.9). It owns the platform seam — sockets, entropy, the clock, the node identity key — reaches a handler by name (`callHandler`), and provides `loadBundle`, the single admin path that admits new code (§12.4). |
| **Handlers** | Pure-transform WASM modules (§4): the host stages input at the module's `scratch` offset, calls `handle`, and reads the response back. They import **nothing from the runtime** — no kernel seam, no I/O of their own — so the sandbox is an absence of wiring rather than a rule. Any language that compiles to WASM qualifies; the contract is three exports and no imports. |
| **Guests** | Confined JS programs (§12.2): a zero-authority QuickJS realm holding only the ECMAScript intrinsics, whose entire seam is `host.call(op, …)` out and `realm.call(entry, bytes)` in — serialized per realm and bounded in heap and execution time (§12.3). Everything a synchronous pure transform cannot be — session state, app logic, the transport's AKE — lives here. |
| **Bundles** | The only way code arrives (§12.4): a manifest, WASM modules, a guest JS program, and one author signature over the whole set. The host checks that signature against the operator's policy (§12.5) and the loader admits the modules into the flat table — a policy decision, then one all-or-none bind. **The transport is one of these.** |

There are no special cases and exactly one way to do everything: one install path (signed bundles, §12.4), one guest seam (`host.call` out, entrypoint invocation in, §12.2), one post-handshake frame plane (§12.6). The transport is no exception, and that is the load-bearing part: it reaches sockets through ops and is driven through named entrypoints, exactly as an app is.

Every binding is three orthogonal pieces: the **name** is the kernel's opaque dispatch key, the **bytes** are the WASM instance held at that key, and the **author** is the signer of the bundle. The loader binds names to bytes under a deployer-supplied **policy** that decides who may install what (§12.5).

## What belongs in the core

"Make the core as small as possible" is a goal, not a test — everything can always be smaller. The test is Saltzer, Reed and Clark's:

> **A function belongs in a lower layer only if it cannot be correctly implemented at the endpoints.**

Almost nothing usually called "the network" survives it, because almost all of it has an endpoint substitute: authenticity of code is the bundle signature that travels with it, and of a relayed message the relaying app's own signature; confidentiality is the endpoints holding the keys; framing, ordering, correlation and routing are state machines over whole messages; content-addressing, quota and encryption at rest belong to whichever app stores the bytes. All of it is content. **Moving bytes from A to B, or to disk and back, has no substitute — there is no such thing.** That is the argument for raw I/O being core: not bootstrapping, not convenience, not that the crypto is already linked in. There is nowhere else to put it.

The end-to-end test decides *which side* of the line a function is on. A second rule decides *what shape the line has*:

> **A core interface is a flat map over opaque names. If the core must understand what a name *means* in order to serve it, the meaning is content that leaked in.**

Four things follow, and together they are most of what the core is:

- **One crypto op, name-addressed.** A guest reaches primitives through `CRYPTO(name, bytes) -> bytes` and the host holds the catalog: `x25519/dh`, `chacha20poly1305-ietf/seal`, `ml-kem-768/encaps`. A new algorithm is a catalog entry — no op number, no ABI rev, no capability domain. A host missing a name refuses the load *by name*.
- **A pure transform is not a capability.** A function of bytes the guest already holds is computation it could have done itself — correct and fast rather than permitted. So the seam holds **primitives**, which are free, and **authorities**, which reach something no confined module can hold: the node key, the entropy source, the clock, a socket, the disk.
- **Signing is domain separation, not parsing.** The node's Ed25519 key never leaves the host, so a module that needs a signature asks for one — and the host signs `DOMAIN ‖ scope ‖ opaque`, choosing the domain from the asking bundle's slot, over a suffix it does not read.
- **Raw net is the capability; structured net is what the transport provides.** The raw capability is an opaque link id with bytes in and out — the socket-side twin of `fs`. The transport bundle consumes that and *provides* the attributed peer, protocol id and correlation every app reaches, unchanged on the app's side.

**Capability-by-non-wiring makes raw I/O core permanently, not just at boot.** A confined module holds no ambient authority by construction (§12.2), so it can never hold a file descriptor, at any point in the process's life, no matter what has already been installed. The host owns the socket forever.

What survives all of this is a socket seam with its flood limits, an entropy source, one Ed25519 verify, a policy file with a version floor, a private key, and a map. That is a seed.

## The transport is a bundle

The channel handshake, the record layer, link routing and the request/response frame codec are the guest program of a signed bundle claiming the `transport` role. It is a **guest**, not a WASM handler, and the reason is structural: a §4 handler is a synchronous pure transform that imports nothing and holds no capabilities, which an AKE carrying session state cannot be. State lives in the guest's own heap keyed by a host-supplied link id, and the node key never enters it.

What this buys is that the **protocol** is replaceable without a fork: the handshake's messages, its transcript, the record framing and the dial policy are all content, and a deployment that wants different ones ships a signed bundle and one policy entry instead of a patched runtime.

Two properties make that safe:

- **A transport module is an authority grant, not a preference.** Admitting an ordinary app risks that app; admitting a transport risks the channel, which sees all plaintext and holds the session keys. `roleAllowlist` admits per slot, and an author trusted for apps cannot land a transport without a second deliberate `roles` entry (§12.5).
- **The suite byte makes a mixed period a rollout rather than a corruption.** One suite per link, unknown ids close the connection, and the byte is covered by both signatures and read before verification (§12.6). An in-path attacker who flips it only makes the two ends sign different bytes, so AUTH fails and the link dies.

**It can be swapped under a running node.** A second bundle claiming the slot goes through the ordinary `loadBundle` path: the shell reads the outgoing driver's host-side state, stands the new realm up while the old one is still serving, then closes the old and hands over — same listening port, same node identity. Live links do not survive and are not meant to: session keys live in the outgoing guest's private memory, which is exactly what makes the occupant confineable. An upgrade is a **reconnect**.

The bundle ships inside the host artifact, which closes the metadata window a first fetch would open. Fetching one over raw net — a node bootstrapping its transport from a peer it does not yet trust — is a separate feature and is not implemented.

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
admit each module — policy ok?                       §12.4
        │
        ▼
bindAll([{name, wasm}]) — table updated, all or none §3.1
        │
        ▼
compile & register guest JS in QuickJS realm
(zero-authority, awaits first invocation)
```

Request flow:

```
socket delivers bytes                    host: raw net + flood limits
        │
        ▼
transport bundle: record open, attribute to peer      §12.6
        │
        ▼
host extracts target name, stages input bytes
        │
        ▼
handlers[name] → handler (one map lookup)            §3
        │
        ▼
pure transform at scratch offset → output bytes      §4
        │
        ▼
host frames response through the transport bundle
```

The reference composition stacks the layers so each depends only on the layers below it (§5). Only the bottom row is core:

```
┌─────────────────────────────────────┐
│   App                               │
│   guest (confined JS) +             │
│   pure-transform WASM handlers      │
├─────────────────────────────────────┤
│   Cap-bridge (required if guest     │
│   JS is present; otherwise omitted) │
│   the guest's host.call seam —      │
│   its only reach to real I/O        │
├─────────────────────────────────────┤
│   Kernel                            │
│   handlers[name] → handler          │
│   one map, held by the host         │
├─────────────────────────────────────┤
│   Transport — a signed bundle       │
│   AKE, record layer, link routing   │
│   beneath the kernel, but content:  │
│   replaceable without a rebuild     │
├─────────────────────────────────────┤
│   Raw I/O                           │
│   net: send(link,bytes)/onBytes     │
│   fs:  get/put over a flat key      │
│   limits, entropy, node key         │
│   CORE — no endpoint substitute     │
└─────────────────────────────────────┘
```

**Design principles:**

- **The core is what the endpoints cannot do for themselves.** Authenticity, confidentiality, framing and routing all have endpoint substitutes and are therefore content. Transmission does not, and is therefore core.
- **Lower is not the same as core.** Layering says who may call whom; core-ness says what cannot be replaced without a rebuild. The transport sits beneath the kernel and is still an ordinary bundle. Keeping these separate is what stops "it's foundational" from becoming a licence to grow.
- The kernel does exactly one thing: name resolution and byte dispatch. No built-in policies, I/O, or dispatch loop. Lower layers gate higher layers; each layer sees only downward.
- Untrusted code is **bounded** as well as confined. A WASM handler declares its linear-memory ceiling in its signed manifest and the loader refuses anything unbounded or over budget; a JS guest runs under a heap cap *and* an operator-set execution budget (5 s by default), enforced by a QuickJS interrupt handler on the JS targets and a wazero deadline on the native one. The one gap is **handler** CPU, and it is a missing mechanism rather than a decision: WebAssembly engines on the JS platform expose no fuel or timeout to call (§4.3, §14).
- Modules, as untrusted code, run confined. WASM handlers are synchronous pure transforms — a buffer in, a buffer out, and that is the full extent of their interaction. JavaScript is reserved for code that must await multiple host interactions or maintain state across asynchronous turns, with zero ambient authority and only the single `host.call` seam.
- Node-to-node links are confidential by default — the transport bundle opens each connection with an authenticated key exchange, then carries every frame as a forward-secret, individually-authenticated encrypted record, uniform across TCP, WebSocket and WebRTC and needing no external TLS or Noise tunnel.
- The channel authenticates one hop, not the whole path. An app that **relays** messages through intermediaries cannot lean on the channel to attribute the *original* author, so it layers its own scheme on top. Bundles already work this way, which is why they need no channel at all.
- The kernel is a specification, not a binary. Each host implements the table as a plain map; what must not drift is the bundle load order and the admission rules, and those are shared as one compiled implementation on every target (§12.9).

## One implementation, three targets

The runtime runs in a browser tab, on Node/Bun, and as a single native binary. Anything two nodes could *disagree* about is compiled once and shared; only the platform seam is written per target. The tree says which is which: `WASM/core/` is what has no endpoint substitute, `WASM/host/` is the runtime around it, `WASM/transport/` is signed content.

The line that matters is not `core/` vs `host/` — it is **shared** vs **per-target**, and it is not a matter of opinion: the shared set is exactly the file list `build:loader-bundles` compiles into `host-shell.gen.js`, which the Go binary embeds and runs in QuickJS. Everything else is one target's plumbing. Counts are lines of code — non-test sources with blank lines and comments excluded.

**Shared — compiled once, run by all three targets (2,560 LOC)**

| Concern | Where | LOC |
| --- | --- | --- |
| Bundle format and admission policy (§12.4, §12.5) | `host/bundle.ts`, `host/policy.ts` | 574 |
| Transport driver — channels by link id, timers, outbound promises, the address book. No protocol, no state machine | `host/transport-host.ts` | 495 |
| Cap-bridge — the guest ABI seam (§12.2) | `host/cap-bridge.ts`, `host/realm-queue.ts` | 474 |
| Shell and protocol-id bindings (§12.10) | `host/shell-core.ts`, `host/bindings.ts` | 386 |
| Core seam and vocabulary — the socket/`fs` contracts, the flood bounds, domain prefixes, suite ids, the primitive catalog | `core/*.ts` (8 files) | 369 |
| WebSocket codec and framing | `host/ws/*`, `host/net-frame.ts` | 261 |

**Per-target platform — the seam, written once per target**

| Target | What | LOC |
| --- | --- | --- |
| **JS** (browser + Node) | sockets (TCP/WS/WebRTC), the `fs` backend, the safe-js realm, the kernel table, the PQ module drivers, entry points, key derivation | 1,545 TS |
| **Native** (Go) | QuickJS embedding, event loop, libsodium and the PQ modules over wazero, raw net and fs, the handler table — plus `native-shim.ts` (235), the Go binding, which is TypeScript and rides in the shared bundle | 3,341 Go + 235 TS |

**Signed content — not host code at all**

| | Where | LOC |
| --- | --- | --- |
| Transport bundle — the AKE and record layer, link routing, the request/response frame codec | `transport/guest.js` | 1,006 |

Each target therefore runs 2,560 shared lines over roughly 1,500–3,500 of its own plumbing, and the protocol on the wire is none of it — that lives in the signed bundle.

Shared binaries, byte-identical on every target:

| Artifact | What | Size |
| --- | --- | --- |
| `libsodium.wasm` | Ed25519, BLAKE2b, ChaCha20/XChaCha20 (sumo build) | 278 KB |
| `mldsa65.wasm` | ML-DSA-65, the `0x02` hybrid manifest suite verifier | 17 KB |
| `mlkem768.wasm` | ML-KEM-768, the primitive catalog's KEM | 11 KB |
| `ws.wasm` | RFC 6455 framing — a no-capability module | 5 KB |

The Go platform is the larger of the two only because it has no npm: it embeds its own QuickJS, owns an event loop, and drives libsodium over wazero, where the JS targets get all three for free. It is a bridge, not a second runtime — no manifest verification, no routing and no policy logic lives in Go. The `core/` and `host/` split inside `WASM/` is the *other* axis: `core/` is what has no endpoint substitute, `host/` is the runtime around it, and both contribute to the shared set and to the JS platform.

## Post-quantum posture

The two migrations are on independent clocks and are scheduled on opposite principles.

**The manifest suite has already moved,** because it is the one that can never get cheaper: a PQ verifier cannot be delivered as a bundle, since the classical verifier would be the thing admitting it. Suite `0x02` is **hybrid Ed25519 + ML-DSA-65** over `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖ json`, and **both** signatures must verify — so a flaw in the young half fails closed (valid bundles rejected) rather than open. A hybrid author is a new identity, derived from the whole key set rather than the Ed25519 half (§12.4).

**The channel suite can wait for a credible break,** because when one arrives the fix is a bundle rollout. Its primitive is already provisioned: `ml-kem-768/{keypair,encaps,decaps}` are in the catalog on all three targets, pinned to NIST's ACVP vectors. That was the only part of a PQ channel that could not have been shipped as content — a bundle is replaceable, the vocabulary it draws on is not, so a core vocabulary is provisioned ahead of need or not at all (§14.1).

## Get started

```sh
cd WASM
npm install
npm run build    # ws.wasm + the transport bundle + the shared host
npm test         # the full suite
```

This repo is the runtime only. Apps live outside it and consume the published surface of `seedkernel-wasm`: [seed store](https://github.com/arj03/seedstore) (a P2P storage node) and [seedchat](https://github.com/arj03/seedchat) (the browser P2P chat demo, §11). `npm run build:browser` produces the browser artifacts they vendor. Because those apps live elsewhere, an export with no in-repo caller is not dead code — [EXPORTS](docs/EXPORTS.md) records who consumes what, and is the thing to check before deleting or moving any entry point. The WebRTC signaling rendezvous both use is a deployment concern rather than runtime surface, so it lives with the apps — `npm run relay` in seedchat, which seed store also points at.

`npm run build:pq` rebuilds the two PQ modules from the pinned `pq/mldsa-native` and `pq/mlkem-native` submodules; it needs `git submodule update --init` and a clang with the wasm32 target.

## The rest of the spec

This file is §1 (and §15); the rest of the spec lives in `docs/`, split by concern. Section numbers are global across the set — any `(§X.Y)` reference resolves to exactly one file:

| Doc | Sections | Contents |
| --- | --- | --- |
| [PROTOCOL](docs/PROTOCOL.md) | §2–§5, §16 | The kernel and its handler table, host-level handler management, standing a host up, the pure-transform WASM handler ABI, layering, the protocol constants. |
| [RUNTIME](docs/RUNTIME.md) | §10–§12 | Distribution size, the app layer (chat as the worked example), and the shell: capability backends, the cap-bridge guest ABI, zero-authority JS realms, signed bundles and how the loader admits them under policy, the node↔node transport, the Go/native binary. |
| [SECURITY](docs/SECURITY.md) | §13–§14 | A byte-by-byte worked example and the collected trust model. |
| [CHANNEL](docs/CHANNEL.md) | §12.6.2 | The concealed-identity channel handshake: what the four messages do, the three secrets and their different jobs, purpose-bound key derivation, and where the design sits against Noise, WireGuard and Secret Handshake. Normative text stays in RUNTIME §12.6; this is the *why*. |
| [EXPORTS](docs/EXPORTS.md) | — | The published entry points and which app consumes each, plus the two traps that table exists to prevent. Maintenance surface, not protocol. |

To read the spec as one document, concatenate the files in that order: `cat README.md docs/{PROTOCOL,RUNTIME,SECURITY}.md`. CHANNEL and EXPORTS sit outside that sequence — one is rationale, the other maintenance.

## 15. Background

This project was inspired by the [8k-demo](https://github.com/ssbc/8k-demo) P2P project built on top of secure scuttlebutt running in the browser. The goal was to strip it down to the bare essentials and make the core as small as possible, moving functionality into modules to be distributed in whatever fashion. The end-to-end argument is that goal made decidable: *core* is what the endpoints cannot do for themselves, everything else is a module, and it turns out that leaves the network in the core — but only the part of it that actually moves bytes.
