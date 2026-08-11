# Seed kernel: a sandboxed app runtime that grows from signed bundles

*Every app is a confined JS guest over a library of pure-transform WASM modules; code arrives only as a signed bundle, and untrusted code runs sandboxed anywhere from a browser tab to a single native binary.*

## 1. Vision

A minimal runtime: a **host** admits signed **bundles**, and every bundle is an app with exactly one shape — a confined JS **guest** (the app's logic) plus, optionally, any number of pure-transform WASM **modules** that serve as the app's library. The guest is the only thing an inbound frame reaches: the host resolves the protocol to an app, invokes the guest's one `handle` entrypoint, and the guest drives its own modules by name when it needs a transform. Authorization, capability gating, confinement and application logic are the **host** and its **guests** — layers that compose around the seam without the host knowing what any of them mean. Installing an app is one signed record: the author-derived app key, the guest source, and the module map. Code arrives as a signed **bundle** and the host binds it under a policy. The system bootstraps from one trusted policy (the authors it will install, or none) into arbitrarily complex behaviour.

**The dispatch path stays small because attribution happens below it.** By the time a frame reaches an app it has already been attributed to a peer's key, so there is no envelope to parse, no per-message signature to verify, no signer state to carry across a call and no size cap to enforce. Delivery gets to be one routing lookup and one guest call *because* a layer beneath it did that work. But being beneath the app is not the same as being in the trusted base: the layer that attributes frames is an ordinary signed bundle.

Signing survives where it must — over the **bundle** that installs code (§12.4), which authenticates its author across any number of relays and any number of hostile hops.

**The whole runtime is five components.** Everything after this table is detail:

| Component | Role |
| --- | --- |
| **Host** | The runtime: the same shared JS on every target (browser, Node, or QuickJS inside the native binary, §12.9). It owns the platform seam — sockets, entropy, the clock, the node identity key — the install records and the module table (§3), the inbound dispatch (§12.10), and `loadBundle`, the single admin path that admits new code (§12.4). |
| **Raw I/O** | Two capabilities of the same shape: `net` is `send(link, bytes)` / `onData` over an opaque link id, `fs` is get/put/size/list/delete over an opaque flat key (§12.1). Raw bytes over an opaque name, plus the flood limits that must sit with whoever holds the descriptor. A *link*, not a peer: a peer id is an attributed identity, which is the transport's output rather than the platform's contribution. |
| **Modules** | An app's *library*: pure-transform WASM modules (§4), reached by the guest by their bare name through `host.call` (§12.2). The host stages input at the module's `scratch` offset, calls `handle`, and reads the response back. They import **nothing from the runtime** — no host seam, no I/O of their own — so the sandbox is an absence of wiring rather than a rule. Any language that compiles to WASM qualifies; the contract is three exports and no imports. A module runs only when its app's guest calls it. |
| **Guests** | Every app's logic (§12.2): a zero-authority QuickJS realm holding only the ECMAScript intrinsics, whose entire seam is `host.call(name, …)` out and `realm.call(entry, bytes)` in — serialized per realm and bounded in heap and execution time (§12.3). Inbound delivery is an entrypoint invocation on the app's guest; everything a synchronous pure transform cannot be — session state, app logic, the transport's AKE — lives here, and the modules are the library it drives by name. |
| **Bundles** | The only way code arrives (§12.4): a manifest, a guest JS program, any number of WASM modules, and one author signature over the whole set. The host checks that signature against the operator's policy (§12.5) and the loader admits the app — a policy decision, then one all-or-none bind. **The transport is one of these.** |

There are no special cases and exactly one way to do everything: one app shape (every app is a guest, §12.4), one install path (signed bundles, §12.4), one guest seam (`host.call` out, entrypoint invocation in, §12.2), one post-handshake frame plane (§12.6). The transport is no exception, and that is the load-bearing part: it reaches sockets through names and is driven through named entrypoints, exactly as an app is.

Every table entry is three orthogonal pieces: the **name** is the module's logical name inside its app, the **bytes** are the WASM instance held at that name, and the **author** is the signer of the bundle — half of the app key the entry sits under. The loader lands a whole bundle's modules at once under a deployer-supplied **policy** that decides who may install what (§12.5).

## What belongs in the core

"Make the core as small as possible" is a goal, not a test — everything can always be smaller. The test is Saltzer, Reed and Clark's:

> **A function belongs in a lower layer only if it cannot be correctly implemented at the endpoints.**

Almost nothing usually called "the network" survives it, because almost all of it has an endpoint substitute: authenticity of code is the bundle signature that travels with it, and of a relayed message the relaying app's own signature; confidentiality is the endpoints holding the keys; framing, ordering, correlation and routing are state machines over whole messages; content-addressing, quota and encryption at rest belong to whichever app stores the bytes. All of it is content. **Moving bytes from A to B, or to disk and back, has no substitute — there is no such thing.** That is the argument for raw I/O being core: not bootstrapping, not convenience, not that the crypto is already linked in. There is nowhere else to put it.

The end-to-end test decides *which side* of the line a function is on. A second rule decides *what shape the line has*:

> **A core interface is a flat map over opaque names. If the core must understand what a name *means* in order to serve it, the meaning is content that leaked in.**

Four things follow, and together they are most of what the core is:

- **One seam, name-addressed.** A guest reaches a primitive by name through the same `host.call` it uses for everything else: `host.call("crypto/blake2b-256", …)`, and the host holds the catalog: `crypto/x25519/dh`, `crypto/chacha20poly1305-ietf/seal`, `crypto/ml-kem-768/encaps`. A new algorithm is a catalog entry — no op number, no ABI rev, no manifest field. A host missing a name refuses the load *by name*.
- **A pure transform is not a capability.** A function of bytes the guest already holds is computation it could have done itself — correct and fast rather than permitted. So the seam holds **primitives**, which are free, and **authorities**, which reach something no confined module can hold: the node key, the entropy source, the clock, a socket, the disk.
- **Signing is domain separation, not parsing.** The node's Ed25519 key never leaves the host, so a module that needs a signature asks for one — and the host signs `DOMAIN ‖ scope ‖ opaque`, choosing the domain from which admission point the asking bundle came through, over a suffix it does not read.
- **Raw net is the capability; structured net is what the transport provides.** The raw capability is an opaque link id with bytes in and out — the socket-side twin of `fs`. The transport bundle consumes that and *provides* the attributed peer, protocol id and correlation every app reaches, unchanged on the app's side.

**Capability-by-non-wiring makes raw I/O core permanently, not just at boot.** A confined module holds no ambient authority by construction (§12.2), so it can never hold a file descriptor, at any point in the process's life, no matter what has already been installed. The host owns the socket forever.

What survives all of this is a socket seam with its flood limits, an entropy source, one Ed25519 verify, a policy file with a version floor, a private key, and a map. That is a seed.

## The transport is a bundle

The wire codec, the channel handshake, the record layer, link routing and the request/response frame codec are the guest program of a signed bundle mounted as the node's transport. It is a **guest**, not a WASM module, and the reason is structural: a §4 module is a synchronous pure transform that imports nothing and holds no capabilities, which an AKE carrying session state cannot be. State lives in the guest's own heap keyed by a host-supplied link id, and the node key never enters it. Where a codec *is* a pure transform it ships as one: RFC 6455 is `ws.wasm`, a no-capability module of the same bundle, reached by logical name.

What this buys is that the **protocol** is replaceable without a fork: the handshake's messages, its transcript, the record framing and the dial policy are all content, and a deployment that wants different ones ships a signed bundle and one policy entry instead of a patched runtime.

Two properties make that safe:

- **The transport is an authority grant, not a preference.** Admitting an ordinary app risks that app; granting the transport risks the channel, which sees all plaintext and holds the session keys — so policy is keyed on the *capability*: `authors` says who may load at all, `grants` names a privilege from the catalog and who may hold it (`grants: { "mount": [...] }`). There is no role field a bundle claims for itself, and no class the shell assigns: which privileges are in play is read off `guest.requires`, and requiring `link/open` puts `mount` in that set rather than taking it out, so an author trusted for apps gains nothing by asking (§12.5).
- **The suite byte makes a mixed period a rollout rather than a corruption.** One suite per link, unknown ids close the connection, and the byte is covered by both signatures and read before verification (§12.6). An in-path attacker who flips it only makes the two ends sign different bytes, so AUTH fails and the link dies.

**It can be swapped under a running node.** A second transport bundle loads the ordinary way: the shell reads the outgoing driver's host-side state, stands the new realm up while the old one is still serving, then closes the old and hands over — same listening port, same node identity. Live links do not survive and are not meant to: session keys live in the outgoing guest's private memory, which is exactly what makes the transport confineable. An upgrade is a **reconnect**.

**The first transport ships inside the host artifact, and that is the design rather than a stopgap.** A node has no network until it has a transport, so there is nothing to fetch the first one over except raw net to a peer it does not yet trust — which would open a metadata window before any channel exists to close it. What travels is the *next* transport: a replacement bundle can arrive over the transport already running, like any other bundle, since what admits it is the manifest signature and not the route it took. Upgrading the transport over the network is the point; bootstrapping it over the network is not a goal.

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
│   install records + module table,   │
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
- **Lower is not the same as core.** Layering says who may call whom; core-ness says what cannot be replaced without a rebuild. The transport sits beneath the host and is still an ordinary bundle. Keeping these separate is what stops "it's foundational" from becoming a licence to grow.
- **Not-core is not the same as replaceable.** The bundle verifier, the guest seam and the shell's assembly order all fail the end-to-end test — an endpoint could check a signature perfectly well — and are still permanently compiled in, because each is what would have to admit its own replacement. Core-ness bounds what the design owes the endpoints; the trust root bounds what a rebuild can avoid. They are different sets, and a component outside the core can still be stuck.
- The host's dispatch does exactly one thing: resolve the protocol to an app and invoke its guest. No built-in policies, I/O, or dispatch loop beyond the seam it is handed. Lower layers gate higher layers; each layer sees only downward.
- Untrusted code is **bounded** as well as confined. A WASM module declares its linear-memory ceiling in its signed manifest and the loader refuses anything unbounded or over budget; a JS guest runs under a heap cap *and* an operator-set execution budget (5 s by default), enforced by a QuickJS interrupt handler on the JS targets and a wazero deadline on the native one. The one gap is **module** CPU, and it is narrower than it sounds: a module call is synchronous, so its time is charged to the calling guest's budget and a module that returns is bounded like any other guest segment. What cannot be interrupted is the call itself — WebAssembly engines on the JS platform expose no fuel or timeout to call, and QuickJS ticks only while running bytecode — so a module that never returns holds the thread (§4.3, §14). It is also one step away from the wire: every inbound frame enters under the guest's execution budget, so a module can only be reached through a guest calling it by name.
- Modules, as untrusted code, run confined. WASM modules are synchronous pure transforms — a buffer in, a buffer out, and that is the full extent of their interaction. **Every app's logic is its guest** — a confined JS program with zero ambient authority and only the single `host.call` seam, because session state and async interaction have no other home. A module is what the guest delegates a pure transform to, by its bare name over the same `host.call` seam as everything else.
- Node-to-node links are confidential by default — the transport bundle opens each connection with an authenticated key exchange, then carries every frame as a forward-secret, individually-authenticated encrypted record, uniform across TCP, WebSocket and WebRTC and needing no external TLS or Noise tunnel.
- The channel authenticates one hop, not the whole path. An app that **relays** messages through intermediaries cannot lean on the channel to attribute the *original* author, so it layers its own scheme on top. Bundles already work this way, which is why they need no channel at all.
- The module table is a specification, not a binary. Each host implements it as a plain map; what must not drift is the bundle load order and the admission rules, and those are shared as one compiled implementation on every target (§12.9).

## One implementation, three targets

The runtime runs in a browser tab, on Node/Bun, and as a single native binary. Anything two nodes could *disagree* about is compiled once and shared; only the platform seam is written per target. The tree says which is which: `WASM/core/` is what has no endpoint substitute, `WASM/host/` is the runtime around it, `WASM/transport/` is signed content.

The line that matters is not `core/` vs `host/` — it is **shared** vs **per-target**: the shared set is exactly the file list `build:loader-bundles` compiles into `host-shell.gen.js`, which the Go binary embeds and runs in QuickJS. Everything else is one target's plumbing. Lines of code are computed using: `npm run loc` (in `WASM/`).

**Shared — compiled once, run by all three targets (2,191 LOC)**

| Concern | Where | LOC |
| --- | --- | --- |
| Bundle format and admission policy (§12.4, §12.5) | `host/bundle.ts`, `host/policy.ts` | 570 |
| Transport driver — channels by link id, outbound promises, the address book. No protocol, no state machine | `host/transport-host.ts` | 416 |
| Guest seam — the guest ABI seam (§12.2) | `host/guest-seam.ts`, `host/realm-queue.ts` | 347 |
| Shell and protocol routing (§12.10) | `host/shell-core.ts` | 376 |
| Node startup — the operator flow: the flag set and its defaults, the order a node boots in (§12.5), what it prints | `host/cli.ts` | 179 |
| Core seam and vocabulary — the socket/`fs` contracts, the key space and flood bounds, domain prefixes, the master-seed subkey derivation (§12.6.2b), the manifest suite ids, the primitive catalog | `core/*.ts` (8 files) | 303 |

**Four reasons a row is shared.** The set is not homogeneous, and the differences are what decide whether anything could ever leave it:

- **Trust root.** The bundle format and admission policy, the guest seam, the shell's assembly order. Whatever verifies a bundle, confines a guest or orders the load cannot itself arrive as a bundle — it is the thing that would admit its own replacement. None of it is core by the end-to-end test; all of it is stuck.
- **Vocabulary.** The domain prefixes, manifest suite ids, primitive names and flood bounds in `core/`. A bundle is replaceable and the vocabulary it draws on is not (§14.1); a bundle defining the vocabulary its own signature is verified under is circular.
- **A stable adapter.** The transport driver holds the link ids, the flood caps and the whitelist gate, and it is what keeps the app-facing `send` unchanged *across* a transport swap. Folding it into the thing being swapped is backwards.
- **Reuse.** Protocol routing carries no security property and two nodes disagreeing about one is harmless (§12.10), so that row is shared to keep one rule — a manifest's claim, one dispatch — on every target, not because agreement is load-bearing.

**Wire framing is in none of them, and so it is not here.** Length-prefixing a TCP stream and RFC 6455 are content by the end-to-end test — state machines over whole messages, which an endpoint can run — so they are the transport bundle's, over `ws.wasm` as one of *its* modules. What the host says about a link is which of those codecs applies (`FRAMING`, §12.1); what to do about it is entirely the bundle's. The browser needs none of it: a platform `WebSocket` and an `RTCDataChannel` arrive framed already and go to the driver as they are.

What differs per target is only the object that moves bytes — and wrapping it is host code on every target, because a confined guest never holds a socket, so whoever owns the platform's object does the wrapping. The browser's only socket objects are the platform `WebSocket` and `RTCPeerConnection`, so the JS platform wraps those (`net-ws.ts`, `net-rtc.ts`) — and precisely because the browser has no raw TCP, WebSocket exists as a codec over a raw TCP listener, which is why a *node* answers a browser's WS with no extra host code: the same `node:net` socket with `FRAMING.WS_*` declared, RFC 6455 in `ws.wasm`. Node also wraps `node:net` for TCP; Go wraps nothing — raw sockets are native there (`net.go`/`sock.go`), and the same `ws.wasm` serves its `--ws-listen`. WebRTC is the one adapter with no Go counterpart, because RTC exists for the browser's NAT traversal: a native node is a reachable server, so it is never the dialing side of an RTC link. Whatever the object, it lands in the driver's `openLink` and the bundle cannot tell the transports apart.

**Per-target platform — the seam, written once per target**

| Target | What | LOC |
| --- | --- | --- |
| **JS** (browser + Node) | sockets (TCP/WS/WebRTC), the `fs` backend, the safe-js realm, the module table, the PQ module drivers, entry points, key derivation | 1,338 TS |
| **Native** (Go) | QuickJS embedding, event loop, libsodium and the PQ modules over wazero, raw net and fs, the module table — plus `native-shim.ts` (386), the Go binding, and `native-polyfills.ts` (93), the Web globals QuickJS lacks, both TypeScript and both riding in the shared bundle | 2,047 Go + 479 TS |

**Signed content — not host code at all**

| | Where | LOC |
| --- | --- | --- |
| Transport bundle — the wire codecs, the AKE and record layer, link routing, the request/response frame codec | `transport/src/*.js` + `ws.wasm` | 1,237 + 5 KB |

Each target therefore runs 2,191 shared lines over roughly 1,500–2,500 of its own plumbing, and nothing on the wire is any of it — the codec that frames a link and the protocol inside it both live in the signed bundle.

Three wasm binaries are shared the same way and for the same reason: `libsodium.wasm` (Ed25519, BLAKE2b, ChaCha20/XChaCha20, sumo build), `mldsa65.wasm` (ML-DSA-65, the `0x02` hybrid manifest suite verifier) and `mlkem768.wasm` (ML-KEM-768, the primitive catalog's KEM). Byte-identical on every target, because a verifier two nodes disagree about is a bundle one admits and the other refuses. Their sizes are the distribution figures in [RUNTIME §10.2](docs/RUNTIME.md).

The Go platform is the larger of the two only because it has no npm: it embeds its own QuickJS, owns an event loop, and drives libsodium over wazero, where the JS targets get all three for free. It is a bridge, not a second runtime — no manifest verification, no routing and no policy logic lives in Go. The `core/` and `host/` split inside `WASM/` is the *other* axis: `core/` is what has no endpoint substitute, `host/` is the runtime around it, and both contribute to the shared set and to the JS platform.

## The overhead, measured

The fair follow-up to all these seams is whether confinement costs throughput. The proof that it does not is [seed store](https://github.com/arj03/seedstore): a complete storage layer including client-side encryption, Reed–Solomon erasure coding, content addressing, repair shipped as two WASM modules and a confined guest. Its measured numbers are the answer:

- **The full write path — encrypt, hash every block, RS-encode — runs at ~210 MB/s on one thread** (100 MB, RS(10,6), 64 KB blocks, Node 20), balanced across its three pieces: xchacha20 at ~545 MB/s, BLAKE2b block-ids at ~1.1 GB/s, SIMD RS encode at ~670 MB/s. Those are the codec's own computations and they dominate — the runtime's seam between guest and module is not where the time goes.
- **A read with every block present is ~3 GB/s** — the code is systematic, so a full read is a concatenation with no GF(2⁸) work at all; only a missing block pays a decode, at ~625 MB/s.
- **End to end, the link bounds throughput, not the runtime:** ~11 MB/s PUT and ~17 MB/s GET over a 10 ms-RTT, WebRTC-capped link with windowed round trips, and ~13 MB/s browser-to-browser — all through the same signed transport bundle every app gets.
- **The whole layer ships as ~15 KB of WASM plus ~8 KB of gzipped guest JS**, reusing the libsodium the runtime already loads rather than bundling a second copy of a crypto library. The numbers reproduce with `node tests/bench.mjs` in the seedstore repo.

## Post-quantum posture

The two migrations are on independent clocks and are scheduled on opposite principles.

**The manifest suite has already moved,** because it is the one that can never get cheaper: a PQ verifier cannot be delivered as a bundle, since the classical verifier would be the thing admitting it. The one manifest suite, `0x02`, is **hybrid Ed25519 + ML-DSA-65** over `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖ json`, and **both** signatures must verify — so a flaw in the young half fails closed (valid bundles rejected) rather than open. An author is a key-set identity, derived from both keys rather than the Ed25519 half (§12.4). The artifact ships hybrid from the first build: the transport bundle — the one signed bundle every deployment loads — is signed under `0x02` by `scripts/build-transport-bundle.mjs`. That is also why the Ed25519-only genesis suite `0x01` is **retired, not deprecated**: with every target verifying `0x02` and no deployed genesis authors, keeping it alive would have bought a second envelope, a second identity rule and a policy dial for a migration nobody is on. The byte stays reserved for a later suite (§14.1).

**The channel suite can wait for a credible break,** because when one arrives the fix is a bundle rollout. Its primitive is already provisioned: `ml-kem-768/{keypair,encaps,decaps}` are in the catalog on all three targets, pinned to NIST's ACVP vectors. A KEM is the PQ stand-in for the DH step of the channel's key agreement: `encaps(pk)` wraps a fresh shared secret in a public key and `decaps(sk, ct)` unwraps it, where the current suite computes the same secret with `x25519/dh` over the two ephemerals. A `0x03` suite is expected to run both — msg1 gains the initiator's ML-KEM encapsulation key, msg2 the responder's ciphertext, and the KEM secret joins the DH secret in the key schedule — so the classical half stays load-bearing while the PQ half is young, and only the handshake widths change, never the record layer. That was the only part of a PQ channel that could not have been shipped as content — a bundle is replaceable, the vocabulary it draws on is not, so a core vocabulary is provisioned ahead of need or not at all (§14.1).

**What that leaves open.** The bundle clock is closed, and the symmetric half needs no clock at all: the ChaCha20-Poly1305 record layer, the catalog's seal/open and the BLAKE2b hashes are already PQ-safe, because a quantum computer threatens only discrete-log and signature keys, never 256-bit symmetric or hash work. The channel clock is the one still running — its session keys are ephemeral X25519, the harvest-now exposure: ciphertext recorded today decrypts when the DH problem breaks, and no retrofit can change that, which is why the `0x03` KEM rollout is the remaining deadline. Nothing else about that fix is missing: the primitive is provisioned, the handshake is a state machine in the transport bundle's guest program, and a replacement bundle loads like any other — swapped under a running node, no rebuild. Its transcript signatures stay Ed25519 on purpose, because a forgery is only live (it cannot retroactively install a bundle) and so that half can genuinely wait for a credible break. One entry the two clocks missed is the guests' own Ed25519 signatures ([SECURITY §14.2](docs/SECURITY.md)), whose clock depends on the record's lifetime like the AUTH half.

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
| [PROTOCOL](docs/PROTOCOL.md) | §2–§5, §16 | The module table, host-level module management, standing a host up, the pure-transform WASM module ABI, layering, the protocol constants. |
| [RUNTIME](docs/RUNTIME.md) | §10–§12 | Distribution size, the app layer (chat as the worked example), and the shell: capability backends, the guest-seam ABI, zero-authority JS realms, signed bundles and how the loader admits them under policy, the node↔node transport, the Go/native binary. |
| [SECURITY](docs/SECURITY.md) | §13–§14 | A byte-by-byte worked example and the collected trust model. |
| [CHANNEL](docs/CHANNEL.md) | §12.6.2 | The concealed-identity channel handshake: what the four messages do, the three secrets and their different jobs, purpose-bound key derivation, and where the design sits against Noise, WireGuard and Secret Handshake. Normative text stays in RUNTIME §12.6; this is the *why*. |
| [EXPORTS](docs/EXPORTS.md) | — | The published entry points and which app consumes each, plus the two traps that table exists to prevent. Maintenance surface, not protocol. |

To read the spec as one document, concatenate the files in that order: `cat README.md docs/{PROTOCOL,RUNTIME,SECURITY}.md`. CHANNEL and EXPORTS sit outside that sequence — one is rationale, the other maintenance.

## 15. Background

This project was inspired by the [8k-demo](https://github.com/ssbc/8k-demo) P2P project built on top of secure scuttlebutt running in the browser. The goal was to strip it down to the bare essentials and make the core as small as possible, moving functionality into modules to be distributed in whatever fashion. The end-to-end argument is that goal made decidable: *core* is what the endpoints cannot do for themselves, everything else is a module, and it turns out that leaves the network in the core — but only the part of it that actually moves bytes.
