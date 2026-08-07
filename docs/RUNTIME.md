# Seed kernel — Runtime

*The runtime as an app host: performance, the chat demo, and the shell — capability backends, the cap-bridge guest ABI, zero-authority JS realms, signed bundles, the node↔node transport, and the Go/native binary.*

> **Part of the [seed kernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · [PROTOCOL](PROTOCOL.md) §2–§5, §16 · **RUNTIME §10–§12** · [SECURITY](SECURITY.md) §13–§14

---

## 10. Performance

The message path does **no asymmetric cryptography and no recursion**: routing a frame to an app is a bindings lookup (§12.10) plus one guest entrypoint invocation, and the only scratch copies are the ones a guest's `module/call` makes (§4). No per-message signature verify sits on that path: authenticity is the channel's (§12.6), established once when the link opens rather than checked per message.

### 10.1 Where the crypto is now

So the costs worth measuring are the three places real cryptography lives, all off the dispatch hot path:

- **Per connection:** the AKE handshake (§12.6) — one Ed25519 sign + verify and one X25519 exchange, amortised across the whole session.
- **Per frame:** one ChaCha20-Poly1305 record seal/open (§12.6) — symmetric, fast, the steady-state transport cost.
- **Per bundle load:** one manifest verify — Ed25519 under suite `0x01`, Ed25519 *and* ML-DSA-65 under `0x02` (§12.4) — plus a BLAKE2b-256 content hash per module. Once, at install, which is why the hybrid suite's extra verify and its ~5.3 KB envelope cost nothing that shows: a manifest is never on the message path (§13).

The Go/native target carries `*_bench_test.go` benchmarks over these hot paths (net round-trip, fs, the crypto primitives, the record layer); `WASM/tests/run.mjs` exercises the same paths end-to-end on the JS target, and seed store's `WASM/tests/bench.mjs` measures storage throughput. There is no signed-message microbenchmark anymore because there is no signed message — a chat frame crosses the WASM boundary only for the module call its guest makes.

### 10.2 Distribution Size

This is the one place these figures live; the README's shared-artifact list points here rather than restating them.

| Component | Size |
|---|---|
| host/*.js — minified (`build-min`, runtime code only; ~40 KB gzipped) | ~132 KB |
| the embedded transport bundle (`host/transport-bundle.js` — the signed `.skb` as base64, so 4/3 of its 84 KB; ~40 KB gzipped) | ~112 KB |
| libsodium.wasm (sumo build: Ed25519 + BLAKE2b + XChaCha20, the §12.1 backends) | 278 KB |
| libsodium-wrappers.mjs + libsodium-core.mjs | 152 KB |
| mldsa65.wasm (ML-DSA-65, the PQ half of manifest suite `0x02`, §12.4) | 18 KB |
| **Total browser deployment** | **~692 KB** |
| mlkem768.wasm (ML-KEM-768, the primitive catalog's KEM, §14.1) — loaded by the Node and native hosts; the browser demo does not fetch it, because nothing in it calls the KEM yet | 12 KB |
| QuickJS realm engine (the single release-sync build, from `quickjs-emscripten`) — only loaded when a bundle's guest runs (§12.3) | ~750 KB |

The table costs nothing to ship: it is a map inside the host (§3), not a module. The `host/*.js` layer is the whole runtime — it holds the install records and the module table, reaches modules by name (`callModule`), admits bundles under policy (§12.4–§12.5), and carries the whole shell (§12) — the raw net and fs seams, the cap-bridge, safe-js, bundle verification, policy, and the transport *driver* (§12.6), which is shared JS rather than a per-target reimplementation. The transport *protocol* is the row beneath it and not part of that figure: it is the guest program of a signed bundle (`transport/guest.js` plus `ws.wasm`), and it ships inside the artifact — inlined as base64 so a first fetch cannot open a metadata window — but it is content, replaceable by a second signed bundle without touching a byte above. libsodium is the host's crypto library — it backs the whole primitive catalog (§12.1) plus content hashing and the manifest signature: BLAKE2b-256, Ed25519, ChaCha20 / XChaCha20; the sumo build is larger than a sign-only build because it backs all of them. Content hashing is BLAKE2b (`crypto_generichash`), the one hash the whole system uses (§5.1). `mldsa65.wasm` is small for the opposite reason: one parameter set, no libc and no imports at all (§12.4), so it is 18 KB rather than a library. The QuickJS engine is lazy: a shell that loads no app never pays for it. Since every app is a guest (§12.4), every shell that hosts apps pays it — the browser chat demo (§11) now does too, which is the honest price of having one app shape.

`npm run build` emits the host twice: the readable `build/` (~287 KB of runtime code, doc comments intact) for debugging and a comment-stripped `build-min/` (~132 KB, ~40 KB gzipped) for shipping — the sources are more than half doc comment, which is where the halving comes from. A small dependency-free stripper (`scripts/minify.mjs`, each output gated through `node --check`) does the cut — no bundler, no new dependencies. The table's host figure is the shipped, minified build.

---

## 11. Example app layer: chat ([seedchat](https://github.com/arj03/seedchat))

Chat is the smallest possible app: a confined JS **guest** over a single **pure-transform** module (§4). The guest is a handful of lines — its `handle` entrypoint forwards its input to the module by name through `module/call` and returns the render bytes — and the module is the transform: it does no I/O and no crypto, reading `senderPk ‖ chatType ‖ body` and writing the render bytes for the UI. Everything around it — authenticating the sender, moving frames, driving the iframe — is the shell's job, because a pure transform has no reach of its own and a guest reaches the world only through `host.call` (§12.2).

The app itself lives in [seedchat](https://github.com/arj03/seedchat), not in this repo. Like [seed store](https://github.com/arj03/seedstore), it is a *consumer* of the runtime: it installs `seedkernel-wasm` and reaches the host only through published entry points (`shell-core`, `bundle`, `net-rtc`, `libsodium`). Nothing here knows chat exists — this section describes it because it is the shortest complete trace of the whole stack, and §13 walks the same pipeline byte-by-byte.

What the demo stands up is a browser shell owning the host's table and its one install path, a WebRTC socket seam (`RtcNetwork`, `host/net-rtc.ts`, §12.7) under the transport bundle, the safe-js guest realm, and a sandboxed iframe — every byte of chat UI and logic arrives as a signed bundle admitted at runtime.

On load it generates an Ed25519 identity, constructs a host (§3), and loads an admission policy (§12.5) approving modules whose author is the local identity — or, for apps received from a peer, one the user consents to. That consent decision is the browser's own policy state, and it is the only one the shell has to make: names cannot contend (§5.1), so a multi-app shell arbitrates *whether code runs*, never *who holds a name*. The table starts empty. The user picks a chat app (`v1 — text only`, `v2 — text + image + nick`); the shell builds a **signed bundle** — a `manifest.bundle` (the local key's Ed25519 signature over the manifest, which commits to the guest's and the module's `genesisHash`) plus `guest.js` and the app's `.wasm`, packed into one blob (§12.4) — verifies it, and the loader admits the app under that policy (§12.4). This is the *same* bundle format seed store loads; a chat app is just a guest that calls its one module. Upgrading v1→v2 is a re-admit at the same name under the same key — the same key derives the same name — and it keeps the `chat` binding it already held (§12.10). Peers hand these bundles to each other in an `OFFER` frame; the recipient re-verifies the original author's manifest signature and admits it the same way — and because the manifest signs the guest and module hashes, the bundle survives any number of transitive relays and still authenticates against its original author (the store-and-forward property an offer needs, §12.4).

Peers connect over a WebRTC mesh from `RtcNetwork` (`host/net-rtc.ts`, §12.7) — the same relay-signaled, perfect-negotiation fabric the storage demo uses, here consumed directly for fire-and-forget `send`. The signaling relay (`scripts/relay.mjs` in seedchat — app-neutral infrastructure that ships with the apps because the runtime itself has no server to run) is only the rendezvous for the SDP/ICE exchange and can be killed once channels are open. Every frame `RtcNetwork` delivers is already attributed to an authenticated peer (§12.6), so chat messages ride the Transport request plane like everything else — `[req][protocolId][type][chatType‖body]`, one plane, one dispatch scheme — and the shell treats the channel's `_from` as the message author: on receipt it resolves the protocol id through its bindings to an app key (§12.10), prepends that authenticated pubkey to the input, and invokes the app's guest `handle` entrypoint under the execution budget (§12.3); the guest forwards to its chat module through `module/call`, and the shell posts the returned render bytes to the iframe. A peer's frame therefore says only *what protocol this is*; which of the chat apps the receiving user holds renders it is that user's own binding, so two peers running different authors' chat apps interoperate as long as both speak the protocol. Because a chat frame travels a **single hop** over the authenticated link, the channel's hop-by-hop attribution *is* end-to-end here — there is no envelope signer to verify and nothing relayed (contrast a feed or forum, §5.1, which would sign each message and chain it). Audio/video publishes over the same `RTCPeerConnection`s; a network change kicks an ICE restart (`RtcNetwork.restartAllIce`) so a transient drop recovers without reconnecting.

The relay is partitioned into **rooms** so one instance hosts many independent groups without cross-talk. A client picks its room as the URL path — `ws://host:8080/<room>` — and the relay forwards only between sockets sharing a room; a bare `/` lands in the default room `global`. Room names are URL-safe (`[A-Za-z0-9._-]`, ≤128 chars). The room is **not** an authenticated channel — knowing the name is the only credential, and the relay sees all signaling in its room — but the end-to-end identity binding below means a relay or room member cannot impersonate a peer, only observe SDP metadata and refuse to forward.

`RtcNetwork` (`host/net-rtc.ts`) is only the WebRTC socket seam: it hands each data channel to the transport driver, and the transport bundle runs its handshake *inside* that channel (§12.6), so each end proves it holds the private key for the identity it claims *before* any frame is delivered — and neither identity crosses the wire in the clear, then every later frame rides the §12.6 ChaCha20-Poly1305 record layer, attributed to that identity rather than to anything inside the frame. This is continuous channel binding, stronger than a one-shot SDP `a=fingerprint` assertion at the signaling layer (RFC 8827 §5.6.4) — a MITM relay can splice SDP and bring DTLS up to itself, but can never produce the transcript signature without the peer's private key, so the link never authenticates and never delivers a byte. The record layer already makes every frame confidential and integrity-protected; the data channel's own DTLS is a redundant second layer underneath (§12.7).

The chat module never reaches the UI itself: it is a pure transform that *returns* render bytes, which the guest's `handle` passes back to the shell, which forwards them to the iframe by `postMessage`. The iframe is `sandbox="allow-scripts allow-forms"` with no same-origin access to the shell, so app-rendered content stays walled off from the shell's keys and peer state.

Two conventions in that demo are worth naming as **not** runtime contracts: the `ui` and `app_meta` WASM custom sections. Bundling the UI bytes inside the app module means one signed install updates compute and presentation atomically, and `app_meta` lets a dropped `.wasm` identify itself — but the host reads neither. Both are encoded and parsed entirely by the shell, so they live in seedchat, and another app is free to ignore or replace them.

The one cost of this shape: the demo runs a guest realm, so it fetches the lazy QuickJS engine (§10.2) where a module-only shell once did not — the honest price of having exactly one kind of app (§12.4).

To run it: build this repo (`npm run build:browser`), then follow the build steps in seedchat, which vendors the artifacts above, runs the signaling rendezvous (`npm run relay`), and serves its own page.

---

## 12. The runtime as an app host: capabilities, the shell, and signed bundles

Chat (§11) is a browser shell wired by hand, in its own repo. The same onion ships as a **general runtime artifact** — the *shell* — that any app rides on as **signed content**. The shell knows nothing about chat or storage; it offers a fixed, generic surface, verifies a bundle against a policy, and *becomes* whatever the bundle is. [seed store](https://github.com/arj03/seedstore) is the worked example: a full peer-to-peer storage node is the shell plus a signed bundle, with no storage-specific code in the runtime.

"Capabilities" from here on mean one thing: the **manifest requires** (§12.2, §12.4) — the exact `host.call` authorities (`node/sign`, `fs/get`, `net/send`, `timer/arm`, …, plus the two halves only the explicit transport mount may declare, `link/*` and `transport/*`) that a bundle's signed manifest declares for the app's confined JS *guest*. They answer "may this *app's guest* reach this backend at all?" (WASM modules, by contrast, carry no capabilities at all — a pure transform reaches nothing but the input it is handed and the output it returns, §4.2.)

**Only authorities are grants, and only grants are declared.** A crypto primitive is a function of bytes the guest already holds, so it reaches nothing and there is nothing to grant: the guest calls it by name through one ungated op and the host resolves it in a catalog (§12.2). The same rule exempts `module/call`: an app's modules are its own bundle's code, installed and verified with it, so calling one reaches nothing the guest does not already hold — the scope (one app's map) is the shape, not a grant. Neither is *declarable* either: `guest.requires` carries authorities and nothing else, so the list an operator reads is exactly the bundle's reach. The reason is that neither can be missing — the primitive catalog is total on any host that has a cap bridge, and a bundle's modules arrive inside the bundle — so declaring them would be a requirement on something that cannot fail, and a dozen such names would bury the two or three that carry real authority. What a guest needs from that half of the seam is `guest.abi`, which versions every name in it.

The manifest's `guest.requires` field is the guest's *entire* authority — which is why it lives inside the signed manifest, nested under `guest`, and nowhere else. It has to: the guest is not a module — it has no name in the module table at all, so nothing below the signed manifest could carry its authority.

### 12.1 Raw-byte capability backends

The runtime provides the capability *backends* an app's confined logic drives through the cap-bridge (§12.2). They are deliberately structureless — bytes in, bytes out — so the host never learns what an app means by them:

- **The primitive catalog** — a flat map from an opaque **name** to a pure transform, reached by name through the `crypto/` prefix of the one seam and served by the bundled sumo libsodium plus `mlkem768.wasm` (`host/cap-bridge.ts`, backed by `loadCrypto`). The names are declared in `core/domains.ts` as `PRIMITIVE_NAMES`: `blake2b-256`, `ed25519/verify`, `xchacha20/xor`, `chacha20poly1305-ietf/{seal,open}`, `x25519/dh`, `ml-kem-768/{keypair,encaps,decaps}`. **This is not a capability.** Every entry is a function of its arguments and reaches nothing a guest could not have computed with code of its own — no key of the host's, no entropy, no state — so there is nothing to grant and nothing gates it. Adding an algorithm is a catalog entry: no op number, no ABI rev, no manifest field. Entropy is deliberately absent from it, which is what keeps it functional: an ephemeral keypair is `node/random(32)` — an authority — followed by `crypto/x25519/dh` against the base point.

  **Why the sumo build, and what it would take to leave it.** Of every libsodium symbol the runtime uses, exactly one is absent from the standard build: `crypto_stream_xchacha20_xor`, which backs the `xchacha20/xor` primitive. Dropping to the core build would save 79 KB across the wasm and its loader (430 → 351 KB, ~14% of the browser deployment; ~0.8% of the native binary) at the price of a hand-written stream cipher in the trusted base on all three targets. Unlike ML-DSA-65 that buys no capability libsodium lacks — only bytes — so the sumo build stays. If browser payload ever becomes the binding constraint, the migration is the one `withMlDsa65` already demonstrates (§12.4): mix `crypto_stream_xchacha20_xor` onto the `sodium` object from a small module with the core build underneath. Keeping the method *on the object* is what makes it free for consumers, because the symbol is also reached directly by host-side app code, not only through this seam.

  The **app-supplied half** of that catalog is the bundle's own module map: `module/call` reaches the asking bundle's WASM modules by their manifest names (§12.2), ungated for the same reason — they are the bundle's own code, verified with it at install — and scoped structurally (the bridge holds one app's map) rather than by a grant.
- **The authorities** — everything that reaches something no confined module can hold. `node/sign` under the node identity but **scoped**: the host prepends a domain and a host-derived scope to the message before signing (§12.2), so a guest never obtains a raw node-key signature and raw signing stays host-internal. `node/verify` is scoped the same way — the host applies `domain ‖ scope` to a caller-named key's signature, so a guest checks a signature under its own bundle's namespace and never reconstructs the prefix. `node/identity` (the node's public key), `node/random` (the OS entropy source), `clock/now`, `timer/*` (the platform's event loop).
- **`fs`** — raw bytes under an opaque, flat key (`core/fs.ts`): `get`/`put`/`size`/`list`/`delete`/`stat` (existence is `size ≥ 0`, so there is no separate `has`). An in-RAM `MemoryFs` (`host/fs-memory.ts`) and a directory-backed `NodeFs` (`host/fs-node.ts`), with OPFS/IndexedDB the shape a browser backend fills in. No content-addressing, no paths — that's app policy.

  **Every method is asynchronous, and that is the seam's property rather than any backend's.** A synchronous `get(key): Uint8Array | null` is a shape no browser backend can implement — IndexedDB is asynchronous by construction and OPFS is synchronous only inside a Worker — so a sync seam would have made the browser the one target unable to carry a capability that is *core* (§1). `MemoryFs` and the native target's Go primitive both answer in the call and are wrapped to resolve in a microtask, because a seam that resolved sometimes-immediately would let a guest work by accident on one backend and fail on the backend it ships against. It follows on the guest side too: the `fs/*` names round-trip like `net/send`, so a guest reads them with `await`, and which side of the sync/async line a name sits on is what `guest.abi` versions (§12.4).
- **Two nets, and they are different capabilities.** `link` is the platform's whole contribution to the network: bytes over an **opaque link id** the host mints and the guest never interprets — open, send, close, and a read of the link's unsent backlog (`link/*`, §12.2). There is no peer here, no protocol id and no correlation, because a peer id is an *attributed* identity, which is an output rather than a contribution. The `net` domain is the **structured** face — `send` to an attributed peer under a protocol id, and `peers` — and it is the transport bundle's output, reached by an ordinary app through the same seam as anything else (§12.2, §12.3). A guest fans out itself with `Promise.all` over `net/send`. The mounted transport consumes the first and provides the second (`transport` domain); nothing else holds both, and neither `link` nor `transport` is an app capability (§12.5).

  **A link says how it is framed, and that is the only thing the platform says about it.** Some transports carry message boundaries and some do not: a browser `WebSocket` and an `RTCDataChannel` deliver whole messages, a TCP socket delivers arbitrary slices. So a link opens with a `FRAMING` code (`core/socket-seam.ts`) — `PLATFORM`, `LENGTH`, `WS_CLIENT`, `WS_SERVER` — and the transport bundle runs the named codec. The host is not describing the socket; it is naming which of the codecs the bundle already holds applies to a link the host has **already opened**. A dialed WebSocket also carries the `authority` it was dialed at, because RFC 6455 requires it in the `Host` header. Neither is a route the guest could dial for itself, which is the property that matters: the link id stays opaque and the address book stays the host's.

  Under the platform the socket seams are `host/net-node.ts` (node:net), `host/net-rtc.ts` (WebRTC, §12.7) and `host/net-ws.ts` (a browser `WebSocket`), each handing a link to the driver in `host/transport-host.ts`; the flood bounds that must sit with whoever holds the descriptor are `core/net-limits.ts` (§12.6.2), declared by the host and applied by the bundle's framers, which are the code that sees a length before its body.

Anything with *structure* is a **no-capability module** that transforms bytes: WebSocket framing is `ws.wasm`, a module of the transport bundle; Reed–Solomon erasure coding is an app's `codec.wasm`. Both are pure transforms their own bundle's guest drives by logical name, never something the host or the platform knows.

### 12.2 The cap-bridge: the guest name ABI

An app's confined logic reaches all of the above through a single seam, `host.call(name, bytes)` — the guest's one route to real I/O, the counterpart to the host's own `callModule`. `host/cap-bridge.ts` (`./cap-bridge`) services that seam from the primitives above and *only* those. Every name is application-neutral; the bridge has no idea it is hosting storage.

The names are a **shared guest↔host identifier**, not a wire value: a flat catalog of opaque strings, the same shape as `PRIMITIVE_NAMES` — no op numbers, no generated `const CAP_X = n;` preamble, no second copy of anything anywhere. The guest writes the literal string ("fs/get", "net/send", "crypto/blake2b-256"); the bridge dispatches the same list. Multi-byte integers are big-endian (§16).

**There are two kinds of entry here and only one of them is a capability.** The `crypto/` entries — and `module/call` — are the *primitive* seam: the first is a flat map over opaque names resolved in the host's catalog (§12.1), the second reaches the bundle's own module map, and both are ungated by a rule rather than by omission, because a function of bytes the guest already holds — or code the bundle itself shipped — is computation, not permission. Every other name is an *authority*: it touches the node key, the entropy source, the clock, a socket or the disk, and is gated through the domains below. That split is why a new algorithm never appears in this table — the `crypto/` entries are derived from `PRIMITIVE_NAMES`, so adding one to that list extends this one.

| Name | Request | Response |
| --- | --- | --- |
| `crypto/<primitive>` | the primitive's argument bytes | its output — dispatched through the catalog (§12.1); an unknown name throws |
| `node/sign` | message bytes | 64-byte detached Ed25519 signature under the node identity, over `domain ‖ scope ‖ msg` — both host-supplied from the asking bundle's slot (below, §16.1), never guest-supplied |
| `node/verify` | `[pk 32][sig 64][msg ..]` | `[ok u8]` — the same `domain ‖ scope` applied host-side: 1 iff `sig` is a valid Ed25519 signature of `domain ‖ scope ‖ msg` under `pk`. The key is caller-named, the scope is not. A payload too short to hold the fixed 96-byte prefix throws rather than answering 0 — a mis-framed call is not a failed verification |
| `node/identity` | (empty) | the node's 32-byte public key |
| `node/random` | `[n u32]` | `n` random bytes |
| `net/send` | `[peer 32][pidLen u8][protocolId utf8][payload ..]` | `[ok u8][response ..]` |
| `net/peers` | (empty) | `[count u32][pk 32 ×count]` |
| `fs/get` | key (utf8) | `[0]` absent \| `[1][bytes ..]` — **awaited** |
| `fs/put` | `[klen u32][key][bytes ..]` | (empty) — **awaited** |
| `fs/list` | prefix (utf8, may be empty) | `[count u32] {[klen u32][key]}` — **awaited** |
| `fs/delete` | key (utf8) | (empty) — **awaited** |
| `fs/stat` | (empty) | `[used u64][available u64]` — **awaited** |
| `fs/size` | key (utf8) | `[size i32]` (−1 if absent) — **awaited** |
| `module/call` | `[name_len u8][name utf8][request ..]` | the installed module's response bytes — `name` is the logical name from the manifest, which is the key it is bound under inside this app's module map — the app key is the one the bridge was built with (§12.4) |
| `clock/now` | (empty) | now in unix ms (`u64`) |
| `link/open` | `[dest ..]` — an opaque destination name the host resolves in the address book it was configured with, exactly as `fs` resolves a key | `[linkId u32][framing u8][authLen u32][authority utf8]` (link 0 ⇒ no route). `framing` names the wire codec to run over this link; `authority` is the `host:port` it was dialed at, non-empty only for a dialed WebSocket (§12.1) |
| `link/send` | `[linkId u32][bytes ..]` | (empty) |
| `link/close` | `[linkId u32][graceful u8]` | (empty) |
| `link/stat` | `[linkId u32]` | `[buffered u32]` — bytes written to this link that are not yet on the wire; 0 for a link that is gone or cannot say |
| `timer/arm` | `[id u32][ms u32]` | (empty) — fires the `timer` entrypoint |
| `timer/clear` | `[id u32]` | (empty) |
| `transport/deliver` | `[corr u32][noReply u8][from 32][pidLen u8][proto][payload ..]` | (empty) — an inbound request, attributed. Answered later through the `respond` entrypoint, never inline |
| `transport/settle` | `[corr u32][ok u8][payload \| utf8 message]` | (empty) — settle an app's outbound request under the corr the host assigned |
| `transport/link-auth` | `[linkId u32][conceal u8][pk 32]` | `[admitted u8]` — this link authenticated as `pk`; the host's whitelist gate answers |
| `transport/peer-edge` | `[up u8][pk 32]` | (empty) — a peer's first link came up / last went down |
| `transport/ready` | `[ok u8]` | (empty) — answer to the `ready` entrypoint |
| `transport/link-down` | `[linkId u32][reason u8]` | (empty) — a link the host handed over tore down, with why |

The `link/*` names are the **raw** net capability and `transport/*` is what the mounted transport **provides** back; both directions ride this one seam rather than a second host↔module ABI, and inbound bytes arrive the other way, as ordinary entrypoint invocations on the mounted transport's guest (§12.6).

`net/send` and the six `fs/*` names genuinely round-trip: the guest `await`s them, and a fan-out is the guest's own `Promise.all` — the seam hands out real promises, so scatter-gather is the guest's own, not a host name. Every other name resolves to bytes without yielding, and **which side of that line a name sits on is the ABI**: moving one is exactly what `guest.abi` versions (§12.4), because the failure is otherwise silent — a guest that forgets the `await` reads a Promise as bytes. **No name re-enters the realm**, which is what lets the mounted transport call out from inside a synchronous entrypoint: a socket write does not deliver during the write, an armed timer fires on a later turn, and `transport/deliver` is answered through the `respond` entrypoint rather than inline.

**The signing names are scoped, never raw, and the scope comes from the slot.** `node/sign` does not sign the guest's bytes as given: the host prepends a domain and a scope, both of its own choosing, and never reads the suffix. An ordinary app gets `DOMAIN_guest ‖ author_pk ‖ app_len u8 ‖ app` (`appSignScope`), derived from the admitted manifest (§12.4) — the same `(author, app)` pair that keys freshness. The **transport slot** gets `DOMAIN_channel ‖ network_key` (`transportSignScope`), which is what lets the AKE transcript signature be an ordinary `node/sign` call: no handshake shape is pinned into the core, and the node key never enters the guest. The domain-prefix family is disjoint (§14, §16.1), so a guest-obtained signature never verifies as a manifest; and distinct bundles derive disjoint scopes, so one app cannot sign in another's namespace. **Verification is scoped the same way.** `node/verify` takes the verifying key in its argument bytes — `[pk 32][sig 64][msg …]` → `[ok u8]` — and the host applies the same `domain ‖ scope` prefix, so an app checks a scoped signature by naming the key and never reconstructs the prefix the host owns. It is an authority like `node/sign` because the scope is host-derived: the guest asks "does this signature verify under *my* bundle's namespace?", a fact it cannot state for itself. The raw `crypto/ed25519/verify` primitive stays, ungated like every pure transform, for callers verifying raw bytes. Every node running the same bundle derives the same scope, which makes the signatures portable across a cohort. One consequence: rotating a bundle's author key changes the scope and orphans previously signed objects, so an app anticipating handover records its scope inside its own signed formats. §14 has the trust rationale.

The seam's names are one table, `AUTHORITY_CALLS` (`core/domains.ts`), plus the ungated `crypto/*` primitives and `module/call`, which are not in it. That table is the manifest vocabulary: a `guest.requires` names a subset of its keys and nothing else. A granted authority is granted *by name* — the bridge refuses any `host.call` that is not exactly one of the declared requires — and the gate decides what is an authority by membership in the table (`isGrant`), never by parsing a prefix off the name. Each entry also carries whether it is an ordinary app authority or one of the mount halves below.

| Name | Serves | |
| --- | --- | --- |
| `node/sign`, `node/verify`, `node/identity`, `node/random` | the node key, scoped signing/verification and the entropy source — what the *host* owns | |
| `net/send`, `net/peers` | the structured face: an attributed peer, a protocol id, a correlation | |
| `fs/get`, `fs/put`, `fs/list`, `fs/delete`, `fs/stat`, `fs/size` | raw bytes under an opaque key, scoped to the app (§12.2) | |
| `clock/now` | | |
| `timer/arm`, `timer/clear` | ordinary and small: any guest that needs a deadline | |
| `link/open`, `link/send`, `link/close`, `link/stat` | **mount only** — bytes over an opaque link id | |
| `transport/deliver`, `transport/settle`, `transport/link-auth`, `transport/peer-edge`, `transport/ready`, `transport/link-down` | **mount only** — what the occupant provides back | |
| `crypto/*` | a fixed host-side catalog of pure transforms — **not a grant** | |
| `module/call` | the bundle's own module map — **not a grant** | |

`crypto/*` and `module/call` are exempt from the gate by a rule, not by omission: there is nothing to grant, and a manifest that had to ask before hashing a byte string would be describing an authority that does not exist. The exemption is not a parse of the name — the gate asks whether the name is a key of `AUTHORITY_CALLS` — and a manifest that names one anyway is refused at load rather than accepted as a no-op.

**The last two rows are not app capabilities.** `link` and `transport` are the transport's (§12.5) and enforced at the load seam, not at first use: a manifest naming them is governed by the policy's `transportAuthors` rather than its `authors`, and mounted as the node's transport rather than bound as an app. The argument is the one that keeps the app allowlist from ever granting them: an authority class this large needs a deliberate second decision, never a name an ordinary app can add to its own manifest and have quietly honoured. Adding them to a manifest buys an author nothing — it moves the bundle onto the *stricter* list, which is the only direction the dispatch can be pushed. There is no manifest field to claim it with either — the bundle format carries no role, because the requires already say it. Splitting the two nets is what makes that statable at all: while `net` meant the structured thing, an app declaring it was implicitly handed the transport's output *and* the platform's socket seam under one word. `timer` is deliberately not on that list — the transport happening to want one is not a reason to make it a privilege.

A name the manifest never granted does not resolve — the bridge refuses it, and the shell never wired the backing resource in the first place (an fs-less bundle gets no fs backend at all, not an fs backend behind a check). An unknown name in a manifest throws at load — the vocabulary is closed (`HOST_CALL_NAMES`, `core/domains.ts`), so a typo fails loudly rather than silently granting nothing, or, worse, everything.

**Relation to WASI.** The cap-bridge is deliberately WASI-shaped at the seam: a small syscall table, a zero-authority guest, capability by non-wiring rather than runtime check. The differences justify a bespoke ABI. The names are identity-centric, not POSIX — `net` is addressed by peer pubkey over a channel bound to that key (§12.6), not by socket; `fs` is a flat opaque blob store with no paths; `node/sign`/`node/identity` surface the node's identity, which WASI has no notion of (and every guest signature is domain-scoped). And the grant is *signed content*: the guest's authority is the `guest.requires` field of an author-signed manifest (§12.4) admitted by operator policy (§12.5), where WASI's grants are host-local instantiation choices with no authorship. WASI begins after who authored the code and who may install it are settled; §12.4–§12.5 settle them. What keeps this from drifting into a worse WASI: names stay structureless bytes, anything with structure becomes a no-capability module (§12.1), and the catalog grows by adding names sparingly.

**`fs` is scoped to the app, not the node.** The backend a guest reaches is wrapped per **app key** `"<author hex>:<app>"` (§12.4), so `fs/list` with an empty prefix enumerates that app's keys and no others, and `fs/get`/`fs/delete` cannot name another app's. Keys come back stripped of the scope, so the guest only ever handles the names it chose. Without this, `fs` was the one place the runtime's "ownership is structural" property (§5.1) did not hold: app *keys* carry their author and are unreachable to anyone else by construction, while fs *keys* carried nothing and were reachable to everyone with the domain. The scope prefix is a hash of the app key (`appScopeFor`), not the app key itself: keys double as **filenames** and both backends restrict them to `[A-Za-z0-9._-]`, which `"<author hex>:<app>"` fails on its colons — and an author-chosen `app` cannot be trusted to stay inside any charset anyway. Hashing fixes both at once, and its fixed length means two distinct app keys cannot produce prefixes where one extends the other (plain concatenation would let app `x` key `y:z` collide with app `x:y` key `z`). `fs/stat` is deliberately **not** scoped: `used`/`available` describe the physical backend, and a per-app `available` would be a fiction.

**The two gates are not optional.** A bridge is constructed with an allowed name set and a logical→host module map, and both are *required* arguments. They once meant "unrestricted" when absent, which made full authority the thing a new call site got by forgetting a field — the wrong default in the one place a mistake is a capability escalation, in a runtime whose admission policy is otherwise deny-all. A host-side caller that legitimately needs neither gate — one that already holds every primitive the bridge wraps — names an explicit `UNRESTRICTED_NAMES` sentinel. (Module scoping needs no sentinel of its own: `callModule` is bound to one app's map, so there is no wider namespace an omitted argument could open onto, and `module/call` is a primitive besides.) The check is enforced at *runtime*, not only in the types: the native target evaluates the compiled JS of this file inside QuickJS (§12.9), where a TypeScript signature is not present to enforce anything, and a gate that holds on only one of two targets is not a gate.

### 12.3 Zero-authority JS realms

Logic that is inherently async or awkward as a *synchronous* WASM module runs as confined JS in a QuickJS-compiled-to-WASM realm (`host/safe-js.ts`, `./safe-js`). A fresh realm has only the ECMAScript intrinsics — it cannot even *name* `fs`/`net`/`process`/`fetch` — and reaches out only through the injected `host.call` seam. The seam is narrow-async: a sync name (the primitive catalog, clock, module, the raw-link and transport names) resolves to bytes immediately, and the round-tripping ones — `net/send` and every `fs/*` — return a real Promise the guest `await`s. So the guest is ordinary async/await JS, a fan-out is `Promise.all`, and there is **one** realm — a single non-Asyncify build — serving both roles. A suspended async guest is just heap state, so there is no second engine, no Asyncify and no module-global suspend state.

**And one way in.** `realm.call(entry, bytes)` is the whole seam, for the initiator and the holder alike. A synchronous second seam is not available to be offered: a holder answers from local storage, and storage cannot answer in the same turn on a target whose backend is asynchronous (§12.1). Both roles are therefore ordinary async entrypoints, and there is one shape to reason about rather than two whose difference is a property of what the guest happens to call.

**Invocations are serialized per realm** (`host/realm-queue.ts`): one entrypoint runs to completion before the next begins, so no two guest frames are ever in flight in one realm and neither can observe the other's half-updated state at an `await`. Re-entrancy is what makes that guarantee necessary rather than free — the alternative is two frames resuming into each other at every await point, in an order neither the author nor the host chose, which a guest keeping state across an await has no way to reason about. The cost is head-of-line blocking: an initiator parked on a network round trip delays an inbound request to the same app rather than being answered around. That is the trade, and an app that genuinely wants both at once wants two realms, which the shell can give it, rather than one realm with two frames inside it. The queue is shared TS on both targets, because a guarantee that held on one and not the other would be a guarantee nobody has.

This is the chat shell's sandboxed-iframe confinement (§11) generalised: "run zero-authority guest JS over a cap seam," the sibling of "run a WASM module under caps."

**Bounded, not merely confined.** Zero authority answers "what can this guest reach"; it says nothing about "how much of this node can it consume". Two bounds answer that, and both default to a real number so a shell that configures neither still gets a bounded guest:

- **Heap** — the realm's QuickJS runtime is capped (64 MiB default, `realmMemoryBytes` / `--guest-memory`). A runaway allocation fails inside the realm instead of taking the host's memory.
- **Execution time** — a budget per entrypoint invocation (5s default, `guestDeadlineMs` / `--guest-timeout`, §16.1), enforced by a QuickJS interrupt handler on the browser/Node target and by a wazero deadline on the native one (§14 — QuickJS's own `maxExecutionTime` is inert in the vendored `qjs.wasm`, so a spinning guest there is stopped by terminating the wasm call, which costs the realm). It covers every path guest code runs on — the entrypoint, a continuation resumed after a host bridge settles, and one the event loop pumps directly (a plain `await`), which is the one that would otherwise let a guest buy an unbounded loop for the price of a single `await`. It measures the time the guest is **running**, not wall clock: the budget is suspended whenever the guest is parked awaiting a host bridge and resumed when its continuation runs. That split is what lets one number serve both roles — an initiator legitimately spends seconds parked on a `net/send` without spending any budget, while a holder that loops forever burns it in a single segment. There is no nested-budget case, because serialization leaves exactly one budget window open at a time.

Both cross every seam between the operator and the realm — CLI flag, `boot()`, `createShell`, `RealmFactory` — because a bound the shell accepts but no target can set is a bound nobody has — one the realm factory takes and nothing upstream carries is dead, since the default applies and nothing can change it. `--guest-timeout 0` reads as "no budget", so disabling one is something an operator says rather than something a missing flag does.

Execution time is the operator's number, not the author's — unlike the module memory ceiling (§4.1), which a bundle declares in its signed manifest. How long *this* node is willing to spend on one message is a property of the deployment, not of the code.

The budget matters most on the holder path, because that runs guest code on the node's only thread in response to an inbound frame (§12.10) — and, with invocations serialized, a wedged holder holds its realm's queue as well as the thread. An interrupted guest throws; the transport already answers a throwing guest with an empty body, so a wedged guest costs one empty response rather than the link. Delivery always targets a guest `handle` (§12.10), so an inbound frame enters under this budget and can never reach a module without crossing the guest first; the one segment it does not cover — a wedged module inside a guest's synchronous `module/call` — is reachable only through a guest's choice (§14).

### 12.4 Signed bundles

An app is delivered as a **bundle** (`host/bundle.ts`, `./bundle`) — one blob of signed content, holding:

```
manifest.bundle     the signed manifest envelope (below)
<name>.wasm          each WASM module, named by its manifest `name`
guest.js            the app's zero-authority guest program (§12.3)
```

A bundle is a **value, not a path**: one blob is read from disk, carried in an `OFFER` over a data channel, and stashed in browser storage without a second format or a second load path. The container framing is `"SKB1" │ count u16 │ count× (nameLen u16 │ name │ dataLen u32 │ data)`, all big-endian — pure naming, with no security properties of its own: the manifest envelope inside carries the author's signature and its module hashes protect the bytes, so anyone may repack a bundle without weakening it.

**Nothing in the manifest names a file.** A module lives in `<name>.wasm` and the guest in `guest.js`, by construction. A signed filename would be one more field every target must validate (and, where a target resolves it against a directory, one more chance to escape it); deriving it removes the field and the obligation together.

**What a bundle carries beyond the modules.** The loader binds exactly one kind of thing: WASM modules into the app's module table. A bundle wraps everything else an app is made of:

- **The guest is the app; the modules are its library.** The guest is JS source for a QuickJS realm, not WASM — the loader's path ends in "instantiate WASM, bind," and the guest is what the shell runs. Modules are the pure transforms the guest drives by name; a bundle may declare zero or many of them. Without the manifest the guest would have no signed identity at all.
- **The guest's authority has no other home.** A WASM module is a pure transform with no capabilities of its own (§4.2); the guest, by contrast, *does* reach I/O — through the cap-bridge — yet is not a module and has no table entry of its own, so the manifest's `guest.requires` is its entire capability declaration.
- **Version coherence.** Module binds are per-name and independent; nothing at the bind level says "codec at hash X, reputation at hash Y, and guest at hash Z together constitute app v1.2." The manifest is the author's signed statement of the coherent set — without it a node can hold a mix of individually-valid module versions that were never meant to run together.
- **Operator/author separation.** The shell is one fixed, auditable artifact; the app arrives as content signed by a third-party key the operator's policy admits. Verification is channel-independent: a bundle read from a USB stick verifies exactly like one fetched from a mirror or pushed over a relay.

**One authenticated statement, one authorization.** The bundle is the *only* way code arrives. The signed manifest commits to every module's `genesisHash` (§5.1), and the loader verifies each `.wasm`'s bytes against it, then admits the verified modules under the app key it *derives* from the manifest's signed `(author, app)` pair, each at its declared logical name (§5.1) — a policy decision (§12.5) followed by one all-or-none bind (§3.1). Admission touches no replay state, so an equal-version reload just re-binds cleanly — a reboot re-reading the same bundle installs the same modules again with no collision. A **live update** is not a separate mechanism: it is delivering a bundle whose manifest `version` is higher, which the freshness guard (below) requires; it replaces the same app's module map because the same key derives it, and a bundle from any other key lands under a key of its own.

**Manifest envelope.** Fixed-width per suite, JSON to the end:

```
0x01  [suite: 1][ed_pk: 32][ed_sig: 64][manifest: UTF-8 JSON to end]
0x02  [suite: 1][ed_pk: 32][ml_dsa_pk: 1952][ed_sig: 64][ml_dsa_sig: 3309][manifest: UTF-8 JSON to end]
```

`0x01` is an Ed25519 detached signature over `DOMAIN_manifest ‖ suite ‖ json`, where `DOMAIN_manifest` is `"seedkernel-manifest-sig-v1\0"` (§16.1), prepended before signing but not stored. The disjoint prefix means a manifest signature can never double as a guest `node/sign` or channel-handshake signature over the same bytes (§14). There is deliberately no canonical-JSON step: the envelope carries the exact signed bytes and the verifier parses exactly what it checked, so the bytes *are* the manifest and canonicalisation has nothing to bite on.

`suite` names the signature algorithm — `0x01` is Ed25519, `0x02` the hybrid Ed25519 + ML-DSA-65 suite below (§16.1) — and an unrecognised id is refused with its own error rather than reported as a bad signature, since "this bundle wants a newer host" and "someone tampered with this bundle" are different problems for an operator. Unlike the domain prefix the byte is **stored as well as signed**, and that pairing is the whole design: a verifier must read it *before* verifying, because another suite's key and signature are other widths, so it has to be legible up front — and because the signature it then checks commits to the same byte, an attacker who rewrites it only invalidates the manifest. A signature is therefore bound to the suite it was made under, and algorithm confusion between two suites is unrepresentable rather than merely unlikely (§14.1). This is the same discipline the channel suite byte follows (§12.6), on the axis that migrates independently.

**Suite `0x02`: hybrid Ed25519 + ML-DSA-65.** Both signatures are made over the same preimage — `DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ json` — and **both must verify**. Not either: "either" is exactly as strong as the weaker algorithm. Requiring both means a flaw in the young half fails *closed* (valid bundles rejected, an operator's problem, recoverable) rather than open (forged bundles admitted, which is not), and the bundle stays no weaker than `0x01` against a classical attacker while ML-DSA is new. The cost is envelope size — ~5.3 KB of header against 97 bytes — paid once per install, off the message path entirely (§13), which is why the manifest is the cheapest place in the system to absorb it.

Both public keys are inside both preimages, so the pair cannot be taken apart: an attacker who holds a forgery for one algorithm cannot keep the sound half's key and signature and splice its own key in beside them — the surviving signature no longer verifies over the new key set.

**Where the primitive comes from.** One freestanding wasm module (`browser/mldsa65.wasm`, built from the pinned `pq/mldsa-native` submodule by `scripts/build-mldsa.mjs`), fetched by the browser, read by Node and instantiated under wazero by the Go loader — the same arrangement Ed25519 has through libsodium.wasm, and for the same reason: a bundle one node admits, every node must admit, so the verifier is compiled once and shared rather than reimplemented per target. The module has no imports at all (randomness and the FIPS 204 context are arguments), so there is no per-target host glue that could differ. `bundle.ts` names only the method `ml_dsa65_verify_detached` on the crypto object; a host that supplies none refuses `0x02` rather than falling back.

**The author id under `0x02` is derived, not carried.** It is `genesisHash(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖ ml_dsa_pk)` — 32 bytes, like an Ed25519 key, so `appKeyFor` and every app key (§5.1), every policy entry and every freshness mark are unchanged by the existence of a second key. Two reasons it is the hash and not simply the Ed25519 key:

- **Otherwise hybrid signing buys nothing at the moment it should pay.** An attacker who eventually breaks Ed25519 forges that half and generates a *fresh* ML-DSA key for the other. Both signatures verify; if the id were the Ed25519 key, the id would be unchanged, and the forged bundle would land on the real author's names. Hashing the whole key set makes the identity unreachable without both private keys — which is the property "hybrid" is supposed to name.
- **The id's width is load-bearing far outside the envelope.** A suite that widened it would change name derivation, the policy file format, and the freshness key at once.

The consequence is that an author moving from `0x01` to `0x02` gets a **new identity**: new app keys, a fresh freshness lineage, a new policy entry. That is the honest reading rather than a wart — a hybrid-signed manifest is a *different, stronger* statement about who signed, and treating it as the old identity would be the bug. Operators list both entries during an overlap and drop the `0x01` one when the author has finished migrating (`manifestSuites`, §12.5).

**Manifest fields.**

| Field | Type | Enforced? | Meaning |
| --- | --- | --- | --- |
| `app` | string | **yes** | Names the coherent set. With `author_pk` it forms the **app key** `"<author hex>:<app>"` — this app's identity everywhere in the runtime: the freshness high-water key (see freshness below), the guest's signing namespace (`guestSignScope`, §12.2), the table key every one of its modules is bound under (§5.1), and what a protocol binding points at (§12.10). Non-empty; free to contain `:`, since the fixed-length author prefix keeps the key unambiguous. |
| `version` | integer | **yes** | Monotonic version of the coherent set. A load whose `version` is below the persisted `(author, app)` high-water mark is refused as a downgrade, the mounted transport included (see freshness below). |
| `modules[]` | `{name, hash}` | yes | One entry per WASM module. `name` does two jobs: the module's file in the container (`<name>.wasm`), and the key it binds at inside its app's module map (§5.1) — which is also the logical name the guest passes through `module/call`, so there is no second name to resolve between them. Unique within a manifest and restricted to `[A-Za-z0-9_-]`. `hash` is `genesisHash(wasm)` hex (§5.1) — the definitive declaration of which bytes the author authorized. `verifyBundle` checks every module against this hash, so by the time a module reaches `installBundle` its integrity is already proven. **There is no bind-name field:** a module binds under the app key the loader derives from values the author already signed, at the logical name the author declared, so a manifest holds nothing that could point a module at unexpected bytes. **Freely zero-to-many:** a guest-only app declares none, an app with a codec library declares many — there is no count rule, because the count is whatever the app's logic needs and nothing dispatches by it. There is no `entry` field either: the app's inbound entry is its guest's `handle` entrypoint (§12.2), fixed by the guest ABI, so the format never has to nominate one. A module cannot call another module (§4.2), so anything that composes modules is the guest, by `module/call` (§12.10). **There is no protocol list either:** the manifest declares nothing about which protocols the app could serve — receiving traffic is chosen by the operator at bind time (§12.10), never by a bundle. |
| `guest` | `{hash, abi, requires, config?}` | **yes** | **Required** — the zero-authority guest program and **everything about it**. Every app is a guest; a manifest without one is refused at load. The format states "this bundle holds no authority" as an **empty `requires` list** — a shape, rather than a rule prose has to state and every target has to honour. |
| `guest.hash` | string | yes | `genesisHash(utf8(source))` hex of `guest.js`. |
| `guest.abi` | integer | **yes** | Which host seam this guest was written against (`GUEST_ABI_VERSION`, §12.2). A guest declaring an ABI this host does not implement is refused by name — a legibility failure, like an unsupported signature suite, not an authenticity verdict. Required rather than defaulted: the default would have to be the oldest ABI, which is exactly the population a bump exists to catch, and a guest author who never considered the seam version is indistinguishable from one who meant the old one. The number tracks changes to the seam's *shape* — the naming scheme of `host.call`'s first argument, a name moving across the sync/async line, a payload framing change, the entrypoint protocol — not the appending of new names, which a guest that never calls them cannot notice. It is the version of every name it contains: within an ABI a name's meaning is fixed. Its reason for existing is that the failure it guards is silent: a guest calling `host.call("fs/get", k)` without `await` gets a Promise where bytes were expected and reads `undefined` — a wrong answer, not an error, and one no care at the call site turns into a loud one. A declared seam version makes it a refused load. |
| `guest.requires` | string[] | **yes** | **Exactly the authorities this guest holds** (`AUTHORITY_CALLS`, §12.2): `node/sign`, `fs/get`, `net/send`, `timer/arm`, … The bridge grants exactly these, name by name — a declared `node` grants nothing on its own, and an undeclared `node/identity` is refused even under a declared `node/sign` — and the shell wires only the backends they reach. **Grants only**, so the list is the bundle's whole reach and reads as short as that reach really is: the ungated names a guest also calls (`crypto/*`, `module/call`) are not declarable, because neither can be absent from a host and a requirement on what cannot fail states nothing (§12.1); `abi` covers what the guest needs of them. The list is closed — a name this host does not grant is a refused manifest, including a pure name asked for as if it were a grant — and may be empty: zero authority is a real posture, and the chat demo's guest declares none at all, reaching nothing but its own module map. `link/*` and `transport/*` are refused on the app path — they are reserved for the explicit transport mount (§12.2). |
| `guest.config` | map (string → string \| number) | no | App-structural constants injected into the guest as `const APP = {…}`. Opaque to the runtime. Facts the runtime already derives do **not** belong here — the runtime's own facts reach the guest through the seam (`node/identity`, the slot scope `node/sign`/`node/verify` apply), never as restated config (see below). |

**Why `requires` and `config` live inside `guest`.** Both are the guest's alone: `requires` is the guest's entire authority (§12.2) and `config` only ever becomes its injected `APP`. WASM modules carry no authority and read no config, so the two fields have no meaning at the top level — nesting groups the app's authority with the app's program, and "no authority ⇒ empty `requires`" is the schema's shape rather than a rule prose has to state and every target has to honour.

**Load algorithm** (`loadBundle`). The shell is host code, so failures here **throw to the operator** — §3's "an unbound name resolves to an empty response" is about resolving a name, not about loading a local file.

The load is three halves: `verifyBundle` (authenticity + integrity), `admit` (governance — §12.5), and `installBundle` (freshness + bind). A single predicate answers the single question: "may this verified bundle land on this host?"

*verify* — pure, nothing lands:

1. Unpack the blob, read `manifest.bundle`, and verify the envelope signature. Invalid ⇒ reject.
2. Read each module's `<name>.wasm` and `guest.js`. A missing file ⇒ reject.

*admit* — governance, the one predicate:

3. Call the admission predicate with the `VerifiedBundle`. Return `true` to admit, `false` or throw to reject. The predicate IS the policy (§12.5) — a file-backed author allowlist, an interactive consent dialog, or "the bundle my operator handed me" are three constructors of it. Deny-all stays the default: the absent predicate admits nothing.

*install* — mechanics, then effect:

4. **Revocation, then freshness.** Refuse outright if `author_pk` is in the host's written-off author set (§12.5) — the shell has already checked this before step 3, so reaching it here means a caller drove the loader directly — a stolen key satisfies the version check trivially, so this must be asked first or it is never asked. Otherwise read the persisted high-water mark for `(author_pk, app)` (absent ⇒ −∞) and refuse if `version < high_water` — a downgrade, nothing lands. The mounted transport is read by the same key as any other bundle. Otherwise the mark advances at the *end* of a fully successful load (see freshness below). Equal versions reload (an ordinary reboot); the mark is monotonic and never rewound, so once version N loads, nothing older ever loads again on this node.
5. Integrity-check **everything** before binding anything: each module against its `hash`, and the guest against `guest.hash` (§5.1). A mismatch anywhere ⇒ reject with nothing bound, so a bad file can never leave a partial bundle on the host.
6. **Install** atomically: for each module, first read its declared memory limits off the bytes and refuse anything unbounded or above `MAX_MODULE_MEMORY_BYTES` (§4.1, §16) — before instantiation, which is what would allocate it — then instantiate (pure, no table effect — compile, validate §4 exports, confirm each IS a module). If any module fails to instantiate the accumulated refs are discarded and the whole load throws — nothing lands. Only when all instantiate successfully are they assigned, in one step, as the module map of `"<author hex>:<app>"` (§5.1).
7. Only now may the guest run (§12.8): a realm (§12.3) over a cap-bridge restricted to `guest.requires`, loaded with `op preamble ‖ const APP = merge(guest.config, operator config) ‖ guest source`.

**Splitting verify from install is what makes consent possible.** An interactive shell must show a bundle's author and metadata and wait for the user *before* anything binds — the browser shell's `OFFER` flow (§11) is exactly that. With a single `admit` predicate between `verifyBundle` and `installBundle`, the shell calls `verifyBundle`, stops, and the predicate asks the user before `installBundle` ever sees the bundle. That is one predicate, one answer.

**Nothing the runtime derives is injected; it is reached through the seam.** The shell injects exactly one preamble next to `APP`: the guest program itself. Every runtime fact an app might want is served by a host call — its identity by `node/identity`, its signing namespace by `node/sign` and `node/verify`, which apply the slot-derived scope for it. An author who baked the scope into `config` would be restating a load-time fact at build time, and a copy that silently disagrees fails as signatures that verify nowhere with nothing naming the cause — the same one-file rule the `DOMAIN_*` family follows (§16.1). There is also nowhere safe to put it: `APP` is operator-mergeable, so a hand-written prefix there would be operator-writable — able to re-scope the app's own signatures at boot. Signing and verification happen under the runtime's own derivation, which no config can touch.

**Module scoping is structural, so there is no map — and no grant.** A guest calls its own modules by the logical name from its manifest through `module/call` (`"codec"`, `"reputation"`), and that is the key they are bound under inside its app's module map — the app key is fixed when the shell builds the bridge and is never something the guest supplies. So a guest reaches exactly the modules it declared and has no way to name another app's; like the `crypto/` catalog, that is a primitive, ungated because it is the bundle's own code (§12.1). The bridge therefore carries no name map and no opt-out sentinel: with one app's map behind the seam there is no wider namespace an omitted argument could open onto.

**Admission is a step inside the loader, not a separate component.** Binding a module *is* the loader's job, and it is the whole job: the loader keeps no side table. It hands the host every verified module in one `bindAll` (§3.1) — the manifest's `modules[].hash` is the definitive declaration of which bytes the author authorized, and `verifyBundle` already proved the bytes match. There is no per-module callback: trusting an author means trusting everything they sign. Nor is there a per-module *outcome* to reconcile, because the bind is all-or-none: a bundle is admitted as a unit, so it lands as one.

**The policy needs no state because the name already carries it.** An admission decision would once have had to ask "who owns this name?", which meant a register mapping names to owners and a rule for updating it. With the author derived into the name (§5.1) that question has no content: a name is reachable only to the key that derives it, so the only bundle that can ever re-bind a name is one signed by the author whose name it is. The policy is a pure function of the bundle in front of it, the module table is the only install state on the host, and neither can drift from the other.

**One authentication, one authorization.** The manifest signature authenticates and integrity-checks the *set* (verifyBundle); the content-hash check binds each module's bytes to the manifest's commitment; the admission predicate (§12.5) authorizes the *bundle* — one predicate, one answer, between verify and install. Every module the manifest declares is authorized by construction — the author signed its hash, and the hash matched the bytes. The manifest is the single authenticated statement, the predicate the single authorization decision.

**Operator config wins.** The shell merges the operator's `--app-config` *over* the manifest's `config` before injection. The split is intentional: author-signed `config` carries content-structural constants (a storage app's k/m/blockSize), the operator's carries per-node policy (a quota). The merge is opaque — the shell never inspects a key — so the operator can even override a structural constant. That fits the trust model (the operator's host *is* the TCB, §14), but bundle authors should not assume their `config` reaches the guest unmodified.

**Bundle freshness.** `version` is an enforced monotonic integer, not a label: step 4 refuses any bundle whose `version` is below the persisted `(author, app)` high-water mark, so an older signed bundle — a stale relay copy, or a confused provisioning step handing over yesterday's build — is rejected as a downgrade. The whole bundle loads wholesale every boot, and neither guest nor modules carries a per-item version, so `version` is the single downgrade guard for the set. The mark is host-local persisted state; a deliberate rollback is an out-of-band operator action (the operator is the TCB, §14). The store file is `{ "marks": { "<author hex>:<app>": version }, "revoked": [ "<author hex>" ] }`; a file written before revocation existed held the bare marks map and is **refused with a migration message** rather than read leniently, since parsing it as "no marks" would drop every downgrade guard on the first boot after an upgrade and say nothing. Any other key is ignored, which is the lenient case precisely because dropping one discards no guard that was ever earned.

**The mounted transport is keyed no differently.** Versions are an author's own lineage, so the bundle standing as the node's transport carries the same `(author, app)` mark as any other and there is no second floor keyed to the mount. One would cost what it bought: every author of a transport would share a single version line with no owner, and replacing A's v5 with B's transport would require B to number above a sequence B does not control. What it would buy is a refusal in one case — a policy trusting authors A and B for the transport mount, where A's v5 has landed and B's stale v1 is offered — and that case needs someone other than the operator choosing which signed bundle arrives. Nothing does: a bundle reaches the shell embedded in the host artifact or from a file the operator names, never off the wire (§12.4). The answer to two trusted authors is therefore to trust **one author for the mount at a time** (§12.5), which is the right posture for an authority grant regardless. What `version` cannot express is that the signing key changed hands — see revocation (§12.5) and §14.

### 12.5 The admission policy

Admission (§12.4) asks exactly one question — *may this author's signed bundle land here?* — and one policy answers it, once per admission point. The form is a predicate `admit(v: VerifiedBundle) → bool | Promise<bool>`, called between `verifyBundle` and `installBundle`; a policy file resolves to one per point (`{ apps, transport }`, below). Three constructors cover three deployment postures, and each builds a predicate for either point:

- **authorAllowlist(authors)** — a closed set of hex author ids parsed from `--policy <allowed-keys.json>`. Trusting an author means trusting every module and guest their manifest declares — the manifest's `modules[].hash` commits to exactly which bytes are authorized, and `verifyBundle` already proved the bytes match.
- An **interactive consent dialog** — the browser shell's posture: `verifyBundle` reveals the author and manifest to the user, and the predicate returns `true` only once the user says yes.
- **admitAll** — "the bundle my operator handed me IS the trust decision." A StorageNode loads exactly the one bundle it was configured with; the choice of bundle already settled admission.

All three are the SAME type — one seam, not three mechanisms layered on top of each other. A fourth constructor, **manifestSuiteAllowlist(suites)**, is an axis rather than a posture — *which signature suites* (§12.4) an operator accepts — and composes with any of the three through `allOf`.

**The transport is a second admission CLASS, not a fifth posture.** Admitting an ordinary app risks that app; admitting a transport risks the channel, which sees all plaintext and holds the session keys. Those are different decisions, and `transportAuthors` is where the second one is made — which is what stops "I trust this author's chat app" from silently becoming "I trust this author to be my transport". It is the same bar §12.10 draws for binding an *observing* guest: a capability grant held apart from "which chat app do I want".

**Which class a bundle answers to is read off `guest.requires`, and nothing else.** There is no `role` field — a transport is exactly the bundle naming the mount-only names (§12.2), which the manifest signature already covers and the verifier has already checked, so restating it as a self-description would only be a second place for the same fact to live. It stays one install path (`loadBundleBlob`, §12.4) because the dispatch is safe in the only direction it can be pushed: adding `link/open` to a manifest moves that bundle onto `transportAuthors`, never onto `authors`. An author already trusted for apps therefore gains nothing by asking for sockets — they move themselves to the list they are not on. Naming one mount half and not the other — sockets with nowhere to report, or the reverse — is refused as malformed before either predicate runs, so a partial claim cannot fall back to the app class. `admitAll` is the exception and stays permissive at both: it is one blob an operator named, and naming a blob is a decision about that blob whatever it declares.

The policy file (when present) is `--policy <allowed-keys.json>` (`host/policy.ts`), parsed strictly — a malformed file fails the boot loudly rather than silently widening trust:

```json
{
  "authors": ["<author id, hex>", "…"],
  "transportAuthors": ["<author id, hex>"],
  "manifestSuites": [1, 2]
}
```

| Field | Required | Semantics |
| --- | --- | --- |
| `authors` | at least one of `authors` / `transportAuthors` | The closed set of author ids that may sign an ordinary app's bundle manifest (§12.4 step 2) — an Ed25519 pubkey under suite `0x01`, the derived key-set id under `0x02`, 32 bytes either way, so an operator pins an identity without naming a suite. Trusting an author means trusting every module and guest their manifest declares — the manifest's `modules[].hash` commits to exactly which bytes are authorized, and `verifyBundle` already proved the bytes match before the predicate runs. |
| `transportAuthors` | at least one of `authors` / `transportAuthors` | The closed set of author ids trusted to fill the **transport mount** — the bundle that carries the node's whole network and signs the channel AUTH (§12.2). An entry here is a separate, deliberate decision from `authors`: it grants raw links and channel identity signing, never app code. A policy may name one side without the other; a policy naming neither is refused at the boot. The old `roles` key is gone with the manifest `role` field — a policy file still carrying it fails the boot loudly rather than parsing into an app-only policy that silently leaves the node without a network. |
| `manifestSuites` | no | The signature suites (§12.4) this deployment will accept. Absent ⇒ any suite the host can verify. This is deliberately *policy* and not verifier logic: "can this host check suite N" and "will this deployment trust suite N" are different questions, and a node finishing a post-quantum migration answers yes to the first for `0x01` and no to the second. Without the field there would be no way to ever finish a migration — the classical suite would stay acceptable forever on every host still able to verify it. |

There is no per-module allowlist: the manifest IS the definitive list of authorized modules. An author who signs a manifest with five modules is authorizing all five. If an operator wants only some of an author's modules, the author publishes a separate bundle.

**Omitting `--policy` is deny-all, not "no policy".** A node with no configured predicate runs `denyAll`: it boots, serves, and refuses every manifest. Trust is something an operator adds deliberately; the absence of a decision is never permission. One shared constant (`denyAll`) resolves this, so every target — the Node shell and the native loader (§12.9) — boots the same posture, with no permissive default of its own.

**Revocation is host-side, and it is one action.** A module is a pure transform with no imports (§4.2), so nothing in the sandbox can reach the loader — there is no revoke-message, and revocation is not something a bundle can carry.

What it answers is the case freshness cannot. `version` orders an author's own releases; it says nothing about whether the key is still theirs. A **stolen author key** clears the freshness guard trivially — the thief signs `version + 1` — and lands on the same names, because the same key derives them (§5.1). Every release after the theft is, to the loader, an ordinary upgrade.

So the store that holds the freshness marks also holds a set of **written-off author keys**, and `installBundle` checks it before the version: a revoked key's bundles are refused whatever they contain and whatever version they claim. `shell.revoke(authorHex)` does both halves in one call — record the key, then uninstall every app it already landed, found by the author half of the app key (§5.1). Both the Node shell and the native loader (§12.9) expose it as `--revoke <hex,…>`, alongside `--uninstall <appKey,…>` for the narrower case; a shell embedding the core calls the method.

The refusal is also checked once more, earlier, in `loadBundleBlob` — before the admission predicate rather than only inside `installBundle`. The predicate is where an interactive shell puts its consent dialog (§12.4), and showing a user the author and metadata of a bundle this host has already decided to refuse, taking their approval, and only then failing is the wrong order to ask in. A written-off key never reaches the prompt.

**Both halves, or neither.** Uninstalling alone leaves nothing to stop the thief's next bundle re-landing on the same names; recording alone leaves the compromised code running. Neither implies the other, and an operator performing them by hand — edit `allowed-keys.json`, call uninstall — can do one and not the other, or do them in the order that leaves a window. That, rather than the absence of a certificate format, was the gap.

**It is deliberately not a protocol.** No signed certificate, no wire format, nothing to distribute — a revocation is a local decision by the operator, who is the TCB (§14), recorded in local state. A fleet applies it the way it applies any other operator decision: by whatever configuration path already reaches those nodes. Building a signed, relayable revocation object would mean deciding who may sign one, which is a second trust set and a second key-management problem to solve the first — worth it for a public deployment admitting third-party authors, and out of scope here.

**The check sits in the loader, not the policy.** An admission predicate (above) is a pure function of the bundle in front of it and every target supplies its own, so a revocation enforced there would be absent from `admitAll` — the "the bundle my operator handed me" posture — and reimplemented in the other three. In the loader it holds for every target and every delivery path, including a bundle arriving in an `OFFER` (§11), which is the path that most needs it.

**Recovery is a new key, not an un-revoke.** The runtime never removes a key from the set: it survives a later edit that puts the key back in `authors`, so re-admitting a compromised author takes more than forgetting why it was removed. It survives reboots wherever the store does — the Node shell and the native loader persist it through the same atomic write as the freshness marks; the browser chat-shell holds both in memory, so there, as with freshness, a revocation lasts only as long as the page. An author who lost a key republishes under a new one, which derives its own names and its own freshness mark and is unaffected by the dead key's state. Genuinely undoing a revocation means editing the store file out of band — the same escape hatch as rolling a freshness mark back, and the same reason it exists.

**Scope.** The set is keyed by author, not by `(author, app)` or by version range. A key is compromised or it is not; "this key was good through v6" would invite rolling back to v6 under a key the operator has just decided to stop trusting. The remedy for a merely *bad release* is the ordinary path below — a higher `version` from the same author.

**The emergency path is the ordinary path.** There is no "replace this module directly" seam, and its absence is deliberate. If a bug is found in a module, the fix is a signed bundle at a higher `version` from the same author, admitted under the policy above — the same act on a running node as on a booting one, exercised on every release rather than held in reserve for the day it is needed. A dedicated emergency seam would be a second way to occupy a slot, reachable only in a crisis and therefore least tested exactly when it matters most; and it would be the one entry in the table with no signature behind it, sitting at a name it could not have derived, so nothing could afterward say who authored what runs there. An operator's emergency powers are the powers they use daily: sign a bundle, load it. The narrow case this forecloses — a module so broken the node cannot reach the point of loading a bundle — is a boot-path failure, answered by the operator's control of what the node boots with (a different bundle on disk, a rollback), not by an in-process seam whose own code path would have to survive whatever broke the first.

The *guest's* §12.2 requires are **not** gated by this file — they come from the signed manifest, bounded by which bundle the operator chose to run (`--bundle`). No per-author gate is needed because the one dangerous power — raw node-identity signing — isn't grantable at all: a guest's `node/sign` is confined to its app scope (§12.2, §14), and the rest (`fs`, `net`, hashing, …) are ordinary app powers.

### 12.6 Node↔node transport: channel identity binding

**Everything in this section is the transport bundle's guest program** (`transport/guest.js`, §1) — the handshake, the record layer, the link router and the request/response frame codec — not host code. It reaches sockets through the `link/*` names and is driven through named entrypoints (§12.2), and the host side of that is one driver, `host/transport-host.ts`, which owns the channels by the link id it mints, the timers, the outbound promises, the address book and the whitelist gate, and knows no protocol. What follows is therefore *content*: replaceable by a second signed bundle loaded the ordinary way (§12.4, §12.5), which is the property the rest of §12.6 exists to make safe.

A real socket carries no trustworthy "from" field, so before a connection delivers frames the bundle runs a mutual challenge/response proving each end holds the private key for the pubkey it claims — the same binding applied to each WebRTC data channel (§11, §12.7). The channel is transport-agnostic over anything that delivers whole messages, and where the platform delivers none the bundle imposes them itself (§12.1): a length prefix over raw TCP node↔node, RFC 6455 over the same socket browser↔node, or a WebRTC `RTCDataChannel` peer↔peer as it comes (`host/net-rtc.ts`, §12.7) — same handshake, same frame plane, only the bottom byte-pipe swaps. Each framer checks its cap against the declared length **before** the body is buffered, so a peer cannot make a node allocate more than one frame. That cap is `MAX_HANDSHAKE_FRAME_BYTES` until the link authenticates and `MAX_FRAME_BYTES` after (§12.6.2). Every codec caps identically.

Four handshake messages, then records. **A message is a bare body — there is no type
byte.**

```
msg1  i→r   [suite: 1][eph_i: 32][seal(k1; nonce_i): 48]      81 B  contact proof, no identity
msg2  r→i   [eph_r: 32][seal(k2; nonce_r): 48]                80 B  contact proof, no identity
msg3  i→r   [seal(k3; id_i: 32 ‖ sig_i: 64): 112]            112 B  the caller names itself
msg4  r→i   [seal(k4; id_r: 32 ‖ sig_r: 64): 112]            112 B  the receiver answers, or not
FRAME       [AEAD record ..]                                        only after authentication

Which message a body is follows from the reader's role and how far the exchange has got:
the initiator reads msg2 then msg4, the responder msg1 then msg3, and every message after
authentication is a record. That state is the reader's own — it must hold it to answer at
all — so the sender has no say in which path a message takes, and each handshake message
is accepted only at its exact width. A post-authentication message has exactly one
destination, the AEAD open, which fails closed and tears the link down. The `suite` field
of msg1 is the one self-describing byte on the wire, and it is a body field, covered by
both signatures.
```

`eph` is a fresh **ephemeral X25519 public key**, generated per connection. `seal` is
ChaCha20-Poly1305-IETF at nonce zero under the named key; each key encrypts exactly one
message, so the nonce need never vary.

**Neither identity appears in cleartext, and only a dialer speaks unprompted.** An
accepting node stays silent until a msg1 opens under its **contact secret** (§12.6.3), so a
stranger who opens a socket sees what it would see from a port that is not listening. The
caller then names itself at msg3, *before* the receiver has said anything about itself, so a
caller the receiver declines learns nothing — not even whether the identity it dialed is
there. Both identities travel under keys derived from `ee`, which dies with the connection.
See [CHANNEL](CHANNEL.md) §3–§4 for why the identities are deferred and why the ordering is
worth a second round trip.

The transcript root is `H(DOMAIN_channel ‖ network_key)`, so two networks derive disjoint
keys and signatures (§12.6.3).

```
root = H(DOMAIN_channel ‖ network_key)
k1   = KDF(contact,      H(root ‖ suite ‖ eph_i))
h1   = H(root ‖ msg1)
ee   = X25519(eph_i_sk, eph_r) = X25519(eph_r_sk, eph_i)
k2   = KDF(ee ‖ contact, h1)
h2   = H(h1 ‖ msg2)     k3 = KDF(ee ‖ contact, h2)   sig_i = Ed25519(root ‖ h2 ‖ id_i)
h3   = H(h2 ‖ msg3)     k4 = KDF(ee ‖ contact, h3)   sig_r = Ed25519(root ‖ h3 ‖ id_r)
h4   = H(h3 ‖ msg4)     k_i2r, k_r2i = KDF(ee ‖ contact, h4, "…i->r-v1\0" / "…r->i-v1\0")
```

Both early messages carry a seal keyed by the contact secret, so neither side reveals an
identity to a party without it.

**`suite` names the handshake, and is not negotiated.** `0x02` is the concealed suite
(§16.1): Ed25519 identity, ephemeral X25519, contact secret, ChaCha20-Poly1305 records. A
link speaks exactly one suite — an unrecognised id draws silence, and every message is a
fixed width per suite, so trailing bytes are malformed rather than forward-compatible.
There is no list, no fallback, and no "highest common" rule. Suite `0x01`, which carried
both identities in cleartext, is removed rather than disabled. Because the byte is folded
into the transcript root at `h1`, both signatures cover it: an in-path attacker who flips
it only makes the two ends sign different bytes. A suite is *chosen* by the endpoints,
never *forced* by the network (§14.1). The bytes a node sends and the bytes it folds into
the transcript are one construction in the transport bundle.

**Each signature commits to its own identity and the whole transcript.** `sig_i` covers
`DOMAIN_channel ‖ h2 ‖ id_i`, and `h2` chains `DOMAIN_channel`, msg1 and msg2 — hence the
suite, both ephemeral keys and both nonces. So a signature collected on one connection,
even from a node used as a signing oracle, names the wrong exchange elsewhere and fails to
verify; see §14. The identity is committed explicitly because it travels *inside* a
ciphertext rather than in the hashed wire bytes. `DOMAIN_channel` is
`"seedkernel-channel-id-v1\0"` — domain separation so a handshake signature cannot double
as another protocol's over the same bytes. An outbound dial pins `expectPeerId`: if msg4
presents a different key, the link closes, and it closes *before* the dial is treated as
live. Frames sent before authentication are queued, bounded by `MAX_QUEUE_BYTES` (1 MiB)
with oldest-dropped — a byte bound, not a frame count — so a peer that never authenticates
cannot make a node hoard memory.

**This is an AKE.** The identity signatures cover the transcript that carries both
ephemeral keys, so they authenticate the key exchange (SIGMA-style; since each signature
already covers its own identity there is no separate identity-MAC seam). The responder
authenticates at msg3 and may carry application data alongside msg4 (1.5 RTT); the
initiator authenticates at msg4 (2 RTT). Session keys derive from `ee` and the contact
secret over the full transcript hash, with roles assigning the directions — the initiator
encrypts with `k_i2r` and decrypts with `k_r2i`, the responder mirrors. Every
post-handshake FRAME is a **ChaCha20-Poly1305-IETF record** under the sending key, with an
implicit monotonic per-direction `(epoch, counter)` nonce and strict enforcement on
receive. There is exactly one post-handshake frame type — the AEAD record — so no plane
split and no downgrade seam. That nonce and the dispatch above both rest on the pipe
delivering whole messages in order, which every socket seam beneath supplies.

**The handshake uses no long-term Diffie–Hellman key at all**: `ee` is ephemeral on both
sides, and the contact secret and network key are KDF inputs. So the channel Ed25519 key
stays signing-only and never takes a DH role (§14), and a node address needs no DH key —
which is also why the post-quantum suite will not change the address format
([CHANNEL](CHANNEL.md) §11).

**Refusals are silent, and that is load-bearing.** Every way a handshake can fail before
authentication — wrong contact secret, wrong network, malformed message, bad signature, an
identity `admitPeer` declines — does nothing at all and lets the deadline expire. Closing
on any of them would answer a question, which is the enumeration this suite exists to
close. The one exception is an `expectPeerId` mismatch at msg4, which aborts: we named
ourselves at msg3, so there is nothing left to hide. See §12.6.2 for what the silence costs
and [CHANNEL](CHANNEL.md) §5 for why it is worth paying.

#### 12.6.2 Half-open budgets

A refused connection stays open until its deadline rather than being dropped, so the
budgets are what stands between a stranger and the node. The half-open limiter lives in the
transport bundle and is shared by every socket seam a host stands up; the two frame caps it
works against are the *host's* (`core/net-limits.ts`), because a limit protecting a resource
must be declared by whoever owns the resource — a host importing its own flood bound from
the module it is bounding would be taking the bounded party's word for the bound. Measured
behaviour lives in
`tests/transport-load.test.mjs`; the reasoning is in [CHANNEL](CHANNEL.md) §5.

- **No cryptography before proof.** An accepting link generates its ephemeral keypair only
  once a msg1 opens; verifying msg1 is a hash and a Poly1305 check. A stranger costs a
  socket, a timer and no asymmetric operations.
- **Two budgets.** `MAX_HALF_OPEN_UNVERIFIED` (1024) for callers that have not yet produced
  the contact secret, `MAX_HALF_OPEN_VERIFIED` (256) for those that have. A link is promoted
  between them the moment its msg1 opens.
- **Both budgets evict the oldest; neither refuses the newest.** Refusing lets a saturating
  flood turn arriving peers away *at the door*, before they can prove anything — promotion
  cannot rescue a connection that was never accepted. This applies to the verified tier
  too: otherwise anyone holding the contact secret could saturate it and lock members out.
- **`MAX_HALF_OPEN_PER_SOURCE` (8) is not evictable.** One address at its own limit is
  refused outright, never allowed to push a different address out, so saturating the
  unverified budget needs 128 distinct sources.
- **Two deadlines.** `UNVERIFIED_TIMEOUT_MS` (2 s) until msg1 opens, `HANDSHAKE_TIMEOUT_MS`
  (10 s) for the rest. Observing the longer one requires the contact secret, so the split
  leaks nothing.
- **`MAX_HANDSHAKE_FRAME_BYTES` (8 KiB) caps inbound reassembly pre-auth**, raised to
  `MAX_FRAME_BYTES` by the bundle's own framer on authentication — both numbers stay the
  host's (`core/net-limits.ts`), learned at init, and what the occupant chooses is only
  when the transition happens. Applying the full application cap to an unauthenticated peer let a
  stranger reserve megabytes per connection. No handshake message today exceeds 113 bytes,
  but the cap is 8 KiB because an ML-KEM-768 encapsulation key is 1,184 bytes: with
  `ml-kem-768` in the primitive catalog (§12.1), a cap tight enough to refuse one would be
  the one remaining reason a post-quantum handshake needed a core rev — the socket seam
  refusing the message the catalog had already made expressible (§14.1). At 8 KiB against
  the 1,024 unverified budget the bound is 8 MiB, still small, and it decides nothing about
  which suites are expressible.

#### 12.6.2b One master seed, purpose-bound keys

A node stores **one** secret: a 32-byte master seed. Every signing keypair is derived from
it under a distinct, versioned label (`core/subkeys.ts`), so no key signs for two purposes.
Two exist today: `channel`, whose public half **is** the peer id and which signs the
handshake; and `guest`, which backs every ordinary app's scoped signature. Both are reached
through the one cap-bridge `node/sign` name (§12.2), and *which* of them a call reaches is the
host's decision from the asking bundle's slot — the transport occupant gets the channel key
under `DOMAIN_channel ‖ network_key`, an app gets the guest key under `DOMAIN_guest ‖ scope`
— never the guest's, and neither key enters a realm. The master signs
nothing itself, and derivation is deterministic, so a node rebuilds every subkey at boot
with nothing extra to persist. Labels are closed and literal, never built from runtime
data. Why this is worth having on top of domain separation: [CHANNEL](CHANNEL.md) §7.

#### 12.6.3 The contact secret, the network key, and `admitPeer`

Three values gate a link, answering different questions. Rationale for the scope of each —
and why the contact secret is per node rather than per deployment or per pair — is in
[CHANNEL](CHANNEL.md) §6.

| | Scope | Secret? | Effect |
| --- | --- | --- | --- |
| **Contact secret** | per node | yes | A caller that cannot produce the *receiver's* secret draws no response. Distributed with the node's address, which makes an address a credential. Absent, the node is open and answers anyone — a DoS and caller-privacy posture, not an identity leak. |
| **Network key** | per deployment | **no, public by design** | Which network this node belongs to. Nodes on different network keys cannot link under any circumstances. An isolation boundary — staging cannot reach production — not access control. |
| **`admitPeer`** | per node | n/a | Optional whitelist, empty by default. Consulted only on an identity whose signature has verified. |

The contact secret is mixed at msg1 together with the initiator's ephemeral, and into every
later key. The network key is applied as a prologue: it seeds the transcript root, so every
derived key *and* every signature preimage differs between networks and a cross-network
handshake fails at the first message. `admitPeer` runs at both gates — inside the handshake at
msg3, before msg4 is built, refusing by silence; and again as the host's **whitelist gate**,
which the bundle asks through `transport/link-auth` (§12.2) before the link is installed or
delivers a frame. The second is applied by the host to the attribution the occupant
*reports*, rather than handed to the occupant to apply to itself.

Revocation is key rotation in each case: a node dropping a peer rotates its contact secret,
a network splitting rotates its network key. There is no separate mechanism, and the
whitelist is not one.

### 12.7 Browser↔console WebRTC

§12.6's channel rides any whole-message pipe, and a WebRTC `RTCDataChannel` is one — which turns WebRTC into a first-class `Network` exposing the same `send` / `peers` surface as the TCP and WebSocket transports.

**`RtcNetwork` (`host/net-rtc.ts`) — relay-signaled mesh.** Peers reach each other directly over `RTCDataChannel`s; the relay (seedchat's `scripts/relay.mjs`) is only the *signaling* rendezvous for SDP/ICE and can be killed once channels are open — no server in the data path. One ordered binary channel per peer carries everything, and the transport bundle's channel stack (§12.6) rides on top — a data channel is handed to the driver through `TransportHost.openLink()`, and the AKE/record/routing state machine runs in the signed bundle's guest exactly as over TCP — so a storage cohort gets P2P for free while a fire-and-forget app (chat) consumes `send` directly. The `Signaling` seam is pluggable — relay, DHT, gossip, or even an existing authenticated link between two connected peers — and carries *no* SDP-fingerprint signature, because identity is proven in-channel: the transport bundle's handshake runs *inside* the data channel (§12.6), stronger than a one-shot SDP-fingerprint assertion at the signaling layer (§11). A MITM relay can splice SDP and bring DTLS up to itself but can never produce the transcript signature without the peer's private key, so the link never authenticates and never delivers a byte. Signaling must also supply the deployment's contact secret, without which a peer draws no response at all. The module is browser-native (it uses the platform `RTCPeerConnection`); a Node/Bun *console* node joins by passing a `peerConnectionFactory` (`weriftPeerConnectionFactory`, `host/net-rtc-node.ts`) — "swap the connection, keep the stack," the §12.6 move applied to WebRTC. werift (pure-TS) is used over native `node-datachannel`, which segfaults under Bun.

**Confidentiality.** Like every transport, the WebRTC fabric's frames are confidential and integrity-protected by the §12.6 AKE record layer. A data channel is also DTLS-encrypted, a redundant-but-harmless second layer underneath. As on the raw transports, the in-channel AUTH supplies the identity binding DTLS alone does not (§11).

### 12.8 The shell

`boot(opts)` (`host/main.ts`, `./shell`) assembles all of the above — the module table, the bundle loader under its admission policy, the fs/net capability backends, the node identity — and returns a `Shell` (`loadBundle`, `runGuest`, `serve`); a CLI wraps it:

```sh
node build/host/main-node.js --policy ./allowed-keys.json --dir ./data --key ./node.key \
     --listen 0.0.0.0:7000 [--ws-listen 0.0.0.0:7001] \
     --bundle ./app-bundle [--transport ./transport.skb] [--peers <pk>@host:port,…] \
     [--put file] [--get hex[:hex…] --out file] \
     [--guest-timeout <ms>] [--guest-memory <MiB>]
```

`--transport` supplies a signed transport bundle from disk instead of the artifact the build embeds (`TRANSPORT_BUNDLE_B64`) — a node with its own pinned transport author, or a newer protocol than the binary ships (§12.6).

A serving node that has loaded a bundle runs the app's *initiator* side on demand (`runGuest` → `realm.call`) **and** serves its *request* side from the **same** confined realm (`serve` routes the transport's inbound requests to the guest's `handle` entrypoint through the same `realm.call`). Both may `await`; the realm serializes them (§12.3), and the driver answers an inbound request through the `respond` entrypoint on a later turn, never inline — which is what lets an app's inbound handling be asynchronous at all. The shell is application-neutral — it can host any signed app — and for a self-contained non-browser deployment the Go/native target ships it as a single binary (§12.9). seed store's WASM README has a complete storage walkthrough.

### 12.9 The Go/native shell — the primary non-browser deployment

The §12.8 shell runs as JS on Node or Bun, but the **recommended** way to run a node outside the browser is the **Go/native target** (`native/`, a top-level Go module): a single self-contained, cgo-free binary — `seedloader` — with no Node, no Bun, and no separate JS engine to install on the box.

It is a **platform target, not a reimplementation.** All protocol and app logic stays shared TypeScript — the cap-bridge (§12.2), the transport driver and its socket seams (§12.6 — the protocol itself is not host code at all, but the guest program of a signed bundle), the loader and its admission policy (§12.4–§12.5), bundle verification (§12.4), the confined safe-js guest (§12.3) — the same code the other targets run, just hosted differently. Go supplies only the platform **primitives** the §1 table calls for; protocol is never re-derived in a second language (*Go grows with primitives, never with logic*).

This is enforced mechanically: the shared modules are compiled by `tsc` and assembled into **one** `native/host-shell.gen.js` by `scripts/bundle-loader.mjs` (`npm run build:loader-bundles`), which the loader `//go:embed`s and evaluates in QuickJS. Nothing under `native/` is a hand-written second copy. The bundle runs over a *seam* — a single TypeScript adapter (`host/native-shim.ts`) satisfying the same interfaces the JS host does (`BundleHost`, `FreshnessStore`, `ChannelFactory`, `RealmFactory`) by forwarding to Go's byte-level `bridge`, and then handing the result to the shared `createShell`. Because the adapter is typechecked against those interfaces, a shared-rule change the native target fails to honor is a **compile error**, not a silent divergence. The seam carries no rules of its own: who may install (§12.5), the name derivation (§5.1), the admit-then-bind step (§12.4), the manifest signature and its domain prefix (§12.4), the freshness arithmetic, and the deny-all default (§14) all live in the shared modules — one implementation of each to audit.

**The assembly order is shared too, not just the parts.** `createShell` (`host/shell-core.ts`) is the one place a node is put together — the module table, the cap-bridge built from the manifest's declared domains, the guest preamble, the confined realm's lifecycle, the protocol bindings, and the inbound dispatch — and every target calls it with a `ShellPlatform` describing only what genuinely varies: `{ sodium, identity, table, fs, freshnessStore, channels, listen, wsListen, networkKey, contactSecret, admitPeer, createRealm }` — the socket seam (`channels`, `listen`, `wsListen`) where the §12.6 driver's DIAL actions and accept paths resolve, and the transport knobs (`networkKey`, `contactSecret`, `admitPeer`) that make the node's network policy-shaped. There is no `network` member to hand in: the transport bundle lands through the ordinary `loadBundleBlob`, and the driver it stands *is* the network. Since every app is a guest (§12.4), `createRealm` is a required member rather than an optional one — a shell that cannot run a guest cannot host an app. `fs` stays optional, but for a different reason than it once had: not "this shell has no guests," but simply "this node has no disk" — and a bundle declaring the `fs` cap on such a shell gets no backend wired at all, so its first `fs/*` call throws by name rather than resolving to a pretend store (§12.2). Realm creation is a *member* of that seam rather than something the shell reaches for itself, so `safe-js.ts` is the JS platform's realm factory and a second quickjs-ng runtime driven by Go's loop (`native/guest.go`) is this one's. Go therefore holds no boot sequence: `main.go` boots the engines, exposes the primitives, evaluates the one bundle, and forwards the CLI as a JSON config. There is no Go-side dispatch, no Go-side cap-bridge construction, and no Go-side notion of which app answers a protocol — which is what makes §12.10 hold identically here and in the browser.

The §3 module table is Go's own `map[string]map[string]*boundModule` — the table is a contract, so the native target implements it rather than embedding it. Concretely the binary embeds and drives, over [wazero](https://wazero.io) (a pure-Go, cgo-free wasm runtime):

- **`libsodium.wasm`** — the *same* crypto blob as the browser/Node build, which is exactly what makes a Go node's sealed boxes, XChaCha20 blocks, and Ed25519→Curve25519 conversions byte-identical to a JS node's. Wire/crypto parity is free when it is literally the same code.
- **a prebuilt QuickJS** (quickjs-ng, `native/qjs`) — so the shared host JS runs unmodified with no native JS-engine dependency. QuickJS is synchronous, so Go owns the event loop (timers, the JS job queue, socket delivery). A round-tripping `host.call` — net or fs — returns a real Promise to the guest: the shell's cap-bridge starts the work under a call id and, when it settles, the realm's own settle callback resolves the guest's pending Promise, and the shared loop pumps the guest realm so the awaiting entrypoint resumes — the same real-promise seam the Node/Bun build uses, driven by Go's loop instead of quickjs-emscripten's job pump. Go's own `fs` primitive is synchronous (it reads the local disk in the call); the wrap that makes it the async seam the shared code consumes is in `native-shim.ts`, not in Go, because adaptation is logic and Go grows only with primitives. The confined guest runs in a second, zero-authority QuickJS realm whose only seam is `host.call`; because the settle path is per realm, a node hosting two guest apps keeps their capability funnels apart by construction.

There is no WebSocket anything here. `ws.wasm` is a module of the transport bundle and lands on the module table through the ordinary loader, so Go instantiates it exactly as it instantiates an app's module — and the codec that drives it runs in the transport guest. A node↔node TCP deployment never touches either.

**Native fast paths, and the one rule that licenses them.** A few primitives run as target-native Go rather than through the shared wasm. That is an optimization and must stay one, so it is governed by a single rule rather than re-argued per call site:

> **Where a primitive is standardized, a target may substitute a native implementation, because the bytes are identical and only the speed differs.**

Three conditions make that safe, and a substitution failing *any* of them is a fork, not an optimization:

1. **The primitive is standardized**, so "correct" is defined by a document rather than by whatever the reference implementation happens to do.
2. **The output is byte-identical**, and is *pinned by a known-answer test* against the shared blob's own output — not merely believed to match.
3. **No protocol judgement lives inside it.** A hash or an AEAD seal qualifies. A verifier does not: its accept/reject boundary is consensus (a bundle one node admits, every node must admit), and two conforming implementations can still disagree at the edges on malformed inputs.

Condition 3 is why Ed25519 and ML-DSA-65 stay on the shared wasm on every target (§12.4, §14.1) while BLAKE2b-256 and the ChaCha20-Poly1305 record layer do not: the first two decide whether to *accept* something, the last two only transform bytes. It is the same trade as `ws.wasm` versus a native RFC 6455, and it will come up again for every suite added under §14.1.

Go-native primitives back the capability seams: `os` for the §12.1 fs backend, `net` for the raw TCP socket — one socket kind, carrying node↔node and browser↔node alike, with the codec named per link and run above Go entirely — and `crypto/rand` for entropy. WebRTC (§12.7) stays browser-only. The CLI mirrors §12.8 exactly:

```sh
seedloader --policy ./allowed-keys.json --dir ./data --key ./node.key \
     --listen 0.0.0.0:7000 [--ws-listen 0.0.0.0:7001] \
     --bundle ./app-bundle [--bind seedstore/v1=<author hex>:seedstore,…] \
     [--peers <pk>@host:port,…] [--put file] [--get hex[:hex…] --out file]
```

The `--key` file holds the node's 32-byte master seed (§12.6.2b) — the same file format
and derivation as the JS shell's `--key`: Go reads it (or mints one from `crypto/rand`)
and `bootNode` in the shared seam derives the `channel` and `guest` subkeys from it, so
both targets hold one secret on disk and no key signs for two purposes.

Because the wire and the bundles are shared, a Go node and a Node/Bun node interoperate directly in one cohort — `put` on either, `get` on the other, in both directions, against the same signed bundle and genesis (verified end-to-end for seed store by `WASM/scripts/loader-interop.sh`).

**Scope: the native target is a bundle-runner.** Its app path is the §12.4 bundle — load, verify, install the modules, run the guest — and its request path is transport → shared route bundle → cap-bridge → the app's guest `handle` entrypoint, which reaches the installed modules by name through `module/call` (§12.2). Both targets install code only from a signed bundle (§12.4), so the app-delivery surface is identical. There is no dispatch loop and no signature pipeline to keep in parity: the table is a two-level name table (§3) and modules are pure transforms (§4), so Go's only module-facing duties are staging input into a module's `scratch`, reading its output, and honoring a declared `scratchSize` (§4.1) — byte-identical to the JS host. The loader's admission and policy (§12.4–§12.5), bundle freshness (§12.4), and the domain prefixes (§16.1) are the same shared TS both targets run in QuickJS; the manifest and channel signatures the loader checks read their `DOMAIN_*` prefixes from that one evaluated `domains.ts`, so every signed preimage is byte-identical across the cohort by construction, not by a hand-copied constant.

**Size.** One file, ~7.5 MB stripped, cross-compiled to win/linux/mac with `GOOS`/`GOARCH` — nothing to install alongside it. The bulk is wazero's compiler backend (~4 MB) and the Go runtime (~2.4 MB); the protocol's own footprint stays tiny (§10.2). Against the JS shell — which needs a Node/Bun install plus the lazily-loaded ~1.5 MB QuickJS engines — the native binary trades a larger single artifact for zero external dependencies, the right shape for a server or an appliance.

**Performance.** Because the Go target drives the *same* `libsodium.wasm` under wazero that the JS targets run under V8, crypto throughput tracks node closely — Ed25519 verify and XChaCha20 land within ~10% either way, and the Reed–Solomon codec runs a touch *faster* (≈330 / 394 vs ≈315 / 319 MB/s encode / decode). The deliberate exceptions are the two native fast paths licensed by the rule above: the block-id hash (BLAKE2b-256, `golang.org/x/crypto/blake2b`), which sits on the storage data path and is the single primitive wazero ran materially slower than V8, so native (~600 vs ~390 MB/s) is the clear win; and the ChaCha20-Poly1305 record layer (RFC 8439, `golang.org/x/crypto/chacha20poly1305`), a per-frame cost that runs ~8× faster natively and, needing no scratch arena, takes no lock. Both are KAT-pinned against this build's own wasm output. Per-frame overhead trails node by Go-side event-loop cost, not crypto. Reproduce with `go test -run x -bench . -benchmem ./...` from `native/`; the node baselines come from `WASM/tests/run.mjs` and seed store's `WASM/tests/bench.mjs`.

### 12.10 Protocol bindings — which app handles a message

Admission (§12.5) decides whether code may run. It does not decide who gets traffic, and after §5.1 it cannot: a node may hold two apps that both serve chat, authored by different keys, bound at names that never collide. Something has to say which one a message goes to.

**A frame names a protocol, not an app.** What travels is a protocol id in the Transport req frame (§12.6) — a chat message carries one, a storage message carries its op. It never names an app, an author, or a module: those are node-local (§5.1), and a wire that named them would make every peer's install choices everyone else's business.

**Installation is inert; the operator owns the routing.** A bundle load lands code and nothing else. The table below is written by exactly one act — an explicit operator call, `shell.bind("seedstore/v1", appKey)` — and nothing in the runtime ever writes it instead: there is no declared protocol list to honor, no default to the app's own name, no binding at install, and no update rule to inherit one. Bundle identity (the app key), the wire protocol (the id), and local routing (the binding) are three separate things, and the last is the operator's alone.

```
bindings: protocol id → app key
```

pointing at the `"<author hex>:<app>"` of §12.4. To deliver, the host reads the frame's protocol id, looks up the app key, and invokes that app's guest `handle` entrypoint (§12.2) with the authenticated sender's 32-byte public key prepended to the payload (`senderPk ‖ payload`). That is the **one delivery shape** — every app is a guest, so there is no second entrypoint to resolve (§12.4) and no branch on how an app is implemented: a guest that needs a transform calls its own module by name through `module/call`. An unbound protocol reaches no app at all, so the request is answered empty (the Transport always answers; a null result is an empty body, never a dropped frame).

**A protocol a shell answers itself is the shell's business, not the runtime's.** Bundle transit is the example: the browser chat-shell reserves the id `_offer` for it — a peer sends a signed bundle blob, the recipient verifies it and asks the user — and answers it in its own `transport.onRequest` handler, ahead of calling `dispatch`. That is a UI decision by the target that owns the feature, not a rule of the runtime; `dispatch` here has no reserved ids and no second path, and a headless node that never wants offers simply has no such handler.

**A bundle can claim nothing.** The manifest carries no protocol list for a loader to honor and no name a message could be routed by — the only facts it signs are the app's identity and the code that lands, both governed by policy (§12.4–§12.5). Receiving traffic is a separate act, chosen by the operator at bind time. This is why no register is needed to keep protocol names apart *and* no race replaces it: the two acts an ownership register would conflate — landing code, and receiving traffic — are separate here, one authorized by policy and one chosen by the operator. An installed app serves nothing until a binding points at it, so no bundle ever receives a byte on the strength of an install.

**Binding rules.** There is exactly one: **a binding is an operator action, and nothing else writes the table.** Install binds nothing; an update inherits nothing and re-applies nothing — an upgrade lands on the same app key, so an existing binding survives it only because the table was never touched; `bind` to another key and `unbind` are the operator's rebind; uninstall drops the app's bindings with it. There are no defaults to fall back on and no vacancies to fill — an unbound protocol stays unbound until the operator says otherwise. The one thing `bind` does check is that the app is *here*: an app key nothing is installed under is refused, at the bind, where the refusal can name the key. Which app answers is entirely the operator's; an app that does not exist is not a choice, and its only other symptom would be a node that boots clean and answers an empty body on that protocol forever — so the native loader exits non-zero on a bad `--bind` rather than serving.

**Rebinding is the answer to a dead or superseded author.** Point `chat` at a different app and it takes over; the previous app stays installed and intact, just idle. No uninstall, no name to vacate, and the move is one table write in either direction — because the two apps were never competing for a slot, only for a binding. That is the practical payoff of putting the author in the name: succeeding an abandoned app stops requiring cooperation from its author.

**One app per protocol.** The table maps to a single app key, not a list. A second app on a protocol would be a *fan-out*, and today it would be a no-op: WASM modules are pure transforms with zero authority (§4.2), so a would-be logger or archiver bound alongside a chat app can only return bytes its guest discards. The component that can genuinely act on a message is an app's guest, with declared `requires` (§12.2) — and binding one as an observer gives it every message on that protocol, which is an authority grant, not a preference. It needs its own approval showing what the app holds, and it must not share an affordance with "which chat app do I want." When that case arrives the extension is additive — the value becomes `{ view, observers[] }`, `view` staying the free preference and `observers` the granted feed — and the manifest already carries the `requires` such a prompt would have to show. Until then a single value is the honest shape.

**Bindings are shell state, not loader state, and hold no security property.** The browser persists them in `sessionStorage` because the chat-shell UI lets a user manually rebind protocols — assigning "chat" to a different installed app — and that choice must survive a page refresh. A headless node applies its operator's binds at boot the same way it applies its policy: the native loader's `--bind proto=appKey` list, or an embedder's own startup script calling `shell.bind`. A user may rewrite a binding at any time. Nothing about integrity, authenticity, or authority rests on them: a binding cannot make unadmitted code run, cannot widen a guest's `requires`, and cannot let one app act in another's signing scope (§12.2). The worst a wrong binding does is send messages to the wrong app the user already chose to install — recoverable by rebinding. That is exactly why it belongs to the user and not to the policy file.
