# Seed kernel — Runtime

*The runtime as an app host: performance, the chat demo, and the shell — capability backends, the guest-seam ABI, zero-authority JS realms, signed bundles, the node↔node transport, and the Go/native binary.*

> **Part of the [seed kernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · [PROTOCOL](PROTOCOL.md) §2–§5, §16 · **RUNTIME §10–§12** · [SECURITY](SECURITY.md) §13–§14

---

## 10. Performance

The message path does **no asymmetric cryptography and no recursion**: routing a frame to an app is one routing lookup (§12.10) plus one guest entrypoint invocation, and the only scratch copies are the ones a guest's own module calls make (§4). No per-message signature verify sits on that path: authenticity is the channel's (§12.6), established once when the link opens rather than checked per message.

### 10.1 Where the crypto is now

So the costs worth measuring are the three places real cryptography lives, all off the dispatch hot path:

- **Per connection:** the AKE handshake (§12.6) — one Ed25519 sign + verify and one X25519 exchange, amortised across the whole session.
- **Per frame:** one ChaCha20-Poly1305 record seal/open (§12.6) — symmetric, fast, the steady-state transport cost.
- **Per bundle load:** one manifest verify — Ed25519 *and* ML-DSA-65, the one suite requiring both (§12.4) — plus a BLAKE2b-256 content hash per module. Once, at install, which is why the second verify and the ~5.3 KB envelope cost nothing that shows: a manifest is never on the message path (§13).

The Go/native target carries `*_bench_test.go` benchmarks over these hot paths (net round-trip, fs, the crypto primitives, the record layer); `WASM/tests/run.mjs` exercises the same paths end-to-end on the JS target, and seed store's `WASM/tests/bench.mjs` measures storage throughput. There is no signed-message microbenchmark anymore because there is no signed message — a chat frame crosses the WASM boundary only for the module call its guest makes.

### 10.2 Distribution Size

This is the one place these figures live; the README's shared-artifact list points here rather than restating them.

| Component | Size |
|---|---|
| host/*.js — minified (`build-min`, runtime code only) | ~168 KB |
| the embedded transport bundle (`host/transport-bundle.js` — the signed `.skb` as base64, including `ws.wasm` and `mlkem768.wasm`) | ~160 KB |
| libsodium.wasm (core build: the host trust root and current channel fast paths) | 217 KB |
| libsodium-wrappers.mjs + libsodium-core.mjs | 135 KB |
| mldsa65.wasm (ML-DSA-65, the PQ half of manifest suite `0x02`, §12.4) | 16 KB |
| **Total browser deployment** | **~696 KB** |
| mlkem768.wasm (ML-KEM-768) | 12 KB, already counted inside the transport bundle; not a host artifact |
| QuickJS realm engine (the in-repo quickjs-ng 0.16.1 emscripten build, `quickjs/` — the same engine source the native loader compiles, §12.9) — only loaded when a bundle's guest runs (§12.3) | ~570 KB |

The `host/*.js` layer is the whole runtime: bundle slots and claim routing, raw net and fs seams, the guest seam, safe-js, verification, policy, and the transport driver. Pure modules remain target values owned privately by a slot. The transport protocol is signed content (`transport/src/*.js` plus `ws.wasm` and `mlkem768.wasm`); the first copy ships inside the artifact because a node has no network until it has a transport, and a later signed bundle can replace it. Core libsodium backs the trust-root crypto and the current channel's remaining host transforms. QuickJS is lazy: a shell with no installed slot never pays for a realm.

`npm run build` emits the host twice: the readable `build/` (~446 KB of runtime code, doc comments intact) for debugging and a comment-stripped `build-min/` (~313 KB, ~108 KB gzipped) for shipping. Roughly a third of both is the generated `transport-bundle.js`, the signed bundle embedded verbatim — it carries no doc comments to strip, so it passes through nearly unchanged and dilutes the ratio. The hand-written host alone goes ~286 KB → ~154 KB, because those sources are close to half doc comment, and that is where the cut comes from. A small dependency-free stripper (`scripts/minify.mjs`, each output gated through `node --check`) does it — no bundler, no new dependencies; it prints the gzipped totals on every run. The table's host figure is the shipped, minified build.

---

## 11. Example app layer: chat ([seedchat](https://github.com/arj03/seedchat))

Chat is the smallest possible app: a confined JS **guest** over a single **pure-transform** module (§4). The guest is a handful of lines — its `handle` entrypoint forwards its input to the module by name through `host.call` and returns the render bytes — and the module is the transform: it does no I/O and no crypto, reading `senderPk ‖ chatType ‖ body` and writing the render bytes for the UI. Everything around it — authenticating the sender, moving frames, driving the iframe — is the shell's job, because a pure transform has no reach of its own and a guest reaches the world only through `host.call` (§12.2).

The app itself lives in [seedchat](https://github.com/arj03/seedchat), not in this repo. Like [seed store](https://github.com/arj03/seedstore), it is a *consumer* of the runtime: it installs `seedkernel-wasm` and reaches the host only through published entry points (`shell-core`, `bundle`, `net-rtc`, `libsodium`). Nothing here knows chat exists — this section describes it because it is the shortest complete trace of the whole stack, and §13 walks the same pipeline byte-by-byte.

What the demo stands up is a browser shell owning the host's table and its one install path, a WebRTC socket seam (`RtcNetwork`, `host/net-rtc.ts`, §12.7) under the transport bundle, the safe-js guest realm, and a sandboxed iframe — every byte of chat UI and logic arrives as a signed bundle admitted at runtime.

On load it generates an Ed25519 identity, constructs a host (§3), and loads an admission policy (§12.5) approving modules whose author is the local identity — or, for apps received from a peer, one the user consents to. That consent decision is the browser's own policy state, and it is the only one the shell has to make: names cannot contend (§5.1), so a multi-app shell arbitrates *whether code runs*, never *who holds a name*. The table starts empty. The user picks a chat app (`v1 — text only`, `v2 — text + image + nick`); the shell builds a **signed bundle** — a `manifest.bundle` (the local key's Ed25519 signature over the manifest, which commits to the guest's and the module's `genesisHash`) plus `guest.js` and the app's `.wasm`, packed into one blob (§12.4) — verifies it, and the loader admits the app under that policy (§12.4). This is the *same* bundle format seed store loads; a chat app is just a guest that calls its one module. Upgrading v1→v2 is a re-admit at the same name under the same key — the same key derives the same name — and the new manifest re-states the `chat` protocol claim, so routing follows the install (§12.10). Peers hand these bundles to each other in an `OFFER` frame; the recipient re-verifies the original author's manifest signature and admits it the same way — and because the manifest signs the guest and module hashes, the bundle survives any number of transitive relays and still authenticates against its original author (the store-and-forward property an offer needs, §12.4).

Peers connect over a WebRTC mesh from `RtcNetwork` (`host/net-rtc.ts`, §12.7). Every delivered frame is already attributed to an authenticated peer, so chat rides the Transport request plane as `[req][protocolId][type][chatType‖body]`. The shell resolves the protocol claim directly to a slot, prepends that peer key, and invokes the slot's guest under its budget; the guest may call its private chat module. A peer states only the protocol, while the receiving user's installed claims decide which verified implementation renders it.

The relay is partitioned into **rooms** so one instance hosts many independent groups without cross-talk. A client picks its room as the URL path — `ws://host:8080/<room>` — and the relay forwards only between sockets sharing a room; a bare `/` lands in the default room `global`. Room names are URL-safe (`[A-Za-z0-9._-]`, ≤128 chars). The room is **not** an authenticated channel — knowing the name is the only credential, and the relay sees all signaling in its room — but the end-to-end identity binding below means a relay or room member cannot impersonate a peer, only observe SDP metadata and refuse to forward.

`RtcNetwork` (`host/net-rtc.ts`) is only the WebRTC socket seam: it hands each data channel to the transport driver, and the transport bundle runs its handshake *inside* that channel (§12.6), so each end proves it holds the private key for the identity it claims *before* any frame is delivered — and neither identity crosses the wire in the clear, then every later frame rides the §12.6 ChaCha20-Poly1305 record layer, attributed to that identity rather than to anything inside the frame. This is continuous channel binding, stronger than a one-shot SDP `a=fingerprint` assertion at the signaling layer (RFC 8827 §5.6.4) — a MITM relay can splice SDP and bring DTLS up to itself, but can never produce the transcript signature without the peer's private key, so the link never authenticates and never delivers a byte. The record layer already makes every frame confidential and integrity-protected; the data channel's own DTLS is a redundant second layer underneath (§12.7).

The chat module never reaches the UI itself: it is a pure transform that *returns* render bytes, which the guest's `handle` passes back to the shell, which forwards them to the iframe by `postMessage`. The iframe is `sandbox="allow-scripts allow-forms"` with no same-origin access to the shell, so app-rendered content stays walled off from the shell's keys and peer state.

Two conventions in that demo are worth naming as **not** runtime contracts: the `ui` and `app_meta` WASM custom sections. Bundling the UI bytes inside the app module means one signed install updates compute and presentation atomically, and `app_meta` lets a dropped `.wasm` identify itself — but the host reads neither. Both are encoded and parsed entirely by the shell, so they live in seedchat, and another app is free to ignore or replace them.

The one cost of this shape: the demo runs a guest realm, so it fetches the lazy QuickJS engine (§10.2) where a module-only shell once did not — the honest price of having exactly one kind of app (§12.4).

To run it: build this repo (`npm run build:browser`), then follow the build steps in seedchat, which vendors the artifacts above, runs the signaling rendezvous (`npm run relay`), and serves its own page.

---

## 12. The runtime as an app host: capabilities, the shell, and signed bundles

Chat (§11) is a browser shell wired by hand, in its own repo. The same onion ships as a **general runtime artifact** — the *shell* — that any app rides on as **signed content**. The shell knows nothing about chat or storage; it offers a fixed, generic surface, verifies a bundle against a policy, and *becomes* whatever the bundle is. [seed store](https://github.com/arj03/seedstore) is the worked example: a full peer-to-peer storage node is the shell plus a signed bundle, with no storage-specific code in the runtime.

"Capabilities" from here on mean one thing: the **manifest requires** (§12.2, §12.4) — SERVICE-level `host.call` grants such as `node`, `fs`, `timer`, `link`, and local service ids of the bundle's own choosing. `link` requires the operator's `link` grant. They answer "may this *app's guest* reach this backend or local service at all?" (WASM modules, by contrast, carry no capabilities at all — a pure transform reaches nothing but the input it is handed and the output it returns, §4.2.)

**Only services are grants, and only grants are declared.** A pure transform is computation, not authority, and belongs in the bundle that uses it. A bundle's modules are installed and verified with its guest, so calling one reaches nothing the guest does not already hold — the scope (one app's map) is the shape, not a grant. `guest.requires` therefore carries services and local service ids only, so the list an operator reads is exactly the bundle's reach. The residual `crypto/*` names are a compatibility table for transforms the host already carries; they are ungated but no longer an algorithm extension mechanism.

The manifest's `guest.requires` field is the guest's entire authority, so it lives inside the signed manifest and nowhere else. The resulting backends and scopes are captured by the bundle slot.

### 12.1 Raw-byte capability backends

The runtime provides the capability *backends* an app's confined logic drives through the guest seam (§12.2). They are deliberately structureless — bytes in, bytes out — so the host never learns what an app means by them:

- **Host transforms and bundle modules.** `HOST_TRANSFORM_NAMES` is the residual `crypto/*` compatibility table: `blake2b-256`, `chacha20poly1305-ietf/{seal,open}` and `x25519/dh`. It is not a capability and is not a catalog to provision ahead of callers. New pure computation ships under a bare module name in the bundle that needs it. The default transport demonstrates the rule: `host.call("mlkem", bytes)` reaches its private `mlkem768.wasm`. Seed store ships its erasure coding the same way, under its own `codec` module name; its hashing and record encryption still reach the residual table, while its signatures use the scoped `node/sign`/`node/verify` pair.

  Removing `xchacha20/xor` also removes the only sumo-only symbol. All targets now use core libsodium; the browser WASM shrinks from 278 KB to 217 KB, and the corresponding wrapper/core JavaScript shrinks as well. `kem.ts`, `mlkem.go`, the native KEM bridge and the separately embedded native KEM artifact are gone.
- **The authorities** — everything that reaches something no confined module can hold. `node/sign` under the node identity but **scoped**: the host prepends a domain and a host-derived scope to the message before signing (§12.2), so a guest never obtains a raw node-key signature and raw signing stays host-internal. `node/verify` is scoped the same way — the host applies `domain ‖ scope` to a caller-named key's signature, so a guest checks a signature under its own bundle's namespace and never reconstructs the prefix. `node/identity` (the node's public key), `node/random` (the OS entropy source), `clock/now`, `timer/*` (the platform's event loop).
- **`fs`** — raw bytes under an opaque, flat key (`core/fs.ts`): `get`/`put`/`size`/`list`/`delete`/`stat` (existence is `size ≥ 0`, so there is no separate `has`). An in-RAM `MemoryFs` (`host/fs-memory.ts`) and a directory-backed `NodeFs` (`host/fs-node.ts`), with OPFS/IndexedDB the shape a browser backend fills in. No content-addressing, no paths — that's app policy.

  **Every method is asynchronous, and that is the seam's property rather than any backend's.** A synchronous `get(key): Uint8Array | null` is a shape no browser backend can implement — IndexedDB is asynchronous by construction and OPFS is synchronous only inside a Worker — so a sync seam would have made the browser the one target unable to carry a capability that is *core* (§1). `MemoryFs` and the native target's Go primitive both answer in the call and are wrapped to resolve in a microtask, because a seam that resolved sometimes-immediately would let a guest work by accident on one backend and fail on the backend it ships against. It follows on the guest side too: the `fs/*` names round-trip like a cross-realm call, so a guest reads them with `await`.
- **Raw links, structured service, and event returns.** `link` moves bytes over an opaque link id and binds platform link events directly to the slot holding that capability — one slot, since the driver has one event sink, so a second link-capable load is refused rather than allowed to take the sockets over (§12.10). The transport exposes its structured API under an ordinary local service id selected by composition (`_net` in the bundled setup) — declared in the manifest's `services` list, a co-resident guest's to reach and never a peer's. Authentication, teardown and inbound attributed delivery are the link slot's **event return conventions**, not more privileges: authentication returns only from the `linkBytes` that completed it, teardown from `linkClosed`, and the occupant that sees plaintext may return `(claim, attribution, payload)` for the host to route. The event supplies the link id, so no return can select another socket. No claim spelling confers the privilege — which LIST a name is signed into is what decides its reach (§12.5, §12.10).

  **A link says how it is framed, and that is the only thing the platform says about it.** Some transports carry message boundaries and some do not: a browser `WebSocket` and an `RTCDataChannel` deliver whole messages, a TCP socket delivers arbitrary slices. So a link opens with a `FRAMING` code (`core/socket-seam.ts`) — `PLATFORM`, `LENGTH`, `WS_CLIENT`, `WS_SERVER` — and the transport bundle runs the named codec. The host is not describing the socket; it is naming which of the codecs the bundle already holds applies to a link the host has **already opened**. A dialed WebSocket also carries the `authority` it was dialed at, because RFC 6455 requires it in the `Host` header. Neither is a route the guest could dial for itself, which is the property that matters: the link id stays opaque and the address book stays the host's.

  Under the platform the socket seams are `host/net-node.ts` (node:net), `host/net-rtc.ts` (WebRTC, §12.7) and `host/net-ws.ts` (a browser `WebSocket`), each handing a link to the driver in `host/transport-host.ts`; the flood bounds that must sit with whoever holds the descriptor are `core/net-limits.ts` (§12.6.2), declared by the host and applied by the bundle's framers, which are the code that sees a length before its body.

  **What differs per target is only the object that moves bytes**, and wrapping it is host code on every target, because a confined guest never holds a socket — so whoever owns the platform's object does the wrapping. The browser's only socket objects are the platform `WebSocket` and `RTCPeerConnection`, so the JS platform wraps those (`net-ws.ts`, `net-rtc.ts`) — and precisely because the browser has no raw TCP, WebSocket exists as a codec over a raw TCP listener, which is why a *node* answers a browser's WS with no extra host code: the same `node:net` socket with `FRAMING.WS_*` declared, RFC 6455 in `ws.wasm`. Node also wraps `node:net` for TCP; Go wraps nothing — raw sockets are native there (`net.go`/`sock.go`), and the same `ws.wasm` serves its `--ws-listen` (§12.9). WebRTC is the one adapter with no Go counterpart, because RTC exists for the browser's NAT traversal: a native node is a reachable server, so it is never the dialing side of an RTC link. Whatever the object, it lands in the driver's `openLink` and the bundle cannot tell the transports apart.

Anything with *structure* is a **no-capability module** that transforms bytes: WebSocket framing is `ws.wasm`, a module of the transport bundle; Reed–Solomon erasure coding is an app's `codec.wasm`. Both are pure transforms their own bundle's guest drives by logical name, never something the host or the platform knows.

### 12.2 The guest seam: the guest name ABI

An app's confined logic reaches all of the above through a single seam, `host.call(name, bytes)` — the guest's one route to real I/O, the counterpart to the host's own `callModule`. `host/guest-seam.ts` (`./guest-seam`) services that seam from the primitives above and *only* those. Every name is application-neutral; the seam has no idea it is hosting storage.

The names are **guest↔host identifiers**, not wire values: opaque strings with no op-number registry or generated preamble. The guest writes the literal string (`"fs/get"`, `"_net"`, `"mlkem"`); the seam dispatches either the host table, a declared local service, or the asking bundle's private module map. Multi-byte integers are big-endian (§16).

**Three kinds of name, told apart by declaration first and charset second.** Host services and residual host transforms are the host's; a name in THIS realm's own declared local services is another realm's; anything else is the asking bundle's own module. The dispatch asks the declaration first. What remains splits by charset: every host name contains a `/` and a module name cannot (`[A-Za-z0-9_-]`, §12.4). `crypto/*` is generated from `HOST_TRANSFORM_NAMES`; `HOST_SERVICES` is hand-written. There is no second framing: the module name is the seam's name argument.

**Two kinds are not capabilities.** The residual `crypto/*` entries and a bundle's own bare module names are ungated because they are pure computation. Every other host name belongs to a service touching the node key, entropy, clock, sockets or disk. New algorithms go in the bundle-module half, not `HOST_TRANSFORM_NAMES`.

| Name | Request | Response |
| --- | --- | --- |
| `crypto/<host-transform>` | argument bytes | output from the frozen compatibility table (§12.1); an unknown name throws |
| `node/sign` | message bytes | 64-byte detached Ed25519 signature under the node identity, over `domain ‖ scope ‖ msg` — this slot's one scope (`slotSignScope`, below, §16.1): an app slot's own `author ‖ app`, the link slot's `network_key`. The host chooses what the name signs under; never guest-supplied |
| `node/verify` | `[pk 32][sig 64][msg ..]` | `[ok u8]` — the same `domain ‖ scope` applied host-side: 1 iff `sig` is a valid Ed25519 signature of `domain ‖ scope ‖ msg` under `pk`. The key is caller-named, the scope is not. A payload too short to hold the fixed 96-byte prefix throws rather than answering 0 — a mis-framed call is not a failed verification |
| `node/identity` | (empty) | the node's 32-byte public key |
| `node/random` | `[n u32]` | `n` random bytes |
| `fs/get` | key (utf8) | `[0]` absent \| `[1][bytes ..]` — **awaited** |
| `fs/put` | `[klen u32][key][bytes ..]` | (empty) — **awaited** |
| `fs/list` | prefix (utf8, may be empty) | `[count u32] {[klen u32][key]}` — **awaited** |
| `fs/delete` | key (utf8) | (empty) — **awaited** |
| `fs/stat` | (empty) | `[used u64][available u64]` — **awaited** |
| `fs/size` | key (utf8) | `[size i32]` (−1 if absent) — **awaited** |
| *any bare name* — `codec`, `ws`, … | the request bytes, unwrapped | the response from the slot's private module of that manifest name. Unknown names are refused; a module that runs and fails answers empty. |
| `clock/now` | (empty) | now in unix ms (`u64`) |
| `link/open` | `[dest ..]` — an opaque destination name the host resolves in the address book it was configured with, exactly as `fs` resolves a key | `[linkId u32][framing u8][authLen u32][authority utf8]` (link 0 ⇒ no route). `framing` names the wire codec to run over this link; `authority` is the `host:port` it was dialed at, non-empty only for a dialed WebSocket (§12.1) |
| `link/send` | `[linkId u32][bytes ..]` | (empty) |
| `link/close` | `[linkId u32][graceful u8]` | (empty) |
| `link/stat` | `[linkId u32]` | `[buffered u32]` — bytes written to this link that are not yet on the wire; 0 for a link that is gone or cannot say |
| `timer/arm` | `[id u32][ms u32][body …]` | (empty) — a fired deadline re-enters `handle` as an ordinary host loopback carrying the supplied body verbatim; its framing belongs to the guest and remains opaque to the kernel |
| `timer/clear` | `[id u32]` | (empty) |
| *any name in this realm's declared local services* | opaque bytes, with the CALLER's 32-byte id prepended host-side | whatever the claiming realm's `handle` returned — **awaited**. A local service id (§12.10) with no kernel-known spellings or roles; refused by name when nothing claims it |

The `link` names are the **raw-link** capability. Raw events arrive directly at the one slot owning that capability; what a transport provides back is an ordinary local service claim. The occupant's observations about a platform-owned socket are returns from the event that caused them, never guest-callable host names. `linkBytes(linkId, bytes)` returns `[authenticated u8][peer 32 when authenticated][delivery count u32][deliveries …]`; the driver binds the optional peer and every delivery to that invocation's captured link and active owner. `linkClosed(linkId)` returns the occupant's one-byte reason. Neither return carries a link id, so it cannot redirect a transition to another socket; a stale return after close, reset or handover is discarded. Attributed inbound requests from `linkBytes` are routed through the host's claim table, and the answer is written back to the link occupant for framing. They reach only what a peer may reach, so a bundle's own `services` claim is not among them (§12.10): the *same shell* routing that refuses a peer's call to a local service name decides the delivery.

**The node's immutable facts use the ordinary config path, not a privileged invocation.** `TransportHost.initialConfig()` returns JSON which the shell merges into the link occupant's installation-local `LOCAL` object before `standRealm`; host-owned keys win same-named values supplied by the load. The peer id, network key, contact secret and admitted peer ids use the same hex spelling as peer references. They are constructor input, delivered once and not re-readable. The address book is mutable node state and is not among the facts: it arrives as `addr` events, replayed after publication (§12.10).
The **contact secret** is the one fact that is not read-only in practice, so it is re-delivered per link too: the driver reads its current value at every open and carries it in the `linkOpen` event — the peer's on a dial, the host's own on an accept (§12.6.3) — so a node that rotates its secret gates new links immediately, with no re-install; only a transport **upgrade** is a re-load (§12.10). The `LOCAL` value remains the fallback.
Every name — local service call, `fs/*`, `crypto/*`, clock, timer, link, module — answers a Promise the guest awaits, and a fan-out is the guest's own `Promise.all`: the seam hands out real promises, so scatter-gather is the guest's own, not a host name. The host injects `__host_call(name, callId, payload)`, which always parks the answer: the preamble holds a Promise under `callId`, settled later by `__netResolve`/`__netReject`. **No name re-enters the realm**: a socket write does not deliver during the write, an armed timer fires on a later turn, and a cross-realm call runs its callee on a later turn by construction, so a guest→guest call never runs the callee inside the caller's frame.

**The answer may come on a later turn: the `__deferred` marker.** The realm serializes invocations (12.3), which is right for a guest whose answer comes from *outside* the realm - an app parked on `fs/get` must hold the queue, because its frame is suspended mid-update. It is wrong for one whose answer arrives *through* the realm: the transport replies to an app's send by reading bytes off a link, and reading those bytes is another invocation of the same realm, so awaiting inside the frame would hold the queue against the only event that could settle it. A guest that answers later sets the kernel's `__deferred` flag (its own `defer()` helper does - content, since only the transport needs it) and the invocation's queue spot frees at the end of the synchronous segment even though nothing has settled. That is the one ABI bit beyond `handle` returning bytes, and it is exactly the assertion that this guest never parks.

**The signing names are scoped, never raw, and there is one pair of them: `node/sign`/`node/verify` mean "this slot's scope," which the host derives once at load.** `node/sign` does not sign the guest's bytes as given: the host prepends a domain and a scope, both of its own choosing, and never reads the suffix. An ordinary app slot gets `DOMAIN_guest ‖ author_pk ‖ app_len u8 ‖ app` (`appSignScope`), derived from the admitted manifest (§12.4) — the same `(author, app)` pair that keys freshness. The slot holding **`link`** gets `DOMAIN_link_scope ‖ network_key` (`linkSignScope`) — the network scope is a fact of that slot, not a second name: peers verify an AKE transcript under `DOMAIN_link_scope ‖ network_key`, never under the transport author's `(author, app)`. Signing is domain separation, not parsing, so what the name signs under is the host's choice; what is inside the suffix is the slot's — the *format* signed under the scope, including the transport's own `DOMAIN_channel` tag, is bundle content, revisable in a bundle update, and the node key never enters the guest. The one scope is a function of admitted facts (`slotSignScope`), which is why it is the same on every load path: boot, an operator's `--bundle`, and the in-place update that replaces a standing slot alike. The domain-prefix family is disjoint (§14, §16.1), so a guest-obtained signature never verifies as a manifest; and distinct app slots derive disjoint scopes, so one app cannot sign in another's namespace. **Verification is scoped the same way, under the same name.** `node/verify` takes the verifying key in its argument bytes — `[pk 32][sig 64][msg …]` → `[ok u8]` — and the host applies the slot's `domain ‖ scope` prefix, so an app checks a scoped signature by naming the key and never reconstructs the prefix the host owns. It is an authority because its scope is host-derived: the guest asks "does this signature verify under *this slot's* scope?" — a fact it cannot state for itself. Raw verification remains host-internal through `SeamCrypto`; it is not separately exposed as a guest transform. Every node running the same bundle derives the same scope, which makes the signatures portable across a cohort. One consequence: rotating a bundle's author key changes its app scope and orphans previously signed objects, so an app anticipating that records its scope inside its own signed formats. §14 has the trust rationale.

The seam's names are one table, `HOST_SERVICES` (`core/domains.ts`), keyed by SERVICE rather than by method — `node`, `fs`, `clock`, `timer`, `link` — plus the ungated `crypto/*` primitives and the asking bundle's own module names. `AUTHORITY_CALLS` is the same table flattened to the full `service/method` list, used to check the dispatch table for completeness at construction (§12.9); it is not itself the manifest vocabulary. That vocabulary is `HOST_SERVICES`'s keys plus whatever local service ids a bundle's own `guest.requires` names: a `host.call` naming a host method resolves iff the method's SERVICE (`serviceOf`, a table lookup on the text before the first `/`) is declared — the unit a manifest grants is the service, never the finer-grained method, so declaring `node` grants `node/sign` *and* `node/identity` together. A grant is granted *by service* — the seam refuses any host-method `host.call` whose service is not one of the declared requires — never by parsing a domain prefix off the method's own name.

| Name | Serves | |
| --- | --- | --- |
| `node` (`node/sign`, `node/verify`, `node/identity`, `node/random`) | the node key, scoped signing/verification under THE slot's one scope — an app's own, the link slot's network scope — and the entropy source — what the *host* owns | |
| `fs` (`fs/get`, `fs/put`, `fs/list`, `fs/delete`, `fs/stat`, `fs/size`) | raw bytes under an opaque key, scoped to the app (§12.2) | |
| `clock` (`clock/now`) | | |
| `timer` (`timer/arm`, `timer/clear`) | ordinary and small: any guest that needs a deadline | |
| `link` (`link/open`, `link/send`, `link/close`, `link/stat`) | **`link` privilege only** — bytes over an opaque link id, the platform's whole contribution to the network. Authentication and teardown observations return from the driver events that caused them rather than travelling through guest-callable names. The link slot's scoped signing/verification is `node/sign`/`node/verify` under the slot's network scope (§12.2) | |
| *any local service id this realm declared* | another REALM, by the id it claims — no host service at all, and carrying no privilege | |
| `crypto/*` | the frozen host-transform compatibility table — **not a grant** | |
| *any bare name* | the bundle's own module map — **not a grant** | |

`crypto/*` and the bundle's own bare module names are exempt from the gate by a rule, not by omission: there is nothing to grant, and a manifest that had to ask before hashing a byte string would be describing a service that does not exist. The exemption is not a parse of the name — the gate asks whether a `/`-bearing name's service (`serviceOf`) is one `HOST_SERVICES` knows and, if so, whether it is declared — and a manifest naming a method directly (`fs/get`) rather than its service (`fs`) is refused at load by name, with the fix, rather than accepted as a no-op or read as a finer-grained grant the seam cannot enforce.

**The `link` row is not an app capability.** That service carries the **`link`** privilege (§12.5), enforced at the load seam rather than at first use: a manifest naming it must be granted the privilege it reaches by the operator's policy. The argument is the one that keeps the plain `authors` list from ever conveying it: an authority this large needs a deliberate separate decision, never a name an ordinary app can add to its own manifest and have quietly honoured. Adding one buys an author nothing — it puts a privilege in the set they must be granted, which is the only direction the derivation can be pushed. There is no manifest field to claim it with either, because the requires already say it.

**Each privilege is one thing, not a pair of halves.** `link` was once "sockets consumed, structure provided", and that shape needed a coherence gate to refuse a bundle claiming one half, because a half claim reached no privilege and would otherwise have fallen through to the unprivileged author list. There is nothing to halve now: the single `link` service is the whole of `link`, and the gate went with the thing it guarded. Delivery rode along the same collapse — the link occupant is the attributer, so `route` was never a half that could be granted alone, and a node with a link slot cannot forget its network's delivery path. `timer` is deliberately not privileged — the transport happening to want a deadline is not a reason to make one.

**Calling the composed transport service is not a privilege.** An app declares that ordinary local service id and calls it; owning raw links (`link`) is the one privileged operation, and attributed delivery rides the same slot.

A name the manifest never granted does not resolve — the seam refuses it, and the shell never wired the backing resource in the first place (an fs-less bundle gets no fs backend at all, not an fs backend behind a check). An unknown SERVICE in a manifest throws at load — the vocabulary is closed (`HOST_SERVICES`, `core/domains.ts`), so a typo fails loudly rather than silently granting nothing, or, worse, everything.

**Relation to WASI.** The guest seam is deliberately WASI-shaped at the seam: a small syscall table, a zero-authority guest, capability by non-wiring rather than runtime check. The differences justify a bespoke ABI. The names are identity-centric, not POSIX — `net` is addressed by peer pubkey over a channel bound to that key (§12.6), not by socket; `fs` is a flat opaque blob store with no paths; `node/sign`/`node/identity` surface the node's identity, which WASI has no notion of (and every guest signature is domain-scoped). And the grant is *signed content*: the guest's authority is the `guest.requires` field of an author-signed manifest (§12.4) admitted by operator policy (§12.5), where WASI's grants are host-local instantiation choices with no authorship. WASI begins after who authored the code and who may install it are settled; §12.4–§12.5 settle them. What keeps this from drifting into a worse WASI: names stay structureless bytes, anything with structure becomes a no-capability module (§12.1), and the catalog grows by adding names sparingly.

**`fs` is scoped to the app, not the node.** The backend a guest reaches is wrapped per **app key** `"<author hex>:<app>"` (§12.4), so `fs/list` with an empty prefix enumerates that app's keys and no others, and `fs/get`/`fs/delete` cannot name another app's. Keys come back stripped of the scope, so the guest only ever handles the names it chose. Without this, `fs` was the one place the runtime's "ownership is structural" property (§5.1) did not hold: app *keys* carry their author and are unreachable to anyone else by construction, while fs *keys* carried nothing and were reachable to everyone with the domain. The scope prefix is a hash of the app key (`appScopeFor`), not the app key itself: keys double as **filenames** and both backends restrict them to `[A-Za-z0-9._-]`, which `"<author hex>:<app>"` fails on its colons — and an author-chosen `app` cannot be trusted to stay inside any charset anyway. Hashing fixes both at once, and its fixed length means two distinct app keys cannot produce prefixes where one extends the other (plain concatenation would let app `x` key `y:z` collide with app `x:y` key `z`). The charset is a consensus predicate (`isSafeFsKey`, §16.1): `.` and `..` are refused, and so are Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9`) on every OS, because Windows resolves the stem before the first `.` to a device (`NUL.txt` is still `NUL`) and two nodes disagreeing about a key disagree about their contents. `fs/stat` is deliberately **not** scoped: `used`/`available` describe the physical backend, and a per-app `available` would be a fiction.

**The two gates are not optional.** A seam is constructed with an allowed name set and a logical→host module map, and both are *required* arguments. Omitting the name set is a construction error, never an unrestricted seam; a host-side test that exercises every current service lists those services explicitly. Module calls remain bound to one app's map, so there is no wider namespace either gate can open onto. The name-set check is enforced at *runtime*, not only in the types: the native target evaluates the compiled JS of this file inside QuickJS (§12.9), where a TypeScript signature is not present to enforce anything, and a gate that holds on only one of two targets is not a gate.

### 12.3 Zero-authority JS realms

Logic that is inherently async or awkward as a *synchronous* WASM module runs as confined JS in a QuickJS-compiled-to-WASM realm (`host/safe-js.ts`, `./safe-js`). A fresh realm has only the ECMAScript intrinsics — it cannot even *name* `fs`/`net`/`process`/`fetch` — and reaches out only through the injected `host.call` seam. Every name answers a Promise: host transforms may compute inline, while `fs/*`, cross-realm calls and bare module names round-trip. So the guest is ordinary async/await JS, a fan-out is `Promise.all`, and there is **one** realm — a single non-Asyncify build — serving both roles.

**And one way in.** `realm.call(entry, bytes)` is the whole seam, for the initiator and the holder alike. A synchronous second seam is not available to be offered: a holder answers from local storage, and storage cannot answer in the same turn on a target whose backend is asynchronous (§12.1). Both roles are therefore ordinary async entrypoints, and there is one shape to reason about rather than two whose difference is a property of what the guest happens to call.

**Invocations are serialized per realm** (`host/realm-queue.ts`): one entrypoint runs to completion before the next begins, so no two guest frames are ever in flight in one realm and neither can observe the other's half-updated state at an `await`. Re-entrancy is what makes that guarantee necessary rather than free — the alternative is two frames resuming into each other at every await point, in an order neither the author nor the host chose, which a guest keeping state across an await has no way to reason about. The cost is head-of-line blocking: an initiator parked on a network round trip delays an inbound request to the same app rather than being answered around. That is the trade, and an app that genuinely wants both at once wants two realms, which the shell can give it, rather than one realm with two frames inside it. The queue is shared TS on both targets, because a guarantee that held on one and not the other would be a guarantee nobody has.

This is the chat shell's sandboxed-iframe confinement (§11) generalised: "run zero-authority guest JS over a cap seam," the sibling of "run a WASM module under caps."

**Bounded, not merely confined.** Zero authority answers "what can this guest reach"; it says nothing about "how much of this node can it consume". Four bounds answer that, and each defaults to a real number so a shell that configures none still gets a bounded guest:

- **Heap** — the realm's QuickJS runtime is capped (64 MiB default, `realmMemoryBytes` / `--guest-memory`). A runaway allocation fails inside the realm instead of taking the host's memory.
- **Execution time** — a budget per entrypoint invocation (5s default, `guestDeadlineMs` / `--guest-timeout`, §16.1), enforced on both targets by a QuickJS interrupt handler, so an overrun throws inside the guest and costs one invocation rather than the realm (§14). A realm with no budget installs no handler and pays nothing for the guard. It covers every path guest code runs on — source evaluation during installation, the entrypoint, a continuation resumed after a host seam settles, and one the event loop pumps directly (a plain `await`), which is the one that would otherwise let a guest buy an unbounded loop for the price of a single `await`. It measures the time the guest is **running**, not wall clock: the budget is suspended whenever the guest is parked awaiting a host seam and resumed when its continuation runs. That split is what lets one number serve both roles — an initiator legitimately spends seconds parked on a network round trip without spending any budget, while a holder that loops forever burns it in a single segment. There is no nested-budget case, because serialization leaves exactly one budget window open at a time.

- **Live timers and their bodies** — one realm may hold at most 1,024 deadlines (`DEFAULT_MAX_LIVE_TIMERS`) and 4 MiB of copied opaque timer bodies (`DEFAULT_MAX_TIMER_PAYLOAD_BYTES`). A guest has no `setTimeout` of its own, so every armed deadline and body is **host-side** state. Re-arm is transactional; clear, fire, and realm disposal release body accounting before anything can re-enter the realm.
- **Outstanding host calls** — at most 256 unresolved calls per realm (`DEFAULT_MAX_OUTSTANDING_HOST_CALLS`). The check runs before the payload copy crosses out of QuickJS, so a fire-and-forget loop cannot multiply host-side buffers and promises outside the confined heap.

**`Shell.close()` waits for in-flight calls.** Every entry into a slot's guest (`dispatch` or a handle's `invoke`) is chained onto one wait (`inFlight` in `shell-core.ts`), and `close()` defers realm disposal until that wait settles. A call parked mid-await — a repair pass waiting out an unreachable peer — must not resume into a freed QuickJS context. Uninstall and revoke dispose immediately; a handle held past that rejects by naming the slot rather than calling into a freed realm.

The first two cross every seam between the operator and the realm — CLI flag, `bootNodeShell()`, `bootShell`, `LoadBundleOptions`, `RealmFactory` — because a bound the shell accepts but no target can set is a bound nobody has — one the realm factory takes and nothing upstream carries is dead, since the default applies and nothing can change it. `--guest-timeout 0` reads as "no budget", so disabling one is something an operator says rather than something a missing flag does.

**And both are per slot, not per shell.** `bootShell` takes this node's default; a single `loadBundleBlob` names its own, resolved as *this load's number, else the node's, else the shared one*. The distinction is not decoration: a shell hosts unrelated apps at once — a seedstore node runs the transport bundle and the storage bundle on one — so a shell-wide heap raised for the guest that streams large windows was also the heap handed to the transport sharing the shell, which needs none of it. A budget belongs to the realm it bounds, and a realm is stood per load. A replacement version therefore carries its own rather than inheriting the outgoing realm's, for the same reason its `LOCAL` does (§12.4).

Execution time is the operator's number, not the author's — unlike the module memory ceiling (§4.1), which a bundle declares in its signed manifest. How long *this* node is willing to spend on one message is a property of the deployment, not of the code.

The budget matters most on the holder path, because that runs guest code on the node's only thread in response to an inbound frame (§12.10) — and, with invocations serialized, a wedged holder holds its realm's queue as well as the thread. An interrupted guest throws; the transport already answers a throwing guest with an empty body, so a wedged guest costs one empty response rather than the link. Delivery always targets a guest `handle` (§12.10), so an inbound frame enters under this budget and can never reach a module without crossing the guest first. A module call is a round trip — the guest parks on it — and it is charged to the calling guest's segment literally: its **deadline is the segment's remaining time**, computed at the moment of the call and carried through the seam to the module's worker (the JS targets) or the wazero call's context (the native target). A module that burns its bound is answered empty and killed at the engine — `terminate()` on its worker, mid-loop if it must — so a spinning module costs one empty response and one bounded core, never the thread (§4.3).

### 12.4 Signed bundles

An app is delivered as a **bundle** (`host/bundle.ts`, `./bundle`) — one blob of signed content, holding:

```
manifest.bundle     the signed manifest envelope (below)
<name>.wasm          each WASM module, named by its manifest `name`
guest.js            the app's zero-authority guest program (§12.3)
```

A bundle is a **value, not a path**: one blob is read from disk, carried in an `OFFER` over a data channel, and stashed in browser storage without a second format or a second load path. The container framing is `"SKB1" │ count u16 │ count× (nameLen u16 │ name │ dataLen u32 │ data)`, all big-endian — pure naming, with no security properties of its own: the manifest envelope inside carries the author's signature and its module hashes protect the bytes, so anyone may repack a bundle without weakening it.

**Nothing in the manifest names a file.** A module lives in `<name>.wasm` and the guest in `guest.js`, by construction. A signed filename would be one more field every target must validate (and, where a target resolves it against a directory, one more chance to escape it); deriving it removes the field and the obligation together.

**What a bundle carries.** A load constructs one slot from everything an app is made of:

- **The guest is the app; the modules are its library.** The guest is JS source for a QuickJS realm, not WASM — the loader's path ends in "instantiate WASM, bind," and the guest is what the shell runs. Modules are the pure transforms the guest drives by name; a bundle may declare zero or many of them. Without the manifest the guest would have no signed identity at all.
- **The guest's authority has no other home.** A WASM module is a pure transform with no capabilities of its own (§4.2); the guest, by contrast, *does* reach I/O — through the guest seam — yet is not a module and has no table entry of its own, so the manifest's `guest.requires` is its entire capability declaration.
- **Version coherence.** Module binds are per-name and independent; nothing at the bind level says "codec at hash X, reputation at hash Y, and guest at hash Z together constitute app v1.2." The manifest is the author's signed statement of the coherent set — without it a node can hold a mix of individually-valid module versions that were never meant to run together.
- **Operator/author separation.** The shell is one fixed, auditable artifact; the app arrives as content signed by a third-party key the operator's policy admits. Verification is channel-independent: a bundle read from a USB stick verifies exactly like one fetched from a mirror or pushed over a relay.

**One authenticated statement, one authorization.** The signed manifest commits to the guest and every module hash; `verifyBundle` proves the bytes, and one policy decision authorizes the whole set. The loader then constructs a complete slot offside and commits its claims atomically (§3.1). A live update is the same path with a higher version and replaces the same verified `(author, app)` identity wholesale.

**Manifest envelope.** One suite, `0x02` — hybrid Ed25519 + ML-DSA-65. Fixed-width, JSON to the end:

```
0x02  [suite: 1][ed_pk: 32][ml_dsa_pk: 1952][ed_sig: 64][ml_dsa_sig: 3309][manifest: UTF-8 JSON to end]
```

Both signatures are made over the same preimage — `DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ json`, where `DOMAIN_manifest` is `"seedkernel-manifest-sig-v1\0"` (§16.1), prepended before signing but not stored. The disjoint prefix means a manifest signature can never double as a guest `node/sign` or channel-handshake signature over the same bytes (§14). There is deliberately no canonical-JSON step: the envelope carries the exact signed bytes and the verifier parses exactly what it checked, so the bytes *are* the manifest and canonicalisation has nothing to bite on.

**Both must verify.** Not either: "either" is exactly as strong as the weaker algorithm. Requiring both means a flaw in the young half fails *closed* (valid bundles rejected, an operator's problem, recoverable) rather than open (forged bundles admitted, which is not), and the bundle stays no weaker than a classical-only signature against a classical attacker while ML-DSA is new. The cost is envelope size — ~5.3 KB of header against 97 bytes — paid once per install, off the message path entirely (§13), which is why the manifest is the cheapest place in the system to absorb it.

`suite` names the signature algorithm, and an id this host does not implement is refused with its own error rather than reported as a bad signature, since "this bundle wants a host I am not" and "someone tampered with this bundle" are different problems for an operator. Unlike the domain prefix the byte is **stored as well as signed**, and that pairing is the whole design: a verifier must read it *before* verifying, because another suite's keys and signatures are other widths, so it has to be legible up front — and because the signature it then checks commits to the same byte, an attacker who rewrites it only invalidates the manifest. A signature is therefore bound to the suite it was made under, and algorithm confusion with a later suite is unrepresentable rather than merely unlikely (§14.1). This is the same discipline the channel suite byte follows (§12.6), on the axis that migrates independently.

**`0x01` is retired, not deprecated.** The genesis suite was an Ed25519-only envelope, `[suite 1][ed_pk 32][ed_sig 64][json]`, and it is gone from the runtime: every target ships the PQ verifier, every artifact is built hybrid, and there were no deployed `0x01` authors to migrate. A second live suite would have cost a second envelope branch, a second author-id rule, and a policy dial whose only purpose was eventually switching the first one off — machinery for a migration nobody is on. An envelope opening `0x01` is now refused as exactly what it is: a suite this host does not implement. The **byte** stays spent (§14.1) — a later suite takes `0x03` — which is the format extensibility the suite-first parse exists for, and all that survives of the pair.

Both public keys are inside both preimages, so the pair cannot be taken apart: an attacker who holds a forgery for one algorithm cannot keep the sound half's key and signature and splice its own key in beside them — the surviving signature no longer verifies over the new key set.

**Where the primitive comes from.** One freestanding wasm module (`browser/mldsa65.wasm`, built from the pinned `pq/mldsa-native` submodule by `scripts/build-mldsa.mjs`), fetched by the browser, read by Node and instantiated under wazero by the Go loader — the same arrangement Ed25519 has through libsodium.wasm, and for the same reason: a bundle one node admits, every node must admit, so the verifier is compiled once and shared rather than reimplemented per target. The module has no imports at all (randomness and the FIPS 204 context are arguments), so there is no per-target host glue that could differ. `bundle.ts` names only the method `ml_dsa65_verify_detached` on the crypto object; a host that supplies none refuses `0x02` rather than falling back.

**The author id is derived, not carried.** It is `genesisHash(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖ ml_dsa_pk)` — 32 bytes, like an Ed25519 key, so `appKeyFor` and every app key (§5.1), every policy entry and every freshness mark are written against one fixed-width identity. One suite means one derivation: nothing downstream has to ask which rule produced the 32 bytes it holds. Two reasons it is the hash and not simply the Ed25519 key:

- **Otherwise hybrid signing buys nothing at the moment it should pay.** An attacker who eventually breaks Ed25519 forges that half and generates a *fresh* ML-DSA key for the other. Both signatures verify; if the id were the Ed25519 key, the id would be unchanged, and the forged bundle would land on the real author's names. Hashing the whole key set makes the identity unreachable without both private keys — which is the property "hybrid" is supposed to name.
- **The id's width is load-bearing far outside the envelope.** A suite that widened it would change name derivation, the policy file format, and the freshness key at once.

A later suite deriving its id the same way would face the same consequence — an author moving to it would get a **new identity**: new app keys, a fresh freshness lineage, a new policy entry. That is the honest reading rather than a wart, since a manifest signed under a different suite is a *different* statement about who signed. It is also why each multi-key suite writes its own derivation rather than parameterising this one: its key set is a different shape, so there is nothing to share but the mistake of deriving two identities the same way.

**One seed is the whole author.** `hybridAuthorKeysFromSeed` derives the Ed25519 half from a 32-byte seed directly and the ML-DSA-65 half from `genesisHash(seed ‖ AUTHOR_MLDSA_SEED_LABEL)` (§16.1). The label is a KDF tag, not a signing prefix (no trailing NUL), and it is **frozen**: changing it re-identifies every author built from a seed. The function lives in the offline-only `bundle-author.ts` rather than in each build script because a copy that drifts fails as a *changed author id* — a bundle landing under a stranger's name and a policy pin matching nobody, which no test catches because each copy agrees with itself. Pass the 32-byte seed, not libsodium's 64-byte secret key.

**Manifest fields.**

| Field | Type | Enforced? | Meaning |
| --- | --- | --- | --- |
| `app` | string | **yes** | Names the coherent set. With `author_pk` it forms the host-internal identity `"<author hex>:<app>"` used for freshness, revocation, scope derivation, audit output, and explicit operator selection. Claims route directly to the complete slot, and modules are private to it (§3). Non-empty; free to contain `:`, since the fixed-length author prefix keeps the identity unambiguous. |
| `version` | integer | **yes** | Monotonic version of the coherent set. A load whose `version` is below the persisted `(author, app)` high-water mark is refused as a downgrade, the transport included (see freshness below). |
| `modules[]` | `{name, hash}` | yes | One entry per private WASM transform. `name` is both its container file (`<name>.wasm`) and the bare name this slot's guest passes to `host.call`; there is no bind name or global namespace. Unique within a manifest and restricted to `[A-Za-z0-9_-]`. `hash` is `genesisHash(wasm)` hex and `verifyBundle` proves the bytes match before construction. Freely zero-to-many; a guest-only app declares none. A module cannot call another module, so composition remains the guest's job (§4.2). |
| `protocols[]` | string[] | yes | The wire protocol ids this app serves (§12.10) — the names a PEER may reach — and the whole of PUBLIC routing: load assigns them to the completed slot and uninstall releases them. **Optional:** an initiator-only app claims nothing, and an absent list says exactly that. |
| `services[]` | string[] | yes | The local service ids this app serves (§12.10) — the names a CO-RESIDENT guest may reach with `host.call`, never a peer. Same charset and uniqueness rules as `protocols[]`, and disjoint from it: a name in both would be ambiguous about which reach it grants, and is refused as malformed. **Optional:** the common case for an app that serves nothing locally. |
| *(both `protocols[]` and `services[]`)* | | | Together, one **claims** vocabulary: unique ACTIVE names across both lists combined, so a different identity cannot shadow an owner in either, while an update atomically replaces its own slot and whole claim set. A claim grants nothing — which list it sits in decides reach, not any leading character; no spelling is reserved to the kernel. |
| `guest` | `{hash, requires, config?}` | **yes** | **Required** — the zero-authority guest program and **everything about it**. Every app is a guest; a manifest without one is refused at load. The format states "this bundle holds no authority" as an **empty `requires` list** — a shape, rather than a rule prose has to state and every target has to honour. |
| `guest.hash` | string | yes | `genesisHash(utf8(source))` hex of `guest.js`. |
| `guest.config` | JSON object | shape only | The app author's signed configuration, injected unchanged as `const APP`. Its schema belongs entirely to that app and is opaque to the runtime; the one shape the runtime insists on is an **object**, since a guest reads config by name and a signed scalar would leave every `APP.x` silently `undefined` rather than fail the load. Absent ≡ `{}`. Facts the runtime already derives do **not** belong here — the runtime's own facts reach the guest through the seam (`node/identity`, the slot scope `node/sign`/`node/verify` apply), never as restated config (see below). |

**Why there is no `guest.abi`.** The seam used to carry a version word, because a name read without `await` on the sync side of the line was a silent wrong answer. Every name answers a Promise now — there is no line left to version.

**Why `requires` and `config` live inside `guest`.** Both are the guest's alone: `requires` is the guest's entire authority (§12.2) and `config` only ever becomes its injected `APP`. WASM modules carry no authority and read no config, so the two fields have no meaning at the top level — nesting groups the app's authority with the app's program, and "no authority ⇒ empty `requires`" is the schema's shape rather than a rule prose has to state and every target has to honour.

**Load algorithm** (`loadBundleBlob`). The shell is host code, so failures here **throw to the operator** — §3's "an unbound name resolves to an empty response" is about resolving a name, not about loading a local file.

The load has three phases: `verifyBundle` (authenticity + integrity), `admit` (governance — §12.5), and construction plus one atomic slot commit. A single predicate answers: "may this verified bundle land on this host?"

*verify* — pure, nothing lands:

1. Unpack the blob, read `manifest.bundle`, and verify the envelope signature. Invalid ⇒ reject.
2. Read each module's `<name>.wasm` and `guest.js`. A missing file ⇒ reject.

*admit* — governance, the one predicate:

3. Read the **admission context** off the freshness store — the privileges this bundle reaches (none, or `link`, from `guest.requires`), the persisted `(author_pk, app)` high-water mark (absent ⇒ −∞), and whether the author key is written off (§12.5) — then call the admission predicate once: `admit(v: VerifiedBundle, ctx: AdmissionContext) → bool | Promise<bool>`. Return `true` to admit, `false` to reject, or throw to reject with a reason. Everything a gate needs arrives in `ctx`, so the predicate is a pure function of the two and the shell reads no store on its behalf mid-decision. The predicate IS the policy (§12.5) — a file-backed author allowlist, an interactive consent dialog, or "the bundle my operator handed me" are three constructors of it, composed with the host's own two (`notRevoked`, `freshVersion`). Deny-all stays the default: the absent predicate admits nothing.

*construct and commit* — mechanics, then one effect:

4. Nothing is re-asked. Revocation and the version floor were answered in step 3 and the store is now only written: the `(author_pk, app)` mark advances at the *end* of a fully successful load (see freshness below). Equal versions reload (an ordinary reboot); the mark is monotonic and never rewound, so once version N loads, nothing older ever loads again on this node. The transport is keyed the same as any other bundle.
5. Integrity-check **everything** before construction: each module against its `hash`, and the guest against `guest.hash`. A mismatch rejects without touching the running slot.
6. Build every private pure module off to the side, reading its declared memory limits before instantiation and validating the §4 exports. If any fails, release the accumulated instances.
7. Derive `fsScope` and `signingScope`, then stand the realm over a seam restricted to `guest.requires` and wired directly to those private modules. The preamble receives the signed `guest.config` unchanged as `APP` and this load's optional, unsigned local JSON as `LOCAL`. A guest that does not compile rejects the candidate. Until step 8 commits, the seam refuses irreversible names (`fs/put`, `fs/delete`, and this realm's own declared local service ids) so disposing the candidate is a real undo (§3.1).
8. Persist the freshness mark for the version that successfully ran, then synchronously replace this identity in the installed slots and reproject every protocol claim directly to its slot. Only after that commit is the previous slot disposed. A failed mark write discards the candidate and leaves the running version unchanged.

**Splitting verify from construction is what makes consent possible.** An interactive shell can show a bundle's author and metadata and wait before any realm or module instance exists. The single `admit` predicate sits between `verifyBundle` and slot construction: one predicate, one answer.

**Nothing the runtime derives is injected; it is reached through the seam.** `APP` and `LOCAL` carry only values explicitly supplied by the bundle author and this installation respectively. Every runtime fact an app might want is served by a host call — its identity by `node/identity`, its signing namespace by `node/sign` and `node/verify`, which apply the slot-derived scope for it. An author who baked the scope into `APP` would be restating a load-time fact at build time, and a copy that silently disagrees fails as signatures that verify nowhere with nothing naming the cause — the same one-file rule the `DOMAIN_*` family follows (§16.1). Signing and verification happen under the runtime's own derivation, which neither config value can touch.

**Module scoping is structural.** A slot captures one private module set and hands only that value to its guest seam. The guest calls a logical name such as `"codec"`; no app key is supplied or looked up, and there is no wider namespace it could escape into. These calls need no grant because the modules are code from the same verified bundle (§12.1).

**Admission is a step inside the loader, not a separate component.** The loader hands the target every verified module in one `build` call (§3.1). There is no per-module callback or outcome: trusting an author means trusting the complete set they signed, and the set either becomes a slot or is released.

**The policy needs no ownership state.** Identity comes from the verified `(author, app)` and a claim points to the resulting slot. The policy is a pure function of the bundle and admission context; module ownership cannot drift because modules never exist outside their slot.

**One authentication, one authorization.** The manifest signature authenticates and integrity-checks the *set* (verifyBundle); the content-hash check binds each module's bytes to the manifest's commitment; the admission predicate (§12.5) authorizes the *bundle* — one predicate, one answer, between verify and install. Every module the manifest declares is authorized by construction — the author signed its hash, and the hash matched the bytes. The manifest is the single authenticated statement, the predicate the single authorization decision.

**App configuration has two named provenances and one-app scope.** `APP` is exactly the signed `guest.config`; the host never merges into it. `LOCAL` starts with the optional JSON object supplied to this particular `loadBundleBlob(blob, { localConfig })` call. For a slot reaching `link`, the shell adds that node's one-time transport facts before standing the realm; those host-owned keys override same-named load values. The object is not retained on the shell and cannot reach another bundle loaded beside this one. Both `APP` and `LOCAL` are objects and both are always defined (absent ≡ `{}`), so a guest guards keys, never the binding. An ordinary app that supports installation-local tuning validates and combines the two objects itself, in guest code its own author signed. Realm memory, execution deadlines and admission remain outside both; transport limits are node facts in the link occupant's `LOCAL` only.

**Bundle freshness.** `version` is an enforced monotonic non-negative safe integer, not a label: `freshVersion` (step 3) refuses any bundle whose `version` is below the persisted `(author, app)` high-water mark, so an older signed bundle — a stale relay copy, or a confused provisioning step handing over yesterday's build — is rejected as a downgrade. The whole bundle loads wholesale every boot, and neither guest nor modules carries a per-item version, so `version` is the single downgrade guard for the set. The mark is host-local persisted state; a deliberate rollback is an out-of-band operator action (the operator is the TCB, §14). The store file is `{ "marks": { "<author hex>:<app>": version }, "revoked": [ "<author hex>" ] }`; a file written before revocation existed held the bare marks map and is **refused with a migration message** rather than read leniently, since parsing it as "no marks" would drop every downgrade guard on the first boot after an upgrade and say nothing. Only a genuine missing file is first boot: malformed JSON, missing or wrong-shaped guard fields, invalid identities or versions, and read errors all fail closed. Unknown top-level keys remain the lenient case precisely because ignoring one discards no guard that was ever earned.

**The transport is keyed no differently.** Versions are an author's own lineage, so the bundle standing as the node's transport carries the same `(author, app)` mark as any other and there is no second floor keyed to the slot. One would cost what it bought: every author of a transport would share a single version line with no owner, and replacing A's v5 with B's transport would require B to number above a sequence B does not control. What it would buy is a refusal in one case — a policy trusting authors A and B for the transport, where A's v5 has landed and B's stale v1 is offered — and that case needs someone other than the operator choosing which signed bundle arrives. Nothing does: a bundle reaches the shell embedded in the host artifact or from a file the operator names, never off the wire (§12.4). The answer to two trusted authors is therefore to trust **one author as the transport at a time** (§12.5), which is the right posture for an authority grant regardless. What `version` cannot express is that the signing key changed hands — see revocation (§12.5) and §14.

### 12.5 The admission policy

Admission (§12.4) asks exactly one question — *may this author's signed bundle land here?* — and **one predicate** answers it, in one call, between `verifyBundle` and slot construction. `admit(v: VerifiedBundle, ctx: AdmissionContext) → bool | Promise<bool>` receives the privileges, high-water mark, and revocation state a gate needs, so the predicate is pure and gate order is a fact of composition. There is no "policy said yes but freshness said no" interleaving: there is one answer.

Three constructors cover three deployment postures, and each builds a predicate for either class:

- **authorAllowlist(authors)** — a closed set of hex author ids parsed from `--policy <allowed-keys.json>`. Trusting an author means trusting every module and guest their manifest declares — the manifest's `modules[].hash` commits to exactly which bytes are authorized, and `verifyBundle` already proved the bytes match.
- An **interactive consent dialog** — the browser shell's posture: `verifyBundle` reveals the author and manifest to the user, and the predicate returns `true` only once the user says yes.
- **admitAll** — "the bundle my operator handed me IS the trust decision." A StorageNode loads exactly the one bundle it was configured with; the choice of bundle already settled admission.

All three are the SAME type — one seam, not three mechanisms layered on top of each other. There is no signature-suite axis beside them: with one manifest suite (§12.4), "can this host check how a bundle was signed" and "will this deployment trust how it was signed" are the same question, and the verifier answers it before any predicate runs.

**Everything else is a combinator over that one type.** `allOf` / `anyOf` are the boolean ones; `byPrivilege({ base, grants })` answers on `ctx.privileges` — `base` for a bundle that reaches none, and every named grant for one that does; `notRevoked` and `freshVersion` are the host's own two, reading the bundle and `ctx` and *throwing* rather than returning `false`, so a refusal keeps its reason without a result type. The runtime holds one function and calls it once — nothing composed here is a second gate at a second point.

**The host's two are composed by the shell, not by the operator.** The shell wraps whatever predicate it is given as `allOf(hostGates, admit)`, where `hostGates` is `allOf(notRevoked, freshVersion)` — in that order. Revocation first, because a written-off key must never reach an interactive consent dialog: showing a user the author and metadata of a bundle this host has already decided to refuse, taking their approval, and only then failing is the wrong order to ask in. Then the downgrade guard. And composed by the shell rather than by configuration because they are invariants rather than posture: an operator running `admitAll` — the "the bundle my operator handed me" posture — must not thereby be running without a downgrade guard, and a bundle arriving in an `OFFER` (§11) is the path that most needs one. Every target gets both from the same place, on the same path.

**Every pure question about a bundle is a gate, and each gate sits where its question is decided.** Claim spellings are checked only for shape and uniqueness; none carries privilege. Privileges come solely from declared SERVICE names in signed `guest.requires`, and admission decides whether the operator grants each one. In particular, `link` derives the `link` privilege; inbound attributed delivery is that slot's return convention and requires no privilege of its own. Admission's own host gates (`notRevoked`, `freshVersion`) are composed around the operator predicate. A rule that refuses a bundle from outside that predicate would be a second decision point, and a second decision point is where "nothing has landed until the predicate says yes" stops being a property of the type and becomes a property of how carefully the load path is read.

**Contests are not gates, and that is why they sit elsewhere.** Whether a claim is free, and whether the raw-link binding is, are questions about the NODE rather than about the bundle — the same manifest is admissible on a node where nothing holds them — so they are answered in the load's own commit window (§12.10) rather than in the predicate. The distinction is what keeps the predicate pure: a gate reads `(bundle, context)` and nothing else, and a contest reads what is currently standing.

**Trust is keyed on the CAPABILITY, not on a kind of bundle.** Admitting an ordinary app risks that app; granting `link` risks the channel, which sees all plaintext and holds the session keys. Those are different decisions, and `grants.link` is where the second one is made — which is what stops "I trust this author's chat app" from silently becoming "I trust this author to be my transport". The grant is a **veto over the transport blob the node booted**, not an appointment: reaching `link` also requires clearing the node's transport author pin, derived from that blob by the assembly (§12.9), so both must name the same author and a policy edit alone cannot hand the network to someone else. It is the same bar §12.10 draws for an *observing* guest: a capability grant held apart from "which chat app do I want". The keys of `grants` are the host's `PRIVILEGES` (`core/domains.ts`), derived from the service catalog, so the next service too dangerous to hand out freely becomes an operator grant by appearing there under a new name — no third class, no second vocabulary, and a misspelled grant fails the boot instead of leaving a node that looks configured and holds nothing. It is a `byPrivilege` combinator rather than predicates the runtime holds separately, so there is no way to reach the wrong one: the capability set is an *argument* to the single predicate, derived by the shell before it asks.

**Which privileges a bundle must be granted is read off `guest.requires`, and nothing else.** There is no `role` field — the privileges are exactly the ones its declared SERVICE names carry in the catalog (§12.2), which the manifest signature already covers and the verifier has already checked, so restating them as a self-description would only be a second place for the same fact to live. It stays one install path (`loadBundleBlob`, §12.4) because the derivation is safe in the only direction it can be pushed: adding `link` to a manifest puts `link` in the set, never takes it out. An author already trusted for apps therefore gains nothing by adding the `link` service — they move themselves under a grant they do not hold. There is no partial claim to worry about: a privilege is one thing, so declaring the single `link` service is the whole of it and nothing that reaches the privilege can fall through to the unprivileged base. `admitAll` is the exception and stays permissive everywhere: it is one blob an operator named, and naming a blob is a decision about that blob whatever it declares.

The policy file (when present) is `--policy <allowed-keys.json>` (`host/policy.ts`), parsed strictly — a malformed file, or one carrying a key the host does not know, fails the boot loudly rather than silently widening trust or quietly deciding nothing:

```json
{
  "authors": ["<author id, hex>", "…"],
  "grants": {
    "link": ["<author id, hex>"]
  }
}
```

The transport bundle reaches `link` — and only `link` — holding the sockets being the same fact as delivering what it decodes off them, so a policy has one grant to get right. A node whose policy grants none says so at the boot (`no transport: the policy does not grant this bundle the "link" privilege`) and then runs with no network.

| Field | Required | Semantics |
| --- | --- | --- |
| `authors` | at least one of `authors` / `grants` | The closed set of author ids that may sign the bundle manifest of an app reaching no privilege (§12.4 step 2) — the derived key-set id (§12.4), 32 bytes. Trusting an author means trusting every module and guest their manifest declares — the manifest's `modules[].hash` commits to exactly which bytes are authorized, and `verifyBundle` already proved the bytes match before the predicate runs. |
| `grants` | at least one of `authors` / `grants` | Who may hold each **privilege**, keyed on the privilege itself. The keys are the host's `PRIVILEGES` (derived from `HOST_SERVICES`, `core/domains.ts`); a key that names none is refused at the boot, so an operator cannot misspell a grant into a node that holds nothing. There is exactly one, a deliberate decision apart from `authors` and never app code: `link`, the raw links the node's transport is built out of — the holder carries the node's whole network, signs the channel AUTH (§12.2), and is the one that attributes and delivers what those links carry, so a second grant would only restate the first. A bundle reaching the privilege must be admitted by the grant AND by the node's transport author pin as well (§12.9), and is not judged by `authors` at all; one reaching none is judged by `authors` alone. A policy may name either side without the other; one naming neither is refused at the boot. |

There is no per-module allowlist: the manifest IS the definitive list of authorized modules. An author who signs a manifest with five modules is authorizing all five. If an operator wants only some of an author's modules, the author publishes a separate bundle.

**Omitting `--policy` is deny-all, not "no policy".** A node with no configured predicate runs `denyAll`: it boots, serves, and refuses every manifest. Trust is something an operator adds deliberately; the absence of a decision is never permission. One shared constant (`denyAll`) resolves this, so every target — the Node shell and the native loader (§12.9) — boots the same posture, with no permissive default of its own.

**Revocation is host-side, and it is one action.** A module is a pure transform with no imports (§4.2), so nothing in the sandbox can reach the loader — there is no revoke-message, and revocation is not something a bundle can carry.

What it answers is the case freshness cannot. `version` orders an author's own releases; it says nothing about whether the key is still theirs. A **stolen author key** clears the freshness guard trivially — the thief signs `version + 1` — and lands on the same names, because the same key derives them (§5.1). Every release after the theft is, to the loader, an ordinary upgrade.

So the store that holds the freshness marks also holds a set of **written-off author keys**, read into `ctx.revoked` and answered by `notRevoked` before the version: a revoked key's bundles are refused whatever they contain and whatever version they claim. `shell.revoke(authorHex)` does both halves in one call — record the key, then uninstall every app it already landed, found by the author half of the app key (§5.1). Both the Node shell and the native loader (§12.9) expose it as `--revoke <hex,…>`, alongside `--uninstall <appKey,…>` for the narrower case; a shell embedding the core calls the method.

**Both halves, or neither.** Uninstalling alone leaves nothing to stop the thief's next bundle re-landing on the same names; recording alone leaves the compromised code running. Neither implies the other, and an operator performing them by hand — edit `allowed-keys.json`, call uninstall — can do one and not the other, or do them in the order that leaves a window. That, rather than the absence of a certificate format, was the gap.

**It is deliberately not a protocol.** No signed certificate, no wire format, nothing to distribute — a revocation is a local decision by the operator, who is the TCB (§14), recorded in local state. A fleet applies it the way it applies any other operator decision: by whatever configuration path already reaches those nodes. Building a signed, relayable revocation object would mean deciding who may sign one, which is a second trust set and a second key-management problem to solve the first — worth it for a public deployment admitting third-party authors, and out of scope here.

**The check is composed by the shell, not supplied by the operator.** It is a predicate like any other — `notRevoked`, reading `ctx.revoked` — but it is the shell that ANDs it in front of whatever the operator configured, so no posture can be a way to lose it: `admitAll` is still revocation-checked, and so is an interactive dialog that always says yes. One composition, in the shared core, holds for every target and every delivery path.

**Recovery is a new key, not an un-revoke.** The runtime never removes a key from the set: it survives a later edit that puts the key back in `authors`, so re-admitting a compromised author takes more than forgetting why it was removed. It survives reboots wherever the store does — the Node shell and the native loader persist it through the same atomic write as the freshness marks; the browser chat-shell holds both in memory, so there, as with freshness, a revocation lasts only as long as the page. An author who lost a key republishes under a new one, which derives its own names and its own freshness mark and is unaffected by the dead key's state. Genuinely undoing a revocation means editing the store file out of band — the same escape hatch as rolling a freshness mark back, and the same reason it exists.

**Scope.** The set is keyed by author, not by `(author, app)` or by version range. A key is compromised or it is not; "this key was good through v6" would invite rolling back to v6 under a key the operator has just decided to stop trusting. The remedy for a merely *bad release* is the ordinary path below — a higher `version` from the same author.

**The emergency path is the ordinary path.** There is no "replace this module directly" seam, and its absence is deliberate. If a bug is found in a module, the fix is a signed bundle at a higher `version` from the same author, admitted under the policy above — the same act on a running node as on a booting one, exercised on every release rather than held in reserve for the day it is needed. A dedicated emergency seam would be a second way to occupy a slot, reachable only in a crisis and therefore least tested exactly when it matters most; and it would be the one entry in the table with no signature behind it, sitting at a name it could not have derived, so nothing could afterward say who authored what runs there. An operator's emergency powers are the powers they use daily: sign a bundle, load it. The narrow case this forecloses — a module so broken the node cannot reach the point of loading a bundle — is a boot-path failure, answered by the operator's control of what the node boots with (a different bundle on disk, a rollback), not by an in-process seam whose own code path would have to survive whatever broke the first.

The *guest's* §12.2 requires are **not** gated by this file — they come from the signed manifest, bounded by which bundle the operator chose to run (`--bundle`). No per-author gate is needed because the one dangerous power — raw node-identity signing — isn't grantable at all: a guest's `node/sign` is confined to its app scope (§12.2, §14), and the rest (`fs`, `net`, hashing, …) are ordinary app powers.

### 12.6 Node↔node transport: channel identity binding

**Everything in this section is the transport bundle's guest program** (`transport/src/*.js`, §1) — the handshake, the record layer, the link router and the request/response frame codec — not host code. It reaches sockets through the `link` service and is reached through the local service id it declares under `services` (§12.10), and the host side of that is one driver, `host/transport-host.ts`, which owns the channels by the link id it mints, the address book and the listeners, and knows no protocol. It holds no correlation table, no peer set and no request facade: those were the host standing between two guests, and they now live in the one heap that can see a link. Its deadlines are not its own: `timer` is an ordinary service, so the transport arms them through the same per-realm timer table any app reaches (§12.3). What follows is therefore *content*: replaceable by a second signed bundle loaded the ordinary way (§12.4, §12.5), which is the property the rest of §12.6 exists to make safe. The *first* one is the exception, and cannot be anything else: a node has no network until it has a transport, so there is nothing to fetch one over except raw net to a peer it does not yet trust — which would open a metadata window before any channel exists to close it. It therefore ships inside the host artifact (§10.2), and what travels is the next one.

A real socket carries no trustworthy "from" field, so before a connection delivers frames the bundle runs a mutual challenge/response proving each end holds the private key for the pubkey it claims — the same binding applied to each WebRTC data channel (§11, §12.7). The channel is transport-agnostic over anything that delivers whole messages, and where the platform delivers none the bundle imposes them itself (§12.1): a length prefix over raw TCP node↔node, RFC 6455 over the same socket browser↔node, or a WebRTC `RTCDataChannel` peer↔peer as it comes (`host/net-rtc.ts`, §12.7) — same handshake, same frame plane, only the bottom byte-pipe swaps. Each framer checks its cap against the declared length **before** the body is buffered, so a peer cannot make a node allocate more than one frame; a platform-framed link has no declaration to check, so the delivered message is measured against the same cap on arrival. That cap is `MAX_HANDSHAKE_FRAME_BYTES` until the link authenticates and `MAX_FRAME_BYTES` after (§12.6.2). Every codec caps identically, and the boundaries a platform supplied are not a bound.

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
keys; the same network key is the slot's signing scope, so their AUTH signatures are
disjoint too (§12.6.3).

```
root = H(DOMAIN_channel ‖ network_key)
k1   = KDF(contact,      H(root ‖ suite ‖ eph_i))
h1   = H(root ‖ msg1)
ee   = X25519(eph_i_sk, eph_r) = X25519(eph_r_sk, eph_i)
k2   = KDF(ee ‖ contact, h1)
h2   = H(h1 ‖ msg2)     k3 = KDF(ee ‖ contact, h2)   sig_i = Sign(DOMAIN_channel ‖ root ‖ h2 ‖ id_i)
h3   = H(h2 ‖ msg3)     k4 = KDF(ee ‖ contact, h3)   sig_r = Sign(DOMAIN_channel ‖ root ‖ h3 ‖ id_r)

Sign(m) = Ed25519(DOMAIN_link_scope ‖ network_key ‖ m)   — the prefix is the host's (§12.2)
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

**Each signature commits to its own identity and the whole transcript.** `sig_i` covers the
channel-tagged content `DOMAIN_channel ‖ root ‖ h2 ‖ id_i` under the slot's host-applied
`DOMAIN_link_scope ‖ network_key`, and `h2` chains `DOMAIN_channel`, msg1 and msg2 — hence
the suite, both ephemeral keys and both nonces. So a signature collected on one connection,
even from a node used as a signing oracle, names the wrong exchange elsewhere and fails to
verify; see §14. The identity is committed explicitly because it travels *inside* a
ciphertext rather than in the hashed wire bytes. `DOMAIN_channel` is
`"seedkernel-channel-id-v1\0"` — the transport's own format tag, so a handshake signature
cannot double as another of its formats over the same bytes; the *cross-protocol*
separation is the host's `DOMAIN_link_scope` prefix, which no occupant can reach past. An
outbound dial pins `expectPeerId`: if msg4
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
identity the peer lint declines — does nothing at all and lets the deadline expire. Closing
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
- **Three budgets.** `MAX_HALF_OPEN_UNVERIFIED` (1024) for callers that have not yet produced
  the contact secret, `MAX_HALF_OPEN_VERIFIED` (256) for those that have, and
  `MAX_AUTHED_LINKS` (256) for links that completed the handshake. A link moves up a tier
  the moment its msg1 opens, and again when its identity is proved and admitted — where its
  slot is **held for the link's life**. Releasing it there would bound only who was getting
  in: past the door, anyone able to complete a handshake could hold links without limit.
- **Every budget evicts the oldest; none refuses the newest.** Refusing lets a saturating
  flood turn arriving peers away *at the door*, before they can prove anything — promotion
  cannot rescue a connection that was never accepted. This applies to the verified tier
  too: otherwise anyone holding the contact secret could saturate it and lock members out.
- **`MAX_HALF_OPEN_PER_SOURCE` (8) is not evictable.** One address at its own limit is
  refused outright, never allowed to push a different address out, so saturating the
  unverified budget needs 128 distinct sources. It spans all three tiers, so one address
  gets eight *links*, not eight handshakes and then as many links as it likes.
- **Three deadlines.** `UNVERIFIED_TIMEOUT_MS` (2 s) until msg1 opens, `HANDSHAKE_TIMEOUT_MS`
  (10 s) for the rest, and `LINK_IDLE_TIMEOUT_MS` (5 min) after that — an authenticated link
  carrying no traffic in either direction is retired with the authenticated goodbye, and the
  address book redials on the next send. Observing the second requires the contact secret, so
  the split leaks nothing.
- **`MAX_HANDSHAKE_FRAME_BYTES` (8 KiB) caps inbound reassembly pre-auth**, raised to
  `MAX_FRAME_BYTES` by the bundle's own framer on authentication — both numbers stay the
  host's (`core/net-limits.ts`), supplied in `LOCAL`, and what the occupant chooses is only
  when the transition happens. Applying the full application cap to an unauthenticated peer let a
  stranger reserve megabytes per connection. Hybrid suite `0x03` makes msg1 1,265 bytes
  and msg2 1,168 bytes because it carries an ML-KEM-768 encapsulation key and ciphertext.
  Both remain comfortably below 8 KiB. At that cap against
  the 1,024 unverified budget the bound is 8 MiB, still small, and it decides nothing about
  which suites are expressible.

**Framer reassembly is linear, and there is one parser per link.** A TCP message arrives in arbitrarily small slices. Joining every slice onto one buffer makes a dribbled full-size frame cost a quadratic number of copies; keeping every slice as it arrived costs a view and a pinned chunk buffer per byte, times the half-open budget. The bundle's `ByteParts` (`transport/src/framing.js`) merges slices below 8 KiB into a doubling tail buffer so every byte moves a constant number of times and the live slice count is bounded by bytes/`MERGE_BELOW`. A slice at or above that size is kept as it arrived. The WebSocket framer serializes `push` so two parses never run over one buffer: `frames()` takes a frame before awaiting its decode, so a second parser would read the frame after it, and `raiseCap()` lands only when msg4 is *delivered*, so a second parser would measure a frame riding the same segment against the pre-auth cap and refuse a legitimate link.

**A request deadline is a stall clock** (§16.1 `DEFAULT_REQUEST_DEADLINE_MS`). It re-arms while this request's own bytes are still draining (`flushed < owed` and `flushed` moving); it does not measure peer chatter, and the progress baseline is taken on first expiry rather than at send, because a frame still in the pre-auth pool has no link backlog to subtract.

**Underneath all of them, two bounds the host keeps for itself.** Everything above is content
policy: "half-open", "verified" and "authenticated" are states only the occupant can see, so
the occupant is what enforces them — and the occupant is a replaceable bundle. What the
platform owns is cruder and comes first, since a socket costs a descriptor and a link-table
entry the moment it is accepted, turns before the guest has formed any opinion about it. The
same rule as the frame caps, applied to the two host-side structures a link occupies:

- **`MAX_RAW_LINKS` (4096)** bounds the driver's own link table, on the single path that
  mints a link id — a guest dial, an accepted connection, a host-managed handover. It
  **refuses** rather than evicts, because which link is worth keeping is precisely the
  judgement this layer does not have, and it sits well above the sum of the tiers so an
  honest occupant never meets it. A wedged or hostile one meets it instead of the host's
  memory (`TransportHostOptions.maxRawLinks`; `tests/transport-load.test.mjs`).
- **`MAX_PREOPEN_QUEUE_BYTES` (1 MiB)** bounds what a channel buffers before its socket is
  writable — the queue that exists because the transport emits its first handshake frames
  ahead of `open`, and therefore the memory a connect that never completes gets to spend.
  Crossing it fails the channel rather than trimming the queue: a hole in an ordered stream
  is a link the far end waits on forever, where a dead channel is one the address book
  redials. It is `MAX_QUEUE_BYTES` — the bundle's bound on its own pre-auth buffering —
  pointed at the buffer on the host's side of the seam, at the same size.

#### 12.6.2b One master seed, one identity

A node stores **one** secret: a 32-byte master seed. Its signing keypair is derived from
that seed under a distinct, versioned label (`core/subkeys.ts`) — `channel` — and that
keypair's public half **is** the node's identity: the peer id, what `senderPk` carries, and
what `node/identity` answers on every target. The master signs nothing itself, and
derivation is deterministic, so a node rebuilds its key at boot with nothing extra to
persist. Labels are closed and literal, never built from runtime data.

That one key signs for both purposes, and *what a signature means* is the host's decision
from the asking bundle's slot, not the key's: the link occupant's `node/sign` binds
`DOMAIN_link_scope ‖ network_key`, an ordinary app's `node/sign` binds
`DOMAIN_guest ‖ author ‖ app` (§12.2) — one pair of names whose scope the slot picks by
which slot the asking bundle occupies, so a link slot signs the handshake and its own
app records only if the host scopes it so. Both prefix and never parse, no op signs raw
bytes, and the key itself never enters a realm —
and inside its own scope the transport
tags its `DOMAIN_channel` format itself, so the handshake's shape is bundle content. Why
purposes are separated this way rather than by a second keypair — and what that costs:
[CHANNEL](CHANNEL.md) §7.

#### 12.6.3 The contact secret, the network key, and the peer list

Three values gate a link, answering different questions. Rationale for the scope of each —
and why the contact secret is per node rather than per deployment or per pair — is in
[CHANNEL](CHANNEL.md) §6.

| | Scope | Secret? | Effect |
| --- | --- | --- | --- |
| **Contact secret** | per node | yes | A caller that cannot produce the *receiver's* secret draws no response. Distributed with the node's address, which makes an address a credential. Absent, the node is open and answers anyone — a DoS and caller-privacy posture, not an identity leak. |
| **Network key** | per deployment | **no, public by design** | Which network this node belongs to. Nodes on different network keys cannot link under any circumstances. An isolation boundary — staging cannot reach production — not access control. |
| **`admitPeers`** | per node | n/a | Optional peer list, empty by default — a LINT the occupant applies, shipped to it in `LOCAL`. Consulted only on an identity whose signature has verified (§6.3, CHANNEL). |

The contact secret is mixed at msg1 together with the initiator's ephemeral, and into every
later key. The network key is applied as a prologue: it seeds the transcript root, so every
derived key *and* every signature preimage differs between networks and a cross-network
handshake fails at the first message. The peer lint runs inside the handshake, at msg3
when accepting and msg4 when dialing — before this end has revealed anything, refusing by
silence (§12.6.2). It is the occupant's, applied from the list the host ships it at init.

**It is a lint and not a gate, and calling it one was the correction.** The host used to
hold the predicate and run it on the attribution the occupant *reported*, on the argument
that a check a program applies to itself gates nothing against a hostile one. The argument
does not survive contact: the host was checking a key the occupant supplied, so a hostile
occupant would supply one that passes, or forge the attribution with no link at all. What
the check catches is a buggy transport or an unlisted peer, and both are the occupant's
business — so it ships as configuration. What holds against a hostile occupant is what
always did: it reaches no service but `link`.

Revocation is key rotation in each case: a node dropping a peer rotates its contact secret,
a network splitting rotates its network key. There is no separate mechanism, and the peer
list is not one. Because the driver re-reads its contact secret per open, rotation is
lazy: links already authenticated are untouched — a node that rotates therefore also
closes them (`TransportHost.reset()`, the same operation a slot handover arrives at),
which is a platform decision, not the occupant's.

### 12.7 Browser↔console WebRTC

§12.6's channel rides any whole-message pipe, and a WebRTC `RTCDataChannel` is one — which turns WebRTC into a first-class `Network` exposing the same `send` / `peers` surface as the TCP and WebSocket transports.

**`RtcNetwork` (`host/net-rtc.ts`) — relay-signaled mesh.** Peers reach each other directly over `RTCDataChannel`s; the relay (seedchat's `scripts/relay.mjs`) is only the *signaling* rendezvous for SDP/ICE and can be killed once channels are open — no server in the data path. One ordered binary channel per peer carries everything, and the transport bundle's channel stack (§12.6) rides on top — a data channel is handed to the driver through `TransportHost.openLink()`, and the AKE/record/routing state machine runs in the signed bundle's guest exactly as over TCP — so a storage cohort gets P2P for free while a fire-and-forget app (chat) consumes `send` directly. The `Signaling` seam is pluggable — relay, DHT, gossip, or even an existing authenticated link between two connected peers — and carries *no* SDP-fingerprint signature, because identity is proven in-channel: the transport bundle's handshake runs *inside* the data channel (§12.6), stronger than a one-shot SDP-fingerprint assertion at the signaling layer (§11). A MITM relay can splice SDP and bring DTLS up to itself but can never produce the transcript signature without the peer's private key, so the link never authenticates and never delivers a byte. Signaling must also supply the deployment's contact secret, without which a peer draws no response at all. The module is browser-native (it uses the platform `RTCPeerConnection`); a Node/Bun *console* node joins by passing its own `peerConnectionFactory` — "swap the connection, keep the stack," the §12.6 move applied to WebRTC. That factory is the app's, not the runtime's: the seam this file owns is a byte duplex, and an ICE/DTLS/SCTP implementation is one way to produce one, so the runtime declares no dependency on any. A console peer wants a pure-JS library (it bundles into `bun --compile`, where a native binding like `node-datachannel` segfaults) wrapped to the W3C subset used above — seedstore's `scripts/werift-pc.mjs` does exactly that over werift.

**Confidentiality.** Like every transport, the WebRTC fabric's frames are confidential and integrity-protected by the §12.6 AKE record layer. A data channel is also DTLS-encrypted, a redundant-but-harmless second layer underneath. As on the raw transports, the in-channel AUTH supplies the identity binding DTLS alone does not (§11).

### 12.8 The shell

`bootShell(opts)` (`host/shell-core.ts`, `./shell-core`) is the kernel assembly and returns the `Shell` plus its channel adapter. Node's `bootNodeShell(opts)` (`host/shell-node.ts`, `./shell-node`) is a platform adapter over it: it selects Node crypto, `NodeFs`, file-backed freshness and `NodeChannelFactory`, and adds file-path bundle loading. It is convenience for a Node application, not a second assembly. The CLI over it is `host/cli.ts`:

```sh
node build/host/main-node.js --policy ./allowed-keys.json --dir ./data --key ./node.key \
     --listen 0.0.0.0:7000 [--ws-listen 0.0.0.0:7001] \
     --bundle ./app-bundle [--transport ./transport.skb] [--peers <pk>@host:port,…] \
     [--contact-secret ./contact.hex] [--app-config ./app.json] \
      [--revoke <hex,…>] [--uninstall <appKey,…>] [--request-deadline <ms>] \
      [--op name  < argument > response] \
      [--guest-timeout <ms>] [--guest-memory <MiB>]
```

**The CLI is shared code, not a per-target wrapper.** `runCli` (`host/cli.ts`) owns the flag set, the defaults (`--dir ./data`, `--key ./seedkernel.key`), the deny-all reading of an absent `--policy` (§14), the order — remedies, then the bundle, then the one-shots, then serve (§12.5) — and every line printed. A target supplies a `CliHost`: files, one console line, raw stdout, entropy, and "stand a node up on this platform". That is five members, none of which decides anything, and it is the whole difference between running a node on Node and running one from the native binary (§12.9). Argument *tokenizing* is not the point of sharing it — a dozen lines that fail loudly — the flag set and the sequence are, because a decision made twice is one that eventually gets made differently. Unknown flags are refused rather than ignored, which is the failure that used to be silent: a mistyped `--polcy` produced a deny-all node that boots, serves, installs nothing, and looks exactly like a policy doing its job.

`--transport` supplies a signed transport bundle from disk instead of the artifact the build embeds (`TRANSPORT_BUNDLE_B64`) — a node with its own pinned transport author, or a newer protocol than the binary ships (§12.6). `--contact-secret` names a *file* holding 64 hex characters (§12.6.3), never the secret itself: an argument is visible in `ps` output and shell history. `--app-config` requires `--bundle` and supplies that one load's `LOCAL` JSON; it is never node setup and never reaches the transport bundle.

**`--op` names an op the CLI does not know, and that is the whole of its app-facing surface.** One flag rather than one per operation, because an op is a name travelling in `handle`'s payload (§12.2) and the runtime passes it through unread: a storage `put` and a chat `render` are reachable the same way, and neither is spelled anywhere in the kernel. **stdin is the argument and stdout is the response** — `handle`'s ABI exactly, bytes in and bytes out — so nothing here decodes, formats, or knows an app's argument shape. Neither a flag per operation nor a *choice* of argument flag can avoid knowing it, since which one an operator needs is decided by the app; composing bytes is the shell's job. `log` therefore goes to **stderr** on both targets, since an operator line landing in the middle of a response would corrupt a redirect. The op targets the app `--bundle` just loaded through that load's returned handle — not through "the only app", which a node with a network cannot mean, since its transport is an ordinary app too (§12.10).

A serving node that has loaded a bundle serves the app's *request* side from its confined realm: an inbound frame reaches the guest's **one** entrypoint, `handle`, with the authenticated sender prepended (`dispatch` → `realm.call`), and the host drives the app's local logic through the **same** `handle` by a loopback — `AppHandle.invoke(payload)` writes the host's own caller id (32 zero bytes) in front of bytes it never reads, so a peer frame and a host loopback both arrive as `handle([caller 32][body …])`. An app therefore has one op vocabulary rather than two, and it is the app's: everything after the caller is the CALLEE's format, and the kernel's whole inbound vocabulary is that 32-byte attribution prefix. A guest declares `handle` — nothing else is ever invoked. Clients that choose the common named `[opLen u8][op][args]` envelope take it from the leaf `seedkernel-wasm/op-frame` client helper. The shell core never imports or interprets that codec; the CLI's `--op` encoder is an operator convenience built on it. A timer follows the same opacity rule: `timer/arm` stores the caller-supplied body and returns it verbatim on the future host loopback. Both directions may `await`; the realm serializes them (§12.3), and the driver resumes on the promise the app's `handle` returned rather than answering inline — which is what lets an app's inbound handling be asynchronous at all. The shell is application-neutral — it can host any signed app — and for a self-contained non-browser deployment the Go/native target ships it as a single binary (§12.9). seed store's WASM README has a complete storage walkthrough.
### 12.9 The Go/native shell — the primary non-browser deployment

The §12.8 shell runs as JS on Node or Bun, but the **recommended** way to run a node outside the browser is the **Go/native target** (`native/`, a top-level Go module): a single self-contained, cgo-free binary — `seedloader` — with no Node, no Bun, and no separate JS engine to install on the box.

It is a **platform target, not a reimplementation.** All protocol and app logic stays shared TypeScript — the guest seam (§12.2), the transport driver and its socket seams (§12.6 — the protocol itself is not host code at all, but the guest program of a signed bundle), the loader and its admission policy (§12.4–§12.5), bundle verification (§12.4), the confined safe-js guest (§12.3) — the same code the other targets run, just hosted differently. Go supplies only the platform **primitives** the §1 table calls for; protocol is never re-derived in a second language (*Go grows with primitives, never with logic*).

This is enforced mechanically: the shared modules are compiled by `tsc` and assembled into **one** `native/host-shell.gen.js` by `scripts/bundle-loader.mjs` (`npm run build:loader-bundles`), which the loader `//go:embed`s and evaluates in QuickJS. Nothing under `native/` is a hand-written second copy. A single TypeScript adapter (`host/native-shim.ts`) satisfies the same `PureModuleLoader`, `FreshnessStore`, channel, and realm interfaces as JS by forwarding to Go's byte bridge, then hands them to the shared `bootShell`. Typechecking makes a missed target change a compile error. Verification, admission, scope derivation, realm construction, freshness arithmetic, claim replacement, and the deny-all default all remain in the shared modules — one implementation of each to audit.

**The assembly order is shared too, not just the parts.** `bootShell` (`host/shell-core.ts`) is the one way to a `Shell`, and it owns verification, admission, module construction, scope derivation, realm construction, freshness, atomic claim replacement, inbound dispatch, and the transport author pin. Each target supplies only `{ sodium, identity, modules, fs, freshnessStore, networkKey, transport, createRealm }`, and every one of those but the first two has a default. The channel adapter remains platform integration state rather than a `Shell` member; it is wired once to the generic claim lookup. There is no layer beneath the assembly for a target to reach: the pin and the load order are part of standing a node up, not a step a caller may skip. A guest that fails to stand or a freshness mark that fails to persist disposes only the candidate, leaving the running slot intact. Go therefore holds no boot sequence, admission rules, routing model, or operator flow of its own.

Native keeps a Go `map[string]map[string]*boundModule` behind opaque slot handles because wazero modules cannot be JS values. That map is target plumbing behind `PureModuleLoader`, not shell state. Concretely the binary embeds and drives, over [wazero](https://wazero.io):

- **`libsodium.wasm`** — the same core crypto blob as the browser/Node build, which keeps Ed25519 and X25519 byte-identical across targets. Application crypto arrives in application modules instead.
- **a prebuilt QuickJS** (quickjs-ng, `native/qjs`) — so the shared host JS runs unmodified with no native JS-engine dependency. QuickJS is synchronous, so Go owns the event loop (timers, the JS job queue, socket delivery). A round-tripping `host.call` — net or fs — returns a real Promise to the guest: the shell's guest seam starts the work under a call id and, when it settles, the realm's own settle callback resolves the guest's pending Promise, and the shared loop pumps the guest realm so the awaiting entrypoint resumes — the same real-promise seam the Node/Bun build uses, driven by Go's loop instead of quickjs-emscripten's job pump. Go's own `fs` primitive is synchronous (it reads the local disk in the call); the wrap that makes it the async seam the shared code consumes is in `native-shim.ts`, not in Go, because adaptation is logic and Go grows only with primitives. The confined guest runs in a second, zero-authority QuickJS realm whose only seam is `host.call`; because the settle path is per realm, a node hosting two guest apps keeps their seams apart by construction. Both engine blobs — this one and the JS platform's `quickjs/` emscripten build — are compiled from the **same** quickjs-ng v0.16.1 pin (`native/qjs/build-qjs.sh`, `WASM/quickjs/build-quickjs-ng.sh`), so a behavioral difference between targets is a build difference, not a version difference.

`ws.wasm` is a private module of the transport slot, instantiated by the same builder as any other pure module; the codec that drives it runs in the transport guest.

**Native fast paths, and the one rule that licenses them.** A few primitives run as target-native Go rather than through the shared wasm. That is an optimization and must stay one, so it is governed by a single rule rather than re-argued per call site:

> **Where a primitive is standardized, a target may substitute a native implementation, because the bytes are identical and only the speed differs.**

Three conditions make that safe, and a substitution failing *any* of them is a fork, not an optimization:

1. **The primitive is standardized**, so "correct" is defined by a document rather than by whatever the reference implementation happens to do.
2. **The output is byte-identical**, and is *pinned by a known-answer test* against the shared blob's own output — not merely believed to match.
3. **No protocol judgement lives inside it.** A hash or an AEAD seal qualifies. A verifier does not: its accept/reject boundary is consensus (a bundle one node admits, every node must admit), and two conforming implementations can still disagree at the edges on malformed inputs.

Condition 3 is why Ed25519 and ML-DSA-65 stay on the shared wasm on every target (§12.4, §14.1) while BLAKE2b-256 and the ChaCha20-Poly1305 record layer do not: the first two decide whether to *accept* something, the last two only transform bytes. It is the same trade as `ws.wasm` versus a native RFC 6455, and it will come up again for every suite added under §14.1.

Go-native primitives back the capability seams: `os` for the §12.1 fs backend, `net` for the raw TCP socket — one socket kind, carrying node↔node and browser↔node alike, with the codec named per link and run above Go entirely — and `crypto/rand` for entropy. WebRTC (§12.7) stays browser-only. The CLI does not *mirror* §12.8 — it **is** §12.8, the same `runCli` over a Go `CliHost`, so the flag set and every default are the same object rather than two that agree:

```sh
seedloader --policy ./allowed-keys.json --dir ./data --key ./node.key \
     --listen 0.0.0.0:7000 [--ws-listen 0.0.0.0:7001] \
     --bundle ./app-bundle [--app-config ./app.json] [--peers <pk>@host:port,…] \
     [--op name  < argument > response]
```

Go's side of it is five primitives — `argv`, `readFile`, `writeFile`, `log`, `stdout` —
plus `__fs.open`, which is how a data directory reaches the fs backend now that Go does
not read `--dir` to find one. Even the `--key` file is read and minted in the shared
flow: it holds the node's 32-byte master seed (§12.6.2b), and `deriveNodeKeys` produces the
node's keypair from it, so both targets hold one secret on disk and derive the same peer id
from the same seed.

Because the wire and the bundles are shared, a Go node and a Node/Bun node interoperate directly in one cohort — `put` on either, `get` on the other, in both directions, against the same signed bundle and genesis (verified end-to-end for seed store by `WASM/scripts/loader-interop.sh`).

**Scope: the native target is a bundle-runner.** Its app path is the §12.4 bundle — load, verify, install the modules, run the guest — and its request path is transport → shared route bundle → guest seam → the app's guest `handle` entrypoint, which reaches the installed modules by their bare names through `host.call` (§12.2). Both targets install code only from a signed bundle (§12.4), so the app-delivery surface is identical. There is no dispatch loop and no signature pipeline to keep in parity: the table is a two-level name table (§3) and modules are pure transforms (§4), so Go's only module-facing duties are staging input into a module's `scratch`, reading its output, and honoring a declared `scratchSize` (§4.1) — byte-identical to the JS host. The loader's admission and policy (§12.4–§12.5), bundle freshness (§12.4), and the domain prefixes (§16.1) are the same shared TS both targets run in QuickJS; the host-applied prefixes on every signature the loader makes or checks come from that one evaluated `domains.ts`, so every signed preimage is byte-identical across the cohort by construction, not by a hand-copied constant. The channel's own `DOMAIN_channel` format tag is not in that family and does not need to be: it lives inside the transport bundle (`transport/src/ake.js`), which is one signed artifact every node in the cohort runs.

**Size.** One file, ~7.5 MB stripped, cross-compiled to win/linux/mac with `GOOS`/`GOARCH` — nothing to install alongside it. The bulk is wazero's compiler backend (~4 MB) and the Go runtime (~2.4 MB); the protocol's own footprint stays tiny (§10.2). Against the JS shell — which needs a Node/Bun install plus the lazily-loaded ~570 KB QuickJS engine — the native binary trades a larger single artifact for zero external dependencies, the right shape for a server or an appliance.

**Performance.** The Go target drives the same core `libsodium.wasm` under wazero that the JS targets run under V8, while bundle modules—including ML-KEM—use the ordinary bounded module path. The deliberate native fast paths remain host work: BLAKE2b-256 for genesis/content hashing and ChaCha20-Poly1305 for the current record layer. Both are KAT-pinned against the shared implementation. Application transforms such as seed store's XChaCha20 and Reed–Solomon remain application modules rather than native crypto methods. Reproduce with `wsl bash gorun.sh test -run x -bench . -benchmem ./...` from `native/`.

One module-path cost differs by design: on the JS targets every module call round-trips through the module's worker (§4.3), and that hop is a flat ~30 µs (small payload) to ~160 µs (64 KiB transfer both ways) added to a call that runs at full engine speed — the wazero target instead slows the compute itself when the bound is armed, by ~1.1–1.2x (SECURITY §14 has both numbers, and the crossover). Reproduce with `node tests/bench-module-call.mjs` from `WASM/`.

### 12.10 Protocol routing — which app handles a message

Admission (§12.5) decides whether code may run. It does not decide who gets traffic, and after §5.1 it cannot: a node may hold two apps that both serve chat, authored by different keys, landed at names that never collide. Something has to say which one a message goes to.

**A frame names a protocol, not an app.** What travels is a protocol id in the Transport req frame (§12.6) — a chat message carries one, a storage message carries its op. It never names an app, an author, or a module: those are node-local (§5.1), and a wire that named them would make every peer's install choices everyone else's business.

**The manifest declares what the app serves, and the load claims it.** A bundle's manifest carries the protocol id(s) its app answers, signed with everything else in it:

```
manifest: { app: "chat", protocols: ["chat-v1"], guest: {…}, modules: […] }
```

`loadBundleBlob` admits the code *and* claims those ids; uninstall drops them. That is one act because it was always one intent — nothing installs an app it does not mean to serve — and it puts the fact where it is actually known: which protocol an app speaks is the author's, stated once in the thing they sign, not an id retyped at every deployment where a typo's only symptom is a node that boots clean and answers an empty body forever.

```
routing: protocol claim → bundle slot
```

To deliver, the host looks up the complete slot and invokes its guest `handle` with `senderPk ‖ payload`. That is the one delivery shape; a guest needing a transform calls its private module value. An unclaimed protocol is answered empty.

**The claim map is a projection of installed slots.** Every entry comes from a verified manifest's `protocols` and `services` TOGETHER — one owner per name across both lists — and the shell recomputes it on each atomic slot replacement or removal. Nothing persists routing separately.

**Three rules fall out of that projection.** An update uses only its new claims; a later installed slot wins a contested id; uninstall reveals the preceding installed claimant. The displaced slot remains complete and private, merely idle.

**Installing is the whole of taking over a protocol, and it is the operator's act.** Point a second chat app at a node and it takes over `chat-v1`; drop it again and the first one resumes. No uninstall of the incumbent, no name to vacate, and no second command — because the two apps were never competing for a slot, only for the last word. That is the practical payoff of putting the author in the name: succeeding an abandoned app stops requiring cooperation from its author. What makes it safe to fuse into the install is that installing is *already* the trusted act: the policy (§12.5) decided the author may run code on this node, and routing frames to code that is already running is strictly less than that.
**A claim is not authority, which is why a signed one is fine.** A protocol id routes frames a peer already chose to send, to code this host's policy already admitted. It cannot make unadmitted code run, widen a guest's `requires` (§12.2), reach another app's fs scope, or let one app sign in another's namespace. Nothing about integrity or authenticity rests on it, and two nodes disagreeing about a routing are each simply serving what they installed. The worst a wrong claim does is deliver to the wrong app of two the operator chose to install — recoverable by uninstalling one.

**Two claim lists — public protocols vs local services — and the cross-realm call the second carries.** A manifest signs two disjoint lists of names: `protocols`, what a PEER may reach, and `services`, what a CO-RESIDENT guest may reach with `host.call`. Both share one charset — alphanumeric-or-`_` first character, then alphanumerics and `._/-`, at most 64 bytes — and one uniqueness rule spanning BOTH lists together: a name claims under one list or the other, never both, and never twice. Which list a name sits in is a fact the manifest STATES, never a fact its spelling implies — `_net` is a spelling convention this repo's own transport bundle uses for its local service id, not a kernel-known reservation, and a name with no leading `_` claims under `services` exactly as well as one that has it. What the list *does* decide is reach: a `services` claim is reachable by a co-resident guest and by no peer, which is a property of the routing rather than of the name — inbound delivery refuses anything not in the resolved slot's `protocols` (below), and no sender's `requires` could have granted a peer that reach in the first place.

Raw-link ownership is an explicit authority; socket observations and inbound routing are its return conventions. Platform link events target the slot binding that owns `link`, without consulting the claim table. Authentication is returned from the `linkBytes` event that completed it and teardown from the socket's `linkClosed` event; the event supplies the link id, never the occupant's return. The occupant that sees the plaintext is the one that attributes: the same `linkBytes` result carries `(claim, opaque attribution, payload)`, the host routes it through the claim table, and the answer comes back to the occupant for framing — holding the sockets *is* the authority to say which peer a request came from, because nothing else ever held the bytes. A bundle's `services` claim is reachable by no peer and no delivery, because the same shell routing refuses it whether the frame arrived off a link or from a co-resident realm; claiming a local service name authorizes neither.

**The raw-link binding has one owner, like a claim.** The driver has one event sink, so two link-capable slots are not a composition: the second would take the node's sockets off the first while leaving its claims and realm in place — installed, routed, and silently off the network. So a load reaching `link` while another identity holds the binding is *refused*, on the same rule and at the same two points as a contested claim. Replacing the holder is uninstalling it, or shipping the next version of it.

**Dispatch has one owner kind.** The claim map holds only bundle slots — there is no second table and no identity beside a slot that can ever hold a name, so nothing above needed a platform branch. What that would otherwise leave out is an embedder's own view of a peer-inbound answer: the wire consumes a delivery return on its way back out, so an embedder whose own mounted app must paint what it just answered — seedchat's guest relaying its render bytes to the page hosting it — has no other path to those bytes. `LoadBundleOptions.onInbound(claim, sender, answer)` is that one seam: fired once a PEER-inbound frame's answer to THIS load's slot resolves, scoped to the load that named it rather than to the shell, so there is still no table, no owner and no name to contest. It is observation only — the callback cannot change what the caller receives, is never consulted for a host loopback `invoke` or a co-resident guest's cross-realm call (both already hold the return directly), and a throw from it is reported and swallowed rather than reaching the transport driver.

**A guest reaches another realm by the same call, and only a name in ITS OWN declared local services is callable.** `host.call("_service", …)` resolves through this routing, the host prepends the CALLER's 32-byte id, and the answer is what the callee's `handle` returned on a later turn. A callable id is a *grant*, declared in `guest.requires` as a local service id rather than a host service name, so the local call graph remains explicit.

**Replacing the transport is ordinary slot replacement, not a protocol.** The same `(author, app)` loads a complete candidate offside, including its private modules, realm and scopes. Before the realm stands, the shell folds the node's immutable facts — identity, network key, contact secret, limits and admitted-peer lint — into that slot's ordinary `LOCAL` config. After it stands and its freshness mark persists, the shell synchronously replaces that identity's slot, claims, and raw-link binding. The socket driver retains the address book and listeners; only events and raw `link` bytes reach the occupant after installation, and the address book comes as `addr` events replayed after publication. Live links do not survive because their session keys were private to the outgoing realm, so an upgrade reconnects.

**One slot per protocol.** The map holds one complete slot, not a list. Fan-out would be an authority-bearing observer model and requires its own admission semantics; until then a single value is the honest shape.
