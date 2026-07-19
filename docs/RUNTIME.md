# Seed kernel — Runtime

*The runtime as an app host: performance, the chat demo, and the shell — capability backends, the cap-bridge guest ABI, zero-authority JS realms, signed bundles, the node↔node transport, and the Go/native binary.*

> **Part of the [seed kernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · [PROTOCOL](PROTOCOL.md) §2–§5, §16 · [REGISTRY](REGISTRY.md) §7, §9 · **RUNTIME §10–§12** · [SECURITY](SECURITY.md) §13–§14

---

## 10. Performance

The message path does **no asymmetric cryptography and no recursion**: routing a frame to a handler is a name lookup (§3) plus two scratch copies and the transform's own work (§4). The per-message signature verify that used to dominate is gone — authenticity is the channel's (§12.6), established once when the link opens, not checked per message.

### 10.1 Where the crypto is now

So the costs worth measuring are the three places real cryptography lives, all off the dispatch hot path:

- **Per connection:** the AKE handshake (§12.6) — one Ed25519 sign + verify and one X25519 exchange, amortised across the whole session.
- **Per frame:** one ChaCha20-Poly1305 record seal/open (§12.6) — symmetric, fast, the steady-state transport cost.
- **Per bundle load:** one Ed25519 manifest verify plus a SHA-3-256 content hash per module (§12.4) — once, at install.

The Go/native target carries `*_bench_test.go` benchmarks over these hot paths (net round-trip, fs, the crypto primitives, the record layer); `WASM/tests/run.mjs` exercises the same paths end-to-end on the JS target, and seed store's `WASM/tests/bench.mjs` measures storage throughput. There is no signed-message microbenchmark anymore because there is no signed message — a chat frame crosses the WASM boundary only for its handler's single pure-transform call.

### 10.2 Distribution Size

| Component | Size |
|---|---|
| kernel.wasm | ~6 KB |
| host/*.js — minified (`build/host-min`; ~29 KB gzipped) | ~117 KB |
| libsodium.wasm (sumo build: Ed25519 + SHA-3-256, plus the §12.1 BLAKE2b / XChaCha20 backends) | 278 KB |
| libsodium-wrappers.mjs + libsodium-core.mjs | 152 KB |
| **Total browser deployment** | **~553 KB** |
| QuickJS realm engine (the single release-sync build, from `quickjs-emscripten`) — only loaded when a bundle's guest runs (§12.3) | ~750 KB |

The kernel is pure protocol logic — no cryptographic code, no dispatch, no signature layer — at ~6 KB of WASM. The `host/*.js` layer is the runtime around it: it loads the kernel, reaches handlers by name (`callHandler`), holds the module registry (§7), and carries the whole shell (§12) — net, fs, the cap-bridge, safe-js, bundle verification, policy, and the entire node↔node transport stack (§12.6), which now lives in shared JS rather than a per-target reimplementation. That transport is the bulk of why the host is larger than a kernel-only driver would be. libsodium is the host's crypto library (SHA-3-256 for content hashing, Ed25519 for manifests and the handshake, ChaCha20 / BLAKE2b / XChaCha20 for the record layer and the §12.1 backends); the sumo build is larger than a sign-only build because it backs all of them. The QuickJS engine is lazy: a node that only relays and dispatches never pays for it.

`npm run build` emits the host twice: the readable `build/host` (~203 KB, doc comments intact) for debugging and a comment-stripped `build/host-min` (~117 KB, ~29 KB gzipped) for shipping. A small dependency-free stripper (`scripts/minify.mjs`, each output gated through `node --check`) does the cut — no bundler, no new dependencies. The table's host figure is the shipped, minified build.

---

## 11. Example app layer: chat (`chat-shell.html`)

Chat is the simplest possible app: a single **pure-transform** handler (§4) bound at an app name. The handler does no I/O and no crypto — the shell hands it `senderPk ‖ chatType ‖ body` and it returns the render bytes for the UI. Everything around it — authenticating the sender, moving frames, driving the iframe — is the shell's job, because a pure transform has no reach of its own.

`WASM/browser/chat-shell.html` is a runnable end-to-end demo of the whole stack: a browser shell that owns only the kernel, the module registry, a WebRTC transport (`RtcNetwork`, `host/net-rtc.ts`, §12.7), and a sandboxed iframe — every byte of chat UI and logic arrives as a signed bundle admitted at runtime.

On load it generates an Ed25519 identity, instantiates `kernel.wasm`, creates the module registry, and wires a first-install policy approving modules whose author is the local identity (or, for received apps, one the user consents to). There is no signature layer to register — the kernel table starts empty. The user picks a chat app from a dropdown (`v1 — text only`, `v2 — text + image + nick`); the shell builds a **signed bundle** — a `manifest.bundle` (the local key's Ed25519 signature over the manifest, which commits to the module's `genesisHash`) plus the app's `.wasm`, packed into one blob (§12.4) — verifies it, and admits the module through `installBundleModule` → `installDirect` under the registry policy (§7.2). This is the *same* bundle format seed store loads; a chat app is just a one-module, guest-less bundle. Upgrading v1→v2 is a re-admit at the same name under the same key, which the same-author rule approves. Peers hand these bundles to each other in an `OFFER` frame; the recipient re-verifies the original author's manifest signature and admits it the same way — and because the manifest signs the module hash, the bundle survives any number of transitive relays and still authenticates against its original author (the store-and-forward property an offer needs, §12.4).

Peers connect over a WebRTC mesh from `RtcNetwork` (`host/net-rtc.ts`, §12.7) — the same relay-signaled, perfect-negotiation fabric the storage demo uses, here consumed directly for fire-and-forget `send`. The signaling relay (`scripts/relay.mjs`), set on the **Network** tab, is only the rendezvous for the SDP/ICE exchange and can be killed once channels are open. Every frame `RtcNetwork` delivers is already attributed to an authenticated peer (§12.6), so the shell frames chat itself — `[FRAME_CHAT][appId][chatType][body]` — and treats the channel's `_from` as the message author: on receipt it prepends that authenticated pubkey to the handler's input, runs the pure transform with `host.callHandler`, and posts the returned render bytes to the iframe. Because a chat frame travels a **single hop** over the authenticated link, the channel's hop-by-hop attribution *is* end-to-end here — there is no envelope signer to verify and nothing relayed (contrast a feed or forum, §5.1, which would sign each message and chain it). A `Start call` button also publishes audio/video over the same `RTCPeerConnection`s as per-peer tiles above the chat UI; a network change kicks an ICE restart (`RtcNetwork.restartAllIce`) so a transient drop recovers without reconnecting.

The relay is partitioned into **rooms** so one instance hosts many independent groups without cross-talk. A client picks its room as the URL path — `ws://host:8080/<room>` — and the relay forwards only between sockets sharing a room; a bare `/` lands in the default room `global`. The shell exposes this as a Room field on the **Network** tab, with a **Random** button that fills in 64 bits of hex entropy (a private rendezvous token). Room names are URL-safe (`[A-Za-z0-9._-]`, ≤128 chars). The room is **not** an authenticated channel — knowing the name is the only credential, and the relay sees all signaling in its room — but the end-to-end identity binding below means a relay or room member cannot impersonate a peer, only observe SDP metadata and refuse to forward.

`RtcNetwork` binds channel identity with `PeerLink`'s in-channel HELLO/AUTH challenge (`host/net-link.ts`, §12.6): each end proves it holds the private key for the pubkey it claims *before* any frame is delivered, then every later frame rides the §12.6 ChaCha20-Poly1305 record layer, attributed to that identity rather than to anything inside the frame. This is continuous channel binding, stronger than a one-shot SDP `a=fingerprint` assertion at the signaling layer (RFC 8827 §5.6.4) — a MITM relay can splice SDP and bring DTLS up to itself, but can never complete AUTH without the peer's private key, so the link never authenticates and never delivers a byte. The record layer already makes every frame confidential and integrity-protected; the data channel's own DTLS is a redundant second layer underneath (§12.7).

The chat handler never reaches the UI itself: it is a pure transform that *returns* render bytes, which the shell forwards to the iframe by `postMessage`. The iframe is `sandbox="allow-scripts allow-forms"` with no same-origin access to the shell, so app-rendered content stays walled off from the shell's keys and peer state.

To run it locally: build the WASM artifacts (`kernel.wasm` and the chat app modules) into `WASM/build/`, then serve `WASM/browser/` over HTTPS (the bundled `localhost+1.pem` / `localhost+1-key.pem` are mkcert certs for `localhost`) and open `chat-shell.html` in two browsers to chat between them.

---

## 12. The runtime as an app host: capabilities, the shell, and signed bundles

Chat (§11) is a browser shell wired by hand. The same onion ships as a **general runtime artifact** — the *shell* — that any app rides on as **signed content**. The shell knows nothing about chat or storage; it offers a fixed, generic surface, verifies a bundle against a policy, and *becomes* whatever the bundle is. [seed store](https://github.com/arj03/seedstore) is the worked example: a full peer-to-peer storage node is the shell plus a signed bundle, with no storage-specific code in the runtime.

"Capabilities" from here on mean one thing: the **bundle cap domains** (§12.2, §12.4) — five coarse names (`crypto`, `net`, `fs`, `module`, `clock`) that a bundle's signed manifest grants to the app's confined JS *guest*. They answer "may this *app's guest* reach this backend at all?" (WASM handlers, by contrast, carry no capabilities at all — a pure transform reaches nothing but the input it is handed and the output it returns, §4.2.)

The manifest's `caps` field is the guest's *entire* authority — which is why it lives inside the signed manifest and nowhere else. It has to: the guest is not a kernel handler — it has no name in the kernel's table and no install record, so nothing below the signed manifest could carry its authority.

### 12.1 Raw-byte capability backends

The runtime provides the capability *backends* an app's confined logic drives through the cap-bridge (§12.2). They are deliberately structureless — bytes in, bytes out — so the kernel never learns what an app means by them:

- `crypto.*` — the bundled sumo libsodium: hash (BLAKE2b), `sign`/`verify` (Ed25519), the raw `stream_xor` (xchacha20), `random` (`host/cap-bridge.ts`, backed by `loadSodium`). `sign` is under the node identity but **scoped**: the host prepends `DOMAIN_guest` plus the app's identity to the message before signing (§12.2), so a guest never obtains a raw node-key signature. Raw signing stays host-internal (it backs the PeerLink handshake, §12.6).
- `net.*` — an authenticated request/response transport over a `Network` (`host/net.ts`): node↔node over raw TCP, browser↔node over RFC 6455 WebSocket (`host/net-node.ts`), or peer↔peer over WebRTC (`host/net-rtc.ts`, §12.7), each connection pinned to a peer's kernel pubkey by a challenge/response (`host/net-link.ts`). It offers `send` (a single peer request/response) and `peers`; a guest fans out itself with `Promise.all` over `send` (§12.2, §12.3).
- `fs.*` — raw bytes under an opaque, flat key (`host/fs.ts`): `get`/`put`/`size`/`list`/`delete`/`stat` (existence is `size ≥ 0`, so there is no separate `has`). An in-RAM `MemoryFs` and a directory-backed `NodeFs` (`host/fs-node.ts`); OPFS/IndexedDB in the browser later. No content-addressing, no paths — that's app policy.
- `clock` and an installed-handler call (`KernelHost.callHandler`) to reach a WASM handler by name.

Anything with *structure* is a **no-capability module** that transforms bytes: WebSocket framing is `ws.wasm` (`./ws`), Reed–Solomon erasure coding is an app's `codec.wasm` — both pure transforms the host drives, never something the kernel knows.

### 12.2 The cap-bridge: the guest op ABI

An app's confined logic reaches all of the above through a single seam, `host.call(op, bytes) → bytes` — the guest's one route to real I/O, the counterpart to the host's own `callHandler`. `host/cap-bridge.ts` (`./cap-bridge`) services that seam from the primitives above and *only* those. Every op is application-neutral; the bridge has no idea it is hosting storage.

The op numbers are a **shared guest↔host identifier**, not a wire value: the generated preamble injects them into the guest as `const CAP_<NAME> = n;` and the bridge switch reads the same table, so the two cannot drift (regenerated together, never independently versioned, never sent between nodes). The set is one contiguous block grouped by domain; new ops are appended. Multi-byte integers are big-endian (§16).

| # | Op | Request | Response |
| --- | --- | --- | --- |
| 1 | `HASH` | message bytes | 32-byte generic hash (BLAKE2b) |
| 2 | `STREAM_XOR` | `[nonce 24][key 32][msg ..]` | `msg` ⊕ XChaCha20 keystream |
| 3 | `SIGN` | message bytes | 64-byte detached Ed25519 signature under the node identity, over `DOMAIN_guest ‖ scope ‖ msg` — the scope is host-derived (below, §16.1), never guest-supplied |
| 4 | `VERIFY` | `[pk 32][sig 64][msg ..]` | `[valid u8]` |
| 5 | `IDENTITY` | (empty) | the node's 32-byte public key |
| 6 | `RANDOM` | `[n u32]` | `n` random bytes |
| 7 | `NET_SEND` | `[peer 32][type u8][payload ..]` | `[ok u8][response ..]` |
| 8 | `NET_PEERS` | (empty) | `[count u32][pk 32 ×count]` |
| 9 | `FS_GET` | key (utf8) | `[0]` absent \| `[1][bytes ..]` |
| 10 | `FS_PUT` | `[klen u32][key][bytes ..]` | (empty) |
| 11 | `FS_LIST` | prefix (utf8, may be empty) | `[count u32] {[klen u32][key]}` |
| 12 | `FS_DELETE` | key (utf8) | (empty) |
| 13 | `FS_STAT` | (empty) | `[used u64][available u64]` |
| 14 | `FS_SIZE` | key (utf8) | `[size i32]` (−1 if absent) |
| 15 | `MODULE_CALL` | `[name_len u8][name][request ..]` | the installed handler's response bytes |
| 16 | `CLOCK` | (empty) | now in unix ms (`u64`) |

`NET_SEND` is the only op that genuinely round-trips: the guest `await`s it, and a fan-out is the guest's own `Promise.all` over it — the seam hands out real promises, so scatter-gather is the guest's own, not a host op. Every other op resolves to bytes without yielding.

**The signing op is scoped, never raw.** `SIGN` does not sign the guest's bytes as given: the host signs `DOMAIN_guest ‖ scope ‖ msg`, where `scope = author_pk ‖ app_len u8 ‖ app` is derived from the admitted manifest (§12.4) — the same `(author, app)` pair that keys freshness — never guest-supplied. The domain-prefix family is disjoint (§14, §16.1), so a guest-obtained signature never verifies as a manifest or a channel AUTH; and distinct bundles derive disjoint scopes, so one app cannot sign in another's namespace. `VERIFY` stays raw — verification is not an oracle — so an app checks a scoped signature by reconstructing the preimage itself; every node running the same bundle derives the same scope, which makes the signatures portable across a cohort. One consequence: rotating a bundle's author key changes the scope and orphans previously signed objects, so an app anticipating handover records its scope inside its own signed formats. §14 has the trust rationale.

The **capability domains** a manifest declares (§12.4) expand to fixed op sets — the coarse, human-auditable vocabulary ("this app reaches net + fs"), not a list of op numbers:

| Domain | Ops |
| --- | --- |
| `crypto` | 1–6 (`HASH`, `STREAM_XOR`, `SIGN`, `VERIFY`, `IDENTITY`, `RANDOM`) |
| `net` | 7–8 (`NET_SEND`, `NET_PEERS`) |
| `fs` | 9–14 (`FS_GET`, `FS_PUT`, `FS_LIST`, `FS_DELETE`, `FS_STAT`, `FS_SIZE`) |
| `module` | 15 (`MODULE_CALL`) |
| `clock` | 16 (`CLOCK`) |

An op outside the granted domains does not resolve — the bridge refuses it, and the shell never wired the backing resource in the first place (an `fs`-less bundle gets no fs backend at all, not an fs backend behind a check). An unknown domain name in a manifest throws when the realm is built — a typo fails loudly rather than silently granting nothing, or, worse, everything.

**Relation to WASI.** The cap-bridge is deliberately WASI-shaped at the seam: a small syscall table, a zero-authority guest, capability by non-wiring rather than runtime check. The differences justify a bespoke ABI. The ops are identity-centric, not POSIX — `net` is addressed by peer pubkey over a channel bound to that key (§12.6), not by socket; `fs` is a flat opaque blob store with no paths; `SIGN`/`IDENTITY` surface the node's identity, which WASI has no notion of (and every guest signature is domain-scoped). And the grant is *signed content*: the guest's authority is the `caps` field of an author-signed manifest (§12.4) admitted by operator policy (§12.5), where WASI's grants are host-local instantiation choices with no authorship. WASI begins after who authored the code and who may install it are settled; §7, §9, and §12.4 settle them. What keeps this from drifting into a worse WASI: ops stay structureless bytes, anything with structure becomes a no-capability module (§12.1), and the table grows by appending sparingly.

### 12.3 Zero-authority JS realms

Logic that is inherently async or awkward as a *synchronous* WASM handler runs as confined JS in a QuickJS-compiled-to-WASM realm (`host/safe-js.ts`, `./safe-js`). A fresh realm has only the ECMAScript intrinsics — it cannot even *name* `fs`/`net`/`process`/`fetch` — and reaches out only through the injected `host.call` seam. The seam is narrow-async: a sync op (crypto/fs/clock/module) resolves to bytes immediately, and the one round-tripping op (`NET_SEND`) returns a real Promise the guest `await`s. So the guest is ordinary async/await JS, a fan-out is `Promise.all`, and there is **one** realm — a single non-Asyncify build — serving both roles: `call()` runs an initiator that may `await` net, and `callSync()` answers an incoming request straight through *while* an initiator is parked mid-`await` in that same realm. A suspended async function is just heap state, so re-entering to run a synchronous handler is ordinary JS — no second engine, no Asyncify, no module-global suspend state. This is the chat shell's sandboxed-iframe confinement (§11) generalised: "run zero-authority guest JS over a cap seam," the sibling of "run a WASM handler under caps."

### 12.4 Signed bundles

An app is delivered as a **bundle** (`host/bundle.ts`, `./bundle`) — a directory of signed content:

```
manifest.bundle     the signed manifest envelope (below)
<module>.wasm       each WASM handler module
<guest>.js          the zero-authority guest program (§12.3) — optional
```

**What a bundle carries beyond the modules.** The module registry (§7) binds exactly one kind of thing: WASM handlers into the kernel's table. A bundle wraps everything else an app is made of:

- **The guest is not a kernel handler.** It is JS source for a QuickJS realm, not WASM — the registry's path ends in "instantiate WASM, `SetHandler`." Without the manifest it would have no signed identity at all.
- **The guest's authority has no other home.** A WASM handler is a pure transform with no capabilities of its own (§4.2); the guest, by contrast, *does* reach I/O — through the cap-bridge — yet has no kernel name and no install record, so the manifest's `caps` is its entire capability declaration.
- **Version coherence.** Module binds are per-name and independent; nothing in §7 says "codec at hash X, reputation at hash Y, and guest at hash Z together constitute app v1.2." The manifest is the author's signed statement of the coherent set — without it a node can hold a mix of individually-valid module versions that were never meant to run together.
- **Operator/author separation.** The shell is one fixed, auditable artifact; the app arrives as content signed by a third-party key the operator's policy admits. Verification is channel-independent: a bundle read from a USB stick verifies exactly like one fetched from a mirror or pushed over a relay.

**One authenticated statement, one authorization.** The bundle is the *only* way code arrives. The signed manifest commits to every module's `genesisHash` (§7.1), and the loader verifies each `.wasm`'s bytes against it, then installs each verified module directly under its declared `kernelName` by calling the registry's `installDirect` (§7.2) — the record's `author` is the manifest author and its `bytes_hash` is the verified hash, gated by the same install policy (§12.5). Admission touches no replay state, so an equal-version reload just re-binds cleanly — a reboot re-reading the same directory installs the same modules again with no collision. A **live update** is not a separate mechanism: it is delivering a bundle whose manifest `version` is higher, which the freshness guard (below) requires and the same-author rule (§7.4) admits.

**Manifest envelope.** `[author_pk: 32][sig: 64][manifest: UTF-8 JSON to end]` — an Ed25519 detached signature over `DOMAIN_manifest ‖ json`, where `DOMAIN_manifest` is `"seedkernel-manifest-sig-v1\0"` (§16.1), prepended before signing but not stored. The disjoint prefix means a manifest signature can never double as a guest `SIGN` or channel-handshake signature over the same bytes (§14). There is deliberately no canonical-JSON step: the envelope carries the exact signed bytes and the verifier parses exactly what it checked, so the bytes *are* the manifest and canonicalisation has nothing to bite on.

**Manifest fields.**

| Field | Type | Enforced? | Meaning |
| --- | --- | --- | --- |
| `app` | string | key | Display name for the coherent set; with `author_pk` it forms the `(author, app)` freshness key (see freshness below). |
| `version` | integer | **yes** | Monotonic version of the coherent set. A load whose `version` is below the persisted `(author, app)` high-water mark is refused as a downgrade (see freshness below). |
| `modules[]` | `{name, file, hash, kernelName}` | yes | One entry per WASM module: logical name, filename, `genesisHash(wasm)` hex (the *same* value the registry records as the module's `bytes_hash` and a policy `modules` allowlist matches, §7.1), and the kernel name the loader binds the module at via the registry's `installDirect` → `SetHandler`. The manifest is the authoritative source of the bind name. |
| `guest` | `{file, hash}` | if present | Optional. The guest program: filename + `genesisHash(utf8(source))` hex. A handler-only bundle (the chat demo — WASM handlers, no zero-authority realm) omits it entirely. |
| `caps` | string[] | **yes** | The capability domains (§12.2) granted to the guest. The shell expands them to the allowed op set and wires only the matching backends; nothing outside them resolves. They are ordinary app powers the operator authorizes by choosing to run this bundle (none grants raw node-identity signing — the `crypto` domain's `SIGN` is scoped to this app's namespace, §12.2, §14). |
| `config` | map (string → string \| number) | no | App constants injected into the guest as `const APP = {…}`. Opaque to the runtime. |

**Load algorithm** (`loadBundle`). The shell is host code, so failures here **throw to the operator** — the §3 "drop" semantics apply to wire messages, not to loading a local directory:

1. Read `manifest.bundle` and verify the envelope signature. Invalid ⇒ reject; nothing has landed.
2. Require `author_pk` to be in the policy's `authors` (§12.5).
3. **Freshness.** Read the persisted high-water mark for `(author_pk, app)` (absent ⇒ −∞). Refuse if `version < high_water` — a downgrade, nothing lands. Otherwise persist `high_water := max(high_water, version)`. Equal versions reload (an ordinary reboot); a newer version advances the mark; the mark is monotonic and never rewound, so once version N loads, nothing older ever loads again on this node.
4. For each manifest module, in order: read the `.wasm` and require `genesisHash(bytes) == hash` (mismatch ⇒ reject); bind the verified bytes at `kernelName` via the registry's `installDirect` with the manifest author (§7.2), which records `(author, bytes_hash)` and gates on the install policy (§12.5). A module the policy refuses does not abort the load — the loader reports which modules registered, and the operator decides.
5. If the manifest declares a `guest`, read its source and require `genesisHash(utf8) == guest.hash` (mismatch ⇒ reject). A handler-only bundle declares none and skips this.
6. Only now, and only if a guest was declared, may it run (§12.8): a realm (§12.3) over a cap-bridge restricted to `caps`' op set, loaded with `op preamble ‖ const APP = merge(manifest.config, operator config) ‖ guest source`.

**One authentication, one authorization.** The manifest signature authenticates and freshness-checks the *set* (steps 1–3); the content-hash check binds each module's bytes to the manifest's commitment (step 4); the install policy (§12.5) authorizes the bind (author in the allowed set, module hash on the allowlist if configured). Tampered bytes fail the hash check; a manifest from an allowed author still cannot land a module the `modules` allowlist excludes. The manifest is the single authenticated statement, the policy the single authorization decision.

**Operator config wins.** The shell merges the operator's `--app-config` *over* the manifest's `config` before injection. The split is intentional: author-signed `config` carries content-structural constants (a storage app's k/m/blockSize), the operator's carries per-node policy (a quota). The merge is opaque — the shell never inspects a key — so the operator can even override a structural constant. That fits the trust model (the operator's host *is* the TCB, §14), but bundle authors should not assume their `config` reaches the guest unmodified.

**Bundle freshness.** `version` is an enforced monotonic integer, not a label: step 3 refuses any directory whose `version` is below the persisted `(author, app)` high-water mark, so an older signed bundle — a stale relay copy, or a confused provisioning step handing over yesterday's build — is rejected as a downgrade. The whole bundle loads wholesale from the directory every boot, and neither guest nor modules carries a per-item version, so `version` is the single downgrade guard for the set. The mark is host-local persisted state; a deliberate rollback is an out-of-band operator action (the operator is the TCB, §14). See §14.

### 12.5 The policy file

The shell's only governance knob is `--policy <allowed-keys.json>` (`host/policy.ts`), parsed strictly — a malformed file fails the boot loudly rather than silently widening trust:

```json
{
  "authors": ["<author ed25519 pubkey, hex>", "…"],
  "modules": ["<module bytes_hash, hex>", "…"]
}
```

| Field | Required | Semantics |
| --- | --- | --- |
| `authors` | yes, non-empty | The closed set of keys that may bind a name (§7.4 rule 1) **and** that may sign a bundle manifest (§12.4 step 2). |
| `modules` | no | Allowlist of module `bytes_hash`es (`genesisHash(wasm)`, §7.1 — the same id a manifest's `modules[].hash` carries). Omitted ⇒ any module from an allowed author; present ⇒ the install's hash must be listed (the §7.3 content-hash pattern, compounded with the author gate). |

**Omitting `--policy` is deny-all, not "no policy".** A node with no policy file runs an *empty author set*: it boots, serves, and refuses everything — manifest author (§12.4 step 2) and every module bind (§7.4 rule 1) alike — so it loads no app at all. Trust is something an operator adds deliberately; the absence of a decision is never permission. One shared function (`policyFromJson`) resolves this, so every target — the Node shell and the native loader (§12.9) — boots the same posture, with no permissive default of its own.

The *guest's* §12.2 cap domains are **not** gated by this file — they come from the signed manifest, bounded by which bundle the operator chose to run (`--bundle`). No per-author gate is needed because the one dangerous power — raw node-identity signing — isn't grantable at all: a guest's `SIGN` is confined to its app scope (§12.2, §14), and the rest (`fs`, `net`, hashing, …) are ordinary app powers.

### 12.6 Node↔node transport: channel identity binding

A real socket carries no trustworthy "from" field, so before a connection delivers frames it runs a mutual challenge/response (`host/net-link.ts`) proving each end holds the kernel private key for the pubkey it claims — the same binding `RtcNetwork` applies to each WebRTC data channel (§11, §12.7). `PeerLink` is transport-agnostic over any channel that delivers whole messages: raw TCP (length-prefix framing) node↔node, RFC 6455 WebSocket (`ws.wasm` framing) browser↔node (`host/net-node.ts`), or a WebRTC `RTCDataChannel` peer↔peer (`host/net-rtc.ts`, §12.7) — same handshake, same frame plane, only the bottom byte-pipe swaps. Every transport enforces one wire-visible frame cap, `MAX_FRAME_BYTES` (16 MiB, §16.1), checked against the length prefix (TCP) or frame length (WS) **before** the body is buffered, so an unauthenticated peer cannot make a node allocate more than a single frame. TCP and WebSocket cap identically.

Three link-layer messages, each tagged with a leading type byte:

```
HELLO = [0x01][pubkey: 32][nonce: 32][eph: 32]   sent by both ends immediately
AUTH  = [0x02][sig: 64]                          sig = Ed25519(transcript) — see below
FRAME = [0x03][AEAD record ..]                   accepted only after AUTH verifies
```

`eph` is a fresh **ephemeral X25519 public key**, generated per connection. AUTH signs the whole **transcript**, not just a nonce:

```
transcript = DOMAIN_channel ‖ lo ‖ hi
             {lo, hi} = the two `pubkey ‖ nonce ‖ eph` triples (mine, the peer's) sorted by bytes
```

Both ends derive the *same* transcript — the two `pubkey ‖ nonce ‖ eph` triples ordered canonically, so dialer and accepter agree regardless of who opened the socket — each signs it and verifies the peer's AUTH against it. Because the signature commits to **both identities, both nonces, and both ephemeral keys**, a signature collected on one connection — even from a node used as a signing oracle — names the wrong peer elsewhere and fails to verify, closing the impersonation hole a nonce-only AUTH would leave (sign the victim's nonce, replay it as the victim); see §14. `DOMAIN_channel` is `"seedkernel-channel-id-v1\0"` — domain separation so a handshake signature cannot double as another protocol's over the same bytes. An outbound dial pins `expectPeerId`: if the far end's HELLO presents a different key, the link closes. Frames sent before authentication are queued, bounded by `MAX_QUEUE_BYTES` (1 MiB) with oldest-dropped — a byte bound, not a frame count — so a peer that never authenticates cannot make a node hoard memory.

**The signed ephemeral key makes this an AKE.** Because the identity signature covers `eph`, the handshake is a SIGMA-style authenticated key exchange: the signature binds the key exchange, and — since it already covers *both* identities — there is no separate identity-MAC seam to get wrong. Once both AUTHs verify, each end computes the ephemeral–ephemeral DH `X25519(my_eph_sk, peer_eph_pk)` and derives two directional session keys from it and the transcript hash, `KDF(dh, transcript_hash, label)`, the canonical lo/hi ordering assigning directions (the `lo` end encrypts with `k_lo→hi`, decrypts with `k_hi→lo`; `hi` mirrors). Every post-AUTH FRAME is then a **ChaCha20-Poly1305-IETF record** under the sending key, with an implicit monotonic per-direction counter as the nonce and strict enforcement on receive. There is exactly one post-handshake frame type — the AEAD record — so no plane split, no downgrade seam. The identity Ed25519 key stays signing-only and never takes a DH role, disjoint from the sealed-box / Curve25519 uses of the node key (§12.9, §14).

Above the link, `Transport` (`host/net.ts`) runs typed request/response inside the encrypted record channel — a single frame plane, no separate unauthenticated bulk path:

```
req = [0x00][corr: u32][type: u8][payload ..]
res = [0x01][corr: u32][payload ..]
```

The `res` frame carries no `type`: the requester matches by `corr` and already knows the `type` it asked for, so echoing it is dead weight. Block bytes ride this plane too (in seed store a STORE pushes bytes in a `req` body, a FETCH returns them in a `res` body), so the record layer authenticates and encrypts them like any frame; content-addressing (`genesisHash(bytes) == block_id`) stays the app-level admission check on those payloads, not the transport's integrity story. A response resolves only if it arrives from the peer the request went to, so a malicious cohort member cannot answer on another's behalf by guessing the counter. Scatter-gather is the guest's own: because `NET_SEND` hands it a real Promise (§12.2, §12.3), a fan-out is `Promise.all` over a distinct request per peer (broadcasting one payload is just N identical entries) — partial results by construction, since an unreachable peer resolves `[ok 0]` rather than rejecting the batch. The transport's one concurrency primitive is the single request/response.

**What the handshake gives.** Because AUTH signs the full transcript, it authenticates that the far end held the claimed private key *for this exchange*: bound to the exact identities, nonces, and ephemeral keys that produced it, the signature cannot be harvested on one connection and replayed on another, and a signing oracle yields nothing reusable. The same signature binds the ephemeral keys, so the session is authenticated end to end. Every post-AUTH frame is then individually authenticated, confidential, and replay-protected (strict counter enforcement over the ordered channel), and the session is **forward-secret** because the DH keys are ephemeral — an in-path attacker who hijacks the live stream after authentication can neither read nor forge frames. `PeerLink` therefore needs no external tunnel (TLS, Noise); the record layer lives in the shared `net-link.ts`, uniform across TCP, WebSocket, and WebRTC. See §14.

### 12.7 Browser↔console WebRTC

§12.6's `PeerLink` rides any whole-message channel, and a WebRTC `RTCDataChannel` is one — which turns WebRTC into a first-class `Network` exposing the same `send` / `peers` surface as the TCP and WebSocket transports.

**`RtcNetwork` (`host/net-rtc.ts`) — relay-signaled mesh.** Peers reach each other directly over `RTCDataChannel`s; the relay (`scripts/relay.mjs`) is only the *signaling* rendezvous for SDP/ICE and can be killed once channels are open — no server in the data path. One ordered binary channel per peer carries everything, and `Transport` (§12.6) rides on top untouched, so a storage cohort gets P2P for free while a fire-and-forget app (chat) consumes `send` directly. The `Signaling` seam is pluggable — relay, DHT, gossip, or even an existing `PeerLink` between two connected peers — and carries *no* SDP-fingerprint signature, because identity is proven in-channel: `PeerLink`'s HELLO/AUTH runs *inside* the data channel (§12.6), stronger than a one-shot SDP-fingerprint assertion at the signaling layer (§11). A MITM relay can splice SDP and bring DTLS up to itself but can never complete AUTH without the peer's private key, so the link never authenticates and never delivers a byte. The module is browser-native (it uses the platform `RTCPeerConnection`); a Node/Bun *console* node joins by passing a `peerConnectionFactory` (`weriftPeerConnectionFactory`, `host/net-rtc-node.ts`) — "swap the connection, keep the stack," the §12.6 move applied to WebRTC. werift (pure-TS) is used over native `node-datachannel`, which segfaults under Bun.

**Confidentiality.** Like every transport, the WebRTC fabric's frames are confidential and integrity-protected by the §12.6 AKE record layer. A data channel is also DTLS-encrypted, a redundant-but-harmless second layer underneath. As on the raw transports, the in-channel AUTH supplies the identity binding DTLS alone does not (§11).

### 12.8 The shell

`boot(opts)` (`host/main.ts`, `./shell`) assembles all of the above — the kernel and the module registry under the loaded policy, the fs/net capability backends, the node identity — and returns a `Shell` (`loadBundle`, `runGuest`, `serve`); a CLI wraps it:

```sh
node build/host/main-node.js --policy ./allowed-keys.json --dir ./data --key ./node.key \
     --listen 0.0.0.0:7000 [--ws-listen 0.0.0.0:7001] \
     --bundle ./app-bundle [--peers <pk>@host:port,…] [--put file] [--get hex[:hex…] --out file]
```

A serving node that has loaded a bundle runs the app's *initiator* side on demand (`runGuest` → `realm.call`, which may `await` net) **and** serves its *request* side from the **same** confined realm (`serve` routes `transport.onRequest` to the guest's `handle` entrypoint via `realm.callSync` — the holder answers from local fs + crypto synchronously, so it responds while an initiator is parked mid-`await` in that realm). The shell is application-neutral — it can host any signed app — and for a self-contained non-browser deployment the Go/native target ships it as a single binary (§12.9). seed store's WASM README has a complete storage walkthrough.

### 12.9 The Go/native shell — the primary non-browser deployment

The §12.8 shell runs as JS on Node or Bun, but the **recommended** way to run a node outside the browser is the **Go/native target** (`native/`, a top-level Go module): a single self-contained, cgo-free binary — `seedloader` — with no Node, no Bun, and no separate JS engine to install on the box.

It is a **platform target, not a reimplementation.** All protocol and app logic stays shared TypeScript — the cap-bridge (§12.2), the node↔node transport (§12.6: the PeerLink AKE, the encrypted request/response Transport, the routing), the installer and its policy (§7), bundle verification (§12.4), the policy file (§12.5), the confined safe-js guest (§12.3) — the same code the other targets run, just hosted differently. Go supplies only the platform **primitives** the §1 table calls for; protocol is never re-derived in a second language (*Go grows with primitives, never with logic*).

This is enforced mechanically: the shared modules are compiled by `tsc` and concatenated into `native/*.gen.js` by `scripts/bundle-loader.mjs` (`npm run build:loader-bundles`), which the loader `//go:embed`s and evaluates in QuickJS. Nothing under `native/` is a hand-written second copy. Each bundle runs over a *seam* — a small TypeScript adapter (`host/native-shim.ts`) satisfying the same interfaces the JS host does (`InstallerHost`, `BundleHost`, `FreshnessStore`) by forwarding to Go's byte-level `bridge`. Because the adapter is typechecked against those interfaces, a shared-rule change the native target fails to honor is a **compile error**, not a silent divergence. The seam carries no rules of its own: who may bind a name (§7.4), the `installDirect` step (§7.2), the manifest signature and its domain prefix (§12.4), the freshness arithmetic, and the deny-all default (§14) all live in the shared modules — one implementation of each to audit.

Concretely the binary embeds and drives, over [wazero](https://wazero.io) (a pure-Go, cgo-free wasm runtime):

- **`kernel.wasm`** — the same §3 handler-table module every target runs.
- **`libsodium.wasm`** — the *same* crypto blob as the browser/Node build, which is exactly what makes a Go node's sealed boxes, XChaCha20 blocks, and Ed25519→Curve25519 conversions byte-identical to a JS node's. Wire/crypto parity is free when it is literally the same code (§6.6).
- **a prebuilt QuickJS** (quickjs-ng, `native/qjs`) — so the shared host JS runs unmodified with no native JS-engine dependency. QuickJS is synchronous, so Go owns the event loop (timers, the JS job queue, socket delivery). A net `host.call` returns a real Promise to the guest: Go kicks off the host realm's Transport request under a call id and, when it settles, resolves the guest's pending Promise (`deliverNet`), and the shared loop pumps the guest realm so the awaiting entrypoint resumes — the same real-promise seam the Node/Bun build uses, driven by Go's loop instead of quickjs-emscripten's job pump. The confined guest runs in a second, zero-authority QuickJS realm whose only seam is `host.call`.
- **`ws.wasm`** — the *same* RFC 6455 framing blob the browser/Node targets use (`host/ws/ws-wasm-backend.ts`), driven over wazero and exposed to QuickJS as `__ws`. WebSocket framing is a no-capability byte transform (§12.1), not host code, so it is the identical module on every target; the handshake/codec state machine stays shared host JS (`ws-codec.ts` + `net-frame.ts`) running in QuickJS over a raw Go socket. Instantiated lazily on first WS use, so a pure node↔node TCP deployment never pays for it.

Go-native primitives back the capability seams: `os` for the §12.1 fs backend, `net` for the raw TCP socket — node↔node directly, and browser↔node under a WebSocket whose RFC 6455 framing is the shared `ws.wasm` above — and `crypto/rand` for entropy. WebRTC (§12.7) stays browser-only. The CLI mirrors §12.8 exactly:

```sh
seedloader --policy ./allowed-keys.json --dir ./data --key ./node.key \
     --listen 0.0.0.0:7000 [--ws-listen 0.0.0.0:7001] \
     --bundle ./app-bundle [--peers <pk>@host:port,…] [--put file] [--get hex[:hex…] --out file]
```

Because the wire and the bundles are shared, a Go node and a Node/Bun node interoperate directly in one cohort — `put` on either, `get` on the other, in both directions, against the same signed bundle and genesis (verified end-to-end for seed store by `WASM/scripts/loader-interop.sh`).

**Scope: the native target is a bundle-runner.** Its app path is the §12.4 bundle — load, verify, install the modules, run the guest — and its request path is transport → shared route bundle → cap-bridge → the installed handlers, each reached by name through `callHandler`. Both targets install code only from a signed bundle (§7, §12.4), so the app-delivery surface is identical. There is no dispatch loop and no signature pipeline to keep in parity: the kernel is a name→id table (§3) and handlers are pure transforms (§4), so Go's only handler-facing duties are staging input into a handler's `scratch`, reading its output, and honoring a declared `scratchSize` (§4.1) — byte-identical to the JS host. The registry and its policy (§7), bundle verification and freshness (§12.4), the policy file (§12.5), and the domain prefixes (§16.1) are the same shared TS both targets run in QuickJS; the manifest and channel signatures the loader checks read their `DOMAIN_*` prefixes from that one evaluated `domains.ts`, so every signed preimage is byte-identical across the cohort by construction, not by a hand-copied constant.

**Size.** One file, ~7.5 MB stripped, cross-compiled to win/linux/mac with `GOOS`/`GOARCH` — nothing to install alongside it. The bulk is wazero's compiler backend (~4 MB) and the Go runtime (~2.4 MB); the protocol's own footprint stays tiny (§10.2). Against the JS shell — which needs a Node/Bun install plus the lazily-loaded ~1.5 MB QuickJS engines — the native binary trades a larger single artifact for zero external dependencies, the right shape for a server or an appliance.

**Performance.** Because the Go target drives the *same* `libsodium.wasm` under wazero that the JS targets run under V8, crypto throughput tracks node closely — Ed25519 verify and XChaCha20 land within ~10% either way, and the Reed–Solomon codec runs a touch *faster* (≈330 / 394 vs ≈315 / 319 MB/s encode / decode). The one deliberate exception is the block-id hash (BLAKE2b-256), which runs on **native Go** (`golang.org/x/crypto/blake2b`, byte-identical to libsodium and KAT-pinned): it sits on the storage data path and is the single primitive wazero ran the wasm materially slower than V8, so native (~600 vs ~390 MB/s) is the clear win. Per-frame overhead trails node by Go-side event-loop cost, not crypto. Reproduce with `go test -run x -bench . -benchmem ./...` from `native/`; the node baselines come from `WASM/tests/run.mjs` and seed store's `WASM/tests/bench.mjs`.
