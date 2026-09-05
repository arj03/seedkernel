# Seed kernel — Protocol

*The message model, bundle slots, the restartable WASM module ABI, and layering. §16 collects the protocol constants.*

> **Part of the [seed kernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · **PROTOCOL §2–§5, §16** · [RUNTIME](RUNTIME.md) §10–§12 · [SECURITY](SECURITY.md) §13–§14

---

## 2. The message model

A message at the runtime boundary is `(protocol id, input bytes)`. The transport has already decrypted it and attributed it to a peer key (§12.6). The host resolves the protocol claim directly to a bundle slot, prepends that peer key, and invokes the slot's guest `handle` entrypoint. There is no module dispatch on the inbound path.

The guest may call one of its own restartable modules by bare name on `host.call` (§12.2). Those modules are private values captured by that guest's slot: no app key participates in lookup and no other guest can address them.

**No wire format means no host-level size cap.** The bounds live where bytes flow: the transport caps a frame at `MAX_FRAME_BYTES` and a module caps I/O at its scratch size (§4.1).

**Authenticity is the channel's.** There is no per-message signature in the host. Signing survives off the message path for bundle manifests and channel AUTH; an app that relays content carries any end-to-end attribution it needs itself.

---

## 3. Bundle slots

The shell's lifecycle model is one direct projection:

```
claim → { verifiedBundle, realm, pureModules, fsScope, signingScope }
```

The realm is the only inbound entry. `pureModules` is a private name-to-instance map captured by that realm's seam. `fsScope` is derived host-side from the verified `(author, app)`, and `signingScope` from that pair or — for the slot reaching `link` — the node's network key. Neither is chosen by guest code. A slot can own several claims; each points to the same value.

The shell also retains installed slots for administration and initiator-only bundles, but that collection is not a second routing model: dispatch is always one `claim → slot` lookup. A claim has one active owner. A different identity that contests it is rejected; an update may atomically replace its own slot and claims.

App keys remain only where identity is required: freshness and revocation records, filesystem and signing scope derivation, audit output, and the operator's explicit `uninstall` selector. Host invocation uses the slot-bound handle returned by a load. Keys are not module addresses and claims do not route through them.

### 3.1 Atomic load and replacement

A load performs these steps:

1. Verify the complete signed bundle and ask the admission predicate.
2. Build every private module off to the side. If any module fails validation or instantiation, release the partial set.
3. Derive the filesystem and signing scopes, then stand the confined realm wired to that private module set.
4. Persist the freshness mark for the version that successfully ran.
5. Synchronously replace the installed identity and reproject all claims, then dispose the previous slot.

Nothing is published before step 5. A malformed module, broken guest, or failed freshness write disposes only the candidate; the running version and all of its claims remain unchanged. The claim commit contains no `await`, so a bundle that owns several claims cannot be observed with only some replaced.

The candidate realm evaluates its guest's top level between steps 3 and 5, and the realm factory runs it synchronously inside the seam — so an effect reached for there has already landed by the time step 5 decides. Until the slot is marked active the seam therefore refuses **every** name, and a guest's authority begins at its first post-commit invocation: disposing a candidate is a real undo because a candidate did nothing to undo. A top level may still define state and validate what the preamble handed it; anything it needs the host for belongs in the first invocation. A link candidate's node facts are not an exception that needs the seam — the host folds them into that slot's installation-local `LOCAL` config before standing the realm (§12.6).

An upgrade replaces the entire slot. A module omitted by the new manifest therefore disappears with the old slot, as do the old realm, timers, scopes, and all other module instances. `uninstall` and `revoke` remove the slot as the same unit and dispose everything it owns; there is no single-module lifecycle.

### 3.2 Target implementation

Only construction and execution of `pureModules` vary by target. JS builds a private map of worker-backed instances and returns closures over it. Native may keep an opaque handle into a Go map because wazero modules cannot be JS values. That map is an implementation detail behind the slot, not a shell API or kernel model.

The shared loader owns verification, admission, ordering, scope derivation, realm construction, and the atomic claim commit (§12.9). A host starts with no slots and a deny-all admission policy; loading signed bundles is the only growth path.

---

## 4. The WASM module ABI

A module is a **restartable transform**: bytes in, bytes out, private WASM memory, and no capability imports. Any language that compiles to WASM (AssemblyScript, C#, Rust, C, Zig, Go) can implement the contract — it is three required exports and no capability imports.

The contract promises isolation, not statelessness or determinism. A module may retain private caches and mutable state between calls, but callers must tolerate that state's loss on a respawn (§4.3).

Modules exchange bytes with the host through a **scratch region** in their own linear memory. There is no allocator contract, no pointers crossing the boundary, no buffer lifetimes to reason about — just "read input here, write output there, return the length."

### 4.1 Exports (module must provide)

| Export name | WASM type | Description |
| --- | --- | --- |
| `memory` | linear memory | Module's memory; the host reads input from and writes output to the scratch offset within it. |
| `scratch` | `global i32` | Byte offset into `memory` where the host places input and reads output. Set once during instantiation; the host reads it once after instantiation and the module MUST NOT change it afterward. |
| `scratchSize` | `global i32` *(optional)* | Bytes of scratch the module reserves at `scratch`. The host reads it once at instantiation and clamps its input/output copies to it; a value below the 128 KB default or naming out-of-bounds memory is refused fail-loud (the install throws). Export it only if the module genuinely reserves that region — the host writes there. |
| `handle` | `(i32) → i32` | `(input_len) → output_len` — transform the input at `scratch` and return the response length. |

**Declared memory is bounded.** A module MUST declare a linear-memory **maximum**, and both its initial size and that maximum MUST fit the host's per-module budget (`DEFAULT_MAX_MODULE_MEMORY_BYTES`, §16). The loader reads the limits off the module bytes *before* instantiating it (`wasm-limits.ts`), because instantiation is what allocates the declared initial memory — a module asking for 4 GiB has already taken the host down by the time an export check could see it. A module that declares no maximum is refused: WebAssembly gives an embedder no way to impose one afterwards, so an undeclared maximum is an unbounded one. Two further refusals fall out of the same read and defend §4.3's claims rather than a budget: an **imported** memory (linear memory must remain private even though fixed inert function shims are allowed, §4.2) and a **shared** one.

For AssemblyScript that requirement is one build flag, `--maximumMemory` (in pages).

**I/O protocol.** Before each call, the host writes the input bytes at offset `scratch` (up to the configured scratch size — default 128 KB, or the module's exported `scratchSize`). The module reads its input from `scratch`, writes its response back at `scratch` (overwriting the input is fine), and returns the number of response bytes. Return `0` for "empty response." The host reads `output_len` bytes at `scratch` after `handle` returns and does not touch the region again until the next call; a trap or a negative/oversized length makes the guest's `host.call` promise reject. Internal module loaders report failure as null; returning `0` succeeds with zero-length bytes (§12.2).

Memory outside the scratch region is the module's private state — statics, globals, whatever allocator it wants for its own bookkeeping — but none of it is durable: a deadline kill discards the instance and respawns a fresh one (§4.3), so that memory is scratch or cache, never the system of record. Anything that must survive a respawn belongs in the guest or the filesystem, not module memory.

### 4.2 No capability imports — the isolation boundary

A module imports **nothing from the runtime** — no host seam, no host functions. The only imports it carries are its own language runtime's shims (for AssemblyScript, `env.abort` / `seed` / `trace`), which are not a route to the outside world.

**Every target resolves exactly that set, and none grants I/O.** `seed` is a constant rather than a clock read, `trace` drops its arguments, and `abort` traps — a module that aborts fails its call on every target rather than running on past the point it declared itself broken. These shims do not make stateful module code deterministic (§4.3). The set is fixed rather than per-target because one `trace()` or `Math.random()` anywhere in a module is the difference between loading and a missing-import failure: a host resolving a subset would refuse modules another host accepts, and would do it at instantiation, far from anything that reads like an import problem.

Concretely, a module **cannot**:

- reach the filesystem, network, clock, or any I/O;
- call another module, or resolve a name — it cannot reach the table, and has no cross-module call;
- ask who sent the input, who signed anything, or who called it — there is no signer, no caller, no author query.

External data arrives **in the input**, and results leave **in the output**; a module may also read and modify its own private memory. When a message must carry the sender's identity to the module, the orchestrator prepends it to the input from the authenticated channel (§12.6) — as the chat app does, staging `senderPk ‖ body` (§11). Private state does not add ambient authority: the module still has no capability imports.

**Composition is the guest's job.** Chaining transforms — running one module's output into another, fanning out, doing I/O between steps — is the app's guest, never a module's. A guest reaches only the private module set captured by its slot, using bare names on the guest seam (§12.2). Because a module cannot call back, these compose without re-entrancy: each transform returns before the next runs.

### 4.3 Safety & memory model

What a module **cannot** do, restated as guarantees:

- **No outside-world reach.** With no capability imports (§4.2), a module can modify its private state and return bytes, but cannot perform I/O. It cannot open a socket or a file even if compromised — not by a rule in its code, but because the capability was never imported.
- **No cross-module corruption.** A buggy or malicious module can scribble anywhere in its own memory but cannot touch the host or another module — each runs in its own WASM instance, and the host copies bytes between scratch regions rather than sharing pointers.
- **No pointers cross the boundary.** There is no allocator contract; the host never holds a pointer into a module's memory across a return and never writes outside the scratch region.
- **No durable state.** A module's memory beyond scratch (§4.1) is its own, but not guaranteed to last: a deadline kill (below) respawns a fresh instance and whatever the old one held is gone. A module is a **restartable transform** — it may use its memory as scratch or cache, but a caller cannot depend on any of it surviving a respawn, and must handle a failed call and instance reset. The host does not verify that resetting private state preserves application meaning.

> **Memory is bounded at admission; compute is bounded at the engine.** Two bounds, two mechanisms — a declaration read off the bytes, and a deadline the engine can land on.
>
> **Memory** is closed at admission: a module declares its ceiling and the loader refuses anything above the host's budget, or anything that declares no ceiling at all (§4.1). The check is a property of the bytes, so it holds identically on every target — it runs on the shared admission path (§3.2), not in each host's instantiation code.
>
> **Compute** is charged to the calling guest and interruptible where the guest's budget ends. A module call runs under a deadline: the calling guest's **remaining execution segment**, computed by the realm at the moment of the call, and a call that burns it rejects at the guest seam — as a trap does — while the engine kills the module. A successful zero-length result remains distinct from failure (§12.2). How the kill lands is per-target, because no engine mechanism is shared: the JS targets run each module in its own worker, and `terminate()` destroys the isolate mid-loop if it must (the one interrupt the JS platform's WebAssembly exposes), respawning a fresh instance for the next call; the native target arms wazero's `WithCloseOnContextDone` and passes that same per-call remainder as the call context's deadline. The call is async on the guest seam (§12.2) — the guest parks on it like any other round-tripping name — so a spinning module burns one core for at most one budget and holds nothing else on the node. §14 has the exposure that remains and what a deployer does about it.

**Replay and ordering are settled off the module.** A module's memory is disposable, not a system of record (above), so it has no durable notion of "seen this before." Where that matters, the defence lives at the layer that owns the bytes: live-traffic replay is closed by the transport's strict per-direction counter (§12.6), and an older install is refused by bundle freshness (§12.4). An app that **relays** messages through intermediaries — where neither of those applies to the original author — adds its own per-message signature and backlink chain (§5.1, §14). None of it is the host's or the module's concern.

---

## 5. Layering and composition

Modules form an onion — the stack diagram in §1 draws it: each layer depends only on the layers below it, and no layer has a hard dependency on the ones around it. The onion is a typical composition, not a required one; every layer is independently usable.

### 5.1 Modules in the reference implementation

| Layer | Modules | What lives there |
| --- | --- | --- |
| **Bundle slot** | `claim → {bundle, realm, modules, fsScope, signingScope}` | Direct dispatch plus the private resources one verified bundle owns (§3). |
| **Guest seam** | Guest seam (host-side) | The `host.call(name, bytes)` seam a confined guest reaches its I/O through — the only outward reach the guest has (§12.2). |
| **App** | [seedchat](https://github.com/arj03/seedchat) (§11), [seed store](https://github.com/arj03/seedstore) — both live outside this repo | A confined JS guest (the app's logic) over its restartable WASM modules — delivered as one signed bundle (§12.4). |

Each layer is testable standalone: the table is exercised on its own, the loader against a bundle with no live transport, chat as a guest over a handful of transforms with no crypto in sight. Composition across layers is the guest's (or a host-side embedder's), through `callModule` / a guest`s bare-name `host.call` (§4.2) — never a module reaching sideways.

**The hash function used for id derivation.** Content hashes and binary pins use **BLAKE2b-256** — the genesis hash, computed by `genesisHash`. The same primitive appears in the guest catalog, AKE KDF/transcript, and block-id path. App identities and module names remain literal fields rather than derived module addresses.

**Names are strings.** A name is an opaque string the host only ever matches — nothing forces a hash, so a name reads plainly in a log and in a manifest.

**A name is slot-local.** Nothing on the wire names a module. A peer sends a protocol id and the receiving host resolves that claim directly to a slot; the confined guest reaches only that slot's modules by manifest name through `host.call`. Two hosts can install the same code under different app names and still interoperate.

**There is no composite module name.** A module is addressed only by its manifest logical name inside the private slot value. `"<author hex>:<app>"` remains a host-internal identity for scopes, freshness, audit, and operator selection; it is not concatenated with or consulted for module dispatch.

The author is the **full** hex, never a truncated prefix. A short prefix would be grindable: an admitted author could generate a key matching another's first bytes and land on their app. App keys are node-local table keys that never travel, so their length costs nothing but log width.

**App identity and routing claims are different namespaces.** The author is part of the host-internal `"<author hex>:<app>"` key, so two authors may use the same app label without colliding in freshness, scope, audit, or uninstall state. Public protocol and local service claims are literal manifest strings, however, and each claim map has one active owner. A different `(author, app)` contesting an occupied claim is refused; an update of the same app key may atomically replace its own slot and claim set (§12.10).

**Relayed-message apps layer their own authenticity.** The channel authenticates one hop (§12.6). An app whose messages pass through intermediaries — a feed, a forum, store-and-forward gossip — cannot let the channel speak for the *original* author, so it becomes its own layer: a per-message signature naming the author, plus **backlinks** (a hash-chain, à la [SSB](https://ssbc.github.io/scuttlebutt-protocol-guide/)'s `previous` or [Bamboo](https://github.com/AljoschaMeyer/bamboo)'s lipmaa links) to order the history and make equivocation detectable. Signed bundles (§12.4) already do the author half for relayed *code*; a relayed-message app does the same one layer up, and it is a distinct app from chat, whose every message travels a single hop (§14 has the rationale for keeping lineage out of the loader).

---

## 16. Protocol constants

Protocol constants and the principal runtime limits in one place. Multi-byte integers are big-endian throughout the protocol.

**A value appears here only where a second implementation has to match it** — wire widths, suite bytes, domain prefixes, the charsets and the caps both ends enforce. Everything else is a *default*: a number this deployment picked, which an operator, an embedder or a signed transport bundle may change. Those rows name the constant and what it bounds but state no value, because there is nothing for a second implementation to agree with — the retained deadlines are the one qualification, since they are each side's own tolerance rather than an agreed number, and a peer feels a short one only as a connection that does not complete. The values live in source (`core/wasm-limits.ts`, `core/net-limits.ts`, `host/net-rtc.ts`, `transport/src/{ake,framing}.js`, `scripts/transport-config.mjs`) so there is one place to read it and nothing to keep in step.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| `DEFAULT_SCRATCH_SIZE` | `131072` (128 KB) | Module instantiation | Per-module I/O region at `scratch`; a module may declare more via `scratchSize` (§4.1). |
| `DEFAULT_MAX_MODULE_MEMORY_BYTES` | *host default* | Slot construction (`loadBundleModules`) | Ceiling on a module's declared initial *and* maximum linear memory, read before instantiation (§4.1). Applied at that one call site against the **tighter** of this and the ceiling the target's loader declares (`PureModuleLoader.maxModuleMemoryBytes`), so a host may hold its own isolates to less and none can be looser about what a *bundle* may land — a composition rather than a rule each loader repeats. |

An unclaimed peer protocol is answered with an **empty response** (§12.10), while a failed module call rejects at the guest seam (§4.1). A module returning zero bytes has succeeded. An undeclared or unknown guest-call name is refused as a catalog error; absence is not a blanket empty-result rule (§12.2).

### 16.1 Runtime (shell) constants

These belong to the reference runtime (§12), not the §3 table contract — a different shell could change them without breaking anything the table sees, but they are wire- or ABI-visible to bundles and peers of *this* runtime. Its bounds implement three distinct laws: retained space uses continuous custody, one causal chain carries a monotone deadline, and fresh invocation roots need explicit rate control. A limit in one column must not be read as a guarantee in another.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| Author id | 32 bytes | Manifest envelope (§12.4) | `genesisHash(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖ ml_dsa_pk)` over the author's whole key set, so the identity is unreachable without both private keys. One suite, one derivation — and 32 bytes, which keeps app-key construction (§5.1), policy files and freshness marks written against a single fixed-width identity. The paired genesis hash is BLAKE2b-256, the one system hash (§5.1). |
| Seam names | `crypto/*`, `node/*`, `fs/*`, `clock/now`, `timer/*`, `link/*`, this realm's own declared local service ids, plus the bare names of the calling bundle's own modules (`codec`, `ws`, `mlkem`, …) | guest seam (§12.2) | Guest↔host identifiers, never wire values. A declared local service dispatches to its claimant; what remains splits by charset — every host name contains `/`, while module names are `[A-Za-z0-9_-]`. Bare module names are private to the asking bundle and carry no grant. |
| Manifest requires | `HOST_SERVICES` (`core/domains.ts`) | manifest `guest.requires` (§12.4) | Exactly the host SERVICES a guest may call, granted BY SERVICE. The seam refuses a host method whose service is undeclared, and the loader refuses an entry naming a finer method (`fs/get`) rather than its service (`fs`), naming an unknown service, or naming a local service id — which belongs in `guest.calls`. `link` requires the operator's `link` grant; inbound delivery rides that slot and is never a name to declare. Ungated `crypto/*` and the bundle's own modules are not declarable. |
| Manifest calls | local service ids, claim charset | manifest `guest.calls` (§12.10) | The local service ids this guest reaches on a co-resident guest, over the same `host.call`. Carries no privilege and nobody grants it; resolved at call time through the local claim map, so an id nothing claims yet is not a manifest error. Refused only when it spells a host method or one of this bundle's own module names, either of which the dispatch would resolve first. |
| Host transforms | `blake2b-256`, `chacha20poly1305-ietf/{seal,open}`, `x25519/dh` | guest seam `crypto/` prefix (§12.1, §12.2) | Frozen compatibility table (`HOST_TRANSFORM_NAMES`, `core/domains.ts`), ungated because each entry is pure, and at its floor because the host itself calls each one. New pure computation is a bundle module, not a new host name. ML-KEM is the transport's bare `mlkem` module; XChaCha20 belongs to the application that uses it. |
| Transport | `link`, and an ordinary local service claim chosen by composition | manifest `guest.requires` + `services` (§12.4, §12.5) | Two facts. `link` is admitted by the operator's `link` grant AND by the node's transport author pin (§12.9), and binds raw-link events directly to that slot — one owner, so a second link-capable load is refused rather than allowed to take the sockets over. Inbound attributed delivery is `link/deliver`, one of that privilege's own names and not a second grant: the occupant that sees the plaintext is the one that attributes, and the host routes what it hands over through the PEER claim map alone, so a bundle's `services` local claim is unreachable there by construction. The service claim grants no authority and has no kernel-known spelling. Freshness and replacement use the ordinary `(author, app)` slot rules. |
| Manifest envelope | `0x02`: `[suite 1][ed_pk 32][ml_dsa_pk 1952]`<br>`[ed_sig 64][ml_dsa_sig 3309][json]` | `verifyBundle` (§12.4) | Fixed width. Signs `DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ json` with **both** keys and requires **both** to verify. The suite byte is stored *and* signed, so a verifier may read it for field widths before verifying and still cannot have it edited under them (§14.1). |
| Link messages | msg1 1,265 B, msg2 1,168 B, msg3 112 B, msg4 112 B, then AEAD records | transport bundle (§12.6) | **A message is a bare body.** Msg1 carries the initiator's X25519 ephemeral and ML-KEM-768 public key; msg2 carries the responder's X25519 ephemeral and ML-KEM ciphertext. Which message a body is follows from the reader's role and progress — the initiator reads msg2 then msg4, the responder msg1 then msg3, and every message after authentication is a record. A handshake message is accepted only at its exact width. Neither identity crosses the wire in the clear. |
| Algorithm suites | channel `0x03` · manifest `0x02` | msg1 byte 0 (§12.6) · manifest byte 0 (§12.4) | **Two independent namespaces on independent clocks** — channel (`0x03`: Ed25519 identity · hybrid ephemeral X25519 + ML-KEM-768 · contact secret · ChaCha20-Poly1305) and manifest (`0x02`: hybrid Ed25519 + ML-DSA-65, both required); never read one as the other. Each namespace accepts exactly one value; all other ids are refused. Neither namespace is negotiated — one suite per link, one per manifest, unknown ids refused (silently, on the channel). Each id is covered by the signature it accompanies, so a suite is chosen by an endpoint and never forced in flight (§14.1). |
| `DOMAIN_manifest` | `"seedkernel-manifest-sig-v1\0"` | Manifest signature (§12.4) | Domain-separation prefix for the signed bundle-manifest JSON. Prepended before signing, not stored. |
| `DOMAIN_manifest_author` | `"seedkernel-manifest-author-v1\0"` | Author id derivation (§12.4) | Prefixes the key material a multi-key suite's 32-byte author id is hashed from. The one member of the family that prefixes a *hash* rather than a signature; it is in the family because it must be disjoint from every signing prefix, so a derived id can never also be something someone signed. |
| `DOMAIN_guest` | `"seedkernel-guest-sig-v1\0"` | Guest seam `node/sign`/`node/verify` for an ordinary app (§12.2) | Domain-separation prefix for guest-obtainable signatures, followed by the host-derived scope `author_pk ‖ app_len u8 ‖ app` from the admitted manifest. Prepended before signing *and* verification (host-applied on both), never transmitted. |
| `DOMAIN_link_scope` | `"seedkernel-link-scope-v1\0"` | Guest seam `node/sign`/`node/verify` for the slot reaching `link` (§12.2, §12.6) | Domain-separation prefix for that slot's signatures, followed by the node's 32-byte network key. The slot's scope, not a second name: the host derives one `SignScope` at load, and this is the link slot's. Host-applied on both sides like `DOMAIN_guest`, never transmitted. The kernel owns the separation and nothing inside it: what format is signed under this scope is the occupant's. |
| `DOMAIN_channel` | `"seedkernel-channel-id-v1\0"` | Transport bundle's handshake signature and transcript (§12.6) | **Not a member of the family above** — a format tag the transport bundle places in its own content, used to seed the transcript hash and prefix each identity payload `DOMAIN_channel ‖ transcript ‖ own_id`. It sub-separates the transport's formats *within* `DOMAIN_link_scope`, so changing the handshake is a bundle update rather than a kernel change. Declared in `transport/src/ake.js`, not `core/domains.ts`. Not transmitted. |
| Contact secret | 32 bytes, out of band | msg1 seal, every handshake KDF (§12.6.3) | Per node, distributed with its address; a caller that cannot produce it draws no response. Never on the wire. Absent = open node. |
| Network key | 32 bytes, config | transcript root (§12.6.3) | Which network this node belongs to — staging vs production. **Public by design**: an isolation boundary, not access control. Applied as a prologue, so every key and every signature preimage differs between networks. |
| Master seed | 32 bytes, on disk | `subkeys.ts` (§12.6.2b) | The node's only stored secret. Signs nothing; derives the `channel` keypair under a versioned label. That keypair's public half is the peer id and the node's one identity — it signs through the one guest-seam sign pair (`node/sign`), whose scope the host sets from the slot: the link slot's `DOMAIN_link_scope ‖ network_key` for the handshake, an app slot's `DOMAIN_guest ‖ author ‖ app` for its own records. |
| `AUTHOR_MLDSA_SEED_LABEL` | `"seedkernel-author-mldsa-v1"` (no trailing NUL) | `hybridAuthorKeysFromSeed` (§12.4) | KDF label, not a signing prefix: `genesisHash(ed25519_seed ‖ label)` is the ML-DSA-65 seed of the same author, so one stored 32-byte seed is the whole key set. **Frozen.** The author id hashes both public keys, so changing the label re-identifies every author built from a seed — new app keys, a dead freshness lineage, every policy pin pointing at nobody. |
| FS key charset | `[A-Za-z0-9._-]+`, minus `.`/`..` and Windows device names | `isSafeFsKey` (`core/fs.ts`) | Both backends map a key to a filename verbatim, so the charset is a consensus predicate, not a backend detail: two nodes disagreeing about it disagree about their contents. Device names (`CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9`) are refused on every OS; Windows ignores the extension, so `NUL.txt` is still `NUL`. A scope is a prefix, not a complete name, and is held only to the charset. |
| Node address | `pk[.secret]@[scheme://]host:port[/path]` | `parsePeerRef` (§12.6) | The peer's Ed25519 identity, optionally that peer's contact secret, and where to reach it. It parses into a peer id and an opaque **destination** string (`scheme://host:port[/path]`), which is what `link/open` carries and only a socket factory takes apart: `tcp://` is node↔node, `ws://`/`wss://` the RFC 6455 codec — the latter asking for TLS — and a path reaches a peer behind a reverse proxy. A reference that states no scheme takes the default of the flag it was typed under. The pk is **routing** — it keys the transport's address book so dial-by-identity has something to look up — and the secret is the **credential**. No long-term Diffie–Hellman or KEM key is published. |
| `MAX_FRAME_BYTES` | `2097152` (2 MiB) | socket seams (§12.6) | Hard cap on one link frame, enforced on the length prefix (TCP) or frame length (WS) **before** buffering — bounds what an unauthenticated peer can make a node allocate from a single prefix. Both transports cap identically, so a frame that crosses one crosses the other. The transport does not fragment, so this is also the largest application message a node can send. Two things move with it: `ws.wasm` stages a whole frame in a scratch region it allocates at init, and since it rides in the transport bundle every shell pays that region whether or not it speaks WebSocket; and the Go loader keeps its own copy (`native/net.go`). Raising it means rebuilding `ws.wasm`, which `tests/transport.test.mjs` asserts rather than leaves to memory; a single deployment may lower the transport guest's cap with `transport.config.maxFrameBytes`. |
| `MAX_HANDSHAKE_FRAME_BYTES` | `8192` (8 KiB) | the transport bundle's framers (§12.6.2) | Bundle-owned inbound frame cap **before** a link authenticates, raised to the host-resolved `maxFrameBytes` on authentication. Applying the full application cap to an unauthenticated peer would be a memory hole. The largest current flight is the 1,265-byte hybrid msg1, comfortably below this cap. |
| `LINK_IDLE_TIMEOUT_MS` | *transport default* | transport bundle (§12.6.2) | How long an authenticated link may carry no traffic in either direction before the bundle retires it with the authenticated goodbye — the other half of `MAX_AUTHED_LINKS`, since a cap alone lets a peer fill it and sit there, and the handshake deadlines stop applying at authentication. Measured as "a whole window passed with nothing seen" (a zero-authority realm has no clock, only deadlines), so the effective window is one to two of these. The address book redials on the next send. |
| `UNVERIFIED_TIMEOUT_MS` | *transport default* | transport bundle (§12.6.2) | How long an accepted connection has to send a msg1 that opens. Short because it covers one message from a peer that has already connected. Leaks nothing: observing the longer deadline requires the contact secret. |
| `HANDSHAKE_TIMEOUT_MS` | *transport default* | transport bundle (§12.6) | Deadline for the rest of the handshake, armed once msg1 opens. Every pre-auth refusal is silent and simply lets this expire. |
| `REKEY_AFTER_FRAMES` | `16777216` (2²⁴) | transport bundle records (§12.6) | Frames per epoch before the sending direction ratchets its key. Must match on both ends; a mismatch desynchronises the link. **Both ends must use the same value.** The AEAD nonce is the implicit `(epoch, counter)` pair and is never transmitted (`transport/src/ake.js`), so a sender and a receiver that ratchet at different frame counts derive different keys and every later record fails to open. It resolves as ordinary transport policy (`LOCAL.rekeyAfterFrames ?? APP`), so lowering it on one node alone silently breaks that node's links to every peer on the default. |
| `REJECT_AFTER_EPOCHS` | `65536` (2¹⁶) | transport bundle records (§12.6) | Epoch ceiling. Reaching it retires the link — a deliberate shutdown that announces itself, not a fault — rather than producing a record under a repeated nonce. |
| Transport frame kinds | `req 0x00`, `res 0x01`, <br>`FLAG_NO_REPLY 0x80` | transport bundle (§12.6) | Single request/response plane, carried inside the §12.6 AEAD record layer. A req names a protocol id so a node hosting several apps can route it (§12.10). `FLAG_NO_REPLY` is OR'd into the kind byte for fire-and-forget sends: the receiver still dispatches to the app but skips the response frame, and the wire corr is **0** (nothing is parked). A response is `[1][corr u32][payload]`, so an **empty** response is exactly five bytes — a 6-byte floor would drop "no app serves this protocol" and make it indistinguishable from an unreachable peer. Six is the request branch's floor (protocol-id length at offset 5). |
| `DEFAULT_MAX_OUTSTANDING_HOST_CALLS` | *host default* | Confined realm host-call seam (§12.3) | Count of unresolved calls one realm may retain outside its heap. Capacity returns on settlement, the caller-owned handoff deadline, or realm disposal, so a backend or deferred callee that never answers cannot pin the charge. |
| `DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES` | *host default* | Confined realm host-call seam (§12.3) | Aggregate copied input bytes across those unresolved calls, plus a response's bytes for the moment it coexists with its request. Enforced with the count ceiling before the host-owned copy, so large calls and tiny calls are bounded independently on both realm targets. It applies to **every** call: the operation name decides routing and authority, never whether the bytes are charged. A **response is charged as it is delivered**, not before — see [RUNTIME.md §12.3](RUNTIME.md#123-zero-authority-js-realms) for why claiming an answer's width ahead of the backend is not worth what it costs. |
| `UNESTABLISHED_PEER_TTL_MS` | *host default* | WebRTC signaling (`host/net-rtc.ts`) | One deadline per peer entry, armed when it is created and answered on **two** facts: an entry that has not both reached `connectionState === "connected"` **and** bound its data channel when it fires is closed and its pending ICE released. Establishing leaves the `MAX_UNESTABLISHED_PEERS` cap but does not disarm the deadline — the polite side never opens a channel, so a peer that completes DTLS/ICE and then stays silent arms no channel watch, and a deadline cleared at "connected" would leave nothing to reap it. |

**The `DOMAIN_*` family lives in one file.** The four prefixes above are a *family*, and the only thing they are for is disjointness: no signature made under one may verify under another, over any bytes, ever — and no derived id may collide with a signed preimage. That is a property of the whole set rather than of any member, so the set is declared together in `core/domains.ts` — where adding a member means reading the others on the same screen — and imported by the modules that sign (`bundle-author.ts`, `guest-seam.ts`). The transport bundle's guest program never sees one: it asks for a signature through `node/sign` and the *host* chooses the prefix from the asking bundle's slot (§12.2), so a prefix cannot be restated in content either. The Go/native target evaluates that same file through its generated bundles (§12.9) and reads its prefixes from the evaluated module, so every prefix on every target derives from this one file by construction, not by a copy that could drift. There is **no** hand-copied member anywhere.
