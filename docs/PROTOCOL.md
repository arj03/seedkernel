# Seed kernel — Protocol

*The message model, the kernel's handler table, host-level `SetHandler`, the pure-transform WASM handler contract, and layering. §16 collects the protocol constants.*

> **Part of the [seed kernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · **PROTOCOL §2–§5, §16** · [RUNTIME](RUNTIME.md) §10–§12 · [SECURITY](SECURITY.md) §13–§14

---

## 2. The message model

The kernel parses nothing off the wire. Its entire state is a table mapping a **name** to a **handler**, and its entire job is to resolve a name to the handler bound there. There is no envelope format, no message header, no dispatch loop — the routing decision is one lookup in `handlers` (§3).

A "message," at the boundary the runtime cares about, is just a `(name, input bytes)` pair the **host** assembles. The host is the orchestrator: it receives bytes from the transport (already decrypted and attributed to a peer key, §12.6), decides which name to route them to, resolves that name through the kernel, and invokes the handler — a **pure transform** (§4) — with the input, reading its output back. The kernel never sees where the bytes came from, who sent them, or what they mean.

That leaves three orthogonal pieces in every binding, none of which the kernel interprets:

- **Name** — an opaque dispatch key, a string. Its meaning is a convention (§5.1), not a kernel concern; the kernel matches names and nothing more.
- **Bytes** — the WASM handler held at that name, a pure transform the host stages input into and reads output from (§4).
- **Author** — the signer of the bundle that installed the bytes. It is the leading component of every kernel name (§5.1), so the table itself carries it; the kernel stores and matches names without interpreting them.

**No wire format means no kernel-level size cap.** The old envelope's 64 KB ceiling is gone with the envelope; the two bounds that remain live where the bytes actually flow — the transport caps a single frame at `MAX_FRAME_BYTES` (16 MiB, §12.6), and a handler caps its own I/O region at its `scratch` size (128 KB default, §4.1). The kernel imposes neither; it only ever holds a name and a handler.

**Authenticity is the channel's, not the kernel's.** Because the transport hands the host frames already authenticated to a peer key (§12.6), there is no per-message signature to check and no signature logic anywhere in the kernel or its handlers. Signing survives in exactly two host-side places, both off the message path: the **bundle manifest** that installs code (§12.4) and the channel **AUTH** that opens a link (§12.6). An app that needs to attribute a *relayed* message to its original author — a forum or feed, where the channel only authenticates the immediate hop — carries its own per-message signature and backlinks on top (§5.1, §14); that is an app concern, not a kernel one.

---

## 3. The kernel

The kernel is a **named table of handlers**: bind a name to a handler, resolve a name to the handler bound there. It holds no cryptography, no authorization, no installation logic, and no message dispatch. The host resolves a name and invokes the handler itself.

The kernel is a **contract, not an artifact**. It is this section — the table, the pure-transform ABI (§4), and the `SetHandler` semantics (§3.1) — and each host implements it as one map:

```
handlers[name] → handler    bind / replace / resolve / remove   (§3.1)
```

`Map<string, handler>` in the JS host, `map[string]*wasmHandler` in the Go host. There is no kernel module to instantiate, no handler-id indirection, no memory staging across a boundary, and no second table to keep in step with a first. §1's vision sentence — "installing a handler is nothing more than `handlers[name] = wasm_bytes`" — is literally the implementation.

**Why the table is not itself a WASM module.** Compiling it would buy "one kernel binary, every host" — but the table is two operations, and the handler *instances* it points at are per-target regardless (a `WebAssembly.Instance` in JS, a wazero `api.Module` in Go), so it could never be self-contained: each host would keep a parallel map beside it, keyed by an id invented to cross the boundary, plus the alloc/copy/call/dealloc round trip per lookup. What genuinely must not diverge between hosts is the bundle **load order** and the **admission rules**, and those *are* shared — as compiled TypeScript evaluated on every target (§12.9), where sharing pays.

**Name resolution** is one map lookup. Names are strings (§5.1), so a bundle module's name reads plainly in a log as `"<app>:<module>"`. A name that is not a key in the table is unbound.

**"Drop" semantics.** Throughout this document, **drop** means "silently ignore: no response is generated, no error is propagated to the sender." An unbound name is dropped by the host. The kernel never produces unsolicited output; every reply an app sends travels as a fresh frame under that app's own logic.

**No re-entrancy to reason about.** A handler is a pure transform that runs to completion and returns before anything else runs (§4). Handlers cannot call one another, so there is no call stack, no depth limit, no current-signer or caller state living across a call — all of which earlier revisions carried and none of which exists now. Concurrency is the host's concern: it drives one transform at a time, typically on a single event loop.

### 3.1 Host-level handler management (`SetHandler`)

The host manages the table through two operations:

```
SetHandler(name, handler)    install or replace the handler for name
SetHandler(name, null)       remove it
```

`SetHandler` installs or replaces in place, so the table never holds two entries for one name. Together these are the **only** way handlers enter or leave it — no install message, no privileged "register" path, no protected-vs-unprotected distinction; every entry arrived the same way. The reference host exposes them as `installBundleModule(name, wasm, author)` and `removeHandler(name)`.

**The bind is not a public host method.** Nothing hands the host a ready-made handler to drop into a slot: the only caller of the bind is the loader's admission (§12.4), which reaches it after the manifest signature and the policy have both passed. So every entry in the table is a bundle module admitted under a verified manifest — there is no second kind of occupant, and no question of who authored what a name resolves to, because the author is the first thing the name says (§5.1). That is what makes "one install path" (§1) literally true rather than nearly true.

`SetHandler` is internal to the host process — never reachable from inbound frames or from a WASM handler. The host controls access through its own authentication (process permissions, operator console, HSM); the kernel defines no access-control policy for it.

**Removing a name frees only that name.** `removeHandler` deletes the entry and nothing else — there is no side table to keep in step. A freed name can only ever be re-occupied by the author whose key derives it (§5.1), so a removal cannot hand a slot to anyone, and the misattribution a stale ownership record would invite has no way to arise. This is the loader's `remove(name)` revocation path (§12.5).

### 3.2 Growth is the loader's job, not the kernel's

Most deployments grow by loading signed bundles (§12.4), not by wiring every handler by hand. The bundle loader admits each verified module — a policy decision (§12.5) followed by `SetHandler` at the name it derives from the manifest (§5.1). None of that is the kernel's: admission is host-side, off any wire path, and the kernel sees only the resulting bind. Frozen-config deployments load no bundles and grow no further.

**Standing a host up.** Because the kernel is a map rather than an artifact, there is no bootstrap sequence to speak of: ready libsodium, construct the host, and the table is live — empty, resolving nothing. Growth is then two ordered steps, and the order is the only constraint: wire an admission policy (§12.5), then load a bundle (§12.4). A host whose policy is never wired is not misconfigured but *frozen* — deny-all is the default, so it boots, serves, and admits nothing (§14). There is no step for instantiating a kernel module, seeding a signature handler, or wiring a slot by hand; each was a step in an earlier revision, and none survives.

Because the loader verifies the manifest signature before it admits anything, "who authored this code" is already settled by an ordinary signature check (§12.4). Installation is not a special operation; it is `handlers[name] = wasm_bytes`, gated by the author + hash policy (§12.5).

---

## 4. WASM handler contract

A handler is a **pure transform**: bytes in, bytes out, no reach beyond the buffer it is handed. Any language that compiles to WASM (AssemblyScript, C#, Rust, C, Zig, Go) can implement the contract — it is three exports and no imports.

Handlers exchange bytes with the host through a **scratch region** in their own linear memory. There is no allocator contract, no pointers crossing the boundary, no buffer lifetimes to reason about — just "read input here, write output there, return the length."

### 4.1 Exports (handler must provide)

| Export name | WASM type | Description |
| --- | --- | --- |
| `memory` | linear memory | Handler's memory; the host reads input from and writes output to the scratch offset within it. |
| `scratch` | `global i32` | Byte offset into `memory` where the host places input and reads output. Set once during instantiation; the host reads it once after instantiation and the handler MUST NOT change it afterward. |
| `scratchSize` | `global i32` *(optional)* | Bytes of scratch the handler reserves at `scratch`. The host reads it once at instantiation and clamps its input/output copies to it; a value below the 128 KB default or naming out-of-bounds memory is refused fail-loud (the install throws). Export it only if the handler genuinely reserves that region — the host writes there. |
| `handle` | `(i32) → i32` | `(input_len) → output_len` — transform the input at `scratch` and return the response length. |

**Declared memory is bounded.** A handler's module MUST declare a linear-memory **maximum**, and both its initial size and that maximum MUST fit the host's per-handler budget (`MAX_HANDLER_MEMORY_BYTES`, §16). The loader reads the limits off the module bytes *before* instantiating it (`wasm-limits.ts`), because instantiation is what allocates the declared initial memory — a module asking for 4 GiB has already taken the host down by the time an export check could see it. A module that declares no maximum is refused: WebAssembly gives an embedder no way to impose one afterwards, so an undeclared maximum is an unbounded one. Two further refusals fall out of the same read and defend §4.3's claims rather than a budget: an **imported** memory (a handler imports nothing, §4.2) and a **shared** one (a handler's memory is private to it).

For AssemblyScript that requirement is one build flag, `--maximumMemory` (in pages).

**I/O protocol.** Before each call, the host writes the input bytes at offset `scratch` (up to the configured scratch size — default 128 KB, or the handler's exported `scratchSize`). The handler reads its input from `scratch`, writes its response back at `scratch` (overwriting the input is fine), and returns the number of response bytes. Return `0` for "empty response." The host reads `output_len` bytes at `scratch` after `handle` returns and does not touch the region again until the next call; a trap or a negative/oversized length is a failure the host reads as "no response."

Memory outside the scratch region is the handler's private state — statics, globals, whatever allocator it wants for its own bookkeeping. None of that is exposed to the host.

### 4.2 No imports — the pure-transform boundary

A handler imports **nothing from the runtime** — no `kernel.*` seam, no host functions. The only imports it carries are its own language runtime's shims (for AssemblyScript, `env.abort` / `seed` / `trace`), which are not a route to the outside world. Concretely, a handler **cannot**:

- reach the filesystem, network, clock, or any I/O;
- call another handler, or resolve a name — it cannot reach the table, and has no cross-module call;
- ask who sent the input, who signed anything, or who called it — there is no signer, no caller, no author query.

Everything a transform needs arrives **in its input**, and everything it produces leaves **in its output**. When a message must carry the sender's identity to the handler, the orchestrator prepends it to the input from the authenticated channel (§12.6) — as the chat app does, staging `senderPk ‖ body` (§11). This is the boundary that makes the sandbox trivial to reason about: a handler that can only read its input and write its output has no confused-deputy surface, no ambient authority, nothing to revoke.

**Composition is the orchestrator's job.** Chaining transforms — running one handler's output into another, fanning out, doing I/O between steps — is the *host's* or a *guest's* work, never a handler's. The host reaches a handler by name with `callHandler(name, bytes)`; a confined guest reaches the same primitive through the cap-bridge's `MODULE_CALL` op (§12.2). Because a handler cannot call back, these compose without re-entrancy: each transform returns before the next runs.

### 4.3 Safety & memory model

What a handler **cannot** do, restated as guarantees:

- **No outside-world reach.** With no imports (§4.2), a handler's only effect is the bytes it returns. It cannot open a socket or a file even if compromised — not by a rule in its code, but because the capability was never imported.
- **No cross-handler corruption.** A buggy or malicious handler can scribble anywhere in its own memory but cannot touch the host, the kernel, or another handler — each runs in its own WASM instance, and the host copies bytes between scratch regions rather than sharing pointers.
- **No pointers cross the boundary.** There is no allocator contract; the host never holds a pointer into a handler's memory across a return and never writes outside the scratch region.

> **Memory is bounded; compute is still the host's problem.** These were one residual and are now two, because only one of them has a mechanism.
>
> **Memory** is closed at admission: a handler declares its ceiling and the loader refuses anything above the host's budget, or anything that declares no ceiling at all (§4.1). The check is a property of the bytes, so it holds identically on every target — it runs on the shared admission path (§3.2), not in each host's instantiation code.
>
> **Compute** is not, and cannot be here: WASM engines on the JS platform expose no fuel or timeout mechanism, so this protocol specifies none. Nothing on the message path does asymmetric crypto or recurses, but an installed handler can still infinite-loop and hold the single-threaded host forever — and a permissive policy (§12.5) multiplies that across many installs. Deployers exposed to runaway handlers should run the host in a Worker with a watchdog, or pre-validate bytecode in the admission policy (forbid unbounded loops) before installing. Note the asymmetry with the confined JS guest, which *does* have an execution budget (§12.3): QuickJS offers an interrupt hook where WebAssembly offers nothing.

**Replay and ordering are settled off the handler.** A handler is stateless-by-input, so it has no notion of "seen this before." Where that matters, the defence lives at the layer that owns the bytes: live-traffic replay is closed by the transport's strict per-direction counter (§12.6), and an older install is refused by bundle freshness (§12.4). An app that **relays** messages through intermediaries — where neither of those applies to the original author — adds its own per-message signature and backlink chain (§5.1, §14). None of it is the kernel's or the handler's concern.

---

## 5. Layering and composition

Modules form an onion — the stack diagram in §1 draws it: each layer depends only on the layers below it, and no layer has a hard dependency on the ones around it. The onion is a typical composition, not a required one; every layer is independently usable.

### 5.1 Modules in the reference implementation

| Layer | Modules | What lives there |
| --- | --- | --- |
| **Kernel** | the host's `handlers` map | The name → handler table and its one lookup (§3). No crypto, no I/O, no dispatch. |
| **Cap-bridge** (optional) | Cap-bridge (host-side) | The `host.call(op, bytes)` seam a confined guest reaches its I/O through — the only outward reach the guest has (§12.2). |
| **App** | [seedchat](https://github.com/arj03/seedchat) (§11), [seed store](https://github.com/arj03/seedstore) — both live outside this repo | Pure-transform WASM handlers plus, optionally, a zero-authority JS guest — delivered as a signed bundle (§12.4). |

Each layer is testable standalone: the kernel is exercised on its own, the loader against a bundle with no live transport, chat as a handful of pure transforms with no crypto in sight. Composition across layers is the host's or the guest's, through `callHandler` / `MODULE_CALL` (§4.2) — never a handler reaching sideways.

**The hash function used for id derivation.** Two places hash: `bytes_hash` (§12.4) and any allowlist that pins a binary. Both mean **BLAKE2b-256** — the *genesis hash*, computed host-side by `genesisHash` (libsodium's core `crypto_generichash`). There is exactly one hash across the whole system: the same BLAKE2b-256 is the `blake2b-256` entry of the primitive catalog a guest reaches by name (§12.1), the AKE KDF and transcript hash (§12.6), and the block-id path. Swapping it shifts every `bytes_hash` — but **kernel names are literal ASCII, not hashes**, so no name shifts with it. Pick the genesis hash once and treat it as a deployment-wide constant.

**Names are strings.** A name is an opaque string the kernel only ever matches — nothing forces a hash, so a name reads plainly in a log and in a manifest.

**A name is node-local.** Nothing on the wire ever names another node's handler. A peer sends an application-level id or opcode — the chat demo's frame carries a *protocol id* (§11), a storage message carries its protocol op — and the receiving host resolves that through its own bindings (§12.10) to whichever app it holds; a confined guest reaches its own modules by logical name through MODULE_CALL, and the bridge resolves the logical name to the kernel name (§12.4) — so the guest never sees a kernel name at all. So a name must be collision-free within one node, not agreed across a deployment. Two hosts that bound the same code under different names interoperate fine, and a host may hold two independent implementations of one protocol at once.

**Names come from exactly one place.** Every name is `"<author hex>:<app>:<module name>"`, derived by the loader from the signed manifest (§12.4) and never declared in it. All three components are covered by the author's signature, so what binds is what the author authenticated, and a manifest holds no bind-name field to forge. There is no second namespace to keep disjoint from this one, because there is no second way to bind (§3.1).

The derivation parses from both ends: the author is a fixed-length 64-char hex prefix and a module name cannot contain `:` (`NAME_RE`), so the last colon always separates the module and everything between is the `app` — which is therefore free to contain colons of its own. The first two components are exactly the **app key** `"<author hex>:<app>"` (§12.4), so one string is at once the app's identity and the prefix of its modules' names.

The author is the **full** hex, never a truncated prefix. A short prefix would be grindable: an admitted author could generate a key matching another's first bytes and land on their names, which is the collision the derivation exists to make unrepresentable. Names are node-local table keys that never travel, so their length costs nothing but log width.

**Ownership is structural.** Because the author is *in* the name, one author's names are unreachable to another — a second author shipping an app called `chat` derives entirely different names and binds alongside, never over. The default policy (§12.5) therefore constrains nothing about names and needs no per-name state to consult: it decides *who* may install, and the derivation does the rest. Squat-resistance is a property of the namespace rather than a rule something has to enforce, and "which of the apps I hold receives a given protocol's messages" is a separate, user-owned decision (§12.10) rather than a race to claim a name.

**Relayed-message apps layer their own authenticity.** The channel authenticates one hop (§12.6). An app whose messages pass through intermediaries — a feed, a forum, store-and-forward gossip — cannot let the channel speak for the *original* author, so it becomes its own layer: a per-message signature naming the author, plus **backlinks** (a hash-chain, à la [SSB](https://ssbc.github.io/scuttlebutt-protocol-guide/)'s `previous` or [Bamboo](https://github.com/AljoschaMeyer/bamboo)'s lipmaa links) to order the history and make equivocation detectable. Signed bundles (§12.4) already do the author half for relayed *code*; a relayed-message app does the same one layer up, and it is a distinct app from chat, whose every message travels a single hop (§14 has the rationale for keeping lineage out of the loader).

---

## 16. Protocol constants

All limits and reserved values in one place. Multi-byte integers are big-endian throughout the protocol.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| `DEFAULT_SCRATCH_SIZE` | `131072` (128 KB) | Handler instantiation | Per-handler I/O region at `scratch`; a handler may declare more via `scratchSize` (§4.1). |
| `MAX_HANDLER_MEMORY_BYTES` | `67108864` (64 MiB) | Bundle admission (`installBundle`) | Ceiling on a handler's declared initial *and* maximum linear memory, read off the module bytes before instantiation (§4.1). A module above it, or declaring no maximum, is refused. A host may hold its own direct installs to something tighter; none may be looser about what a bundle may land. |

A name absent from the table is **dropped** by the host (§3). The kernel enforces nothing else — no magic, no version, no size cap; the transport and the handler own those bounds (§2).

### 16.1 Runtime (shell) constants

These belong to the reference runtime (§12), not the kernel protocol — a different shell could change them without breaking anything the kernel sees, but they are wire- or ABI-visible to bundles and peers of *this* runtime.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| Author id | 32 bytes | Manifest envelope (§12.4) | The Ed25519 public key under manifest suite `0x01`; under the hybrid suite `0x02`, `genesisHash(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖ ml_dsa_pk)` over the whole key set, so the identity is unreachable without both private keys. 32 bytes either way, which is what keeps name derivation (§5.1), policy files and freshness marks suite-agnostic. The paired genesis hash is BLAKE2b-256, the one system hash (§5.1). |
| Cap op ids | `1`–`26` | cap-bridge (§12.2) | Guest↔host op identifiers, contiguous and numbered in the order they were added; regenerated with the guest preamble, never sent between nodes. The numbering is not the grant grouping. Op `1` (`CRYPTO`) is in no domain at all — it is the primitive seam, not a capability. |
| Capability domains | `crypto`, `net`, `fs`, `module`, `clock`, `timer` · slot-only: `rawnet`, `transport` | manifest `caps` (§12.4) | An unknown domain throws when the guest realm is built. Only **authorities** appear here — each reaches something no confined module can hold. `rawnet` (bytes over an opaque link id) and `transport` (the attributed peer, protocol id and correlation the occupant provides back) are refused to any manifest that claims no `role`, checked at load (`SLOT_ONLY_DOMAINS`, §12.2). Pure transforms are not domains: a guest calls them by name (below). |
| Primitive catalog | `blake2b-256`, `ed25519/verify`, `xchacha20/xor`, `chacha20poly1305-ietf/{seal,open}`, `x25519/dh`, `ml-kem-768/{keypair,encaps,decaps}` | manifest `guest.primitives`, cap-bridge op `1` (§12.1, §12.2) | The names the one `CRYPTO` op dispatches through (`PRIMITIVE_NAMES`, `core/domains.ts`). Every entry is a function of its arguments — no host key, no entropy, no state — so nothing gates it and a new algorithm is a catalog entry rather than an op number, an ABI rev or a domain. A manifest's declaration is a **compatibility** check: a host missing a name refuses the load by name. |
| Guest ABI | `1` | manifest `guest.abi` (§12.4) | Which host seam a guest was written against (`GUEST_ABI_VERSION`, §12.2). Required wherever a guest exists; a value this host does not implement is refused by name, like an unsupported suite. Bumped when an existing op changes what it returns — not when an op is appended. |
| Bundle slots | `transport` | manifest `role` (§12.4) | The closed set of slots a bundle may claim. A claim is signed, needs its own policy entry (§12.5), and carries a freshness floor keyed by the slot rather than by the signer. An unknown name is a rejected manifest, never an ignored field. |
| Manifest envelope | `0x01`: `[suite 1][ed_pk 32][ed_sig 64][json]` <br> `0x02`: `[suite 1][ed_pk 32][ml_dsa_pk 1952]`<br>`[ed_sig 64][ml_dsa_sig 3309][json]` | `loadBundle` (§12.4) | Fixed width per suite. `0x01` signs `DOMAIN_manifest ‖ suite ‖ json`; `0x02` signs `DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ json` with **both** keys and requires **both** to verify. The suite byte is stored *and* signed, so a verifier may read it for field widths before verifying and still cannot have it edited under them (§14.1). |
| Link message tags | `HELLO 0x01`, `AUTH 0x02`, `FRAME 0x03` | transport bundle (§12.6) | AKE handshake + encrypted frame plane. `HELLO` is the initiator's opening message; `AUTH` carries the other three handshake messages (which of them follows from role and progress, not from a tag); `FRAME` bodies are AEAD records. Neither identity crosses the wire in the clear. |
| Algorithm suites | channel `0x02` · manifest `0x01`, `0x02` | msg1 byte 0 (§12.6) · manifest byte 0 (§12.4) | **Two independent namespaces on independent clocks** — channel (`0x02`: Ed25519 identity · ephemeral X25519 · contact secret · ChaCha20-Poly1305) and manifest (`0x01`: Ed25519 detached; `0x02`: hybrid Ed25519 + ML-DSA-65, both required); never read one as the other. The channel is at `0x02` because the cleartext-identity genesis suite `0x01` was **removed, not disabled**: a node accepting both would have the concealment of the weaker one. The manifest namespace moved for its own reason — it is the one that cannot be migrated cheaply later (§14.1) — which is what independent clocks look like in practice. Neither namespace is negotiated — one suite per link, one per manifest, unknown ids refused (silently, on the channel). Each is covered by the signature it accompanies, so a suite is chosen by an endpoint and never forced in flight (§14.1). |
| `DOMAIN_manifest` | `"seedkernel-manifest-sig-v1\0"` | Manifest signature (§12.4) | Domain-separation prefix for the signed bundle-manifest JSON. Prepended before signing, not stored. |
| `DOMAIN_manifest_author` | `"seedkernel-manifest-author-v1\0"` | Author id derivation (§12.4) | Prefixes the key material a multi-key suite's 32-byte author id is hashed from. The one member of the family that prefixes a *hash* rather than a signature; it is in the family because it must be disjoint from every signing prefix, so a derived id can never also be something someone signed. |
| `DOMAIN_guest` | `"seedkernel-guest-sig-v1\0"` | Cap-bridge `SIGN` (§12.2) | Domain-separation prefix for guest-obtainable signatures, followed by the host-derived scope `author_pk ‖ app_len u8 ‖ app` from the admitted manifest. Prepended before signing, not transmitted. |
| `DOMAIN_channel` | `"seedkernel-channel-id-v1\0"` | Handshake signature and transcript (§12.6) | Domain-separation prefix, used both to seed the transcript hash and as the prefix of each identity signature `DOMAIN_channel ‖ transcript ‖ own_id`. Not transmitted. |
| Contact secret | 32 bytes, out of band | msg1 seal, every handshake KDF (§12.6.3) | Per node, distributed with its address; a caller that cannot produce it draws no response. Never on the wire. Absent = open node. |
| Network key | 32 bytes, config | transcript root (§12.6.3) | Which network this node belongs to — staging vs production. **Public by design**: an isolation boundary, not access control. Applied as a prologue, so every key and every signature preimage differs between networks. |
| Master seed | 32 bytes, on disk | `subkeys.ts` (§12.6.2b) | The node's only stored secret. Signs nothing; derives the `channel` keypair (whose public half is the peer id) and the `guest` keypair (cap-bridge `SIGN`) under versioned labels. |
| Node address | `pk[.secret]@host:port` | `parsePeerSpec`, `parseWsPeer` (§12.6) | The peer's Ed25519 identity, optionally that peer's contact secret, and where to reach it. The pk is **routing** — it keys the address book so dial-by-identity has something to look up — and the secret is the **credential**. No long-term Diffie–Hellman key is published, so a PQ suite will not change the format. |
| `MAX_FRAME_BYTES` | `16777216` (16 MiB) | socket seams (§12.6) | Hard cap on one link frame, enforced on the length prefix (TCP) or frame length (WS) **before** buffering — bounds what an unauthenticated peer can make a node allocate from a single prefix. Both transports cap identically, so a frame that crosses one crosses the other. |
| `MAX_HANDSHAKE_FRAME_BYTES` | `8192` (8 KiB) | TCP/WS reassembly (§12.6.2) | Inbound frame cap **before** a link authenticates, raised to `MAX_FRAME_BYTES` when the transport bundle asks through `NET_LINK_CAP` (§12.2) — the host owns both numbers. Applying the 16 MiB application cap to an unauthenticated peer was a memory hole: a stranger knowing only `host:port` could declare a large frame, dribble the body, and hold that much memory — times the half-open budget. No handshake message today exceeds 113 bytes; the headroom over that is deliberate, so an ML-KEM-768 encapsulation key (1,184 bytes) does not need a core rev to become expressible (§14.1). |
| `MAX_QUEUE_BYTES` | `1048576` (1 MiB) | transport bundle (§12.6) | Total bytes of frames buffered pre-auth; oldest dropped once the sum would exceed it. A byte bound (not a frame count) so pre-auth buffering is capped regardless of frame size. |
| `MAX_HALF_OPEN_UNVERIFIED` | `1024` | half-open limiter (§12.6.2) | Connections accepted but not yet proved to hold the contact secret. A full budget **evicts the oldest**, it does not refuse the newest — refusing would let a flood shut members out at the door, before they could prove they belong. Such a connection costs no asymmetric crypto: the ephemeral keypair is generated only once msg1 opens. |
| `MAX_HALF_OPEN_VERIFIED` | `256` | half-open limiter (§12.6.2) | Connections that have produced our contact secret and are mid-handshake. A separate budget, so no volume of connections without the secret can keep members from handshaking. |
| `MAX_HALF_OPEN_PER_SOURCE` | `8` | half-open limiter (§12.6.2) | Per-`remoteAddr` bound across both budgets. Deliberately **not** evictable: one address at its own limit is refused outright, never allowed to push a different address out — so saturating the unverified budget needs 128 distinct sources. |
| `UNVERIFIED_TIMEOUT_MS` | `2000` ms | transport bundle (§12.6.2) | How long an accepted connection has to send a msg1 that opens. Short because it covers one message from a peer that has already connected. Leaks nothing: observing the longer deadline requires the contact secret. |
| `HANDSHAKE_TIMEOUT_MS` | `10000` ms | transport bundle (§12.6) | Deadline for the rest of the handshake, armed once msg1 opens. Every pre-auth refusal is silent and simply lets this expire. |
| `REKEY_AFTER_FRAMES` | `16777216` (2²⁴) | transport bundle records (§12.6) | Frames per epoch before the sending direction ratchets its key. Must match on both ends; a mismatch desynchronises the link. |
| `REJECT_AFTER_EPOCHS` | `65536` (2¹⁶) | transport bundle records (§12.6) | Epoch ceiling. Reaching it retires the link — a deliberate shutdown that announces itself, not a fault — rather than producing a record under a repeated nonce. |
| Transport frame kinds | `req 0x00`, `res 0x01`, <br>`FLAG_NO_REPLY 0x80` | transport bundle (§12.6) | Single request/response plane, carried inside the §12.6 AEAD record layer. A req names a protocol id so a node hosting several apps can route it (§12.10). `FLAG_NO_REPLY` is OR'd into the kind byte for fire-and-forget sends: the receiver still runs its handler but skips the response frame. |
| Default request timeout | `2000` ms | shell boot (§12.8) | Response deadline before a peer counts as unreachable (`--timeout`). |
| Guest execution budget | `5000` ms | Confined realm (§12.3) | Per entrypoint invocation, measured over guest **run** time rather than wall clock: a guest parked awaiting a host bridge spends none of it. Exceeding it interrupts the guest, which surfaces to the caller as a thrown error; on the native target the interruption terminates the realm rather than throwing inside it (§14). Operator-set (`guestDeadlineMs`, CLI `--guest-timeout`), not author-declared; `Infinity` — CLI `0` — disables it. The realm heap cap alongside it is 64 MiB (`realmMemoryBytes`, CLI `--guest-memory`, in MiB). |

**The `DOMAIN_*` family lives in one file.** The four prefixes above are a *family*, and the only thing they are for is disjointness: no signature made under one may verify under another, over any bytes, ever — and no derived id may collide with a signed preimage. That is a property of the whole set rather than of any member, so the set is declared together in `core/domains.ts` — where adding a member means reading the others on the same screen — and imported by the modules that sign (`bundle.ts`, `cap-bridge.ts`). The transport bundle's guest program never sees one: it asks for a signature through `SIGN` and the *host* chooses the prefix from the asking bundle's slot (§12.2), so a prefix cannot be restated in content either. The Go/native target evaluates that same file through its generated bundles (§12.9) and reads its prefixes from the evaluated module, so every prefix on every target derives from this one file by construction, not by a copy that could drift. There is **no** hand-copied member anywhere — with the per-message envelope wrapper gone, so is the one AssemblyScript constant that used to restate `DOMAIN_env` by hand.
