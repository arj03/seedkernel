# Seed kernel — Protocol

*The message model, the kernel's handler table, host-level `SetHandler`, the pure-transform WASM handler contract, and layering. §16 collects the protocol constants.*

> **Part of the [seed kernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · **PROTOCOL §2–§5, §16** · [BOOTSTRAP](BOOTSTRAP.md) §9 · [RUNTIME](RUNTIME.md) §10–§12 · [SECURITY](SECURITY.md) §13–§14

---

## 2. The message model

The kernel parses nothing off the wire. Its entire state is a table mapping a **name** to a **handler**, and its entire job is to resolve a name to the handler bound there. There is no envelope format, no message header, no dispatch loop — the routing decision is one lookup in `handlers` (§3).

A "message," at the boundary the runtime cares about, is just a `(name, input bytes)` pair the **host** assembles. The host is the orchestrator: it receives bytes from the transport (already decrypted and attributed to a peer key, §12.6), decides which name to route them to, resolves that name through the kernel, and invokes the handler — a **pure transform** (§4) — with the input, reading its output back. The kernel never sees where the bytes came from, who sent them, or what they mean.

That leaves three orthogonal pieces in every binding, none of which the kernel interprets:

- **Name** — an opaque dispatch key, a string. Its meaning is a convention (§5.1), not a kernel concern; the kernel matches names and nothing more.
- **Bytes** — the WASM handler held at that name, a pure transform the host stages input into and reads output from (§4).
- **Author** — the signer of the bundle that installed the bytes, recorded host-side in the loader's install record (§12.4). The kernel never learns it.

**No wire format means no kernel-level size cap.** The old envelope's 64 KB ceiling is gone with the envelope; the two bounds that remain live where the bytes actually flow — the transport caps a single frame at `MAX_FRAME_BYTES` (16 MiB, §12.6), and a handler caps its own I/O region at its `scratch` size (128 KB default, §4.1). The kernel imposes neither; it only ever holds a name and a handler.

**Authenticity is the channel's, not the kernel's.** Because the transport hands the host frames already authenticated to a peer key (§12.6), there is no per-message signature to check and no signature logic anywhere in the kernel or its handlers. Signing survives in exactly two host-side places, both off the message path: the **bundle manifest** that installs code (§12.4) and the channel **AUTH** that opens a link (§12.6). An app that needs to attribute a *relayed* message to its original author — a forum or feed, where the channel only authenticates the immediate hop — carries its own per-message signature and backlinks on top (§5.1, §14); that is an app concern, not a kernel one.

---

## 3. The kernel

The kernel is a **named table of handlers**: bind a name to a handler, resolve a name to the handler bound there. It holds no cryptography, no authorization, no installation logic, and no message dispatch. The host resolves a name and invokes the handler itself.

The kernel is a **contract, not an artifact**. It is this section — the table, the pure-transform ABI (§4), and the `SetHandler` semantics (§3.1) — and each host implements it as one map:

```
handlers[name] → handler    bind / replace / resolve / remove   (§3.1)
```

`Map<string, handler>` in the JS host, `map[string]*entry` in the Go host. There is no kernel module to instantiate, no handler-id indirection, no memory staging across a boundary, and no second table to keep in step with a first. §1's vision sentence — "installing a handler is nothing more than `handlers[name] = wasm_bytes`" — is literally the implementation.

**Why the table is not itself a WASM module.** Compiling it would buy "one kernel binary, every host" — but the table is two operations, and the handler *instances* it points at are per-target regardless (a `WebAssembly.Instance` in JS, a wazero `api.Module` in Go), so it could never be self-contained: each host would keep a parallel map beside it, keyed by an id invented to cross the boundary, plus the alloc/copy/call/dealloc round trip per lookup. What genuinely must not diverge between hosts is the bundle **load order** and the **admission rules**, and those *are* shared — as compiled TypeScript evaluated on every target (§12.9), where sharing pays.

**Name resolution** is one map lookup. Names are strings (§5.1), so a bootstrap name reads plainly in a log and a scoped name is the hex a manifest already carries. A name that is not a key in the table is unbound.

**"Drop" semantics.** Throughout this document, **drop** means "silently ignore: no response is generated, no error is propagated to the sender." An unbound name is dropped by the host. The kernel never produces unsolicited output; every reply an app sends travels as a fresh frame under that app's own logic.

**No re-entrancy to reason about.** A handler is a pure transform that runs to completion and returns before anything else runs (§4). Handlers cannot call one another, so there is no call stack, no depth limit, no current-signer or caller state living across a call — all of which earlier revisions carried and none of which exists now. Concurrency is the host's concern: it drives one transform at a time, typically on a single event loop.

### 3.1 Host-level handler management (`SetHandler`)

The host manages the table through two operations:

```
SetHandler(name, handler)    install or replace the handler for name
SetHandler(name, null)       remove it
```

`SetHandler` installs or replaces in place, so the table never holds two entries for one name. Together these are the **only** way handlers enter or leave it — no install message, no privileged "register" path, no protected-vs-unprotected distinction; every entry arrived the same way. The reference host exposes them as `register(name, jsHandler)` / `installBundleModule(...)` / `removeHandler(name)`. What sits at a name is either a JS closure or an instantiated WASM handler; the table is indifferent, because both are reached the same way — by name, through `callHandler`.

`SetHandler` is internal to the host process — a direct method call, never reachable from inbound frames or from a WASM handler. The host controls access through its own authentication (process permissions, operator console, HSM); the kernel defines no access-control policy for it. Handlers seeded this way directly (rare — most deployments install nothing by hand and grow only through bundles, §9) have **no install record** — the loader's records (§12.4) cover only bundle-admitted modules.

The same call the host uses during bootstrap (§9) stays available afterward for emergency replacement of any handler. Ordinary growth loads a signed bundle (§12.4); the host-level `SetHandler` path is the emergency fallback for cases the message pipeline can't reach.

**Replacing recorded names.** The kernel never touches an install record — it does not know records exist (§12.4). But a stale `(author, bytes_hash)` left behind by a raw replacement would misattribute the slot: the old author would apply to brand-new bytes, so the default policy would treat the next same-name install as a same-author upgrade of code it never signed. So the host's handler-management path auto-clears any record when it (re)binds or removes a slot — `register` / `installBundleModule` and `removeHandler` all do. A `SetHandler` replacement thus always runs with no record (a later bundle load may wire a fresh one), needing no separate `remove(name)` first; the loader's `remove(name)` (§12.5) remains the path for operator revocation, where clearing the record is the point.

### 3.2 Growth is the loader's job, not the kernel's

Most deployments grow by loading signed bundles (§12.4), not by wiring every handler by hand. The bundle loader admits each verified module — a policy decision (§12.5) followed by `SetHandler` — and holds the install records `(author, bytes_hash)` that back it. None of that is the kernel's: admission is host-side, off any wire path, and the kernel sees only the resulting bind. Frozen-config deployments load no bundles and grow no further.

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
| `scratchSize` | `global i32` *(optional)* | Bytes of scratch the handler reserves at `scratch`. The host reads it once at instantiation and clamps its input/output copies to it; when absent (or below the 128 KB default, or naming out-of-bounds memory) the default is used. Export it only if the handler genuinely reserves that region — the host writes there. |
| `handle` | `(i32) → i32` | `(input_len) → output_len` — transform the input at `scratch` and return the response length. |

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

> **Compute and memory exhaustion are the host's problem.** WASM engines on the JS platform expose no fuel/timeout mechanism, so this protocol specifies none. Nothing on the message path does asymmetric crypto or recurses, but an installed handler can still infinite-loop or declare a huge linear memory and OOM the single-threaded host — and a permissive policy (§12.5) multiplies that across many installs. Deployers exposed to runaway handlers should run the host in a Worker with a watchdog and pre-validate bytecode in the admission policy (cap declared memory, forbid unbounded loops) before installing.

**Replay and ordering are settled off the handler.** A handler is stateless-by-input, so it has no notion of "seen this before." Where that matters, the defence lives at the layer that owns the bytes: live-traffic replay is closed by the transport's strict per-direction counter (§12.6), and an older install is refused by bundle freshness (§12.4). An app that **relays** messages through intermediaries — where neither of those applies to the original author — adds its own per-message signature and backlink chain (§5.1, §14). None of it is the kernel's or the handler's concern.

---

## 5. Layering and composition

Modules form an onion — the stack diagram in §1 draws it: each layer depends only on the layers below it, and no layer has a hard dependency on the ones around it. The onion is a typical composition, not a required one; every layer is independently usable.

### 5.1 Modules in the reference implementation

| Layer | Modules | What lives there |
| --- | --- | --- |
| **Kernel** | the host's `handlers` map | The name → handler table and its one lookup (§3). No crypto, no I/O, no dispatch. |
| **Cap-bridge** (optional) | Cap-bridge (host-side) | The `host.call(op, bytes)` seam a confined guest reaches its I/O through — the only outward reach the guest has (§12.2). |
| **App** | Chat (§11), [seed store](https://github.com/arj03/seedstore) | Pure-transform WASM handlers plus, optionally, a zero-authority JS guest — delivered as a signed bundle (§12.4). |

Each layer is testable standalone: the kernel is exercised on its own, the loader against a bundle with no live transport, chat as a handful of pure transforms with no crypto in sight. Composition across layers is the host's or the guest's, through `callHandler` / `MODULE_CALL` (§4.2) — never a handler reaching sideways.

**The hash function used for id derivation.** A few places hash: `bytes_hash` (§12.4), the app-name derivations a policy may choose (`hash(canonical ‖ author_pubkey)`, below), and any allowlist that pins a binary. Throughout, `hash(…)` means **BLAKE2b-256** — the *genesis hash*, computed host-side by `genesisHash` (libsodium's core `crypto_generichash`). There is exactly one hash across the whole system: the same BLAKE2b-256 backs the guest `HASH` op (§12.2), the AKE KDF and transcript hash (§12.6), and the block-id path. Swapping it shifts every `bytes_hash` — but the **bootstrap names are literal ASCII, not hashes**, so they do *not* shift, and the §9 seeds survive the swap untouched. Pick the genesis hash once and treat it as a deployment-wide constant.

**Names are strings.** A name is an opaque string the kernel only ever matches — nothing forces a hash, so a name can read plainly in a log and in a manifest. **Bootstrap handlers:** `name = "seedkernel.bootstrap.v1:" + canonical_name`. These names are host-seeded via `SetHandler` (§3.1) when a deployment wires a handler by hand, not admitted through the loader, so there is no install record to mix in. The chat shell uses the same helper (`deriveBootstrapName`) to derive an *app's* kernel name from its id, so two peers running the same app route to the same name (§11).

**Naming convention for app handlers:** free-form within whatever the policy approves. The default policy (§12.5) places no constraint on names beyond uniqueness — the first author to bind a name owns it, and only that author can update it. Deployers who want author-scoped namespaces (so two parties can each have their own `chat` without conflict) can require names of the form `hex(hash(canonical ‖ author_pubkey))` in their admission policy (the host's `deriveScopedName` computes exactly that — a hash rendered as hex, since a name is a string). The kernel is indifferent.

**Relayed-message apps layer their own authenticity.** The channel authenticates one hop (§12.6). An app whose messages pass through intermediaries — a feed, a forum, store-and-forward gossip — cannot let the channel speak for the *original* author, so it becomes its own layer: a per-message signature naming the author, plus **backlinks** (a hash-chain, à la [SSB](https://ssbc.github.io/scuttlebutt-protocol-guide/)'s `previous` or [Bamboo](https://github.com/AljoschaMeyer/bamboo)'s lipmaa links) to order the history and make equivocation detectable. Signed bundles (§12.4) already do the author half for relayed *code*; a relayed-message app does the same one layer up, and it is a distinct app from chat, whose every message travels a single hop (§14 has the register-vs-log rationale).

---

## 16. Protocol constants

All limits and reserved values in one place. Multi-byte integers are big-endian throughout the protocol.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| `DEFAULT_SCRATCH_SIZE` | `131072` (128 KB) | Handler instantiation | Per-handler I/O region at `scratch`; a handler may declare more via `scratchSize` (§4.1). |

A name absent from the table is **dropped** by the host (§3). The kernel enforces nothing else — no magic, no version, no size cap; the transport and the handler own those bounds (§2).

### 16.1 Runtime (shell) constants

These belong to the reference runtime (§12), not the kernel protocol — a different shell could change them without breaking anything the kernel sees, but they are wire- or ABI-visible to bundles and peers of *this* runtime.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| Author key | 32-byte Ed25519 public key | Install record (§12.4) | An author *is* a key: Ed25519 is the only signing algorithm the runtime uses, so a record carries the raw public key and no algorithm id. The paired genesis hash is BLAKE2b-256, the one system hash (§5.1); together they are the whole genesis — one verifier, one hash, both compiled into the host. |
| Cap op ids | `1`–`16` | cap-bridge (§12.2) | Guest↔host op identifiers, contiguous and grouped by domain (§12.2); regenerated with the guest preamble, never sent between nodes. |
| Capability domains | `crypto`, `net`, `fs`, `module`, `clock` | manifest `caps` (§12.4) | An unknown domain throws when the guest realm is built. |
| Manifest envelope | `[pk 32][sig 64][json]` | `loadBundle` (§12.4) | Ed25519 detached signature over `DOMAIN_manifest ‖ json`. |
| Link message tags | `HELLO 0x01`, `AUTH 0x02`, `FRAME 0x03` | `PeerLink` (§12.6) | AKE handshake + encrypted frame plane; HELLO carries the ephemeral X25519 key, FRAME bodies are AEAD records. |
| `DOMAIN_manifest` | `"seedkernel-manifest-sig-v1\0"` | Manifest signature (§12.4) | Domain-separation prefix for the signed bundle-manifest JSON. Prepended before signing, not stored. |
| `DOMAIN_guest` | `"seedkernel-guest-sig-v1\0"` | Cap-bridge `SIGN` (§12.2) | Domain-separation prefix for guest-obtainable signatures, followed by the host-derived scope `author_pk ‖ app_len u8 ‖ app` from the admitted manifest. Prepended before signing, not transmitted. |
| `DOMAIN_channel` | `"seedkernel-channel-id-v1\0"` | AUTH signature (§12.6) | Domain-separation prefix for the signed AKE transcript (both identities, nonces, and ephemeral keys). Not transmitted. |
| `MAX_FRAME_BYTES` | `16777216` (16 MiB) | `PeerLink` framing (§12.6) | Hard cap on one link frame, enforced on the length prefix (TCP) or frame length (WS) **before** buffering — bounds what an unauthenticated peer can make a node allocate from a single prefix. Both transports cap identically, so a frame that crosses one crosses the other. |
| `MAX_QUEUE_BYTES` | `1048576` (1 MiB) | `PeerLink` (§12.6) | Total bytes of frames buffered pre-auth; oldest dropped once the sum would exceed it. A byte bound (not a frame count) so pre-auth buffering is capped regardless of frame size. |
| Transport frame kinds | `req 0x00`, `res 0x01` | `Transport` (§12.6) | Single request/response plane, carried inside the §12.6 AEAD record layer. |
| Default request timeout | `2000` ms | shell boot (§12.8) | Response deadline before a peer counts as unreachable (`--timeout`). |

**The `DOMAIN_*` family lives in one file.** The three prefixes above are a *family*, and the only thing they are for is disjointness: no signature made under one may verify under another, over any bytes, ever. That is a property of the whole set rather than of any member, so the set is declared together in `host/domains.ts` — where adding a fourth means reading the other three on the same screen — and imported by the modules that sign (`bundle.ts`, `cap-bridge.ts`, `net-link.ts`). The Go/native target evaluates that same file through its generated bundles (§12.9) and reads its prefixes from the evaluated module, so every prefix on every target derives from this one file by construction, not by a copy that could drift. There is **no** hand-copied member anywhere — with the per-message envelope wrapper gone, so is the one AssemblyScript constant that used to restate `DOMAIN_env` by hand.
