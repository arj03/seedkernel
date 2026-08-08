# Seed kernel — Protocol

*The message model, the module table, host-level module management, the pure-transform WASM module ABI, and layering. §16 collects the protocol constants.*

> **Part of the [seed kernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · **PROTOCOL §2–§5, §16** · [RUNTIME](RUNTIME.md) §10–§12 · [SECURITY](SECURITY.md) §13–§14

---

## 2. The message model

The host parses nothing off the wire. Its entire dispatch state is a table mapping a **name** to a **module**, and the only thing an inbound frame reaches is an app's guest (§12.10). There is no envelope format, no message header, no dispatch loop — an inbound frame is one routing lookup and one guest entrypoint call.

A "message," at the boundary the runtime cares about, is a `(protocol id, input bytes)` pair the **host** assembles. The host is the orchestrator: it receives bytes from the transport (already decrypted and attributed to a peer key, §12.6), resolves the protocol id to the app whose manifest claims it (§12.10), and invokes that app's guest `handle` entrypoint with the input (§12.2), reading the response back. The guest may compose its own modules — **pure transforms** (§4) — by calling them by name on the same `host.call` seam; neither the host nor a module sees a caller context the guest did not hand it.

That leaves three orthogonal pieces in every binding, none of which the host interprets:

- **Name** — an opaque dispatch key, a string. Its meaning is a convention (§5.1), not a host concern; the host matches names and nothing more.
- **Bytes** — the WASM module held at that name, a pure transform the host stages input into and reads output from (§4).
- **Author** — the signer of the bundle that installed the bytes. It is half of every app key (§5.1), which is the table's outer key, so the table itself carries it; the host stores and matches keys without interpreting them.

**No wire format means no host-level size cap.** The host parses nothing, so it has nothing to bound; the two bounds that exist live where the bytes actually flow — the transport caps a single frame at `MAX_FRAME_BYTES` (2 MiB, §12.6), and a module caps its own I/O region at its `scratch` size (128 KB default, §4.1). The host imposes neither; it only ever holds a name and a module.

**Authenticity is the channel's, not the host's.** Because the transport hands the host frames already authenticated to a peer key (§12.6), there is no per-message signature to check and no signature logic anywhere in the host or its modules. Signing survives in exactly two host-side places, both off the message path: the **bundle manifest** that installs code (§12.4) and the channel **AUTH** that opens a link (§12.6). An app that needs to attribute a *relayed* message to its original author — a forum or feed, where the channel only authenticates the immediate hop — carries its own per-message signature and backlinks on top (§5.1, §14); that is an app concern, not a host one.

---

## 3. The module table

The runtime has no kernel component: the **host** owns the table, and this section is what the table is and how it is maintained. It is a **named table of modules**: bind a name to a module, resolve a name to the module bound there. It holds no cryptography, no authorization, no installation logic, and no message dispatch — an inbound frame reaches an app's guest (§12.10), and a module is reached only when that guest calls one.

The table is a **contract, not an artifact**. It is this section — the table, the pure-transform ABI (§4), and the bind/unbind semantics (§3.1) — and each host implements it as one map:

```
apps[appKey][name] → module      bind / replace / resolve / remove   (§3.1)
```

`Map<string, Map<string, WasmModuleRef>>` in the JS host, `map[string]map[string]*boundModule` in the Go host. There is nothing else to instantiate beside it, no module-id indirection, no memory staging across a boundary, and no second table to keep in step with a first.

**The outer level is an install record, not a dispatch level.** `apps[appKey]` is what a bundle load created: one record per installed app, keyed by the author-derived app key (§5.1), holding the app's module map (and, in the shell, the realm its guest runs in — §12.8). Inbound dispatch resolves a protocol to an app key and stops there; it never descends into the table. The only paths *into* the module map are a guest naming one of its own modules on `host.call` (§12.2) and a host-side embedder's `callModule` — both of which name a module inside one app.

**Two levels, because there are two things.** An app is what installs, what a protocol binding points at, and what `revoke` removes; a module is what a call resolves. Flattening both into one string key would buy a single map at the cost of a codec — a charset rule so the module half could not contain the separator, a fixed-width author half so the app half could, a prefix scan for the unbind — and every one of those defends a shared namespace. There is no shared namespace: a guest reaches only its own app's modules, a binding points at an app key, and nothing on the wire names either (§5.1). Nesting the maps makes ownership the outer key, readable without parsing anything.

**Why the table is not itself a WASM module.** Compiling it would buy "one table binary, every host" — but the table is two operations, and the module *instances* it points at are per-target regardless (a `WebAssembly.Instance` in JS, a wazero `api.Module` in Go), so it could never be self-contained: each host would keep a parallel map beside it, keyed by an id invented to cross the boundary, plus the alloc/copy/call/dealloc round trip per lookup. What genuinely must not diverge between hosts is the bundle **load order** and the **admission rules**, and those *are* shared — as compiled TypeScript evaluated on every target (§12.9), where sharing pays.

**Name resolution** is two map lookups — the app, then its module. Both keys are strings (§5.1), so a module reads plainly in a log as its app key and its logical name. A module that is not a key in its app's map — or an app that is not a key at all — is unbound, and the two are the same answer.

**Unbound is a refusal on the guest seam, and no bytes on the host's.** A host-side embedder's `callModule` returns no bytes for a name absent from the table — it is the raw primitive and its caller already knows what it installed. A guest naming a module it never declared is a different event: the name is a *typo* in the one catalog, so the bridge refuses it exactly as it refuses an unknown `crypto/` name (§12.2). A module that runs and fails still answers empty, which is also what a module returning nothing says. The empty-response shape does hold one level up at the protocol routing — a protocol no installed app claims reaches no app, and the transport answers the request with an empty body rather than discarding the frame (§12.10). Nothing on either path is silently discarded, so there is no "drop" for the table to define; what the host does *not* do is produce unsolicited output, and every reply an app sends travels as a fresh frame under that app's own logic.

**No re-entrancy to reason about.** A module is a pure transform that runs to completion and returns before anything else runs (§4). Modules cannot call one another, so there is no call stack, no depth limit, no current-signer or caller state living across a call. Concurrency is the host's concern: it drives one transform at a time, typically on a single event loop.

### 3.1 Host-level module management

The table has two mutating operations, and they are the **same unit** — an app:

```
bindAll(appKey, [{name, wasm}, ...])   admit a bundle's modules, all or none   (the loader's)
removeApp(appKey)                      drop one app and everything it landed    (the shell's)
```

**The bind belongs to the loader, and there is only one.** Nothing hands the host a ready-made module to drop into a slot, and there is no per-module install: the sole caller is the loader's admission (§12.4), which reaches `bindAll` only after the manifest signature and the policy have both passed, and hands it a whole bundle's modules at once. A bundle may declare no modules at all — a guest-only app — in which case `bindAll` creates the app's record with an empty map (§12.4). So every entry in the table is a bundle module admitted under a verified manifest — there is no second kind of occupant, and no question of who authored what a call resolves to, because the author is half of the key it sits under (§5.1). That is what makes "one install path" (§1) literally true rather than nearly true.

**The bind is atomic, and it is visibly so.** `bindAll` builds the app's whole module map first — validating each against the §4 ABI, releasing whatever it had already built if any fails — and then assigns it under the app key. The commit is one assignment, so a partially-installed bundle is not a state a caller has to avoid reaching; it is one that cannot be expressed. This matters most where a wasm instance is a real resource: on a host whose modules are not garbage-collected, the release path is the host's own, so no target can forget it.

Binding an occupied app **replaces its whole module map**, which is what a version of an app is — a bundle that drops a module from its manifest leaves nothing of the old one behind. This is how a same-author, higher-`version` bundle lands (§12.4). It is internal to the host process, never reachable from an inbound frame or from a WASM module; the host controls access through its own authentication (process permissions, operator console, HSM), and the host defines no access-control policy for it.

**The unbind belongs to the shell, and its unit is the same app.** `removeApp` deletes the key — the shell's `uninstall`, and `revoke`'s teardown of everything a written-off key landed (§12.5). There is no single-module remove: a module is not a unit anything installs, so it is not one anything revokes either.

**Dropping an app drops only that app.** There is no side table to keep in step, and no shared namespace for a freed entry to be contended for — an app key can only be derived by the author whose public key is half of it (§5.1) — so an unbind cannot hand anything to anyone, the misattribution a stale ownership record would invite has no way to arise, and there is no tombstone: the key accepts the author's next bundle immediately.

### 3.2 Growth is the loader's job, not the host's

Most deployments grow by loading signed bundles (§12.4), not by wiring every module by hand. The bundle loader admits a bundle's modules — a policy decision (§12.5) followed by one `bindAll` under the app key it derives from the manifest (§5.1). None of that is the table's: admission is host-side, off any wire path, and the table sees only the resulting bind. Frozen-config deployments load no bundles and grow no further.

**Standing a host up.** Because the table is a map rather than an artifact, there is no bootstrap sequence to speak of: ready libsodium, construct the host, and the table is live — empty, resolving nothing. Growth is then two ordered steps, and the order is the only constraint: wire an admission policy (§12.5), then load a bundle (§12.4). A host whose policy is never wired is not misconfigured but *frozen* — deny-all is the default, so it boots, serves, and admits nothing (§14). There is no step for instantiating a table binary, seeding a signature module, or wiring a slot by hand.

Because the loader verifies the manifest signature before it admits anything, "who authored this code" is already settled by an ordinary signature check (§12.4). Installation is not a special operation; it is `apps[appKey].modules[name] = wasm_bytes`, gated by the author + hash policy (§12.5).

---

## 4. The WASM module ABI

A module is a **pure transform**: bytes in, bytes out, no reach beyond the buffer it is handed. Any language that compiles to WASM (AssemblyScript, C#, Rust, C, Zig, Go) can implement the contract — it is three exports and no imports.

Modules exchange bytes with the host through a **scratch region** in their own linear memory. There is no allocator contract, no pointers crossing the boundary, no buffer lifetimes to reason about — just "read input here, write output there, return the length."

### 4.1 Exports (module must provide)

| Export name | WASM type | Description |
| --- | --- | --- |
| `memory` | linear memory | Module's memory; the host reads input from and writes output to the scratch offset within it. |
| `scratch` | `global i32` | Byte offset into `memory` where the host places input and reads output. Set once during instantiation; the host reads it once after instantiation and the module MUST NOT change it afterward. |
| `scratchSize` | `global i32` *(optional)* | Bytes of scratch the module reserves at `scratch`. The host reads it once at instantiation and clamps its input/output copies to it; a value below the 128 KB default or naming out-of-bounds memory is refused fail-loud (the install throws). Export it only if the module genuinely reserves that region — the host writes there. |
| `handle` | `(i32) → i32` | `(input_len) → output_len` — transform the input at `scratch` and return the response length. |

**Declared memory is bounded.** A module MUST declare a linear-memory **maximum**, and both its initial size and that maximum MUST fit the host's per-module budget (`MAX_MODULE_MEMORY_BYTES`, §16). The loader reads the limits off the module bytes *before* instantiating it (`wasm-limits.ts`), because instantiation is what allocates the declared initial memory — a module asking for 4 GiB has already taken the host down by the time an export check could see it. A module that declares no maximum is refused: WebAssembly gives an embedder no way to impose one afterwards, so an undeclared maximum is an unbounded one. Two further refusals fall out of the same read and defend §4.3's claims rather than a budget: an **imported** memory (a module imports nothing, §4.2) and a **shared** one (a module's memory is private to it).

For AssemblyScript that requirement is one build flag, `--maximumMemory` (in pages).

**I/O protocol.** Before each call, the host writes the input bytes at offset `scratch` (up to the configured scratch size — default 128 KB, or the module's exported `scratchSize`). The module reads its input from `scratch`, writes its response back at `scratch` (overwriting the input is fine), and returns the number of response bytes. Return `0` for "empty response." The host reads `output_len` bytes at `scratch` after `handle` returns and does not touch the region again until the next call; a trap or a negative/oversized length is a failure the host reads as "no response."

Memory outside the scratch region is the module's private state — statics, globals, whatever allocator it wants for its own bookkeeping. None of that is exposed to the host.

### 4.2 No imports — the pure-transform boundary

A module imports **nothing from the runtime** — no host seam, no host functions. The only imports it carries are its own language runtime's shims (for AssemblyScript, `env.abort` / `seed` / `trace`), which are not a route to the outside world.

**Every target resolves exactly that set, and every member of it is inert.** `abort` traps, `seed` is a constant rather than a clock read, and `trace` drops its arguments — so the shims cost the module its determinism nowhere and give it no effect beyond the bytes it returns (§4.3). The set is fixed rather than per-target because one `trace()` or `Math.random()` anywhere in a module is the difference between loading and a missing-import failure: a host resolving a subset would refuse modules another host accepts, and would do it at instantiation, far from anything that reads like an import problem.

Concretely, a module **cannot**:

- reach the filesystem, network, clock, or any I/O;
- call another module, or resolve a name — it cannot reach the table, and has no cross-module call;
- ask who sent the input, who signed anything, or who called it — there is no signer, no caller, no author query.

Everything a transform needs arrives **in its input**, and everything it produces leaves **in its output**. When a message must carry the sender's identity to the module, the orchestrator prepends it to the input from the authenticated channel (§12.6) — as the chat app does, staging `senderPk ‖ body` (§11). This is the boundary that makes the sandbox trivial to reason about: a module that can only read its input and write its output has no confused-deputy surface, no ambient authority, nothing to revoke.

**Composition is the guest's job.** Chaining transforms — running one module's output into another, fanning out, doing I/O between steps — is the app's guest (or a host-side embedder), never a module's. A guest reaches its own modules through the cap-bridge by their bare names (§12.2); the host-side equivalent is `callModule(appKey, name, bytes)`. Because a module cannot call back, these compose without re-entrancy: each transform returns before the next runs.

### 4.3 Safety & memory model

What a module **cannot** do, restated as guarantees:

- **No outside-world reach.** With no imports (§4.2), a module's only effect is the bytes it returns. It cannot open a socket or a file even if compromised — not by a rule in its code, but because the capability was never imported.
- **No cross-module corruption.** A buggy or malicious module can scribble anywhere in its own memory but cannot touch the host or another module — each runs in its own WASM instance, and the host copies bytes between scratch regions rather than sharing pointers.
- **No pointers cross the boundary.** There is no allocator contract; the host never holds a pointer into a module's memory across a return and never writes outside the scratch region.

> **Memory is bounded; compute is still the host's problem.** They are two residuals rather than one, because only one of them has a mechanism.
>
> **Memory** is closed at admission: a module declares its ceiling and the loader refuses anything above the host's budget, or anything that declares no ceiling at all (§4.1). The check is a property of the bytes, so it holds identically on every target — it runs on the shared admission path (§3.2), not in each host's instantiation code.
>
> **Compute** is not, and cannot be here: WASM engines on the JS platform expose no fuel or timeout mechanism, so this protocol specifies none. Nothing on the message path does asymmetric crypto or recurses, and a module runs only when its app's guest calls it (§12.10): inbound frames enter under the guest's execution budget first (§12.3), so the unbounded segment is reachable only through a guest calling one of its own modules — but a module can still infinite-loop and hold the single-threaded host forever, and a permissive policy (§12.5) multiplies that across many installs. Deployers exposed to runaway modules should run the host in a Worker with a watchdog, or pre-validate bytecode in the admission policy (forbid unbounded loops) before installing. Note the asymmetry with the confined JS guest, which *does* have an execution budget (§12.3): QuickJS offers an interrupt hook where WebAssembly offers nothing.

**Replay and ordering are settled off the module.** A module is stateless-by-input, so it has no notion of "seen this before." Where that matters, the defence lives at the layer that owns the bytes: live-traffic replay is closed by the transport's strict per-direction counter (§12.6), and an older install is refused by bundle freshness (§12.4). An app that **relays** messages through intermediaries — where neither of those applies to the original author — adds its own per-message signature and backlink chain (§5.1, §14). None of it is the host's or the module's concern.

---

## 5. Layering and composition

Modules form an onion — the stack diagram in §1 draws it: each layer depends only on the layers below it, and no layer has a hard dependency on the ones around it. The onion is a typical composition, not a required one; every layer is independently usable.

### 5.1 Modules in the reference implementation

| Layer | Modules | What lives there |
| --- | --- | --- |
| **Host table** | the host's `apps[appKey][module]` map | The name → module table and its two lookups (§3). No crypto, no I/O, no dispatch — an app's guest is what an inbound frame reaches (§12.10). |
| **Cap-bridge** | Cap-bridge (host-side) | The `host.call(name, bytes)` seam a confined guest reaches its I/O through — the only outward reach the guest has (§12.2). |
| **App** | [seedchat](https://github.com/arj03/seedchat) (§11), [seed store](https://github.com/arj03/seedstore) — both live outside this repo | A confined JS guest (the app's logic) over its pure-transform WASM modules — delivered as one signed bundle (§12.4). |

Each layer is testable standalone: the table is exercised on its own, the loader against a bundle with no live transport, chat as a guest over a handful of pure transforms with no crypto in sight. Composition across layers is the guest's (or a host-side embedder's), through `callModule` / a guest`s bare-name `host.call` (§4.2) — never a module reaching sideways.

**The hash function used for id derivation.** Two places hash: `bytes_hash` (§12.4) and any allowlist that pins a binary. Both mean **BLAKE2b-256** — the *genesis hash*, computed host-side by `genesisHash` (libsodium's core `crypto_generichash`). There is exactly one hash across the whole system: the same BLAKE2b-256 is the `blake2b-256` entry of the primitive catalog a guest reaches by name (§12.1), the AKE KDF and transcript hash (§12.6), and the block-id path. Swapping it shifts every `bytes_hash` — but **app keys and module names are literal ASCII, not hashes**, so no table key shifts with it. Pick the genesis hash once and treat it as a deployment-wide constant.

**Names are strings.** A name is an opaque string the host only ever matches — nothing forces a hash, so a name reads plainly in a log and in a manifest.

**A name is node-local.** Nothing on the wire ever names another node's module. A peer sends an application-level id or opcode — the chat demo's frame carries a *protocol id* (§11), a storage message carries its protocol op — and the receiving host resolves that (§12.10) to whichever of its installed apps claims it; a confined guest reaches its own modules by the logical name from its manifest through `host.call`, against the app key its bridge was built with — so the guest never names an app at all. So names must be unambiguous within one node, not agreed across a deployment. Two hosts that bound the same code under different app names interoperate fine, and a host may hold two independent implementations of one protocol at once.

**There is no composite name to derive.** A module is addressed by two values that already exist: the **app key** `"<author hex>:<app>"` (§12.4) and the **logical name** the manifest declares for the module. Neither is invented at bind time and neither is declared as a bind name, so a manifest holds nothing to forge — both are covered by the author's signature. There is no second namespace to keep disjoint from this one, because there is no second way to bind (§3.1).

Encoding the two into one string — `"<author hex>:<app>:<module>"` — would oblige everything downstream to decode it again: a fixed-width author half so the app half may contain colons, a charset rule so the module half may not, and a last-colon split to read the parts back out. Nesting the maps means the structure is simply there. The app key itself keeps its fixed-length author prefix regardless, so `"<author hex>:<app>"` stays unambiguous with an `app` free to contain `:`.

The author is the **full** hex, never a truncated prefix. A short prefix would be grindable: an admitted author could generate a key matching another's first bytes and land on their app. App keys are node-local table keys that never travel, so their length costs nothing but log width.

**Ownership is structural.** Because the author is *in* the name, one author's names are unreachable to another — a second author shipping an app called `chat` derives entirely different names and binds alongside, never over. The default policy (§12.5) therefore constrains nothing about names and needs no per-name state to consult: it decides *who* may install, and the derivation does the rest. Squat-resistance is a property of the namespace rather than a rule something has to enforce, and "which of the apps I hold receives a given protocol's messages" is a separate, user-owned decision (§12.10) rather than a race to claim a name.

**Relayed-message apps layer their own authenticity.** The channel authenticates one hop (§12.6). An app whose messages pass through intermediaries — a feed, a forum, store-and-forward gossip — cannot let the channel speak for the *original* author, so it becomes its own layer: a per-message signature naming the author, plus **backlinks** (a hash-chain, à la [SSB](https://ssbc.github.io/scuttlebutt-protocol-guide/)'s `previous` or [Bamboo](https://github.com/AljoschaMeyer/bamboo)'s lipmaa links) to order the history and make equivocation detectable. Signed bundles (§12.4) already do the author half for relayed *code*; a relayed-message app does the same one layer up, and it is a distinct app from chat, whose every message travels a single hop (§14 has the rationale for keeping lineage out of the loader).

---

## 16. Protocol constants

All limits and reserved values in one place. Multi-byte integers are big-endian throughout the protocol.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| `DEFAULT_SCRATCH_SIZE` | `131072` (128 KB) | Module instantiation | Per-module I/O region at `scratch`; a module may declare more via `scratchSize` (§4.1). |
| `MAX_MODULE_MEMORY_BYTES` | `67108864` (64 MiB) | Bundle admission (`installBundle`) | Ceiling on a module's declared initial *and* maximum linear memory, read off the module bytes before instantiation (§4.1). A module above it, or declaring no maximum, is refused. A host may hold its own direct installs to something tighter; none may be looser about what a bundle may land. |

A name absent from the table resolves to an **empty response**, never an error (§3). The host enforces nothing else — no magic, no version, no size cap; the transport and the module own those bounds (§2).

### 16.1 Runtime (shell) constants

These belong to the reference runtime (§12), not the §3 table contract — a different shell could change them without breaking anything the table sees, but they are wire- or ABI-visible to bundles and peers of *this* runtime.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| Author id | 32 bytes | Manifest envelope (§12.4) | The Ed25519 public key under manifest suite `0x01`; under the hybrid suite `0x02`, `genesisHash(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖ ml_dsa_pk)` over the whole key set, so the identity is unreachable without both private keys. 32 bytes either way, which is what keeps name derivation (§5.1), policy files and freshness marks suite-agnostic. The paired genesis hash is BLAKE2b-256, the one system hash (§5.1). |
| Cap names | `crypto/*`, `node/*`, `net/*`, `fs/*`, `clock/now`, `timer/*`, `link/*`, `transport/*`, plus the bare names of the calling bundle's own modules (`codec`, `ws`, …) | cap-bridge (§12.2) | Guest↔host name identifiers, a flat catalog of opaque strings — the keys of the cap-bridge's dispatch table plus the asking app's module map — the same shape as `PRIMITIVE_NAMES`. No op numbers, no generated preamble, never sent between nodes. **Every host name contains a `/` and no module name can** (`[A-Za-z0-9_-]`, §12.4), so one `host.call` covers all three sources and the dispatch tells them apart by the name alone. Neither the `crypto/` prefix nor a bare module name is a grant at all — the primitive seam, not a capability: the first resolves in a fixed host catalog, the second in the bundle's own module map. |
| Manifest requires | `AUTHORITY_CALLS` (`core/domains.ts`): the authorities above, and nothing else | manifest `guest.requires` (§12.4) | Exactly the authorities a guest holds — the whole of what it needs *granted*, in the one vocabulary. A granted authority is granted BY NAME: the bridge refuses any `host.call` that is not exactly one of the declared names. An unknown name throws at load. Only **authorities** are grants — each reaches something no confined module can hold. `link/*` (bytes over an opaque link id) and `transport/*` (the attributed peer, protocol id and correlation the transport provides back) are the transport's: a manifest naming them is governed by `transportAuthors` and mounted as the node's transport rather than bound as an app, and one naming names under some but not all of the two prefixes is refused as malformed (§12.2, §12.5). The ungated names a guest also calls (`crypto/*`, its own modules) are **not declarable** — neither can be absent from a host, so a manifest naming one is refused rather than accepted as a no-op; `guest.abi` is what versions them. |
| Primitive catalog | `blake2b-256`, `ed25519/verify`, `xchacha20/xor`, `chacha20poly1305-ietf/{seal,open}`, `x25519/dh`, `ml-kem-768/{keypair,encaps,decaps}` | manifest `guest.requires`, cap-bridge `crypto/` prefix (§12.1, §12.2) | The names the `crypto/` prefix dispatches through (`PRIMITIVE_NAMES`, `core/domains.ts`). Every entry is a function of its arguments — no host key, no entropy, no state — so nothing gates it and a new algorithm is a catalog entry rather than an op number, an ABI rev or a grant. A manifest's declaration is a **compatibility** check: a host missing a name refuses the load by name. |
| Guest ABI | `3` | manifest `guest.abi` (§12.4) | Which host seam a guest was written against (`GUEST_ABI_VERSION`, §12.2). Required — every bundle declares a guest (§12.4); a value this host does not implement is refused by name, like an unsupported suite. Tracks changes to the seam's *shape* — the naming scheme of `host.call`'s first argument, a name moving across the sync/async line, a payload framing change — not the appending of new names, which a guest that never calls them cannot notice. |
| Transport mount | names under both `link/` and `transport/` | shell (§12.4, §12.5) | What makes a bundle the node's transport, on the one install path: the shell verifies it, admits it under `transportAuthors` (never the app allowlist), and stands the driver up instead of binding protocols. The manifest has **no role field** — the requires already carry the fact, and the signature already covers them. Naming them is not a way in: it moves a bundle onto the stricter list. Freshness is the ordinary `(author, app)` mark, so each author of the transport keeps their own version lineage. |
| Manifest envelope | `0x01`: `[suite 1][ed_pk 32][ed_sig 64][json]` <br> `0x02`: `[suite 1][ed_pk 32][ml_dsa_pk 1952]`<br>`[ed_sig 64][ml_dsa_sig 3309][json]` | `loadBundle` (§12.4) | Fixed width per suite. `0x01` signs `DOMAIN_manifest ‖ suite ‖ json`; `0x02` signs `DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ json` with **both** keys and requires **both** to verify. The suite byte is stored *and* signed, so a verifier may read it for field widths before verifying and still cannot have it edited under them (§14.1). |
| Link messages | msg1 81 B, msg2 80 B, msg3 112 B, msg4 112 B, then AEAD records | transport bundle (§12.6) | **A message is a bare body.** Which one it is follows from the reader's role and progress — the initiator reads msg2 then msg4, the responder msg1 then msg3, and every message after authentication is a record. The state is the reader's own, so a sender cannot steer which path a message takes: a handshake message is accepted only at its exact width, and a post-authentication one has the AEAD open as its single destination. Neither identity crosses the wire in the clear. |
| Algorithm suites | channel `0x02` · manifest `0x01`, `0x02` | msg1 byte 0 (§12.6) · manifest byte 0 (§12.4) | **Two independent namespaces on independent clocks** — channel (`0x02`: Ed25519 identity · ephemeral X25519 · contact secret · ChaCha20-Poly1305) and manifest (`0x01`: Ed25519 detached; `0x02`: hybrid Ed25519 + ML-DSA-65, both required); never read one as the other. The channel is at `0x02` because the cleartext-identity genesis suite `0x01` was **removed, not disabled**: a node accepting both would have the concealment of the weaker one. The manifest namespace moved for its own reason — it is the one that cannot be migrated cheaply later (§14.1) — which is what independent clocks look like in practice. Neither namespace is negotiated — one suite per link, one per manifest, unknown ids refused (silently, on the channel). Each is covered by the signature it accompanies, so a suite is chosen by an endpoint and never forced in flight (§14.1). |
| `DOMAIN_manifest` | `"seedkernel-manifest-sig-v1\0"` | Manifest signature (§12.4) | Domain-separation prefix for the signed bundle-manifest JSON. Prepended before signing, not stored. |
| `DOMAIN_manifest_author` | `"seedkernel-manifest-author-v1\0"` | Author id derivation (§12.4) | Prefixes the key material a multi-key suite's 32-byte author id is hashed from. The one member of the family that prefixes a *hash* rather than a signature; it is in the family because it must be disjoint from every signing prefix, so a derived id can never also be something someone signed. |
| `DOMAIN_guest` | `"seedkernel-guest-sig-v1\0"` | Cap-bridge `node/sign`/`node/verify` (§12.2) | Domain-separation prefix for guest-obtainable signatures, followed by the host-derived scope `author_pk ‖ app_len u8 ‖ app` from the admitted manifest. Prepended before signing *and* verification (host-applied on both), never transmitted. |
| `DOMAIN_channel` | `"seedkernel-channel-id-v1\0"` | Handshake signature and transcript (§12.6) | Domain-separation prefix, used both to seed the transcript hash and as the prefix of each identity signature `DOMAIN_channel ‖ transcript ‖ own_id`. Not transmitted. |
| Contact secret | 32 bytes, out of band | msg1 seal, every handshake KDF (§12.6.3) | Per node, distributed with its address; a caller that cannot produce it draws no response. Never on the wire. Absent = open node. |
| Network key | 32 bytes, config | transcript root (§12.6.3) | Which network this node belongs to — staging vs production. **Public by design**: an isolation boundary, not access control. Applied as a prologue, so every key and every signature preimage differs between networks. |
| Master seed | 32 bytes, on disk | `subkeys.ts` (§12.6.2b) | The node's only stored secret. Signs nothing; derives the `channel` keypair (whose public half is the peer id) and the `guest` keypair (cap-bridge `node/sign`) under versioned labels. |
| Node address | `pk[.secret]@host:port` | `parsePeerSpec`, `parseWsPeer` (§12.6) | The peer's Ed25519 identity, optionally that peer's contact secret, and where to reach it. The pk is **routing** — it keys the address book so dial-by-identity has something to look up — and the secret is the **credential**. No long-term Diffie–Hellman key is published, so a PQ suite will not change the format. |
| `MAX_FRAME_BYTES` | `2097152` (2 MiB) | socket seams (§12.6) | Hard cap on one link frame, enforced on the length prefix (TCP) or frame length (WS) **before** buffering — bounds what an unauthenticated peer can make a node allocate from a single prefix. Both transports cap identically, so a frame that crosses one crosses the other. The transport does not fragment, so this is also the largest application message a node can send. Two things move with it: `ws.wasm` stages a whole frame in a scratch region it allocates at init, and since it rides in the transport bundle every shell pays that region whether or not it speaks WebSocket; and the Go loader keeps its own copy (`native/net.go`). Raising it means rebuilding `ws.wasm`, which `tests/transport.test.mjs` asserts rather than leaves to memory; a single deployment may lower its own cap with `TransportHostOptions.maxFrameBytes`. |
| `MAX_HANDSHAKE_FRAME_BYTES` | `8192` (8 KiB) | the transport bundle's framers (§12.6.2) | Inbound frame cap **before** a link authenticates, raised to `MAX_FRAME_BYTES` on authentication — the host declares both numbers and the bundle learns them at init (§12.1). Applying the full application cap to an unauthenticated peer would be a memory hole: a stranger knowing only `host:port` could declare a large frame, dribble the body, and hold that much memory — times the half-open budget. No handshake message today exceeds 113 bytes; the headroom over that is deliberate, so an ML-KEM-768 encapsulation key (1,184 bytes) does not need a core rev to become expressible (§14.1). |
| `MAX_QUEUE_BYTES` | `1048576` (1 MiB) | transport bundle (§12.6) | Total bytes of frames buffered pre-auth; oldest dropped once the sum would exceed it. A byte bound (not a frame count) so pre-auth buffering is capped regardless of frame size. |
| `MAX_HALF_OPEN_UNVERIFIED` | `1024` | half-open limiter (§12.6.2) | Connections accepted but not yet proved to hold the contact secret. A full budget **evicts the oldest**, it does not refuse the newest — refusing would let a flood shut members out at the door, before they could prove they belong. Such a connection costs no asymmetric crypto: the ephemeral keypair is generated only once msg1 opens. |
| `MAX_HALF_OPEN_VERIFIED` | `256` | half-open limiter (§12.6.2) | Connections that have produced our contact secret and are mid-handshake. A separate budget, so no volume of connections without the secret can keep members from handshaking. |
| `MAX_HALF_OPEN_PER_SOURCE` | `8` | half-open limiter (§12.6.2) | Per-`remoteAddr` bound across both budgets. Deliberately **not** evictable: one address at its own limit is refused outright, never allowed to push a different address out — so saturating the unverified budget needs 128 distinct sources. |
| `UNVERIFIED_TIMEOUT_MS` | `2000` ms | transport bundle (§12.6.2) | How long an accepted connection has to send a msg1 that opens. Short because it covers one message from a peer that has already connected. Leaks nothing: observing the longer deadline requires the contact secret. |
| `HANDSHAKE_TIMEOUT_MS` | `10000` ms | transport bundle (§12.6) | Deadline for the rest of the handshake, armed once msg1 opens. Every pre-auth refusal is silent and simply lets this expire. |
| `REKEY_AFTER_FRAMES` | `16777216` (2²⁴) | transport bundle records (§12.6) | Frames per epoch before the sending direction ratchets its key. Must match on both ends; a mismatch desynchronises the link. |
| `REJECT_AFTER_EPOCHS` | `65536` (2¹⁶) | transport bundle records (§12.6) | Epoch ceiling. Reaching it retires the link — a deliberate shutdown that announces itself, not a fault — rather than producing a record under a repeated nonce. |
| Transport frame kinds | `req 0x00`, `res 0x01`, <br>`FLAG_NO_REPLY 0x80` | transport bundle (§12.6) | Single request/response plane, carried inside the §12.6 AEAD record layer. A req names a protocol id so a node hosting several apps can route it (§12.10). `FLAG_NO_REPLY` is OR'd into the kind byte for fire-and-forget sends: the receiver still dispatches to the app but skips the response frame. |
| `DEFAULT_REQUEST_DEADLINE_MS` | `10000` ms | transport driver (§12.6) | How long one request may take before it settles as unreachable, for a caller that names no deadline of its own. A **deadline is per request, not per node**: only the caller knows whether it sent a 200-byte control message or a 4 MB block, so `request(to, proto, payload, deadlineMs)` takes one and this is merely the fallback (operator default `requestDeadlineMs`, CLI `--request-deadline`). App guests take it as-is — `net/send` carries no deadline — which is why it is generous rather than tight. |
| Guest execution budget | `5000` ms | Confined realm (§12.3) | Per entrypoint invocation, measured over guest **run** time rather than wall clock: a guest parked awaiting a host bridge spends none of it. Exceeding it interrupts the guest, which surfaces to the caller as a thrown error; on the native target the interruption terminates the realm rather than throwing inside it (§14). Operator-set (`guestDeadlineMs`, CLI `--guest-timeout`), not author-declared; `Infinity` — CLI `0` — disables it. The realm heap cap alongside it is 64 MiB (`realmMemoryBytes`, CLI `--guest-memory`, in MiB). |

**The `DOMAIN_*` family lives in one file.** The four prefixes above are a *family*, and the only thing they are for is disjointness: no signature made under one may verify under another, over any bytes, ever — and no derived id may collide with a signed preimage. That is a property of the whole set rather than of any member, so the set is declared together in `core/domains.ts` — where adding a member means reading the others on the same screen — and imported by the modules that sign (`bundle.ts`, `cap-bridge.ts`). The transport bundle's guest program never sees one: it asks for a signature through `node/sign` and the *host* chooses the prefix from the asking bundle's slot (§12.2), so a prefix cannot be restated in content either. The Go/native target evaluates that same file through its generated bundles (§12.9) and reads its prefixes from the evaluated module, so every prefix on every target derives from this one file by construction, not by a copy that could drift. There is **no** hand-copied member anywhere.
