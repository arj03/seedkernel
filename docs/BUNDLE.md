# seedkernel: bundle

*The signed bundle and the WASM modules inside it: the bytes a signer produces and any node verifies, how a node admits and loads them, and the module ABI. For a bundle author and anyone writing a signer.*

> **Part of the [seedkernel](../README.md) spec.** Section numbers are global across the doc set, so a `(§X.Y)` reference points to whichever file holds that section:
>
> [README](../README.md) §1, §10 · [ARCHITECTURE](ARCHITECTURE.md) §2, §3, §5, §12, §12.6.2b, §16.1 · **BUNDLE §3.1, §4, §12.4, §12.5, §16** · [GUEST](GUEST.md) §12.2, §12.3 · [TRANSPORT](TRANSPORT.md) §12.6.1, §12.6.2, §12.6.3 · [SECURITY](SECURITY.md) §13, §14 · [CLIENT](CLIENT.md) §12.8
>
> The envelope, the manifest and the module ABI are exact: a bundle signed by one implementation must verify, load and run on every node. Admission and loading are design, stated with their reasons.

---

## Overview

An app ships as one signed blob: a manifest, a JS guest and zero or more WASM modules. A node verifies the author's signatures, asks its operator's policy whether that author may install, builds the app's slot off to the side, and switches to it in one step. The guest is the app's logic and holds all its authority ([GUEST](GUEST.md)). The modules are pure transforms with no imports, which only that guest can call.

A bundle is a value, not a path. One blob is read from disk, carried in an app's own frame over a link, or kept in browser storage, with no second format or load path, and it verifies the same wherever it came from. So bundles travel over the same peer network as app data, and the node never has to trust the peer that delivered one.

This file follows a bundle's life:

- **§12.4 Signed bundles**: the envelope, the manifest, the author's keys and freshness.
- **§12.5 The admission policy**: who may install, and how a slot is replaced or revoked.
- **§3.1 Atomic load and replacement**: why a failed load leaves nothing behind.
- **§4 The WASM module ABI**: what a module exports, why it imports nothing, and what it may assume.
- **§16 Module limits**: the numbers every node applies alike.

---

## 12.4 Signed bundles

### Envelope

```
[suite 1 = 0x02][ed_pk 32][ml_dsa_pk 1952][ed_sig 64][ml_dsa_sig 3309][body]
body = [manifest_len u32][manifest JSON][guest_len u32][guest UTF-8]
       [module_len u32][module WASM] ...   one per manifest module, in manifest order
```

- Every length is an unsigned 32-bit big-endian byte count. There are no filenames. Missing fields or trailing bytes reject the bundle.
- **Both signatures**, Ed25519 and ML-DSA-65, are over `DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ BLAKE2b-256(body)` (§16.1). **Both must verify**, and the body is authenticated before any of it is interpreted. The signatures commit to every byte and position in the body, so there is no separate content-hash check.
- **Suite** `0x02` is the only one accepted. Another id is refused with its own error, distinct from a bad signature, and suite ids are never reused.
- **The author id** is `BLAKE2b-256(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖ ml_dsa_pk)`. Policy entries, revocations and freshness marks name it.

Why both halves must verify, why the suite byte is signed, and why the author id hashes the whole key set is §14.1. A host blob uses this same envelope under `DOMAIN_host` (§12.9).

### Author keys

An author's two keys derive from one 32-byte seed: Ed25519 from the seed itself, and ML-DSA-65 from `BLAKE2b-256(seed ‖ AUTHOR_MLDSA_SEED_LABEL)` (§16.1). The seed is the 32-byte Ed25519 seed, not libsodium's 64-byte secret key. The label is frozen and declared in one file: a copy that drifted would show up as a changed author id, so every policy entry would miss and every freshness lineage restart, and no test catches that when each copy agrees only with itself. `scripts/bundle-author.ts` is the reference signer.

### Manifest

```json
{
  "app": "chat",
  "version": 3,
  "modules": [{ "name": "codec" }],
  "protocols": ["chat"],
  "services": ["chat"],
  "guest": { "requires": ["fs", "_net"], "config": { "room": "lobby" } }
}
```

- **`app`**, required: the slot's label. One slot per label per node, whoever authored it. It names the fs and signing scopes (§5) and is what a replacement or uninstall selects. Non-empty, at most 255 UTF-8 bytes, with no control, line-separator, bidi or zero-width characters.
- **`version`**, required: a non-negative safe integer, the bundle's place in its author's sequence (Freshness).
- **`modules`**: one `{name}` per WASM module, in body order, at most `DEFAULT_MAX_BUNDLE_MODULES` (§16). A name is what the guest passes to `host.call`: unique, `[A-Za-z0-9_-]`, alphanumeric first.
- **`protocols`**: ids a **peer** may reach, and the only ids this app may send under (§12.10).
- **`services`**: ids a **co-resident guest** or the embedder may reach. A name may appear in both lists.
- **`guest.requires`**, required: everything the guest reaches. Host services by service name (`fs`, never `fs/get`) and the local service ids it calls. A method name is refused with the service to declare instead, and an unknown service is refused. Empty means no authority.
- **`guest.config`**: a JSON object handed to the guest unchanged as `APP` (§12.3). Absent means `{}`. The host reads nothing in it.

A **claim** (a `protocols` or `services` entry, or a local id in `requires`) starts with an alphanumeric or `_`, continues with alphanumerics and `._/-`, and is at most 64 bytes. A local id may not live in a host namespace (`fs/…`, `crypto/…`) or spell a module name, so the three kinds of name a guest calls stay disjoint (§12.2). No claim spelling is reserved; `_net` is the shipped transport's convention.

The host reads no WASM custom sections and nothing else in the manifest. A convention such as seedshell's `shell` entry in `guest.config` belongs to the app.

The manifest exists for three reasons:

- **The guest's authority has no other home.** A module holds no grants, so `guest.requires` is the app's entire grant, and "no authority" is a shape (an empty list) rather than a rule every target must honour.
- **Version coherence.** Nothing at the module level says "this codec and this guest belong together". The signed manifest is that statement; without it a node could hold individually valid modules never meant to run together.
- **Operator and author are different parties.** The host is one fixed artifact the operator chose; the app is third-party signed content the operator's policy admits.

Runtime facts never come from the manifest. The node key, budgets and the signing scope reach the guest from the host only (§12.3). An author who baked the signing scope into `config` would restate a load-time fact at build time, and a copy that disagreed would fail as signatures that verify nowhere, with nothing naming the cause. Execution time is the operator's for the same reason: how long this node spends on one message is a property of the deployment, not the code.

### Freshness

A node keeps one high-water mark per `(author, app)`. A bundle whose `version` is below it is refused; an equal version reloads. The mark advances only when a load commits and never rewinds; a deliberate rollback is an operator editing the store.

Versions are an author's own count (§5). The transport is keyed like any bundle, with no floor of its own: a per-slot floor would put every transport author on one version line nobody owns, so a different author's transport would have to number above a sequence it does not control.

---

## 12.5 The admission policy

Every install passes two gates, revocation then freshness, and then, for an ordinary app, the operator's predicate. A transport skips the predicate: `link` is granted only by the operator's boot selection or by replacing the slot that holds it.

**The gates are the host's because they are invariants, not posture.** A node that admits every author still has a downgrade guard and still honours revocation, and so does an interactive dialog that always says yes. Revocation comes first so a written-off key never reaches a consent prompt. Both gates run again at commit, in case a newer version landed or the author was revoked while the candidate was being built.

**The predicate is a pure function of the verified bundle**: it admits, rejects, or throws a reason, and may be asynchronous. An author allowlist, an interactive consent dialog and admit-all are all instances of it, and further checks compose as ordinary functions; the embedder supplies it (§12.8). With none, every app is refused. Verification is split from construction so a client can show a bundle's author and metadata and wait for consent before any realm or module exists. There is no per-module check: trusting an author means trusting everything they signed together.

**Contests are not gates.** The same manifest is admissible on a node where nothing holds its names, so whether a label, a claim or `link` is free is a question about the node, answered by the slot table (§12.10). Keeping it out of the predicate is what keeps the predicate a pure function of the bundle.

### Install and replacement

- **An install with no `replaces` takes a free label.** A bundle whose `app` is already installed is refused by name, whoever authored it, and so is one requiring `link`.
- **An install naming `replaces: app` takes over that slot atomically**, across authors and labels. An app candidate still needs the predicate. A candidate requiring `link` is admitted only if the slot it replaces holds `link`, so replacing an ordinary app can never acquire raw sockets.
- **A replacement takes its predecessor's label and claims, never anyone else's.** Claims the new manifest drops are released. The target is captured when the install starts and checked again at commit, so a concurrent update or uninstall fails the stale one. Any failure leaves the current owner running.

`replaces` is the only way to displace a slot, so an app's own next version and a different author's candidate take the same path. What is retired is always something the operator named, never a coincidence of keys, and two concurrent installs of one app get a refusal rather than a silent winner. The fs and signing scopes follow the label and the freshness mark follows the author (§5).

### Revocation

Revoking an author records its id as written off and uninstalls every slot admitted under it, in one action. A revoked author's bundles are refused at any version, and the runtime never un-revokes: a key survives being added back to the allowlist. An author recovers with a new key, which starts a new freshness mark and may take a label the revocation released, inheriting that label's data and scope.

- **Both halves in one action**, because either alone fails. Uninstalling leaves the thief's next bundle free to land under the label again; recording leaves the compromised code running; and an operator doing both by hand can forget one or do them in an order that leaves a window. Freshness cannot answer a stolen key, since the thief signs higher versions (§14).
- **Keyed by author, not by version range.** "This key was good through version 6" would invite rolling back under a key the operator just stopped trusting. A merely bad release is fixed by a higher version.
- **Revocation is local, not a protocol.** A signed, relayable revocation needs someone authorized to sign it: a second trust set and a second key-management problem. A fleet applies a revocation the way it applies any operator decision.
- **The emergency path is the ordinary path.** A fix is a signed bundle at a higher version. A dedicated "replace this module" seam would be a second way to occupy a slot, exercised only in a crisis and so least tested when it matters, and it would put unsigned code in a slot.

---

## 3.1 Atomic load and replacement

A load verifies and admits the bundle, builds every module and the guest's realm off to the side, writes the freshness mark, and only then, synchronously, replaces the installed slot and points its claims at the new one. The old slot is disposed after.

**Nothing is published before that commit.** A malformed module, a guest that does not compile, a declared service the node cannot back, or a failed freshness write disposes only the candidate; the running version and all its claims stay as they were. The commit contains no `await`, so a bundle that owns several claims is never observed with only some of them replaced.

**A guest's authority begins at its first invocation after commit.** The candidate evaluates its guest's top level before the commit decision, so anything that top level reached would already have happened if the load then failed. The seam therefore refuses every name until the slot is active, and disposing a candidate is a real undo because the candidate did nothing to undo. A top level may define state and validate `APP` and `LOCAL`; anything it needs the host for belongs in its first invocation.

---

## 4. The WASM module ABI

A module is a **restartable transform**: bytes in, bytes out, private memory, and no host imports. Any toolchain that can emit a module with no host imports (AssemblyScript, C, Rust, Zig) implements it with three required exports. The contract promises isolation, not statelessness or determinism: a module may keep caches and mutable state between calls, but its caller must tolerate losing that state when the instance is replaced (§4.3).

Bytes cross through a **scratch region** in the module's own memory. There is no allocator contract, no pointer crossing the boundary and no buffer lifetime to reason about: read input here, write output there, return the length.

### 4.1 Exports (module must provide)

| Export | WASM type | Meaning |
| --- | --- | --- |
| `memory` | linear memory | The module's memory, holding the scratch region. |
| `scratch` | `global i32` | Byte offset of the scratch region in `memory`. Read once after instantiation; it must not change. |
| `scratchSize` | `global i32`, optional | Bytes reserved at `scratch`. Absent means `DEFAULT_SCRATCH_SIZE` (§16); a smaller value, or one naming memory out of bounds, refuses the install. Export it only if the module really reserves that region, since the host writes there. |
| `handle` | `(i32) → i32` | `(input_len) → output_len`: transform the input at `scratch` and return the response length. |

**A call.** The host writes the input at `scratch`, calls `handle(input_len)`, and reads `output_len` bytes back from `scratch`; overwriting the input is fine. Then it wipes what input and output occupied, so neither lingers in a long-lived instance. An input larger than the scratch size is refused before the call. Returning 0 is a successful empty response; a trap, a negative length or one past the scratch size fails the call, and the guest's `host.call` rejects (§12.2).

**Declared memory is bounded, and read before instantiation.** A module must declare a linear-memory maximum. Its initial size and maximum must each fit `DEFAULT_MAX_MODULE_MEMORY_BYTES` (§16), and the maxima of all a bundle's modules together must fit it too. The limits are read off the bytes before instantiating, because instantiation is what allocates the initial memory: a module asking for 4 GiB would already have taken the host down by the time an export check could see it. A module with no declared maximum is refused, since WebAssembly gives an embedder no way to impose one afterwards. Memory must be neither imported nor shared, which keeps it private (§4.3). In AssemblyScript the maximum is one build flag, `--maximumMemory`.

**Declared tables count against the same budget.** A table is the other allocation a module buys by declaring it, so a bound on memory alone would leave the same exhaustion open under another section. Each declared element is charged `WASM_TABLE_ELEMENT_BYTES` (§16) and added to the module's memory. A table must declare a maximum, be neither imported, shared nor 64-bit indexed, and hold `funcref` or `externref`: a table the check cannot read is a table it cannot charge.

### 4.2 No host imports: the isolation boundary

A module imports nothing from the runtime. The only imports it may carry are AssemblyScript's runtime shims, `env.abort`, `env.seed` and `env.trace`, and every node resolves exactly that set and nothing else: `seed` returns a constant, `trace` drops its arguments, and `abort` traps, so a module that aborts fails its call everywhere. Any other import, WASI included, refuses the install before instantiation.

The set is fixed rather than per-target because one `trace()` or `Math.random()` anywhere in a module is the difference between loading and a missing-import failure: a node resolving a subset would refuse modules another node accepts, at instantiation, far from anything that reads like an import problem.

So a module **cannot** reach the filesystem, network, clock or any I/O; call another module or look up a name; or ask who sent its input, who signed anything or who called it. Its input carries everything it knows. When it needs the sender's identity, the guest prepends it to the input from the authenticated channel.

**Composition is the guest's job.** Feeding one module's output to another, fanning out, and doing I/O between steps all happen in the guest. Since a module cannot call back, these compose without re-entrancy: each transform returns before the next runs.

### 4.3 Safety & memory model

- **No reach.** With no host imports, a compromised module can corrupt its own state and return wrong bytes, but cannot open a socket or a file: nothing that reaches one was ever imported.
- **No cross-module corruption.** Each module runs in its own instance, and the host copies bytes between scratch regions rather than sharing pointers. No pointer crosses the boundary in either direction.
- **No durable state.** Memory beyond scratch is the module's own but not guaranteed to last. A module that runs out its time is killed and the next call gets a fresh instance, so a caller must handle a failed call and a reset. Anything that must survive belongs in the guest or in `fs`. Replay and ordering are therefore settled by the layer that owns the bytes, never by a module.

**Memory is bounded at admission; compute is bounded at the engine.** Memory is a property of the bytes, checked once on the shared admission path, so it holds identically on every target. Compute is charged to the calling guest: a module call runs under the remainder of the guest's deadline (§12.3), and when it runs out the call rejects as a trap does and the engine kills the instance. A spinning module costs at most one budget. The kill lands differently per target (a worker terminated on the JS targets, an engine context cancelled on native), which is why the ABI promises a reset and not an instance that survives. §14 has the exposure that remains.

---

## 16. Module limits

Every node applies the same numbers, because a bundle admitted on one node and refused on another is a bundle that loads by luck.

| Constant | Value | Bounds |
| --- | --- | --- |
| `DEFAULT_SCRATCH_SIZE` | `131072` (128 KiB) | scratch region of a module that exports no `scratchSize`, and the floor for one that does (§4.1) |
| `DEFAULT_MAX_MODULE_MEMORY_BYTES` | `67108864` (64 MiB) | a module's declared initial and maximum footprint, memory plus tables, and the sum of maxima across a bundle (§4.1) |
| `DEFAULT_MAX_BUNDLE_MODULES` | `256` | modules per bundle, so modules declaring no memory cannot make admission an unbounded walk (§12.4) |
| `WASM_TABLE_ELEMENT_BYTES` | `32` | bytes charged per declared table element (§4.1); conservative, as a funcref entry measures about 28 bytes on V8 and 8 in wazero |
