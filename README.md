# Seed kernel: a tiny message kernel that bootstraps into a sandboxed app runtime

*Everything is a message. An auditable-in-one-sitting kernel grows from one trusted key into arbitrary behaviour — untrusted code runs sandboxed (WASM handlers or confined JS), anywhere from a browser tab to a single native binary.*

## 1. Vision

A minimal runtime where **everything is a message**. The kernel does one thing: parse an envelope and dispatch it to a handler registered under a **name**. Signing, authorization, capability gating, and application logic are **modules** — layers that compose around the kernel like an onion. Installing a handler is nothing more than `handlers[name] = wasm_bytes`; there is no separate "install protocol," just a signature to check and a policy to consult. The system bootstraps from one trusted key (or no key at all, if that's what you want) into arbitrarily complex behaviour without the kernel knowing what any of it means.

**The whole runtime is four components.** Everything after this table is detail:

| Component | Role |
| --- | --- |
| **Kernel** | Routes names to handlers — a flat `handlers[name]` table plus dispatch (§3). No signature logic, no install messages, no mutation during dispatch: the table changes only through the host-level `SetHandler` (§3.1). |
| **Host** | The runtime around the table — the same shared JS on every target (browser, Node, or QuickJS inside the native binary, §12.9). It provides the `signature` handler as built-in host code — parse the outer wrapper, verify via a WASM suite slot, re-dispatch the inner envelope (§6) — and `loadBundle`, the single admin path that admits new code (§12.4). |
| **WASM suites** | Pure cryptographic verifiers at conventional slot names (§6.4, §6.6). They know nothing about envelopes, signers, or kernels — bytes in, valid/invalid out. |
| **Bundles** | The only way code arrives (§12.4): a manifest, WASM modules, a guest program, and one author signature over the whole set. The host checks that signature against the operator's policy (§12.5) and binds each module into the flat table through the module registry (§7). |

```
external world ──► signed bundle (version + manifest + WASM modules + guest)
                       │
                       ▼
                policy check — authorized author? fresh version?     (§12.4–§12.5)
                       │
                       ▼
                installDirect → SetHandler — flat-table update       (§7.2)
                       │
       …the node now runs the app; each signed message then flows:
                       │
                       ▼
                host signature handler — parses the wrapper, calls
                a suite slot, re-dispatches the inner envelope       (§6.3–§6.5)
                       │
                       ▼
                WASM suite slots — pure crypto, no envelope logic    (§6.6)
```

There are no special cases and exactly one way to do everything: one install path (signed bundles, §12.4), one signature per message (§2.3), one guest seam (`host.call`, §12.2), one post-handshake frame plane (§12.6).

Every binding is three orthogonal pieces: the **name** is the kernel's opaque dispatch key, the **bytes** are the WASM instance held at that key, and the **author** is the signer who installed it — a record in the registry, invisible to the kernel. The signature module identifies authors; the host-side registry binds names to bytes under a deployer-supplied **policy** that decides who may install what.

**Design principles:**

- The kernel is small enough to audit in a single sitting — one file, no cryptography, no authorization, no installation logic.
- The kernel makes one routing decision: look up the name and invoke the handler. Everything else, including how new handlers get installed, is a module concern.
- Modules form layers. Lower layers (signatures, installation) gate higher layers (apps like chat). Each layer can only see downward.
- Modules are independently usable — each is a standalone WASM module testable in isolation; nothing forces you to use them together.
- Untrusted code runs confined — a WASM handler reaches the outside world only through bridges it is pinned to, and logic too dynamic for WASM runs as zero-authority JavaScript in a QuickJS realm whose only reach is a single `host.call` seam.
- Node-to-node links are confidential by default — the runtime transport opens each connection with an authenticated key exchange, then carries every frame as a forward-secret, individually-authenticated encrypted record, uniform across TCP, WebSocket, and WebRTC and needing no external TLS or Noise tunnel.
- The same envelope works for tiny JSON payloads and large binary blobs.
- Cryptographic algorithms are pluggable; the kernel can survive a post-quantum transition without a protocol rewrite.
- The kernel compiles to WebAssembly, so the same kernel runs unmodified in every host — browser, server runtime, or a single native binary.

The reference composition stacks app modules → module registry → signature → kernel; §5 diagrams it.

---

### 1.1 Concepts at a glance

A reader's-digest mental model; full details follow in §2–§9.

- **Envelope** — `magic | version | name_len | name | payload` (§2). The kernel's only routing decision is `handlers[name]`.
- **Name** — opaque dispatch key; convention `"seedkernel.bootstrap.v1:" + canonical` (literal ASCII) for bootstrap handlers, free-form for apps under the policy's discretion.
- **Handler** — a WASM module that exchanges bytes with the host through a fixed scratch offset in its own memory (§4).
- **Signing is a wrapper, not a header field.** A signed message is an outer envelope with `name = signature` whose payload carries `(algo_id, signer, sig, inner_envelope)` (§6.3). The handler at that name is an ordinary one — no special status in the kernel.
- **Author** — the signer of the current dispatch, read via `kernel.call(signature.signer, …)` (§6.5).
- **Module registry** — host-side state that holds install records `(author, bytes_hash)` and runs a deployer-supplied policy callback whenever the bundle loader admits a module (§7). It is state the loader drives, not a wire protocol.
- **Policy callback** — the only authorization decision point. Reference policy: deployer chooses who may claim a name first; subsequent binds at that name require the same author (§7.4).
- **Bridges** — `SetHandler`-installed handlers that pin the caller names they serve; the only code that performs real I/O (§8).
- **Bootstrap** — host wires kernel, signature, and (optionally) the registry; growth then happens by loading a higher-version signed bundle (§9).
- **Runtime / shell** — the deployable artifact: kernel + signature + the module registry under a policy, plus raw-byte capability backends (`crypto`, `net`, `fs`, `module`, `clock`) and a zero-authority JS confinement host. It loads a **signed bundle** and *becomes* that app — chat (§11) and [seed store](https://github.com/arj03/seedstore) are two (§12).
- **Bundle** — an app as signed content: an author-signed manifest committing to each module's hash, a guest program, and the capability domains the guest is granted. The loader verifies each module against its committed hash and installs it directly (§12.4) — no per-module install envelope.
- **Guest** — zero-authority JS confined in a QuickJS realm; its only reach is the `host.call(op, bytes)` seam into the cap-bridge, restricted to the domains its bundle's manifest declares (§12.2–§12.3).

**Want to see it run?** Build the WASM artifacts (see `WASM/package.json` scripts), then either run `node WASM/tests/run.mjs` for the end-to-end test + 10k-message benchmark, or serve `WASM/browser/` over HTTPS and open `chat-shell.html` in two browsers for a P2P chat demo (§11). The worked-example trace in §13 walks through the same pipeline byte-by-byte.

## 2. The Envelope

Every message shares a single envelope format. The envelope carries the bare minimum the kernel needs: a routing key (`name`) and an opaque payload. The kernel's only job is to look up the handler for the name and invoke it.

```
┌───────────────────────────────────────────────────────┐
│ magic: 2 bytes          (0x5344 — ASCII "SD")         │
│ version: 1 byte         (0x01)                        │
│ name_len: 1 byte                                      │
│ name: [var bytes]       (opaque dispatch key)         │
│ payload: [remainder of buffer]                        │
└───────────────────────────────────────────────────────┘
```

Four bytes of fixed header, then the name, then the payload runs to the end of the buffer. The total envelope (all fields) must not exceed 65,536 bytes (§2.2). `name_len` must be at least 1; a zero-length name is invalid and will be rejected by the kernel.

| Field | Size | Description |
| --- | --- | --- |
| `magic` | 2 bytes | `0x5344` — identifies a seed kernel envelope |
| `version` | 1 byte | Protocol version (`0x01`) |
| `name_len` | 1 byte | Length of the name (1–255 bytes; `0` is invalid) |
| `name` | variable | Opaque dispatch key; meaning is a convention, not a kernel concern |
| `payload` | to end | The message body — handler-defined |

The kernel does not interpret the payload. Installation, signature wrapping, capability declarations, and every other piece of structure live inside the payload of some specific name and are the concern of the handler registered for that name, not the kernel.

### 2.1 Signing is a wrapper, not a field

To sign a message, you wrap an envelope inside another envelope whose `name` is `signature`. The outer payload carries the algorithm id, signer pubkey, the signature, and the inner envelope bytes. The `signature` handler re-dispatches the inner envelope after verifying. Wire layout and details are in §6.3.

This makes signing **opt-in per message**: you can have unsigned messages alongside signed ones, and a different wrapper kind (say an encryption layer) can wrap or be wrapped without ever changing the envelope format. Signing itself is a **single** wrapper — one signature per message (§2.3); hybrid post-quantum signatures are a **composite suite** (§6.4), both signatures in one suite payload, not nested wrappers.

### 2.2 Maximum message size (64 KB)

The kernel enforces a hard upper bound of **65,536 bytes** on the total envelope (header + name + payload). The kernel rejects any buffer larger than this limit before parsing.

**Rationale.** Signature verification dominates per-message cost (§10). Capping the envelope at 64 KB bounds the worst-case data a `verify` call must process, keeping per-message latency predictable and preventing a single oversized message from stalling the pipeline. For use cases that need to reference large data (files, images, firmware blobs), the payload carries a **content hash** — the digest of the external data under the envelope's signature suite — and consumers retrieve the actual bytes from an external store. The signature still covers the hash, so integrity is preserved end-to-end; the kernel just never has to move the bulk data through its dispatch path.

This limit applies to the **outermost** envelope on the wire. For signature wrappers (§2.1), the 64 KB budget includes the outer framing, the signature fields, and the complete inner envelope. Implementations should account for wrapper overhead — ~140 bytes for Ed25519 over the 33-byte literal-ASCII `signature` name (4 envelope header + 33 name + 2 algo + 2 signer_len + 32 pubkey + 2 sig_len + 64 sig), larger for PQ suites — when sizing inner payloads.

The 64 KB limit is a protocol constant, not a per-deployment configuration knob. Keeping it fixed avoids interoperability splits where one node accepts messages another rejects.

**The cap never constrains module or suite size.** Code never arrives on the wire — a WASM module is delivered in a signed bundle (§12.4) and installed via `SetHandler` from a verified local file, off the dispatch path — so the cap, a bound on inbound `verify` work, does not apply to it. Signature suites are no exception: even post-quantum ones (ML-DSA, Falcon, SLH-DSA), whose verify-only builds run to tens of kilobytes, are ordinary bundle modules, and the genesis suite is seeded host-side (§3.1, §9).

### 2.3 One signature per message

A message carries **at most one** signature. The host drops any `signature` envelope whose inner envelope is *itself* a `signature` envelope — nesting is not allowed, so exactly one signature wraps any message (§6.5).

**Rationale.** Each signature wrapper costs one verify (~95 µs for Ed25519 on a modern core). Per-wrapper overhead is ~140 bytes for Ed25519 (§2.2), so if wrappers could nest, a 64 KB envelope could stack ~475 of them and force that many verifies (~45 ms CPU) from one tiny input — a CPU-amplification DoS against the single-threaded dispatch loop. Forbidding nesting makes that vector **unrepresentable** rather than merely capped: the host records the verified signer of the current dispatch and refuses a second `signature` wrapper while one is already set, so the check is a single null test and costs no verify.

Use cases one might reach a wrapper stack for are served better without one: a hybrid Ed25519+post-quantum signature is a **composite suite** (§6.4) — one `algo_id`, both signatures in one suite payload, verified by one suite handler — which fits the suite-slot model exactly and needs no wrapping-order convention to get right.

---

## 3. The kernel

The kernel has one message-driven path: parse an envelope and dispatch its payload to the handler registered for the name. It also exposes `SetHandler` (§3.1) — a host-level method for directly installing or replacing any handler. `SetHandler` is the **only** install path the kernel knows about; the host-side module registry (§7) drives it under a policy when a signed bundle is loaded. There is no install *message* — installation is a host call, not a wire protocol.

**"Drop" semantics.** Throughout this document, **drop** means "silently ignore: no response is generated, no error is propagated to the sender." Implementations MAY log or meter dropped messages but MUST NOT return a synchronous error or surface a side-effect. The kernel never produces unsolicited responses — every reply travels in a fresh envelope under the relevant app handler's policy.

```
dispatch(bytes):
  if len(bytes) > MAX_ENVELOPE_BYTES:                 drop
  envelope = parse(bytes)
  if envelope == null:                                drop  // bad magic, version, name_len, or truncation
  if handlers[envelope.name] is null:                 drop
  handlers[envelope.name](envelope.payload)
```

A module can call another module using `kernel.call`. The kernel knows nothing about signers, authors, or capabilities — that state lives in the signature handler (§6.5) and the module registry (§7). Any handler that needs to know who signed the current message calls `kernel.call` to `signature.signer`.

**Single-threaded dispatch.** A kernel instance dispatches one message at a time. The current signer (§6.5), the call-depth counter, and the caller stack (used by `kernel.caller`) are all per-instance; the host MUST NOT enter `dispatch` re-entrantly except via `kernel.call`. Concurrent inbound traffic is the host's concern — typically by serializing onto a single event loop or running independent kernel instances per worker.

```mermaid
flowchart TD
    IN["Incoming bytes"] --> SIZE{"len ≤ 64 KB?"}
    SIZE -->|"no"| DROP["Drop"]
    SIZE -->|"yes"| PARSE["Envelope.Decode"]
    PARSE -->|"malformed"| DROP
    PARSE --> LOOKUP["handlers[name]"]
    LOOKUP -->|"not found"| DROP
    LOOKUP -->|"found"| HANDLER["Handler"]
```

### 3.1 Host-level handler management (`SetHandler`)

The kernel exposes a single method for the host to manage handlers directly:

```
kernel.SetHandler(name, handler)
```

`SetHandler` installs or replaces the handler for `name` (null removes it); replace is in-place, so the kernel never holds two entries for one name. It returns nothing — a side-effecting primitive on the handler table. The reference host wraps it with a thin `host.register(name, handler) → handlerId` that allocates an internal handler id (used by `host.blockFromCall`, §4.4) before calling `SetHandler`.

`SetHandler` is the only way handlers enter or leave the table — no install message, no privileged "register" path, no protected-vs-unprotected distinction; every entry arrived the same way. Handlers seeded directly (the bootstrap handlers, §9) have **no install record** — they are invisible to the registry (§7). Attribution and policy are the host's concern; the kernel just stores the function pointer.

Because these directly-seeded handlers have no install record, their name is not in any bridge's pinned-caller list; see §8 for why this means bootstrap handlers cannot reach any I/O bridge.

`SetHandler` is internal to the host process — a direct method call, never reachable from inbound messages or WASM handlers. The host controls access through its own authentication (process permissions, operator console, HSM); the kernel defines no access-control policy for it.

The same call the host uses during bootstrap (§9) remains available afterward for emergency replacement of any handler, including bootstrap handlers like `signature`. Ordinary growth loads a signed bundle (§12.4); the host-level `SetHandler` path is the emergency fallback.

**Replacing registry-managed names.** The kernel never touches an install record — it does not know records exist (§7.1). But a stale `(author, bytes_hash)` left behind by a raw replacement would misattribute the slot: the old author would apply to brand-new bytes, so the reference policy would treat the next same-name install as a same-author upgrade of code it never signed. So the host's handler-management path auto-clears any record when it (re)binds or removes a slot — `SetHandler`/`register` and `removeHandler` all do. A `SetHandler` replacement thus always runs with no record (a later bundle load may wire a fresh one), needing no separate `installer.remove(name)` first; `installer.remove` (§7.5) remains the path for operator revocation, where clearing the record is the point.

### 3.2 The module registry (optional)

Most deployments grow by loading signed bundles (§12.4), not by wiring every handler by hand. The bundle loader admits each verified module through a small host-side **module registry**: it holds the install records `(author, bytes_hash)` and runs a deployer-supplied policy callback before each `SetHandler` call. The registry is not part of the kernel — it is host-side state (`host/installer.ts`) the loader calls, not a wire protocol. Frozen-config deployments simply skip it and grow no further.

The registry is described in detail in §7. Its surface is two ideas:

- **`installDirect(name, wasm, author)`** binds a `name` to WASM bytes. The bundle loader calls it once per module, with the manifest author.
- **A policy callback** decides whether to honor each bind. The reference policy is in §7.4.

Because the manifest signature is verified by the loader before it ever calls `installDirect`, "who authored this code" is already settled by an ordinary signature check — the same signature machinery every message uses (§6). Installation is not a special operation; it is `handlers[name] = wasm_bytes`, gated by author + hash policy.

---

## 4. WASM Handler Contract

All WASM interfaces are specified as raw WASM function signatures. Any language that compiles to WASM (AssemblyScript, C#, Rust, C, Zig, Go) can implement these.

Handlers exchange messages with the host through a **scratch region** in their own linear memory. There is no allocator contract, no pointers crossing the boundary, no buffer lifetimes for the handler author to reason about — just "read input here, write output there, return the length."

### 4.1 Exports (handler must provide)

| Export name | WASM type | Description |
| --- | --- | --- |
| `memory` | linear memory | Handler's memory; the host reads input from and writes output to the scratch offset within it. |
| `scratch` | `global i32` | Byte offset into `memory` where the host places input and reads output. Set once during instantiation; the host reads it once after instantiation and the handler MUST NOT change it afterward. |
| `scratchSize` | `global i32` *(optional)* | Bytes of scratch the handler reserves at `scratch`. The host reads it once at instantiation and clamps its input/output copies to it; when absent (or below the 128 KB default, or naming out-of-bounds memory) the default is used. Export it only if the handler genuinely reserves that region — the host writes there. |
| `handle` | `(i32) → i32` | `(input_len) → output_len` — process the message at `scratch` and return the response length. |

**I/O protocol.** Before each call, the host writes the input bytes at offset `scratch` (up to the configured scratch size — default 128 KB, or the handler's exported `scratchSize`, set per handler at instantiation). The handler reads its input from `scratch`, writes its response back at `scratch` (overwriting the input is fine), and returns the number of response bytes. Return `0` for "no response." The host reads `output_len` bytes at `scratch` after `handle` returns and does not touch the region again until the next call.

Memory outside the scratch region is the handler's private state — statics, globals, whatever allocator it wants for its own bookkeeping. None of that is exposed to the host.

### 4.2 Imports (host provides to handler)

The host exposes these under the import module `"kernel"`. These are the **only** host imports — everything else (author queries, capability lookups, logging) is accessed via `kernel.call` to the appropriate module.

| Import name | WASM signature | Description |
| --- | --- | --- |
| `call` | `(i32, i32, i32, i32) → i32` | `(name_ptr, name_len, payload_ptr, payload_len) → response_len` — synchronous dispatch to the handler registered for the given name. The four pointers are into the **caller's own memory** (anywhere the caller likes). The response is written into the caller's scratch region; the return value is the response length, or `-1` on error (no handler registered, call depth exceeded, response too large for caller's scratch). See §4.4. |
| `caller` | `(i32) → i32` | `(out_ptr) → len` — writes the **immediate caller** at `out_ptr` as `[name_len u8][name bytes]`: the name of the handler whose `kernel.call` reached this one. `[0x00]` (single byte, `name_len = 0`) means no caller — the handler was reached by direct envelope dispatch, not through `kernel.call`. Only the immediate caller is exposed, never the deeper chain: bridge authorization (§8.1) is on this name, and exposing nothing else makes treating a non-immediate frame as authoritative *impossible* rather than merely forbidden. It reflects `kernel.call` only; signature-wrapper re-dispatch starts a fresh context (its lineage is the current signer, §6.5). A host that wants a full call-chain audit trail logs it host-side; it routes every `kernel.call` and already holds the chain. |

### 4.3 Safety & memory model

What a handler **cannot** do:

- Access the filesystem, network, or clock. The only outside-world reach is `kernel.call` to other handlers; bridges (handlers that perform real I/O) additionally require the caller to be one they serve — each bridge pins the caller names it answers for (§8). The default is no reach; a bridge only serves callers it explicitly pins.
- Allocate memory across the boundary. There is no allocator contract — every cross-module byte lives in one handler's scratch and is copied by the host into another's. The host never holds a pointer into a handler's memory across a return, and never writes outside the scratch region.
- Corrupt anything outside its own scratch and private memory. A buggy or malicious handler can scribble in itself but cannot touch the host, the kernel, or another handler.

What a handler **must** internalize:

- Memory is bounded by what the WASM module declares (and the host engine's own limits); the kernel imposes no per-handler cap.
- A `kernel.call` overwrites your scratch with the callee's response. If you still need the input, copy it first (§4.4).

> **Compute and memory exhaustion are the host's problem.** WASM engines on the JS platform expose no fuel/timeout mechanism, so this protocol specifies none. The single-signature rule (§2.3), the call-depth cap (§4.4), and the 64 KB limit (§2.2) bound verify-amplification and recursion, but an installed handler can still infinite-loop or declare a huge linear memory and OOM the single-threaded host — and a permissive registry (§7.4) multiplies that across many installs. Deployers exposed to runaway handlers should run dispatch in a Worker with a watchdog and pre-validate bytecode in the policy callback (cap declared memory, forbid unbounded loops) before installing. The kernel bounds call depth but not per-handler time or memory.

### 4.4 Synchronous cross-module calls (`kernel.call`)

`kernel.call` performs a synchronous dispatch to the handler registered for the given `name`. The host wires the two handlers together by copying through their scratch regions:

1. Host reads `name_len` bytes from caller memory at `name_ptr`, and `payload_len` bytes at `payload_ptr`. (These pointers are into caller memory — anywhere the caller put them; they do not need to be in scratch.)
2. Host looks up the target handler. If none is registered, returns `-1`.
3. Host writes the payload bytes into the target's scratch region and calls `target.handle(payload_len)`.
4. Target reads input, writes response at its own scratch, returns `response_len`.
5. Host reads `response_len` bytes from the target's scratch and writes them into the caller's scratch region.
6. Host returns `response_len` to the caller. The caller reads its response from its own `scratch` offset.

**Semantics:**

- The callee sees raw payload bytes at its scratch — there is no envelope wrapping. Routing is by `name` only.
- The callee cannot distinguish an inbound envelope from a `kernel.call`. It sees input at scratch and writes output at scratch.
- Calls are **re-entrant**: A can call B can call C. The host enforces a maximum call depth (default 8); exceeding it returns `-1`.
- **A non-empty callee response overwrites the caller's scratch.** A handler that still needs its input across a `kernel.call` must copy it to private memory first. A `0`-byte response leaves scratch untouched, so callers MUST NOT rely on `kernel.call` to clear it; a handler holding secrets there must zero them itself.
- If the callee's response exceeds the caller's scratch size, the host returns `-1` and writes nothing. Tune scratch size per handler if you expect large responses.

**Handlers blocked from `kernel.call`.** Some handlers MUST cause `kernel.call` to return `-1` *before* the target is invoked. The check belongs at the call router (the host's `kernel.call` import), not inside the handlers.

1. **The `signature` wrapper** — it does not mutate persistent state, but accepting it records the signer and re-dispatches the inner envelope under it. Allowing it via `kernel.call` would let an arbitrary handler reframe the active signer mid-chain and break the "signer = author" rule.
2. **Any deployer-added state mutator** — a handler that calls `kernel.SetHandler` or edits the registry's records under the signer's authority (e.g. a `bootstrap.replace` handler, §9.1). Without the block, an in-handler `kernel.call` could mutate kernel state under the current signer without that signer's intent.

Blocked handlers run only at top-level dispatch, where the signature wrapper has already verified the outer signature. Read-only queries (`signature.signer`) remain freely callable.

The reference bootstrap installs **no** state-mutating wire handler — code arrives as a signed bundle (§12.4), not a wire message — so the standing blocklist holds only `signature`. A deployer who adds a mutating handler MUST mark it blocked via `host.blockFromCall(handlerId)` immediately after `host.register`.

**Replay protection is an application concern.** The kernel has no state-mutating wire handler and no `seq` table — installation is a host call under the bundle loader (§12.4), not a signed message. But a signed *app* envelope replayed verbatim re-verifies and re-dispatches byte-identically; its signature stays valid forever, so anyone who saw the bytes can resend them. Whether that matters is app-specific: an idempotent handler (appending a chat line, say) can ignore replays; a handler whose payload changes state (transferring an asset, casting a vote, charging an account) MUST defend itself. The usual mechanism is a `seq` field consumed before the action, against a per-`(handler, signer.pubkey)` high-water mark keyed on the canonical pubkey — the app picks the field's placement, the counter's storage, and whether related handlers share a map. Stronger needs (exactly-once across a partition, freshness windows) layer a nonce/timestamp/challenge scheme on top; the kernel exposes no clock. A deployer who adds a state-mutating wire handler (§9.1) inherits the same duty.

---

## 5. Layering and composition

Modules form an onion: each layer wraps the layers above it and depends only on the layers below (§1). No layer has a hard dependency on the layers around it — the onion is a typical composition, not a required one.

```
┌──────────────────────────────────┐
│   App modules                    │
│   (chat, …)                      │
│                                  │
│   handlers dispatched normally   │
├──────────────────────────────────┤
│   I/O bridges (optional)         │
│   (net, ui, fs, clock, …)        │
│                                  │
│   SetHandler-installed           │
│   caller-name pinned             │
├──────────────────────────────────┤
│   Module registry (optional)     │
│                                  │
│   host-side, not a wire layer    │
│   runs policy callback           │
│   holds (author, bytes_hash)     │
│         records                  │
├──────────────────────────────────┤
│   Signature                      │
│                                  │
│   signature wrapper              │
│   the current signer             │
├──────────────────────────────────┤
│   Kernel                         │
│                                  │
│   envelope parsing               │
│   dispatch by name               │
└──────────────────────────────────┘
```

### 5.1 Modules in the reference implementation

A one-line per layer index — full details live in §6 (Signature), §7 (Module registry), §8 (Bridges), and §11 (App examples).

| Layer | Modules | What lives there |
| --- | --- | --- |
| **1: Signature** | Signature | Algorithm suites, the current signer, wrapper verification. |
| **2: Module registry** | Registry (host-side) | The install records and the policy callback. `installDirect` binds a verified bundle module; no wire message. |
| **3: I/O bridges** | Deployer-defined (`net.send`, `ui.write`, `fs.read`, `clock.now`, …) | The only code that performs real I/O. `SetHandler`-installed, each pinning the caller names it serves. |
| **4: App modules** | Chat (example) | User-facing handlers delivered in a signed bundle (§12.4). |

Each module is in its own file and can be used standalone — the signature handler is testable on the kernel alone, the registry is testable without bridges, and chat is just a handler testable without signatures. Inter-module queries go through `kernel.call` to the target module's name (e.g. `signature.signer`); install records are read host-side, not over the wire (§7.6).

**The hash function used for id derivation.** A few places hash: `bytes_hash` (§7.1), the app-name derivations a policy may choose (`hash(canonical || author_pubkey)`, below), and any allowlist that pins a binary. Throughout, `hash(…)` means the **genesis suite's hash** (§6.2) — the only hash guaranteed at boot; in the reference implementation SHA-3-256 (32 bytes). Swapping the genesis suite swaps that hash, so every `bytes_hash` shifts — but the **bootstrap and suite slot names are literal ASCII, not hashes**, so they do *not*, and the §9 seeds survive a genesis swap untouched. Pick the genesis suite once and treat it as a deployment-wide constant.

**Naming convention for bootstrap handlers:** `name = "seedkernel.bootstrap.v1:" + canonical_name` — the **literal ASCII string**, not a hash. Names are opaque bytes, so nothing forces a hash; a readable name reads plainly in logs and keeps the bootstrap namespace independent of the genesis hash (only `bytes_hash` earns that dependency, §14). Suite slots follow the same rule at `"seedkernel.suite.v1:" + algo_id_hex` (§6.4). These handlers are host-seeded via `SetHandler` (§3.1), not admitted through the registry, so there is no install record to mix in.

**Naming convention for app handlers:** free-form within whatever the policy approves. The reference policy (§7.4) places no constraint on names beyond uniqueness — the first author to bind a name owns it, and only that author can update it. Deployers who want author-scoped namespaces (so two parties can each have their own `chat` without conflict) can require names of the form `hash(canonical || author_pubkey)` in their policy callback. The kernel is indifferent.

---

## 6. The signature module

This is where pluggable signatures live. The signature module dispatches verification to pluggable **algorithm suites** — each an ordinary handler (§6.6) installed at a conventional suite-slot name and selected by `algo_id` — and owns the `signature` name, a wrapper format that lets any envelope be signed.

### 6.1 Algorithm suite

An algorithm suite is a bundle of:

| Operation | Purpose | Example (suite 0x0000) |
| --- | --- | --- |
| `hash(data) → bytes` | Produce a name from a canonical string | SHA-3-256 → 32 bytes |
| `verify(pubkey, signature, data) → bool` | Verify a message signature | Ed25519 |

Each suite declares fixed sizes (key length, sig max length, hash length) used for sanity-checking the wrapper payload. Only `verify` is exposed as a WASM handler op (§6.6): signing is a sender-side operation that lives in the host, and id derivation hashes host-side too (§5.1, §6.2) — the suite handler runs neither.

### 6.2 The Genesis suite (algo_id = 0x0000)

The signature module needs *something* to verify the very first message. By convention:

- **algo_id 0x0000** = Ed25519 + SHA-3-256
- It is delivered as a **separate WASM module** (e.g. libsodium compiled to WASM), loaded at boot time.
- The host trusts it **by hash** — the expected SHA-3-256 hash of the genesis WASM module is the one cryptographic constant in the bootstrap configuration.
- It cannot be removed through the pipeline — the reference policy refuses its `SetHandler`-seeded slot (§7.4), so no bundle can unseat it; only a direct host-side `SetHandler(name, null)` can (§7.5, §9.1). But it **can be superseded** for all new messages by installing a new suite at a different slot (§6.4).

The kernel itself does not know about a genesis suite. The hash is held by the host's bootstrap code, which seeds the suite handler via `SetHandler` at its suite-slot name (§6.4) before any messages are dispatched — exactly like the `signature` handler itself.

During a PQ migration, the hybrid is a **composite suite** at a new `algo_id` — one suite that carries and verifies both an Ed25519 and a post-quantum signature — not two nested wrappers. See §6.4.

### 6.3 The `signature` wrapper

Signing is a wrapper message. To send a signed inner envelope, build the inner envelope as normal, then wrap it:

```
outer envelope:
  name          = signature name id
  payload       = [ algo_id:     2 bytes (u16)            ]
                  [ signer_len:  2 bytes (u16)            ]
                  [ signer:      var bytes (public key)   ]
                  [ sig_len:     2 bytes (u16)            ]
                  [ signature:   var bytes                ]
                  [ inner_envelope: remainder of payload  ]
```

The inner envelope is a complete envelope — including its own magic, version, name, and payload.

The signature is computed over `DOMAIN_env ‖ algo_id ‖ signer_len ‖ signer ‖ inner_envelope` — a domain-separation prefix, the outer wrapper fields (`signer_len` is the same 2-byte u16 as on the wire), and the inner envelope's raw bytes including its framing. `DOMAIN_env` is the constant `"seedkernel-envelope-sig-v1\0"` (§16.1), one of a disjoint family of per-context prefixes (§14); it is prepended before signing and verifying but **not** transmitted, so the wire payload and §2.2 overhead are unchanged. Relaying is lossless: a relay alters none of these fields, so the signature stays valid.

Length-prefixing `signer` makes the preimage **self-delimiting**: `signer_len` fixes the `(signer, inner_envelope)` boundary, so no other split of the same bytes yields an identical preimage. With genesis's fixed 32-byte key this is belt-and-suspenders, but a future variable-length-key suite would otherwise let an attacker re-partition `signer ‖ inner` into a different `(signer', inner')` over the same signed bytes — a splice attack the length prefix forecloses structurally, without relying on every suite pinning its key length.

**Signing the outer `algo_id` and `signer` closes the flip attacks.** Covering `algo_id` means an attacker cannot flip it to replay a captured message under a second suite that verifies the same key (§6.4), and covering `signer` means the message cannot be re-attributed to a different `(algo_id, pubkey)` identity — either edit breaks verification. So an app's replay state (§4.4) may be keyed however it likes, and the `signer` a suite verifies against is fixed by the signature, not an out-of-band hint. Suites SHOULD still reject non-canonical or small-order public keys so one logical key has one encoding — author-matching and replay marks key on raw pubkey bytes, so a second encoding would split one identity — but with `signer` signed this is defense-in-depth.

After verification the inner envelope re-enters the pipeline and dispatches normally. The `signature` name holds a single **ordinary handler** — routed like `chat.send` or `store.put`, no special kernel status, no bespoke ABI. It parses the wrapper, verifies via the suite, and on success records the signer, re-dispatches the inner envelope under it, and clears the signer on return (§6.5). The verify-time flow:

```mermaid
flowchart TD
    MSG["Incoming bytes"] --> KERNEL["Kernel.Dispatch"]
    KERNEL --> NAME{"name == signature?"}
    NAME -->|"yes"| WRAP["signature handler: parse wrapper"]
    NAME -->|"no"| INNER["Direct handler (unsigned message)"]
    WRAP --> LOOKUP{"suite handler for algo_id?"}
    LOOKUP -->|"0x0000"| NATIVE["suite: Ed25519+SHA3-256"]
    LOOKUP -->|"0x0001"| WASM1["suite: Dilithium+SHA3 (example)"]
    LOOKUP -->|"unknown"| DROP["Drop"]
    NATIVE --> VERIFY{"verify ok?"}
    WASM1 --> VERIFY
    VERIFY -->|"no"| DROP
    VERIFY -->|"yes"| RECORD["handler records signer, re-Dispatch(inner)"]
    RECORD --> KERNEL
```

Unknown `algo_id`s drop because no handler is installed at that suite slot (§6.4); only installed suites can be verified against.

### 6.4 Registering new algorithms

A suite is an **ordinary handler** (§6.6): a standard scratch-ABI (§4) WASM module at the conventional slot `name = "seedkernel.suite.v1:" + algo_id_hex` — the **literal ASCII string** (`algo_id_hex` is 4 lowercase hex digits), not a hash. There is no suite registry and no separate suite ABI — the signature module builds the literal slot name itself and reaches the suite by plain `kernel.call`, exactly as any handler reaches any other, with no host-side suite-dispatch import (§6.6). Multi-argument primitives fit the single buffer by length-prefixing (§6.6), the same framing the wrapper and install payloads use.

The genesis suite is seeded at bootstrap via `SetHandler` (§6.2, §9), like every bootstrap handler. To add another, ship it as a module in a signed bundle (§12.4) whose manifest binds it at the slot for the new `algo_id`: the loader admits it through the same `installDirect` path as any module (§7) — policy runs, and on approval `SetHandler(slot_name, instance)` binds it and the `(author, bytes_hash)` record lands in `installations[]`. A suite is pure computation.

The policy callback (§7.3) governs who may register suites — the same callback that governs every module; "may this author bind the slot for `algo_id N`?" is just a policy question. The reference first-install/same-author rule (§7.4) applies: the first author to bind a slot owns it and alone can replace its WASM.

Once a new suite is installed, a message signed under it carries that one suite's `algo_id` in its single wrapper (§6.5). A migration that must satisfy two algorithms at once uses a **composite suite** — one `algo_id` whose payload carries and verifies both signatures — rather than two nested wrappers, so there is no wrapping order to get right.

**Duplicate registration.** The same-author rule prevents a different author from replacing an installed suite; to rotate, allocate a new `algo_id` and bind at the new slot. The genesis suite (`0x0000`) is host-seeded via `SetHandler` (§9), so the reference policy refuses to bind over it — its slot has no install record (§7.4). Emergency replacement is a direct host-side `SetHandler`, like any bootstrap-handler replacement (§9.1).

**Lazy validation.** The signature module does not check that suite bytes implement the contract at bind time. If they don't, the first message signed under that `algo_id` fails verification and drops — fail-safe. Interface checking is the policy's job if a deployment cares (it can inspect WASM exports before approving, §7.3).

### 6.5 The current signer

The host records the **signer** of the current dispatch — the single key whose `signature` wrapper verified. The kernel doesn't know it exists; it lives in the host handler that already spans the inner dispatch (§6.3).

**Lifecycle.** On an accepted `signature` wrapper the handler records the signer, dispatches the inner envelope synchronously, and clears it on return. Because the record, the dispatch, and the clear are three consecutive host statements — set / `dispatch(inner)` / clear in a `finally` — the invariant "a signer is set ⟺ its wrapper verified" holds by construction: no partial state, no repair path, nothing to leak across a boundary.

There is at most one signer, because nesting is forbidden (§2.3): a `signature` wrapper whose inner envelope is itself a `signature` wrapper drops before any verify work, since a signer is already set. One message, one signature.

**Query API — `signature.signer`.** Any handler may call `kernel.call(signature.signer, …)` to read the signer. The handler ignores its payload (zero bytes is canonical) and returns `[0x01][algo_id u16][pubkey ..]` when the dispatch is signed — the pubkey runs to the end, so it needs no length prefix and a post-quantum suite's multi-kilobyte key (e.g. ML-DSA) fits — or `[0x00]` when it is not. The signer is scoped to the *top-level* dispatch, so every nested `kernel.call` frame sees the same answer: "who signed the message that caused this chain?" is well-defined throughout.

**Author = the signer.** When the registry (§7) or any other handler asks "who is the author of this dispatch," the answer is that one signer. There is no attestation layer and no wrapping-order convention to get wrong: co-signing or attestation, if a deployment ever needs it, is a **composite suite** (§6.4) that verifies several keys under one `algo_id` and reports whichever the deployment treats as authoritative — an explicit decision in one suite handler, not an implicit consequence of nesting order.

### 6.6 Suite handler contract

A suite is a standard scratch-ABI handler (§4): it exports `memory`, `scratch`, and `handle`, reads input from scratch and writes its response there — no allocator, no pointer arguments, no host-side suite-dispatch import. The signature module invokes it with `kernel.call(suite_slot_name, request)` — the same import every handler gets (§4.2) — building the literal-ASCII slot name (§6.4) itself and reading the `[valid u8]` response from its own scratch. A suite does exactly one operation — **verify** — so the request carries no op selector; its fields are length-prefixed into the single buffer, big-endian (§16), like the wrapper payload (§6.3):

| Request (at scratch) | Response |
| --- | --- |
| `[pubkey_len u16][pubkey][sig_len u16][sig][data ..]` | `[valid u8]` (1 = valid, 0 = invalid) |

Verify is the suite's whole contract. Id derivation is **not** routed through it — the reference host hashes directly via bundled libsodium (§5.1) and the genesis hash is a host-side constant (§6.2) — so a suite never exposes a hash. A second operation, if ever needed, is a *new contract at a new slot version*: the slot pins `…suite.v1:` (§6.4), so a `v2` suite lives at a distinct slot and cannot collide. No in-band op or version byte is needed — the slot you call names the ABI you get.

The `u16` length prefixes accommodate post-quantum suites whose keys and signatures run to kilobytes (§6.5). The `data` field is the full signed preimage `DOMAIN_env ‖ algo_id ‖ signer_len ‖ signer ‖ inner_envelope` (§6.3): the signature module prepends the domain constant and outer fields (including the 2-byte `signer_len` that keeps the preimage self-delimiting) to the inner envelope it already parsed, then hands the whole thing over. The suite stays oblivious to the structure — it verifies `sig` over `data` under `pubkey`, nothing more — so domain separation and outer-field binding live entirely in the signature module, and every suite gets them free.

The one cost versus a bespoke ABI is a single ≤64 KB `memcpy` of `data` into the suite's scratch per verify — negligible against the ~95 µs verify it precedes (§10).

The signer-query schema (`signature.signer`) is described in §6.5 — it is exposed by the signature module itself, not by suite handlers.

---

## 7. The module registry

The module registry is host-side state, not a wire protocol. It holds the install records `(author, bytes_hash)`, runs a deployer-supplied policy callback, and exposes one operation — `installDirect(name, wasm, author)` — that the bundle loader (§12.4) calls to bind each verified module. The records are read host-side (§7.6), never over the wire — there is no dispatch path onto the registry. "Who authored this code" is already settled by the manifest signature the loader checked (§6, §12.4), so admitting a module is just a policy check followed by `SetHandler`.

### 7.1 Install records

The registry maintains one table, the install records:

```
installations[name] → {
  author:      (algo_id, pubkey)
  bytes_hash:  content hash of the installed WASM module — genesisHash(wasm)
}
```

`bytes_hash` is the genesis-suite hash (§6.2) of the **WASM module** — `genesisHash(wasm)`, the same id a manifest's `modules[].hash` (§12.4) and a policy allowlist (§7.3) use. The registry computes it from the bytes directly; caller claims are never trusted. Being the hash of the wasm alone, it survives re-signings — one identifier across install records, allowlists, and manifests.

`SetHandler`-seeded bootstrap handlers have **no row** in this table. They have no author of record and their name is in no bridge's pinned-caller list (§8). The host owns whatever metadata it cares about.

There is **no replay high-water table** here. Installation is a host call under the bundle loader, not a self-authenticating wire message anyone who saw it could resend, so there is nothing to replay. App-level replay defence, when an app needs it, is the app's own concern (§4.4).

### 7.2 `installDirect`

The registry's one binding operation, `installDirect(name, wasm, author)`:

1. Computes `bytes_hash = genesisHash(wasm)` — the content hash of the WASM module (§7.1). One identifier across install records, policy allowlists, and manifests.
2. Fetches the existing record at `name`, if any.
3. Calls the deployer-supplied **policy callback** `approveInstall(name, author, bytes_hash, wasm, existing_record_or_null) → bool`. If no callback is wired or it returns false, refuse — no bind. With no callback wired, every bind is refused; admission is opt-in for the deployment.
4. Instantiates the WASM against the standard handler ABI (§4) and calls `SetHandler(name, instance)`. Suite binds (§6.4) take this same path — a suite is an ordinary handler at its slot name, with no special-casing.
5. Writes the install record to `installations[name]`.

The bundle loader (§12.4) calls this once per module, with the manifest author. The module bytes came from a verified local file, not the dispatch path, so no envelope cap or wire framing applies. The policy callback runs against the *resolved* state (with `bytes_hash` already computed and any existing record fetched), so the policy never has to do that work itself.

### 7.3 The policy callback

The callback is the entire authorization story. It receives everything relevant:

- `name` — the name the module targets
- `author` — `(algo_id, pubkey)` of the manifest author
- `bytes_hash` — the content hash of the WASM about to be bound
- `wasm` — the raw WASM bytes. Pre-approved binaries match against `bytes_hash` cheaply; inspection-based policies (e.g. structural validation, instruction-set filtering, export-table checks for suites) get the bytes directly without re-hashing.
- `existing_record_or_null` — the current installation at `name`, if any

It returns `true` to proceed with the bind or `false` to refuse. That is the full interface.

Deployers wire whatever policy fits their environment. Some examples:

- **Open registry.** `return true;` — any admitted author may bind any name. This is not wire-reachable (installation is a host call, not a message), so it is not remote code execution the way an open wire-install policy would have been. But it still means every module in every bundle the loader is handed lands unconditionally, so pair it with a closed author set (the shell's `--policy`, §12.5) — an open policy is a bring-up convenience, not a posture for a node handed bundles from untrusted sources.
- **Reference policy.** `existing == null ? deployer_first_install(...) : author == existing.author` — an author gate; see §7.4.
- **Content-hash allowlist.** `return bytes_hash ∈ approved_hashes;` — only pre-audited binaries. `bytes_hash = genesisHash(wasm)`, so an entry pins one specific binary and stays valid across re-signings.

Other common patterns: fixed author allowlists and M-of-N quorums (a composite suite that verifies several keys under one `algo_id`, §6.4).

The callback may be arbitrarily expensive — it runs once per module at bundle-load time, not on the message-dispatch hot path. A callback that consults an operator console or HSM is fine.

### 7.4 Default reference policy

The reference registry ships with a default policy that is easy to explain — "trust the original author." It has two rules, both about *who* may bind a name:

1. **First bind at a name:** the deployer's choice. The reference implementation exposes a `firstInstallPolicy(name, author, bytes_hash)` sub-callback that the deployer wires. Common values are:
   - An author allowlist (closed registry — only specified keys may claim new names).
   - A naming-convention check (e.g. names must be of the form `hash(canonical || author_pubkey)`, structurally proving the author claimed the name for themselves).
   - `return true` (open registry). **Read the warning in §7.3 before using this** — an unconditional first-bind policy admits any module the loader is handed, so it belongs with a closed author set, never alone on a node handed untrusted bundles.
2. **Subsequent bind at the same name:** the module must be authored by the existing author:
   ```
   author == existing.author
   ```

   This is the reference choice, not a protocol requirement. Every bind flows through `approveInstall`, so a deployer who wants stricter update control — a quorum, or an explicit acknowledgement on every update — encodes it in the callback.

These rules give you everything you'd usually want without any extra machinery:

- **Squat-resistant.** Once an author has bound a name, no one else can take it over — their bind fails rule 2.
- **Upgrades just work.** The author ships a new bundle version signed with the same key; the binding updates in place with no further interaction.
- **Delegation is just an upgrade.** To hand a name over, the current author ships a new version whose handler treats some other key as the relevant authority going forward, and (optionally) the registry records the new author. The kernel doesn't care; the install record is the source of truth.
- **Slots seeded by `SetHandler` are refused.** If there is no record for `name` but `kernel.handlers[name]` is non-null, the slot was seeded via host-side `SetHandler` (a bootstrap entry like the signature handler). The registry refuses to overlay it. To replace such a slot, the host uses `SetHandler` directly.

The reference policy is one specific way of saying "trust the original author." Deployments with different needs — quorum-controlled production registries, content-hash allowlists, delegation hierarchies — replace `firstInstallPolicy` or the whole callback. Everything else in the system behaves the same.

**Design note: install state is a register, not a log.** `installations[name]` holds only the current record — no `parent` hash chaining a name's versions. Backlinks earn their keep where *history* replicates through untrusted intermediaries — [SSB](https://ssbc.github.io/scuttlebutt-protocol-guide/)'s `previous` link, [Bamboo](https://github.com/AljoschaMeyer/bamboo)'s lipmaa links — verifying a log segment as complete and in-order and making equivocation provable. Both need an observer that *stores* history; a register holding only the current record has no verifier, and fork detection is impossible for a component that never holds two versions at once. Bundle `version` (§12.4) already gives per-`(author, app)` ordering and downgrade protection — SSB's sequence-number role. A deployment wanting verifiable lineage should log the signed manifests in a replicated append-only log (Bamboo is the design to borrow — entries commit to a payload hash, keeping it small) and feed the loader from it; the lineage then lives where it can be verified, and the registry stays a register.

### 7.5 Revocation

There is no separate revocation cascade. Revocation is something the policy expresses, plus a small mechanism the registry exposes for undoing previous binds.

**Removing a bind.** The registry exposes `installer.remove(name)` as a host-side method (callable by the host directly, not via messages — like `SetHandler`). It clears `installations[name]` and calls `SetHandler(name, null)`. Suite slots (§6.4) are ordinary handler binds and take exactly this path. The genesis suite is never registry-managed (its handler was seeded by the host via `SetHandler`, not admitted), so `installer.remove` on the genesis slot is a no-op; removing the genesis suite requires a direct host-side `SetHandler(name, null)`. Used by operators for emergency cleanup or by a message-driven revocation handler a deployer chooses to add.

**Message-driven revocation.** A deployer who wants signed messages to be able to revoke binds adds a `revoke` handler (a state mutator, so blocked from `kernel.call` and gated by signature verification at top-level dispatch, §4.4) that:

1. Identifies the author (the signer).
2. Decides — through its own logic, which the deployer writes — whether this author is permitted to revoke this name. The reference suggestion: only the current author may revoke it; in trust-chain-like deployments, an ancestor authority may revoke a descendant's binds.
3. Calls `installer.remove(name)` on approval.

**Post-revocation behaviour.** Removing a bind clears the slot. Anyone may then re-bind at the same name under rule 1 of the reference policy, or the deployer's policy can maintain a deny-list to prevent specific bytes_hashes or specific authors from reclaiming. The kernel doesn't enforce permanence; the policy callback does, if a deployment wants permanence.

**Compromised key recovery.** Under the strict reference policy a compromised key can keep shipping new versions of its handlers indefinitely — `author == existing.author` still matches. The protocol does not bake in a single recovery model; *who* may override the original author is a deployment policy question. Three deployer-side responses exist, and most production deployments will want at least one:

- **Deny-list in `approveInstall`.** Refuse binds where `author` is in a deployment-maintained revoked set. The set is out-of-band state, distributed by whatever channel the deployment trusts (operator console, gossip, signed update from a higher authority). This stops new binds but does not by itself remove the compromised handler that is already in place.
- **Host-side `installer.remove`.** The operator clears the compromised handler directly. Pair with a deny-list so the same key cannot re-bind immediately afterward.
- **A deployer-defined `revoke` handler** as described above, signed by a higher authority (operator key, M-of-N quorum). On approval it calls `installer.remove`.

### 7.6 Reading install records

The install records are read **host-side** — there is no `kernel.call` query message. A host holds a direct `lookup(name) → {author, bytes_hash} | null` on the registry. The only in-pipeline consumer of an install record is the policy callback (§7.3), and it already receives the resolved `existing` record, so nothing needs a wire round-trip to read one. Bridges don't read the registry at all — they authorize callers by pinning names (§8).

The registry has **no wire surface** — nothing dispatchable. It is pure host-side state that the bundle loader mutates through `installDirect` and the host reads through `lookup`. A deployment that wants a wire-reachable directory of installs builds one as an ordinary app handler over the host-side `lookup`.

---

## 8. I/O Bridges

A bridge is a `SetHandler`-installed handler that **pins the caller names it serves**. Bridges are the only code in the system that performs real I/O; everything else is pure computation inside the WASM sandbox.

### 8.1 Bridge authorization: pinning `kernel.caller`

A bridge authorizes each request by comparing its **immediate caller** against the set of caller names it was wired to serve. There is no capability index to consult and no per-install cap to declare: granting a handler access to a bridge *is* the operator wiring that handler's name into the bridge's pin list.

```
caller = kernel.caller()               # [name_len u8][name bytes]; [0x00] = no caller
if caller.name_len == 0: return -1     # reached by direct envelope dispatch, not by kernel.call
if caller.name ∉ my_pinned_callers: return -1
# ...perform I/O and return the result...
```

The chat shell's UI bridge is the worked example (§11): it compares `kernel.caller` against the single handler name it serves and refuses everyone else. Pinning collapses the trust flow to one decision by one decider — the operator wiring the pin — with no index in between.

**`kernel.caller` is not an author.** It returns the *name* of the immediate calling handler, not a key. A bridge whose policy depends on the **author** rather than on which handler called MUST additionally consult `signature.signer`: the two answer "which handler is asking?" versus "whose signed message kicked off this chain?". Most bridges need only the former, being pinned to handler *names*. Only the immediate caller is exposed, so the confused-deputy mistake of authorizing on a deeper frame is structurally unavailable, not merely forbidden.

**Whether the input was signed is orthogonal to whether the bridge fires.** Signing is opt-in (§2.1) and the bridge check is caller-*name*-based. So an *unsigned* envelope dispatched to a served handler drives that handler's bridge I/O with no signer set — nothing in the kernel, registry, or bridge layer requires the triggering envelope to be signed. An app author MUST NOT assume "my handler only runs on signed input"; a handler whose behaviour depends on the caller's identity MUST consult `signature.signer` itself and refuse an absent or unauthorized signer. The chat demo gets this for free only because its inbound frames are signed and the signer is pinned to the channel (§11); the core protocol does not enforce it. See §14.

### 8.2 Structural sandbox invariant

A bridge serves only the caller names it was wired with. A bootstrap handler seeded via `SetHandler` (the `signature` wrapper, a suite) is in no bridge's pin list, so every bridge check against it fails — not by a rule in its code, but because nothing pins it. That is the structural reason a compromised bootstrap handler still can't open a socket.

---

## 9. Bootstrap Sequence

Bootstrap is the host's job, not the kernel's. The host instantiates the kernel and the modules, then composes the onion.

1. Instantiate the kernel.
2. `SetHandler` for the genesis signature suite handler (verified by hash) at its suite-slot name (§6.4).
3. `SetHandler` for the `signature` wrapper and the `signature.signer` query handler.
4. *(Optional — needed to grow the deployment.)* Create the module registry and wire `approveInstall(name, author, bytesHash, wasm, existing) => …`. With no registry, the deployment is frozen. With it created but no callback, every bind is refused. The registry is host-side state (§7), not a handler — there is nothing to `SetHandler`, and its records are read host-side (§7.6).
5. *(Optional.)* `SetHandler` for I/O bridges (`net.send`, `ui.write`, `fs.read`, …). Bridges are native host code, each pinning the caller names it serves.
6. *(Optional.)* App modules (chat, …) arrive after this point in a signed bundle (§12.4): the bundle loader verifies the manifest, integrity-checks each module, and calls the registry's `installDirect` — no further host wiring needed.

The kernel's role in this sequence is: store handlers and dispatch messages. Everything else — author identification, install records, policy gating — is the host wiring modules together. Signature verification happens once at the `signature` entry point (and once, host-side, on each bundle manifest, §12.4). The bundle loader turns verified modules into `SetHandler` calls through the registry and records each module's author + bytes_hash. Bridges authorize their callers by pinning caller names (§8), independent of the registry. App modules (layer 4, §5.1) are delivered in signed bundles.

### 9.1 Post-bootstrap replacement

The `SetHandler` calls during bootstrap are not special bootstrap-only operations. The same `kernel.SetHandler(name, handler)` method (§3.1) remains available to the host after bootstrap. If a bug is found in the signature handler, a suite, or any other bootstrap handler, the host can replace it at any time:

```
kernel.SetHandler(signatureName, patchedSignatureHandler)
```

This does not depend on the message pipeline — the host calls it directly, bypassing `signature` and the registry. This is deliberate: if the component you need to fix is the one that verifies messages, no signed message can authorize the fix. The host controls access to `SetHandler` through its own security model (process-level permissions, operator console, HSM, or whatever is appropriate for the deployment).

**Message-driven replacement of bootstrap handlers.** Ordinary growth delivers *app* handlers in a signed bundle under the registry's policy (§12.4). Replacing a *bootstrap* handler (signature, a suite) is a different threat model — the reference policy refuses to bind over a slot that was seeded via `SetHandler` precisely because that's how bootstrap handlers arrive. Deployers who want signed-message authority to swap a bootstrap handler can wire a separate `bootstrap.replace` handler after bootstrap, with whatever authorization rules fit (single root key, M-of-N quorum, etc.). It is a state-mutating wire handler — added to the `kernel.call` blocklist (§4.4), gated by signature verification at top-level dispatch, and it owns its own replay defence (§4.4).

The host-level `SetHandler` path remains available regardless as the emergency fallback for cases where the message pipeline itself is compromised.

---

## 10. Performance

Benchmarks verify 10,000 signed messages (Ed25519, genesis suite) through the full kernel pipeline vs. a plain signature-verify baseline. Each message is a `signature` wrapper around a `chat.text` inner envelope (~221 bytes on the wire).

### 10.1 Kernel pipeline vs. raw verify

Measured in Node.js with `performance.now()` on an AMD Ryzen 7 PRO 7840U. The kernel is a `.wasm` module (AssemblyScript); the `signature` wrapper and the genesis suite are host JS (`host/kernel-host.ts`), and the module registry is host-side JS (`host/installer.ts`). A JavaScript host orchestrates them and provides Ed25519 via libsodium (also WASM). Each signed message still crosses a couple of WASM boundaries and memory copies. (These figures were taken before the wrapper became host code, which removes two of those crossings, so they are an upper bound on current overhead.)

| Method | Node.js |
|---|---|
| Kernel pipeline (decode + verify + dispatch) | 834 ms (~83 µs/msg) |
| Plain Ed25519 verify only | 810 ms (~81 µs/msg) |
| **Overhead** | **~2.9%** |

The Ed25519 verify dominates. Signature handling is host code — the wrapper parse, the suite verify, and recording the signer are all host-side — so a signed message crosses the WASM boundary only for the kernel's two envelope parses (outer wrapper, then inner) and the inner handler's invocation; the set/clear of the signer are host operations, not boundary crossings. Even at the boundary count measured above, the sandbox tax is ~2 µs/msg over the raw verify.

Installation is a host-side call under the bundle loader, off the message-dispatch path entirely, so it never touches the steady-state pipeline whose overhead the table above measures.

### 10.2 Distribution Size

| Component | Size |
|---|---|
| kernel.wasm | 6 KB |
| host/*.js — minified (`build/host-min`; ~20 KB gzipped) | 88 KB |
| libsodium.wasm (sumo build: Ed25519 + SHA-3-256, plus the §12.1 BLAKE2b / XChaCha20 backends) | 278 KB |
| libsodium-wrappers.mjs + libsodium-core.mjs | 152 KB |
| **Total deployment with default genesis suite** | **~525 KB** |
| QuickJS realm engine (the single release-sync build, from `quickjs-emscripten`) — only loaded when a bundle's guest runs (§12.3) | ~750 KB |

The kernel is pure protocol logic — no cryptographic code — at ~6 KB of WASM; the `signature` wrapper is host code, not a separate module. The `host/*.js` layer is the runtime around the kernel: it loads it, routes `invoke_handler` callbacks, owns the `signature` wrapper and the current signer (§6.5), provides the `kernel.call` / `kernel.caller` imports (the wrapper reaches the genesis suite through the host's own call path, §6.6), services the genesis suite with libsodium, and holds the module registry (§7). It also contains the whole shell (§12) — net, fs, cap-bridge, safe-js, bundle, policy — which is why it dwarfs a kernel-only host. libsodium is the host's default genesis suite, not part of the protocol; the sumo build is larger than a sign-only build because it also backs the §12.1 raw-byte crypto. A post-quantum suite at a new slot (§6.4) would be larger still, bundling its own algorithm. The QuickJS engine is lazy: a node that only relays and dispatches envelopes never pays for it.

`npm run build` emits the host twice: the readable `build/host` (144 KB, doc comments intact) for debugging and a comment-stripped `build/host-min` (88 KB, ~20 KB gzipped) for shipping. The doc-comment density is high enough that a small dependency-free stripper (`scripts/minify.mjs`, each output gated through `node --check`) cuts ~40% of the source — no bundler, no new dependencies. The table's host figure is the shipped, minified build.

---

## 11. Example app layer: chat (`chat-shell.html`)

Chat is the simplest possible app module: a single handler installed at a `chat.text` name. After the signature + registry layer is bootstrapped, the application handler itself is trivial — it receives a verified, dispatched envelope and does whatever it wants with the payload.

`WASM/browser/chat-shell.html` is a runnable end-to-end demo of the whole stack: a browser shell that owns only the kernel, the signature layer, the module registry, a WebRTC transport (`RtcNetwork`, `host/net-rtc.ts`, §12.7), and a sandboxed iframe — every byte of chat UI and logic arrives as a signed WASM blob admitted at runtime.

On load it generates an Ed25519 identity, instantiates `kernel.wasm`, registers the signature wrapper host-side, and wires a permissive first-install policy approving modules whose author is the local identity (or, for received apps, one the user consents to). The user picks a chat app from a dropdown (`v1 — text only`, `v2 — text + image + nick`); the shell wraps the WASM in a self-contained signed blob — `[authorPk 32][sig 64][wasm]`, the local key's signature over a chat-install domain prefix ‖ wasm — verifies it, and admits the module **directly** through `installBundleModule` → `installDirect` under the registry policy (§7.2). This is a miniature bundle: author-signed content, verified locally and bound into the kernel. Upgrading v1→v2 is a re-admit at the same name under the same key, which the same-author rule approves. Peers hand these blobs to each other over a signed `app.offer` message; the recipient re-verifies the original author's signature and admits it the same way, so distribution is peer-to-peer while the code path stays "verify a signature, call the registry."

Peers connect over a WebRTC mesh from `RtcNetwork` (`host/net-rtc.ts`, §12.7) — the same relay-signaled, perfect-negotiation fabric the storage demo uses, here consumed directly for fire-and-forget `send`. The signaling relay (`scripts/relay.mjs`), set on the **Network** tab, is only the rendezvous for the SDP/ICE exchange and can be killed once channels are open. `RtcNetwork` hands every authenticated inbound frame to `host.dispatch`: the signature verifies against the peer's pubkey and the inner `chat.text` (or v2 name) envelope routes to the handler. A `Start call` button also publishes audio/video over the same `RTCPeerConnection`s as per-peer tiles above the chat UI; a network change kicks an ICE restart (`RtcNetwork.restartAllIce`) so a transient drop recovers without reconnecting.

The relay is partitioned into **rooms** so one instance hosts many independent groups without cross-talk. A client picks its room as the URL path — `ws://host:8080/<room>` — and the relay forwards only between sockets sharing a room; a bare `/` lands in the default room `global`. The shell exposes this as a Room field on the **Network** tab, with a **Random** button that fills in 64 bits of hex entropy (a private rendezvous token). Room names are URL-safe (`[A-Za-z0-9._-]`, ≤128 chars). The room is **not** an authenticated channel — knowing the name is the only credential, and the relay sees all signaling in its room — but the end-to-end identity binding below means a relay or room member cannot impersonate a peer, only observe SDP metadata and refuse to forward.

The wire is DTLS underneath: WebRTC data channels run over DTLS (TLS adapted for datagrams — same handshake, key exchange, and per-record encryption-plus-MAC), so every channel is confidential and integrity-protected by default. But DTLS authenticates only "the other end of this handshake," not "the holder of kernel pubkey *X*." `RtcNetwork` binds the two with `PeerLink`'s in-channel HELLO/AUTH challenge (`host/net-link.ts`, §12.6): each end proves it holds the private key for the pubkey it claims *before* any frame is delivered, and every later frame is attributed to that identity, not to anything inside the frame. This is continuous channel binding, stronger than a one-shot SDP `a=fingerprint` assertion at the signaling layer (RFC 8827 §5.6.4) — a MITM relay can splice SDP and bring DTLS up to itself, but can never complete AUTH without the peer's private key, so the link never authenticates and never delivers a byte. Kernel envelopes are signed, not encrypted; wire confidentiality comes entirely from DTLS underneath.

The shell never sees plaintext message content beyond what the iframe chooses to render: the chat handler runs inside the kernel, talks to its UI through a scoped `chat.ui` bridge name that the shell pins to that handler's name (§8), and the iframe is `sandbox="allow-scripts allow-forms"` with no same-origin access to the shell.

To run it locally: build the WASM artifacts (`kernel.wasm` and the chat app modules) into `WASM/build/`, then serve `WASM/browser/` over HTTPS (the bundled `localhost+1.pem` / `localhost+1-key.pem` are mkcert certs for `localhost`) and open `chat-shell.html` in two browsers to chat between them.

---

## 12. The runtime as an app host: capabilities, the shell, and signed bundles

Chat (§11) is a browser shell wired by hand. The same onion ships as a **general runtime artifact** — the *shell* — that any app rides on as **signed content**. The shell knows nothing about chat or storage; it offers a fixed, generic surface, verifies a bundle against a policy, and *becomes* whatever the bundle is. [seed store](https://github.com/arj03/seedstore) is the worked example: a full peer-to-peer storage node is the shell plus a signed bundle, with no storage-specific code in the runtime.

"Capabilities" from here on mean one thing: the **bundle cap domains** (§12.2, §12.4) — five coarse names (`crypto`, `net`, `fs`, `module`, `clock`) that a bundle's signed manifest grants to the app's confined JS *guest*. They answer "may this *app's guest* reach this backend at all?" (WASM handlers, by contrast, carry no cap declaration at all — a handler reaches a bridge only when that bridge pins its name, §8.)

The manifest's `caps` field is the guest's *entire* authority — which is why it lives inside the signed manifest and nowhere else. It has to: the guest is not a kernel handler — it has no name in the kernel's table, no install record, and no entry in the caller stack, so a bridge's §8 name-pinning check cannot see it.

### 12.1 Raw-byte capability backends

Beyond the bridges that pin caller names (§8), the runtime provides the capability *backends* an app's confined logic actually drives. They are deliberately structureless — bytes in, bytes out — so the kernel never learns what an app means by them:

- `crypto.*` — the bundled sumo libsodium: hash (BLAKE2b), `sign`/`verify` (Ed25519), the raw `stream_xor` (xchacha20), `random` (`host/cap-bridge.ts`, backed by `loadSodium`). `sign` is under the node identity but **scoped**: the host prepends `DOMAIN_guest` plus the app's identity to the message before signing (§12.2), so a guest never obtains a raw node-key signature. Raw signing stays host-internal (it backs the PeerLink handshake, §12.6).
- `net.*` — an authenticated request/response transport over a `Network` (`host/net.ts`): node↔node over raw TCP, browser↔node over RFC 6455 WebSocket (`host/net-node.ts`), or peer↔peer over WebRTC (`host/net-rtc.ts`, §12.7), each connection pinned to a peer's kernel pubkey by a challenge/response (`host/net-link.ts`). It offers `send` (a single peer request/response) and `peers`; a guest fans out itself with `Promise.all` over `send` (§12.2, §12.3).
- `fs.*` — raw bytes under an opaque, flat key (`host/fs.ts`): `get`/`put`/`size`/`list`/`delete`/`stat` (existence is `size ≥ 0`, so there is no separate `has`). An in-RAM `MemoryFs` and a directory-backed `NodeFs` (`host/fs-node.ts`); OPFS/IndexedDB in the browser later. No content-addressing, no paths — that's app policy.
- `clock` and an installed-handler call (`KernelHost.callHandler`) to reach a WASM handler by name.

Anything with *structure* is a **no-capability module** that transforms bytes: WebSocket framing is `ws.wasm` (`./ws`), Reed–Solomon erasure coding is an app's `codec.wasm` — both pure transforms the host drives, never something the kernel knows.

### 12.2 The cap-bridge: the guest op ABI

An app's confined logic reaches all of the above through a single seam, `host.call(op, bytes) → bytes` — the capability counterpart to a WASM handler's `kernel.call`. `host/cap-bridge.ts` (`./cap-bridge`) services that seam from the primitives above and *only* those. Every op is application-neutral; the bridge has no idea it is hosting storage.

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

**The signing op is scoped, never raw.** `SIGN` does not sign the guest's bytes as given: the host signs `DOMAIN_guest ‖ scope ‖ msg`, where `scope = author_pk ‖ app_len u8 ‖ app` is derived from the admitted manifest (§12.4) — the same `(author, app)` pair that keys freshness — never guest-supplied. The domain-prefix family is disjoint (§14, §16.1), so a guest-obtained signature never verifies as an envelope wrapper, a manifest, or a channel AUTH; and distinct bundles derive disjoint scopes, so one app cannot sign in another's namespace. `VERIFY` stays raw — verification is not an oracle — so an app checks a scoped signature by reconstructing the preimage itself; every node running the same bundle derives the same scope, which makes the signatures portable across a cohort. One consequence: rotating a bundle's author key changes the scope and orphans previously signed objects, so an app anticipating handover records its scope inside its own signed formats. §14 has the trust rationale.

The **capability domains** a manifest declares (§12.4) expand to fixed op sets — the coarse, human-auditable vocabulary ("this app reaches net + fs"), not a list of op numbers:

| Domain | Ops |
| --- | --- |
| `crypto` | 1–6 (`HASH`, `STREAM_XOR`, `SIGN`, `VERIFY`, `IDENTITY`, `RANDOM`) |
| `net` | 7–8 (`NET_SEND`, `NET_PEERS`) |
| `fs` | 9–14 (`FS_GET`, `FS_PUT`, `FS_LIST`, `FS_DELETE`, `FS_STAT`, `FS_SIZE`) |
| `module` | 15 (`MODULE_CALL`) |
| `clock` | 16 (`CLOCK`) |

An op outside the granted domains does not resolve — the bridge refuses it, and the shell never wired the backing resource in the first place (an `fs`-less bundle gets no fs backend at all, not an fs backend behind a check). An unknown domain name in a manifest throws when the realm is built — a typo fails loudly rather than silently granting nothing, or, worse, everything.

**Relation to WASI.** The cap-bridge is deliberately WASI-shaped at the seam: a small syscall table, a zero-authority guest, capability by non-wiring rather than runtime check. The differences justify a bespoke ABI. The ops are identity-centric, not POSIX — `net` is addressed by peer pubkey over a channel bound to that key (§12.6), not by socket; `fs` is a flat opaque blob store with no paths; `SIGN`/`IDENTITY` surface the node's identity, which WASI has no notion of (and every guest signature is domain-scoped). And the grant is *signed content*: the guest's authority is the `caps` field of an author-signed manifest (§12.4) admitted by operator policy (§12.5), where WASI's grants are host-local instantiation choices with no authorship. WASI begins after who authored the code, who may install it, and who signed the triggering message are settled; §2–§9 settles them. What keeps this from drifting into a worse WASI: ops stay structureless bytes, anything with structure becomes a no-capability module (§12.1), and the table grows by appending sparingly.

### 12.3 Zero-authority JS realms

Logic that is inherently async or awkward as a *synchronous* WASM handler runs as confined JS in a QuickJS-compiled-to-WASM realm (`host/safe-js.ts`, `./safe-js`). A fresh realm has only the ECMAScript intrinsics — it cannot even *name* `fs`/`net`/`process`/`fetch` — and reaches out only through the injected `host.call` seam. The seam is narrow-async: a sync op (crypto/fs/clock/module) resolves to bytes immediately, and the one round-tripping op (`NET_SEND`) returns a real Promise the guest `await`s. So the guest is ordinary async/await JS, a fan-out is `Promise.all`, and there is **one** realm — a single non-Asyncify build — serving both roles: `call()` runs an initiator that may `await` net, and `callSync()` answers an incoming request straight through *while* an initiator is parked mid-`await` in that same realm. A suspended async function is just heap state, so re-entering to run a synchronous handler is ordinary JS — no second engine, no Asyncify, no module-global suspend state. This is the chat shell's sandboxed-iframe confinement (§11) generalised: "run zero-authority guest JS over a cap seam," the sibling of "run a WASM handler under caps."

### 12.4 Signed bundles

An app is delivered as a **bundle** (`host/bundle.ts`, `./bundle`) — a directory of signed content:

```
manifest.bundle     the signed manifest envelope (below)
<module>.wasm       each WASM handler module
<guest>.js          the zero-authority guest program (§12.3)
```

**What a bundle carries beyond the modules.** The module registry (§7) binds exactly one kind of thing: WASM handlers into the kernel's table. A bundle wraps everything else an app is made of:

- **The guest is not a kernel handler.** It is JS source for a QuickJS realm, not WASM — the registry's path ends in "instantiate WASM, `SetHandler`" — and it can exceed the 64 KB size a wire message would carry. Without the manifest it would have no signed identity at all.
- **The guest's authority has no other home.** A bridge grants a WASM handler access by pinning its kernel name (§8); the guest has no name and no install record, so the manifest's `caps` is its entire capability declaration.
- **Version coherence.** Module binds are per-name and independent; nothing in §7 says "codec at hash X, reputation at hash Y, and guest at hash Z together constitute app v1.2." The manifest is the author's signed statement of the coherent set — without it a node can hold a mix of individually-valid module versions that were never meant to run together.
- **Operator/author separation.** The shell is one fixed, auditable artifact; the app arrives as content signed by a third-party key the operator's policy admits. Verification is channel-independent: a bundle read from a USB stick verifies exactly like one fetched from a mirror or pushed over a relay.

**One authenticated statement, one authorization.** The bundle is the *only* way code arrives. The signed manifest commits to every module's `genesisHash` (§7.1), and the loader verifies each `.wasm`'s bytes against it, then installs each verified module directly under its declared `kernelName` by calling the registry's `installDirect` (§7.2) — the record's `author` is the manifest author and its `bytes_hash` is the verified hash, gated by the same install policy (§12.5). Two things follow: a bundled module is **not** bound by the §2.2 64 KB envelope cap (it never crosses the kernel's dispatch path — the one place §2.2's rationale doesn't apply, since a local file needs no verify-latency bound); and admission touches no replay state, so an equal-version reload just re-binds cleanly — a reboot re-reading the same directory installs the same modules again with no collision. A **live update** is not a separate mechanism: it is delivering a bundle whose manifest `version` is higher, which the freshness guard (below) requires and the same-author rule (§7.4) admits.

**Manifest envelope.** `[author_pk: 32][sig: 64][manifest: UTF-8 JSON to end]` — an Ed25519 detached signature over `DOMAIN_manifest ‖ json`, where `DOMAIN_manifest` is `"seedkernel-manifest-sig-v1\0"` (§16.1), prepended before signing but not stored. The disjoint prefix means a manifest signature can never double as an envelope-wrapper or channel-handshake signature over the same bytes (§6.3, §14). There is deliberately no canonical-JSON step: the envelope carries the exact signed bytes and the verifier parses exactly what it checked, so the bytes *are* the manifest and canonicalisation has nothing to bite on.

**Manifest fields.**

| Field | Type | Enforced? | Meaning |
| --- | --- | --- | --- |
| `app` | string | key | Display name for the coherent set; with `author_pk` it forms the `(author, app)` freshness key (see freshness below). |
| `version` | integer | **yes** | Monotonic version of the coherent set. A load whose `version` is below the persisted `(author, app)` high-water mark is refused as a downgrade (see freshness below). |
| `modules[]` | `{name, file, hash, kernelName}` | yes | One entry per WASM module: logical name, filename, `genesisHash(wasm)` hex (the *same* value the registry records as the module's `bytes_hash` and a policy `modules` allowlist matches, §7.1), and the kernel name the loader binds the module at via the registry's `installDirect` → `SetHandler`. The manifest is the authoritative source of the bind name. |
| `guest` | `{file, hash}` | yes | The guest program: filename + `genesisHash(utf8(source))` hex. |
| `caps` | string[] | **yes** | The capability domains (§12.2) granted to the guest. The shell expands them to the allowed op set and wires only the matching backends; nothing outside them resolves. They are ordinary app powers the operator authorizes by choosing to run this bundle (none grants raw node-identity signing — the `crypto` domain's `SIGN` is scoped to this app's namespace, §12.2, §14). |
| `config` | map (string → string \| number) | no | App constants injected into the guest as `const APP = {…}`. Opaque to the runtime. |

**Load algorithm** (`loadBundle`). The shell is host code, so failures here **throw to the operator** — the §3 "drop" semantics apply to wire messages, not to loading a local directory:

1. Read `manifest.bundle` and verify the envelope signature. Invalid ⇒ reject; nothing has landed.
2. Require `author_pk` to be in the policy's `authors` (§12.5).
3. **Freshness.** Read the persisted high-water mark for `(author_pk, app)` (absent ⇒ −∞). Refuse if `version < high_water` — a downgrade, nothing lands. Otherwise persist `high_water := max(high_water, version)`. Equal versions reload (an ordinary reboot); a newer version advances the mark; the mark is monotonic and never rewound, so once version N loads, nothing older ever loads again on this node.
4. For each manifest module, in order: read the `.wasm` and require `genesisHash(bytes) == hash` (mismatch ⇒ reject); bind the verified bytes at `kernelName` via the registry's `installDirect` with the manifest author (§7.2), which records `(author, bytes_hash)` and gates on the install policy (§12.5). A module the policy refuses does not abort the load — the loader reports which modules registered, and the operator decides.
5. Read the guest source and require `genesisHash(utf8) == guest.hash` (mismatch ⇒ reject).
6. Only now may the guest run (§12.8): a realm (§12.3) over a cap-bridge restricted to `caps`' op set, loaded with `op preamble ‖ const APP = merge(manifest.config, operator config) ‖ guest source`.

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

`boot(opts)` (`host/main.ts`, `./shell`) assembles all of the above — kernel + signature + the module registry under the loaded policy, the fs/net capability backends, the node identity — and returns a `Shell` (`loadBundle`, `runGuest`, `serve`); a CLI wraps it:

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

- **`kernel.wasm` + the genesis suite** — the same §3 / §6 modules every target runs.
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

**Scope: the native target is a bundle-runner.** Its app path is the §12.4 bundle — load, verify, install the modules, run the guest — and its request path is transport → shared route bundle → cap-bridge → the installed handlers. Both targets install code only from a signed bundle (§7, §12.4), so the app-delivery surface is identical. The native binary has no front door onto top-level `dispatch` — no CLI flag or network path feeds a raw §2 envelope into the kernel — so the §6.5 signature-wrapper pipeline, while fully wired and covered by the loader's tests, is exercised only internally (the loader re-dispatches each inner envelope once its wrapper verifies). The registry and policy are the same shared TS both targets run in QuickJS; the dispatch orchestration — the `signature` wrapper, the single signer, the genesis verify — is the host-side kernel-host role, native Go here and `kernel-host.ts` on the JS targets, like every host primitive (`invoke`, `kernel.call` routing, the caller stack). The one drift-sensitive input, `DOMAIN_env`, is not hand-copied into the Go code: the loader reads it at boot from the shared `domains.ts` (§16.1), so a signed preimage is byte-identical across the cohort. The rest of the handler contract is at parity: `kernel.caller` tracks the real call chain (§4.2), so §8.1 pinning decides on the same name; `kernel.call` resolves through the kernel's own `find_handler`, the same table `dispatch` uses, so the paths cannot disagree; and a handler's declared `scratchSize` (§4.1) is honored identically.

**Size.** One file, ~7.5 MB stripped, cross-compiled to win/linux/mac with `GOOS`/`GOARCH` — nothing to install alongside it. The bulk is wazero's compiler backend (~4 MB) and the Go runtime (~2.4 MB); the protocol's own footprint stays tiny (§10.2). Against the JS shell — which needs a Node/Bun install plus the lazily-loaded ~1.5 MB QuickJS engines — the native binary trades a larger single artifact for zero external dependencies, the right shape for a server or an appliance.

**Performance.** Because the Go target drives the *same* `libsodium.wasm` under wazero that the JS targets run under V8, crypto throughput tracks node closely — Ed25519 verify and XChaCha20 land within ~10% either way, and the Reed–Solomon codec runs a touch *faster* (≈330 / 394 vs ≈315 / 319 MB/s encode / decode). The one deliberate exception is the block-id hash (BLAKE2b-256), which runs on **native Go** (`golang.org/x/crypto/blake2b`, byte-identical to libsodium and KAT-pinned): it sits on the storage data path and is the single primitive wazero ran the wasm materially slower than V8, so native (~600 vs ~390 MB/s) is the clear win. Signed-envelope dispatch trails node by Go-side per-message overhead, not crypto. Reproduce with `go test -run x -bench . -benchmem ./...` from `native/`; the node baselines come from `WASM/tests/run.mjs` (`testPerf10k`) and seedstore's `WASM/tests/bench.mjs`.

---

## 13. End-to-end worked example

A signed `chat.text` message arriving at a fully bootstrapped node, traced through every boundary. Assume `<keyA>` was used to install the chat handler at name `chat.text@keyA` (the canonical name the deployer's first-install policy approves under), so the chat handler is in the kernel's table and `installations[chat.text@keyA]` has the corresponding record. The message below is signed by `<keyA>`.

**Message on the wire.** An outer signature envelope (per §6.3) carries `algo_id = 0x0000` (genesis), `signer = <keyA pubkey>`, `sig = Ed25519(DOMAIN_env ‖ 0x0000 ‖ 0x0020 ‖ <keyA pubkey> ‖ inner_envelope, keyA_sk)` (where `0x0020` is `signer_len` = 32), and an inner envelope with `name = chat.text@keyA`, `payload = "hello, world"` (per §2). The signature covers the domain prefix, the outer `algo_id`, `signer_len`, and `signer`, and the inner envelope's raw bytes (§6.3).

**Pipeline trace:**

1. **Host receives bytes** from the transport, copies them into kernel memory, calls `kernel.dispatch(ptr, len)`.
2. **Kernel `dispatch`**: `len ≤ 65536` ✓; parse succeeds with `magic=SD`, `version=01`. Look up `handlers[<signature name>]` → found (installed by `SetHandler` at bootstrap). Call `invoke_handler(...)`.
3. **Host `invoke_handler`** routes to the `signature` handler — an ordinary host handler, no scratch ABI — passing it the wrapper payload.
4. **Signature handler (host code)**: Parse `algo_id=0` → genesis. `signer_len=32` matches Ed25519. Build the suite verify request `[pk_len=32][<keyA>][sig_len=64][sig][DOMAIN_env ‖ 0x0000 ‖ 0x0020 ‖ <keyA> ‖ inner_envelope_bytes]` — the fields are length-prefixed with no op selector (§6.6), and the last field is the signed preimage as `data` (`0x0020` is `signer_len` = 32, §6.3) — and reach the genesis suite at its slot; the reference host services that slot with libsodium's `ed25519_verify`. Response is `[01]` (valid).
5. **Verified**: the handler records the signer `(0, <keyA>)` and re-enters the kernel with the inner bytes: `kernel.dispatch(innerPtr, innerLen)`.
6. **Kernel `dispatch`** (recursive): parse succeeds, look up `handlers[chat.text@keyA]` → found (bound earlier through the registry from a signed bundle). Call `invoke_handler(...)`.
7. **Host `invoke_handler`** routes to keyA's chat handler WASM instance. Copy payload `"hello, world"` into the chat module's scratch region. Call `chat.handle(12)`.
8. **Chat handler** reads from scratch, prints (or appends to a buffer), returns `0` (no response). Inbound dispatch ignores the response.
9. **Inner dispatch returns**; the signature handler clears the signer — now none.
10. **Outer `dispatch` returns** to the host. Done.

If the chat handler had wanted to know *who sent this*, it would have called `kernel.call(signature.signer, [])` between steps 7 and 8 and received `[01] [00 00] [<keyA pubkey>]` — present=1, algo_id=0 (u16 BE), then the 32 pubkey bytes to the end.

If the chat handler had wanted to log via a `ui.write` bridge, it would have called `kernel.call(ui.write, payload)`. The `ui.write` bridge would then call `kernel.caller()` to read its immediate caller — `[20] [chat.text@keyA]` here (`name_len = 0x20 = 32`, then the name) — check that name against the caller names it was pinned to serve, and only then perform the I/O (§8).

That's the entire pipeline. Every step is a synchronous call across one of two WASM boundaries — kernel/host or app-handler/host; the `signature` wrapper is host code, so it crosses none. Nothing else is moving.

---

## 14. Security considerations

The security properties are introduced where they arise (§2.3, §3.1, §4.4, §6.5, §8, §12.4–§12.6); this section collects the trust assumptions and the load-bearing invariants in one place so an implementer or auditor can see the whole model at once.

**Trust boundary / TCB.** The host *is* the trusted computing base. Anyone with `SetHandler` access (§3.1) owns everything: they can replace the signature module, a suite, or any bridge with no signed message (§9.1), and the registry is host-side state they already own. The kernel enforces no access control on `SetHandler` — guarding it is the host's job (process permissions, operator console, HSM). Everything above is sandboxed WASM that reaches the outside world only through bridges, which serve only the caller names they are pinned to (§8).

**The one cryptographic root constant.** The genesis suite's WASM hash (§6.2) is the single trust anchor baked into bootstrap. Bootstrap and suite slot names are literal ASCII (§5.1), not hashes, so they are independent of it; only `bytes_hash` (§7.1) and the app-name / allowlist hashes a policy chooses use the genesis hash. Swapping the genesis suite shifts content ids and hash-derived app names — but not the bootstrap namespace — so the §9 seeds survive it. Pick the genesis suite once per deployment.

**Domain-separated signature contexts.** Every signature the runtime produces is over a context-specific prefix: `DOMAIN_env` for envelope wrappers (§6.3), `DOMAIN_manifest` for manifests (§12.4), and `DOMAIN_channel` for the handshake transcript (§12.6). The prefixes are disjoint and prepended before signing (never transmitted), so a signature harvested in one context cannot verify in another — cross-context replay is closed by construction. Folding the wrapper's `algo_id` and `signer` into the envelope preimage (§6.3) extends the discipline *within* the envelope context: a captured message cannot be re-attributed to a different suite or key by editing the outer fields, since those edits break verification.

**Kernel authentication vs. transport confidentiality.** At the *kernel protocol* level (§2–§9), envelopes are *signed, not encrypted*: the wrapper (§6.3) gives authentication and integrity, replay defence is the app's concern when a payload changes state (§4.4), and the protocol provides **no** confidentiality — envelopes at rest, or over a transport that adds none, are plaintext unless a deployment adds an encryption wrapper (another layer, §2.1). The *runtime transport* (§12.6) does add its own: after the AKE handshake every frame is an AEAD record under a forward-secret key, so node↔node frames — envelopes and control req/res alike — are confidential and integrity-protected across all transports (TCP, WebSocket, WebRTC); WebRTC additionally runs inside DTLS (§12.7), a redundant second layer. The confidentiality boundary is the transport: on the wire the runtime protects frames end to end between authenticated peers; at rest and above the transport, envelopes remain plaintext unless separately encrypted.

**The channel handshake is an authenticated key exchange (AKE).** §12.6's HELLO carries an ephemeral X25519 key alongside the identity pubkey and nonce, and AUTH signs the full transcript — both identity keys, both nonces, **and both ephemeral keys**, canonically ordered — so the identity signature binds the key exchange (SIGMA-style; since each signature already covers *both* identities there is no separate identity-MAC seam). A node induced to sign produces a signature bound to *that* exchange, useless elsewhere, so frame attribution stays sound against impersonation and misattribution. From the ephemeral–ephemeral DH plus the transcript hash both ends derive per-direction session keys, and every post-AUTH frame is a ChaCha20-Poly1305 record with an implicit monotonic counter as its nonce — forgery resistance, replay resistance (strict counter enforcement), and confidentiality in one mechanism, forward-secret because the DH keys are ephemeral. So `PeerLink` needs no external TLS/Noise tunnel. The identity Ed25519 key stays signing-only, disjoint from the sealed-box / Curve25519 uses of the node key (§12.9). The residual exposure is what any AEAD channel leaves: traffic-analysis metadata (frame sizes and timing) and the endpoints — a compromised node still sees its own plaintext.

**Bundle freshness.** The manifest carries a monotonic `version`, enforced at load against a persisted per-`(author, app)` high-water mark (§12.4): a directory whose `version` is below the mark is refused as a downgrade, and the mark is never rewound. This closes the older-directory-reload gap. The whole bundle loads wholesale every boot and neither modules nor guest carries a per-item version, so `version` is the single downgrade guard for the set; an equal-version reload just re-binds the same modules. The mark is host-local persisted state, so a deliberate rollback is an out-of-band operator action (the operator is the TCB).

**Guest signatures are domain-confined; the node's raw key never signs guest bytes.** The guest ABI's `SIGN` (§12.2) is not a raw oracle: the host signs `DOMAIN_guest ‖ scope ‖ msg`, the scope derived from the admitted manifest's `(author_pk, app)`, never from the guest. So **no guest-obtainable signature verifies in any protocol context** — not as an envelope wrapper (`DOMAIN_env`), a manifest (`DOMAIN_manifest`), or a channel AUTH (`DOMAIN_channel`) — **nor in any other app's scope**, since distinct bundles derive disjoint scopes. Raw node-key signatures exist only for host-authored material: the AKE transcript, and any envelopes host code deliberately signs. What remains is deliberate: *within its own scope* an admitted app speaks for the node — a compromised guest can sign arbitrary statements in its namespace (a storage app's chunk descriptors, say). That is the authority the operator granted by running the bundle, and the oracle form contains it: the key can be *used* but never *exfiltrated*, so unloading the bundle revokes it instantly, where an app-held key would outlive its own compromise. Apps SHOULD sub-separate their object types under their scope (a distinct leading tag per signed format) — the same prefix-family discipline, one level down.

**Replay protection is an application concern.** The kernel carries no state-mutating wire handler and no `seq` table of its own — installation is a host call under the bundle loader, not a self-authenticating message anyone could resend (§4.4, §7.1). A signed *app* envelope, however, replayed verbatim re-verifies and re-dispatches, so any app handler whose payload causes a meaningful state change MUST add its own `seq` defence (§4.4). A deployer who adds a state-mutating wire handler (§9.1) takes on the same duty.

**Signing is opt-in, so bridge authorization ≠ message authenticity.** A bridge's caller-pinning check (§8.1) asks "which handler is calling me," not "was the triggering message signed." An unsigned envelope routed to a bridge's served handler still drives that handler's bridge I/O. Handlers whose policy depends on *who* signed MUST consult `signature.signer` and refuse an absent/unauthorized signer themselves; nothing below them enforces it.

**Structural sandbox.** Bootstrap handlers seeded via `SetHandler` have no install record, and — more to the point — their name is in no bridge's pinned-caller list, so every bridge check against them fails (§8.2). A compromised bootstrap handler still cannot open a socket — not by a rule in its code, but because nothing pins it.

**A suite carries more authority than an ordinary handler.** A signature suite is an ordinary module at its literal-ASCII slot `SUITE_SLOT_PREFIX + algo_id_hex` (§6.4) — to the policy the slot looks like any other name. But whoever binds a rogue verifier at an `algo_id` slot can thereafter mint envelopes that "verify" under it for *any* pubkey, impersonating authors at scoped names as `{algo_id, pk}`. Binding a suite is "just a policy question" (§6.4), so a closed author-set (and module-hash) gate handles it like anything else — but bind suites only from a trusted author under a closed policy. This is not a shipped-default hazard: code arrives only as an operator-loaded bundle (§12.4), never from a peer, and a `--policy`-omitted node admits nothing (§12.5); the exposure is confined to an operator who both wires an accept-all rule (`referencePolicy(host, () => true)`) and loads a bundle from an untrusted author. Treat accept-all as a bring-up convenience only.

**Residual: compute and memory.** The protocol bounds verify-amplification (one signature per message §2.3, 64 KB envelopes §2.2) and recursion (call depth §4.4) but does not bound a single handler's CPU time or linear-memory footprint (§4.3). A permissive registry multiplies the exposure. Deployers exposed to untrusted installs should run dispatch under a Worker watchdog and pre-validate handler bytecode (memory caps, loop/recursion limits) in the policy callback.

---

## 15. Background

This project was inspired by the [8k-demo](https://github.com/ssbc/8k-demo) P2P project built on top of secure scuttlebutt running in the browser. The goal was to strip it down to the bare essentials and make the core as small as possible, moving functionality into modules to be distributed in whatever fashion.

## 16. Protocol constants

All limits and reserved values in one place. Multi-byte integers are big-endian throughout the protocol.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| `MAGIC` | `0x5344` ("SD") | Envelope decode | First 2 bytes of every envelope. |
| `VERSION` | `0x01` | Envelope decode | Only accepted version. |
| `MAX_ENVELOPE_BYTES` | `65536` | Kernel dispatch + encode | Hard cap on the outermost envelope (§2.2). |
| `MIN_NAME_LEN` | `1` | Envelope decode | `name_len = 0` is invalid. |
| `MAX_NAME_LEN` | `255` | Envelope encode | One-byte length prefix. |
| `MAX_CALL_DEPTH` | `8` (default) | `kernel.call` host import | Re-entrant call cap; host configurable. |
| `DEFAULT_SCRATCH_SIZE` | `131072` (128 KB) | Handler instantiation | Per-handler scratch region; host configurable. |
| `GENESIS_ALGO_ID` | `0x0000` | Signature module | Reserved for the genesis suite (§6.2). |

Reserved-value handling: any envelope whose `magic`, `version`, or `name_len` is outside the table above is **dropped** (see §3 for what *drop* means).

### 16.1 Runtime (shell) constants

These belong to the reference runtime (§12), not the kernel protocol — a different shell could change them without breaking envelope interop, but they are wire- or ABI-visible to bundles and peers of *this* runtime.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| Cap op ids | `1`–`16` | cap-bridge (§12.2) | Guest↔host op identifiers, contiguous and grouped by domain (§12.2); regenerated with the guest preamble, never sent between nodes. |
| Capability domains | `crypto`, `net`, `fs`, `module`, `clock` | manifest `caps` (§12.4) | An unknown domain throws when the guest realm is built. |
| Manifest envelope | `[pk 32][sig 64][json]` | `loadBundle` (§12.4) | Ed25519 detached signature over `DOMAIN_manifest ‖ json`. |
| Link message tags | `HELLO 0x01`, `AUTH 0x02`, `FRAME 0x03` | `PeerLink` (§12.6) | AKE handshake + encrypted frame plane; HELLO carries the ephemeral X25519 key, FRAME bodies are AEAD records. |
| `DOMAIN_env` | `"seedkernel-envelope-sig-v1\0"` | Signature wrapper (§6.3) | Domain-separation prefix for the signed envelope preimage (`algo_id ‖ signer_len ‖ signer ‖ inner`). Prepended before signing, not transmitted. |
| `DOMAIN_manifest` | `"seedkernel-manifest-sig-v1\0"` | Manifest signature (§12.4) | Domain-separation prefix for the signed bundle-manifest JSON. Prepended before signing, not stored. |
| `DOMAIN_guest` | `"seedkernel-guest-sig-v1\0"` | Cap-bridge `SIGN` (§12.2) | Domain-separation prefix for guest-obtainable signatures, followed by the host-derived scope `author_pk ‖ app_len u8 ‖ app` from the admitted manifest. Prepended before signing, not transmitted. |
| `DOMAIN_channel` | `"seedkernel-channel-id-v1\0"` | AUTH signature (§12.6) | Domain-separation prefix for the signed AKE transcript (both identities, nonces, and ephemeral keys). Not transmitted. |
| `MAX_FRAME_BYTES` | `16777216` (16 MiB) | `PeerLink` framing (§12.6) | Hard cap on one link frame, enforced on the length prefix (TCP) or frame length (WS) **before** buffering — bounds what an unauthenticated peer can make a node allocate from a single prefix. Both transports cap identically, so a frame that crosses one crosses the other. |
| `MAX_QUEUE_BYTES` | `1048576` (1 MiB) | `PeerLink` (§12.6) | Total bytes of frames buffered pre-auth; oldest dropped once the sum would exceed it. A byte bound (not a frame count) so pre-auth buffering is capped regardless of frame size. |
| Transport frame kinds | `req 0x00`, `res 0x01` | `Transport` (§12.6) | Single request/response plane, carried inside the §12.6 AEAD record layer. |
| Default request timeout | `2000` ms | shell boot (§12.8) | Response deadline before a peer counts as unreachable (`--timeout`). |

**The `DOMAIN_*` family lives in one file.** The four prefixes above are a *family*, and the only thing they are for is disjointness: no signature made under one may verify under another, over any bytes, ever. That is a property of the whole set rather than of any member, so the set is declared together in `host/domains.ts` — where adding a fifth means reading the other four on the same screen — and imported by the modules that sign (`kernel-host.ts`, `bundle.ts`, `cap-bridge.ts`, `net-link.ts`). The Go/native target evaluates that same file through its generated bundles (§12.9) and reads its prefixes from the evaluated module — including `DOMAIN_env`, which the loader pulls from the realm at boot to verify envelope wrappers natively — so every prefix on every target derives from this one file by construction, not by a copy that could drift. There is **no** hand-copied member anywhere — the wrapper is host code and reads the prefixes from this one file like every other target.
