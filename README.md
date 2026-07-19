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

The reference composition stacks the layers as an onion — each layer wraps the one above it and depends only on the layers below (§5 discusses the composition):

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

## Get started

```sh
cd WASM
npm install
npm run build        # kernel.wasm + ws.wasm + the shared host
node tests/run.mjs   # end-to-end tests + 10k signed-message benchmark
```

For the browser P2P chat demo (§11): `npm run build:browser`, serve `WASM/browser/` over HTTPS, and open `chat-shell.html` in two browsers. The worked-example trace in §13 walks the same pipeline byte-by-byte.

## The rest of the spec

This file is §1 (and §15); the rest of the spec lives in `docs/`, split by concern. Section numbers are global across the set — any `(§X.Y)` reference resolves to exactly one file:

| Doc | Sections | Contents |
| --- | --- | --- |
| [PROTOCOL](docs/PROTOCOL.md) | §2–§6, §16 | The envelope, kernel dispatch, the WASM handler ABI, layering, the signature module and its suites, the protocol constants. |
| [REGISTRY](docs/REGISTRY.md) | §7–§9 | How code is admitted and wired: the module registry and its policy callback, I/O bridges, the bootstrap sequence. |
| [RUNTIME](docs/RUNTIME.md) | §10–§12 | Performance, the chat demo, and the shell: capability backends, the guest ABI, zero-authority JS realms, signed bundles, the node↔node transport, the Go/native binary. |
| [SECURITY](docs/SECURITY.md) | §13–§14 | A byte-by-byte worked example and the collected trust model. |

To read the spec as one document, concatenate the files in that order: `cat README.md docs/{PROTOCOL,REGISTRY,RUNTIME,SECURITY}.md`.

## 15. Background

This project was inspired by the [8k-demo](https://github.com/ssbc/8k-demo) P2P project built on top of secure scuttlebutt running in the browser. The goal was to strip it down to the bare essentials and make the core as small as possible, moving functionality into modules to be distributed in whatever fashion.
