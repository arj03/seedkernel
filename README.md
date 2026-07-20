# Seed kernel: a tiny handler-table kernel that bootstraps into a sandboxed app runtime

*A simple kernel grows from a signed message handler bundle into arbitrary behaviour — untrusted code runs sandboxed (WASM handlers or confined JS), anywhere from a browser tab to a single native binary.*

## 1. Vision

A minimal runtime built around a kernel that does one thing: look up a **name** in `handlers` and run the handler bound there as a **pure transform** — bytes in at a fixed scratch offset, bytes out. Authorization, capability gating, confinement, and application logic are the **host** and its **modules** - layers that compose around the table without the kernel knowing what any of them mean. Installing a handler is nothing more than `handlers[name] = wasm_bytes`; code arrives as a signed **bundle** and the host binds each module into the table under a policy. The system bootstraps from one trusted policy (the authors it will install, or none) into arbitrarily complex behaviour.

Every node-to-node link is an **encrypted, authenticated channel** (§12.6): an authenticated key exchange opens the connection, then each frame rides as a forward-secret, individually-authenticated encrypted record that the transport attributes to a peer's key. Message authenticity is the *channel's* job, not the kernel's. Signing survives only where it must: over the **bundle** that installs code (§12.4), which has to authenticate its author across any number of relays.

**The whole runtime is four components.** Everything after this table is detail:

| Component | Role |
| --- | --- |
| **Kernel** | Routes names to handlers: a flat `handlers[name]` table resolved by `find_handler` (§3). Handlers are pure transforms; the kernel has no dispatch loop, no signature logic, no I/O. The table changes only through the host-level `SetHandler` (§3.1). |
| **Host** | The runtime around the table: the same shared JS on every target (browser, Node, or QuickJS inside the native binary, §12.9). It reaches a handler by name (`callHandler`), does all I/O and authorization itself, and provides `loadBundle`, the single admin path that admits new code (§12.4). |
| **Handlers** | Pure-transform WASM modules (§4): the host stages input at the module's `scratch` offset, calls `handle`, and reads the response back. They import nothing but the AssemblyScript runtime — no kernel seam, no I/O of their own. |
| **Bundles** | The only way code arrives (§12.4): a manifest, WASM modules, a guest JS program, and one author signature over the whole set. The host checks that signature against the operator's policy (§12.5) and the loader admits each module into the flat table — a policy decision, then `SetHandler`. |

There are no special cases and exactly one way to do everything: one install path (signed bundles, §12.4), one guest seam (`host.call`, §12.2), one post-handshake frame plane (§12.6).

Every binding is three orthogonal pieces: the **name** is the kernel's opaque dispatch key, the **bytes** are the WASM instance held at that key, and the **author** is the signer of the bundle. The loader binds names to bytes under a deployer-supplied **policy** that decides who may install what (§12.5).

Installation flow:

```
signed bundle (manifest + WASM + guest JS + signature)
        │
        ▼
loadBundle (host admin path)                         §12.4
        │
        ▼
policy check — author trusted? version valid?        §12.5
        │
        ▼
admit each module — policy ok? record (author, hash) §12.4
        │
        ▼
SetHandler(name, wasm_bytes) — kernel table updated  §3.1
        │
        ▼
compile & register guest JS in QuickJS realm
(zero-authority, awaits first invocation)
```

Request flow:

```
incoming encrypted frame (authenticated channel)      §12.6
        │
        ▼
host extracts target name, stages input bytes
        │
        ▼
kernel.find_handler(name) → WASM instance            §3
        │
        ▼
pure transform at scratch offset → output bytes      §4
        │
        ▼
host frames response & sends over channel
```

The reference composition stacks the layers so each depends only on the layers below it (§5 discusses the composition):

```
┌──────────────────────────────────┐
│   App                            │
│   guest (confined JS) +          │
│   pure-transform WASM handlers   │
├──────────────────────────────────┤
│   Cap-bridge (required if guest   │
│   JS is present; otherwise omitted)│
│   the guest's host.call seam —   │
│   its only reach to real I/O     │
├──────────────────────────────────┤
│   Kernel                         │
│                                  │
│   name → handler table           │
│   find_handler routing           │
└──────────────────────────────────┘
```

**Design principles:**

- The kernel does exactly one thing: name resolution and byte dispatch. No built‑in policies, I/O, or dispatch loop. Every additional capability (installation, confinement, application logic) lives in layers above it. Lower layers gate higher layers; each layer sees only downward.
- Modules, as untrusted code, run confined. WASM handlers are synchronous pure transforms with no reach beyond the bytes they are handed—they receive a buffer and return a buffer, and that is the full extent of their interaction. JavaScript is reserved for handlers that must await multiple host interactions, handle streaming data, or maintain conversational state across asynchronous turns—QuickJS's native async model makes this straightforward—while maintaining zero ambient authority and exposing only the single host.call seam.
- Node-to-node links are confidential by default — the runtime transport opens each connection with an authenticated key exchange, then carries every frame as a forward-secret, individually-authenticated encrypted record, uniform across TCP, WebSocket, and WebRTC and needing no external TLS or Noise tunnel.
- The channel authenticates one hop, not the whole path. The encrypted link attributes each frame to the peer that sent it (§12.6) — end-to-end for a direct exchange like chat, where every message travels a single hop. An app that **relays** messages through intermediaries — a forum, a feed, store-and-forward gossip — cannot lean on the channel to attribute the *original* author, so it layers its own scheme on top.
- The kernel compiles to WebAssembly, so the same kernel runs unmodified in every host — browser, server runtime, or a single native binary.

## Get started

```sh
cd WASM
npm install
npm run build        # kernel.wasm + ws.wasm + the shared host
node tests/run.mjs   # end-to-end tests
```

For the browser P2P chat demo (§11): `npm run build:browser`, serve `WASM/browser/` over HTTPS, and open `chat-shell.html` in two browsers. The worked-example trace in §13 walks the same pipeline byte-by-byte.

## The rest of the spec

This file is §1 (and §15); the rest of the spec lives in `docs/`, split by concern. Section numbers are global across the set — any `(§X.Y)` reference resolves to exactly one file:

| Doc | Sections | Contents |
| --- | --- | --- |
| [PROTOCOL](docs/PROTOCOL.md) | §2–§5, §16 | The kernel and its handler table, host-level `SetHandler`, the pure-transform WASM handler ABI, layering, the protocol constants. |
| [BOOTSTRAP](docs/BOOTSTRAP.md) | §9 | The bootstrap sequence that composes the onion — kernel, admission policy, and the first signed bundles. |
| [RUNTIME](docs/RUNTIME.md) | §10–§12 | Distribution size, the chat demo, and the shell: capability backends, the cap-bridge guest ABI, zero-authority JS realms, signed bundles and how the loader admits them under policy, the node↔node transport, the Go/native binary. |
| [SECURITY](docs/SECURITY.md) | §13–§14 | A byte-by-byte worked example and the collected trust model. |

To read the spec as one document, concatenate the files in that order: `cat README.md docs/{PROTOCOL,BOOTSTRAP,RUNTIME,SECURITY}.md`.

## 15. Background

This project was inspired by the [8k-demo](https://github.com/ssbc/8k-demo) P2P project built on top of secure scuttlebutt running in the browser. The goal was to strip it down to the bare essentials and make the core as small as possible, moving functionality into modules to be distributed in whatever fashion.
