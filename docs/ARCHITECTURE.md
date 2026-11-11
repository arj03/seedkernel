# seedkernel: architecture

*How the host is structured and why: messages, slots, names, the resource laws, what belongs in the host, the transport's place, loaders and routing. Read end to end.*

> **Part of the [seedkernel](../README.md) spec.** Section numbers are global across the doc set, so a `(§X.Y)` reference points to whichever file holds that section:
>
> [README](../README.md) §1, §10 · **ARCHITECTURE §2, §3, §5, §12, §12.6.2b, §16.1** · [BUNDLE](BUNDLE.md) §3.1, §4, §12.4, §12.5, §16 · [GUEST](GUEST.md) §12.2, §12.3 · [TRANSPORT](TRANSPORT.md) §12.6.1, §12.6.2, §12.6.3 · [SECURITY](SECURITY.md) §13, §14 · [CLIENT](CLIENT.md) §12.8
>
> This file is design: each choice is stated, then its reason, and the mechanism is left to the source file named. The exact surfaces (wire, bundle bytes, guest and module ABI) are in TRANSPORT, BUNDLE and GUEST. §16.1 is the one table of values here, because every other file depends on it.

---

## Overview

A node is three layers, and only the bottom one is fixed when it is deployed:

```
+------------------------------------------------------------------+
| Bundles, one slot each: an app, or the transport                 |
|   guest (confined JS realm)  +  private WASM modules             |
+------------------------------------------------------------------+
            host.call(name, bytes) ↓       ↑ handle([caller][body])
+------------------------------------------------------------------+
| Host script (signed host blob)                                   |
|   admission, slots, routing, host services, resource bounds      |
+------------------------------------------------------------------+
            platform primitives: files, sockets, wasm engine
+------------------------------------------------------------------+
| Loader (native binary, Node, or a page importing the host)       |
+------------------------------------------------------------------+
```

- **The loader** gives the host raw primitives and keeps the one thing a host cannot keep for itself: the ability to roll back a host that crashes.
- **The host** is a signed script the loader runs. It verifies bundles against the operator's policy, gives each one a slot, routes messages to slots, and lends each slot the host services its manifest declares. It never interprets what an app's bytes mean.
- **A bundle** is a signed app: a JS guest that runs with no ambient authority, plus private WASM modules only that guest can call. The guest reaches the world only by name through `host.call`, and is entered only through `handle`.
- **The transport is a bundle too.** It holds the node's sockets, runs the handshake and encrypts every frame. Other apps reach the network through it, and peers reach apps through it.

A request from a peer crosses all of it. The host reads bytes off a socket and hands them to the transport's guest, which authenticates and decrypts them and names the protocol they are for. The host looks that protocol up among the installed claims and invokes the claiming app's `handle` with the sender's key in front. The app answers, perhaps after calling its modules or its own host services, and the answer goes back through the transport to the socket.

Two ideas shape every section below. **Authority is declared, signed and admitted**: a bundle reaches only what its author declared in a signed manifest and the operator's policy allowed, and anything undeclared is absent rather than refused. **Anything with structure lives in a bundle**: the host moves raw bytes and enforces bounds, so protocols, storage formats and even the handshake change by signed update without a host release.

The file follows that order:

- **§2 The message model** and **§3 Bundle slots**: what a message is at the host boundary, and the unit an installed bundle becomes.
- **§5 Names**: how labels, claims and module names are scoped, and what the author does and does not own.
- **§12 The runtime as an app host**: the three resource laws every bound follows, then the host services (§12.1), the host's side of the transport (§12.6, §12.7), the node's one identity (§12.6.2b), the loader and host blob (§12.9), and routing (§12.10).
- **§16.1 Host constants**: the values everything else depends on.

---

## 2. The message model

A message at the runtime boundary is `(protocol id, input bytes)`. The transport has already decrypted it and put the peer key it attributes it to in front (§12.6). The host resolves the protocol claim to a bundle slot and invokes that slot's guest `handle` with those bytes (§12.10). Nothing on the inbound path dispatches to a module: a module is reached only by its own guest, by bare name (§4).

The host has no wire format, so it has no message cap of its own. Bounds live where bytes are framed: the transport caps a frame and a module caps its I/O at its scratch size (§4.1). The host bounds only what it holds, such as one socket read (§12.6).

Authenticity is the channel's. The host checks no per-message signature; an app that relays content carries its own end-to-end attribution (§5).

---

## 3. Bundle slots

A slot is one projection of an installed bundle:

```
claim → { verifiedBundle, realm, pureModules, fsScope }
```

The realm is the only inbound entry. `pureModules` is a private name-to-instance map that only that realm's seam can reach. The fs scope and the signing scope derive host-side from the verified manifest's `app` label, or from the fixed link domain for the link occupant (§12.2); guest code chooses neither. A slot can own several claims, each pointing at the same value, and each claim has one active owner, so dispatch is always one `claim → slot` lookup (§12.10).

The slot is the unit of lifecycle. An upgrade replaces the whole slot (§3.1): the realm, its timers, its scopes and every module go together, and a module the new manifest omits disappears with the old slot. `uninstall` and `revoke` remove the same unit. There is no single-module lifecycle, because a module's private state has no meaning apart from the guest that drives it.

### 3.2 Target implementation

Only how `pureModules` are built and run varies by target: workers on the JS targets, engine instances in the host realm on native. Verification, admission, ordering, scope derivation, realm construction and the atomic claim commit are one shared implementation, the host script (§12.9). A host starts with no slots and a deny-all admission policy; loading signed bundles is its only way to grow.

The rule is that anything a bundle can observe is shared code. A guarantee that held on one target and not another would be a guarantee nobody has, and two implementations kept equal by hand drift.

---

## 5. Names, hashes and relayed authenticity

**Names are strings.** A module name, an `app` label and a claim are opaque strings the host only ever matches. Nothing forces a hash, so a name reads plainly in a log and in a manifest.

**A module name is slot-local.** Nothing on the wire names a module. A peer sends a protocol id, the receiving host resolves it to a slot, and the slot's guest reaches only its own modules. No label takes part in that lookup, so two hosts can install the same code under different app names and still interoperate.

**The label is the namespace; the author is trust and lineage.** The `app` label, each `protocols` claim and each `services` claim are literal manifest strings with one active owner on a node. A candidate contesting one is refused; a replacement of the slot holding it takes over the slot, its label and its claims, whoever authored it (§12.10). The label names the fs and signing scopes, so they belong to the label rather than to an author: a fork under the same label signs and verifies in the same scope, an author who rotates its key keeps its records, and whatever holds the label next inherits its data. The author is what admission and revocation decide on (§12.5), and it keys the freshness mark, so versions are an author's own count (§12.4).

**One hash.** Content hashes, author ids and binary pins use BLAKE2b-256 (`genesisHash`). The same primitive is `crypto/blake2b` for guests and the shipped transport's KDF and transcript hash.

**Relayed-message apps layer their own authenticity.** The channel authenticates one hop (§12.6). An app whose messages pass through intermediaries (a feed, a forum, store-and-forward gossip) cannot let the channel speak for the original author, so it adds a per-message signature naming the author, plus backlinks (a hash chain, as [SSB](https://ssbc.github.io/scuttlebutt-protocol-guide/)'s `previous` or [Bamboo](https://github.com/AljoschaMeyer/bamboo)'s lipmaa links) to order the history and make equivocation detectable. Signed bundles already do the author half for relayed code; such an app does the same one layer up. §14 says why lineage stays out of the install path.

---

## 12. The runtime as an app host: host services and signed bundles

The host knows nothing about chat or storage. It offers a fixed, generic surface, verifies a bundle against a policy, and becomes whatever the bundle is. [seedstore](https://github.com/arj03/seedstore) is the worked example: a peer-to-peer storage node is the host plus a signed bundle.

### The three resource laws

Every bound in the host follows one of three laws, kept apart because they compose differently: space sums over owners, lifetime shrinks along a causal chain, and rate needs a schedule. A population bound is not a rate bound, and reading a limit under one law as a guarantee under another is the mistake the split prevents.

1. **Retained space has continuous custody.** Every host-side byte caused by untrusted input has a finite owner from creation to destruction, and a handoff reserves in the receiver before releasing the sender. No operation relaxes custody; a name may tighten what an owner admits (`fs/put` meets a storage quota), and the owner enforces its bound, not the dispatcher.
2. **Causal lifetime has a monotone deadline.** One absolute deadline begins where an invocation starts and only shrinks through queues and calls. No callee can renew it. The link occupant is the one exception, for the reason §12.3 gives.
3. **Initiation rate has explicit scheduling.** The realm wake paces the only fresh work a guest can start for itself. Work from the network arrives only over authenticated links and is bounded per invocation; there is no node-wide CPU guarantee, and pacing that ingress is the transport's.

Three consequences shape every owner:

- **Every owner is bounded in time as well as size**, and names its complete release paths. A release nothing is committed to calling bounds only until the freeing event fails to happen.
- **Pool within a tenant, quota between them.** Every owner is per realm and the realm count is bounded, which makes per-realm numbers ceilings. Apps on one node do not trust each other, and an allowance they share is a standing way for a busy app to starve a quiet one. Where the tenant is one, a shared pool is right: every socket belongs to the link occupant, so outbound bytes pool across links.
- **A bound crosses every seam or it does not exist.** A bound the host accepts but no target can set is a bound nobody has. Every owner has a default, so a host that configures nothing still bounds its guests, and an edge value that would silently lift a bound (a heap limit of 0 means "none" to the engine) is refused. The defaults are in `host/wasm-limits.ts` and `services/net-limits.ts`; what they mean for a guest is §12.3.

### 12.1 Host services: raw-byte backends

The host provides five host services (`HOST_SERVICES`, `host/domains.ts`) and two ungated name families. Their exact names and byte layouts are §12.2.

- **`node`**: signing and verification with the node key, under the slot's scope. The key never enters a realm.
- **`fs`**: raw bytes under an opaque, flat key, scoped to the app label.
- **`timer`**: the realm's one wake.
- **`link`**: raw links over opaque ids, attributed inbound delivery, and datagram sockets. The link occupant only (§12.5).
- **`host`**: hands the loader a host blob to run next (§12.9). The blob authenticates itself, so any app may declare it; the loader's rules and the operator decide.
- **`crypto/*`**, ungated: a frozen table of transforms the host already carries, plus host entropy.
- **bare names**, ungated: the bundle's own modules.

Every node offers `node` and `timer`; `fs`, `link` and `host` only where the embedder enables them (§12.8). A declared service the node cannot back refuses the install, since a node's services are fixed for its life and the install already knows what the first call would answer.

**Only reach is declared.** A transform is computation, not authority: a bundle's modules are verified and installed with its guest, so calling one reaches nothing the guest does not already hold. Time is not authority either, since every realm has ECMAScript's clocks. So `guest.requires` carries exactly what a guest could not otherwise touch (the node key, disk, its wake, sockets, the loader's host slots and other realms), and the list an operator reads is the bundle's whole reach. A grant is a whole service, never a method: there is no finer grant the seam could enforce.

**An undeclared service is not wired.** An fs-less bundle gets no fs backend at all, not a backend behind a check. A gate built from the declared list is a gate on every target, including native, where the guest runs inside QuickJS and no TypeScript type exists to lean on.

**Names stay structureless.** Bytes in, bytes out, so the host never learns what an app means by them and bundles change their wire and storage formats under the same boundaries. Anything with structure lives in a bundle: protocol logic is guest JS (the transport's handshake, relays and UDP punching), and work whose cost is per byte or per packet is one of the bundle's private modules (RFC 6455 masking in `ws.wasm`, QUIC in `quic.wasm`, an app's erasure coding). The catalog grows by adding names sparingly, and `crypto/*` takes no new algorithms; why it is at its floor rather than mid-removal is §14.

**The seam is WASI-shaped, not WASI.** Like WASI it is a small syscall table, a zero-authority guest, and an ungranted service left unwired rather than checked. It differs where it has to: `link` moves bytes over opaque ids with peers addressed by key inside the transport, `fs` is a flat blob store with no paths, the node's identity is a scoped signing oracle, and above all the grant is signed content (an author-signed manifest admitted by operator policy), where WASI's grants are host-local choices with no authorship. WASI begins after who wrote the code and who may install it are settled; bundles and admission settle them.

**Wrapping sockets is host code on every target.** A confined guest never holds a socket, so whoever owns the platform's object wraps it. The browser's only socket objects are `WebSocket` and `RTCPeerConnection`; since the browser has no raw TCP, WebSocket is a codec over a raw listener, which is why a node answers a browser with no extra host code. Whatever the object, the bundle cannot tell transports apart.

**The fs scope is a hash of the label.** Keys double as filenames and are held to `[A-Za-z0-9._-]`, which an author-chosen label cannot be trusted to stay inside, and a case-folding filesystem would merge labels differing only in case. Lowercase hex fixes both, and its fixed width means one label's prefix never extends another's (plain concatenation would let app `x` key `yz` collide with app `xy` key `z`).

### 12.6 Node↔node transport: channel identity binding

The link occupant, a transport bundle, owns the channel: handshake, record layer, peer set, request correlation, address book, relays and the signaling of direct paths. The host driver (`services/link.ts`) owns sockets by link id and the listeners. Apps reach the transport through the local service id it declares (`_net` by convention). The shipped transport's wire is [TRANSPORT](TRANSPORT.md).

**Confinement is why the transport is a bundle.** It parses everything a stranger sends: frames before any handshake, the handshake itself, relay messages. That is the node's largest attack surface, so it runs where a parsing bug owns one realm, its sessions and plaintext, and never the host's state, the node key or another slot. That any admitted author can write one, and that a running node can replace it, follow from the same placement.

**The protocol is content.** The handshake, records and routing change in a bundle update without a host release. That holds only while nothing beneath the bundle assumes this handshake: the host sees no handshake width, the shell passes the transport's flags through unread, and each `crypto/*` name takes its algorithm's whole interface (§12.2), so an algorithm the host lacks ships as a module, as ML-KEM does. What stays the host's is the identity key's algorithm (Ed25519, through `node/sign`), the socket kinds a destination can name, and the link events.

**The first transport ships inside the host blob.** A node has no network until it has a transport, and fetching one over raw sockets from a peer it does not yet trust would open a metadata window before any channel exists to close it. So the first one ships in the artifact, and what travels is the next one.

**The host keeps coarse bounds under the transport's.** "Half-open" and "authenticated" are states only the occupant sees, and the occupant is replaceable content. A socket costs a descriptor and a table entry the moment it is accepted, before the guest has an opinion, so the driver bounds its own structures (`services/net-limits.ts`): the link table, one read, held inbound reads, and outbound backlog per link and per node. Its ceilings sit well above the transport's tiers, so an honest occupant never meets them.

- **The link table refuses rather than evicts**, because which link is worth keeping is exactly the judgement the host lacks.
- **A read that cannot be held waits or fails.** A pausable socket, as every socket on Node and native is, waits unread until the inbound budget has room: backpressure costs nothing there and the socket's receive window carries it to the peer. A link that cannot pause is failed, because thousands of raw links must not each buy an independent realm invocation.
- **Outbound overflow fails the whole link, never one write.** A record sealed and never sent is a hole in a nonce-ordered stream, and the peer's next decrypt would tear the link down as a forgery, blaming it for our backpressure. Custody spans the adapter's buffer and the platform's send backlog, since both are bytes the link made the host retain.

#### 12.6.2b One master seed, one identity

A node stores one secret, a 32-byte **master seed**. Its signing keypair derives from it (`host/subkeys.ts`) under the closed label `channel` (`DOMAIN_subkey`, §16.1); that public key **is** the node's identity: its peer id, the key peers authenticate and `HOST.identity`. The master seed signs nothing. The one key signs for both purposes, the link and the apps, separated by signing scope (§12.2). Nothing revokes it: a leaked seed is a lost identity, and recovery is a new seed and so a new peer id (§14).

There is one key rather than one per purpose because a peer knows a record's author only as a peer id, the key the handshake authenticated. A record signed by a sibling key would name an author in no peer's roster, and binding the two would need a new gossiped protocol element per peer. Both keys would derive from one seed in one process, so a compromise reaching either reaches both; a split buys resistance to one class of code bug (a lost prefix), not identity separation. So the purposes are kept apart as every other pair is: the host chooses domain and scope from the asking slot, and no name signs raw bytes. The stored secret is still not the signing key, so the key file format stays independent of the key algorithm.

### 12.7 Relays, WebRTC and UDP paths

A node that cannot be dialed is reached through a relay and moves to a direct path when one can be made. Which peers, the relay wire, who offers and how long to wait are the transport's ([TRANSPORT](TRANSPORT.md)). The host lends the two platform primitives a direct path needs and decides nothing: a browser's `RTCPeerConnection`, which a confined guest cannot hold, and, off the browser, datagram sockets. Their guest-facing formats are §12.2.

**The seam is the platform object and nothing else.** A host that chose peers, spoke a relay wire or compared keys would need a release for a transport to change any of it. The negotiation link passes the W3C verbs through as bytes, so what the host carries changes only if WebRTC does.

**`via` rather than a dialed peer.** The occupant opened the negotiation, so it already knows which peer a data channel is for; the host names the link the channel arrived through, never a key. A host-side "dialed" field would be a peer identity in the host with WebRTC as its only writer.

**Roles instead of perfect negotiation.** Only one side ever offers, so glare cannot happen, the seam needs no rollback, and the occupant needs no view of the signaling state. The pre-agreed data channel makes the two ends symmetric below the handshake.

**The data link arrives with its channel.** A handshake clock started at `link/open` would spend itself on ICE; announcing the link once its channel opens keeps the handshake deadlines meaning what they mean on TCP.

**The UDP path runs in the transport's realm.** Punching and the stream parse every datagram a stranger sends, so they run confined, beside the handshake that already parses a stranger's bytes. A realm of their own would cost an entry and host calls each way every turn; in the transport's realm a datagram batch enters a realm the transport is entered for anyway, and stream bytes reach the record layer with no host link between. Per-packet work (QUIC) is the transport's own module.

**The host keeps raw ceilings only.** It caps the sockets it lends and the datagrams it holds while the transport is busy, as it caps links and reads. What the path holds (candidates, punching sockets, unacknowledged data) is the transport's to bound, inside a realm whose memory the host caps anyway.

**Media is the app's own connection.** Audio and video need a peer connection an app can add tracks to. Lending the transport's would put a platform object back across the seam and its renegotiation back into the host, so an app that wants media opens its own and signals it over its own protocol.

**The runtime depends on no ICE/DTLS/SCTP library.** The seam it owns is a byte duplex; a peer-connection implementation is one way to produce one, so a console embedder may pass its own. Between console nodes the UDP path is the direct path.

### 12.9 Loaders and the host blob

A node is a **loader** running a **host blob**. The loader is the only code fixed when a node is deployed: the syscalls, the wasm engine, and rollback. Everything the node does, from admission to the CLI, is the host script inside the blob, and the same script runs on every loader. The blob also carries the QuickJS engine, the host's crypto and the default transport bundle. A page has no loader: it imports the host directly and takes the engine and crypto from a script-less blob.

The platform ABI between loader and host script (`host/abi.ts`) is internal; a second implementation of the host would draw it differently. The choices that matter outside it:

- **The host is updatable because the fixed part is small.** A node that changes only by redeploying its binary changes on its operator's schedule, not when a fix ships. Very little has to sit below confinement and be fixed, so that is all the loader is, and the rest arrives signed. The ABI is raw primitives (bytes in files and on sockets, numbers in and out of wasm) because primitives stay put; a bridge shaped around the host's internals would freeze them.
- **A host blob is signed like a bundle.** It uses the manifest envelope (§12.4) under its own domain, `DOMAIN_host` (§16.1), so a host blob never passes as an app bundle nor an app bundle as a host.
- **The host checks its successor, as it checks an app.** A verifier cannot be delivered through the format it verifies, but it can be delivered by one already trusted: the running host checks the next blob with the crypto it was itself admitted under, and the chain starts at the genesis blob built into the loader. So the loader holds no crypto and no rules about authorship, and those rules can change in an update. A host stages only a blob from its own author, at a version above its own.
- **There is a version floor.** The committed host's version is the floor, and it rises only when a new host commits, so a rollback never goes below it. A loader whose built-in genesis blob is newer than the committed host runs the genesis blob.
- **Tried once, committed after a health window.** A blob that boots and then dies on its first link is the failure that matters, and only something that outlives the host can see it. A mark written before a trial turns a crash into a rollback at the next start without trusting the crashed code to report it; the window turns "it started" into "it served". The loader keeps the slots, the mark and the window, because only something that outlives a crash can.
- **Staging is opt-in.** Updating moves trust: the host author's key then decides what every updating node runs. So a node refuses staged hosts unless its operator turns updates on (§12.8, §14).
- **The crypto rides with the host.** The host's libsodium and ML-DSA-65 run on the engine from the blob, so a fix to either ships as a host update rather than a loader redeploy.
- **A page keeps no slots.** Its origin serves the page and anything it would use to check a blob, so a signature check there proves only what TLS already does. A pinned loader (an extension, a signed web bundle) would change that; it is a packaging decision for the embedder, not a host feature.

The native loader is Go over [wazero](https://wazero.io) and runs the host script in QuickJS; the Node loader runs it in V8, because the host realm is the busiest code a node runs and V8 is there. A Go node and a Node node join one cohort against the same signed bundles.

### 12.10 Protocol routing: which app handles a message

A frame names a **protocol id**, never an app, author or module. Apps, authors and modules are node-local; a wire that named them would make every peer's install choices everyone else's business. A peer states only the protocol, and the receiver's installed claims decide which verified code answers.

Each slot claims names from its signed manifest, and the host keeps three books, projections of the installed set recomputed at every commit and removal and never persisted:

- **`peer`**, from `protocols`: reached by inbound peer requests, through `link/deliver`.
- **`local`**, from `services`: reached by a co-resident guest's `host.call` and the embedder's `Shell.call`.
- **the raw-link binding**, from a `guest.requires` holding `link`: reached by the driver's link events.

**The manifest claims, and install is the claim.** Nothing installs an app it does not mean to serve, so admitting and claiming are one act. Which protocol an app speaks is stated once by its author, not retyped per deployment, where a typo's only symptom is a node that boots clean and answers empty forever. The claim charset is §12.4.

**Two lists, two books.** Reach follows from which book holds a name and nothing else: a `services` name is not in the `peer` book, so no peer reaches it, by construction rather than a second check. The same name in both lists means "reachable either way", which a single union book could not express.

**One owner per name per book.** A candidate contesting an active claim, label or the binding is refused before commit; only a replacement of the holder takes it over (§12.5). There is no fan-out: that would be an authority-bearing observer model with admission semantics of its own.

**The raw-link binding is a claim.** The driver has one event sink, so a second holder would take the node's sockets off the first while leaving its claims and realm in place: installed, routed, and silently off the network. Claiming it under the same rule as a name makes that a refusal. The occupant is also the one that attributes: holding the sockets is the authority to say which peer a request came from, because nothing else ever held the bytes. A claim grants no authority, but it does select which admitted app receives decrypted input (§14).

**Peer delivery.** The occupant decodes a request and calls `link/deliver(claim, attribution, payload)`; the host looks the claim up in the `peer` book alone and invokes that slot's `handle` with `attribution ‖ payload`. An unclaimed protocol, or a `services`-only name, is answered empty, so "nobody here serves that" stays distinct from an unreachable peer.

**A claim is also the right to send.** The far end knows a frame by its protocol id and this node's key; nothing says which local app wrote it, so an app free to name any id would speak as the node in every other app's protocol. An app may send only under ids in its own `protocols`. The host checks this on every call from an app to the occupant, reading the leading fields of a `send`: `[op "send"][noReply u8][to blob][proto blob]` (blobs as in §12.2). These fields are the one part of the occupant's vocabulary the host reads; the check sits in the host because the claim book does, where asking the transport would cost a round trip on every send.

**Transport replacement is slot replacement of the link owner.** The candidate loads complete and off to the side, the host passes its own `LOCAL` unchanged, and at commit the slot, its claims and the binding swap together. The driver keeps its listeners, so inbound links work at once; the old occupant's links, sessions and address book go with it, and peers reconnect. The host keeps nothing peer-shaped, so there is no second copy to migrate, and the embedder re-supplies peers in the replacement's own configuration.

---

## 16.1 Host constants

The values a second implementation of a bundle signer, a guest or a peer must match, and that belong to the host rather than to the shipped transport. The transport's values are in [TRANSPORT](TRANSPORT.md), Constants; module limits are §16.

| Constant | Value | Used by |
| --- | --- | --- |
| `DOMAIN_manifest` | `"seedkernel-manifest-sig-v1\0"` | bundle signatures (§12.4) |
| `DOMAIN_manifest_author` | `"seedkernel-manifest-author-v1\0"` | author id derivation (§12.4); prefixes a hash, not a signature |
| `DOMAIN_host` | `"seedkernel-host-sig-v1\0"` | host blob signatures (§12.9) |
| `DOMAIN_guest` | `"seedkernel-guest-sig-v1\0"` | `node/sign` and `node/verify` for an ordinary app, followed by `app_len u8 ‖ app` (§12.2) |
| `DOMAIN_link_scope` | `"seedkernel-link-scope-v1\0"` | `node/sign` and `node/verify` for the link occupant (§12.2) |
| `DOMAIN_subkey` | `"seedkernel-subkey-v1\0"` | deriving the node keypair seed from the master seed (§12.6.2b) |
| Manifest suite | `0x02` | byte 0 of a bundle or host blob envelope (§12.4) |
| Author id | 32 bytes, `BLAKE2b-256(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖ ml_dsa_pk)` | admission, revocation, freshness (§12.4, §12.5) |
| `AUTHOR_MLDSA_SEED_LABEL` | `"seedkernel-author-mldsa-v1"`, no trailing NUL | an author's ML-DSA-65 seed is `BLAKE2b-256(ed25519_seed ‖ label)` (§12.4) |
| Master seed | 32 bytes | the node's only stored secret; derives the identity under the label `channel` (§12.6.2b) |

Domain strings end in a NUL and are prepended before signing or hashing, never stored or transmitted. The fs key charset is §12.2.

**The `DOMAIN_*` family is declared in one file.** The prefixes exist for one property: no signature made under one may verify under another, over any bytes, and no derived id or seed may collide with a signed preimage. That is a property of the whole set rather than any member, so the set lives together in `host/domains.ts`, where adding a member means reading the others on the same screen, and every place a prefix is applied imports it from there. A guest never sees one: it asks through `node/sign`, and the host chooses the prefix from the asking slot, so a prefix cannot be restated in content. The transport's `DOMAIN_channel` is not a member: it is a format tag inside the transport's own content, under `DOMAIN_link_scope`.

**The seed label is frozen.** Changing it re-identifies every author whose keys were built from a seed.
