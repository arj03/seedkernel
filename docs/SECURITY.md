# seedkernel: security

*The trust model in one place: what each component is trusted with, the claims the design makes, and where each claim's rule lives. For an auditor.*

> **Part of the [seedkernel](../README.md) spec.** Section numbers are global across the doc set, so a `(§X.Y)` reference points to whichever file holds that section:
>
> [README](../README.md) §1, §10 · [ARCHITECTURE](ARCHITECTURE.md) §2, §3, §5, §12, §12.6.2b, §16.1 · [BUNDLE](BUNDLE.md) §3.1, §4, §12.4, §12.5, §16 · [GUEST](GUEST.md) §12.2, §12.3 · [TRANSPORT](TRANSPORT.md) §12.6.1, §12.6.2, §12.6.3 · **SECURITY §13, §14** · [CLIENT](CLIENT.md) §12.8
>
> Rules are stated once, in the file that owns them; this file states the security claim and points at the rule. There has been no external audit, and no cryptographer has reviewed the design.

---

## Overview

Three parties shape a node's security. The **operator** runs the node and decides which authors may install code. An **author** signs bundles. A **peer** is another node that talks to this one. The host trusts the operator completely, trusts an author only with what its signed manifest declares and the operator admitted, and trusts a peer only with being who the handshake proved.

The design's main claims, each argued below:

- **Code runs only if an admitted author signed it**, and a running bundle reaches only the services it declared (§14, Structural sandbox).
- **The node key never leaves the host**, and every signature it makes is bound to a context no other context accepts (§14, Domain-separated signature contexts).
- **A peer's traffic is confidential against a future quantum computer, and its identity is hidden from observers** (TRANSPORT).
- **Untrusted code is bounded in what it can consume**, not only in what it can reach (§14, Resource bounds).
- **Bundles stay authentic across any number of relays**; app messages authenticate one hop (§5).

What it does not claim: protection from the operator, from a transport the operator installed, or from an admitted app within the services it was granted. §13 follows one message through a node to show where each boundary sits; §14 is the trust model; §14.1 and §14.2 are the cryptography and its post-quantum exposure.

---

## 13. End-to-end worked example

A chat message arriving at a node, traced through every boundary. Nodes **A** and **B** are already linked by an authenticated channel, and **B** has a chat app installed from a signed bundle (§12.4), with a guest and a private module, claiming the protocol id `chat` (§12.10). The app is [seedshell](https://github.com/arj03/seedshell)'s. **A** sends `"hello, world"` to a room they are both in.

1. **The transport opens a record.** The transport bundle's guest decrypts the record under its receive key and the next expected counter (§12.6.1), which yields the plaintext frame and, from the link, A's authenticated key. There is no per-message signature: the handshake bound the channel to A once, so every frame on it is A's.
2. **The host resolves the protocol.** The transport hands the host the claim `chat`, A's key and the payload through `link/deliver`, and the host looks the claim up among B's installed claims (§12.10). An unclaimed protocol reaches no guest and is answered empty. A named only the protocol; which code runs is B's choice alone.
3. **The guest receives the attribution and the payload**: `[A's key 32][payload]`. The key comes from the link, never from the frame body, so a peer cannot claim to be someone else: the bytes it chooses do not include the attribution. The host does not check the attribution itself; the transport is trusted with it (§14).
4. **The guest runs** under its deadline and heap cap (§12.3), and calls its module by bare name. The name resolves only among that slot's own modules (§12.2).
5. **The module transforms bytes.** The host copies the input to the module's scratch region, calls `handle`, and copies the answer back (§4.1). The module imports nothing and can ask nobody who sent the message; everything it knows is in its input (§4.2).
6. **The answer goes back** through the guest, the host and the transport, sealed for A.

Public-key cryptography runs only per link and per install. A bundle a peer offers re-runs the whole install check on B, which is why a bundle authenticates against its author across any number of relays while a chat message authenticates only its one hop (§5).

---

## 14. Security considerations

**Trust depends on the property protected.** Anyone with host-process access controls slot construction, routing and admission, so bundle signatures constrain an author, never the operator. The host, its loader, its engines and its crypto are the trusted base. A bundle's confinement limits its powers, and its replaceability says how it can be updated; neither decides whether a given property depends on it.

| Protected property | Trusted with it |
| --- | --- |
| Code admission and guest confinement | The host's verifier, install path and guest seam, the engines, and the operator's policy. A valid signature identifies the author and commits to the bytes; it does not make the code safe. |
| The node key and signing-scope separation | The host, which keeps the key and picks each signature's domain and scope. A guest may misuse the signing oracle it was granted, but cannot extract the key or choose another slot's scope. |
| Channel confidentiality, record authenticity, peer attribution | Also the transport guest and its modules, which hold session keys, see plaintext, and supply attribution through `link/deliver`. A compromised transport can disclose channel data or fabricate attributed input within its granted services. |
| Application exchanges | The host's routing, the operator's choice of claim owners, and the receiving app. Protocol claims select who receives decrypted peer input; service claims select who receives local call arguments. |

**The transport is in the trusted base for channel security**, though it is replaceable signed content. Confinement keeps other slots' state and signing scopes out of its reach; it cannot protect plaintext or session keys already entrusted to it. A malicious transport can bypass the peer list, fabricate attribution, or have the host sign another network's transcript (§12.6.3); honest peers still enforce their own secrets and lists. It gets `link` only by the operator's boot selection or by replacing the slot that holds it (§12.5).

**Admitted apps are trusted with what they declare.** The host admits a bundle on the operator's word, confines its guest to `guest.requires`, scopes its storage and signing by label (§12.2) and holds its sends to the protocol ids it claims (§12.10). It does not contain an app within a service it was granted: apps with `fs` share one backend's space, and apps that use the transport share its send queues, so one can crowd out another. The model is a browser extension's: admitting a bundle is the permission, and the manifest says what was permitted. An embedder that admits bundles of mixed trust, such as ones a peer offers, shows `guest.requires` and `protocols` where the user decides.

**Authenticity is the channel's, per hop.** The runtime carries no per-message signature: the transport attributes each frame to the immediate peer. That is end to end for a direct exchange, and not across relays: an app that forwards messages authenticates the original author itself (§5).

**Domain-separated signature contexts.** Offline, an author signs bundle manifests and host blobs (§12.4, §12.9); a running host verifies those and never makes them. At runtime the node key signs the link occupant's handshake transcripts and an ordinary app's `node/sign` statements, each under a prefix from the `DOMAIN_*` family that the host picks from the asking slot (§12.2, §16.1). The prefixes are disjoint and never transmitted, so a signature from one context verifies in no other, and the key never enters a realm.

**Guest signatures verify nowhere else.** No app-obtainable signature verifies as a manifest, a channel transcript, or in another app's scope. The scope is the label's, so whatever holds the label next signs in it (§5), and who holds a label is the operator's `replaces`. Within its own scope an admitted app does speak for the node: a compromised guest can sign arbitrary statements in its namespace. The oracle form contains that: the key can be used but never exfiltrated, so uninstalling the bundle ends it, where an app-held key would outlive its compromise. Apps should sub-separate their signed formats under their scope with a leading tag each, as the transport does with `DOMAIN_channel`.

**The channel conceals both identities**, forward-secretly, and the identity key is signing-only. The construction, and what it does not hide (traffic metadata, a stable `host:port`, the cleartext suite byte), are [TRANSPORT](TRANSPORT.md), Handshake and Limits.

**The cryptographic root is the host, not a bundle.** Ed25519, BLAKE2b-256 and ML-DSA-65 are the manifest trust root, shipped in the host blob, and a host's successor is checked by the host it replaces (§12.9). The trust anchors are the loader and its genesis blob, the host author, and the operator's policy.

**The host author is a node's root of code.** With updates on, whoever holds the host author's key decides what every updating node runs, including the code that holds the master seed: a stolen host key is the whole node. That is why updates are off unless the operator turns them on, and why the key belongs offline. It cannot move a node below the version floor or reach a node with updates off (§12.9). A page is outside this: it keeps no slots, its origin is its trust root, and bundles and peer input run only inside QuickJS in wasm, so it needs no `'unsafe-eval'`.

**A leaked seed is a lost identity.** Nothing revokes a node key (§12.6.2b): whoever reads the seed can, indefinitely, complete handshakes, register at relays and sign in any app's scope as the node. Reaching it takes host-process access: the host, the loader, a host blob from the host author on a node with updates on, or the key file on disk and in backups. No guest reaches it. A compromised transport is the lesser case: it can act as the node over links while installed, and replacing it ends that.

**The host's name table grows only under a test.** Every host name must be implemented identically on every target, so an addition must satisfy one of three conditions:

1. the trusted base already calls it for its own work;
2. it cannot be delivered as a module at the endpoints, as the manifest verifier cannot;
3. it is a migration the host itself must call.

A pure function of bytes the guest already holds is computation, not a grant, and belongs in a module. The same test is why the residual `crypto/*` table does not shrink further. `blake2b` passes the first condition outright: the host hashes bundles and derives ids with it. `chacha20poly1305-ietf` is the per-record cipher, where a module would add a scratch copy per record against a library the host already links. `x25519/dh` fails the test on its merits, but removing it would mean vendoring a second, unreviewed, handshake-critical X25519, since none exists in the vendored post-quantum code. And a module cannot borrow the host's copy: reaching libsodium would mean exporting the memory that holds the node key.

**Freshness is not revocation.** `version` refuses downgrades (§12.4); it cannot say a key is still its author's. An attacker holding an admitted author's keys signs `version + 1` and lands as an ordinary upgrade. The remedy is revocation (§12.5). The residual is the window between compromise and the operator noticing, which no host mechanism shortens.

**Replay and ordering are settled where the bytes live.** The transport's per-direction counter rejects a replayed record within a session (§12.6.1), and freshness refuses an older install (§12.4). Routing keeps no state beyond the claim map, so a relayed message arriving over another link than it started on is the relaying app's to handle, with per-message signatures and a backlink chain (§5).

**Ownership is structural.** A slot holds exactly what was derived for it and a claim points at the slot (§3), so no ownership register can drift from the code it describes. There is no install log; an app needing verifiable lineage across relays builds it from signatures and backlinks (§5), where it can be verified.

**Claims select data recipients without granting services.** `protocols` and `services` cannot make unadmitted code run, widen `guest.requires`, or let an app sign in another's scope. They do decide which admitted app receives decrypted messages and local call arguments, and uninstalling the wrong recipient cannot retract what it saw. Collision checks keep a second slot off an occupied claim but reserve no free names, including those an uninstall releases. Operators should pin sensitive claims to approved owners in the admission predicate ([CLIENT](CLIENT.md#the-assembly-is-an-export) has the code). Channel authentication identifies the peer node, not the app answering on it.

**Structural sandbox.** A module has no host imports (§4.2); a guest reaches exactly its `guest.requires`, with ungranted services unwired (§12.1). Its modules, storage namespace and signing oracle are private values on its slot, so cross-app access is unrepresentable rather than checked per call.

### Resource bounds

Confinement says what untrusted code can reach; bounds say what it can consume. They follow the three resource laws (§12):

- **Module memory** is declared in the module and refused at admission when over budget (§4.1).
- **Module compute** is bounded by the calling guest's remaining deadline and killed at the engine when it runs out (§4.3), armed by default on every target.
- **Guest memory** is the realm's heap cap, and **guest compute** its deadline (§12.3).

Network work arrives only over authenticated links, but authentication is attribution, not trust: peer-initiated work is bounded per invocation, not in aggregate, and there is no node-wide CPU guarantee (§12.3).

**Module compute is bounded at the engine, not in the realm**, because the realm's interrupt cannot land inside a wasm call (§4.3). The bound is armed by default on every target, since a bound nobody turns on bounds nothing. On native it rests on a pinned fork of wazero (`native/go.mod`) that checks a termination flag in compiled code, which puts that fork in the trusted base; its cost is measured in `native/module_bound_bench_test.go`. The host's own crypto runs unarmed: a wedged trust-root module is a host bug, not a confinement breach. A deployer facing untrusted installs can also pre-validate module bytecode in the admission predicate.

**Guest compute is bounded by QuickJS's interrupt handler** on every target, so exceeding the deadline throws inside the guest and the realm survives. The engine is an in-repo build (`native/qjs/`) for that handler, and it keeps the engine's stack limit, so deep recursion throws a `RangeError` rather than trapping the engine.

**A stopped realm settles what it owes.** The host fails an interrupted invocation's caller itself, and every waiting caller on disposal, since delivering a rejection from inside the realm would be more guest work under the budget just exhausted. A bound that turns a runaway guest into a hung host is not a bound.

---

### 14.1 Cryptographic suites and update boundaries

Channel confidentiality, live authentication and long-lived app signatures are exposed differently to future cryptographic breaks.

**Recorded channel confidentiality needs both ephemeral secrets broken.** Every channel key from msg2 on derives from X25519 and ML-KEM-768, and both secrets are erased once session keys exist (TRANSPORT, Hybrid key establishment). Endpoint compromise while secrets or plaintext are live is outside that protection.

**Live-verified authenticity cannot be harvested.** Manifests carry hybrid Ed25519 and ML-DSA-65 signatures (§12.4), and a channel handshake is Ed25519 (§12.6). A recording of either verification buys nothing: a future ability to forge cannot install a past bundle or complete a past handshake. Only an attacker with a quantum computer at connection time could impersonate a node. This does not extend to app signatures kept as long-lived records (§14.2).

**Peer authentication stays classical for now.** That is where deployed protocols stand: TLS, Signal (PQXDH) and OpenSSH run hybrid post-quantum key exchange by default and keep classical authentication, because harvested traffic is the threat that exists today. Post-quantum authentication would add about 5.1 KiB to each of msg2 and msg3, against messages of about 1.2 KiB. Bundles are the other way round, long-lived and verified once per install, so they are signed post-quantum now. Moving peer authentication later is a transport and host update, and changes every peer id, since an id binding both keys is a hash over them, as the author id is.

**The hash is already fine.** BLAKE2b-256 is the one system hash (§5). Grover gives at most a quadratic speedup on preimage search, and at 256 bits collision resistance for author ids and content addresses is unchanged.

**Suite bytes keep the path open.** Both places that use public-key cryptography carry a suite byte, by one discipline: it is the first field of the structure it governs, and it is covered by that structure's signature.

- **Channel**: the first byte of msg1, folded into the transcript both ends sign, so flipping it makes them sign different transcripts.
- **Manifest**: the first byte of the envelope, inside the signed preimage. It lets a verifier read the field widths before it can verify anything, and reject an unsupported suite with its own error, since "this bundle wants a host I am not" is a different problem from tampering.

Neither is a negotiation: one suite per link and per manifest, unknown ids refused. The byte is read before verification yet covered by it, so it is legible up front but not editable underneath, and a future suite can change every field width without ambiguity. The two ids are independent namespaces, the manifest's the host's and the channel's the transport's.

**Manifest suite `0x02`** has four properties:

- **Both signatures must verify, not either.** "Either" is as strong as the weaker algorithm. Requiring both means a flaw in the young half fails closed, refusing valid bundles, which an operator can recover from. The ~5.1 KiB of header is paid once per install, off the message path.
- **The author id binds the whole key set.** Otherwise an attacker who breaks Ed25519 forges that half, supplies a fresh ML-DSA key for the other, and is admitted as the author, pins and lineage included. A future suite deriving its own id gives an author a new identity, which is honest: a different suite is a different statement about who signed.
- **Both keys are inside both preimages**, so the pair cannot be spliced.
- **A host without an ML-DSA verifier refuses the bundle** rather than fall back to Ed25519 alone, which would be exactly the downgrade the construction prevents.

**One verifier for every target.** ML-DSA-65 is one wasm module built from pinned source and run on every target's engine, as libsodium is. A verifier's accept/reject boundary is consensus, and two lattice implementations can disagree at the edges while each passes its own tests. The module is checked against NIST's published ACVP vectors, and hybrid-signed bundles, tampered ones included, go through the production install path in tests.

**Live agility is deliberately not solved.** Runtime negotiation would mean several implementations, a downgrade-resistant selection protocol kept correct across versions, and an attacker-influenced choice in the handshake. Migration stays an operator action.

### 14.2 Post-quantum exposure and remaining limits

Each role is protected according to when a quantum attacker could use it:

| Use | Primitive | Suite byte | Status |
| --- | --- | --- | --- |
| Channel session keys | ephemeral X25519 + ML-KEM-768 | yes | closed |
| Channel authentication | Ed25519 | yes | classical by design: verified live (§14.1) |
| Manifest signatures | Ed25519 + ML-DSA-65 | yes | closed |
| App signatures (`node/sign`) | Ed25519 | no, deliberately | the app's to close, inside its own records |
| Author ids and content hashes | BLAKE2b-256 | n/a | no change needed |

**App signatures can outlive their algorithm.** The argument that a signature need only be unforgeable when verified holds for manifests and handshakes. It does not hold for signatures an app keeps in a replicated log: every future replica verifies them, so their deadline is the record's lifetime. Once Ed25519 falls, an attacker can mint history that verifies. An app needing long-horizon non-repudiation adds a post-quantum signature or an external anchor (timestamping, a witnessed checkpoint) inside its own records.

**No suite byte on the seam, and no key in the guest.** `node/sign` is a call, not a format, and its algorithm is the host's business like its domain and scope; a suite byte belongs in the app's own record, beside its backlinks and version. A post-quantum key in the guest would surrender custody: a guest compromise could exfiltrate it, and uninstalling would no longer end its use.

**Sealed boxes are the app's.** Nothing on the runtime's own path uses a long-term DH or KEM key. An app that needs post-quantum sealing ships that transform in its own bundle.

**Downgrade by refusal is the open risk of any future rollout.** A signed suite byte stops downgrade by modification, but a dialer speaking a newer suite than its peer gets silence, indistinguishable from a wrong secret or an absent peer. The pressure that creates is to fall back because the peer looks down, which reintroduces the downgrade. A deployment that ever accepts overlapping suites needs an explicit rule: never retry an older suite after silence, and pin each peer's suite beside the key a dial already pins.

**Constant-time behaviour is an open item.** `mldsa65.wasm` and `mlkem768.wasm` are each built once from pinned source and run byte-identically on every target. Whether their signing and decapsulation paths are constant-time remains for independent review; passing functional vectors does not establish it.
