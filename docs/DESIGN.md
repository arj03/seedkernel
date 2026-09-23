# Seedkernel — Design rationale

*Why the runtime is shaped the way it is.*

> Rationale companion to [RUNTIME](RUNTIME.md) §12, under the same section numbers: RUNTIME §12.x says what the host *is*, DESIGN §12.x says why. The channel handshake's rationale is in [CHANNEL](CHANNEL.md), and the trust model in [SECURITY](SECURITY.md) §14.

---

## 12.1 Host services: raw-byte backends

**Only reach is declared.** A transform is computation, not authority: a bundle's modules are verified and installed with its guest, so calling one reaches nothing the guest does not already hold. Time is not authority either — every realm has ECMAScript's clocks. So `guest.requires` carries exactly what a guest could not otherwise touch — the node key, disk, its wake, sockets and other realms — and the list an operator reads is the bundle's whole reach. The residual `crypto/*` table is ungated for the same reason; why it is at its floor rather than mid-removal is argued in [SECURITY](SECURITY.md) §14.

**Names stay structureless.** Bytes in, bytes out, so the host never learns what an app means by them and bundles can change their wire and storage formats under the same boundaries. Anything with structure becomes a pure module, and the catalog grows by adding names sparingly.

**The seam is WASI-shaped, not WASI.** Like WASI it is a small syscall table, a zero-authority guest, and an ungranted service left unwired rather than checked. It differs where it has to: `link` moves bytes over opaque ids with peers addressed by key inside the transport, `fs` is a flat blob store with no paths, the node's identity is surfaced as a scoped signing oracle, and — the real difference — the grant is **signed content**, the `guest.requires` of an author-signed manifest admitted by operator policy, where WASI's grants are host-local instantiation choices with no authorship. WASI begins after who wrote the code and who may install it are settled; bundles and admission settle them.

**fs is asynchronous at the seam, not per backend.** IndexedDB is asynchronous by construction and OPFS is synchronous only inside a Worker, so a synchronous seam would make the browser the one target unable to carry storage. Backends that could answer inline are still wrapped to resolve in a microtask: a seam that resolved sometimes-immediately would let a guest work by accident on one backend and fail on the one it ships against.

**`MemoryFs` has a quota.** A host call bounds requests in flight, but a successful `fs/put` retains bytes after it settles; without a quota the in-memory backend turns bounded input into unbounded process memory.

**The fs scope is a hash of the label.** Keys double as filenames and both backends restrict them to `[A-Za-z0-9._-]`, which an author-chosen label cannot be trusted to stay inside, and a case-folding filesystem would merge labels differing only in case. Lowercase hex fixes both, and its fixed width means one label's prefix can never extend another's (plain concatenation would let app `x` key `yz` collide with app `xy` key `z`). The charset is a consensus predicate: two nodes disagreeing about a key disagree about their contents, which is why Windows device names are refused on every OS. `fs/stat` stays unscoped because a per-app `available` would be a fiction.

**Wrapping sockets is host code on every target.** A confined guest never holds a socket, so whoever owns the platform's object wraps it. The browser's only socket objects are `WebSocket` and `RTCPeerConnection`; because the browser has no raw TCP, WebSocket is a codec over a raw listener, which is why a node answers a browser's WS with no extra host code. Go wraps nothing — raw sockets are native there. WebRTC has no Go adapter because RTC exists for the browser's NAT traversal, and a native node is a reachable server. Whatever the object, the bundle cannot tell transports apart.

**A `RawLink` states only what the guest cannot know.** The guest named the destination, so it already holds the codec and the authority; what it cannot derive is whether the socket under that name frames messages, since the same `ws://` string is a platform `WebSocket` on one target and a byte stream on another.

## 12.2 The guest seam: the guest name ABI

**A name means what the manifest declared.** Dispatch builds one map of declared names at load and falls through to the host table, so it never reads a name's spelling. A method named where a service belongs is refused at load rather than accepted as a no-op or read as a finer grant the seam cannot enforce, and an unknown service throws, so a typo fails loudly rather than granting nothing — or everything.

**The gates are required arguments, enforced at runtime.** A seam is constructed with an allowed name set and a module map; omitting the set is a construction error, never an unrestricted seam. The check is a runtime one, not only a type, because the native target evaluates the compiled JS inside QuickJS where no TypeScript signature exists, and a gate that holds on one target of two is not a gate.

**One settlement algebra.** Because a produced value resolves and anything else rejects, nothing downstream re-derives failure from an answer's length, and "ran and returned nothing" stays distinct from "trapped".

**`__deferred` exists for answers that arrive through the realm.** Serializing invocations is right when the answer comes from outside — an app parked on `fs/get` must hold the queue, because its frame is suspended mid-update. It is wrong when the answer arrives *through* the realm: the transport answers an app's send by reading bytes off a link, and that read is another invocation of the same realm, so awaiting inside the frame would hold the queue against the only event that could settle it. The flag transfers queue occupancy and never time custody, which is why the deadline stays attached.

**`linkClosed` returns a reason instead of exposing a name.** A guest-callable "report close" would let the occupant say it about a link it never observed, and the return carries no link id, so it cannot redirect a transition to another socket. The pre-auth split answers the question an operator actually has — is the other machine absent, hostile, silent, or is the failure ours — and since the byte never goes on the wire, telling these apart locally does not weaken the handshake's silence ([CHANNEL](CHANNEL.md) §5).

**The signing scope is derived, never supplied.** It is the label's rather than the author's for the reason §5 gives. Deriving it from admitted facts (`slotSignScope`) is what makes it the same on boot, on `--bundle` and on an in-place update, so an upgrade cannot silently re-scope a node. `node/verify` counts as an authority, not a transform, because its scope is host-derived: "does this verify under *my* scope?" is a fact the guest cannot state for itself. Why the purposes share one key at all is [CHANNEL](CHANNEL.md) §7.

## 12.3 Zero-authority JS realms

**One entrypoint, for initiator and holder alike.** Which role an invocation serves is read out of the guest's own body format, never selected by the host. A second, synchronous seam is not available to offer: a holder answers from storage, and storage cannot answer in the same turn on a target whose backend is asynchronous. So both roles are ordinary async invocations of one entrypoint, and there is one shape to reason about.

**Invocations are serialized because re-entrancy is unreasonable.** The alternative is two frames resuming into each other at every await, in an order neither the author nor the host chose. The cost is head-of-line blocking, which `__deferred` relieves where it matters. The queue is shared code on both targets, because a guarantee that held on one and not the other would be a guarantee nobody has.

**Three laws, kept apart.** Space, lifetime and rate compose differently: space sums over owners, lifetime shrinks along a causal chain, and rate needs a schedule. A population bound is not a rate bound, and reading a limit in one column as a guarantee in another is the mistake the split exists to prevent.

**Every owner is bounded in time as well as size.** A release path nothing is committed to calling bounds only until the freeing event fails to happen. That is why every owner names its complete release paths.

**The link occupant's turns are its own.** It writes streams every caller shares, and a turn that runs out of time halfway through a record leaves a hole in one — so no single caller's clock may be the one it runs on.

**Deadlines read a monotonic clock.** A deadline is the distance between two readings; on a wall clock a step backwards would expire every live deadline at once and a step forwards extend them all.

**One wake per realm bounds timers by construction.** One armed wake with a fixed body needs no timer table, no ids and no payload accounting. Deadline tables, callbacks and scheduling policy live in the guest's own heap, where the heap cap already bounds them, and the guest reads its own clock to find what is due — so a wake left in flight by a replacement costs one walk, and needs no tag to be recognized. It arrives as a named event in the envelope the link events use, so no host input is told apart by its length.

**The clock share debits execution, not wall time.** Measuring the synchronous span of each host call separates compute from waiting without a list of which names do which: a name that does I/O has handed back its promise before the second reading. A timer fire is the one fresh root a guest can mint for itself — `timer/arm(0)` from inside a wake would otherwise repeat forever with no external initiator — so it is the thing paced. Attribution is per turn rather than per job because one realm's queue is shared by every root in it; the bound covers the realm's aggregate self-initiated work, which is what needs pacing. It deliberately stops short of a node CPU total: an authenticated peer can continuously replace settled work, and scheduling that ingress belongs to the transport, which can add per-peer pacing or fair queuing in a bundle update without a host change.

**A response is charged at delivery, not before.** A request's width is a fact the caller already handed over; an answer's is one only the backend learns. For `fs/get` and `fs/list`, learning it early means a second round trip or a budget threaded through every backend. That would not buy a bound — the delivery charge is already the bound — only a lower peak: the window where several answers are built and none charged, which the count ceiling already caps. If a listing over a huge store becomes the real problem, the fix is a cursor on `fs/list`, bounding the answer by construction.

**Pool within a tenant, quota between them.** Every owner is per realm and the realm count is bounded, which is what makes per-realm numbers ceilings rather than floors. Apps on one node do not trust each other, and an allowance they draw on in common is a standing way for a busy app to starve a quiet one. Where the tenant is one, a shared pool is right: every socket belongs to the link slot, so outbound bytes pool across links.

**Bounds cross every seam or they do not exist.** A bound the host accepts but no target can set is a bound nobody has; one the realm factory takes and nothing upstream carries is dead. `--guest-timeout 0` reads as "no budget" so that disabling one is something an operator says, never what a mistyped flag does — and edge values both engines would read differently (a heap limit of 0 means "none" to the JS engine) are refused.

**Execution time is the operator's.** Module memory is the author's to declare because it is a property of the code; how long *this* node will spend on one message is a property of the deployment. It matters most on the holder path, where an inbound frame runs guest code on the node's only thread: an interrupted guest throws, the transport answers a throwing guest empty, and a wedged guest costs one empty response rather than the link.

## 12.4 Signed bundles

**A bundle is a value, not a path.** One blob is read from disk, carried in an `OFFER` over a data channel, and stashed in browser storage without a second format or load path. Verification is channel-independent: a bundle from a USB stick verifies exactly like one pushed over a relay.

**What the manifest is for.**

- **The guest's authority has no other home.** A module holds no grants; the guest does reach I/O but is not a module and has no table entry, so the manifest's `guest.requires` is its entire grant. Nesting `requires` and `config` under `guest` groups the app's authority with its program, and makes "no authority" a shape — an empty list — rather than a rule every target must honour.
- **Version coherence.** Nothing at the module level says "codec at hash X and guest at hash Y together constitute v1.2". The signed manifest is that statement; without it a node could hold individually valid modules never meant to run together.
- **Operator/author separation.** The host is one fixed, auditable artifact; the app arrives as third-party signed content the operator's policy admits.

**One authentication, one authorization.** The signatures commit to every byte and position in the body, so there is no separate content-hash check; one predicate authorizes the whole set, and the set either becomes a slot or is released. There is no per-module callback, because trusting an author means trusting everything they signed. Modules never exist outside their slot, so the policy needs no ownership state and nothing can drift.

**The envelope's cryptography** — why both signatures must verify, why the suite byte is stored and signed, why the author id hashes the whole key set, and why the verifier is one shared wasm module — is SECURITY §14.1.

**The author seed label is frozen and lives in one file.** A copy that drifts fails as a changed author id — every policy pin misses and every freshness lineage restarts — and no test catches it when each copy agrees only with itself.

**Verify is split from construction so consent is possible.** An interactive client can show a bundle's author and metadata and wait before any realm or module instance exists.

**Runtime facts never come from config.** An author who baked the signing scope into `APP` would restate a load-time fact at build time, and a copy that silently disagrees fails as signatures that verify nowhere with nothing naming the cause. The same one-source rule governs the `DOMAIN_*` family. `HOST` budgets are advertised so a guest can *pace* itself — a fan-out windowed to the byte budget turns a mid-PUT rejection into ordinary backpressure. Transport policy values must be finite because an absent bound does not fail the comparison that applies it; it makes that comparison always false.

**The transport is keyed like any bundle.** A per-slot version floor would put every transport author on one version line with no owner: replacing A's v5 with B's transport would require B to number above a sequence B does not control. All it would buy is refusing B's stale v1 after A's v5, and that case needs someone other than the operator choosing which bundle replaces which. Nothing does — the transport changes only by boot selection or an install naming the owner it retires.

## 12.5 The admission policy

**The gates are the host's because they are invariants, not posture.** An `admitAll` node still has a downgrade guard and still honours revocation, and so does an interactive dialog that always says yes. One composition in shared code holds for every target and delivery path. Revocation comes first so a written-off key never reaches a consent dialog.

**Contests are not gates.** The same manifest is admissible on a node where nothing holds its names, so whether a name is free is a question about the node. Keeping it in the slot table is what keeps `admit` a pure function of the bundle.

**One install, one field of variation.** `replaces` is the only way to displace a slot, so an app's own next version and a different author's candidate take the identical path. What dies is then a thing the operator chose, never a coincidence of keys, and two concurrent installs of one app get a refusal rather than a silent winner. A `link` candidate needs the named predecessor to own `link` so that replacing an ordinary chat app can never acquire raw sockets.

**Revocation does both halves in one action.** It answers the stolen-key case freshness cannot (§14), and either half alone fails: uninstalling leaves the thief's next bundle free to re-land under the label; recording leaves the compromised code running; and an operator doing them by hand can do one, or do them in the order that leaves a window.

**Revocation is not a protocol.** A signed, relayable revocation needs someone authorized to sign one — a second trust set and a second key-management problem. That is worth it for a public deployment admitting third-party authors and out of scope here; a fleet applies a revocation the way it applies any operator decision.

**Recovery is a new key, not an un-revoke.** A key survives being put back in `authors`, so re-admitting a compromised author takes more than forgetting why it was removed. The set is keyed by author, not version range: "this key was good through v6" would invite rolling back under a key the operator just stopped trusting. A merely bad release is fixed by a higher version.

**The emergency path is the ordinary path.** A dedicated "replace this module" seam would be a second way to occupy a slot, exercised only in a crisis and so least tested when it matters most, and it would place an unsigned value into a slot so nothing could say who authored what runs there. A module so broken the node cannot load a bundle is a boot-path failure, answered by what the node boots with.

## 12.6 Node↔node transport: channel identity binding

**The protocol is content.** The handshake, records and routing are a signed bundle so a deployment can change them without a host fork. The *first* transport cannot travel: a node has no network until it has one, and fetching it over raw net from a peer it does not yet trust would open a metadata window before any channel exists to close it. So it ships in the artifact, and what travels is the next one. The handshake's own reasoning — concealment, ordering, silence, the three secrets, one identity key — is [CHANNEL](CHANNEL.md).

**The pre-auth cap exists because the application cap was a memory hole.** Applying the full frame cap to an unauthenticated peer let a stranger reserve megabytes per connection; 8 KiB against the 1,024 unverified budget is 8 MiB (sizing against the PQ message widths: CHANNEL §11). The cap is raised only after msg4's step runs because a full-size first record riding the same segment, measured against the pre-auth cap, would refuse a legitimate link.

**Reassembly is linear.** Joining every slice onto one buffer makes a dribbled full-size frame cost quadratic copies; keeping every slice costs a view and a pinned chunk per byte, times the half-open budget. Merging small slices into a doubling tail moves every byte a constant number of times. The WebSocket framer serializes `push` because `frames()` takes a frame before awaiting its decode, so a second parser would read the frame after it.

**The request window bounds what one peer holds, not what it costs.** An admitted request still runs to its deadline, and CPU across peers stays unscheduled. The window exists because every record open, seal and teardown draws on the same host-call budget, where a refusal takes a link down.

**The host keeps coarse bounds under the transport's.** "Half-open" and "authenticated" are states only the occupant sees, and the occupant is replaceable content. The host's structures cost a descriptor and a table entry the moment a socket is accepted, before the guest has an opinion, so the driver bounds them itself — and **refuses** rather than evicts, because which link is worth keeping is exactly the judgement it lacks. Its ceiling sits well above the transport's tiers, so an honest occupant never meets it.

**Each driver owner fails the way its situation allows.**

- *Inbound reads* fail the link that crosses the window, because 4,096 raw links must not each buy an independent realm invocation. The native reader goroutine waits instead: it is the one place backpressure costs nothing, and the socket's receive window carries it to the peer, whereas failing there would put a capacity cliff far below the link ceiling.
- *Signals* drop rather than tear down: one relay carries every peer, so a dropped signal costs one redial where a failed channel costs all of them. Byte and count limits are paired because the per-message caps admit a 256 KiB session description, so a count alone would make this lane the node's largest single allowance.
- *Outbound writes* fail the whole link, never one write: a record sealed and never sent is a hole in a nonce-ordered stream, and the peer's next decrypt would tear the link down as a forgery, blaming it for our own backpressure. Custody spans the adapter's buffer and the platform's backlog because both are bytes that link made the host retain. Retiring the drained *prefix* of admitted sizes, rather than waiting for an empty backlog a busy link may never reach, relies on ordering every transport already has.

**Teardown must not queue behind the wire it is ending.** The occupant runs one work chain per link so a teardown cannot overtake a record being sealed. But the WebSocket codec parks every write until its upgrade completes, so a peer that dribbles a partial head and stops would park msg1 forever, with the handshake deadline's own abort queued behind it. Severing the wire synchronously first breaks that.

**A request inherits its caller's deadline, and neither clock is waited out needlessly.** Transport content cannot extend an owner's time because bytes happen to be moving; that is why `buffered()` is host-only and why `requestTimeoutMs` only retires the transport's own bookkeeping.

## 12.7 Browser↔console WebRTC

**Identity is proven in-channel.** The handshake runs inside the data channel, which is continuous channel binding — stronger than a one-shot SDP `a=fingerprint` at the signaling layer (RFC 8827 §5.6.4). A MITM relay can splice SDP and bring DTLS up to itself, but cannot produce the transcript signature without the peer's key, so the link never authenticates and never delivers a byte. That is also why signaling needs no signature and carries no credential: an RTC link opens under the node's own contact secret, so signaling has no secret to leak.

**Signaling is measured before it is believed.** Charging a description at the boundary means nothing oversized is retained across the async negotiation that follows. A peer that establishes and never carries a data channel is reaped by the same deadline as one that never establishes, because leaving the speculative cap is not the same as being a live link.

**The peer-connection factory is the app's.** The seam the runtime owns is a byte duplex; an ICE/DTLS/SCTP implementation is one way to produce one, so the runtime depends on none. A console peer wants a pure-JS library, since it must bundle into `bun --compile`, where a native binding like `node-datachannel` segfaults.

## 12.8 The shell: node assembly and the CLI

**`bootShell` is the one assembly.** There is no layer beneath it for a target to reach: transport selection and load order are part of standing a node up, not steps a caller may skip. `bootNodeShell` is convenience for a Node application, not a second assembly.

**The CLI is shared so decisions are made once.** Tokenizing arguments is a dozen lines; the flag set and the boot sequence are the point, because a decision made twice is eventually made differently. The five `CliHost` members decide nothing.

**`--op` is one flag with stdin/stdout.** An op is a name travelling in `handle`'s payload that the runtime passes through unread, so a flag per operation, or a choice of argument flag, would have to know each app's argument shape. Bytes in, bytes out is `handle`'s ABI exactly; logs go to stderr so an operator line cannot corrupt a redirected response. The op targets the loaded bundle's handle, not "the only app", which a networked node cannot mean since its transport is an app too.

**`--contact-secret` is a file** because an argument is visible in `ps` output and shell history.

## 12.9 The native binary — the primary non-browser deployment

**A platform target, not a reimplementation.** Go grows with primitives, never with logic: protocol is never re-derived in a second language, and verification, admission, scope derivation, freshness and routing each have one implementation to audit. The generated bundle makes a missed target change a compile error. Both QuickJS builds come from one pin, so a behavioural difference between targets is a build difference, not a version difference.

**Why the fast-path rule has three conditions.** A standardized primitive with byte-identical, KAT-pinned output differs only in speed. A verifier fails condition 3, because its accept/reject boundary is consensus (§14.1). So BLAKE2b-256 and the record-layer AEAD, which only transform bytes, are native; Ed25519 and ML-DSA-65, which decide acceptance, stay on the shared wasm. It is the same trade as `ws.wasm` against a native RFC 6455, and it will come up again for every suite added.

**Size.** The binary trades a larger single artifact (~7.5 MB) for zero external dependencies — the right shape for a server or appliance — against a JS host needing a Node/Bun install plus the lazily loaded QuickJS. The protocol's own footprint is tens of KB. QuickJS is lazy on the JS targets because a host with no installed slot should not pay for a realm.

**Minification is a second `tsc` pass**, not a bundler: no new dependency, and the compiler is the one tool on hand that can tell a regex literal from a division, so nothing hand-written lexes the host.

## 12.10 Protocol routing — which app handles a message

**A frame names a protocol, not an app.** Apps, authors and modules are node-local; a wire that named them would make every peer's install choices everyone else's business. A peer states only the protocol, and the receiver's installed claims decide which verified code answers.

**The manifest claims, and install is the claim.** Nothing installs an app it does not mean to serve, so admitting and claiming are one act, and which protocol an app speaks is stated once by its author — not retyped at every deployment, where a typo's only symptom is a node that boots clean and answers empty forever.

**Two lists, two maps.** Reach follows from which map holds a name and nothing else: a `services` name is not in `peerClaims`, so no peer can reach it by construction, not by a second check. The same name in both lists says "reachable either way" — two reaches to one owner, which a single union map could not express.

**The raw-link binding is a claim.** The driver has one event sink, so a second holder would take the node's sockets off the first while leaving its claims and realm in place — installed, routed, and silently off the network. Claiming it under the same rule as a name makes that a refusal. The occupant that sees plaintext is the one that attributes: holding the sockets *is* the authority to say which peer a request came from, because nothing else ever held the bytes.

**`onInbound` exists because the transport consumes the answer.** An embedder whose mounted app must paint what it just answered — seedchat relaying render bytes to its page — has no other path to those bytes. Scoping the callback to the load keeps it a hook, not a second owner kind in the claim map.

**One slot per protocol.** Fan-out would be an authority-bearing observer model needing its own admission semantics; until then a single value is the honest shape.

**Transport replacement discards the address book.** The host keeps nothing peer-shaped, so there is no second copy to migrate; both in-repo callers already hold the list they would re-supply (`cli.ts` from `--peers`, seedstore's `StorageNode.connect`), and one spelling of a cohort serves boot and replacement alike.
