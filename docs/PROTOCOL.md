# Seedkernel — Protocol

*The message model, bundle slots, the restartable WASM module ABI, and names. §16 collects the protocol constants.*

> **Part of the [seedkernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · **PROTOCOL §2–§5, §16** · [RUNTIME](RUNTIME.md) §10–§12 · [SECURITY](SECURITY.md) §13–§14

---

## 2. The message model

A message at the runtime boundary is `(protocol id, input bytes)`. The transport has already decrypted it and attributed it to a peer key (§12.6). The host resolves the protocol claim directly to a bundle slot, prepends that peer key, and invokes the slot's guest `handle` entrypoint. There is no module dispatch on the inbound path.

The guest may call one of its own restartable modules by bare name on `host.call` (§12.2). Those modules are private values captured by that guest's slot: no app label participates in lookup and no other guest can address them.

**No wire format means no host-level size cap.** The bounds live where bytes flow: the transport caps a frame at `MAX_FRAME_BYTES` and a module caps I/O at its scratch size (§4.1).

**Authenticity is the channel's.** There is no per-message signature in the host; an app that relays content carries its own end-to-end attribution (§5).

---

## 3. Bundle slots

The host's lifecycle model is one direct projection:

```
claim → { verifiedBundle, realm, pureModules, fsScope, signingScope }
```

The realm is the only inbound entry. `pureModules` is a private name-to-instance map captured by that realm's seam. `fsScope` is derived host-side from the verified manifest's `app` label, and `signingScope` from that label or — for the slot reaching `link` — the constant `DOMAIN_link_scope` domain. Neither is chosen by guest code. A slot can own several claims; each points to the same value.

The host also retains installed slots for administration and initiator-only bundles, but that collection is not a second routing model: dispatch is always one `claim → slot` lookup, and each claim has one active owner (§12.10).

The `app` label is the slot's key (§5). Host invocation uses the slot-bound handle returned by a load. Labels are not module addresses and claims do not route through them.

### 3.1 Atomic load and replacement

A load verifies and admits the bundle, builds every private module and the confined realm off to the side, persists the freshness mark, and only then synchronously replaces the installed slot and reprojects its claims (the full sequence is §12.4).

Nothing is published before that commit. A malformed module, broken guest, or failed freshness write disposes only the candidate; the running version and all of its claims remain unchanged. The claim commit contains no `await`, so a bundle that owns several claims cannot be observed with only some replaced.

The candidate realm evaluates its guest's top level between steps 3 and 5, and the realm factory runs it synchronously inside the seam — so an effect reached for there has already landed by the time step 5 decides. Until the slot is marked active the seam therefore refuses **every** name, and a guest's authority begins at its first post-commit invocation: disposing a candidate is a real undo because a candidate did nothing to undo. A top level may still define state and validate what the preamble handed it; anything it needs the host for belongs in the first invocation. A link candidate stands its whole routing state here, from its installation-local `LOCAL` config and the node identity in `HOST` (§12.6).

An upgrade replaces the entire slot. A module omitted by the new manifest therefore disappears with the old slot, as do the old realm, timers, scopes, and all other module instances. `uninstall` and `revoke` remove the slot as the same unit and dispose everything it owns; there is no single-module lifecycle.

### 3.2 Target implementation

Only construction and execution of `pureModules` vary by target. JS builds a private map of worker-backed instances and returns closures over it. Native may keep an opaque handle into a Go map because wazero modules cannot be JS values. That map is an implementation detail behind the slot, not a host API or model.

The shared host code owns verification, admission, ordering, scope derivation, realm construction, and the atomic claim commit (§12.9). A host starts with no slots and a deny-all admission policy; loading signed bundles is the only growth path.

---

## 4. The WASM module ABI

A module is a **restartable transform**: bytes in, bytes out, private WASM memory, and no host imports. Any language that compiles to WASM (AssemblyScript, C#, Rust, C, Zig, Go) can implement the contract — it is three required exports and no host imports.

The contract promises isolation, not statelessness or determinism. A module may retain private caches and mutable state between calls, but callers must tolerate that state's loss on a respawn (§4.3).

Modules exchange bytes with the host through a **scratch region** in their own linear memory. There is no allocator contract, no pointers crossing the boundary, no buffer lifetimes to reason about — just "read input here, write output there, return the length."

### 4.1 Exports (module must provide)

| Export name | WASM type | Description |
| --- | --- | --- |
| `memory` | linear memory | Module's memory; the host reads input from and writes output to the scratch offset within it. |
| `scratch` | `global i32` | Byte offset into `memory` where the host places input and reads output. Set once during instantiation; the host reads it once after instantiation and the module MUST NOT change it afterward. |
| `scratchSize` | `global i32` *(optional)* | Bytes of scratch the module reserves at `scratch`. The host reads it once at instantiation and clamps its input/output copies to it; a value below the 128 KB default or naming out-of-bounds memory is refused fail-loud (the install throws). Export it only if the module genuinely reserves that region — the host writes there. |
| `handle` | `(i32) → i32` | `(input_len) → output_len` — transform the input at `scratch` and return the response length. |

**Declared memory is bounded.** A module MUST declare a linear-memory **maximum**, and both its initial size and that maximum MUST fit the host's per-module budget (`DEFAULT_MAX_MODULE_MEMORY_BYTES`, §16). The host reads the limits off the module bytes *before* instantiating it (`wasm-limits.ts`), because instantiation is what allocates the declared initial memory — a module asking for 4 GiB has already taken the host down by the time an export check could see it. A module that declares no maximum is refused: WebAssembly gives an embedder no way to impose one afterwards, so an undeclared maximum is an unbounded one. Two further refusals fall out of the same read and defend §4.3's claims rather than a budget: an **imported** memory (linear memory must remain private even though fixed inert function shims are allowed, §4.2) and a **shared** one.

For AssemblyScript that requirement is one build flag, `--maximumMemory` (in pages).

**Declared tables are bounded on the same walk, against the same budget.** A table is the other host allocation a module buys by declaring it — the engine reserves every element at instantiation and `table.grow` reaches the declared maximum — so a bound on pages alone would leave the same exhaustion open under another section header. Each element is charged `WASM_TABLE_ELEMENT_BYTES` (§16) and the total is added to the module's memory: the per-module and per-bundle budget is what a module may allocate, not one allowance per kind. The refusals mirror memory's: a table with no declared maximum, an imported table (§4.2), a shared or 64-bit-indexed one, and an element type outside `funcref`/`externref` — the last because a table the walk cannot read is a table it cannot charge. A module that declares no linear memory at all is still charged for its tables, since instantiation reserves them before any export check runs.

**I/O protocol.** Before each call, the host writes the input bytes at offset `scratch` (up to the configured scratch size — default 128 KB, or the module's exported `scratchSize`). The module reads its input from `scratch`, writes its response back at `scratch` (overwriting the input is fine), and returns the number of response bytes. Return `0` for "empty response." The host reads `output_len` bytes at `scratch` after `handle` returns and does not touch the region again until the next call; a trap or a negative/oversized length makes the guest's `host.call` promise reject. Each target's module runner reports failure as null; returning `0` succeeds with zero-length bytes (§12.2).

Memory outside the scratch region is the module's private state — statics, globals, whatever allocator it wants for its own bookkeeping — but none of it is durable: a deadline kill discards the instance and respawns a fresh one (§4.3), so that memory is scratch or cache, never the system of record. Anything that must survive a respawn belongs in the guest or the filesystem, not module memory.

### 4.2 No host imports — the isolation boundary

A module imports **nothing from the runtime** — no host seam, no host functions. The only imports it carries are its own language runtime's shims (for AssemblyScript, `env.abort` / `seed` / `trace`), which are not a route to the outside world.

**Every target resolves exactly that set, and none grants I/O.** `seed` is a constant rather than a clock read, `trace` drops its arguments, and `abort` traps — a module that aborts fails its call on every target rather than running on past the point it declared itself broken. These shims do not make stateful module code deterministic (§4.3). The set is fixed rather than per-target because one `trace()` or `Math.random()` anywhere in a module is the difference between loading and a missing-import failure: a host resolving a subset would refuse modules another host accepts, and would do it at instantiation, far from anything that reads like an import problem.

Concretely, a module **cannot**:

- reach the filesystem, network, clock, or any I/O;
- call another module, or resolve a name — there is no cross-module call and nothing to look a name up in;
- ask who sent the input, who signed anything, or who called it — there is no signer, no caller, no author query.

External data arrives **in the input**, and results leave **in the output**; a module may also read and modify its own private memory. When a message must carry the sender's identity to the module, the orchestrator prepends it to the input from the authenticated channel (§12.6) — as the chat app does, staging `senderPk ‖ body` (§11). Private state does not add ambient authority: the module still has no host imports.

**Composition is the guest's job.** Chaining transforms — running one module's output into another, fanning out, doing I/O between steps — is the app's guest, never a module's. A guest reaches only the private module set captured by its slot, using bare names on the guest seam (§12.2). Because a module cannot call back, these compose without re-entrancy: each transform returns before the next runs.

### 4.3 Safety & memory model

What a module **cannot** do, restated as guarantees:

- **No outside-world reach.** With no host imports (§4.2), a module can modify its private state and return bytes, but cannot perform I/O. It cannot open a socket or a file even if compromised — not by a rule in its code, but because nothing that reaches one was ever imported.
- **No cross-module corruption.** A buggy or malicious module can scribble anywhere in its own memory but cannot touch the host or another module — each runs in its own WASM instance, and the host copies bytes between scratch regions rather than sharing pointers.
- **No pointers cross the boundary.** There is no allocator contract; the host never holds a pointer into a module's memory across a return and never writes outside the scratch region.
- **No durable state.** A module's memory beyond scratch (§4.1) is its own, but not guaranteed to last: a deadline kill (below) respawns a fresh instance and whatever the old one held is gone. A module is a **restartable transform** — it may use its memory as scratch or cache, but a caller cannot depend on any of it surviving a respawn, and must handle a failed call and instance reset. The host does not verify that resetting private state preserves application meaning.

> **Memory is bounded at admission; compute is bounded at the engine.** Two bounds, two mechanisms — a declaration read off the bytes, and a deadline the engine can land on.
>
> **Memory** is closed at admission: a module declares its ceiling and the host refuses anything above its budget, or anything that declares no ceiling at all (§4.1). The check is a property of the bytes, so it holds identically on every target — it runs on the shared admission path (§3.2), not in each host's instantiation code.
>
> **Compute** is charged to the calling guest and interruptible where the guest's budget ends. A module call runs under a deadline: the calling guest's **remaining execution segment**, computed by the realm at the moment of the call, and a call that burns it rejects at the guest seam — as a trap does — while the engine kills the module. A successful zero-length result remains distinct from failure (§12.2). How the kill lands is per-target, because no engine mechanism is shared: the JS targets run each module in its own worker, and `terminate()` destroys the isolate mid-loop if it must (the one interrupt the JS platform's WebAssembly exposes), respawning a fresh instance for the next call; the native target arms wazero's `WithCloseOnContextDone` and passes that same per-call remainder as the call context's deadline. The call is async on the guest seam (§12.2) — the guest parks on it like any other round-tripping name — so a spinning module burns one core for at most one budget and holds nothing else on the node. §14 has the exposure that remains and what a deployer does about it.

**Replay and ordering are settled off the module**, at the layer that owns the bytes (§14): a module's memory is disposable, so it has no durable notion of "seen this before".

---

## 5. Names, hashes and relayed authenticity

**Names are strings.** A module name, an `app` label and a claim are opaque strings the host only ever matches — nothing forces a hash, so a name reads plainly in a log and in a manifest.

**A module name is slot-local.** Nothing on the wire names a module. A peer sends a protocol id and the receiving host resolves that claim directly to a slot (§3); the slot's guest reaches only its own modules, by manifest name through `host.call` (§12.2). No label is concatenated with or consulted for that lookup, so two hosts can install the same code under different app names and still interoperate.

**The label is the namespace; the author is trust and lineage.** The `app` label, each `protocols` claim and each `services` claim are literal manifest strings, and each has one active owner on a node. A candidate contesting an occupied label or claim is refused; a replacement of the slot holding it atomically takes over that slot, its label and its claim set, whoever authored it (§12.10). The label names the slot's filesystem and signing scopes, so they belong to the label rather than to an author: a fork under the same label signs and verifies in the same scope, an author who rotates its key keeps its records, and whatever holds the label next inherits its data. The author is what admission and revocation decide on (§12.5), and it keys the freshness mark, so versions are an author's own count (§12.4).

**One hash.** Content hashes, author ids and binary pins use **BLAKE2b-256** — the genesis hash, computed by `genesisHash`. The same primitive appears in the guest catalog, the AKE KDF and transcript, and the block-id path.

**Relayed-message apps layer their own authenticity.** The channel authenticates one hop (§12.6). An app whose messages pass through intermediaries — a feed, a forum, store-and-forward gossip — cannot let the channel speak for the *original* author, so it adds a per-message signature naming the author, plus **backlinks** (a hash-chain, à la [SSB](https://ssbc.github.io/scuttlebutt-protocol-guide/)'s `previous` or [Bamboo](https://github.com/AljoschaMeyer/bamboo)'s lipmaa links) to order the history and make equivocation detectable. Signed bundles (§12.4) already do the author half for relayed *code*; a relayed-message app does the same one layer up, and it is a distinct app from chat, whose every message travels a single hop (§14 has the rationale for keeping lineage out of the install path).

---

## 16. Protocol constants

Protocol constants and the principal runtime limits in one place. Multi-byte integers are big-endian throughout the protocol.

**A value appears here only where a second implementation has to match it** — wire widths, suite bytes, domain prefixes, the charsets and the caps both ends enforce. Everything else is a *default*: a number this deployment picked, which an operator, an embedder or a signed transport bundle may change. Those rows name the constant and what it bounds but state no value, because there is nothing for a second implementation to agree with — the retained deadlines are the one qualification, since they are each side's own tolerance rather than an agreed number, and a peer feels a short one only as a connection that does not complete. The values live in source (`host/wasm-limits.ts`, `services/net-limits.ts`, `services/net-rtc.ts`, `transport/src/{ake,framing}.js`, `scripts/transport-config.mjs`) so there is one place to read it and nothing to keep in step.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| `DEFAULT_SCRATCH_SIZE` | `131072` (128 KB) | Module instantiation | Per-module I/O region at `scratch`; a module may declare more via `scratchSize` (§4.1). |
| `DEFAULT_MAX_MODULE_MEMORY_BYTES` | *host default* | Slot construction (`loadBundleModules`) | Ceiling on a module's declared initial *and* maximum footprint — linear memory plus its tables at `WASM_TABLE_ELEMENT_BYTES` each — read before instantiation (§4.1). Applied at that one call site, so every target holds its isolates to one number rather than repeating the rule per target. |
| `WASM_TABLE_ELEMENT_BYTES` | `32` | Slot construction (`loadBundleModules`) | Host bytes charged per declared table element, so tables meet the module budget above (§4.1). A charge rather than a wire value, but one every target must make alike: a module admitted on one node and refused on another is a bundle that loads by luck. Conservative — a funcref entry measures ~28 bytes on V8 and 8 in wazero. |

An unclaimed peer protocol is answered with an **empty response** (§12.10), while a failed module call rejects at the guest seam (§4.1). A module returning zero bytes has succeeded. An undeclared or unknown guest-call name is refused as a catalog error; absence is not a blanket empty-result rule (§12.2).

### 16.1 Host constants

These belong to the reference runtime (§12), not the §3 slot model — a different host could change them without changing that model, but they are wire- or ABI-visible to bundles and peers of *this* runtime. Its bounds follow the three laws of §12.3.

| Constant | Value | Where enforced | Notes |
| --- | --- | --- | --- |
| Author id | 32 bytes | Manifest envelope (§12.4) | `genesisHash(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖ ml_dsa_pk)` — BLAKE2b-256 over the whole hybrid key set (§14.1). |
| Seam names | `crypto/*`, `node/*`, `fs/*`, `timer/*`, `link/*`, this realm's declared local service ids, and the bare names of the calling bundle's own modules (`codec`, `ws`, `mlkem`, …) | guest seam (§12.2) | Guest↔host identifiers, never wire values; resolution and the disjointness rules are §12.2. |
| Manifest requires | `HOST_SERVICES` (`services/domains.ts`) + local service ids | manifest `guest.requires` (§12.4) | Host services are granted by service, never by method (§12.1); any other entry is a local service id, resolved at call time, so an id nothing claims yet is not a manifest error (§12.10). `crypto/*` and module names are not declarable. |
| Host transforms | `blake2b-256`, `chacha20poly1305-ietf/{seal,open}`, `x25519/dh`, `random` | guest seam `crypto/` prefix (§12.1) | Frozen compatibility table (`HOST_TRANSFORM_NAMES`); why it is at its floor is §14. |
| Transport | `link`, and an ordinary local service claim chosen by composition | manifest `guest.requires` + `services` (§12.4, §12.5) | `link` is authorized only by boot selection or by replacing its current owner (§12.5), and binds raw-link events to that one slot (§12.10). The service claim grants no authority and has no host-known spelling. |
| Manifest envelope | `0x02`: `[suite 1][ed_pk 32][ml_dsa_pk 1952]`<br>`[ed_sig 64][ml_dsa_sig 3309][body]` | `verifyBundle` (§12.4) | Fixed width. **Both** keys sign `DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ BLAKE2b-256(body)` and **both** must verify (§14.1). |
| Link messages | msg1 1,265 B, msg2 1,168 B, msg3 112 B, msg4 112 B, then AEAD records | transport bundle (§12.6) | Bare bodies with no type byte, each accepted only at its exact width. |
| Algorithm suites | channel `0x03` · manifest `0x02` | msg1 byte 0 (§12.6) · manifest byte 0 (§12.4) | Two independent namespaces; each accepts exactly one value, is never negotiated, and is covered by the signature it accompanies (§14.1). An unknown channel id draws silence. |
| `DOMAIN_manifest` | `"seedkernel-manifest-sig-v1\0"` | Manifest signature (§12.4) | Prepended before signing, not stored. |
| `DOMAIN_manifest_author` | `"seedkernel-manifest-author-v1\0"` | Author id derivation (§12.4) | The one member of the family that prefixes a *hash* rather than a signature, so a derived id can never also be something someone signed. |
| `DOMAIN_guest` | `"seedkernel-guest-sig-v1\0"` | `node/sign`/`node/verify` for an ordinary app (§12.2) | Followed by the host-derived scope `app_len u8 ‖ app`. Host-applied on both sides, never transmitted. |
| `DOMAIN_link_scope` | `"seedkernel-link-scope-v1\0"` | `node/sign`/`node/verify` for the slot reaching `link` (§12.2) | No further host-owned scope bytes. Host-applied on both sides, never transmitted; the format signed under it is the occupant's. |
| `DOMAIN_channel` | `"seedkernel-channel-id-v1\0"` | Transport bundle's transcript and identity payloads (§12.6) | **Not a member of the family** — a format tag inside the transport's own content, sub-separating its formats within `DOMAIN_link_scope`. Declared in `transport/src/ake.js`. Not transmitted. |
| Contact secret | 32 bytes, out of band | msg1 seal, every handshake KDF (§12.6.3) | Per node, never on the wire. Absent = open node. |
| Network key | 32 bytes, config | transcript root (§12.6.3) | **Public by design.** Seeds the transcript root, so every key and signature preimage differs between networks. |
| Master seed | 32 bytes, on disk | `subkeys.ts` (§12.6.2b) | The node's only stored secret; signs nothing; derives the `channel` keypair whose public half is the node's identity. |
| `AUTHOR_MLDSA_SEED_LABEL` | `"seedkernel-author-mldsa-v1"` (no trailing NUL) | `hybridAuthorKeysFromSeed` (§12.4) | KDF label: `genesisHash(ed25519_seed ‖ label)` is the same author's ML-DSA-65 seed. **Frozen** — changing it re-identifies every author built from a seed. |
| FS key charset | `[A-Za-z0-9._-]+`, minus `.`/`..` and Windows device names | `isSafeFsKey` (`services/fs.ts`, §12.1) | A consensus predicate: backends map a key to a filename verbatim. A scope is a prefix, not a complete name, and is held only to the charset. |
| Node address | `pk[.secret]@[scheme://]host:port[/path]` | `parsePeerRef` (§12.6) | Peer id, optionally that peer's contact secret, and an opaque destination `scheme://host:port[/path]` — what `link/open` carries. `tcp://` is node↔node, `ws://`/`wss://` the RFC 6455 codec (the latter asking for TLS), and a path reaches a peer behind a reverse proxy. A reference with no scheme takes the default of the flag it was typed under. No long-term DH or KEM key is published. |
| `MAX_FRAME_BYTES` | `2097152` (2 MiB) | transport bundle (§12.6) | Cap on one post-authentication frame, checked before buffering; the transport does not fragment, so it is also the largest application message. The signed default of `maxFrameBytes` (`scripts/transport-config.mjs`); a deployment may lower it with `transport.config.maxFrameBytes`. `ws.wasm` stages a whole frame in a scratch region, and a platform-framed link carries one frame per message under the host's `MAX_LINK_READ_BYTES` (§12.6), so raising it means rebuilding `ws.wasm` and raising that read cap (both asserted by `tests/transport.test.mjs`). |
| `MAX_HANDSHAKE_FRAME_BYTES` | `8192` (8 KiB) | the transport bundle's framers (§12.6.2) | Inbound frame cap **before** authentication, raised to `MAX_FRAME_BYTES` after. |
| `LINK_IDLE_TIMEOUT_MS` | *transport default* | transport bundle (§12.6.2) | An authenticated link idle in both directions this long is retired with the authenticated goodbye — the other half of `MAX_AUTHED_LINKS`. |
| `UNVERIFIED_TIMEOUT_MS` | *transport default* | transport bundle (§12.6.2) | Time an accepted connection has to send a msg1 that opens. |
| `HANDSHAKE_TIMEOUT_MS` | *transport default* | transport bundle (§12.6.2) | Deadline for the rest of the handshake, armed once msg1 opens; every pre-auth refusal lets it expire. |
| `REKEY_AFTER_FRAMES` | `16777216` (2²⁴) | transport bundle records (§12.6.1) | Frames per epoch before the sending direction ratchets its key. **Both ends must use the same value**: the `(epoch, counter)` nonce is implicit, so ends that ratchet at different counts derive different keys and every later record fails. It resolves as `LOCAL.rekeyAfterFrames ?? APP`, so lowering it on one node alone breaks its links to every peer on the default. |
| `REJECT_AFTER_EPOCHS` | `65536` (2¹⁶) | transport bundle records (§12.6.1) | Epoch ceiling; reaching it retires the link rather than repeating a nonce. |
| Transport frame kinds | `req 0x00`, `res 0x01`, <br>`FLAG_NO_REPLY 0x80` | transport bundle (§12.6) | Single request/response plane, carried inside the §12.6 AEAD record layer. A req names a protocol id so a node hosting several apps can route it (§12.10). `FLAG_NO_REPLY` is OR'd into the kind byte for fire-and-forget sends: the receiver still dispatches to the app but skips the response frame, and the wire corr is **0** (nothing is parked). A response is `[1][corr u32][payload]`, so an **empty** response is exactly five bytes — a 6-byte floor would drop "no app serves this protocol" and make it indistinguishable from an unreachable peer. Six is the request branch's floor (protocol-id length at offset 5). |
| `DEFAULT_MAX_OUTSTANDING_HOST_CALLS` | *host default* | realm host-call seam (§12.3) | Unresolved calls one realm may hold outside its heap. |
| `DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES` | *host default* | realm host-call seam (§12.3) | Copied input bytes across those calls, charged for **every** call before the copy; a response is charged as it is delivered (why: [DESIGN](DESIGN.md#123-zero-authority-js-realms) §12.3). |
| `UNESTABLISHED_PEER_TTL_MS` | *host default* | WebRTC signaling (`services/net-rtc.ts`, §12.7) | One deadline per peer entry, disarmed only once the entry is both `connected` **and** bound to its data channel — the polite side never opens a channel, so a peer that completes DTLS/ICE and stays silent would otherwise never be reaped. |

**The `DOMAIN_*` family lives in one file.** The four prefixes above are a *family*, and the only thing they are for is disjointness: no signature made under one may verify under another, over any bytes, ever — and no derived id may collide with a signed preimage. That is a property of the whole set rather than of any member, so the set is declared together in `services/domains.ts` — where adding a member means reading the others on the same screen — and imported by the modules that sign (`bundle-author.ts`, `guest-seam.ts`). The transport bundle's guest program never sees one: it asks for a signature through `node/sign` and the *host* chooses the prefix from the asking bundle's slot (§12.2), so a prefix cannot be restated in content either. The Go/native target evaluates that same file through its generated bundles (§12.9) and reads its prefixes from the evaluated module, so every prefix on every target derives from this one file by construction, not by a copy that could drift. There is **no** hand-copied member anywhere.
