# seedkernel: runtime

*The runtime as an app host: performance, the chat demo, and the host's normative surface — host services, the guest-seam ABI, zero-authority JS realms, signed bundles, admission, the node↔node transport, the targets and routing.*

> **Part of the [seedkernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · [PROTOCOL](PROTOCOL.md) §2–§5, §16 · **RUNTIME §10–§12** · [SECURITY](SECURITY.md) §13–§14
>
> This file states each rule once. Why a rule is shaped the way it is lives in [DESIGN](DESIGN.md), under the same section numbers, and for the channel handshake in [CHANNEL](CHANNEL.md).

---

## 10. Performance

The message path does **no asymmetric cryptography and no recursion**: routing a frame to an app is one claim lookup (§12.10) plus one guest entrypoint invocation, and the only scratch copies are the ones a guest's own module calls make (§4). Authenticity is the channel's (§12.6), established once per link.

### 10.1 Where the crypto is now

- **Per connection:** the AKE handshake (§12.6) — one Ed25519 sign + verify, one ephemeral X25519 exchange, and one ML-KEM-768 encapsulation or decapsulation per endpoint.
- **Per frame:** one ChaCha20-Poly1305 record seal/open (§12.6).
- **Per bundle load:** one BLAKE2b-256 hash of the body and verification of both Ed25519 and ML-DSA-65 signatures (§12.4).

The Go/native target carries `*_bench_test.go` benchmarks over these hot paths (§12.9); `npm test` from `WASM/` exercises them end-to-end on the JS target, and seedstore's `WASM/tests/bench.mjs` measures storage throughput.

### 10.2 Distribution Size

This is the one place these figures live.

| Component | Size |
|---|---|
| `services/*.js` + hand-written `host/*.js` a page can reach — minified (`build-min`, excluding the embedded transport) | ~124 KB |
| the embedded transport bundle (`host/transport-bundle.js` — the signed `.skb` as base64, including `ws.wasm` and `mlkem768.wasm`) | ~177 KB |
| libsodium.wasm (core build: the host trust root and current channel fast paths) | 217 KB |
| libsodium-wrappers.mjs + libsodium-core.mjs | 135 KB |
| mldsa65.wasm (ML-DSA-65, the PQ half of manifest suite `0x02`) | 16 KB |
| **Total browser deployment** | **~669 KB** |
| mlkem768.wasm (ML-KEM-768) | 12 KB, counted inside the transport bundle |
| QuickJS realm engine (`quickjs/`, loaded only when a guest runs) | ~570 KB |
| **Native binary**, stripped, per `GOOS`/`GOARCH` — mostly wazero's compiler backend (~4 MB) and the Go runtime (~2.4 MB) | ~7.5 MB |

`npm run build` emits the readable `build/` (~482 KB of runtime code) and the comment-stripped `build-min/` (~301 KB) — a second `tsc` pass with `removeComments` (`scripts/minify.mjs` over `tsconfig.min.json`) holding only what the browser entry points reach. It prints the current plain and gzipped totals on every run.

---

## 11. Example app layer: chat ([seedchat](https://github.com/arj03/seedchat))

Chat is the smallest complete app, and lives in [seedchat](https://github.com/arj03/seedchat), a consumer of this runtime's published entry points (`shell-core`, `bundle`, `net-rtc`, `libsodium`). Nothing here knows chat exists; §13 walks the same pipeline byte by byte.

- **The bundle** is a guest of a handful of lines whose `handle` forwards its input to one restartable module by name and returns the render bytes. The module reads `senderPk ‖ chatType ‖ body` and writes render bytes; it does no I/O and no crypto. Seedchat derives its consent key by hashing the verified WASM bytes it holds.
- **The page** generates an Ed25519 channel identity, constructs a host (§3), installs a policy approving the authors the user trusts (§12.5), and starts with an empty table. `v1 — text only` and `v2 — text + image + nick` are two bundles under one `(author, app)`; v1→v2 is an install naming that slot, re-stating the `chat` protocol claim (§12.10).
- **Peers** connect over a WebRTC mesh from `RtcNetwork` (§12.7); chat rides the transport request plane as `[req][protocolId][type][chatType‖body]`, and the host invokes the claiming slot's guest with the authenticated peer key prepended.
- **Relayed bundles** travel in an `OFFER` frame; the recipient re-verifies both author signatures and applies its own policy (§12.4).
- **Rendering** leaves the host: the guest returns render bytes to the page, which `postMessage`s them to an iframe sandboxed `allow-scripts allow-forms` with no same-origin access to the page's keys.
- **The relay** partitions signaling into rooms by URL path (`ws://host:8080/<room>`, default `global`, `[A-Za-z0-9._-]`, ≤128 chars). A room is not authenticated: its members see its SDP metadata, but cannot impersonate a peer (§12.7).
- **`ui` and `app_meta`** WASM custom sections are seedchat conventions; the host reads neither.

To run it: `npm run build:browser` here, then follow seedchat's build steps (`npm run relay` runs the rendezvous).

---

## 12. The runtime as an app host: host services and signed bundles

The host knows nothing about chat or storage: it offers a fixed, generic surface, verifies a bundle against a policy, and becomes whatever the bundle is. [seedstore](https://github.com/arj03/seedstore) is the worked example: a peer-to-peer storage node is the host plus a signed bundle.

### 12.1 Host services: raw-byte backends

The host provides four **host services** — `node`, `fs`, `timer`, `link` (`HOST_SERVICES`, `services/domains.ts`) — and two ungated name families. All of them move raw bytes; the host never interprets what an app means by them.

| Service | Methods | Backs |
| --- | --- | --- |
| `node` | `node/sign`, `node/verify` | The node key: signing and verification under this slot's scope (§12.2). The node's public key is not a call; every realm reads it as `HOST.identity` (§12.3). |
| `fs` | `fs/get`, `fs/put`, `fs/list`, `fs/delete`, `fs/stat`, `fs/size` | Raw bytes under an opaque, flat key, scoped to the app label (§12.1). |
| `timer` | `timer/arm`, `timer/clear` | The realm's one wake (§12.3). |
| `link` | `link/open`, `link/send`, `link/close`, `link/deliver` | Raw links over opaque link ids, and attributed inbound delivery. **The link owner only** (§12.5). |
| `crypto/*` | `blake2b`, `chacha20poly1305-ietf/{seal,open}`, `x25519/dh`, `random` | `HOST_TRANSFORM_NAMES`, a frozen compatibility table of transforms the host already carries, each over its algorithm's whole standard interface (§12.2). `random` is host entropy. **Not a grant.** |
| *bare names* | the bundle's own module names | The asking bundle's private WASM modules. **Not a grant.** |

- **A grant is a service.** `guest.requires` (§12.4) lists everything a guest reaches: host services, and the local service ids it calls (§12.10). Which of the two a name is, is one closed-table lookup (`isService`), never a spelling convention. Host services are named by service, never by method; declaring `node` grants `node/sign` and `node/verify` together. Install refuses a method name (`fs/get`) with the service to declare instead, and refuses an unknown service. The seam refuses any host method whose service (`serviceOf`, the text before the first `/`) is not declared.
- **An undeclared service is not wired.** An fs-less bundle gets no fs backend at all, not a backend behind a check.
- **`crypto/*` and bare module names are ungated** and cannot be declared. New pure computation ships as a module of the bundle that needs it; `HOST_TRANSFORM_NAMES` takes no new algorithms. A name it does hold takes its algorithm's whole standard interface — BLAKE2b's output length and key, the AEAD's associated data — never the subset one bundle uses, so a standard protocol over these algorithms is a bundle, not a host release (`tests/noise-vectors.js` replays published Noise XX vectors through them on both targets).
- **Time is not a service.** Every realm reads `Date.now()` and `performance.now()` as ordinary ECMAScript intrinsics.
- **Anything with structure is a pure module**, never host code: WebSocket framing is `ws.wasm` in the transport bundle, erasure coding is an app's `codec.wasm`.

#### fs

- **Every method is asynchronous**, on every backend. `MemoryFs` and the native Go primitive answer in the call and are wrapped to resolve in a microtask.
- **Keys** satisfy `isSafeFsKey` (`services/fs.ts`): `[A-Za-z0-9._-]+`, minus `.`, `..` and the Windows device names `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9` — on every OS, and regardless of extension (`NUL.txt` is `NUL`).
- **Scoped to the app label.** The backend a guest reaches prefixes every key with `appScopeFor(app)`, a lowercase-hex hash of the label. `fs/list` with an empty prefix enumerates only that app's keys, `fs/get`/`fs/delete` cannot name another app's, and keys come back stripped of the scope. The scope belongs to the label, not the author (§5).
- **`fs/stat` is not scoped**: `used`/`available` describe the physical backend.
- **Backends.** `MemoryFs` (`services/fs-memory.ts`) enforces `DEFAULT_MEMORY_FS_MAX_BYTES` and `DEFAULT_MEMORY_FS_MAX_ENTRIES`; the directory-backed `NodeFs` (`services/fs-node.ts`) takes the medium's own limit. OPFS/IndexedDB is the shape a browser backend fills in.

#### Links

- **A `RawLink`** reports `stream` (1: a byte duplex the caller frames itself; 0: the platform delivers whole messages), and `buffered()` — the bytes it still holds. It carries no codec and no authority. Every `RawLink` is ordered.
- **An `Arrival`** accompanies a platform-opened link: the listener label and, for a link the platform dialed on the node's behalf, `dialed` — the peer it was dialed for. WebRTC sets `dialed` on the side signaling chose to initiate. Guest-opened links have no `Arrival`.
- **Socket seams**, each handing a `RawLink` to the driver (`host/transport-host.ts`) through the one `ChannelFactory` seam: `services/net-node.ts` (node:net — TCP, and WebSocket behind a listener labelled `LISTENER.WS`), `services/net-ws.ts` (a browser `WebSocket`), `services/net-rtc.ts` (§12.7); on the native target `net.go`/`sock.go`. The flood bounds are `services/net-limits.ts` (§12.6).

### 12.2 The guest seam: the guest name ABI

A guest reaches the world through one seam, `host.call(name, bytes)`, and is entered through one entrypoint, `handle(bytes)` (§12.3). `host/guest-seam.ts` services the seam.

**Names** are guest↔host identifiers, not wire values: opaque strings with no op-number registry. A name resolves to what the manifest declared it as:

1. a local service id in **this realm's** `guest.requires` → the realm claiming it (§12.10);
2. a name in this bundle's `modules` → that private module;
3. anything else → the host table (host services and `crypto/*`).

Install keeps the three disjoint: every host name contains `/`, a module name matches `[A-Za-z0-9_-]` and begins alphanumeric, and a local service id may neither live in a host namespace (`fs/…`, `crypto/…`) nor spell one of the bundle's module names. Multi-byte integers are big-endian.

| Name | Request | Response |
| --- | --- | --- |
| `crypto/blake2b` | `[outLen u8][keyLen u8][key][msg ..]`, `outLen` 1..64, `keyLen` 0..64 | `outLen` bytes of BLAKE2b (RFC 7693), keyed when `keyLen` > 0 |
| `crypto/chacha20poly1305-ietf/seal` | `[npub 12][key 32][adLen u32][ad][msg ..]` | `ciphertext ‖ tag 16` (RFC 8439), binding `ad` |
| `crypto/chacha20poly1305-ietf/open` | `[npub 12][key 32][adLen u32][ad][ciphertext ‖ tag ..]` | `[1][plaintext ..]` | `[0]` when the tag does not verify |
| `crypto/x25519/dh` | `[sk 32][pk 32]` | `[1][shared 32]` | `[0]` for a low-order point. Against the base point it derives a public key. |
| `crypto/random` | `[n u32]` | `n` bytes of host entropy |
| `node/sign` | message bytes | 64-byte Ed25519 signature under the node identity over `domain ‖ scope ‖ msg` (§12.2) |
| `node/verify` | `[pk 32][sig 64][msg ..]` | `[ok u8]`: 1 iff `sig` verifies over `domain ‖ scope ‖ msg` under `pk`. A payload shorter than 96 bytes throws. |
| `fs/get` | key (utf8) | `[0]` absent \| `[1][bytes ..]` |
| `fs/put` | `[klen u32][key][bytes ..]` | (empty) |
| `fs/list` | prefix (utf8, may be empty) | `[count u32] {[klen u32][key]}` |
| `fs/delete` | key (utf8) | (empty) |
| `fs/stat` | (empty) | `[used u64][available u64]` |
| `fs/size` | key (utf8) | `[size i32]`, −1 if absent |
| *bare module name* | request bytes, unwrapped | the module's response. An unknown name is refused; a trap, an overrun length or a deadline kill rejects. |
| `link/open` | `[dest utf8 ..]` — an opaque destination the host resolves against the sockets it can open. The shipped seams read `scheme://host:port[/path]`. | `[linkId u32][stream u8]`. Link 0 means no route, including an unparseable or unroutable destination. |
| `link/send` | `[linkId u32][bytes ..]` | (empty) |
| `link/close` | `[linkId u32][graceful u8]` | (empty) |
| `link/deliver` | `[claimLen u8][claim utf8][attribution 32][payload ..]` | the claimant's answer, routed through the peer claim map (§12.10). Empty both for a claim no peer may reach and for a handler that failed. |
| `timer/arm` | `[ms u32]` | (empty). Replaces this realm's one armed wake, due in 0..2147483647 ms; it arrives as the `wake` host event (§12.2). A realm that has spent its clock share has it slipped, not failed. |
| `timer/clear` | (empty) | (empty). Cancels the armed wake; a notification already handed to the realm is not retracted. |
| *declared local service id* | opaque bytes; the host prepends the **caller's** 32-byte id | what the claimant's `handle` returned. Refused by name when nothing claims it. |

#### Settlement

- **Every name answers a Promise.** A call that produced a value resolves to bytes; a call that did not rejects. Zero bytes is a value: `fs/put` and `link/send` answer empty on success, and a module that returned nothing is distinct from one that trapped, overran or was killed. A fan-out is the guest's own `Promise.all`.
- **No name re-enters the calling realm.** A socket write does not deliver during the write, an armed timer fires on a later turn, and a call into another realm (a local service id, `link/deliver`) runs its callee on a later turn. A guest answering such a call fires it and returns rather than awaiting it inside its own frame.
- **Mechanics.** The host injects `__host_call(name, callId, payload)`, which always parks: the preamble holds a Promise under `callId`, settled by `__resolveHostCall`/`__rejectHostCall`.
- **`__deferred`.** A guest that will answer on a later turn sets the host's `__deferred` flag; the invocation's queue spot frees at the end of its synchronous segment though nothing has settled. Its caller-owned deadline stays attached to the answer and settles a deferral that never completes. This is the one ABI bit beyond `handle` returning bytes.

#### Signing scope

Each slot has **one** signing scope, derived once at load from admitted facts (`slotSignScope`), identical on every load path:

| Slot | Domain ‖ scope |
| --- | --- |
| an ordinary app | `DOMAIN_guest ‖ app_len u8 ‖ app` (`appSignScope`) — the manifest's `app` label, never the author |
| the slot holding `link` | `DOMAIN_link_scope`, no further scope bytes (`linkSignScope`) |

`node/sign` signs `domain ‖ scope ‖ msg`; `node/verify` checks a caller-named key's signature under the same prefix. The guest never supplies or reads the prefix, no name signs raw bytes, and the key never enters a realm. Raw verification stays host-internal (`SeamCrypto`). The domain family is disjoint (§16.1). Every node running an app under the same label derives the same scope, whoever authored it. The format inside a scope — including the transport's `DOMAIN_channel` tag — is bundle content.

#### Host events

The host enters a realm with its own events. A realm that armed a wake receives `wake` when it fires; the slot holding `link`, and only it, receives the three raw-link events, the `link` service's `events` list beside its `calls` in `services/domains.ts`. Each arrives at `handle` as `[32 zero bytes][opLen u8][op ASCII][args …]`, encoded with `OpArgs` (`services/op-frame.ts`); the envelope and field order are host ABI every guest that arms a wake, and every link occupant, must accept. There is no padding or terminator. A `u32` is unsigned big-endian, a `blob` is `[byteLength u32][bytes]`, `text` is a blob of UTF-8, and a boolean is one byte, `0` or `1`.

| Event | `opLen` | `args`, in byte order | Return body |
| --- | --- | --- | --- |
| `wake` | 4 | none | ignored |
| `linkOpen` | 8 | `[linkId u32][stream u8][listener text][dialed blob][remoteAddr text]` | ignored |
| `linkBytes` | 9 | `[linkId u32][bytes blob]` | ignored; the driver awaits completion before admitting the next read on this link |
| `linkClosed` | 10 | `[linkId u32]` | `[reason u8]`, bare; an absent, malformed or rejected answer reads as `0` |

- `linkId` 0 is never a live link. `linkOpen` announces a platform-accepted or platform-initiated socket; a guest-opened link gets its id and `stream` from `link/open` instead, with no event.
- Missing arrival metadata encodes as an empty listener and an empty `dialed` blob, which is an accepted socket. A `dialed` peer is its 32 key bytes and makes this end the handshake's initiator. A missing source address is empty text. Listener and address are platform metadata, not authenticated identity.
- `stream = 1` makes each `linkBytes` an arbitrary byte-stream slice; `0` makes it one platform-framed message. The bytes inside the blob are opaque to the host.

**The close reason** is a local fact; it never goes on the wire. The shipped vocabulary (`transport/src/ake.js` `REASON_*`):

| Phase | Reason | Meaning |
| --- | --- | --- |
| before authentication | `dropped` | the socket went away under an unfinished handshake: refused connect, unreachable host, far end hung up |
| | `refused` | the peer provoked it: bad contact-secret probe, malformed or over-cap frame, bad signature, identity the peer lint rejects |
| | `timeout` | our deadline fired on a socket that stayed open and silent |
| | `handshake` | anything else, ours rather than theirs (half-open eviction, local failure) |
| after authentication | `clean` | the peer's end-of-stream record |
| | `aborted` | a teardown the peer provoked |
| | `local` | our own deliberate shutdown |
| | `truncated` | the stream just stopped |

The driver prints every reason but `clean` and `local` as `[transport] link N from <addr> down: <reason>` (`TransportHost.suppressLinkLog` silences it). Printing is the only place the driver reads the vocabulary; a replacement transport's own codes print as numbers.

### 12.3 Zero-authority JS realms

A guest runs as confined JS in a QuickJS realm (`host/safe-js.ts`) holding only the ECMAScript intrinsics and the injected preamble. It cannot name `fs`, `net`, `process` or `fetch`.

- **One entrypoint.** `realm.call(bytes)` invokes the guest's `handle` with `[caller 32][body …]`. The caller id is the host's to write: the peer key for a peer request, the calling realm's id for a local call, 32 zero bytes for the host itself and its events (the wake and the raw-link events). The body format is the callee's. A guest declares `handle`; nothing else is ever invoked.
- **Invocations are serialized per realm** (`host/realm-queue.ts`, shared by both targets): one invocation holds the queue until it completes or sets `__deferred`.
- **Top-level evaluation** runs at install, before commit, while the seam refuses every name (§3.1).
- **Disposal fails what is parked.** `Shell.close()`, uninstall and revoke dispose a slot's realm at once, rejecting every invocation still parked in it and freeing the engine on a later turn. A handle held past that rejects, naming the slot.

#### Preamble

Three constants reach the guest before its top level runs. All are objects and always defined (absent ≡ `{}`).

| Constant | Contents | Source |
| --- | --- | --- |
| `HOST` | `identity` (the node's public key, 64 lowercase hex — the key `node/sign` signs with), `maxOutstandingHostCalls`, `maxOutstandingHostCallBytes` | the host; fixed for the realm's life. The budgets are advice for pacing; the ceilings still enforce. |
| `APP` | exactly the manifest's signed `guest.config` | the author; the host never merges into it |
| `LOCAL` | exactly the JSON object passed to this `install(blob, { localConfig })` | the installation; passed unchanged for every slot, not retained, invisible to other bundles |

Runtime facts — the node key, budgets, the signing scope — come only from the host, never from `APP` or `LOCAL`. A guest validates and combines `APP` and `LOCAL` itself.

#### Resource bounds

Boundedness follows three separate laws:

1. **Retained space uses continuous custody.** Every host-side byte caused by untrusted input has a finite owner from creation to destruction; a handoff reserves in the receiver before releasing the sender.
2. **Causal lifetime uses a monotone deadline.** One absolute deadline begins at an invocation root and only shrinks through queues and calls. No callee can renew it. The link occupant is the one exception (below).
3. **Initiation rate uses explicit scheduling.** The realm wake paces the only fresh roots a guest can create for itself. Network-originated roots arrive only over authenticated links and are bounded per invocation; there is no node-wide CPU guarantee.

No operation name relaxes custody; a name may tighten what an owner admits (`fs/put` meets a storage quota), and the owner of a resource enforces its bound, not the dispatcher. Every owner has a complete release path and a default, so a host that configures nothing still bounds its guests:

- **Heap** — the realm's QuickJS runtime is capped: 64 MiB default, `realmMemoryBytes` / `--guest-memory`.
- **Deadline** — per entrypoint invocation: 5 s default, `guestDeadlineMs` / `--guest-timeout`. Admission resolves one absolute deadline, the tighter of the initiator's live remainder and the callee realm's ceiling. It begins **before** the realm queue and runs through guest execution, host-call waits, socket backlog and a deferred answer. Every `host.call` and cross-realm delivery carries the remainder. A queued invocation keeps its deadline and is rejected rather than given a fresh segment. Installation-time evaluation runs under the configured ceiling. `Infinity` disables a realm's local ceiling but cannot widen a finite deadline handed to it. Every reading is monotonic (`performance.now`). Both targets enforce it with QuickJS's interrupt handler; an interrupted guest throws and the realm survives.
- **The link occupant's turns are its own** (`ownTurns`). A caller's remainder bounds the caller's wait and the time its request queues, but the occupant runs each invocation on its own ceiling, and a `link/deliver` answer resumes it as a new turn.
- **Module calls** run under the calling segment's remaining time and are killed at the engine when it runs out (§4.3).
- **One wake per realm.** The host retains at most one armed wake and one notification in flight, each the fixed `wake` event. The guest reads its own clock to find what is due. A due successor waits for the previous wake invocation to settle. Replacement is transactional, clear cancels, disposal closes permanently; none retracts a notification already handed over. A wake handler must return before waiting for work that needs another wake.
- **Clock share for self-initiated work.** Each timer fire receives a host-only causal clock, restored whenever that root's continuations run and carried through host calls, module calls, `link/deliver` and cross-realm calls, awaited or not. It debits **execution**: QuickJS segments, the measured CPU of module calls, and the synchronous span of host-service calls; time parked on I/O is free. A realm banks one invocation's budget and earns credit at `1 / SELF_INITIATED_CLOCK_DIVISOR` (twice `DEFAULT_MAX_APP_SLOTS`). A wake due with the share spent is **slipped**, never failed or dropped. Attribution is per turn: roots live in one realm share its account. A full node's summed self-initiated execution is at most half a CPU after the initial bank (`tests/verify-hardening.mjs`).
- **Outstanding host calls** — at most 256 unresolved calls and 16 MiB of copied input per realm (`DEFAULT_MAX_OUTSTANDING_HOST_CALLS`, `DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES`), plus a response's bytes while it coexists with its request. The id, count slot and width are admitted together, before the copy leaves QuickJS. A response is charged when it is delivered. Release paths: settlement, the handoff deadline, disposal (which also clears their armed deadlines).
- **The realm-entry queue** has no depth of its own: every entry borrows its bytes and population from a bounded upstream owner (the driver's inbound window, the calling realm's call registry, an explicit host owner) and keeps its admission deadline.
- **Realms** — at most `DEFAULT_MAX_APP_SLOTS` slots, refused at `install`; a replacement retires one as it installs one.

**Operator knobs.** Heap and deadline cross every seam: CLI flag, `bootNodeShell()`, `bootShell`, `InstallOptions`, `RealmFactory`. `--guest-timeout 0` means no budget; a value that is not a whole number is refused. `bootShell` refuses a heap below 1 byte or from 2³², and a budget under 1 ms. Each `install` resolves its limits from its own option, then the `bootShell` default, then the shared default; a replacement resolves its own rather than inheriting. Execution time is the operator's number, never the manifest's.

### 12.4 Signed bundles

An app is delivered as a **bundle** (`host/bundle.ts`): one signed blob holding the manifest, the guest's JS source, and zero or more WASM modules.

#### Envelope

```
[suite: 1 = 0x02][ed_pk: 32][ml_dsa_pk: 1952][ed_sig: 64][ml_dsa_sig: 3309][body]
body = [manifest_len u32][manifest JSON][guest_len u32][guest UTF-8]
       [module_len u32][module WASM] ...   one per manifest module, in manifest order
```

- Every length is an unsigned 32-bit big-endian byte count. There are no filenames. Missing fields or trailing bytes reject the bundle.
- **Both signatures** — Ed25519 and ML-DSA-65 — are over `DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ BLAKE2b-256(body)`; `DOMAIN_manifest` is prepended, not stored. **Both must verify.** The verifier authenticates the body before interpreting any of it.
- **Suite.** Only `0x02` is supported. Another id is refused with its own error, distinct from a bad signature. Suite ids are never reused.
- **Author id** = `genesisHash(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖ ml_dsa_pk)`, 32 bytes. Policy entries, revocations and freshness marks are written against it.
- **Author keys from one seed.** `hybridAuthorKeysFromSeed` (offline-only `host/bundle-author.ts`) derives the Ed25519 half from a 32-byte seed and the ML-DSA-65 half from `genesisHash(seed ‖ AUTHOR_MLDSA_SEED_LABEL)`. The label is frozen. Pass the 32-byte seed, not libsodium's 64-byte secret key.
- **The ML-DSA verifier** is `browser/mldsa65.wasm`, an import-free module built from the pinned `pq/mldsa-native` submodule (`scripts/build-mldsa.mjs`; `npm run build:pq` rebuilds it and `mlkem768.wasm`, given the submodules and a clang with the wasm32 target). All targets run the same bytes. `bundle.ts` calls `ml_dsa65_verify_detached` on the crypto object; a host that supplies none refuses `0x02`.

#### Manifest

| Field | Type | Enforced | Meaning |
| --- | --- | --- | --- |
| `app` | string | yes | The slot's key: one slot per label per node, whoever authored it. Names the fs and signing scopes; what `replaces` and `uninstall` select; with the author, keys the freshness mark. Non-empty, at most 255 UTF-8 bytes. |
| `version` | integer | yes | Non-negative safe integer; the set's monotonic version (§12.4). |
| `modules[]` | `{name}` | yes | One entry per private WASM module, in body order. `name` is what the guest passes to `host.call`: unique, `[A-Za-z0-9_-]`, alphanumeric first. Zero or more. |
| `protocols[]` | string[] | yes | Protocol ids a **peer** may reach (§12.10). Optional. |
| `services[]` | string[] | yes | Local service ids a **co-resident guest** or the host may reach. Optional. A name may appear in both lists. |
| `guest` | `{requires, config?}` | yes | Required; a manifest without one is refused. |
| `guest.requires` | string[] | yes | Everything the guest reaches: host services by service name, and local service ids it calls. A method name is refused with the service to declare; a local id must follow the claim charset, stay out of host namespaces and not spell a module name. Empty means no authority. |
| `guest.config` | JSON object | shape only | Injected unchanged as `APP`. Must be an object; absent ≡ `{}`. Opaque to the runtime. |

The host reads no WASM custom sections; conventions such as seedchat's `ui` and `app_meta` belong to the app.

#### Install

`install(blob, options)` runs three phases. Failures throw to the operator.

*Verify* — pure, nothing lands:

1. Read the fixed-width suite, keys and signatures; hash the body and verify both signatures. Invalid ⇒ reject.
2. Parse and validate the manifest, then read the guest and modules in manifest order. Truncation or trailing bytes ⇒ reject.

*Admit* — governance:

3. Ask the host's gates — author revoked? version below the `(author, app)` mark? — then, for an ordinary app, the admission predicate once (§12.5).

*Construct and commit*:

4. Contests (label, claims, `link`) are checked against the slot table (§12.10).
5. Read every module's declared memory and table limits before instantiating any; enforce per-module and aggregate bounds (§4.1).
6. Build every module off to the side and validate its exports; on any failure release them all.
7. Derive `fsScope` and `signingScope`, then stand the realm over a seam restricted to `guest.requires` and wired to those modules, with the preamble `HOST`, `APP`, `LOCAL`. A guest that does not compile rejects the candidate. The seam refuses every name until step 8 (§3.1).
8. Synchronously: re-check the gates and contests against current state, persist the freshness mark, put the slot in the installed set (in the place of the slot `replaces` named, or a free one) and reproject every claim to it. Only then dispose the predecessor. A candidate overtaken by a newer mark, revoked mid-load, or whose mark cannot be written is discarded, leaving the running version unchanged.

The predicate is not re-asked at commit. Atomicity is specified in Atomic load and replacement (§3.1).

#### Freshness

- The persisted `(author, app)` high-water mark (absent ⇒ −∞) refuses any `version` below it, the transport included. Equal versions reload. The mark advances at the end of a successful load and never rewinds.
- The transport carries the same `(author, app)` mark as any bundle; there is no per-slot floor.
- The store file is `{ "marks": { "<author hex>:<app>": version }, "revoked": [ "<author hex>" ] }`. A bare marks map is refused. Only a missing file is first boot; malformed JSON, missing or wrong-shaped guard fields, invalid ids or versions, and read errors fail closed. Unknown top-level keys are ignored.
- A deliberate rollback is an out-of-band edit of the store.

### 12.5 The admission policy

- **Gates.** Every bundle clears revocation, then freshness, before any predicate and again at commit. The host composes them in front of whatever the operator configured; `admitAll` still has both.
- **The predicate** is `admit(v: VerifiedBundle) → bool | Promise<bool>`: `true` admits, `false` rejects, a throw rejects with a reason. It is a pure function of the verified bundle. `authorAllowlist`, an interactive consent dialog and `admitAll` are constructors of it; further checks compose as ordinary functions. An absent predicate is `denyAll`.
- **Link bundles** skip the predicate: `link` is authorized only by boot selection or by replacing its current owner (below).
- **Contests are not gates.** Whether a label, claim or the `link` binding is free is answered by the slot table, before the candidate's code runs and again at commit (§12.10).

#### Install and replacement

- **`install(blob)`** with no `replaces` takes a FREE label. A blob whose `app` is already installed is refused by name, whoever authored it, and so is one requiring `link`.
- **`install(blob, { replaces: app })`** runs the same sequence and atomically takes over that slot, across authors and labels. An app candidate still needs the predicate. A candidate requiring `link` is authorized only if the named predecessor owns `link`.
- A replacement may take the predecessor's label and claims, never unrelated claims nor a label a third slot holds. Claims the new manifest drops are released. The target is captured at call time and checked again at commit, so a concurrent update, uninstall or shutdown fails the stale replacement. Any failure leaves the current owner running. Replacement works at the slot ceiling.
- Scopes follow the label and the freshness mark follows the author (§5). Old invocation handles become invalid.
- **`reachesLink(manifest)`** — `guest.requires` contains `link` — is the one test the installer, the binding, the wiring and the signing scope use.

#### Boot transport

`bootShell`'s `transport.bundle` defaults to the embedded artifact; selecting it authorizes its `link` independently of app policy, and it must declare `link`. `transport: false` (the `bootShell` default) creates none. The CLI enables networking only with `--listen`, `--ws-listen` or `--peers`; `--transport` selects the boot blob, and it and `--contact-secret` are refused without one of those. After the transport is uninstalled or replaced by an ordinary app, starting another requires a new boot.

#### Policy file

`--policy <allowed-keys.json>` (`host/policy.ts`):

```json
{ "authors": ["<64-character hex app author id>"] }
```

`authors` is required; an empty array denies all apps. Malformed ids, unknown keys and malformed JSON fail boot. **Omitting `--policy` denies ordinary app installs**; it does not disable an enabled transport.

Sensitive protocol and service names are pinned to approved owners (author and `app` label) inside the predicate — [CLIENT](CLIENT.md#the-assembly-is-an-export) has an example. A pin reserves ownership, not availability, and changing admission rules evicts no installed slot.

#### Revocation

- **`shell.revoke(authorHex)`** records the author key as written off and uninstalls every slot admitted under it, in one action. The CLI and native binary expose `--revoke <hex,…>`, and `--uninstall <app,…>` for removing an app alone.
- A revoked key's bundles are refused whatever version they claim. The set is keyed by author only.
- The runtime never removes a key from the set, even if it reappears in `authors`. The Node CLI and native binary persist it atomically with the freshness marks; the browser chat page holds both in memory. Undoing a revocation is an out-of-band store edit.
- An author with a new key starts a new freshness mark and may take a label released by the revocation, inheriting that label's data and signing scope.
- There is no emergency module-replacement seam: a fix is a signed bundle at a higher `version`.

### 12.6 Node↔node transport: channel identity binding

Everything in this section is the **shipped transport bundle's guest program** (`transport/src/*.js`, with private modules `ws.wasm` and `mlkem768.wasm`), not host code. A replacement transport may differ; this is what ships. The first transport is embedded in the host artifact (`TRANSPORT_BUNDLE_B64`).

- **Division of labour.** The host driver (`host/transport-host.ts`) owns sockets by link id and the listeners, and hands a `link/open` destination to its socket factory. The transport guest owns the handshake, record layer, correlation table, peer set, request facade and address book. Apps reach it through the local service id it declares under `services` (`_net`); ops such as waiting for a cohort, listing peers and teaching an address (`addr`) are ordinary calls through it, framed with `services/op-frame.ts`.
- **Deadlines.** Every link, open correlation and `ready` waiter holds a monotonic due time; the realm's one wake is armed for the soonest, and each wake retires what is due and re-arms. The wake is armed only while something waits; a refused arm fails nothing. A pending request fails as soon as its peer loses its last routable link.
- **What a replacement changes without a host release.** Everything in this section: the handshake, key schedule, suite byte, record layer, framing, address grammar and config keys. The host sees no handshake width, the shell passes `--peers` and `--contact-secret` through unread (§12.8), and each `crypto/` name takes its algorithm's whole interface (§12.1); an algorithm the host lacks ships as a module, as ML-KEM does. What stays the host's: the identity key's algorithm (`node/sign` and `node/verify` are Ed25519), the socket kinds a destination can name, and the link events (§12.2). The shell's one call into a transport is `ready` on its service id, made when `--peers` is given (§12.8).

#### Framing

- Node↔node over TCP: a length prefix. Browser↔node: RFC 6455 in `ws.wasm` over the same TCP socket. Platform `WebSocket` and `RTCDataChannel`: whole messages as delivered.
- Each framer checks its cap against the declared length **before** buffering the body; a platform-framed message is measured on arrival. The cap is `MAX_HANDSHAKE_FRAME_BYTES` (8 KiB, `transport/src/framing.js`) until authentication and `maxFrameBytes` (`MAX_FRAME_BYTES` by default) after. `raiseCap()` lands once the authenticating step (msg2 dialing, msg3 accepting) has run; until then framers take one message at a time.
- `ByteParts` merges slices below 8 KiB (`MERGE_BELOW`) into a doubling tail buffer and keeps larger slices as they arrived. The WebSocket framer serializes `push`.

#### Handshake

Three messages, then records. A message is a bare body — no type byte.

```
msg1  i→r   [suite: 1][eph_i: 32][kem_pk_i: 1184]
             [seal(k_probe; ∅): 16]                         1,233 B  contact proof, no identity
msg2  r→i   [eph_r: 32][kem_ct: 1088]
             [seal(k2; sig_r: 64): 80]                      1,200 B  hybrid reply, signed, no identity
msg3  i→r   [seal(k3; id_i: 32 ‖ sig_i: 64): 112]             112 B  the caller names itself
FRAME       [AEAD record ..]                                          only after authentication
```

```
root    = H(DOMAIN_channel ‖ network_key)
k_probe = KDF(contact, H(root ‖ suite ‖ eph_i ‖ kem_pk_i), LABEL_probe)
h1      = H(root ‖ msg1)
ee      = X25519(eph_i_sk, eph_r) = X25519(eph_r_sk, eph_i)
pq      = ML-KEM-768.Decaps(kem_sk_i, kem_ct) = ML-KEM-768.Encaps(kem_pk_i).shared_secret
hs      = H(h1 ‖ eph_r ‖ kem_ct)
sig_r   = Sign(DOMAIN_channel ‖ root ‖ hs ‖ id_r)
k2      = KDF(ee ‖ pq ‖ contact, hs, LABEL_msg2)
h2      = H(h1 ‖ msg2)
k3      = KDF(ee ‖ pq ‖ contact, h2, LABEL_msg3)
sig_i   = Sign(DOMAIN_channel ‖ root ‖ h2 ‖ id_i)
h3      = H(h2 ‖ msg3)
k_i2r, k_r2i = KDF(ee ‖ pq ‖ contact, h3, "…i->r-v1\0" / "…r->i-v1\0")

Sign(m) = Ed25519(DOMAIN_link_scope ‖ m)   — node/sign; the prefix is the host's
```

- **Parsing is by state.** The initiator reads msg2, the responder msg1 then msg3, and everything after authentication is a record. Each handshake message is accepted only at its exact width.
- **Keys.** `eph` is a fresh X25519 key per connection on each side; `kem_pk_i` is a fresh ML-KEM-768 key; the responder encapsulates, the initiator decapsulates. `seal` is ChaCha20-Poly1305-IETF at nonce zero; each key seals exactly one message. No long-term DH or KEM key is used; the contact secret and network key are KDF inputs.
- **Suite `0x03`** is the only suite: Ed25519 identity, ephemeral X25519 + ML-KEM-768, contact secret, ChaCha20-Poly1305 records. An unrecognised id draws silence. There is no list, fallback or negotiation. `suite` is folded into `h1`, so both signatures cover it.
- **A dial pins its peer, and the receiver's key never travels.** `sig_r` is checked against the key the caller dialed; `id_r` is in the signed message but not on the wire. A signature under any other key — including the caller's own — closes the link before the caller names itself.
- **Ordering.** An accepting node sends nothing until a msg1 opens under its contact secret. The receiver proves itself at msg2; the caller names itself at msg3, only to a receiver it has verified.
- **Signatures** cover `DOMAIN_channel ‖ root ‖ transcript ‖ own id` under the host's `DOMAIN_link_scope`; `sig_r`'s transcript chains the suite, both ephemerals, the KEM key and ciphertext, and `sig_i`'s all of msg2 besides. The initiator authenticates the responder at msg2 (1 RTT) and sends its first records behind msg3; the responder authenticates the initiator at msg3 (1.5 RTT).
- **Refusals before msg3 are silent.** A responder refuses a wrong contact secret, wrong network, malformed message or bad msg3 by doing nothing until the deadline. A caller the peer lint declines at msg3 is closed at once: it has verified the receiver, so silence would conceal nothing. An initiator's rejection at msg2 — a bad signature, its own key, the peer lint — closes.
- **Pre-auth sends** are queued oldest-dropped under both `MAX_QUEUE_BYTES` and `maxPreAuthQueueSlices`. When the link goes before authenticating — a dial that dies, or the loser of the double-connect tie-break (the link the smaller identity dialed is kept) — the queue passes to another link to the same peer.

#### 12.6.1 Records and link teardown

- Every post-handshake frame is a ChaCha20-Poly1305-IETF record: the initiator seals with `k_i2r` and opens with `k_r2i`, the responder mirrors. There is one post-handshake frame type.
- The nonce is an implicit per-direction `(epoch, counter)`, strictly enforced on receive; a bad tag or out-of-order counter tears the link down. After `REKEY_AFTER_FRAMES` a direction ratchets its key; reaching `REJECT_AFTER_EPOCHS` retires the link (§16.1).
- Only `close()` emits the authenticated end-of-stream record; every failure path is silent.
- A graceful `link/close` asks the socket to flush its queued bytes before closing, bounded on TCP by `TCP_LINGER_MS` (`services/net-limits.ts`).
- Records assume an ordered whole-message pipe, which every socket seam supplies.

#### 12.6.2 Half-open budgets

- **No asymmetric cryptography before proof.** An accepting link generates its X25519 and ML-KEM keypairs only once a msg1 opens.
- **Three budgets**: `MAX_HALF_OPEN_UNVERIFIED` (1024) until msg1 opens, `MAX_HALF_OPEN_VERIFIED` (256) until the identity is proved, `MAX_AUTHED_LINKS` (256) for the link's life.
- **Every budget evicts; none refuses the newest.** The half-open tiers shed their oldest occupant; the authed tier sheds its quietest — a record crossing a link re-books it at the tail.
- **A proved msg1 is spent.** The initiator's ephemeral key is remembered (4,096, drop-oldest) and a second sighting draws silence before promotion or asymmetric work. Only proved msg1s are remembered.
- **`MAX_HALF_OPEN_PER_SOURCE` (8)** spans all three tiers and is not evictable: an address at its limit is refused rather than pushing another address out.
- **Three deadlines**: `UNVERIFIED_TIMEOUT_MS` until msg1 opens, `HANDSHAKE_TIMEOUT_MS` for the rest, `LINK_IDLE_TIMEOUT_MS` after — an authenticated link carrying no traffic either way is retired with the authenticated goodbye, and the address book redials on the next send.

Measured behaviour: `tests/transport-load.test.mjs`.

#### Requests

- **A request inherits the initiating deadline.** The `send` op carries no time field; the app's remaining handoff deadline crosses the `_net` call, covers the pre-auth pool and socket backlog, and stays attached to a deferred answer. The transport's own turn runs on its own ceiling, so an app out of time loses its request, never the link.
- **`requestTimeoutMs`** (10 s default, `0` disables) retires the transport's own pending correlation; it cannot extend the inherited deadline.
- **Known outcomes fail at once**: a request no link can take (no address, a dial that opened nothing or died as the last way to its peer) fails immediately; a claimant's answer too big for one record, or none by the delivery's deadline, comes back empty.
- **The request window.** A request handed to `link/deliver` holds one of the transport realm's host calls and its bytes until answered. The transport admits decoded requests only inside that budget (`HOST`) less room for one maximum-size record open and its plaintext, weighing each as its bytes plus the budget's bytes per call. A peer with nothing waiting may use any room left; a peer already waiting leaves one maximum-size request's room for others and stops at an equal share among waiting peers. A request past that is answered empty at once.

#### Driver bounds

The host driver keeps its own coarse bounds beneath the transport's, on structures a socket costs the moment it is accepted:

- **`MAX_LINK_READ_BYTES` (2 MiB)** caps one read handed to the occupant — a platform-framed message whole — and fails the link past it, before the copy into the realm. The occupant's frame cap must fit under it. The byte windows below are sized in it.
- **`DEFAULT_MAX_RAW_LINKS` (4096)** bounds the link table on the one path that mints a link id, and **refuses** rather than evicts (`TransportHostOptions.maxRawLinks`).
- **`MAX_INBOUND_HOLD_BYTES` / `MAX_INBOUND_HOLD_SLICES`** are one driver-wide budget for reads admitted toward the transport realm, charged while held and while dispatched. The link whose next read crosses a ceiling is failed; reservations release when the dispatched call settles or held input is dropped. The native reader goroutine charges the same ceiling again on its staging copy and **waits** instead of failing, so native inbound memory is bounded at twice this figure.
- **`MAX_QUEUED_SIGNAL_BYTES` (4 MiB) / `MAX_QUEUED_SIGNALS` (256)** bound the one ordered WebRTC signaling lane, node-wide; overflow **drops** the newcomer. Per peer, `MAX_PENDING_ICE_BYTES` (256 KiB) and `MAX_PENDING_ICE_CANDIDATES` (256); across peers, `MAX_UNESTABLISHED_PEERS` (256), each entry reaped by `UNESTABLISHED_PEER_TTL_MS` unless it both connects and binds a data channel.
- **`MAX_OUTBOUND_QUEUE_BYTES` / `_SLICES`** per link and **`MAX_NODE_OUTBOUND_QUEUE_BYTES` / `_SLICES`** (4× each) node-wide bound authenticated writes waiting below the transport; the guest applies the same window to frames on its encryption chain. One custody period per link spans the adapter's pre-open buffer and the platform's send backlog: the charge is `RawLink.buffered()` (`writableLength` on Node, `bufferedAmount` in the browser, an exact queue on native), and the driver retires the drained prefix of the admitted sizes at each write. An adapter that cannot report fails its link. Crossing any ceiling — or the occupant's own `host.call` budget refusing a write — fails the whole link, never one record.
- **Teardown severs the wire first.** `close`/`abort` cut the wire synchronously, failing any parked write, then run the queued teardown; the link leaves routing at once.

`buffered()` is host-only accounting; it is not exposed to guests.

#### 12.6.2b One master seed, one identity

A node stores one secret, a 32-byte **master seed**. `services/subkeys.ts` derives its signing keypair under the closed, literal label `channel`; that public key **is** the node's identity — the peer id, `senderPk`, and `HOST.identity`. The master signs nothing. The one key signs for both purposes, separated by signing scope (§12.2).

#### 12.6.3 The contact secret, the network key, and the peer list

| | Scope | Secret? | Effect |
| --- | --- | --- | --- |
| **Contact secret** | per node | yes | A caller that cannot produce the receiver's secret draws no response. Distributed with the node's address. Absent (32 zero bytes), the node is open. Mixed at msg1 with the initiator's ephemeral and into every later key. |
| **Network key** | per deployment | **no, public** | Seeds the transcript root, so every key and signature preimage differs between networks and a cross-network handshake fails at msg1. Isolation, not access control. |
| **`admitPeers`** | per node | n/a | Optional peer list, applied as a lint to signature-verified identities only — at msg3 when accepting, closing the link, and at msg2 when dialing. It controls admission, not concealment: to stay invisible to scanners, set a contact secret. Empty by default in the signed `APP`; overridable in `LOCAL`. |

The transport enforces all three; a malicious transport can bypass the lint or fabricate attribution (§14). Revocation is key rotation: rotate a contact secret to drop a peer, a network key to split a network.

#### Configuration

- The transport reads `networkKey` and `contactSecret` from `LOCAL` as 64 lowercase hex, rejects malformed values at load, and defaults each to 32 zero bytes (the public network, an open node).
- Its other policy values resolve as `LOCAL.x ?? APP.x`; any that is not a non-negative finite number fails the load, so a transport bundle without `guest.config` is refused. `bootShell({ transport: { config } })` passes operator overrides as that load's `localConfig`.
- Its identity comes from `HOST.identity`, never from config.
- Peers arrive in `transport.config.peers` as `pk[.secret]@dest` strings — this transport's own grammar (`peerRef`, `core.js`), refused at load when malformed — and through `addr` calls.
- The host-only `contact` op (one blob: 32 bytes, or empty for an open node) moves the accept gate and the value host-announced dials present, without reinstalling. Links already up keep their secret; `TransportHost.reset()` closes them if required. A guest-dialed link presents the **peer's** secret from the address book.

### 12.7 Browser↔console WebRTC

`RtcNetwork` (`services/net-rtc.ts`) is the browser's socket seam: a `ChannelFactory` handing each established `RTCDataChannel` to the driver as an ordinary `RawLink`, with the transport's handshake and records running inside it.

- **Signaling only.** Peers connect directly; the app-neutral [`seedrelay`](https://github.com/arj03/seedrelay) server is the SDP/ICE rendezvous and can be killed once channels are open. The `Signaling` seam is pluggable and carries one opaque encoded string each way; the compact NUL-separated frame is decoded once inside `RtcNetwork`, before policy or allocation. Signaling carries no SDP-fingerprint signature and no credential.
- **One ordered binary channel per peer.** Its `Arrival` carries `dialed` on the side signaling chose to initiate, and no listener. An RTC link opens under the node's own contact secret.
- **Bounds.** `MAX_SDP_BYTES` (worst-case UTF-16 storage) is charged at the signaling boundary before policy runs; an oversized description is dropped. Candidates queued before a remote description are normalized to the four standard scalar fields and capped per peer; crossing a cap tears the speculative peer down. A peer connection that does not reach `connected` with a bound data channel within 30 s is closed (§12.6).
- **Console nodes** pass their own `peerConnectionFactory` implementing the W3C subset `RtcNetwork` uses; the runtime depends on no ICE/DTLS/SCTP library. Seedstore's `scripts/werift-pc.mjs` wraps werift. The native binary has no WebRTC.
- DTLS on the data channel is a second, redundant encryption layer.

### 12.8 The shell: node assembly and the CLI

`bootShell(opts)` (`host/shell-core.ts`) assembles the host and returns its `Shell` plus the channel adapter. `bootNodeShell(opts)` (`host/shell-node.ts`) selects Node crypto, `NodeFs`, file-backed freshness and `NodeChannelFactory`, and adds file-path bundle loading. The CLI is `host/cli.ts`:

```sh
node build/host/main-node.js --policy ./allowed-keys.json --dir ./data --key ./node.key \
     --listen 0.0.0.0:7000 [--ws-listen 0.0.0.0:7001] \
     --bundle ./app-bundle [--transport ./transport.skb] [--peers <pk>@host:port,…] \
     [--contact-secret ./contact.hex] [--local-config ./app.json] \
     [--revoke <hex,…>] [--uninstall <app,…>] \
     [--op name  < argument > response] \
     [--guest-timeout <ms>] [--guest-memory <MiB>]
```

- **`runCli` is shared by both targets.** It owns the flag set, the defaults (`--dir ./data`, `--key ./seedkernel.key`), the deny-all reading of an absent `--policy`, the order — remedies, then the bundle, then the one-shots, then serve — and every printed line. A target supplies a `CliHost` of five members: files, one console line, raw stdout, entropy, and "stand a node up on this platform". Unknown flags are errors.
- **`--key`** holds the 32-byte master seed; `deriveNodeKey` derives the keypair from it on both targets.
- **`--transport`** selects a signed transport bundle from disk instead of the embedded one.
- **`--contact-secret`** names a file, never the secret itself; its contents, less the line ending, become `transport.config.contactSecret` unread.
- **`--local-config`** requires `--bundle` and is that load's `LOCAL`; it never reaches the transport.
- **`--peers`** becomes `transport.config.peers` on the automatic transport load, as typed: the shell parses neither flag, so a replacement transport can spell addresses and secrets its own way, and the transport's load refuses a malformed one. Once up, the CLI waits for the cohort with the transport's `ready` op on its service id; `null` means no transport is installed.
- **`--op name`** invokes the app `--bundle` just loaded, through that load's handle: stdin is the argument, stdout the response, framed as `[opLen u8][op][args]`. Logs go to stderr on both targets.

**The request side.** An inbound frame and a host loopback both reach the app's one `handle` as `[caller 32][body]` (§12.3); `AppHandle.invoke` supplies the host's zero caller id. Bodies use the callee's format. Clients choosing the common `[opLen u8][op][args]` envelope take it from `seedkernel-wasm/op-frame` (`services/op-frame.ts`); the host never imports or interprets it. The driver resumes on the promise `handle` returned, so inbound handling may be asynchronous. Seedstore's WASM README has a complete storage walkthrough.

### 12.9 The native binary: the primary non-browser deployment

The Go/native target (`native/`) is the recommended non-browser deployment: one cgo-free binary, `seedkernel`, with no Node, Bun or separate JS engine.

- **Shared code, Go primitives.** `scripts/bundle-native-host.mjs` (`npm run build:native-host`) compiles the shared TypeScript into one `native/host-shell.gen.js`, which the binary `//go:embed`s and evaluates in QuickJS. `host/native-shim.ts` satisfies `PureModuleLoader`, `FreshnessStore`, the channel and realm interfaces by forwarding to Go's byte bridge, then calls the shared `bootShell`. Nothing under `native/` re-implements protocol, admission, routing or boot order; Go supplies only platform primitives.
- **`bootShell` is the one assembly.** A target supplies `{ sodium, identity, modules, fs, freshnessStore, transport, createRealm }`; all but the first two have defaults.
- **Embedded engines** over [wazero](https://wazero.io): the same core `libsodium.wasm` and `mldsa65.wasm` as the JS targets; a QuickJS built from the same quickjs-ng v0.16.2 pin as the JS platform (`native/qjs/build-qjs.sh`, `WASM/quickjs/build-quickjs-ng.sh`). Go owns the event loop — timers, the JS job queue, socket delivery. The guest runs in a second, zero-authority QuickJS realm whose only seam is `host.call`. Bundle modules, `ws.wasm` included, go through the ordinary private-module builder (§3.2).
- **Primitives**: `os` for fs (synchronous; `native-shim.ts` wraps it async), `net` for one raw TCP socket kind (node↔node and browser↔node, the codec chosen per link above Go), `crypto/rand` for entropy. The CLI is the shared `runCli` over a Go `CliHost` of `argv`, `readFile`, `writeFile`, `log`, `stdout`, plus `__fs.open` for the data directory.
- **Native fast paths.** A target may substitute a native implementation of a primitive only if (1) it is standardized, (2) its output is byte-identical, pinned by a known-answer test against the shared blob, and (3) no protocol judgement lives inside it. BLAKE2b-256 and the ChaCha20-Poly1305 record layer are native Go; Ed25519 and ML-DSA-65 verification stay on the shared wasm.
- **Interop.** A Go node and a Node/Bun node join one cohort against the same signed bundles (`WASM/scripts/native-interop.sh`).

```sh
seedkernel --policy ./allowed-keys.json --dir ./data --key ./node.key \
     --listen 0.0.0.0:7000 [--ws-listen 0.0.0.0:7001] \
     --bundle ./app-bundle [--local-config ./app.json] [--peers <pk>@host:port,…] \
     [--op name  < argument > response]
```

Benchmarks: `wsl bash gorun.sh test -run x -bench . -benchmem ./...` from `native/`; `node tests/bench-module-call.mjs` from `WASM/` for the JS module-call hop.

### 12.10 Protocol routing: which app handles a message

A frame names a **protocol id**, never an app, author or module. Each installed slot claims names from its signed manifest; the host keeps three books, all projections of the installed set, recomputed at every commit and removal and never persisted:

| Book | Filled from | Reached by |
| --- | --- | --- |
| `peerClaims` | `protocols` | inbound peer requests, via `link/deliver` |
| `localClaims` | `services` | a co-resident guest's `host.call`, and the host's `Shell.call` |
| the raw-link binding | `guest.requires` containing a service with `events` (only `link`) | the driver's raw-link events |

- **One owner per name per book.** A candidate contesting an active claim, label or the binding is refused before commit. Only an install naming the holder in `replaces` takes it over; uninstall releases. A free `link` is taken only by boot selection.
- **Claim charset**: alphanumeric or `_` first, then alphanumerics and `._/-`, at most 64 bytes. Uniqueness is per list; the same name in both lists is allowed. No spelling is reserved — `_net` is this repo's transport's convention.
- **Peer delivery.** The link occupant decodes a request and calls `link/deliver(claim, attribution, payload)`; the host looks the claim up in `peerClaims` alone and invokes the slot's `handle` with `attribution ‖ payload`. An unclaimed protocol, or a `services`-only name, is answered empty.
- **Local calls.** `host.call(id, …)` on a local service id in the caller's own `guest.requires` resolves through `localClaims`; the host prepends the caller's 32-byte id and the answer is the callee's `handle` result on a later turn.
- **Host doors.** `AppHandle.invoke(payload)` is slot-bound (a bundle claiming nothing has one) and prepends 32 zero bytes. `Shell.call(serviceId, payload)` resolves `localClaims` with the host's caller id and returns `null` when nothing claims the name.
- **The binding.** The driver follows the book, and the host wires raw-link authority (`rawNet`) only into that slot.
- **`InstallOptions.onInbound(claim, sender, answer)`** fires once a peer-inbound request to this load's slot resolves. It is observation only: it cannot change the answer, never fires for `invoke` or local calls, and a throw from it is reported and swallowed.
- **One slot per name.** There is no fan-out.
- A claim grants no authority, but selects which admitted app receives decrypted input (§14).

**Transport replacement** is ordinary slot replacement of the link owner. The candidate loads complete and offside; the host passes its own `LOCAL` unchanged, so the embedder re-supplies the network key (omission selects the public network) and peers — in the replacement's `transport.config.peers` (in that transport's own grammar) or afterwards by an `addr` call through `Shell.call`. At commit the host swaps the slot, its claims and the binding together. The driver keeps its listeners, so inbound links work at once; session keys and the address book are discarded, so peers reconnect.
