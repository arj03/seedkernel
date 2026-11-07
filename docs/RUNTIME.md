# seedkernel: runtime

*The runtime as an app host: performance, the chat demo, and the host's normative surface (host services, the guest-seam ABI, zero-authority JS realms, signed bundles, admission, the node↔node transport, the targets and routing).*

> **Part of the [seedkernel](../README.md) spec.** Section numbers are global across the doc set, so a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · [PROTOCOL](PROTOCOL.md) §2–§5, §16 · **RUNTIME §10–§12** · [SECURITY](SECURITY.md) §13–§14
>
> This file states each rule once. Why a rule is shaped the way it is lives in [DESIGN](DESIGN.md), under the same section numbers. The shipped transport's rules and rationale are [TRANSPORT](TRANSPORT.md).

---

## 10. Performance

The message path does **no asymmetric cryptography and no recursion**: routing a frame to an app is one claim lookup (§12.10) plus one guest entrypoint invocation, and the only scratch copies are the ones a guest's own module calls make (§4). Authenticity is the channel's (§12.6), established once per link.

### 10.1 Where the crypto is now

- **Per connection and per frame:** the transport's handshake and records, the shipped one's costs in [TRANSPORT](TRANSPORT.md) (Handshake, §12.6.1).
- **Per bundle load:** one BLAKE2b-256 hash of the body and verification of both Ed25519 and ML-DSA-65 signatures (§12.4).

The host's libsodium and ML-DSA-65 run on the platform's engine table (§12.9), on every target, and ML-KEM-768 in the transport bundle's own module. The Go/native target carries `*_bench_test.go` benchmarks over these hot paths; `npm test` from `WASM/` exercises them end-to-end on the JS target, and seedstore's `WASM/tests/bench.mjs` measures storage throughput.

### 10.2 Distribution Size

This is the one place these figures live.

| Component | Size |
|---|---|
| `services/*.js` + hand-written `host/*.js` a page imports beside the blob, minified (`build-min`): the host (`platformHost`) and its browser platform, the socket seams and bundle verification | ~140 KiB |
| **Host blob** (`build/host.skb`): the host script, `qjs.wasm`, libsodium, ML-DSA-65 and the default transport, signed (§12.9). The native and Node loaders run it | 1.18 MiB |
| of which the host script (`build/host.js`) | 219 KiB |
| of which `qjs.wasm`, the realm engine, built for size (`-Os`, native/qjs/build-qjs.sh) | 624 KiB |
| of which libsodium.wasm (core build: the host's crypto) | 217 KiB |
| of which mldsa65.wasm (ML-DSA-65, the PQ half of manifest suite `0x02`) | 16 KiB |
| of which the transport bundle (`build/transport.skb`): its guest, signed without comments, `ws.wasm` and `mlkem768.wasm` (ML-KEM-768, 12 KiB) | 134 KiB |
| **Web host blob** (`build/host-web.skb`): the same signed blob with an empty script, since a page imports the host instead | 996 KiB |
| **Total browser deployment**: the modules and the web host blob | **~1.1 MiB (~470 KiB gzipped)** |
| **Native binary**, stripped, per `GOOS`/`GOARCH`: mostly wazero's compiler backend (~4 MiB), the Go runtime (~2.4 MiB) and the genesis host blob | ~6.9 MiB |

`npm run build` emits the readable `build/` (~285 KiB of JS in `host/` and `services/`) and the comment-stripped `build-min/` (~140 KiB), a second `tsc` pass with `removeComments` (`scripts/minify.mjs` over `tsconfig.min.json`) holding only what the browser entry points reach: the host modules a page imports. It prints the gzipped size before and after minifying on every run.

---

## 11. Example app layer: chat ([seedshell](https://github.com/arj03/seedshell))

Chat is the smallest complete app, and lives in [seedshell](https://github.com/arj03/seedshell), the browser page that hosts it and a consumer of this runtime's published entry points (`platform`, `platform-web`, `host-web.skb`, `bundle`, `net-rtc`, `net-ws`). Nothing here knows chat exists; §13 walks the same pipeline byte by byte.

- **The bundle** is a guest of a few dozen lines and one restartable module, with an HTML view carried in its signed manifest. A peer's frame is drawn only if it is for this node, written to a room its sender is in or addressed to this node, and the module's render bytes are the answer; a frame from the app's own view goes out through the transport's `_net` service to the peers it is for. The module reads `senderPk ‖ chatType ‖ body` and writes render bytes; it does no I/O and no crypto. The page names a consent by one hash over the whole verified bundle: author, manifest, guest and modules.
- **The page** generates an Ed25519 channel identity, boots a host (§12.8) and loads two small bundles of its own beside the transport, pinned to the author it was built with. Every other bundle is admitted only if the user consented to it (§12.5). A later build of chat is another bundle under the same `(author, app)`: installing it names that slot and re-states the `chat` protocol claim (§12.10).
- **Peers** meet in a room on the relay, which the page joins itself, then link through the relay and move to WebRTC, negotiated by the transport bundle (§12.7); chat rides the transport request plane as `[req][protocolId][chatType][body]`, and the transport's `link/deliver` hands the claiming slot's guest the authenticated peer key in front of it.
- **Offered bundles** travel under `offer/v1`, a protocol of the page's boot bundle; the recipient re-verifies both author signatures and applies its own policy (§12.4).
- **Rendering** leaves the host: the guest returns render bytes to the page, which `postMessage`s them to an iframe sandboxed `allow-scripts allow-forms allow-downloads` with no same-origin access to the page's keys.
- **The relay** hosts rooms the page joins with seedrelay's room client (`rooms.mjs`), whose messages travel on the transport's own relay link through its `tell` op and status, and which names each member to the transport as a `relay+` address; the relay sees only a room's hashed id, and the transport sees no rooms at all. A room is not authenticated: its members see which keys are in it, but cannot impersonate a peer (§12.7).
- **Calls** are the page's own: it opens a separate `RTCPeerConnection` per peer for audio and video and signals it over the authenticated transport, under a protocol a small boot bundle claims.
- **An app's name, version, description and view** ride in its signed manifest under `guest.config.shell`, a seedshell convention; the host passes `guest.config` to the guest and reads none of it.

To run it: `npm run build:browser` here, then follow seedshell's build steps (`npm run relay` runs the relay).

---

## 12. The runtime as an app host: host services and signed bundles

The host knows nothing about chat or storage: it offers a fixed, generic surface, verifies a bundle against a policy, and becomes whatever the bundle is. [seedstore](https://github.com/arj03/seedstore) is the worked example: a peer-to-peer storage node is the host plus a signed bundle.

### 12.1 Host services: raw-byte backends

The host provides five **host services**, `node`, `fs`, `timer`, `link` and `host` (`HOST_SERVICES`, `host/domains.ts`), and two ungated name families. Each service is one file in `services/`, its handlers beside its backend. Every node offers `node` and `timer`; `fs`, `link` and `host` only where `bootShell`'s `services` names them (§12.8). All of them move raw bytes; the host never interprets what an app means by them.

| Service | Methods | Backs |
| --- | --- | --- |
| `node` | `node/sign`, `node/verify` | The node key: signing and verification under this slot's scope (§12.2). The node's public key is not a call; every realm reads it as `HOST.identity` (§12.3). |
| `fs` | `fs/get`, `fs/put`, `fs/list`, `fs/delete`, `fs/stat`, `fs/size` | Raw bytes under an opaque, flat key, scoped to the app label (§12.1). |
| `timer` | `timer/arm`, `timer/clear` | The realm's one wake (§12.3). |
| `link` | `link/open`, `link/send`, `link/pause`, `link/close`, `link/deliver`, `link/status`, `link/udpBind`, `link/udpSend`, `link/udpClose` | Raw links over opaque link ids, attributed inbound delivery, the occupant's status, and raw datagram sockets for its UDP paths (§12.7). **The link owner only** (§12.5). |
| `host` | `host/stage` | Hands the loader a host blob to run next (§12.9). The blob authenticates itself, so any app may declare it; the loader's rules and the operator's `--host-updates` decide. A `bootShell` without `services.host` refuses an app that declares it; a library node and a page offer the name and refuse every blob, having no slots to keep one in (§12.8). |
| `crypto/*` | `blake2b`, `chacha20poly1305-ietf/{seal,open}`, `x25519/dh`, `random` | `HOST_TRANSFORM_NAMES`, a frozen compatibility table of transforms the host already carries, each over its algorithm's whole standard interface (§12.2). `random` is host entropy. **Not a grant.** |
| *bare names* | the bundle's own module names | The asking bundle's private WASM modules. **Not a grant.** |

- **A grant is a service.** `guest.requires` (§12.4) lists everything a guest reaches: host services, and the local service ids it calls (§12.10). Which of the two a name is, is one closed-table lookup (`isService`), never a spelling convention. Host services are named by service, never by method; declaring `node` grants `node/sign` and `node/verify` together. Install refuses a method name (`fs/get`) with the service to declare instead, and refuses an unknown service. The seam holds handlers only for declared services, so an undeclared service's methods are unknown names.
- **An undeclared service is not wired.** An fs-less bundle gets no fs backend at all, not a backend behind a check. A declared service the node cannot back (`fs` on a diskless node) refuses the install.
- **`crypto/*` and bare module names are ungated** and cannot be declared. New pure computation ships as a module of the bundle that needs it; `HOST_TRANSFORM_NAMES` takes no new algorithms. A name it does hold takes its algorithm's whole standard interface (BLAKE2b's output length and key, the AEAD's associated data), never the subset one bundle uses, so a standard protocol over these algorithms is a bundle, not a host release (`tests/noise-vectors.js` replays published Noise XX vectors through them on both targets).
- **Time is not a service.** Every realm reads `Date.now()` and `performance.now()` as ordinary engine built-ins.
- **Anything with structure lives in a bundle, never in host code.** Protocol logic is the bundle's guest JS: the transport's handshake, relays and UDP stream. A byte transform whose cost is per byte is one of the bundle's private WASM modules: RFC 6455 masking and the handshake accept are `ws.wasm` in the transport bundle, erasure coding is an app's `codec.wasm`.

#### fs

- **Every method answers in the frame that asked**, on every backend, since the `RawFiles` under each is synchronous. The guest still sees a Promise (§12.2).
- **Keys** satisfy `isSafeFsKey` (`services/fs.ts`): `[A-Za-z0-9._-]+`, minus `.`, `..` and the Windows device names `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9`, on every OS and regardless of extension (`NUL.txt` is `NUL`).
- **Scoped to the app label.** The backend a guest reaches prefixes every key with `appScopeFor(app)`, a lowercase-hex hash of the label. `fs/list` with an empty prefix enumerates only that app's keys, `fs/get`/`fs/delete` cannot name another app's, and keys come back stripped of the scope. The scope belongs to the label, not the author (§5).
- **`fs/stat` is not scoped**: `used`/`available` describe the physical backend.
- **Backends.** `MemoryFs` (`services/fs-memory.ts`) enforces `DEFAULT_MEMORY_FS_MAX_BYTES` and `DEFAULT_MEMORY_FS_MAX_ENTRIES`. A directory is one store on every loader, `FilesFs` (`services/fs-files.ts`), over a platform's whole-file primitives: it keeps the used total, reclaims the temp files a crash leaves, and never reads a file larger than a put can carry. It takes the medium's own limit. `NodeFs` (`services/fs-node.ts`) is it over `node:fs`. A durable browser backend has to fill in `RawFiles` synchronously too ([DESIGN](DESIGN.md) §12.1).

#### Links

- **A `RawLink`** reports `stream` (1: a byte duplex the caller frames itself; 0: the platform delivers whole messages), and `buffered()`, the bytes it still holds. It carries no codec and no authority. Every `RawLink` is ordered.
- **An `Arrival`** accompanies a platform-opened link: the label of the listener that accepted it, or `via`, the link it arrived through, which is how a WebRTC data channel names the negotiation link the occupant opened for it (§12.7). Guest-opened links have no `Arrival`.
- **Listeners are labelled.** A `ListenAddress` is `{ label, host, port }`; the label reaches the occupant with every link that listener accepts, and the host never reads it.
- **Socket seams**, each handing a `RawLink` to the driver (`services/link.ts`) through the one `ChannelFactory` seam: `tcpChannels` (`host/platform.ts`, one TCP listener per address over the platform's sockets; `nodeChannels` in `host/shell-node.ts` is it on `node:net`), `services/net-ws.ts` (a browser `WebSocket`), `services/net-rtc.ts` (§12.7), and `combineChannels` (`services/socket-seam.ts`) to put several behind one driver; on the native target `tcp.go`/`net.go`. The flood bounds are `services/net-limits.ts` (§12.6).

### 12.2 The guest seam: the guest name ABI

A guest reaches the world through one seam, `host.call(name, bytes)`, and is entered through one entrypoint, `handle(bytes)` (§12.3). `host/guest-seam.ts` services the seam, wiring only the host services the node offers that slot.

**Names** are guest↔host identifiers, not wire values: opaque strings with no op-number registry. A name resolves to what the manifest declared it as:

1. a local service id in **this realm's** `guest.requires` → the realm claiming it (§12.10);
2. a name in this bundle's `modules` → that private module;
3. a method of a host service in `guest.requires`, or a `crypto/*` transform → the host (§12.1).

Any other name is refused. Install keeps the three disjoint: every host name contains `/`, a module name matches `[A-Za-z0-9_-]` and begins alphanumeric, and a local service id may neither live in a host namespace (`fs/…`, `crypto/…`) nor spell one of the bundle's module names. Multi-byte integers are big-endian.

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
| `link/open` | `[dest utf8 ..]`: an opaque destination the host resolves against the sockets it can open. The shipped seams read `scheme://host:port[/path]`. | `[linkId u32][stream u8]`. Link 0 means no route, including an unparseable or unroutable destination. |
| `link/send` | `[linkId u32][bytes ..]`; no bytes sends nothing and only asks | `[backlog u32]`: what the link still holds for the wire, this write included, 0 for a link that is gone. An occupant forwarding between links reads it to stop reading the other side. |
| `link/pause` | `[linkId u32][paused u8]` | (empty). While paused, none of the link's reads reach the occupant: a pausable socket is not read, and a read the platform had already granted waits in the driver until the link resumes. |
| `link/close` | `[linkId u32][graceful u8]` | (empty) |
| `link/deliver` | `[claimLen u8][claim utf8][attribution 32][payload ..]` | the claimant's answer, routed through the `peer` book (§12.10). Empty both for a claim no peer may reach and for a handler that failed. |
| `link/status` | occupant-defined bytes describing its own reachability (the shipped transport's format is in [TRANSPORT](TRANSPORT.md), Configuration) | (empty). The occupant says it each time its state changes, and the host hands the bytes unread to the embedder's `onStatus` (`bootShell`'s transport options), so a host follows the occupant's state without polling it. The format is the occupant's; the shell's console decodes the shipped transport's, and prints one that starts with a printable byte, such as a relay's log line, as text. |
| `link/udpBind` | `[port u16]`, or nothing for 0 | `[socket u32][port u16][addresses utf8 ..]`: a datagram socket on that port, or on one the OS picks for 0, dual-stack where the machine has IPv6, and every address the machine's sockets are reached at, `\n`-separated. Socket 0 when the host has no datagram sockets, has lent `MAX_UDP_SOCKETS`, or the bind failed. Its reads arrive as `datagrams` events. |
| `link/udpSend` | `([socket u32][hostLen u8][host utf8][port u16][len u16][bytes])*`: a turn's datagrams, each to an IPv4 or IPv6 address, or to a name, which resolves to IPv4 | (empty). A datagram that cannot be sent is lost, as is one from a socket this occupant does not hold; one running past the payload rejects the call. |
| `link/udpClose` | `[socket u32]` | (empty), behind what the socket was given to send |
| `timer/arm` | `[ms u32]` | (empty). Replaces this realm's one armed wake, due in 0..2147483647 ms; it arrives as the `wake` host event (§12.2). A realm that has spent its clock share has it slipped, not failed. |
| `timer/clear` | (empty) | (empty). Cancels the armed wake; a notification already handed to the realm is not retracted. |
| *declared local service id* | opaque bytes; the host prepends the **caller's** 32-byte id. A call into the link occupant is the one the host reads, for the protocol a `send` names (§12.10) | what the claimant's `handle` returned. Refused by name when nothing claims it. |

#### Settlement

- **Every name answers a Promise.** A call that produced a value resolves to bytes; a call that did not rejects. Zero bytes is a value: `fs/put` answers empty on success, and a module that returned nothing is distinct from one that trapped, overran or was killed. A fan-out is the guest's own `Promise.all`.
- **No name re-enters the calling realm.** A socket write does not deliver during the write, an armed timer fires on a later turn, and a call into another realm (a local service id, `link/deliver`) runs its callee on a later turn. A guest answering such a call fires it and returns rather than awaiting it inside its own frame.
- **Mechanics.** The host injects `__host_call(name, callId, payload)`, `__callDone` and `__callFail`; the preamble moves them into its closure and deletes them from `globalThis`, and keeps its own state there too, so no guest name can collide with or reach the seam's internals. A call that has to wait parks: `link/deliver`, `link/udpBind`, `host/stage`, a module name and a local service id. The preamble holds a Promise under `callId`, settled by `__settleHostCall`. The engine reads `__settleHostCall` and `__start`, the preamble function that calls `handle`, once the preamble has run and before the guest's source does, and calls only those captured functions from then on, so a guest that redefines either, as a getter say, never runs code outside its budget through it. Every other name gets its answer back in the frame that asked, so the guest's `await` continues in the same turn with no host turn in between.
- **`__deferred`.** A guest that will answer on a later turn sets the host's `__deferred` flag; the invocation's queue spot frees at the end of its synchronous segment though nothing has settled. Its caller-owned deadline stays attached to the answer and settles a deferral that never completes. This is the one ABI bit beyond `handle` returning bytes.

#### Signing scope

Each slot has **one** signing scope, derived once at load from admitted facts (`slotSignScope`), identical on every load path:

| Slot | Domain ‖ scope |
| --- | --- |
| an ordinary app | `DOMAIN_guest ‖ app_len u8 ‖ app` (`appSignScope`), from the manifest's `app` label, never the author |
| the slot holding `link` | `DOMAIN_link_scope`, no further scope bytes |

`node/sign` signs `domain ‖ scope ‖ msg`; `node/verify` checks a caller-named key's signature under the same prefix. The guest never supplies or reads the prefix, no name signs raw bytes, and the key never enters a realm. Raw verification stays host-internal (`SeamCrypto`). The domain family is disjoint (§16.1). Every node running an app under the same label derives the same scope, whoever authored it. The format inside a scope, including the transport's `DOMAIN_channel` tag, is bundle content.

#### Host events

The host enters a realm with its own events. A realm that armed a wake receives `wake` when it fires; the slot holding `link`, and only it, receives the four link events, the `link` service's `events` list beside its `calls` in `host/domains.ts`. Each arrives at `handle` as `[32 zero bytes][opLen u8][op ASCII][args …]`, encoded with `OpArgs` (`host/op-frame.ts`); the envelope and field order are host ABI every guest that arms a wake, and every link occupant, must accept. There is no padding or terminator. A `u32` is unsigned big-endian, a `blob` is `[byteLength u32][bytes]`, `text` is a blob of UTF-8, and a boolean is one byte, `0` or `1`.

| Event | `opLen` | `args`, in byte order | Return body |
| --- | --- | --- | --- |
| `wake` | 4 | none | ignored |
| `linkOpen` | 8 | `[linkId u32][stream u8][listener text][via u32][remoteAddr text]` | ignored |
| `linkBytes` | 9 | `[linkId u32][bytes blob]` | ignored; the driver awaits completion before admitting the next read on this link |
| `linkClosed` | 10 | `[linkId u32]` | `[severity u8][reason utf8 ..]`; the driver prints a reason above severity 0. An absent or rejected answer reads as an empty reason at severity 0 |
| `datagrams` | 9 | `([socket u32][batch blob])*` to the end, each batch `([n u8][ip n][port u16][len u16][bytes])*`, n 4 for IPv4 and 16 for IPv6 | ignored; the driver holds the next until it settles |

- `linkId` 0 is never a live link. `linkOpen` announces a platform-accepted or platform-initiated socket; a guest-opened link gets its id and `stream` from `link/open` instead, with no event.
- Missing arrival metadata encodes as an empty listener and `via` 0. A `via` names the live link this one arrived through, 0 when there is none or it has already gone. A missing source address is empty text. Listener, `via` and address are platform metadata, not authenticated identity.
- `stream = 1` makes each `linkBytes` an arbitrary byte-stream slice; `0` makes it one platform-framed message. The bytes inside the blob are opaque to the host.

**The close reason** is a local fact; it never goes on the wire. Its words, and how much each matters, are the occupant's; the host reads neither. The shipped vocabulary is in [TRANSPORT](TRANSPORT.md) (§12.6.1). The driver prints a reason above severity 0 verbatim as `[transport] link N from <addr> down: <reason>` (`TransportHostOptions.suppressLinkLog` silences it) and hands every reason to `TransportHostOptions.onLinkClosed`.

### 12.3 Zero-authority JS realms

A guest runs as confined JS in a QuickJS realm holding only the engine's built-ins (the ECMAScript intrinsics plus `queueMicrotask`, `performance`, `atob`/`btoa` and `DOMException`) and the injected preamble, which leaves `host`, `HOST`, `APP`, `LOCAL`, `__deferred`, `__start` and `__settleHostCall` on `globalThis`. It cannot name `fs`, `net`, `process` or `fetch`. A realm is one `qjs.wasm` instance on the platform's engine table (§12.9), driven by one shared driver, `host/engine-realm.ts`, on every target. What runs on every call, arming the deadline, draining the job queue and the host-call ledger, is compiled into the engine's realm ABI (`native/qjs/csrc/realm.c`); the driver moves bytes and numbers only.

- **One entrypoint.** `realm.call(bytes)` invokes the guest's `handle` with `[caller 32][body …]`. The caller id is the host's to write: the peer key for a peer request, the calling realm's id for a local call, 32 zero bytes for the host itself and its events (the wake and the raw-link events). The body format is the callee's. A guest declares `handle`; nothing else is ever invoked.
- **Invocations are serialized per realm** (`host/realm-queue.ts`, shared by both targets): one invocation holds the queue until it completes or sets `__deferred`.
- **Top-level evaluation** runs at install, before commit, while the seam refuses every name (§3.1).
- **Disposal fails what is parked.** `Shell.close()`, uninstall and revoke dispose a slot's realm at once, rejecting every invocation still parked in it and freeing the engine. A handle held past that rejects, naming the slot.

#### Preamble

Three constants reach the guest before its top level runs. All are objects and always defined (absent ≡ `{}`).

| Constant | Contents | Source |
| --- | --- | --- |
| `HOST` | `identity` (the node's public key as 64 lowercase hex, the key `node/sign` signs with), `maxOutstandingHostCalls`, `maxOutstandingHostCallBytes`, `deadlineMs` (each invocation's handoff deadline, a deferred answer included; `null` when unbounded) | the host; fixed for the realm's life. The budgets are advice for pacing; the ceilings still enforce. |
| `APP` | exactly the manifest's signed `guest.config` | the author; the host never merges into it |
| `LOCAL` | exactly the JSON object passed to this `install(blob, { localConfig })` | the installation; passed unchanged for every slot, not retained, invisible to other bundles |

Runtime facts (the node key, budgets, the signing scope) come only from the host, never from `APP` or `LOCAL`. A guest validates and combines `APP` and `LOCAL` itself.

#### Resource bounds

Boundedness follows three separate laws:

1. **Retained space uses continuous custody.** Every host-side byte caused by untrusted input has a finite owner from creation to destruction; a handoff reserves in the receiver before releasing the sender.
2. **Causal lifetime uses a monotone deadline.** One absolute deadline begins at an invocation root and only shrinks through queues and calls. No callee can renew it. The link occupant is the one exception (`ownTurns`).
3. **Initiation rate uses explicit scheduling.** The realm wake paces the only fresh roots a guest can create for itself. Network-originated roots arrive only over authenticated links and are bounded per invocation; there is no node-wide CPU guarantee.

No operation name relaxes custody; a name may tighten what an owner admits (`fs/put` meets a storage quota), and the owner of a resource enforces its bound, not the dispatcher. Every owner has a complete release path and a default, so a host that configures nothing still bounds its guests:

- **Heap:** the realm's QuickJS runtime is capped at 64 MiB by default, `realmMemoryBytes` / `--guest-memory`.
- **Deadline:** per entrypoint invocation, 5 s by default, `guestDeadlineMs` / `--guest-timeout`. Admission resolves one absolute deadline, the tighter of the initiator's live remainder and the callee realm's ceiling. It begins **before** the realm queue and runs through guest execution, host-call waits, socket backlog and a deferred answer. Every `host.call` and cross-realm delivery carries the remainder. A queued invocation keeps its deadline and is rejected rather than given a fresh segment. Installation-time evaluation runs under the configured ceiling. `Infinity` disables a realm's local ceiling but cannot widen a finite deadline handed to it. Every reading is monotonic (`performance.now`). Both targets enforce it with QuickJS's interrupt handler; an interrupted guest throws and the realm survives.
- **The link occupant's turns are its own** (`ownTurns`). A caller's remainder bounds the caller's wait and the time its request queues, but the occupant runs each invocation on its own ceiling, and a `link/deliver` answer resumes it as a new turn.
- **Module calls** run under the calling segment's remaining time and are killed at the engine when it runs out (§4.3).
- **One wake per realm.** The host retains at most one armed wake and one notification in flight, each the fixed `wake` event. The guest reads its own clock to find what is due. A due successor waits for the previous wake invocation to settle. Replacement is transactional, clear cancels, disposal closes permanently; none retracts a notification already handed over. A wake handler must return before waiting for work that needs another wake.
- **Clock share for self-initiated work.** Each timer fire receives a host-only causal clock, restored whenever that root's continuations run and carried through host calls, module calls, `link/deliver` and cross-realm calls, awaited or not. It debits **execution**: QuickJS segments, the measured CPU of module calls, and the synchronous span of host-service calls, the disk time of `fs/*` included; time parked on I/O is free. A realm banks one invocation's budget and earns credit at `1 / SELF_INITIATED_CLOCK_DIVISOR` (twice `DEFAULT_MAX_APP_SLOTS`). A wake due with the share spent is **slipped**, never failed or dropped. Attribution is per turn: roots live in one realm share its account. A full node's summed self-initiated execution is at most half a CPU after the initial bank (`tests/verify-hardening.mjs`).
- **Outstanding host calls:** at most 256 unresolved calls and 16 MiB of copied input per realm (`DEFAULT_MAX_OUTSTANDING_HOST_CALLS`, `DEFAULT_MAX_OUTSTANDING_HOST_CALL_BYTES`), plus a response's bytes while it coexists with its request. The id, count slot and width are admitted together, before the copy leaves QuickJS. A response is charged when it is delivered, and a call answered in the frame holds its charge only while that answer is copied in. Release paths: settlement, the handoff deadline, disposal (which also clears their armed deadlines).
- **The realm-entry queue** has no depth of its own: every entry borrows its bytes and population from a bounded upstream owner (the driver's inbound window, the calling realm's call registry, an explicit host owner) and keeps its admission deadline.
- **Realms:** at most `DEFAULT_MAX_APP_SLOTS` slots, refused at `install`; a replacement retires one as it installs one.

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
- **Both signatures**, Ed25519 and ML-DSA-65, are over `DOMAIN_manifest ‖ suite ‖ ed_pk ‖ ml_dsa_pk ‖ BLAKE2b-256(body)`; `DOMAIN_manifest` is prepended, not stored. **Both must verify.** The verifier authenticates the body before interpreting any of it.
- **Suite.** Only `0x02` is supported. Another id is refused with its own error, distinct from a bad signature. Suite ids are never reused.
- **Author id** = `genesisHash(DOMAIN_manifest_author ‖ suite ‖ ed_pk ‖ ml_dsa_pk)`, 32 bytes. Policy entries, revocations and freshness marks are written against it.
- **Author keys from one seed.** `hybridAuthorKeysFromSeed` (offline-only `scripts/bundle-author.ts`) derives the Ed25519 half from a 32-byte seed and the ML-DSA-65 half from `genesisHash(seed ‖ AUTHOR_MLDSA_SEED_LABEL)`. The label is frozen. Pass the 32-byte seed, not libsodium's 64-byte secret key.
- **The ML-DSA verifier** is `browser/mldsa65.wasm`, an import-free module built from the pinned `pq/mldsa-native` submodule (`scripts/build-mldsa.mjs`; `npm run build:pq` rebuilds it and `mlkem768.wasm`, given the submodules and a clang with the wasm32 target). All targets run the same bytes. `bundle.ts` calls `ml_dsa65_verify_detached` on the crypto object; a host that supplies none refuses `0x02`.

#### Manifest

| Field | Type | Enforced | Meaning |
| --- | --- | --- | --- |
| `app` | string | yes | The slot's key: one slot per label per node, whoever authored it. Names the fs and signing scopes; what `replaces` and `uninstall` select; with the author, keys the freshness mark. Non-empty, at most 255 UTF-8 bytes, with no control, line-separator, bidi or zero-width characters. |
| `version` | integer | yes | Non-negative safe integer; the set's monotonic version (§12.4). |
| `modules[]` | `{name}` | yes | One entry per private WASM module, in body order. `name` is what the guest passes to `host.call`: unique, `[A-Za-z0-9_-]`, alphanumeric first. Zero to `DEFAULT_MAX_BUNDLE_MODULES` (§16). |
| `protocols[]` | string[] | yes | Protocol ids a **peer** may reach (§12.10). Optional. |
| `services[]` | string[] | yes | Local service ids a **co-resident guest** or the host may reach. Optional. A name may appear in both lists. |
| `guest` | `{requires, config?}` | yes | Required; a manifest without one is refused. |
| `guest.requires` | string[] | yes | Everything the guest reaches: host services by service name, and local service ids it calls. A method name is refused with the service to declare; a local id must follow the claim charset, stay out of host namespaces and not spell a module name. Empty means no authority. |
| `guest.config` | JSON object | shape only | Injected unchanged as `APP`. Must be an object; absent ≡ `{}`. Opaque to the runtime. |

The host reads no WASM custom sections. A convention such as seedshell's `shell` entry in `guest.config` belongs to the app.

#### Install

`install(blob, options)` runs three phases. Failures throw to the operator.

*Verify* (pure, nothing lands):

1. Read the fixed-width suite, keys and signatures; hash the body and verify both signatures. Invalid ⇒ reject.
2. Parse and validate the manifest, then read the guest and modules in manifest order. Truncation or trailing bytes ⇒ reject.

*Admit* (governance):

3. Ask the host's gates (author revoked? version below the `(author, app)` mark?), then, for an ordinary app, the admission predicate once (§12.5).

*Construct and commit*:

4. Contests (label, claims, `link`) are checked against the slot table (§12.10).
5. Read every module's declared memory and table limits before instantiating any; enforce per-module and aggregate bounds (§4.1).
6. Build every module off to the side and validate its exports; on any failure release them all.
7. Derive `fsScope` and the signing scope, then stand the realm over a seam wired with exactly the services in `guest.requires` and those modules, with the preamble `HOST`, `APP`, `LOCAL`. A declared service the node cannot back, or a guest that does not compile, rejects the candidate. The seam refuses every name until step 8 (§3.1).
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
- **Link bundles** skip the predicate: `link` is authorized only by boot selection or by replacing its current owner.
- **Contests are not gates.** Whether a label, claim or the `link` binding is free is answered by the slot table, before the candidate's code runs and again at commit (§12.10).

#### Install and replacement

- **`install(blob)`** with no `replaces` takes a FREE label. A blob whose `app` is already installed is refused by name, whoever authored it, and so is one requiring `link`.
- **`install(blob, { replaces: app })`** runs the same sequence and atomically takes over that slot, across authors and labels. An app candidate still needs the predicate. A candidate requiring `link` is authorized only if the named predecessor owns `link`.
- A replacement may take the predecessor's label and claims, never unrelated claims nor a label a third slot holds. Claims the new manifest drops are released. The target is captured at call time and checked again at commit, so a concurrent update, uninstall or shutdown fails the stale replacement. Any failure leaves the current owner running. Replacement works at the slot ceiling.
- Scopes follow the label and the freshness mark follows the author (§5). Old invocation handles become invalid.
- **`reachesLink(manifest)`** (`guest.requires` contains `link`) is the one test the installer, the binding, the wiring and the signing scope use.

#### Boot transport

`bootShell`'s `services.transport.bundle` defaults to the embedded artifact; selecting it authorizes its `link` independently of app policy, and it must declare `link`. Without `services.transport` (the `bootShell` default) the node offers no `link` and creates no transport. The CLI enables networking only with `--listen`, `--peers` or `--relay`; `--transport` selects the boot blob, and it, `--transport-config` and `--contact-secret` are refused without one of those. After the transport is uninstalled or replaced by an ordinary app, starting another requires a new boot.

`services.transport.datagrams` lends the link occupant the platform's datagram sockets for its UDP paths (§12.7). The Node loader and the native binary pass their platform's; a node without them (a browser) has no UDP path.

#### Policy file

`--policy <allowed-keys.json>` (`host/policy.ts`):

```json
{ "authors": ["<64-character hex app author id>"] }
```

`authors` is required; an empty array denies all apps. Malformed ids, unknown keys and malformed JSON fail boot. **Omitting `--policy` denies ordinary app installs**; it does not disable an enabled transport.

Sensitive protocol and service names are pinned to approved owners (author and `app` label) inside the predicate; [CLIENT](CLIENT.md#the-assembly-is-an-export) has an example. A pin reserves ownership, not availability, and changing admission rules evicts no installed slot.

#### Revocation

- **`shell.revoke(authorHex)`** records the author key as written off and uninstalls every slot admitted under it, in one action. The CLI and native binary expose `--revoke <hex,…>`, and `--uninstall <app,…>` for removing an app alone.
- A revoked key's bundles are refused whatever version they claim. The set is keyed by author only.
- The runtime never removes a key from the set, even if it reappears in `authors`. The Node CLI and native binary persist it atomically with the freshness marks; the browser chat page holds both in memory. Undoing a revocation is an out-of-band store edit.
- An author with a new key starts a new freshness mark and may take a label released by the revocation, inheriting that label's data and signing scope.
- There is no emergency module-replacement seam: a fix is a signed bundle at a higher `version`.

### 12.6 Node↔node transport: channel identity binding

The link occupant, a transport bundle, owns the channel. The shipped one's handshake, records, budgets, secrets, configuration, relays and direct paths are [TRANSPORT](TRANSPORT.md) (§12.6.1–§12.6.3). This section is the host's side. The first transport ships inside the host blob (§12.9).

- **Division of labour.** The host driver (`services/link.ts`) owns sockets by link id and the listeners, and hands a `link/open` destination to its socket factory. The transport guest owns the handshake, record layer, correlation table, peer set, request facade, address book, relays and the signaling of direct paths, UDP and WebRTC. Apps reach it through the local service id it declares under `services` (`_net`).
- **What a replacement changes without a host release.** Everything in [TRANSPORT](TRANSPORT.md): the handshake, key schedule, suite byte, record layer, framing, listener labels, address grammar, relay wire and config keys. The host sees no handshake width, the shell passes `--peers`, `--relay`, `--relay-secret` and `--contact-secret` through unread, refusing only a `wss://` destination (§12.8), and each `crypto/` name takes its algorithm's whole interface (§12.1); an algorithm the host lacks ships as a module, as ML-KEM does. What stays the host's: the identity key's algorithm (`node/sign` and `node/verify` are Ed25519), the socket kinds a destination can name, and the link events (§12.2). The shell's calls into a transport are `relay` and `ready` on its service id, made when `--relay` and `--peers` are given (§12.8).

#### Driver bounds

The host driver keeps its own coarse bounds beneath the transport's, on structures a socket costs the moment it is accepted:

- **`MAX_LINK_READ_BYTES` (2 MiB)** caps one read handed to the occupant (a platform-framed message whole) and fails the link past it, before the copy into the realm. The occupant's frame cap must fit under it. The byte windows below are sized in it.
- **`DEFAULT_MAX_RAW_LINKS` (4096)** bounds the link table on the one path that mints a link id, and **refuses** rather than evicts (`TransportHostOptions.maxRawLinks`).
- **`MAX_INBOUND_HOLD_BYTES` / `MAX_INBOUND_HOLD_SLICES`** are one driver-wide budget for reads admitted toward the transport realm, charged while held and while dispatched. A link that cannot pause is failed when its next read crosses a ceiling; a pausable one has its one read charged anyway and waits, unread, until the budget has room, so a node holding a read from each of hundreds of busy sockets (a relay) slows them rather than dropping them. Reservations release when the dispatched call settles or held input is dropped. The platforms keep no budget of their own beneath it: each holds at most one read per socket until `resume` (Node pauses the socket; the native reader waits on its read token, its read still in the buffer it reads into).
- **`MAX_OUTBOUND_QUEUE_BYTES` / `_SLICES`** per link and **`MAX_NODE_OUTBOUND_QUEUE_BYTES` / `_SLICES`** (4× each) node-wide bound authenticated writes waiting below the transport; the guest applies the same window to frames on its encryption chain. One custody period per link spans the adapter's pre-open buffer and the platform's send backlog: the charge is `RawLink.buffered()` (`writableLength` on Node, `bufferedAmount` in the browser, an exact queue on native), and the driver retires the drained prefix of the admitted sizes at each write. An adapter that cannot report fails its link. Crossing any ceiling, or the occupant's own `host.call` budget refusing a write, fails the whole link, never one record.
- **Teardown severs the wire first.** `close`/`abort` cut the wire synchronously, failing any parked write, then run the queued teardown; the link leaves routing at once.

`buffered()` is the host's accounting; a guest sees only the backlog `link/send` answers.

#### 12.6.2b One master seed, one identity

A node stores one secret, a 32-byte **master seed**. `host/subkeys.ts` (`seedkernel-wasm/subkeys`, for a tool that boots the node a `--key` names) derives its signing keypair under the closed, literal label `channel`; that public key **is** the node's identity: the peer id, `senderPk` and `HOST.identity`. The master signs nothing. The one key signs for both purposes, separated by signing scope (§12.2). Nothing revokes it: a leaked seed is a lost identity, and recovery is a new seed and peer id (§14).

### 12.7 Relays, WebRTC and UDP paths

A node that cannot be dialed is reached through a relay and moves to a direct path when one can be made; which peers, the relay and its wire, who offers and how long connecting may take are the transport's ([TRANSPORT](TRANSPORT.md)). The host lends the two platform primitives a direct path needs and decides nothing: a browser's `RTCPeerConnection`, which a confined guest cannot hold, and, off the browser, datagram sockets.

#### WebRTC

`RtcNetwork` (`services/net-rtc.ts`) holds the peer connection.

- **Two links per peer connection.** `link/open("rtc:offer")` or `"rtc:answer"`, optionally followed by `?` and an `RTCConfiguration` as JSON, opens the *negotiation link*: message-framed, each message `[tag u8][UTF-8 text]`. The pre-agreed data channel (`negotiated`, id 0, on both sides) arrives once it opens as the *data link*, a byte stream announced with the negotiation link as its `via` (§12.2). Closing either closes both.

| Tag | Up (host → occupant) | Down (occupant → host) |
| --- | --- | --- |
| `o` | the local offer's SDP | a remote offer's SDP (answering side only) |
| `a` | the local answer's SDP | the remote answer's SDP (offering side only) |
| `c` | a local candidate | a remote candidate |
| `s` | the connection state | — |
| `r` | — | restart ICE (empty) |

- A candidate is its `candidate`, `sdpMid`, `sdpMLineIndex` and `usernameFragment`, NUL-separated, an absent one empty.
- **Only the offering side offers.** Its `negotiationneeded` sets and sends a local offer; the answering side answers what it is given and never offers, so there is no glare. Down messages apply in order, a candidate never ahead of its description; up, a candidate gathered while a description is being set follows it. A malformed or out-of-role message fails the link.
- **Bounds are the driver's.** Each link is an entry under `DEFAULT_MAX_RAW_LINKS`; down messages not yet applied are the negotiation link's `buffered()` backlog, so outbound custody bounds them (§12.6); up messages are ordinary reads.
- **Console nodes** may pass their own `peerConnectionFactory` implementing the W3C subset `RtcNetwork` uses; the runtime depends on no ICE/DTLS/SCTP library. None of the shipped clients does: between console nodes the UDP path is the direct path, and a console node's link to a browser stays on the relay. The native binary has no WebRTC.

#### Datagram sockets

The occupant runs UDP paths itself over sockets the host lends it (`link/udpBind`, §12.2); the host reads no datagram and keeps no path.

- **The platform** is the platform ABI's `__udp` (`RawDatagrams`, `services/datagrams.ts`): a socket on a port the OS picks, dual-stack where the machine has IPv6, whose reads arrive in batches of `[n u8][ip n][port u16][len u16][bytes]`, n 4 for IPv4 and 16 for IPv6, a send that takes a `link/udpSend` batch as it is and resolves a name to IPv4, and the machine's addresses. `services/datagrams-node.ts` is Node's. Each socket asks for 4 MiB receive and send buffers, since a sender may put a whole receive credit on the wire at once and a buffer that drops a burst's tail cuts the sender's window; a kernel that grants less is taken at its word. The native binary's is `native/udp.go`: a reader goroutine per socket, reading into 2 KiB since an end behind a hard NAT opens hundreds of sockets, holds what it reads until the loop takes it, so a turn's datagrams cross into the host realm in one call.
- **Reads.** One `datagrams` event is in the realm at a time, carrying every socket's reads since the last, up to `MAX_LINK_READ_BYTES`; past `MAX_UDP_HELD_BYTES` held, a datagram is dropped as a full socket buffer drops it. The native reader goroutines charge the same ceiling, across every socket together, to what they hold before the loop takes it, so native datagram memory is bounded at twice this figure. Unlike a TCP read, nothing gates a datagram socket's reader on the loop, so this charge is the only bound on what it holds.
- **Sends.** `link/udpSend` takes up to 256 KiB a call, which the host checks (every datagram inside the payload, from a socket the occupant holds) and hands the platform whole.
- The host lends at most `MAX_UDP_SOCKETS` and closes them with the occupant's links when it goes.

### 12.8 The shell: node assembly and the CLI

`bootShell(opts)` (`host/shell-core.ts`) assembles the host and returns its `Shell` plus the channel adapter. `bootNodeShell(opts)` (`host/shell-node.ts`) stands a node up in-process through the host's own `standUp` (`host/platform.ts`) on the Node platform the Node loader runs (§12.9), with the package's host blob for its engine and crypto, and adds file-path bundle loading. A page stands up the same way on the browser platform, `platformHost(browserPlatform({ hostBlob })).standUp(cfg)` (`host/platform-web.ts`, §12.9), passing its own channels and, in place of a policy file, its own `admit`. The CLI is `host/cli.ts`:

Both loaders take the same flags; `seedkernel` (the native binary) stands in for `node build/host/loader-node.js` anywhere below.

```sh
node build/host/loader-node.js --policy ./allowed-keys.json --dir ./data --key ./node.key \
     --listen 0.0.0.0:7000[,ws=0.0.0.0:7001] \
     --bundle ./app-bundle [--transport ./transport.skb] [--transport-config ./transport.json] \
     [--peers <pk>.<secret>@host:port,…] \
     [--relay ws://<relay key>.<secret>@host:port [--relay-secret ./relay.secret]] \
     [--contact-secret ./contact.hex] [--local-config ./app.json] \
     [--revoke <hex,…>] [--uninstall <app,…>] \
     [--op name [--app name]  < argument > response] \
     [--guest-timeout <ms>] [--guest-memory <MiB>] \
     [--host ./host.skb] [--host-updates off|next|now]
```

- **`runCli` is shared by both loaders**, in the host script (§12.9). It owns the flag set, the defaults (`--dir ./data`, `--key ./seedkernel.key`), the deny-all reading of an absent `--policy`, the order (remedies, then the bundle, then the one-shots, then serve) and every printed line. A target supplies a `CliHost`: file reads and writes, argv and a banner, one console line, raw stdin and stdout, entropy, and `standUp` to stand a node up on that platform. Unknown flags are errors.
- **`--key`** holds the 32-byte master seed; `deriveNodeKey` derives the keypair from it on both targets.
- **`--listen [label=]host:port,…`** binds one listener per entry, labelled `tcp` when it names no label. An IPv6 host goes in brackets, `[::]:9000`. The label reaches the transport with every link the listener accepts, unread (§12.1).
- **`--transport`** selects a signed transport bundle from disk instead of the embedded one. A relay node runs seedrelay's bundle this way, as its transport.
- **`--transport-config`** names a JSON object that becomes the boot transport's `LOCAL` unread; `--peers` and `--contact-secret` take precedence over its own entries.
- **`--contact-secret`** names a file, never the secret itself; its contents, less the line ending, become `transport.config.contactSecret` unread: 64 hex characters, or `open` for a node that answers anyone, which is a node in public. Without it the shipped transport derives the secret from the node's key, and the node prints it at boot as `contact <hex>`, the part of its address after `pk.`.
- **`--local-config`** requires `--bundle` and is that load's `LOCAL`; it never reaches the transport.
- **`--peers`** becomes `transport.config.peers` on the automatic transport load, as typed: the shell parses neither it nor `--contact-secret`, beyond refusing a `wss://` destination, which no console socket reaches, so a replacement transport can spell addresses and secrets its own way, and the transport's load refuses a malformed one. Once up, the CLI waits for the cohort with the transport's `ready` op on its service id; `null` means no transport is installed.
- **`--relay`** registers the node on that relay through the transport's `relay` op, passing the URL unread, so a node nobody can dial is reached there (§12.7). The URL names the relay's key, as the relay prints it. It must be `ws://`: neither console target's sockets speak TLS, so `wss://` is refused rather than redialed forever, and the relay link runs the channel handshake, so the path sees no key ([TRANSPORT](TRANSPORT.md), Relays). The boot line says whether the registration took; a relay that is down, or refuses the node, does not stop the boot. A node on a relay keeps serving without a listener.
- **`--relay-secret`** names a file holding the relay's contact secret in hex, for a URL that does not carry it, never the secret itself, as `--contact-secret` does; its contents, less the line ending, follow the URL in the `relay` op unread. It requires `--relay`.
- **`--op name`** invokes the app `--bundle` just loaded, through that load's handle: stdin is the argument, stdout the response, framed as `[opLen u8][op][args]`. Logs go to stderr on both targets. When a node already serves `--dir`, the op goes to that node instead, through its control endpoint (below), and nothing boots. That node reads no other flag, so such an `--op` takes only `--app`, the app there (omitted, the node's only one); with `--bundle` or any other flag it is refused while a node serves the directory, rather than half obeyed. `--app` never goes with `--bundle`.
- **The control endpoint.** A node that serves a bundle listens on a local socket, `<dir>.control` beside its data directory (`host/control.ts`), and on nothing else: no port is opened. It is a Unix domain socket, owner-only from the moment it is bound (the bind runs under a umask, so no connection can land before the mode is set), so being the user the node runs as is the operator authority the endpoint asks for. Node on Windows has only named pipes, so there `<dir>.control` is a file naming a random pipe, and the pipe's default ACL keeps others to reading; a native node there makes a real Unix socket, which takes its directory's ACL. The two kinds do not reach each other on Windows, and each refuses the other's file rather than reading it as nobody serving. The node speaks first, `[0]`, and the caller sends nothing before it, so a socket nothing serves never receives a request. One request per connection, `[len u32][appLen u8][app][op frame]`, answered `[status u8][len u32][bytes]`, status 0 the app's answer and 1 an error as text. A request reaches the app through `AppHandle.invoke`, the same caller-zero loopback `--op` uses, so it waits its turn in the app's realm as any invocation does. A socket nothing answers at is stale: `--op` then boots as before, and the next node to serve there replaces it; a live one is never replaced. The platform ABI's optional `listenLocal`/`connectLocal` carry it (§12.9); library callers use `serveControl`, `controlServes` and `controlInvoke` from `seedkernel-wasm/control`, with `nodeLocalChannels()` from `seedkernel-wasm/shell-node` on Node.

**The request side.** An inbound frame and a host loopback both reach the app's one `handle` as `[caller 32][body]` (§12.3); `AppHandle.invoke` supplies the host's zero caller id. Bodies use the callee's format. Clients choosing the common `[opLen u8][op][args]` envelope take it from `seedkernel-wasm/op-frame` (`host/op-frame.ts`); the host never imports or interprets it. The driver resumes on the promise `handle` returned, so inbound handling may be asynchronous. Seedstore's WASM README has a complete storage walkthrough.

### 12.9 Loaders and the host blob

A node is a **loader** running a **host blob**. The loader is the only code fixed when a node is deployed; everything the node does, from admission to the CLI, is the host script inside the blob, and the same script runs on every loader.

- **The host blob** (`host/host-blob.ts`, `build/host.skb`) is a suite `0x02` envelope (§12.4) under `DOMAIN_host`, so it never passes as an app bundle or an app bundle as a host. Its body is the manifest `{version, abi}`, the host script (`build/host.js`, the shared TypeScript bundled by `scripts/bundle-host.mjs`), `qjs.wasm`, `libsodium.wasm`, `mldsa65.wasm` and the default transport bundle (`build/transport.skb`, §12.6), which a host's `standUp` installs unless told otherwise. `npm run build` signs it with `host-author.key`, which the first build writes, at `package.json`'s `hostVersion`.
- **The platform ABI** (`host/abi.ts`) is what a loader gives the host script: process I/O and entropy, private modules (§4), the engine table, files, TCP and UDP sockets, timers, and `stageHost`. Every member is a raw primitive. A call a platform can only answer asynchronously is awaited by the host on every loader. The script refuses a loader that implements another ABI version, and a loader passes over a slot whose blob needs one.
- **The engine** instantiates wasm from bytes, calls its exports with numbers and reads and writes its memory. The Node and browser loaders pass it to the host script whole, over `WebAssembly`; the native loader passes a table of handles, which the host wraps into the same (`host/platform.ts`). The Node and browser engines also lend a view of that memory, so a host call whose handler is done with its payload when it returns (`crypto/*`, `node/*`, `fs/*`) reads it without a copy; the native host realm is another instance, so it always copies. Guest realms (§12.3) and the host's crypto (`host/sodium-engine.ts`) run on it, so the engine and the crypto ship in the blob.
- **Two loaders.** The native binary (`native/`) is Go over [wazero](https://wazero.io): the host script runs in a `qjs.wasm` instance from the blob, and Go owns the event loop (timers, the JS job queue, socket delivery). The Node loader (`host/loader-node.ts`, `npm run shell`) runs the host script in V8 on the Node platform (`host/platform-node.ts`), the ABI over `node:net`, `node:dgram`, `node:fs` and `WebAssembly`. The Node library (`bootNodeShell`, §12.8) runs the same host in-process on the same platform. A page has no loader: it imports the host as the Node library does, `platformHost(browserPlatform(...))` on the browser platform (`host/platform-web.ts`: the engine table over `WebAssembly`, private modules in workers, an in-memory store by default, and no sockets), and takes only the blob's engine and crypto, from `build/host-web.skb`, the blob with an empty script. The page stands its node up through the same `standUp` with its own channels and admission gate. It has no slots: the origin that serves it is its trust root.
- **Checked by the host it replaces.** A loader holds no crypto and decides nothing about authorship. The running host checks a blob before handing it over (`checkStagedHost`, `host/host-blob.ts`), with its own libsodium and ML-DSA-65, as it checks an app bundle: both signatures, then the parts. The chain is rooted in the genesis blob built into the loader. A loader reads the layout of what is in its slots, which only a host put there, and trusts those files as it trusts the data directory beside them.
- **Updates** follow one implementation of a loader's decisions, `host/slots.ts`: its flags, which blob each boot runs, and the trial. The Node loader imports it into the realm it runs the host in. The native binary runs it as `build/loader.js` in a QuickJS realm of its own (`native/hostslots.go`), never the host's, so there a broken host cannot break its own rollback. On both, the script comes only from what the loader was built with. Each loader keeps only the booting and the clock the health window runs on. The slots sit beside the data directory: `<dir>.host/committed.skb`, `pending.skb` and the `tried` mark.
  - **Who and what.** A host stages only a blob from its own author, for its loader's ABI, at a version above its own. The running host is never older than the committed one, so that version is the floor.
  - **Staging.** A running host hands a checked blob to `stageHost`, which apps reach through `host/stage` (§12.1), and the loader keeps it as pending. `--host-updates off`, the default, refuses staging; `next` boots a pending host at the next start; `now` reboots into it in place once the operator flow has ended. A reboot drops a completed `--op`, so the one-shot runs once.
  - **Tried once.** The `tried` mark is written before a pending host boots, so a pending host found marked never committed, and is dropped unrun.
  - **Committed after a health window.** A pending host that serves for 30 s with no fatal error is written over `committed.skb`, which raises the floor. A blob it staged meanwhile stays pending for a trial of its own. A failure before that, at boot or while serving, drops it and boots the committed host; a crash is caught by the mark at the next start. A run that only performs an `--op` and exits proves nothing either way and leaves it pending.
  - **A newer loader wins.** A loader whose genesis blob is newer than the committed host runs the genesis blob.
- **Loader flags** (§12.8's command line). `--host <file>` boots that blob instead of the slots' choice, unchecked and from any author, by the operator's explicit choice, and leaves the slots alone. `--host` and `--host-updates` are the loader's; the host never sees them.
- **Interop.** A Go node and a Node node join one cohort against the same signed bundles (`WASM/scripts/native-interop.sh`).

Benchmarks: `go test -run x -bench . -benchmem ./...` from `native/`; `node tests/bench-module-call.mjs` from `WASM/` for the JS module-call hop.

### 12.10 Protocol routing: which app handles a message

A frame names a **protocol id**, never an app, author or module. Each installed slot claims names from its signed manifest; the host keeps three books, all projections of the installed set, recomputed at every commit and removal and never persisted:

| Book | Filled from | Reached by |
| --- | --- | --- |
| `peer` | `protocols` | inbound peer requests, via `link/deliver` |
| `local` | `services` | a co-resident guest's `host.call`, and the host's `Shell.call` |
| `occupied`, the raw-link binding | `guest.requires` containing a service with `events` (only `link`) | the driver's raw-link events |

- **One owner per name per book.** A candidate contesting an active claim, label or the binding is refused before commit. Only an install naming the holder in `replaces` takes it over; uninstall releases. A free `link` is taken only by boot selection.
- **Claim charset**: alphanumeric or `_` first, then alphanumerics and `._/-`, at most 64 bytes. Uniqueness is per list; the same name in both lists is allowed. No spelling is reserved; `_net` is this repo's transport's convention.
- **Peer delivery.** The link occupant decodes a request and calls `link/deliver(claim, attribution, payload)`; the host looks the claim up in the `peer` book alone and invokes the slot's `handle` with `attribution ‖ payload`. An unclaimed protocol, or a `services`-only name, is answered empty.
- **Local calls.** `host.call(id, …)` on a local service id in the caller's own `guest.requires` resolves through the `local` book; the host prepends the caller's 32-byte id and the answer is the callee's `handle` result on a later turn.
- **An app sends under its own claims.** A frame names only a protocol id, and the far end routes by it with this node's key in front, so an app may send only under the ids in its own `protocols`. An app that only sends under an id claims it too. On every call from an app to the link occupant the host reads the op, and for a `send` the protocol it names (`sendProtocol`, `host/op-frame.ts`), and refuses an id outside the caller's `protocols` at the call site. Those leading fields, `[op "send"][noReply u8][to blob][proto blob]`, are the link occupant's contract with the host, and the rest of its vocabulary is its own. `Shell.call` is the embedder's own door and is not held to them.
- **Host doors.** `AppHandle.invoke(payload)` is slot-bound (a bundle claiming nothing has one) and prepends 32 zero bytes. `Shell.call(serviceId, payload)` resolves the `local` book with the host's caller id and returns `null` when nothing claims the name.
- **The binding.** The driver follows the book, and the host wires the `link` service (the driver's raw links plus its own `deliver`) only into that slot.
- **`InstallOptions.onInbound(claim, sender, answer)`** fires once a peer-inbound request to this load's slot resolves. It is observation only: it cannot change the answer, never fires for `invoke` or local calls, and a throw from it is reported and swallowed.
- **One slot per name.** There is no fan-out.
- A claim grants no authority, but selects which admitted app receives decrypted input (§14).

**Transport replacement** is ordinary slot replacement of the link owner. The candidate loads complete and offside; the host passes its own `LOCAL` unchanged, so the embedder re-supplies whatever configuration the replacement wants, in its own grammar, or afterwards through `Shell.call`. At commit the host swaps the slot, its claims and the binding together. The driver keeps its listeners, so inbound links work at once; the old occupant's links and state go with it, so peers reconnect.
