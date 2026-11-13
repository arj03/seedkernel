# seedkernel: guest

*What a guest calls, what it is called with, and the realm it runs in. For a guest author, a transport author included: a transport is a guest that also declares `link`.*

> **Part of the [seedkernel](../README.md) spec.** Section numbers are global across the doc set, so a `(§X.Y)` reference points to whichever file holds that section:
>
> [README](../README.md) §1, §10 · [ARCHITECTURE](ARCHITECTURE.md) §2, §3, §5, §12, §12.6.2b, §16.1 · [BUNDLE](BUNDLE.md) §3.1, §4, §12.4, §12.5, §16 · **GUEST §12.2, §12.3** · [TRANSPORT](TRANSPORT.md) §12.6.1, §12.6.2, §12.6.3 · [SECURITY](SECURITY.md) §13, §14 · [CLIENT](CLIENT.md) §12.8
>
> The names, their bytes and the realm's rules are exact: one bundle runs unchanged on every target, so a host that answers a name differently runs a different ABI. Each rule is followed by its reason; the laws behind the bounds are ARCHITECTURE §12.

---

## Overview

A guest is a JS program that defines one function, `handle`. It runs in its own QuickJS realm with the language's built-ins and nothing else: no files, sockets, `fetch` or `process`. The host calls `handle` with `[caller 32][body]` and sends back whatever bytes it returns. Everything the guest does beyond computing goes through one function, `await host.call(name, bytes)`, and the names it may use are exactly what its signed manifest declared: the host services in `guest.requires`, other apps' service ids, its own modules, and the `crypto/*` transforms.

```js
// manifest: "guest": { "requires": ["fs"] }
const key = new TextEncoder().encode("count");

async function handle(input) {                 // [caller 32][body]
  const got = await host.call("fs/get", key);  // [0] absent, or [1][value]
  const count = got[0] === 1 ? (got[1] + 1) & 255 : 1;
  const put = new Uint8Array(4 + key.length + 1);
  new DataView(put.buffer).setUint32(0, key.length);
  put.set(key, 4);
  put[4 + key.length] = count;
  await host.call("fs/put", put);              // [klen u32][key][value]
  return new Uint8Array([count]);
}
```

The same `handle` receives a peer's request (caller = the peer's key), a co-resident app's call (caller = that app's id), and the host's own events (caller = 32 zero bytes): a timer `wake`, and, for the transport only, socket events. Invocations run one at a time per realm, each under a deadline, a heap cap and a cap on outstanding host calls. A guest that wants to do work on its own schedule arms its one wake.

A transport is a guest like any other, with one more service: `link`, which lends it the node's sockets and lets it hand decrypted requests to the apps that claim them.

This file has two parts:

- **§12.2 The guest seam**: every name, its request and response bytes, when a call settles, the signing scope, and the host events.
- **§12.3 Zero-authority JS realms**: what the realm contains, the entrypoint, the preamble constants, and the bounds a guest runs under.

---

## 12.2 The guest seam: the guest name ABI

A guest reaches the world through one call, `host.call(name, bytes)`, which answers a Promise. `bytes` is a `Uint8Array` or `ArrayBuffer`, or an array of them, which the call sends back to back: a guest hands over an argument's parts without concatenating them. It is entered through one function, `handle(bytes)` (§12.3). Multi-byte integers are big-endian.

### Names

A name is a guest↔host identifier, never a wire value: an opaque string with no op-number registry. A name resolves to what the manifest declared it as:

1. a local service id in **this realm's** `guest.requires`: the realm claiming it (§12.10);
2. a name in this bundle's `modules`: that private module (§4);
3. a method of a host service in `guest.requires`, or a `crypto/*` transform: the host (§12.1).

Any other name is refused. Install keeps the three disjoint: every host name contains `/`, a module name matches `[A-Za-z0-9_-]` and begins alphanumeric, and a local service id may neither live in a host namespace (`fs/…`, `crypto/…`) nor spell one of the bundle's module names.

Dispatch builds one map at load of every name the realm can reach, so it never reads a name's spelling, and a name means only what the signed manifest said. A service's names exist only if `requires` put them there, so an ungranted service is absent rather than present behind a check: omitting `requires` yields a seam with no services, never an unrestricted one. A method named where a service belongs (`fs/get` instead of `fs`) is refused at install rather than read as a finer grant the seam cannot enforce, and an unknown service throws, so a typo fails loudly rather than granting nothing, or everything.

### The name table

| Name | Request | Response |
| --- | --- | --- |
| `crypto/blake2b` | `[outLen u8][keyLen u8][key][msg ..]`, `outLen` 1..64, `keyLen` 0..64 | `outLen` bytes of BLAKE2b (RFC 7693), keyed when `keyLen` > 0 |
| `crypto/chacha20poly1305-ietf/seal` | `[npub 12][key 32][adLen u32][ad][msg ..]` | `ciphertext ‖ tag 16` (RFC 8439), binding `ad` |
| `crypto/chacha20poly1305-ietf/open` | `[npub 12][key 32][adLen u32][ad][ciphertext ‖ tag ..]` | `[1][plaintext ..]`, or `[0]` when the tag does not verify |
| `crypto/x25519/dh` | `[sk 32][pk 32]` | `[1][shared 32]`, or `[0]` for a low-order point. Against the base point it derives a public key. |
| `crypto/random` | `[n u32]` | `n` bytes of host entropy |
| `node/sign` | message bytes | 64-byte Ed25519 signature under the node identity over `domain ‖ scope ‖ msg` (Signing scope) |
| `node/verify` | `[pk 32][sig 64][msg ..]` | `[ok u8]`: 1 iff `sig` verifies over `domain ‖ scope ‖ msg` under `pk`. A payload shorter than 96 bytes throws. |
| `fs/get` | key (UTF-8) | `[0]` absent, or `[1][bytes ..]` |
| `fs/put` | `[klen u32][key][bytes ..]` | (empty) |
| `fs/list` | prefix (UTF-8, may be empty) | `[count u32] {[klen u32][key]}` |
| `fs/delete` | key (UTF-8) | (empty) |
| `fs/stat` | (empty) | `[used u64][available u64]` |
| `fs/size` | key (UTF-8) | `[size i32]`, −1 if absent |
| `timer/arm` | `[ms u32]` | (empty). Replaces this realm's one armed wake, due in 0..2147483647 ms; it arrives as the `wake` event. A realm that has spent its clock share has it slipped, not failed (§12.3). |
| `timer/clear` | (empty) | (empty). Cancels the armed wake; a `wake` already handed to the realm is not retracted. |
| `host/stage` | a host blob | (empty), or rejects. Hands the loader a host blob to run next (§12.9). |
| *bare module name* | request bytes, unwrapped | the module's response. A trap, an overrun length or a deadline kill rejects (§4.3). |
| *declared local service id* | opaque bytes; the host prepends the **caller's** 32-byte id | what the claimant's `handle` returned. Refused by name when nothing claims it (§12.10). |
| **`link/*`** | | **The link occupant only (§12.5).** Raw bytes over opaque link ids and datagram sockets; the transport above them is the occupant's (§12.6). |
| `link/open` | `[dest utf8 ..]`: an opaque destination the host resolves against the sockets it can open. The shipped sockets read `scheme://host:port[/path]`. | `[linkId u32][stream u8]`. Link 0 means no route, an unparseable or unroutable destination included. |
| `link/send` | `[linkId u32][bytes ..]`; no bytes sends nothing and only asks | `[backlog u32]`: what the link still holds for the wire, this write included, 0 for a link that is gone. An occupant forwarding between links reads it to stop reading the other side. |
| `link/pause` | `[linkId u32][paused u8]` | (empty). While paused, none of the link's reads reach the occupant. |
| `link/close` | `[linkId u32][graceful u8]` | (empty) |
| `link/deliver` | `[claimLen u8][claim utf8][attribution 32][payload ..]` | the claimant's answer, routed through the `peer` book (§12.10). Empty both for a claim no peer may reach and for a handler that failed. |
| `link/status` | occupant-defined bytes describing its own reachability | (empty). Handed unread to the embedder (§12.8). |
| `link/udpBind` | `[port u16]`, or nothing for 0 | `[socket u32][port u16][addresses utf8 ..]`: a datagram socket on that port, or one the OS picks for 0, dual-stack where the machine has IPv6, and every address the machine is reached at, `\n`-separated. Socket 0 when the host has no datagram sockets, has lent its maximum, or the bind failed. |
| `link/udpSend` | `([socket u32][host][port u16][len u16][bytes])*`: one turn's datagrams. `host` is `[4][ip 4]` or `[16][ip 16]`, as the `datagrams` event spells an address, or a name as `[0][len u8][name utf8]`, which resolves to IPv4. | (empty). A datagram that cannot be sent is lost, as is one from a socket this occupant does not hold; one running past the payload rejects the call. |
| `link/udpClose` | `[socket u32]` | (empty), after what the socket was given to send |

**fs keys** satisfy `[A-Za-z0-9._-]+`, minus `.`, `..` and the Windows device names `CON`, `PRN`, `AUX`, `NUL`, `COM0` to `COM9` and `LPT0` to `LPT9`, on every OS and regardless of extension (`NUL.txt` is `NUL`). Backends map a key to a filename verbatim, so the charset is a consensus predicate. Two nodes that disagree about which keys exist disagree about their contents, which is why a name only Windows refuses is refused everywhere.

**fs is scoped to the app label.** A guest's keys live under its `app` label: `fs/list` with an empty prefix enumerates only that app's keys, no key names another app's, and keys come back without the scope. Every bundle under the same label, whoever authored it, sees the same store (§5). `fs/stat` is not scoped: `used` and `available` describe the physical backend, since a per-app `available` would be a fiction when apps share one disk.

**A host transform takes its algorithm's whole standard interface** (the AEAD's associated data, BLAKE2b's output length and key), never the subset one bundle uses. The table itself is frozen and takes no new algorithms; new computation ships as a module of the bundle that needs it. The table exists only because the host already carries the code (§14). A name trimmed to one bundle's use makes the next bundle re-ship that code, or wait for a host release to adopt a standard protocol such as Noise. Published Noise XX vectors run through these names on every target and hold the interfaces there (`tests/noise-vectors.js`).

**`node/verify` is a grant, not a transform**, because its prefix is the host-derived scope, and "does this verify under *my* scope?" is a fact the guest cannot state for itself.

### Links

- **Every link is ordered.** `stream` 1 means a byte duplex the occupant frames itself; 0 means the platform delivers whole messages. This is the one fact a link states, because the guest named the destination, so it already knows the codec and the authority; what it cannot know is whether the socket under that name frames messages, since the same `ws://` is a platform `WebSocket` on one target and a byte stream on another.
- **One read is at most `MAX_LINK_READ_BYTES` (2 MiB)**, a platform-framed message whole; a larger one fails the link. An occupant's frame cap must fit under it.
- **Exceeding the host's own link and backlog ceilings fails the whole link**, never one write (§12.6). `link/send`'s backlog is how an occupant stays under them.
- **`link/status` bytes are the occupant's format.** The shipped transport's is in [TRANSPORT](TRANSPORT.md), Local interface. The host follows the occupant's reachability without polling it and without knowing what reachability means to this transport.
- **WebRTC, where the platform has it** (§12.7). `link/open("rtc:offer")` or `"rtc:answer"`, optionally followed by `?` and an `RTCConfiguration` as JSON, opens a message-framed *negotiation link*, each message `[tag u8][UTF-8 text]`. Tags: `o` an offer's SDP, `a` an answer's SDP, `c` a candidate (its `candidate`, `sdpMid`, `sdpMLineIndex` and `usernameFragment`, NUL-separated, an absent one empty), each in both directions; `s` the connection state, host to occupant only; `r` restart ICE (empty), occupant to host only. Only the offering side offers, and it sends a remote `a`; only the answering side sends a remote `o`. Messages apply in order, and a malformed or out-of-role one fails the link. The pre-agreed data channel (`negotiated`, id 0) arrives once open as a stream `linkOpen` whose `via` is the negotiation link. Closing either link closes both.

### Settlement

**Every name answers a Promise.** A call that produced a value resolves to bytes; a call that did not rejects. Zero bytes is a value: `fs/put` answers empty on success, and a module that returned nothing is distinct from one that trapped, overran or was killed. A fan-out is the guest's own `Promise.all`. With one settlement rule, nothing downstream re-derives failure from an answer's length.

**No name re-enters the calling realm.** A socket write does not deliver during the write, an armed timer fires on a later turn, and a call into another realm (a local service id, `link/deliver`) runs its callee on a later turn. A guest answering such a call fires it and returns rather than awaiting it inside its own frame, because invocations are serialized per realm (§12.3) and a re-entrant answer would deadlock on the frame that asked for it.

**`fs/*`, `crypto/*` and `node/*` answer within the asking turn**: the guest's `await` continues with no host turn in between. Module calls, local service ids, `link/deliver`, `link/udpBind` and `host/stage` answer on a later turn. The file primitive under every fs backend is synchronous on every target, so a guest cannot work on one backend and fail on another by accident. A durable browser backend therefore has to be synchronous too (OPFS sync access handles in a Worker, or a store loaded from IndexedDB and persisted behind it).

**`__deferred`.** A guest that will answer on a later turn sets `globalThis.__deferred = true` during the synchronous part of `handle`. The realm's queue is freed at the end of that segment though nothing has settled; the invocation's deadline stays attached to the answer and settles one that never arrives. This is the one ABI bit beyond `handle` returning bytes. Serializing invocations is right when the answer comes from outside, since a guest parked on a module call is suspended mid-update and must hold the queue. It is wrong when the answer arrives *through* the realm: the transport answers an app's send by reading bytes off a link, and that read is another invocation of the same realm, so awaiting inside the frame would hold the queue against the only event that could settle it. The flag hands over queue occupancy, never time, which is why the deadline stays.

### Signing scope

Each slot has **one** signing scope, derived at load from admitted facts, identical on every load path: `DOMAIN_guest ‖ app_len u8 ‖ app` for an ordinary app, from the manifest's `app` label and never the author, and bare `DOMAIN_link_scope` for the link occupant. `node/sign` signs `domain ‖ scope ‖ msg`; `node/verify` checks a caller-named key's signature under the same prefix. The guest never supplies or reads the prefix, no name signs raw bytes, and the key never enters a realm. The prefixes are the `DOMAIN_*` family (§16.1). The format inside a scope, the transport's `DOMAIN_channel` tag included, is bundle content.

Every node running an app under the same label derives the same scope, whoever authored it, for the reason §5 gives. Deriving it from admitted facts rather than accepting it from the guest is what makes it the same on boot, on an explicit install and on an in-place update, so an upgrade cannot silently re-scope a node. §12.6.2b says why both purposes share one key.

### Host events

The host enters a realm with its own events. A realm that armed a wake receives `wake`; the link occupant, and only it, receives the link events. Each arrives at `handle` as:

```
[32 zero bytes][opLen u8][op ASCII][args ..]
```

No padding or terminator. A `u32` is unsigned big-endian, a `blob` is `[byteLength u32][bytes]`, `text` is a blob of UTF-8, and a boolean is one byte, 0 or 1.

| Event | `opLen` | `args`, in byte order | Return body |
| --- | --- | --- | --- |
| `wake` | 4 | none | ignored |
| `linkOpen` | 8 | `[linkId u32][stream u8][listener text][via u32][remoteAddr text]` | ignored |
| `linkBytes` | 9 | `[linkId u32][bytes blob]` | ignored; the link's next read waits for it to settle |
| `linkClosed` | 10 | `[linkId u32]` | `[severity u8][reason utf8 ..]`. An absent or rejected answer reads as an empty reason at severity 0. |
| `datagrams` | 9 | `([socket u32][batch blob])*` to the end, each batch `([n u8][ip n][port u16][len u16][bytes])*`, n 4 for IPv4 and 16 for IPv6 | ignored; the next waits for it to settle |
| `listening` | 9 | `[socket u32][label text]` | ignored |

- **`linkId` 0 is never a live link.** `linkOpen` announces a socket the platform accepted or opened; a link the guest opened gets its id from `link/open` instead, with no event.
- **Arrival metadata is platform metadata, not identity.** `listener` is the label of the listener that accepted the link, `via` the live link it arrived through (how a WebRTC data channel names the negotiation link that opened it, §12.7), and `remoteAddr` the source address. Each is empty or 0 when absent.
- **`listening`** hands the occupant a `udp` listener the operator configured, as one of its own datagram sockets. It is bound each time an occupant takes `link`, so it goes with the occupant as its other sockets do.

There is one envelope because host events and peer requests arrive at the same `handle`, and the zero caller id is one no peer or realm can hold, so no host input is told apart by its length or position. A wake carries no payload because the guest keeps its own deadline table and reads its own clock (§12.3).

Listeners are labelled, not typed, because which codec a listener speaks is the transport's choice, not a property of the socket. A host that typed listeners would carry one transport's vocabulary, and a replacement speaking a third codec would need a host release to be listened for. A label is a string the host hands over unread, so the operator's flag and the transport agree without the host between them.

`linkClosed` returns a reason rather than the occupant calling a name, because a callable "report close" would let the occupant say it about a link it never observed, and a return value carries no link id, so it cannot be redirected to another socket. The reason is a local fact for the operator's log and never goes on the wire, so telling an absent peer from a hostile one locally does not weaken the handshake's silence ([TRANSPORT](TRANSPORT.md), Refusals are silent). Its words and severities are the occupant's; the host prints one above severity 0 and reads neither.

## 12.3 Zero-authority JS realms

A guest runs as confined JS in a QuickJS realm. The realm holds the ECMAScript intrinsics plus `queueMicrotask`, `performance`, `atob`/`btoa` and `DOMException`, and the preamble's globals: `host`, `HOST`, `APP`, `LOCAL` and `__deferred`. It cannot name `fs`, `net`, `process` or `fetch`. `Date.now()` and `performance.now()` are ordinary built-ins. The engine is the same build on every target, so a behavioural difference between targets is a build difference, not a version difference.

A realm starts with no authority and receives only names, so the list in `guest.requires` is the guest's whole reach (§12.1). Time is not authority: every ECMAScript program already has a clock.

### One entrypoint

The host invokes the guest's `handle` with `[caller 32][body ..]` and nothing else. The caller id is the host's to write: the peer key for a peer request, the calling realm's id for a local call, and 32 zero bytes for the host and its events. The body format is the callee's. `handle` may return bytes or a Promise of bytes.

Which role an invocation serves, requester or responder, is read from the guest's own body format, never selected by the host. A synchronous second entry is not possible to offer, since a responder may need a module or another realm, and neither answers in the same turn. So both roles are ordinary async invocations of one function.

### Invocations are serialized

One invocation holds the realm until its Promise settles or it sets `__deferred`. Top-level evaluation runs at install, before the install commits, and every name is refused during it (§3.1). Disposal (uninstall, revoke, replacement, shutdown) rejects every invocation still waiting on the realm.

Serializing them avoids two frames resuming into each other at every await, in an order neither the author nor the host chose. The cost is head-of-line blocking, which `__deferred` relieves where it matters.

### Preamble

Three constants reach the guest before its top level runs. Each is an object and always defined; absent means `{}`.

- **`HOST`**, from the host and fixed for the realm's life: `identity` (the node's public key as 64 lowercase hex, the key `node/sign` signs with, §12.6.2b), `maxOutstandingHostCalls`, `maxOutstandingHostCallBytes`, and `deadlineMs` (each invocation's deadline, a deferred answer included; `null` when unbounded).
- **`APP`**, from the author: exactly the manifest's signed `guest.config`. The host never merges into it.
- **`LOCAL`**, from the installation: exactly the JSON object the installer passed for this install. Not retained, invisible to other bundles.

Runtime facts (the node key, budgets, the signing scope) come only from the host, never from `APP` or `LOCAL`. A guest validates and combines `APP` and `LOCAL` itself.

The budgets are advertised so that a guest that windows a fan-out to `maxOutstandingHostCallBytes` meets backpressure instead of a rejection halfway through. The ceilings still enforce; the numbers are for pacing.

### Resource bounds

A guest is bounded by the three resource laws (§12): space has an owner, time has a deadline, and self-initiated work has a schedule. What that means for a guest:

- **Heap.** The realm's QuickJS heap is capped; past it, allocation throws.
- **Deadline.** Each invocation has one absolute deadline, set when it is admitted and only ever shrinking. It runs from **before** the realm queue through execution, host-call waits, socket backlog and a deferred answer. Every `host.call` and call into another realm carries the remainder; a callee cannot renew it. An interrupted guest throws and the realm survives. A module call runs under the remainder and is killed when it runs out (§4.3).
- **Outstanding host calls.** Unresolved calls and their copied input bytes are capped per realm (`HOST` advertises both), charged before the copy; a response is charged when delivered. Over the cap, `host.call` rejects.
- **One wake.** At most one armed wake and one `wake` in flight per realm. A due wake waits for the previous `wake` invocation to settle.
- **Clock share.** Each `wake` and everything it causes, awaited or not, is debited for **execution**: QuickJS time, module CPU and the synchronous part of host calls (disk time of `fs/*` included); time waiting on I/O is free. A realm banks one invocation's budget and earns credit at a fixed fraction of real time. A wake due with the share spent is **slipped**, never failed or dropped.

Heap and deadline are the operator's numbers, never the manifest's (§12.8). Defaults and ceilings are in `host/wasm-limits.ts`.

Execution time is the operator's because module memory is a property of the code, so the author declares it (§4.1). How long *this* node spends on one message is a property of the deployment. It matters most on the responding path: an interrupted guest throws, the transport answers a throwing guest empty, and a wedged guest costs one empty response rather than the link.

The deadline is one and only shrinks because a deadline that a callee could renew bounds nothing, since each hop would restart the clock. On a wall clock a step backwards would expire every live deadline at once and a step forwards would extend them all, so every reading is monotonic.

The link occupant runs on its own clock because it writes streams every caller shares, and a turn cut off halfway through a record leaves a hole in one. So a caller's remainder bounds the caller's wait and its time in the queue, but the occupant runs each invocation on its own ceiling, and a `link/deliver` answer resumes it as a new turn.

A realm gets one wake because one armed wake with a fixed body needs no timer table, no ids and no payload accounting in the host. The guest keeps its own deadline table in its own heap, which the heap cap already bounds, and reads its clock to find what is due.

The clock share paces timer fires because a timer fire is the one fresh root a guest can mint for itself (`timer/arm(0)` inside a `wake` would otherwise repeat forever with no outside cause), so it is what gets paced. Measuring each realm entry separates compute from waiting without a list of which names do which, and `fs/*` is debited because disk time holds the node's thread as compute does. Attribution is per realm because one realm's queue is shared by every root in it. The bound stops short of a node CPU total on purpose: an authenticated peer can keep replacing settled work, and pacing that ingress is the transport's, which can change in a bundle update without a host release.

A response is charged at delivery because a request's width is something the caller already handed over; an answer's is known only once the handler has run. Charging it earlier buys no bound the delivery charge does not already give, and the count cap bounds the window where answers are built but not yet charged.
