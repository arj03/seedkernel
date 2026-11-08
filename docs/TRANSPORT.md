# seedkernel: the shipped transport

*The transport bundle's program: its channel, relays and direct paths, and why each is shaped that way.*

> Everything here is the **shipped transport bundle's guest program** (`transport/src/*.js`, with private modules `ws.wasm` and `mlkem768.wasm`), not host code. A replacement transport may differ; this is what ships. The host's side (the link driver and its bounds, the identity key, the `rtc:` and datagram seams, and what a replacement can change without a host release) is [RUNTIME](RUNTIME.md) §12.6–§12.7, with its rationale in [DESIGN](DESIGN.md). Sections keep the global ids the source cites (§12.6.1–§12.6.3).

---

## What it provides

**An observer who can open sockets to a node and watch traffic cannot enumerate which identities are present on the network, nor which pairs are talking.** Three attacks are denied:

| Attack | Denied by |
| --- | --- |
| **Probe**: connect to a host, learn which node lives there | the contact secret, which every node and relay has unless opened (§12.6.3); an open one is in public and denies it to nobody (Limits) |
| **Attribute**: watch a flow, learn which pair it belongs to | the caller's identity travelling under the hybrid ephemeral secrets, the receiver's not travelling at all, on every link a relay's included (Relays) |
| **Membership-test**: ask a node "would you talk to key P?" | a peer list that sees only verified identities (§12.6.3), and silent refusal before one |

It does not hide a node at a stable `host:port` from anyone holding an address book and a packet capture, and the cleartext suite byte identifies the traffic as seedkernel. Hiding the communication graph itself is mixnet work and a different project. Limits has the full list.

Apps reach the transport through the local service id it declares under `services` (`_net`); ops such as waiting for a cohort, listing peers and teaching an address (`addr`) are ordinary calls through it, framed with `host/op-frame.ts`. Every link, open correlation and `ready` waiter holds a monotonic due time, a `ready` waiter's capped short of `HOST.deadlineMs` so the wait settles before its invocation fails; the realm's one wake is armed for the soonest, and each wake retires what is due and re-arms. The wake is armed only while something waits; a refused arm fails nothing. A pending request fails as soon as its peer loses its last routable link.

## Framing

- Node↔node over TCP: a length prefix. Browser↔node: RFC 6455 over the same TCP socket, its headers in `framing.js` and its masking in `ws.wasm`. Platform `WebSocket`: whole messages as delivered. `RTCDataChannel`: a byte stream under the same length prefix, whatever the platform's message limit (`RTC_CHUNK_BYTES`).
- Each framer checks its cap against the declared length **before** buffering the body; a platform-framed message is measured on arrival. The cap is `MAX_HANDSHAKE_FRAME_BYTES` (8 KiB, `transport/src/framing.js`) until authentication and `maxFrameBytes` (`MAX_FRAME_BYTES` by default) after. `raiseCap()` lands once the authenticating step (msg2 dialing, msg3 accepting) has run; until then framers take one message at a time.
- A listener labelled `ws` is read as RFC 6455, any other label as length framing.
- `Pieces` (`transport/src/util.js`) merges slices below 8 KiB (`MERGE_BELOW`) into a doubling tail buffer and keeps larger slices as they arrived. The WebSocket framer serializes `push`.

**The pre-auth cap exists because the application cap would be a memory hole.** The full frame cap on an unauthenticated peer would let a stranger reserve megabytes per connection; 8 KiB against the 1,024 unverified budget is 8 MiB, with room above both PQ message widths. The cap is raised only after the authenticating step runs because a full-size first record riding the same segment, measured against the pre-auth cap, would refuse a legitimate link.

**Reassembly is linear.** Joining every slice onto one buffer makes a dribbled full-size frame cost quadratic copies; keeping every slice costs a view and a pinned chunk per byte, times the half-open budget. Merging small slices into a doubling tail moves every byte a constant number of times. The WebSocket framer serializes `push` because `frames()` takes a frame before awaiting its decode, so a second parser would read the frame after it.

## Handshake

Three messages, then records. A message is a bare body with no type byte.

```
msg1  i→r   [suite: 1][eph_i: 32][kem_pk_i: 1184]
             [seal(k_probe; ∅): 16]                         1,233 B  contact proof, no identity
msg2  r→i   [eph_r: 32][kem_ct: 1088]
             [seal(k2; sig_r: 64): 80]                      1,200 B  hybrid reply, signed, no identity
msg3  i→r   [seal(k3; id_i: 32 ‖ sig_i: 64): 112]             112 B  the caller names itself
FRAME       [AEAD record ..]                                          only after authentication
```

```
H(x)    = BLAKE2b-256(x), unkeyed; ‖ is concatenation
KDF(ikm, ctx, label) = H(ikm ‖ ctx ‖ label)
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
k_i2r   = KDF(ee ‖ pq ‖ contact, h3, LABEL_i2r)
k_r2i   = KDF(ee ‖ pq ‖ contact, h3, LABEL_r2i)

Sign(m) = Ed25519(DOMAIN_link_scope ‖ m)   (node/sign; the prefix is the host's)

LABEL_probe = "seedkernel-c-probe-v1\0"         LABEL_i2r   = "seedkernel-session-i->r-v1\0"
LABEL_msg2  = "seedkernel-c-msg2-v1\0"          LABEL_r2i   = "seedkernel-session-r->i-v1\0"
LABEL_msg3  = "seedkernel-c-msg3-v1\0"          LABEL_rekey = "seedkernel-session-rekey-v1\0"
```

- **Parsing is by state.** The initiator reads msg2, the responder msg1 then msg3, and everything after authentication is a record. Each handshake message is accepted only at its exact width, derived in one place from named field lengths (`M1_LEN`…`M3_LEN`, `transport/src/ake.js`).
- **Keys.** `eph` is a fresh X25519 key per connection on each side; `kem_pk_i` is a fresh ML-KEM-768 key; the responder encapsulates, the initiator decapsulates. `seal` is ChaCha20-Poly1305-IETF at nonce zero; each key seals exactly one message. No long-term DH or KEM key is used; the contact secret is a KDF input and the network key seeds `root`. An all-zero X25519 result (a low-order point: `crypto/x25519/dh` answers `ok = 0`) or a KEM call the module refuses is a refusal like a seal that does not open: silence, on either side, the initiator at msg2 included.
- **Suite `0x03`** is the only suite: Ed25519 identity, ephemeral X25519 + ML-KEM-768, contact secret, ChaCha20-Poly1305 records. An unrecognised id draws silence. There is no list, fallback or negotiation. `suite` is folded into `h1`, so both signatures cover it.
- **The KEM is bundle content.** `mlkem768.wasm` is the bundle's own import-free module, reached under the bare name `mlkem` through the same private module map as `ws.wasm`, and pinned to 40 NIST ACVP cases. It adds no host transform name.
- **A dial pins its peer, and the receiver's key never travels.** `sig_r` is checked against the key the caller dialed; `id_r` is in the signed message but not on the wire. A signature under any other key, including the caller's own, closes the link before the caller names itself.
- **Ordering.** An accepting node sends nothing until a msg1 opens under its contact secret or one of its other secrets (§12.6.3). The receiver proves itself at msg2; the caller names itself at msg3, only to a receiver it has verified.
- **Signatures** cover `DOMAIN_channel ‖ root ‖ transcript ‖ own id` under the host's `DOMAIN_link_scope`; `sig_r`'s transcript chains the suite, both ephemerals, the KEM key and ciphertext, and `sig_i`'s all of msg2 besides. The initiator authenticates the responder at msg2 (1 RTT) and sends its first records behind msg3; the responder authenticates the initiator at msg3 (1.5 RTT).
- **Refusals before an identity is verified are silent.** A responder refuses a wrong contact secret, wrong network, malformed message or bad msg3 by doing nothing until the deadline. A caller the peer lint declines at msg3, or that an accept held for another peer does not take, is closed at once. An initiator's rejection at msg2 (a bad signature, its own key, the peer lint) closes the link.
- **Cost.** Each endpoint makes one Ed25519 signature, one verification and one ephemeral X25519 exchange; the dialer also generates an ML-KEM-768 keypair and decapsulates, and the acceptor encapsulates. Every record after is one ChaCha20-Poly1305 seal or open.
- **Pre-auth sends** are queued oldest-dropped under both `MAX_QUEUE_BYTES` and `maxPreAuthQueueSlices`. When the link goes before authenticating (a dial that dies, or the loser of the double-connect tie-break), the queue passes to another link to the same peer.
- **Double connect.** Two nodes dialing each other keep the link the smaller identity dialed. Only the loser's dialer closes it: a dialer sends behind msg3, before the far end has chosen, so the accepting end stops routing to the loser but reads it until the dialer's end-of-stream record. If the winner goes first, the loser routes again.

### Identities travel under the hybrid ephemeral secrets

Neither identity appears in cleartext. The caller's is sealed under keys derived from `ee` and the ML-KEM secret; the receiver's is never sent, since every caller dialed it. Both secrets are erased once the session keys exist, so a node seized years later yields nothing from a recording. At msg1 the only key in existence is long-term, so anything sealed there would be sealed under a key that lives for years: Noise names this property for its `IK` pattern, and WireGuard documents it as a known limitation (a responder's private key plus a traffic log reveals who sent every recorded handshake). Deferring identity until both ephemeral secrets exist makes concealment forward-secret and hybrid for both ends.

So the handshake uses **no long-term Diffie–Hellman key at all**. The Ed25519 identity key stays signing-only, without the Ed25519→Curve25519 conversion Secret Handshake needs, and an address carries no DH or KEM key, so the address format (`pk[.secret]@host:port`) does not depend on the suite.

### The receiver proves itself first

Every dial is pinned, so msg2 carries a signature and no key, and the caller checks it before building msg3. Every peer the node has given its address to holds the contact secret and can answer msg1 as the node, but none can produce that signature, so an impostor draws msg1 and nothing more. This is SIGMA-I's order with the responder's identity left off the wire.

Someone must go first; that is only assignable. Assigning it to the receiver costs little: with a contact secret only secret holders reach msg2, and the secret travels in an address that already names the key. What msg2 gives away is a signature an anonymous caller can check against candidate keys, and only an open node gives it to one. Every node has a contact secret unless it is opened.

The peer lint runs at msg3 on the caller's verified identity. A caller it declines is closed rather than stalled: it verified the receiver at msg2, so silence would conceal nothing and only leave it sending into a dead link. It sees its link come up at msg2 and close at once, as a TLS 1.3 client finishes before the server has checked its certificate.

### Refusals are silent

Every refusal before an identity is verified lets the deadline expire, so an unauthorised caller cannot tell this node from any server that waits for its client to speak first. It can still tell it from a closed port, and the fixed deadline is itself observable. The framing layer refuses the same way: almost every four random bytes declare more than the cap, and closing on sight would identify the node. Closing on a bad message answers a question ("I am a seedkernel node and that is not the key"), which is exactly the oracle this removes, available to anyone who can open a socket. In the code this looks like missing error handling, which is why it is commented as load-bearing: the likeliest way to lose it is someone tidying up error paths.

The cost is that a refused connection occupies a socket until its deadline, which makes the half-open budgets (§12.6.2) the thing standing between a stranger and the node.

### Hybrid key establishment

Session keys derive from both the X25519 and the KEM secret, so the classical half still protects them if the PQ half turns out to be flawed while it is young. The responder encapsulates at the point it already generates its own ephemeral, so the hybrid costs no round trip: still three messages, one encapsulation and one decapsulation per link.

**Where the KEM secret enters is the part that is quiet when wrong.** The key schedule takes a *list* of shared secrets; the KEM secret is appended to it, never XOR-ed into `ee` and never substituted for it. Msg2's seal key is the first key available to both ends after encapsulation, and it already derives from `[ee, pq]`; msg3 and both session directions inherit the pair. The transcript chains complete messages, binding the encapsulation key and ciphertext.

**What must not change.** The transcript chain, the signature preimages, the contact-secret and network-key mixes, the silence discipline, the address format, the record layer, and the invariant that the bytes a node sends are the bytes it folds into the transcript.

**The DoS interaction.** msg1 is 1,233 bytes before either end has authenticated, so the KEM raises what a stranger holds for `unverifiedTimeoutMs`; `MAX_HANDSHAKE_FRAME_BYTES` bounds it at 8 KiB times the unverified budget. `MAX_QUEUE_BYTES` bounds queued application frames, not the handshake. The contact-secret seal covers the KEM public key and is checked before the responder encapsulates, so unauthenticated junk does not reach the expensive transform. On a UDP path msg1 exceeds one 1,200-byte packet, which costs nothing: QUIC carries its handshake data across packets.

## 12.6.1 Records and link teardown

- Every post-handshake frame is a ChaCha20-Poly1305-IETF record with no associated data: the initiator seals with `k_i2r` and opens with `k_r2i`, the responder mirrors. There is one post-handshake frame type.
- The nonce is an implicit per-direction `(epoch, counter)`, never sent: the 12 bytes `epoch u32 ‖ 0x00000000 ‖ counter u32`, both starting at 0. It is strictly enforced on receive, and the receiving counter advances only on a record that opens; a bad tag or out-of-order counter tears the link down. After `rekeyAfterFrames` records a direction ratchets, `k ← H(k ‖ LABEL_rekey)`, advancing the epoch and restarting the counter at 0; reaching `REJECT_AFTER_EPOCHS` retires the link (§16.1).
- Only `close()` emits the authenticated end-of-stream record, a record with an empty plaintext (its 16-byte tag alone), modelled on Secret Handshake's box-stream goodbye; an application frame is never empty, so the two cannot be confused. Every failure path is silent. The record goes out behind what was handed to the link before the close, so a frame sent and a peer forgotten right after still arrives; a failure drops what was waiting.
- **Close reasons** (`REASON_*` in `ake.js`), the answer to the host's `linkClosed`, severity 1 but for `clean` and `local` at 0:

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

- A graceful `link/close` asks the socket to flush its queued bytes before closing, bounded on TCP by `TCP_LINGER_MS` (`services/net-limits.ts`).
- Records assume an ordered whole-message pipe, which a framer, or a seam that frames for itself, supplies.

## 12.6.2 Half-open budgets

- **No asymmetric cryptography before proof.** An accepting link generates its X25519 and ML-KEM keypairs only once a msg1 opens.
- **Three budgets**: `maxHalfOpenUnverified` (1024) until msg1 opens, `maxHalfOpenVerified` (256) until the identity is proved, `maxAuthedLinks` (256) for the link's life. Separate tiers mean a flood without the contact secret cannot crowd out callers that have it.
- **Every tier evicts; none refuses the newest.** The half-open tiers shed their oldest occupant; the authed tier sheds its quietest, since a record crossing a link re-books it at the tail.
- **A proved msg1 is spent.** The initiator's ephemeral key is remembered (4,096, drop-oldest) and a second sighting draws silence before promotion or asymmetric work. Only proved msg1s are remembered.
- **`maxHalfOpenPerSource` (8)** spans all three tiers and is not evictable: a source at its limit is refused rather than pushing another source out. A source is an IPv4 address or an IPv6 /64, since one machine is routinely given a whole /64.
- **Three deadlines**: `unverifiedTimeoutMs` until msg1 opens, `handshakeTimeoutMs` for the rest, `linkIdleTimeoutMs` after. An authenticated link carrying no traffic either way is retired with the authenticated goodbye, and the address book redials on the next send.

**Why evict rather than refuse.** Refusing arrivals at a full budget would let a flood block peers before they could send their proof. The oldest unverified connection is overwhelmingly likely to be a stranger making no progress, while a legitimate caller occupies the budget for one round trip, so an attacker must cycle the whole budget faster than a round trip rather than fill it once. The same holds one tier up. Past the door every link has proved the same thing, so that budget evicts the link quiet longest; order of arrival there would say only who has been useful longest.

Measured behaviour: `tests/transport-load.test.mjs`.

## Requests

- **A request inherits the initiating deadline.** The `send` op carries no time field; the app's remaining handoff deadline crosses the `_net` call, covers the pre-auth pool and socket backlog, and stays attached to a deferred answer. The transport's own turn runs on its own ceiling, so an app out of time loses its request, never the link.
- **`requestTimeoutMs`** (10 s default, `0` disables) retires the transport's own pending correlation; it cannot extend the inherited deadline.
- **Known outcomes fail at once**: a request no link can take (no address, a dial that opened nothing or died as the last way to its peer) fails immediately; a claimant's answer too big for one record, or none by the delivery's deadline, comes back empty.
- **The request window.** A request handed to `link/deliver` holds one of the transport realm's host calls and its bytes until answered. The transport admits decoded requests only inside that budget (`HOST`) less room for one maximum-size record open and its plaintext, weighing each as its bytes plus the budget's bytes per call. A peer with nothing waiting may use any room left; a peer already waiting leaves one maximum-size request's room for others and stops at an equal share among waiting peers. A request past that is answered empty at once.

The window bounds what one peer holds, not what it costs: an admitted request still runs to its deadline, and CPU across peers stays unscheduled. It exists because every record open, seal and teardown draws on the same host-call budget, where a refusal takes a link down. Transport content cannot extend an owner's time because bytes happen to be moving, which is why the backlog `link/send` answers only paces and why `requestTimeoutMs` only retires the transport's own bookkeeping. Policy values must be finite: an absent bound does not fail the comparison that applies it, it makes that comparison always false.

## 12.6.3 The contact secret, the network key, and the peer list

| | Scope | Secret? | Effect |
| --- | --- | --- | --- |
| **Contact secret** | per node | yes | A caller that cannot produce the receiver's secret draws no response. Distributed with the node's address. Unset, the node uses its key's own (below); opened (32 zero bytes), it answers anyone. Mixed at msg1 with the initiator's ephemeral and into every later key. |
| **Network key** | per deployment | **no, public** | Seeds the transcript root, so every key and signature preimage differs between networks and a cross-network handshake fails at msg1. Isolation, not access control. |
| **`admitPeers`** | per node | n/a | Optional peer list, applied as a lint to signature-verified identities only: at msg3 when accepting, closing the link, and at msg2 when dialing. It controls admission, not concealment: to stay invisible to scanners, set a contact secret. Empty by default in the signed `APP`; overridable in `LOCAL`. |

The transport enforces all three; a malicious transport can bypass the lint or fabricate attribution (§14). Revocation is key rotation: rotate a contact secret to drop a peer, a network key to split a network.

**Gated by default; open is public.** A node given no contact secret uses its key's own: a hash of its signature over a fixed tag (`keySecret` in `ake.js`). Only the key's holder can compute it, it lasts as long as the key, and nothing is stored, so a node's address, `pk.secret@dest`, survives a restart; `contact` answers it, and the CLI prints it. A relay derives its own the same way, so its URL is `ws://<key>.<secret>@host`. A node or relay that nobody gave its address to is unreachable: a stranger's msg1 costs it one hash and one failed open, and draws the silence any refusal draws. Opening one (`contactSecret: "open"`, a relay's `--open`) is choosing to be in public, and everything the secret denied comes back for anyone who can reach it: probing which node is at an address, the asymmetric work of a handshake for any msg1, which many sources can turn into a connection storm, and, on a relay, asking whether a key is there (Limits). A key-derived secret changes only with the key, so rotating one means setting it explicitly.

**More secrets than one.** The contact secret gates callers the node has no other reason to answer. The host-only `secrets` op names others a msg1 may open under, and which those are is the app's to say: a room's, which everyone who knows the room holds, so room-mates reach each other without exchanging contact secrets. Each is tried in turn on every accept, direct or relayed, and the first that opens is the link's secret from then on, mixed into every later key as the contact secret is. Nothing about a caller selects one: a relay names a splice's caller, and that name is only the accept's source for the per-source cap, so what a relay says reads nothing off the node. A direct path's data link runs with no secret (Direct paths), and takes the one key it was signaled for at msg3.

**Why three values and not one.** They answer different questions and so fail differently when they leak. "May I reach you" is per relationship and must be secret; "are we the same network" is per deployment and need not be; "are you on the list" is local policy that cannot be decided until an identity is proven. Collapsing any two gives one value the worst properties of both.

- **The contact secret is per node.** Per deployment, one leak would force re-keying the whole fleet. Per pair cannot work, for the reason Noise prefers `psk1` over `psk0` when the initiator's static is transmitted: the responder cannot select a pairwise secret before it knows who is calling, and at msg1 it does not. Per node is both selectable at msg1 and containable: rotate, re-issue your address to your own peers, nothing else moves. It is mixed at msg1 with the initiator's ephemeral, Noise's PSK validity rule, so it is randomized before it encrypts anything. A *published* key would be weaker on both counts Noise names (it gates nothing an address holder lacks, and can be trial-checked against candidates), hence Noise §14's rule that pre-shared authentication uses a PSK, not a public key. **It is not what conceals identities from an observer**: a passive observer learns as little from an open node. What it adds is that a stranger costs no asymmetric cryptography, active probing draws silence, and msg2's signature reaches only parties whose address already names the key.
- **The network key is public, and separate.** Contact secrets are per relationship and say nothing about which network a node belongs to, so a staging and a production fleet sharing operators and configs need a value whose only job is to make crossing the boundary fail loudly, as Secret Handshake's network key does. An attacker who learns it can address the network, which every member already can. **Treat it as public; do not treat it as access control.** It is a Noise **prologue** rather than another KDF input, so every signature preimage differs too and a signature harvested on one network is not even a well-formed candidate on another. The host applies only the constant `DOMAIN_link_scope`; network separation trusts the transport (§14).
- **The peer list runs after verification.** A filter on an unproven key that refuses visibly is a membership oracle: name any key, watch whether the response differs, and read the list (on a social graph, the graph) off a node without holding a private key. Seeing only verified identities, it may refuse by closing: the answer is only ever "would you talk to *me*". It is a lint rather than a gate, since a host checking a key a malicious occupant supplies cannot establish attribution, and a convenience for membership without re-keying, not a revocation mechanism.

## Configuration

- The transport reads `networkKey` and `contactSecret` from `LOCAL` as 64 lowercase hex, and `contactSecret` also as `"open"`, and rejects malformed values at load. `networkKey` defaults to 32 zero bytes, the public network; `contactSecret` to the key's own (§12.6.3).
- Every other key resolves as `LOCAL.x ?? APP.x`; a numeric one that is not a non-negative finite number fails the load, so a transport bundle without `guest.config` is refused. `bootShell({ services: { transport: { config } } })` passes operator overrides as that load's `localConfig`. The keys and their signed defaults are listed in `scripts/transport-config.mjs`.
- Its identity comes from `HOST.identity`, never from config.
- Peers arrive in `transport.config.peers` as `pk[.secret]@dest` strings (this transport's own grammar, `peerRef` in `core.js`, refused at load when malformed) and through `addr` calls. A `dest` of `relay+ws[s]://<key>[.<secret>]@host:port` reaches the peer through that relay: its key, which the relay link is pinned to, and its contact secret for a private one.
- The host-only `contact` op answers the contact secret in force, empty when the node is open; given one blob first (32 bytes, or empty to open the node), it moves the accept gate without reinstalling. Links already up keep their secret; `TransportHost.reset()` closes them if required. A dial presents the **peer's** secret, the one in the address book, and none for a peer taught without one.
- The host-only `relay` op (one text: `ws[s]://<key>[.<secret>]@host:port` with no path, empty to leave; then optionally a second, the relay's contact secret in hex, so it need not travel in the URL) registers on that relay and answers `[u8]` once registered, once that attempt has failed, or at `ready`'s cap: 0 none, 1 registered, 2 redialing. `relayState` answers the same byte at any time. Every peer connection asks the relay its peer is linked through for STUN, then `iceServers` (`RTCConfiguration.iceServers` as JSON, `LOCAL ?? APP`, empty by default), such as a TURN server.
- The host-only `addr` op (`[key 32][secret][dest utf8]`, each a blob) teaches one peer: its key, its contact secret (32 bytes; empty or all zeros for none) and where it is reached, `relay+ws[s]://<key>.<secret>@host:port` for a peer behind that relay. Teaching a key again replaces its entry.
- The host-only `ready` op (`[timeout u32]`, ms) dials every taught peer and answers empty once all are linked or the timeout passes, capped short of `HOST.deadlineMs`.
- The host-only `dial` op (`[key blob][timeout u32]`, the key 32 bytes) dials one taught peer and answers `[1]` once it is linked, or `[0]` as soon as no dial to it is left or the timeout passes. A host that keeps a peer linked redials with it, rather than by sending something.
- The host-only `ice` op (one blob: a 32-byte key) answers the `iceServers` JSON this node uses toward that peer: STUN at the relay it is linked through, else at the home relay, then the configured ones. A host's own peer connections, a call's media, take it so they ask what the transport asks.
- The host-only `routes` op answers the linked peers, as `peers` does, with how each is reached: `[key 32][direct u8]` apiece, 1 while a direct link carries the peer's traffic and 0 while a relay forwards it.
- **Status.** Each time either changes, the transport says `[0][relay u8][key 32][direct u8]*`, the `relayState` byte then the `routes` entries, through `link/status`, so a host follows its relay and its links without polling. `[1]` and bytes after it is what the home relay told the node (`tell`).
- The host-only `tell` op (one blob) hands those bytes to the home relay, unread, and answers `[1]` once they are on the wire, `[0]` with no registered home relay. It carries what a relay offers beside calls, which is the host's and the relay's: seedrelay's rooms.
- The host-only `secrets` op (one blob: `[secret 32]*`, the whole list each time, empty for none, at most 16) names the secrets a msg1 may open under beside the contact secret (§12.6.3). Links already up are not affected.
- The host-only `forget` op (one blob: a 32-byte key) drops that peer's address and closes every link to it, dialing or up, with the authenticated goodbye.
- **Replaced**, the transport's session keys and address book go with it. The host passes the replacement the same `LOCAL`, so the embedder re-supplies the network key (omission selects the public network) and peers, in the replacement's `transport.config.peers` or afterwards by `addr`.

## Relays

A node that cannot be dialed (a browser, or anything behind NAT) is reached through a relay, and moves to a direct link when one can be made. The relay's server is seedrelay.

- **The relay link.** The `relay` op opens one link to the relay at `<origin>/v1/` (through `WsNetwork` in a browser, or a raw socket and the bundle's own RFC 6455 framing elsewhere) and runs the channel handshake on it, the node the initiator and the relay the responder, pinned to the relay's key from its URL and presenting the contact secret the URL carries. It is on the public network's root whatever the node's network key, so one relay serves every network, outside `admitPeers`, and ratchets after a fixed `RELAY_REKEY_AFTER_FRAMES`, since the relay cannot know a node's own setting. A private relay (seedrelay's `--secret`) is one with a contact secret, which the node presents at msg1 like any dial's. The home relay's link never idles out; one the node only calls through is left once nothing has crossed it for `linkIdleTimeoutMs`. A relay that drops is redialed after a wait that starts at two seconds and doubles with each drop in a row up to a minute, drawn from its upper half. Every relay path starts with the wire version (`RELAY_WIRE`), so a relay speaking another refuses the socket instead of misreading it.
- **Registration is the handshake.** msg3 proves the node's key, and the relay routes calls for that key to the link that proved it last, saying so in a record (`registered`). Nothing else registers a key, so a link that cannot finish the handshake draws no calls.
- **Peers.** A peer whose address is `relay+<relay>` is called through that relay. Which peers those are is the app's to say, through `addr`. A peer's address need not carry the home relay's secret: a call takes the link already up.
- **Splices.** A call names the callee's key and a fresh 16-byte ticket on the caller's relay link. The relay passes the callee a ticket of its own, on the callee's relay link only; for a key it cannot reach it refuses the caller's splice socket, which fails the dial at once. A node takes calls only on its home relay's link, once registered there. A call through a relay that is not the node's own registers there first. Each end opens `<origin>/v1/?splice=<ticket hex>` with its ticket, the caller only once its call is on the wire, and the relay joins the two sockets. The caller's end dials as the handshake's initiator, pinned to the key it called; the callee's is an accept under the half-open budgets, with the caller's key, as the relay names it, for its source; a caller at the per-source cap gets no socket. `admitPeers` waits for msg3, as on any accept. The handshake and records run end to end, and the callee's secrets gate the call as they gate any accept (§12.6.3).
- **The relay wire**, `[type u8][body]` in the relay link's records: from the relay `0x01` registered, `0x05` incoming `[from 32][ticket 16]`, `0x06` unreachable `[to 32][ticket 16]`, which the node does not read, and `0x08` tell `[bytes]`; from the node `0x05` call `[to 32][ticket 16]` and `0x08` tell `[bytes]`. A tell is the host's and the relay's (`tell`, Configuration), and only the home relay's reaches the host.

**A relay is a peer.** The node holds a channel link to it like any other, so nothing on the path names a key: registration, calls and tells all travel in records, under the same hybrid secrets, and a relay URL names the key the link is pinned to, as a peer's address does. Nobody on the path can write to the link either, so only the relay itself can name a caller (Limits). The handshake already proves who is at each end, so registration needs no signature of its own, and a private relay's secret is a contact secret: it gates msg1, and nothing on the wire can be tested against it.

**A relay joins two sockets and nothing more.** The handshake already proves who is at the other end of a splice, so a relay needs to know only which two sockets belong together. One socket per peer pair makes the relay's backpressure TCP's, so one slow peer cannot stall another's link, and records are encrypted once, end to end. Multiplexing peers over the relay link would need a window per peer inside the transport, and a relay that could read or drop single records would break the record layer's strict nonce order.

**Tickets decide who can open a splice.** Each end opens its splice with its own ticket, and the callee's came only on its own relay link, so only the two parties to a call can open its ends. That refusal is also how a caller learns its callee is not there, so the transport reads no separate notice.

**What a splice carries is the relay's to meter.** Keys cost nothing to make, so one party holding two keys can call itself and use the splice as a free pipe. seedrelay limits what splices carry per client address and charges both sockets to the caller; the two tickets are how it tells the ends apart.

**Rooms and peers are the app's.** Discovery belongs to the app: a room on a relay is one way, an address book another. The transport takes a peer as a `relay+` address, and passes what a relay says beside calls through `tell` unread, so a new way of meeting peers needs no transport release. A relay vouches only that a key registered, so a call through it goes through the same handshake and contact secret as any dial.

## Direct paths

The offering side opens the first path kind it has: UDP when its host lends it a socket (`link/udpBind`), WebRTC when its host routes `rtc:` (§12.7), and on a decline, the next. A UDP offer travels as `u`; answers, candidates and declines use the WebRTC tags. Bounds, deadlines and the binding of the data link are the same for both.

- **Signaling.** The smaller key offers, over the authenticated link as control frames `[KIND_CTL][tag u8][sid 8][UTF-8 text]` with the negotiation link's `o`, `a` and `c` tags, and `x` when the answering side has no path of the kind offered. A negotiation's signals all travel on the peer's first link, so a candidate never passes its description on another. `sid` is the offering side's name for one negotiation, so a signal for one an end has dropped or replaced is ignored. Each side learns its public address from STUN at the relay the pair is linked through (`stun:<relay host>:3478` and `:3479`, seedrelay's `--stun`), which already sees that address, so no third party learns it.
- **Binding.** The offering side's data link is the initiator, pinned to the peer; the answering side's is an accept that takes that peer and no other. Both run with no contact secret.
- **Routing.** A peer's direct links carry its traffic whenever it has one; relayed links carry it otherwise. The double-connect tie-break compares a link only with links of its own kind.
- **The relay window.** A relay may meter its splices, and what a node hands one waits there, past recall, even once a direct link replaces it. So a peer reached only through relays has at most `maxFrameBytes` of requests awaiting an answer, though one request may fill an empty window alone. The rest wait unsealed in the transport, and each answer, failure or timeout frees room for the next. When a direct link authenticates, everything waiting goes out on it at once. Requests that want no answer and answers themselves pass ungated. A waiting request's `requestTimeoutMs` runs from the send.
- **Retiring the splice.** The end that accepted the direct link authenticates it last, so the peer already routes over it. That end stops writing its relayed links, keeps reading them, and asks the peer (`CTL_RETIRE`) to close them, which the peer does behind the last record it sent on them, as a double connect's loser is closed by its dialer. Both ends must stop writing before either closes, or a record still crossing the relay is lost.
- **Bounds.** `maxRtcNegotiating` caps negotiations without an authenticated link; `rtcConnectTimeoutMs` drops one whose data link has not opened, and the handshake deadlines start when it does. A declined or failed upgrade leaves the relayed link in place, and the next relayed link to authenticate offers again.
- **A lost path is redialed, not restarted.** An ICE restart's offer would have to cross the link whose path was lost, and keeping the splice open for it would hold a relay socket for every direct pair. A connection that fails closes its links, and the next send dials through the relay again.

**Identity is proven in-channel.** The handshake runs inside the data link, which is continuous channel binding, stronger than a one-shot SDP `a=fingerprint` (RFC 8827 §5.6.4). A party that tampered with signaling could bring DTLS up to itself but could not produce the transcript signature, so the link would never authenticate. Signaling travels inside the authenticated channel, so no relay sees SDP or candidates and none can offer in a peer's name, and DTLS is a second, redundant encryption layer. Nobody but the signaled peer can reach a WebRTC data link, so it needs no contact secret; a UDP path's handshake is the link's own, so whoever sees its first packets can cut it then (Limits), but not get past it. The answering side still takes that peer's key and no other, or a peer could bring a second key past a contact secret it never held.

### UDP paths

The transport runs UDP paths itself (`transport/src/udp.js`, `quic.js`) over the datagram sockets the host lends (§12.7). A negotiation is given the `stun:` servers an `rtc:` negotiation would be, and speaks the negotiation link's messages with other contents. A UDP path is WebRTC less what a browser requires: off the browser, WebRTC costs a whole ICE, DTLS and SCTP stack for what a node with sockets can do itself. Punching is the small part; the path is a QUIC connection (ngtcp2, in the bundle's `quic.wasm`), whose handshake is the link's own in TLS's place, so every packet past it is sealed under keys only the two authenticated ends hold.

- **The description** is the end's token, 8 random bytes in hex. Every probe to that end carries it, and one without it is dropped.
- **A candidate** is an IPv4 `host:port` or an IPv6 `[host]:port`, the address in RFC 5952's form: one per address of the machine, IPv6 but for link-local, then the address each STUN server reports to a Binding request, which is asked over IPv4. Two answers that differ mean the end's NAT gives each destination its own port (endpoint-dependent mapping, a symmetric NAT), and it adds `host:*` for each address they named. Of the machine's addresses the transport takes the outward IPv4 ones, or loopback on a machine with none, then IPv6 but for loopback and link-local.
- **Punching.** Once an end has the peer's token and a candidate, it probes every candidate every 50 ms, up to 16 of them, since the peer names them. A probe carries both tokens and a random challenge, and is answered to wherever it came from; the first answer that echoes the challenge is the offering end's path, and it dials the connection from the socket the answer came to. The answering end takes as its path the socket the first QUIC packet reaches it on, from an address whose probe it has seen, and takes the connection from that address alone. A probe that leaves through a NAT opens it for the peer's probes back, so two ends behind NATs that keep one public port per socket meet. A probe's source is a candidate too, and its sender's token stands in for a description still on its way. QUIC packets have the fixed bit (0x40) set and probes have it clear, so one byte tells them apart.
- **IPv6.** A socket is dual-stack where the machine has IPv6. An IPv6 address is mostly routed end to end with no NAT, behind a firewall that lets in only replies to what went out (RFC 6092), which the plain punch opens as it opens a NAT that keeps one port. So two ends with IPv6 meet over it whatever NATs their IPv4 is behind, two strict ones among them; the first answer is the path, of either family.
- **Hard NATs.** A NAT that gives each destination its own port, against one that lets in only addresses it has sent to, defeats the plain punch: the hard end's probe leaves from a port the peer cannot know. So once the plain punch has had 1 s, the two ends play the birthday paradox. The hard end, one that sent `host:*` facing one that did not, opens 256 more sockets and probes every candidate of the peer from each, so its NAT opens 256 ports toward the peer. The easy end, one whose two STUN answers agreed facing a `host:*`, probes random ports above 1023 at that address, 64 every 50 ms and 4,096 in all across the peer's `host:*` addresses, since the peer names them. A probe that lands on one of the 256 ports passes, since the hard end's socket sent to exactly that address, and is answered from it; the first answer is the path, from whichever socket it reached, and the other sockets close. With 256 of 64,512 ports open, 99 runs in 100 land within 1,160 probes. Two hard ends cannot meet this way and stay relayed.
- **The handshake.** The link's three messages cross in QUIC's CRYPTO frames. Messages 1 and 2 go in Initial packets under fixed keys, since they conceal themselves (§12.6). Once message 2 has crossed, both ends derive Handshake keys from the handshake's shared secrets, and message 3 and each end's QUIC transport parameters go under them; the client's parameters also go in its first Initial, as TLS's ClientHello carries them, and count only once the same bytes come again under the Handshake keys. The 1-RTT keys are the link's session keys, and go in when the handshake completes; ngtcp2 updates them every 2^24 packets, each a hash of the last. The link's records then go in the clear on the connection: one AEAD a packet (ChaCha20-Poly1305 with ChaCha20 header protection, RFC 9001 §5.4.4), not one a record as well. The dialing end is the QUIC client.
- **The data link** is a QUIC connection with one stream each way, each end opening its own, carrying the link's records. QUIC supplies loss recovery (RFC 9002), congestion control and flow control. The congestion control is BBR, unpaced, rather than ngtcp2's default CUBIC: one path carries what TCP spreads over several connections, and one CUBIC flow gives up far more rate at each loss than several do together. Flow control: each stream and the connection have a 4 MiB window, renewed as the link reads, which it does at most 256 KiB at a time. What was written and not yet taken by the connection is capped at 16 MiB, past which a write fails the link, as the host fails a socket whose backlog passes its cap. The connection takes at most 256 KiB not yet sent, and holds what it sent until it is acked, in 64 KiB pieces freed as the acks come, so an idle path holds none. A turn hands the connection everything a `datagrams` event brought, in one call. Something goes out after 5 s of silence, which keeps NAT mappings open, and 30 s with nothing heard closes the path. A graceful close waits up to 10 s for what was written to be acked. The path goes as soon as it closes, so its close is sent three times, since nothing acks it.
- **A path that moves.** A packet from a new address is QUIC connection migration: the end validates the address with a PATH_CHALLENGE, sealed like every other packet, before it sends there. Ends that both move at once, or an end that sends nothing to show where it went, fall back on the 30 s silence and a new path through the relay.
- **Packet size.** A path starts at QUIC's 1200-byte floor, which every path is taken to carry, and probes for 1452 bytes (Ethernet's 1500 less IPv6 and UDP headers) as RFC 8899 does. Every cost of the connection is per packet, so 1452 bytes is about 17% fewer of them.
- **In the transport's realm.** The punch and the connection run where the handshake does, so what a stranger sends is parsed confined, never in the host. `quic.wasm` is a pure module (§4): it touches no socket and keeps no clock, and each call hands it the realm's time, the datagrams and what the link wrote, and answers what the link reads, the handshake messages, the datagrams to send and when to call again. Timers are due times the realm's one wake walks (§12.3). A turn's datagrams go out as one `link/udpSend`. The connection is the data link's channel: the link's handshake and records go into it rather than to `link/send`, and what arrives goes to the link with no host link between. A local link has an id of its own, past any the host gives, and its close reason is not printed. Tokens, challenges and the connection's randomness are host entropy (`crypto/random`).

---

## Prior art

This design space is well mapped. **Consult it before changing the handshake**, in particular Noise §7.8, the identity-hiding table, which grades exactly the property this document is about.

| Mechanism here | What it already is |
| --- | --- |
| Contact secret gating msg1 | WireGuard's per-peer preshared key; Noise `psk` modes |
| The msg1 seal as a "you must know me" gate | WireGuard's `mac1`, keyed on a secret rather than a public key |
| Network key seeding the transcript | Secret Handshake's network key, applied as a Noise prologue |
| Identity deferred past `ee` | Noise's deferred patterns; avoids `IK`'s documented limitation |
| Transcript-signature authentication | SIGMA |
| Master seed with a derived, labelled signing key | libsodium `crypto_kdf` |
| Evict-oldest half-open budgets | the accept-queue policy of loaded TCP servers |

**Identity-hiding grades.** Noise scores each side's static key 0–9:

| | Initiator | Responder |
| --- | --- | --- |
| **Open** (`"open"`, no contact secret) | **8**: *"encrypted with forward secrecy to an authenticated party"* | not transmitted; an anonymous initiator can check candidates against msg2's signature |
| **With a contact secret** | **8** | not transmitted; the signature reaches only secret holders, whose address already names the key |

A contact-secret holder is not an authenticated party in Noise's sense: every peer given the address shares it and can answer msg1 as the node, but none can produce msg2's signature, which is why the initiator's grade does not depend on the secret. The open responder falls between Noise's **1** and **3**: a passive observer learns nothing, but an active anonymous initiator draws a signature it can test candidate keys against, the `XK` weakness reached by probing. For comparison, `XX` grades the initiator **8** and transmits the responder's static (**1**); `XK` grades the responder **3**, with candidates checkable and replays linkable, a replay property msg1 shares (Limits).

**Why not Noise itself.** In order of weight: Noise authenticates with static DH and this with signatures, which the spec leaves to a future extension (libp2p's workaround is `XX` with a per-node X25519 static signed by the Ed25519 identity, a second key per node); the pinned dial is pre-knowledge of a *signing* key, and Noise's pre-message patterns pre-share a DH key, so the nearest fit, `XX`, transmits the static the caller already holds; and hybrid key establishment is not standard Noise (only the draft HFS extension or PQNoise, with few implementations to test against). None of this reaches the host: the crypto names carry what a Noise transport needs (§12.1), so choosing Noise later is a bundle update. What signatures cost: a transcript signature is transferable, so each end finishes holding proof, showable to a third party, that the two spoke, where Noise's DH authentication leaves none. Taken from Noise regardless: the identity-hiding vocabulary, the prologue construction, the PSK validity rule and `psk1`-over-`psk0` reasoning, the 256-bit PSK entropy requirement, and the rule that pre-shared knowledge authenticates as a shared secret, not a public key.

**Why not Secret Handshake.** SHS gets three things right: the responder's identity is never transmitted, the client's is sealed so only the real server can open it, and box-stream has an authenticated goodbye. Its network key is adopted outright. It is not adopted wholesale because it needs the identity key in a DH role (Ed25519 converted to Curve25519), and has no suite byte for the ML-KEM fields.

## Limits

**The IP layer still identifies nodes.** A stable `host:port` is identified to anyone who maps it once.

**A relay sees who calls whom.** The relay forwards only ciphertext and cannot pose as either end, but it learns which pairs talk, when and how much, until the pair moves to a direct link. A deployment that must hide that runs its own relay.

**Open is public.** Nodes and relays are gated by default (§12.6.3). Opening one is choosing to be in public, and these come with it, for anyone who can reach it:

- **Probing.** msg2's signature lets an anonymous caller test candidate keys, so whoever can reach the address learns which node is there (Identity-hiding grades).
- **Connection storms.** A valid msg1 costs a caller one hash and one seal (the ephemeral can be random bytes and the KEM key reused), and the node answers it with an X25519 exchange, an encapsulation and a signature, holding a verified slot until `handshakeTimeoutMs`. The per-source cap and the evicting budgets bound what one source holds, not what many cost, and such a flood also turns the spent set over, so an old msg1 recording answers again.
- **Presence on a relay.** Any registered client can call a key, and the relay refuses the splice at once when that key is not registered, so it answers whether a key is online there. On an open relay that is anyone; on a gated one, only the holders of its secret.

A room's secret is derived from its name, so a room with a guessable name is open in the same way, to whoever guesses it.

**Whoever sees a link's packets can cut it.** A TCP or WebSocket link's packets are the OS's, so anyone who sees them can forge a reset, a close, an ack or bytes the record layer refuses, and the link closes, as any TLS connection does; the address book redials. Nothing reads or forges a record this way. A UDP path is open to this only while its handshake runs, in the Initial packets under fixed keys; every packet after is sealed, so a forged one is dropped, as a WebRTC data channel drops one.

**A recorded msg1 can be replayed once.** A replay draws a msg2 nobody can open without the ephemeral private key, but the answer says the holder of that contact secret is at the address replayed to, so a recording tracks the node across address changes. The spent set (§12.6.2) makes a recording worth one answer rather than one per copy, but it is bounded and per-realm: a restart, or 4,096 further proved handshakes, makes an old recording good for one more. Closing it needs freshness in msg1 (a challenge costing a round trip, a clock like WireGuard's timestamp, or a seen-set that survives restarts), and none is taken: this is the replay linkability Noise grades `XK` down for.

**The protocol is fingerprintable.** A cleartext `0x03` at offset 0 says "seedkernel": the protocol, not the peer. Hiding it would cost the self-describing format and the migration path of §14.1; a first message indistinguishable from random belongs in its own suite.

**A WebSocket listener answers as one.** It writes the HTTP upgrade before any msg1, so a prober learns a WebSocket server is there, though not whose. The silence starts behind that answer.

**Impersonation after key compromise.** Seizing a node's master seed lets an attacker be that node, for good: nothing revokes it (§14). Only the deferred identity limits the *retroactive* damage.

## Invariants worth a named test

1. An accepting node transmits nothing of the channel before opening the caller's msg1.
2. A wrong contact secret, a malformed message, an over-cap frame and silence are mutually indistinguishable.
3. Neither identity appears in cleartext anywhere on the wire, a relay link's included.
4. msg1 contains no identity, so a recording plus a later key seizure reveals none.
5. The receiver's key never goes on the wire, and the caller's goes only to a receiver that proved the dialed key.
6. Neither the contact secret nor the network key goes on the wire.
7. Honest transports on different network keys never link.
8. Subkey derivation is deterministic: a node rebuilds its identity from the seed alone.
9. Only `close()` emits the end-of-stream record; every failure path is silent (§12.6.1).
10. A graceful close asks the transport to flush (§12.6.1).
11. An unproven connection costs zero asymmetric operations.
12. A member authenticates under a sustained flood, credentialled or not.
13. A proved msg1 is spent: a replay draws the same silence a wrong secret draws.
14. A full authed budget sheds the quietest link, never one carrying traffic.
15. The channel Ed25519 key is never an argument to `crypto_scalarmult`: the invariant most likely to be lost to a convenient refactor.
16. A node given no contact secret answers only callers holding its key's own, which the same key derives again.

1–14 and 16 are covered by `tests/transport-link.test.mjs` and `tests/transport-load.test.mjs`, which pin them against the shipped transport bundle through the real host stack, over an instrumented in-process channel. 15 is a check of the signed guest source in `tests/transport-bundle.test.mjs`: every X25519 runs on an ephemeral scalar, none takes an identity key, and only the one helper reaches the host's DH.

**Where 5 lives, and why it is easy to lose.** The receiver's half is structural: msg2 has no field for its key. The caller's half is one check in `onMsg2`: the signature is verified against `dialedPeerId` before msg3 is built, and a dial pinned to the node's own key is refused there too. Moving that check after the `wire(w3)` call, or verifying against a key the message itself supplies, loses the invariant silently: every honest handshake still succeeds. The self-dial and impostor tests pin it.
