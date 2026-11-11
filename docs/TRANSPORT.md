# seedkernel: transport

*The shipped transport's wire: framing, the handshake, records, requests, relays and direct paths, each with its reason. For anyone talking to a node from outside this codebase.*

> **Part of the [seedkernel](../README.md) spec.** Section numbers are global across the doc set, so a `(§X.Y)` reference points to whichever file holds that section:
>
> [README](../README.md) §1, §10 · [ARCHITECTURE](ARCHITECTURE.md) §2, §3, §5, §12, §12.6.2b, §16.1 · [BUNDLE](BUNDLE.md) §3.1, §4, §12.4, §12.5, §16 · [GUEST](GUEST.md) §12.2, §12.3 · **TRANSPORT §12.6.1, §12.6.2, §12.6.3** · [SECURITY](SECURITY.md) §13, §14 · [CLIENT](CLIENT.md) §12.8
>
> This file is meant to be enough on its own to implement a peer. Everything here is the shipped transport bundle (`transport/src/*.js`), not the host: a deployment can replace it with a signed bundle update, and why that is possible is ARCHITECTURE §12.6. Multi-byte integers are big-endian.

---

## Overview

A node is known by its Ed25519 public key, its **peer id**, and reached at an address such as `pk.secret@host:port`. A link between two nodes is any ordered byte pipe: TCP, WebSocket, a WebRTC data channel, a QUIC stream, or a splice through a relay. On every one of them the same three-message handshake runs, authenticates both ends and derives session keys, and every frame after it is a ChaCha20-Poly1305 record. Inside the records, a node sends requests named by a protocol id and gets responses back.

The handshake is built so that **an observer who can open sockets to a node and watch traffic cannot tell which identities are present on the network, nor which pairs are talking**. It denies three attacks:

- **Probe**: connect to a host and learn which node lives there. Denied by the contact secret every node has unless opened (§12.6.3).
- **Attribute**: watch a flow and learn which pair it belongs to. Denied because the caller's identity travels only under ephemeral hybrid secrets and the receiver's never travels, on relayed links too.
- **Membership test**: ask a node "would you talk to key P?". Denied because the peer list sees only verified identities, and every refusal before that is silent.

It does not hide a node at a stable `host:port` from anyone with an address book and a packet capture, and the cleartext suite byte says the traffic is seedkernel. Limits has the full list.

A node nobody can dial (a browser, anything behind NAT) registers at a **relay**, which joins two sockets so the handshake runs end to end through it. Two nodes on a relayed link then try a **direct path**, WebRTC in a browser or a UDP path elsewhere, signaled inside their authenticated channel.

The file follows a link's life: Framing, Handshake, records (§12.6.1), half-open budgets (§12.6.2), Requests, secrets and the peer list (§12.6.3), Relays, Direct paths, then Constants, Limits, Prior art and the Local interface an app on the node uses.

---

## Framing

- **TCP**: each message is `[len u32][bytes]`.
- **WebSocket**: RFC 6455 on the same TCP socket, one message per WebSocket message. A listener labelled `ws` speaks it; any other TCP listener speaks length framing.
- **WebRTC data channel**: a byte stream under the same `[len u32]` prefix, whatever the platform's message size.
- **QUIC**: one stream each way (Direct paths).

The cap is checked against the declared length before the body is buffered: `MAX_HANDSHAKE_FRAME_BYTES` (8 KiB) until the handshake has authenticated the peer, `maxFrameBytes` after. An over-cap frame is a refusal (Refusals are silent).

The pre-authentication cap exists because the application cap would be a memory hole: the full cap on an unauthenticated peer would let a stranger reserve megabytes per connection, while 8 KiB times the unverified budget is 8 MiB, with room above both post-quantum message widths. The cap rises only after the authenticating step has run, so a full-size first record arriving in the same segment is not measured against the small cap.

## Handshake

Three messages, then records. A message is a bare body with no type byte, accepted only at its exact width.

```
msg1  i→r   [suite 1][eph_i 32][kem_pk_i 1184][seal(k_probe; ∅) 16]       1,233 B  contact proof, no identity
msg2  r→i   [eph_r 32][kem_ct 1088][seal(k2; sig_r 64) 80]                1,200 B  hybrid reply, signed, no identity
msg3  i→r   [seal(k3; id_i 32 ‖ sig_i 64) 112]                              112 B  the caller names itself
then        [AEAD record ..]
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

Sign(m) = Ed25519(DOMAIN_link_scope ‖ m)
seal    = ChaCha20-Poly1305-IETF, nonce zero, no associated data; each key seals one message
```

The labels, `DOMAIN_channel` and `DOMAIN_link_scope` are in Constants. `contact` is the receiver's contact secret, or 32 zero bytes for an open node (§12.6.3).

- **Keys.** `eph` is a fresh X25519 key per connection on each side, and `kem_pk_i` a fresh ML-KEM-768 key; the responder encapsulates, the initiator decapsulates. No long-term Diffie-Hellman or KEM key exists. An all-zero X25519 result (a low-order point) or a KEM input the implementation refuses is a refusal like a seal that does not open.
- **Suite `0x03`** is the only suite: Ed25519 identity, ephemeral X25519 and ML-KEM-768, contact secret, ChaCha20-Poly1305 records. There is no list, fallback or negotiation, and an unknown id draws silence. The suite byte is folded into `h1`, so both signatures cover it.
- **A dial pins its peer, and the receiver's key never travels.** The initiator checks `sig_r` against the key it dialed; `id_r` is in the signed message but not on the wire. A signature under any other key, the initiator's own included, closes the link before the initiator names itself.
- **Ordering.** A responder sends nothing until a msg1 opens under its contact secret or one of its other secrets (§12.6.3). The responder proves itself at msg2; the initiator names itself at msg3, only to a responder it has verified. The initiator authenticates the responder at 1 RTT and may send records right behind msg3; the responder authenticates the initiator at 1.5 RTT.
- **Refusals.** A responder refuses a wrong contact secret, wrong network, malformed message or bad msg3 by doing nothing until its deadline. An initiator the responder's peer list declines at msg3 is closed at once. An initiator closes on a bad msg2 (wrong signature, its own key, a peer it declines).
- **Double connect.** When two nodes dial each other, both keep the link the smaller peer id dialed. Only the loser's dialer closes it: a dialer may already have sent records behind msg3, so the accepting end stops routing to the losing link but reads it until the dialer's end-of-stream record.
- **Cost.** Each end makes one Ed25519 signature, one verification and one X25519 exchange; the initiator also generates an ML-KEM-768 keypair and decapsulates, and the responder encapsulates.

### Identities travel under the hybrid ephemeral secrets

Neither identity appears in cleartext. The initiator's is sealed under keys derived from `ee` and the ML-KEM secret; the responder's is never sent, since every initiator dialed it. Both secrets are erased once session keys exist, so a node seized years later yields nothing from a recording. At msg1 the only key in existence is long-term, so anything sealed there would be sealed under a key that lives for years: Noise names this for its `IK` pattern, and WireGuard documents it as a known limitation (a responder's private key plus a traffic log reveals who sent every recorded handshake). Deferring identity until both ephemeral secrets exist makes concealment forward-secret and hybrid for both ends.

So the handshake uses no long-term Diffie-Hellman key at all. The Ed25519 identity key stays signing-only, with no Ed25519-to-Curve25519 conversion, and an address carries no DH or KEM key, so the address format does not depend on the suite.

### The receiver proves itself first

Every dial is pinned, so msg2 carries a signature and no key, and the initiator checks it before building msg3. Every peer the node gave its address to holds the contact secret and could answer msg1 as the node, but none can produce that signature, so an impostor draws msg1 and nothing more. This is SIGMA-I's order with the responder's identity left off the wire.

Someone has to go first. Assigning it to the receiver costs little: with a contact secret, only secret holders reach msg2, and the secret travels in an address that already names the key. What msg2 gives away is a signature an anonymous caller can check against candidate keys, and only an open node gives it to one.

The peer list runs at msg3, on the initiator's verified identity. A declined initiator is closed rather than stalled: it already verified the responder at msg2, so silence would conceal nothing and only leave it sending into a dead link.

### Refusals are silent

Every refusal before an identity is verified lets the deadline expire, so an unauthorised caller cannot tell the node from any server that waits for its client to speak first. It can still tell it from a closed port, and the fixed deadline is itself observable. Framing refuses the same way: almost any four random bytes declare more than the cap, and closing on sight would identify the node. Closing on a bad message answers a question ("I am a seedkernel node and that is not the key"), which is exactly the oracle this removes. In code this looks like missing error handling, and the likeliest way to lose it is someone tidying up error paths.

The cost is that a refused connection holds a socket until its deadline, which makes the half-open budgets (§12.6.2) what stands between a stranger and the node.

### Hybrid key establishment

Session keys derive from both the X25519 and the KEM secret, so the classical half still protects them if the post-quantum half turns out to be flawed while it is young. The responder encapsulates where it already generates its ephemeral, so the hybrid costs no round trip.

Where the KEM secret enters is the part that is quiet when wrong. The key schedule takes a list of shared secrets; the KEM secret is appended, never XOR-ed into `ee` and never substituted for it. msg2's seal key is the first key both ends have after encapsulation, and it already derives from `[ee, pq]`; msg3 and both session directions inherit the pair. The transcript chains complete messages, binding the KEM key and ciphertext, and the bytes a node sends are exactly the bytes it folds into the transcript.

msg1 is 1,233 bytes before either end has authenticated, so the KEM raises what a stranger holds while unverified; the pre-authentication cap bounds it. The contact-secret seal covers the KEM public key and is checked before the responder encapsulates, so unauthenticated junk never reaches the expensive step.

## 12.6.1 Records and link teardown

- **Every frame after the handshake is a record**: ChaCha20-Poly1305-IETF with no associated data. The initiator seals with `k_i2r` and opens with `k_r2i`; the responder mirrors.
- **The nonce is implicit**, per direction, never sent: `epoch u32 ‖ 0x00000000 ‖ counter u32`, both starting at 0. The receiving counter advances only on a record that opens; a bad tag or an out-of-order record tears the link down.
- **Rekey.** After `rekeyAfterFrames` records a direction ratchets, `k ← H(k ‖ LABEL_rekey)`, advances the epoch and restarts the counter. Both ends must use the same value, since the nonce is implicit. Reaching `REJECT_AFTER_EPOCHS` retires the link rather than repeat a nonce.
- **End of stream** is a record with an empty plaintext, its 16-byte tag alone, sent only by a deliberate close and behind everything sent before it. An application frame is never empty, so the two cannot be confused. Every failure closes silently.

Records assume an ordered, whole-message pipe, which every framing above supplies. An authenticated goodbye lets the other end tell a close from a cut (Limits).

## 12.6.2 Half-open budgets

A node bounds connections that have not authenticated, and every bound is local policy whose defaults live in `scripts/transport-config.mjs`. What a peer can observe:

- **No asymmetric cryptography before proof.** A responder generates its X25519 and ML-KEM keys only once a msg1 opens.
- **Three tiers**: unverified (until msg1 opens), verified (until msg3 proves an identity) and authenticated. Separate tiers mean a flood without the contact secret cannot crowd out callers that have it.
- **Every tier evicts; none refuses the newest.** The half-open tiers shed their oldest; the authenticated tier sheds the link quiet longest. Refusing at a full budget would let a flood block peers before they could send their proof, while the oldest unverified connection is overwhelmingly a stranger making no progress, so an attacker has to cycle the whole budget faster than a round trip rather than fill it once.
- **A per-source cap spans all tiers and is not evictable**, so one source cannot push another out. A source is an IPv4 address or an IPv6 /64, since one machine is routinely given a whole /64.
- **A proved msg1 is spent.** Its ephemeral key is remembered (a bounded, drop-oldest set) and a second sighting draws silence.
- **Three deadlines**: one for msg1 to open, one for the rest of the handshake, and an idle timeout after which an authenticated link with no traffic either way is closed with the end-of-stream record.

## Requests

Inside records, a frame's first byte is its kind:

```
request   [0x00 | noReply 0x80][corr u32][protoLen u8][proto][payload ..]
response  [0x01][corr u32][payload ..]
control   [0x02][tag u8][body ..]
```

- **A request names a protocol id**, never an app; the receiver routes it to whichever app claims that id (ARCHITECTURE §12.10) and attributes it to the authenticated sender. `corr` is the sender's correlation number. With `noReply` the receiver still delivers the request but sends no response, and `corr` is 0.
- **A response** goes back on the link the request came in on, and is accepted only from the peer the request went to.
- **An empty response is an answer**: no app claims the protocol, the app failed, the answer would not fit one frame, or the receiver had no room for the request. So a response is at least five bytes, and "nobody here serves that" stays distinct from an unreachable peer, which is no response at all.
- **Control frames** are the transport's own messages and never reach an app: tag `0x00` asks the peer to close the relayed links a direct link replaced (Direct paths), and the letter tags are direct-path signals.

A receiver bounds what one peer's requests may hold while they wait for an answer, sharing room equally among waiting peers, and answers a request past that bound empty at once. That bounds memory, not cost: an admitted request runs to its deadline, and CPU across peers is not scheduled.

## 12.6.3 The contact secret, the network key, and the peer list

Three values, each answering a different question, and so failing differently when they leak:

- **The contact secret** (per node, secret): "may I reach you". An initiator that cannot produce it draws no response. It is distributed in the node's address and mixed at msg1 with the initiator's ephemeral and into every later key. Opened (32 zero bytes), the node answers anyone.
- **The network key** (per deployment, public): "are we the same network". It seeds `root`, so every key and signature preimage differs between networks and a cross-network handshake fails at msg1. Isolation, not access control.
- **The peer list** (per node, local): "are you on the list". Applied only to verified identities: at msg3 when accepting, closing the link, and at msg2 when dialing.

Revocation is rotation: rotate a contact secret to drop a peer, a network key to split a network. Collapsing any two of the three gives one value the worst properties of both.

**Gated by default; open is public.** A node given no contact secret derives one from its key: a hash of its signature over a fixed tag, so only the key's holder can compute it, it lasts as long as the key, and nothing is stored. A node that nobody gave its address to is unreachable: a stranger's msg1 costs one hash and one failed open, and draws silence. Opening a node is choosing to be in public, and everything the secret denied comes back for anyone who can reach it (Limits).

**The contact secret is per node.** Per deployment, one leak would force re-keying the whole fleet. Per pair cannot work, for the reason Noise prefers `psk1` over `psk0` when the initiator's static key is transmitted: the responder cannot select a pairwise secret before it knows who is calling, and at msg1 it does not. Per node is selectable at msg1 and containable: rotate it and re-issue the address to your own peers. Mixing it with the initiator's ephemeral is Noise's PSK validity rule. A published key would be weaker on both counts Noise names, hence Noise's rule that pre-shared authentication uses a secret, not a public key. The contact secret is not what conceals identities from a passive observer, who learns as little from an open node; what it adds is that a stranger costs no asymmetric cryptography, probing draws silence, and msg2's signature reaches only parties whose address already names the key.

**More secrets than one.** Beside the contact secret, a node may accept a msg1 under other secrets an app names, such as a room's, which everyone who knows the room holds, so room-mates reach each other without exchanging contact secrets. Each is tried in turn on every accept, and the first that opens is that link's `contact` from then on. Nothing the initiator sends selects one, so trying them reveals nothing.

**The network key is public, and separate.** Contact secrets say nothing about which network a node belongs to, so a staging and a production fleet sharing operators and configs need a value whose only job is to make crossing the boundary fail loudly, as Secret Handshake's network key does. It is a Noise prologue rather than another KDF input, so a signature harvested on one network is not even a well-formed candidate on another. Treat it as public.

**The peer list runs after verification.** A filter on an unproven key that refuses visibly is a membership oracle: name a key, watch whether the response differs, and read the list off the node without holding a private key. Seeing only verified identities, it may close the link, because the only question it answers is "would you talk to me".

### Addresses

```
pk[.secret]@[scheme://]host:port[/path]
pk[.secret]@relay+ws[s]://relayKey[.relaySecret]@host:port
pk[.secret]@quic://ip:port
```

`pk` is the peer id and `secret` its contact secret, each 64 lowercase hex; no secret means none. `tcp://` (the default for a bare `host:port`) is length-framed TCP, `ws://` and `wss://` are WebSocket, and a path reaches a peer behind a reverse proxy. A `relay+` destination reaches the peer through that relay, named by the key its link is pinned to and, for a private relay, its contact secret. `quic://` dials a QUIC listener directly, by IP address. No long-term DH or KEM key is ever published.

## Relays

A relay is a peer. A node opens one link to it at `<origin>/v1/` over WebSocket and runs the channel handshake on it, as initiator, pinned to the relay key from its URL and presenting the relay's contact secret if it has one. The relay link always uses the public network key (32 zero bytes) and a fixed `rekeyAfterFrames` of 2²⁴, whatever the node's own settings, so one relay serves every network and needs to know nothing about a node's configuration. The `/v1/` path names the relay wire version, so a relay speaking another refuses the socket rather than misread it.

**Registration is the handshake.** msg3 proves the node's key, and the relay routes calls for that key to the link that proved it last, saying so with a `registered` message. Nothing else registers a key.

**The relay wire** is `[type u8][body]` inside the relay link's records:

| Type | Direction | Body | Meaning |
| --- | --- | --- | --- |
| `0x01` | relay → node | (empty) | registered |
| `0x05` | node → relay | `[to 32][ticket 16]` | call: the node wants a splice to `to` |
| `0x05` | relay → node | `[from 32][ticket 16]` | incoming: `from` is calling; open a splice with this ticket |
| `0x06` | relay → node | `[to 32][ticket 16]` | unreachable (a node may ignore it) |
| `0x08` | both | `[bytes ..]` | tell: opaque bytes between the node's host and the relay, such as seedrelay's rooms |

**Splices.** A caller picks a fresh 16-byte ticket and sends a call. The relay sends the callee an incoming message with a ticket of its own, on the callee's relay link only. Each end then opens `<origin>/v1/?splice=<ticket hex>`, the caller only once its call is on the wire, and the relay joins the two sockets. The caller's end runs the handshake as initiator, pinned to the key it called; the callee's end is an ordinary accept under its own contact secret and budgets, with the caller's key as its source. For a key it cannot reach, the relay refuses the caller's splice socket, which is how the caller learns the callee is absent. A node takes calls only on its home relay's link, once registered.

- **Nothing on the path names a key.** Registration, calls and tells travel in records under the same hybrid secrets, so nobody on the path can write to the link, and only the relay itself can name a caller.
- **A relay joins two sockets and nothing more.** The handshake already proves who is at the other end, so the relay needs to know only which two sockets belong together. One socket per pair makes the relay's backpressure TCP's, so one slow peer cannot stall another, and records are encrypted once, end to end. Multiplexing over the relay link would need a window per peer, and a relay that could drop single records would break the strict nonce order.
- **Tickets decide who can open a splice.** The callee's ticket came only on its own relay link, so only the two parties to a call can open its ends.
- **What a splice carries is the relay's to meter.** Keys cost nothing, so one party with two keys could use a splice as a free pipe; the relay charges both sockets to the caller, telling the ends apart by their tickets.
- **Discovery is the app's.** A relay vouches only that a key registered, so a call through it runs the same handshake and contact secret as any dial.

## Direct paths

Two peers on a relayed link try to replace it with a direct one. The smaller peer id offers, using the first path kind it has: a UDP path when it has datagram sockets, WebRTC when it is in a browser, and the next kind on a decline.

**Signaling** travels as control frames over the peer's first authenticated link:

```
[0x02][tag u8][sid 32][UTF-8 text]
```

- `o`: a WebRTC offer, its SDP.
- `u`: a UDP offer, the offering end's token.
- `a`: the answer to either, SDP or the answering end's token.
- `c`: a candidate.
- `x`: decline; the answering end has no path of the kind offered.

`sid` is 32 random bytes naming one negotiation, so a signal for one an end has dropped is ignored. All of a negotiation's signals go on one link, so a candidate never overtakes its description. Each side learns its public address from STUN at the relay the pair is linked through (`stun:<relay host>:3478` and `:3479`), which already sees that address, so no third party learns it.

**Binding.** The data link runs the same handshake with `sid` as its contact secret: the offering end as initiator, pinned to the peer, and the answering end accepting that peer's key and no other. Only the two ends ever saw `sid`, since it crossed only in records.

**Switching over.** A peer's direct links carry its traffic whenever it has one. The end that accepted the direct link, which authenticates last, stops writing its relayed links, keeps reading them, and sends control tag `0x00` asking the peer to close them, which the peer does behind the last record it sent there. Both ends must stop writing before either closes, or a record still crossing the relay is lost. A failed or declined upgrade leaves the relayed link in place. A direct path that fails is not restarted: its links close and the next send dials through the relay again.

**Identity is proven in-channel.** The handshake runs inside the data link, which binds identity continuously rather than once, as an SDP fingerprint does (RFC 8827 §5.6.4). A party that tampered with signaling could bring DTLS up to itself but could not produce the transcript signature. Signaling travels inside the authenticated channel, so no relay sees SDP or candidates, and none can offer in a peer's name.

### UDP paths

A UDP path is WebRTC less what a browser requires: punching, then a QUIC connection whose handshake is the channel handshake in TLS's place, so every packet past it is sealed under keys only the two authenticated ends hold.

- **Token and candidates.** A UDP description is the end's token, 8 random bytes in hex. A candidate is `host:port`, IPv6 as `[host]:port` in RFC 5952 form: one per machine address (not link-local), then each STUN-reported address. When two STUN answers differ, the end's NAT maps per destination, and it also sends `host:*` for each address they named.
- **Probes.** QUIC packets have bit `0x40` of byte 0 set; probes have it clear:

  ```
  PROBE      [0x30][receiver's token 8][sender's token 8][challenge 8]
  PROBE_ACK  [0x31][receiver's token 8][the probe's challenge 8]
  ```

  Once an end has the peer's token and a candidate, it probes every candidate (at most 16) every 50 ms and acks every probe to wherever it came from. A probe without the receiver's token is dropped. The offering end takes as its path the first ack that echoes its challenge and dials QUIC from that socket; the answering end takes the socket the first QUIC packet reaches, from an address whose probe it has seen. A probe's source counts as a candidate, so ends behind NATs that keep one public port per socket meet.
- **Hard NATs.** If the plain punch has not succeeded after 1 s and exactly one end sent `host:*`, that end opens 256 more sockets and probes from each, while the other end probes random ports above 1023 at the `host:*` addresses, 64 every 50 ms and 4,096 in all. With 256 of 64,512 ports open, 99 runs in 100 land within 1,160 probes. Two such ends stay relayed.

The punch and the connection run in the transport's own realm, where the handshake already parses a stranger's bytes, never in the host.

### The QUIC connection

A UDP path is QUIC version 1 (RFC 9000) with the channel handshake in TLS's place. The dialing end is the client. Everything QUIC leaves to TLS is defined here; everything else (packets, frames, loss recovery per RFC 9002, migration with PATH_CHALLENGE, connection IDs, stateless reset) is standard.

**Keys.** Each encryption level has one 32-byte secret per direction. From a secret `s`:

```
K(s, label)  = BLAKE2b-256 keyed with s, over the ASCII label (no NUL)
packet key   = K(s, "seedkernel-quic-key-v1")
iv           = first 12 bytes of K(s, "seedkernel-quic-iv-v1")
hp key       = K(s, "seedkernel-quic-hp-v1")
```

Packets are protected as RFC 9001 §5.3 and §5.4.4 describe for `TLS_CHACHA20_POLY1305_SHA256`: ChaCha20-Poly1305 with the nonce `iv XOR packet number`, and ChaCha20 header protection whose counter is the sample's first four bytes, little-endian, and whose nonce is the other twelve. The secrets per level:

| Level | Client → server secret | Server → client secret |
| --- | --- | --- |
| Initial | `K(0³², "seedkernel-quic-initial-client-v1")` | `K(0³², "seedkernel-quic-initial-server-v1")` |
| Handshake | `KDF(ee ‖ pq ‖ contact, h2, LABEL_hs_i2r)` | `KDF(ee ‖ pq ‖ contact, h2, LABEL_hs_r2i)` |
| 1-RTT | `k_i2r` | `k_r2i` |

`0³²` is 32 zero bytes, `KDF`, `h2`, `k_i2r` and `k_r2i` are the handshake's (Handshake), and the Handshake labels are in Constants. Initial keys are fixed, not derived from the connection ID, and stay the same after a Retry: msg1 and msg2 conceal themselves, so the Initial level needs only integrity against damage. A 1-RTT key update (RFC 9001 §6) ratchets each secret to `K(s, "seedkernel-quic-update-v1")` and keeps the header-protection key. An end updates after 2²⁴ packets.

**CRYPTO data** at each level is a run of `[kind u8][len u16][body]`, where kind 1 is a channel handshake message and kind 2 is this end's QUIC transport parameters (RFC 9000 §18 encoding). Any other kind, or CRYPTO data at the 1-RTT level, fails the connection.

| Level | Client sends | Server sends |
| --- | --- | --- |
| Initial | its transport parameters, msg1 | msg2 |
| Handshake | msg3, its transport parameters | its transport parameters |

The client's parameters cross at Initial too, as a TLS ClientHello carries them, because the server needs them before its first Handshake packet. They count only once the same bytes arrive again under the Handshake keys; the server fails the connection if the two differ. The server's parameters cross only under Handshake keys, so they authenticate its Retry source connection ID (RFC 9000 §7.3) against a forged Retry.

**Completion.** An end installs the 1-RTT keys once it has both the session keys and the peer's Handshake-level parameters, whichever comes last, and only then reads 1-RTT packets.

**Streams.** Each end opens one unidirectional stream (`initial_max_streams_bidi` 0, `initial_max_streams_uni` 1) and writes the link's frames on it as `[len u32][frame]`, unsealed: every packet is already one AEAD under keys only the two authenticated ends hold, so a record layer above it would be a second, redundant one. The end-of-stream record of §12.6.1 is an empty frame, `[0 u32]`, followed by the stream's FIN.

**Transport parameters a peer should match**: `max_idle_timeout` 30 s, the stream and connection windows 4 MiB, no greasing of the fixed bit (RFC 9287), since the fixed bit is how a UDP socket tells QUIC packets from probes. An end sends a keep-alive after 5 s of silence, which holds NAT mappings open. A path starts at 1200-byte packets and probes up to 1452 (RFC 8899).

### QUIC listeners

A node can be dialed over QUIC directly at `quic://ip:port`, with no relay and no punch, as a TCP listener is dialed. The destination is an IP address, since a client takes its connection only from the address it dials. Past the first packets the connection is a UDP path's.

- **Retry.** An Initial addressed to no connection and carrying no token is answered with a stateless Retry. Only an Initial that echoes the Retry's token, from the address the Retry went to, opens a connection. So a spoofed source costs the listener one answer smaller than what it sent and no state, and every connection's address is validated from its first packet. A forged Retry fails the handshake, since the server's transport parameters name the Retry's source connection ID under the Handshake keys. The cost is one round trip per dial.
- **Retry integrity.** The Retry integrity tag is RFC 9001 §5.8's, over the same pseudo-packet with the same version 1 nonce, but sealed with ChaCha20-Poly1305 under the fixed key `K(0³², "seedkernel-quic-retry-v1")`. Like RFC 9001's fixed key, it proves only that the Retry was not damaged. The token's contents and the Retry's source connection ID are the listener's own; a client only echoes them, as RFC 9000 §8.1 has it. The shipped listener makes the token `[odcid len u8][odcid][issued f64]`, good for 10 s, and the source connection ID a 16-byte keyed hash of the token and the client's address under a key drawn at start, so the ID is the token's MAC and the listener keeps no state.
- **Accepting.** A connection's link is an accept like a TCP one: open to whoever holds the contact secret, since msg1 crosses in the first Initial, and counted against the half-open budgets and the per-source cap.

---

## Constants

The values a peer must match.

| Constant | Value | Notes |
| --- | --- | --- |
| `DOMAIN_link_scope` | `"seedkernel-link-scope-v1\0"` | prefixes every handshake signature; the host's, repeated here from ARCHITECTURE §16.1 |
| Channel suite | `0x03` | byte 0 of msg1; the only one accepted |
| Message widths | msg1 1,233 B, msg2 1,200 B, msg3 112 B | each accepted only at its exact width |
| `DOMAIN_channel` | `"seedkernel-channel-id-v1\0"` | seeds `root` and prefixes both signatures' messages; a format tag inside `DOMAIN_link_scope`, never transmitted |
| `LABEL_probe` | `"seedkernel-c-probe-v1\0"` | |
| `LABEL_msg2` | `"seedkernel-c-msg2-v1\0"` | |
| `LABEL_msg3` | `"seedkernel-c-msg3-v1\0"` | |
| `LABEL_i2r` | `"seedkernel-session-i->r-v1\0"` | |
| `LABEL_r2i` | `"seedkernel-session-r->i-v1\0"` | |
| `LABEL_rekey` | `"seedkernel-session-rekey-v1\0"` | |
| `LABEL_hs_i2r` | `"seedkernel-channel-handshake-i->r-v1\0"` | QUIC Handshake secret, client to server |
| `LABEL_hs_r2i` | `"seedkernel-channel-handshake-r->i-v1\0"` | QUIC Handshake secret, server to client |
| QUIC labels | `seedkernel-quic-{key,iv,hp,update,retry}-v1`, `seedkernel-quic-initial-{client,server}-v1` | ASCII, no NUL, keyed-BLAKE2b labels (The QUIC connection) |
| QUIC version | `0x00000001` | connection IDs are 16 bytes |
| Contact secret | 32 bytes | never on the wire; 32 zero bytes means open |
| Network key | 32 bytes | public; 32 zero bytes is the public network |
| `MAX_HANDSHAKE_FRAME_BYTES` | 8192 | inbound frame cap before authentication |
| `MAX_FRAME_BYTES` | 2097152 (2 MiB) | default `maxFrameBytes`, the cap after authentication and so the largest message; a deployment may lower it |
| `rekeyAfterFrames` | 16777216 (2²⁴) | records per epoch; both ends must agree, so changing it on one node breaks its links to every peer on the default |
| `REJECT_AFTER_EPOCHS` | 65536 (2¹⁶) | epoch ceiling; reaching it retires the link |
| Frame kinds | `req 0x00`, `res 0x01`, `ctl 0x02`, `noReply 0x80` | Requests |
| Relay wire | path `/v1/`, types `0x01`, `0x05`, `0x06`, `0x08` | Relays |
| UDP probes | `0x30`, `0x31`, token 8, challenge 8 | UDP paths |

## Limits

**The IP layer still identifies nodes.** A stable `host:port` is identified to anyone who maps it once.

**A relay sees who calls whom.** It forwards only ciphertext and cannot pose as either end, but it learns which pairs talk, when and how much, until the pair moves to a direct link. A deployment that must hide that runs its own relay.

**Open is public.** Nodes and relays are gated by default (§12.6.3). An open one gives these to anyone who can reach it:

- **Probing.** msg2's signature lets an anonymous caller test candidate keys, so it learns which node is at the address.
- **Connection storms.** A valid msg1 costs a caller one hash and one seal, and the node answers with an X25519 exchange, an encapsulation and a signature, holding a verified slot until its deadline. The per-source cap and evicting budgets bound what one source holds, not what many cost, and a flood also turns over the spent set, so an old msg1 recording answers again.
- **Presence on a relay.** The relay refuses a splice at once for a key not registered, so any client that may call learns whether a key is online there.

A room's secret is derived from its name, so a room with a guessable name is open in the same way.

**Whoever sees a link's packets can cut it.** On TCP and WebSocket, anyone who sees the packets can forge a reset, or bytes the record layer refuses, and the link closes; nothing reads or forges a record this way. A UDP path is open to this only during its handshake, in the Initial packets; after that every packet is sealed.

**A recorded msg1 can be replayed once.** A replay draws a msg2 nobody can open without the ephemeral private key, but it shows that the holder of that contact secret is at the address replayed to, so a recording tracks a node across address changes. The spent set makes a recording worth one answer rather than one per copy, but it is bounded and does not survive a restart. Closing this needs freshness in msg1 (a challenge costing a round trip, a clock like WireGuard's timestamp, or a seen-set that survives restarts), and none is taken: this is the replay linkability Noise grades `XK` down for.

**The protocol is fingerprintable.** A cleartext `0x03` at offset 0 says "seedkernel": the protocol, not the peer. A first message indistinguishable from random belongs in a suite of its own.

**WebSocket and QUIC listeners answer as one.** A WebSocket listener writes the HTTP upgrade before any msg1, and a QUIC listener answers any Initial with a Retry, so a prober learns that such a server is there, though not whose. The channel's own silence starts behind that.

**Impersonation after key compromise.** Whoever holds a node's master seed is that node, for good: nothing revokes it (§14). Only the deferred identity limits the retroactive damage.

### Invariants

Each of these is pinned by a test against the shipped bundle (`tests/transport-link.test.mjs`, `tests/transport-load.test.mjs`, `tests/transport-bundle.test.mjs`), and a second implementation should hold them too:

1. A responder transmits nothing of the channel before opening the initiator's msg1.
2. A wrong contact secret, a malformed message, an over-cap frame and silence are indistinguishable.
3. Neither identity appears in cleartext anywhere on the wire, relay links included.
4. A recording plus a later key seizure reveals no identity.
5. The responder's key never goes on the wire, and the initiator's goes only to a responder that proved the dialed key. The initiator's half is one check: verify msg2 against the dialed key before building msg3. Moving it later, or verifying against a key from the message, loses this silently while every honest handshake still succeeds.
6. Neither the contact secret nor the network key goes on the wire.
7. Nodes on different network keys never link.
8. A node rebuilds its identity from its seed alone.
9. Only a deliberate close sends the end-of-stream record; every failure is silent.
10. An unproven connection costs no asymmetric operation.
11. A member authenticates under a sustained flood, with or without the contact secret.
12. A proved msg1 is spent: a replay draws the same silence as a wrong secret.
13. A full authenticated budget sheds the quietest link, never one carrying traffic.
14. The identity key is never used for Diffie-Hellman.
15. A node given no contact secret answers only callers holding its key-derived one.

---

## Prior art

This design space is well mapped. Consult it before changing the handshake, in particular Noise §7.8, the identity-hiding table, which grades exactly the property this file is about.

| Mechanism here | What it already is |
| --- | --- |
| Contact secret gating msg1 | WireGuard's per-peer preshared key; Noise `psk` modes |
| The msg1 seal as a "you must know me" gate | WireGuard's `mac1`, keyed on a secret rather than a public key |
| Network key seeding the transcript | Secret Handshake's network key, applied as a Noise prologue |
| Identity deferred past `ee` | Noise's deferred patterns; avoids `IK`'s documented limitation |
| Transcript-signature authentication | SIGMA |
| Master seed with a derived, labelled signing key | libsodium `crypto_kdf` |
| Evict-oldest half-open budgets | the accept-queue policy of loaded TCP servers |

**Identity hiding.** In Noise's 0 to 9 grades, the initiator scores 8 ("encrypted with forward secrecy to an authenticated party") whether or not the node has a contact secret, since a secret holder can answer msg1 but cannot produce msg2's signature. The responder's key is never transmitted. An open responder falls between Noise's 1 and 3: a passive observer learns nothing, but an active anonymous initiator draws a signature it can test candidate keys against, the `XK` weakness reached by probing. With a contact secret, that signature reaches only holders whose address already names the key.

**Why not Noise itself.** Noise authenticates with static Diffie-Hellman and this with signatures, which Noise leaves to a future extension; the pinned dial is prior knowledge of a signing key, and Noise's pre-message patterns pre-share a DH key, so the nearest fit, `XX`, transmits the static key the caller already holds; and hybrid key establishment is not standard Noise. Signatures do cost something: a transcript signature is transferable, so each end finishes holding proof, showable to a third party, that the two spoke, where Noise's DH authentication leaves none. Taken from Noise regardless: the identity-hiding vocabulary, the prologue construction, the PSK validity rule and the `psk1`-over-`psk0` reasoning, and the rule that pre-shared knowledge authenticates as a shared secret, not a public key. The host's crypto names carry what a Noise transport needs, so choosing Noise later is a bundle update.

**Why not Secret Handshake.** SHS gets three things right: the responder's identity is never transmitted, the client's is sealed so only the real server can open it, and its box-stream has an authenticated goodbye. Its network key is adopted outright. It is not adopted wholesale because it needs the identity key in a Diffie-Hellman role and has no suite byte for the ML-KEM fields.

---

## Local interface

Not wire: how an app and the embedder on the same node use the shipped transport. Apps reach it through the local service id it claims (`_net`), with calls framed `[opLen u8][op][args]` (`host/op-frame.ts`), where a `blob` is `[len u32][bytes]`.

- **`send`** `[noReply u8][to blob][proto blob][payload blob]`: a request to peer `to` (32 bytes) under protocol `proto` (at most 255 bytes), which must be one of the calling app's own `protocols` (ARCHITECTURE §12.10). Answers the response, or `[1]` at once for `noReply`. A request inherits the caller's deadline; `requestTimeoutMs` only retires the transport's own bookkeeping and cannot extend it.
- **`ready`**, **`dial`**, **`addr`**, **`forget`**, **`peers`**, **`routes`**: wait for the configured peers, dial one, teach or forget an address, list linked peers and how each is reached.
- **`relay`**, **`relayState`**, **`tell`**, **`ice`**: register on a home relay, read its state, pass bytes to it, and get the ICE servers to use toward a peer.
- **`contact`**, **`secrets`**: read or move the contact secret, and set the other secrets a msg1 may open under.

Configuration arrives in `LOCAL`, then the signed `APP`: `networkKey` and `contactSecret` (64 hex, or `"open"`), `peers` as addresses, and the policy numbers listed with their defaults in `scripts/transport-config.mjs`. The node's identity comes from `HOST.identity`, never from config.

**Status.** Each time its relay state or routes change, the transport reports through `link/status`: `[0][relay u8][key 32][direct u8]*`, where `relay` is 0 none, 1 registered, 2 redialing, then one entry per linked peer, `direct` 1 while a direct link carries its traffic. `[1][bytes ..]` is a `tell` from the home relay.

The exact op arguments and answers are in `transport/src/core.js`. CLIENT shows them in use.
