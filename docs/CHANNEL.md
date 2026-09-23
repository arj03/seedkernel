# seedkernel: the concealed-identity channel handshake (§12.6.2)

*What the handshake is, what each part is for, and where it sits in the literature.*

> Rationale companion to the normative text in [RUNTIME](RUNTIME.md) §12.6–§12.6.3,
> [PROTOCOL](PROTOCOL.md) §16.1 and [SECURITY](SECURITY.md) §14–§14.1. Those say what the
> protocol *is*; this says why it is shaped that way. The rest of the runtime's
> rationale is in [DESIGN](DESIGN.md).

---

## 1. What it provides

**An observer who can open sockets to a node and watch traffic cannot enumerate which
identities are present on the network, nor which pairs are talking.**

Three attacks are denied:

| Attack | Denied by |
| --- | --- |
| **Probe** — connect to a host, learn which node lives there | the contact secret (§6.1); an open node does not deny it (§8.1) |
| **Attribute** — watch a flow, learn which pair it belongs to | the caller's identity travelling under the hybrid ephemeral secrets, the receiver's not travelling at all (§3) |
| **Membership-test** — ask a node "would you talk to key P?" | a peer list that sees only verified identities (§6.3), and silent refusal before one (§5) |

Two things it does not provide, stated here rather than buried: a node at a stable
`host:port` is still identified to anyone holding an address book and a packet capture, and
the cleartext suite byte still identifies the traffic as seedkernel. Concealment defeats
probing and flow attribution; hiding the communication graph itself is mixnet work and a
different project. §9 has the full list.

---

## 2. Shape

Three messages. The initiator opens with an X25519 ephemeral, an ML-KEM-768 public key, and
a seal keyed by the receiver's contact secret; the receiver answers with its X25519
ephemeral, an ML-KEM ciphertext, and its signature over both, sealed under both shared
secrets. The caller checks that signature against the key it dialed, and only then names
itself.

```
msg1  i→r   X25519 ephemeral + KEM pk + contact proof       — no identity
msg2  r→i   X25519 ephemeral + KEM ct + sealed signature   — no identity
msg3  i→r   the caller names itself
```

Wire layout, exact widths, the key schedule and the constants are normative and live in
[RUNTIME](RUNTIME.md) §12.6. Everything below is why they are that way.

## 3. Identities travel under the hybrid ephemeral secrets

Neither identity public key appears in cleartext. The caller's is sealed under keys derived
from the ephemeral X25519 secret `ee` and the ephemeral ML-KEM secret; the receiver's is
never sent, since every caller dialed it, and its signature is sealed under the same keys.
Both secrets are erased once the session keys exist, so a node seized years later yields
nothing from a recording of one.

This is why the identity and signatures wait for the second and third messages. At
msg1 the only key in existence is long-term, so anything sealed there is sealed under a key
that lives for years — the property Noise names for its `IK` pattern and WireGuard
documents as a known limitation: compromising a responder's private key plus a traffic log
reveals who sent every recorded handshake. Deferring identity disclosure until both `ee`
and the ML-KEM secret exist makes concealment forward-secret and hybrid for both ends.

The handshake therefore uses **no long-term Diffie–Hellman key at all**. `ee` is ephemeral
on both sides; the contact secret and network key are KDF inputs. Two consequences worth
having: the Ed25519 identity key stays signing-only, as §12.6 requires, without the
Ed25519→Curve25519 conversion Secret Handshake needs; and a node address carries no DH key,
so the post-quantum `0x03` landing did not change the address format (§11).

---

## 4. The receiver proves itself first

The caller names itself only to the receiver it meant. Every dial is pinned: the caller
holds the receiver's key from the address it dialed, so msg2 carries a signature and no key,
and the caller checks it before building msg3. Every peer the node has given its address to
holds the contact secret and can answer msg1 as the node, but none can produce that
signature, so an impostor draws msg1 and nothing more. This is SIGMA-I's order with the
responder's identity left off the wire, and it grades the caller as `XX` does (§8.1).

Someone must go first; that is not solvable, only assignable. Assigning it to the receiver
costs the receiver little. With a contact secret, only secret holders reach msg2, and the
secret travels in an address that already names the key. What msg2 gives away is a
signature an anonymous caller can check against candidate keys, and an anonymous caller
reaches msg2 only on an open node. A node that must be invisible to scanners sets a contact
secret; that is what the secret is for (§6.1).

The peer lint (§6.3) runs at msg3, on the caller's verified identity. A caller it declines is
closed rather than stalled: it verified the receiver at msg2, so silence would conceal
nothing and only leave it sending into a link that never answers. What that caller sees is
its link come up at msg2 and close at once — the caller authenticates first, as a TLS 1.3
client does before the server has checked its certificate.

The caller's first records ride behind msg3, one round trip after msg1.

---

## 5. Refusals are silent

Every refusal before an identity is verified does nothing at all and lets the deadline
expire, so an unauthorised caller cannot tell this node from any server that waits
for its client to speak first. It can still tell it from a closed port, which refuses the
connection, and the fixed deadline that ends the silence is itself observable. The framing
layer refuses the same way: an over-cap length prefix or message is a refusal like any
other, because almost every four random bytes declare more than the cap, and closing on
sight would let them identify the node. Two refusals close instead, because neither has
anything left to hide: the caller's own at msg2 — a signature under a key it did not dial,
or one its peer lint declines — and the receiver's peer lint at msg3 (§4).

The alternative — closing on a bad message — answers a question. "I am a seedkernel node
and that is not the key" is exactly the oracle §1 removes, and it is available to anyone
who can open a socket. Silence is the only response that says nothing, so every refusal
path funnels to the same place. In the code this looks like missing error handling, which
is why it is commented as load-bearing: the likeliest way to lose this property is someone
tidying up error paths.

The cost is that a refused connection occupies a socket until its deadline instead of being
dropped on sight, which promotes the half-open budgets from defence in depth to the thing
standing between a stranger and the node. Four measures bound this exposure:

- **No asymmetric cryptography before proof.** The accepting side verifies the
  contact-secret proof before generating ephemeral keys or invoking the KEM.
- **A proved msg1 is spent** (§9), so a recording cannot buy that work, or an answer, more
  than once.
- **Separate budgets for proven and unproven callers**, so a flood without the contact
  secret cannot crowd out those that have it.
- **Evict rather than refuse the newest.** Refusing arrivals at a full budget would let a
  flood block peers before they could send their proof. The oldest unverified connection is
  overwhelmingly likely to be a stranger making no progress, while a legitimate caller
  occupies that budget for one round trip — so an attacker must cycle the whole budget
  faster than a round trip rather than merely fill it once. The same argument applies one
  tier up, which is why the verified budget evicts too. Past the door the question changes:
  every authenticated link has proved the same thing, so that budget evicts the link that
  has been quiet longest rather than the one admitted longest. Order of arrival there would
  say only who has been useful longest.

Constants and measured numbers: [RUNTIME](RUNTIME.md) §12.6.2 and
`tests/transport-load.test.mjs`.

## 6. Why three secrets and not one

A link is gated by a contact secret, a network key and an optional peer list. What each
*does* is tabulated in [RUNTIME](RUNTIME.md) §12.6.3; this is why they are three things
rather than one.

They differ in the question they answer, and therefore in what happens when they leak. "May
I reach you" is per relationship and must be secret. "Are we the same network" is per
deployment and need not be. "Are you on the list" is a local policy decision that cannot be
made until an identity is proven. Collapsing any two of them gives one value the worst
properties of both.

### 6.1 Why the contact secret is per node

Per *deployment* was the first attempt and it is wrong: one compromised node forces a
re-key of the entire fleet, so the blast radius of any single member's leak is the whole
network.

Per *pair* is tighter and unusable, for the reason the Noise spec gives when it prefers
`psk1` over `psk0` on patterns that transmit the initiator's static: a pairwise secret
cannot be selected by the responder until it knows who is calling, and at msg1 it does not.
The secret gating the first message can only be one the receiver identifies unaided.

Per node is the only granularity that is both selectable at msg1 and containable on leak:
rotate, re-issue your address to your own peers, nothing else in the network moves.

**It is not what conceals the identities from an observer.** §3 does that, and against a
passive observer an open node conceals just as well. Against an active prober it does not:
an open node answers anyone's msg1, and msg2's signature can be checked against a list of
candidate keys (§8.1). What the secret adds: a stranger costs no asymmetric cryptography;
active probing draws silence, so "a node speaks this protocol here" stops being observable;
and msg2's signature reaches only parties whose address already names the key. The caller's
identity does not depend on it: msg3 goes only to a receiver that proved the dialed key (§4).

**Why a secret rather than a published key.** Gating msg1 on a long-term public key is
WireGuard's `mac1` and Noise's `XK`, and it is weaker on both counts Noise names: the value
ships in the address, so it gates nothing an address holder lacks, and a public value can be
trial-checked against candidates. Noise §14 states the rule — if the parties want to
authenticate with a shared secret, it should be a PSK, not a public key.

Placement follows Noise's PSK validity rule: mixed at msg1 together with the initiator's
ephemeral, so a PSK-derived key is randomized by a self-chosen ephemeral before it encrypts
anything.

### 6.2 Why the network key is public, and separate

A per-node contact secret cannot express network membership: contact secrets are handed out
per relationship and say nothing about which network a node belongs to. So a staging fleet
and a production fleet sharing operators, configs and address formats need a second value —
one whose only job is to make crossing the boundary impossible, so that a stale address or a
copied config fails loudly rather than connecting to the wrong world. This is the job Secret
Handshake's network key does.

Because it is a boundary rather than a gate, disclosure costs little: an attacker who learns
it can address the network, which every member already can, and still draws nothing from any
node whose contact secret it lacks. **Treat it as public. Do not treat it as access
control** — that conflation is exactly what made the deployment-wide secret in §6.1 a bad
idea.

Applying it as a Noise **prologue** rather than as another KDF input is deliberate: seeding
the transcript root means every signature *preimage* differs too, so a signature harvested
on one network is not even a well-formed candidate on another, and a cross-network handshake
fails at the first message rather than somewhere later and more confusingly.

The host applies only the constant `DOMAIN_link_scope` prefix; the transport binds the
network through its signed root, so network separation trusts the transport (§14).

### 6.3 Why the peer list runs after verification

A filter on an unproven key that refuses visibly is a membership oracle: name any key, watch
whether the response differs, and read the list off a node without holding a single private
key. On a list that tracks a social graph, that is the graph. So the check sees only
identities whose signature has verified. It may then refuse by closing (§4): a caller that
reached it has signed as the key it names, so the answer is only ever "would you talk to
*me*", never "would you talk to P".

It controls admission, not concealment. A node whose key must stay unconfirmable to
scanners sets a contact secret; the list does not need one to do its own job.

It is optional and empty by default. Revocation is key rotation — a node dropping a peer
rotates its contact secret, a network splitting rotates its network key — so the list is a
convenience for expressing membership without re-keying, not a revocation mechanism.

The list is the transport's to enforce, so a malicious transport can bypass it (§14).

## 7. Why one identity key, and not a key per purpose

A node signs for two purposes with one key: the handshake, under `DOMAIN_link_scope`
(with the transport's own `DOMAIN_channel ‖ root ‖ transcript ‖ id` inside), and an app's
scoped records, under `DOMAIN_guest ‖ app`
([RUNTIME](RUNTIME.md) §12.6.2b). Deriving a second keypair for the second purpose is the
obvious hardening, and it is worth saying why it is not done.

The argument for it is real. Domain separation is a property of the **code**: it holds
provided the prefix is applied, on both the signing and the verifying side, on every path,
forever. Being wrong is silent — signatures still verify, just for more things than
intended — and a single omitted prefix on a signing path turns that signer into an oracle
for every other purpose sharing the key. That matters most where a signing oracle is
deliberate, and `node/sign` is exactly that: it signs guest-supplied bytes on request,
exposed to guest code. Key separation would be a property of the **keys**, and would
survive the refactor that loses a prefix.

What defeats it is what a signature is **for**. A signed record leaves the node. Every peer
that receives one knows its author only as a peer id — a channel public key, the thing the
handshake authenticated and `senderPk` carries. A record signed by a sibling key names an
author that appears in no peer's roster, so a cohort would have to gossip a signed
guest-pk↔channel-pk binding per peer to resolve one to the other: a new protocol element,
new state, and a new place for identity to disagree with itself.

That is a heavy price for a split no node can deploy. Both keys derive from one seed at
boot, inside one process, so a compromise that reaches either reaches both — and a node
handed only the channel key cannot serve `node/sign` at all, which is not an operating mode
any app has. The property being bought is narrower than it looks: not identity separation,
only resistance to one class of code bug.

So the purposes are kept apart the way every other pair of purposes here is. The host — not
the guest, and not the signing code — chooses the domain and scope from the slot the asking
bundle occupies, binds `domain ‖ scope ‖ msg`, and never parses `msg`. No op signs raw
bytes, and neither slot can reach the other's prefix. Sub-separating *within* a scope is the
occupant's own job, one level down: this program's `DOMAIN_channel` tag is exactly that, and
it is why the handshake's format can change in a bundle update. One key, one identity
namespace, the same meaning on every target.

The stored secret is still not the signing key: a node holds a 32-byte master seed and
derives from it under a closed, versioned label set (libsodium `crypto_kdf`'s shape), which
keeps the key file format independent of the key and leaves room for a purpose that is
genuinely node-local.

## 8. Prior art

This design space is well mapped, and the table below is the correspondence. **Consult it
before changing the handshake** — in particular Noise §7.8, the identity-hiding table, which
grades exactly the property this document is about.

| Mechanism here | What it already is |
| --- | --- |
| Contact secret gating msg1 | WireGuard's per-peer preshared key; Noise `psk` modes |
| The msg1 seal as a "you must know me" gate | WireGuard's `mac1`, keyed on a secret rather than a public key |
| Network key seeding the transcript | Secret Handshake's network key, applied as a Noise prologue |
| Identity deferred past `ee` | Noise's deferred patterns; avoids `IK`'s documented limitation |
| Transcript-signature authentication | SIGMA |
| Master seed with a derived, labelled signing key | libsodium `crypto_kdf` |
| Evict-oldest half-open budgets | the accept-queue policy of loaded TCP servers |

### 8.1 Identity-hiding grades

Noise scores each side's static key 0–9. This design places as:

| | Initiator | Responder |
| --- | --- | --- |
| **Open** (no contact secret) | **8** — *"encrypted with forward secrecy to an authenticated party"* | not transmitted; an anonymous initiator can check candidates against msg2's signature |
| **With a contact secret** | **8** | not transmitted; the signature reaches only secret holders, whose address already names the key |

A holder of the contact secret is not an authenticated party in Noise's sense: the secret
travels in the node's address, so it is shared by every peer the node has given that
address to, and any of them can answer msg1 as the node. None of them can produce msg2's
signature, which is why the initiator's grade does not depend on the secret.

The open responder falls between Noise's **1** and **3**. Its static is never transmitted, so
a passive observer learns nothing, but an active anonymous initiator draws a signature it can
test candidate keys against — the `XK` weakness, reached by probing rather than by
eavesdropping.

For comparison, the two nearest standard patterns: `XX` grades the initiator **8** and
transmits the responder's static in message 2 (**1**); `XK` grades the responder **3**, not
transmitted but with candidates checkable and replays linkable — a replay property msg1
shares (§9).

### 8.2 Why not Noise itself

Three reasons, in order of weight.

1. **Noise authenticates with static DH; this authenticates with signatures.** Signature
   authentication is a future extension in the Noise spec. The established workaround is
   libp2p's: `XX` with a per-node X25519 static, and the Ed25519 identity signing that
   static inside the handshake payload. `XX` statics travel in the handshake, so addresses
   would not change; the cost is a second key per node and a signature binding it to the
   identity.
2. **The pinned dial is pre-knowledge of a signing key.** Noise's pre-message patterns
   (`XK`, `NK`, `IK`) pre-share the responder's static as a DH key; with a signing
   identity the nearest fit is `XX`, which transmits the static the caller already holds.
3. **Hybrid key establishment is not standard Noise.** ML-KEM enters Noise only through the
   draft HFS extension (`e1`/`ekem1`) or PQNoise's KEM patterns, with few implementations to
   test against.

None of these reaches the host: the crypto names carry what a Noise transport needs, and a
published-vector test holds them there (RUNTIME §12.6), so choosing Noise later is a bundle
update.

**What signatures cost.** A transcript signature is transferable. Each end finishes holding
a signature by the other over a transcript that contains its own ephemeral, which it can
show a third party as proof that the two spoke. Noise's DH authentication leaves no such
proof, because either end could have produced the whole transcript alone. §1 hides which
pairs talk from observers; against a peer that later turns informant, signatures give that
fact away.

What is taken from Noise regardless: the identity-hiding vocabulary; the prologue
construction (§6.2); the PSK validity rule and the `psk1`-over-`psk0` reasoning that forces
the contact secret to be per-node (§6.1); the 256-bit PSK entropy requirement; and the rule
that a shared secret, not a public key, is how to authenticate with pre-shared knowledge.

### 8.3 Why not Secret Handshake

SHS gets three things right that a naive design does not: the responder's identity is never
transmitted, the client's is sealed so only the real server can open it, and box-stream has
an authenticated goodbye — which is where §12.6.1's end-of-stream record came from. Its
network key is adopted outright (§6.2).

Not adopted wholesale because it requires the identity key to take a DH role, converting
Ed25519 to Curve25519, which §12.6 rules out; and because it has no suite byte for the
ML-KEM fields in suite `0x03`. The suite byte identifies the field layout; the handshake
uses the same node address format and round-trip count described above.

---

## 9. Limits

**The IP layer still identifies nodes.** A stable `host:port` is identified to anyone who
maps it once. Concealment defeats probing and flow attribution, not an observer who already
knows where to look.

**A recorded msg1 can be replayed once.** Anyone who captures a valid msg1 can replay it and
draw a msg2. They cannot open it — no ephemeral private key — but the answer itself says
the holder of that contact secret is at the address replayed to, so a recording tracks the
node across address changes. A responder remembers the initiator's ephemeral key and stalls
every later copy before promotion or asymmetric work, so the recording is worth one answer
rather than one per copy sent. That memory is bounded and per-realm: a restart, or 4,096
further proved handshakes, makes an old recording good for one more. Closing it outright
needs freshness in msg1 — a challenge (a round trip), a clock (WireGuard's timestamp) or a
seen-set that survives restarts — and none is taken: this is the replay linkability Noise
grades `XK` down for (§8.1).

**The protocol is fingerprintable.** A cleartext `0x03` at offset 0 says "seedkernel". That
identifies the protocol, not the peer, and hiding it would cost the self-describing format
and the migration path of §14.1. First message indistinguishable from random is a separate
goal and belongs in its own suite.

**Impersonation after key compromise.** Seizing a node's master seed lets an attacker be
that node. Only §3's deferral limits the *retroactive* damage.

---

## 10. Invariants worth a named test

1. A node never transmits anything before opening the caller's msg1.
2. A wrong contact secret, a malformed message, an over-cap frame and silence are mutually
   indistinguishable.
3. Neither identity appears in cleartext anywhere on the wire.
4. msg1 contains no identity, so a recording plus a later key seizure reveals none.
5. The receiver's key never goes on the wire, and the caller's goes only to a receiver that
   proved the dialed key.
6. Neither the contact secret nor the network key appears on the wire.
7. Honest transports on different network keys never link.
8. Subkey derivation is deterministic: a node rebuilds its identity from the seed alone.
9. Only `close()` emits the end-of-stream record; every failure path is silent. *(§12.6.1)*
10. A graceful close asks the transport to flush. *(§12.6.1)*
11. An unproven connection costs zero asymmetric operations.
12. A member authenticates under a sustained flood, credentialled or not.
13. A proved msg1 is spent: a replay draws the same silence a wrong secret draws.
14. A full authed budget sheds the quietest link, never one carrying traffic.
15. The channel Ed25519 key is never an argument to `crypto_scalarmult`. Worth a grep test
    in CI — the invariant most likely to be lost to a convenient refactor.

All but 15 are covered by `tests/transport-link.test.mjs` and
`tests/transport-load.test.mjs`, which pin them against the shipped transport bundle —
through the real host stack, over an instrumented in-process channel — rather than against
a library object a test could hold.

**Where 5 lives, and why it is easy to lose.** The receiver's half is structural: msg2 has
no field for its key. The caller's half is one check in `onMsg2`: the signature is verified
against `dialedPeerId` before msg3 is built, and a dial pinned to the node's own key is
refused there too. Moving that check after the `wire(w3)` call, or verifying against a key
the message itself supplies, loses the invariant silently — every honest handshake still
succeeds. The self-dial and impostor tests pin it. The peer list is *configuration*, shipped
to the occupant at init and applied by it — a LINT rather than a gate, since a host checking
a key supplied by a malicious occupant cannot establish authentic attribution.

---

## 11. Hybrid key establishment (suite `0x03`)

**The KEM is bundle content.** `mlkem768.wasm` is the transport bundle's own import-free
module, reached under the bare name `mlkem` through the same private module map as
`ws.wasm`. It adds no host transform name, native KEM bridge or separately embedded host
artifact. The generic module ABI is pinned to 40 NIST ACVP cases.

The message widths are derived in one place from named field lengths (`M1_LEN`…`M3_LEN`,
`transport/src/ake.js`); the host never sees a handshake width. The key schedule takes a
*list* of shared secrets, so a KEM secret joins it rather than displacing anything. And
because the handshake publishes no long-term DH key, **a KEM never enters an address** —
addresses use `pk[.secret]@host:port`.

Msg1 carries the initiator's ML-KEM-768 encapsulation key and msg2 the responder's
ciphertext with the receiver's signature: exactly 1,233 and 1,200 bytes.
Session keys derive from the X25519 and KEM secrets both — hybrid, so the classical half
stays load-bearing while the PQ half is young. The worry that hybrid costs a round trip
belongs to a symmetric two-message layout; this one has explicit roles, so the responder
encapsulates at exactly the point it is already generating an ephemeral of its own. Still
three messages: 1 RTT to the initiator's authentication of the responder, 1.5 to the
responder's of the initiator, one encapsulation and one decapsulation per link.

**Where the KEM secret enters is the part that is quiet when wrong.** It is appended to the
schedule's ordered list, never XOR-ed into `ee` and never substituted for it. Msg2's seal
key is the first key available to both endpoints after encapsulation/decapsulation, and it
already derives from `[ee, kemSecret]`; msg3 and both session directions inherit the same
pair. The transcript chains complete messages, binding both the encapsulation key and
ciphertext.

**What must not change.** The transcript chain, the signature preimages, the contact-secret
and network-key mixes, the silence discipline, the address format, the record layer, and the
invariant that the bytes a node sends are the bytes it folds into the transcript.

**The DoS interaction.** A refused connection is held to its deadline, and msg1 is 1,233
bytes before either end has authenticated. `MAX_HANDSHAKE_FRAME_BYTES` is 8 KiB, clearing
both PQ widths with room while bounding a stranger to that cap times the unverified budget.
`MAX_QUEUE_BYTES` is unaffected: it bounds queued application frames, not the handshake.
What does change is the memory a stranger holds for `UNVERIFIED_TIMEOUT_MS`, and — on any
datagram path — that msg1 stops fitting one common-case MTU. The contact-secret seal covers
the KEM public key and is checked before the responder performs encapsulation, so
unauthenticated junk does not reach the expensive transform.
