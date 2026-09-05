# §12.6.2 — The concealed-identity channel handshake

*What the handshake is, what each part is for, and where it sits in the literature.*

> Rationale companion to the normative text in [RUNTIME](RUNTIME.md) §12.6–§12.6.3,
> [PROTOCOL](PROTOCOL.md) §16.1 and [SECURITY](SECURITY.md) §14–§14.1. Those say what the
> protocol *is*; this says why it is shaped that way.

---

## 1. What it provides

**An observer who can open sockets to a node and watch traffic cannot enumerate which
identities are present on the network, nor which pairs are talking.**

Three capabilities are denied:

| Capability | Denied by |
| --- | --- |
| **Probe** — connect to a host, learn which node lives there | the contact secret (§6.1) and the message ordering (§4) |
| **Attribute** — watch a flow, learn which pair it belongs to | both identities travelling under the hybrid ephemeral secrets (§3) |
| **Membership-test** — ask a node "would you talk to key P?" | silent refusal on every pre-auth path (§5) |

Two things it does not provide, stated here rather than buried: a node at a stable
`host:port` is still identified to anyone holding an address book and a packet capture, and
the cleartext suite byte still identifies the traffic as seedkernel. Concealment defeats
probing and flow attribution; hiding the communication graph itself is mixnet work and a
different project. §9 has the full list.

---

## 2. Shape

Four messages. The initiator opens with an X25519 ephemeral, an ML-KEM-768 public key, and
a seal keyed by the receiver's contact secret; the receiver answers with its X25519
ephemeral, an ML-KEM ciphertext, and a seal derived from both shared secrets. The caller
then names itself; and only then does the receiver name itself.

```
msg1  i→r   X25519 ephemeral + KEM pk + contact proof  — no identity
msg2  r→i   X25519 ephemeral + KEM ct + hybrid proof  — no identity
msg3  i→r   the caller names itself
msg4  r→i   the receiver answers, or does not
```

Wire layout, exact widths, the key schedule and the constants are normative and live in
[RUNTIME](RUNTIME.md) §12.6. Everything below is why they are that way.

## 3. Identities travel under the hybrid ephemeral secrets

Neither identity public key appears in cleartext. Both are sealed under keys derived from
the ephemeral X25519 secret `ee` and the ephemeral ML-KEM secret. Both are erased once the
session keys exist, so a node seized years later yields nothing from a recording of one.

This is why identities wait for the third and fourth messages rather than the first. At
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

## 4. The caller names itself first

The receiver learns who is calling before it says who it is. A caller that fails
the peer lint is turned away having learned nothing — not even whether the identity it dialed
is live at that address.

This is what the fourth message buys, and it is the one place this design leaves the
standard patterns. Across all twelve fundamental and twenty-three deferred Noise patterns,
whenever the responder transmits its static key it does so in message 2, *before* the
initiator's. Receiver-decides-first has no standard pattern.

Someone must name themselves first; that is not solvable, only assignable. Because both
early messages carry a seal keyed by the contact secret, whoever goes first is exposed only
to a party already holding the credential. Assigning it to the caller is what lets the
receiver run its peer lint before revealing anything.

The cost is one round trip, once per connection, against a property that holds for every
connection forever.

---

## 5. Refusals are silent

Every refusal before the responder reveals its identity does nothing at all and lets the
deadline expire, so an unauthorised caller cannot distinguish this node from a port that is
not listening. After the initiator has revealed itself at msg3, its local msg4 peer-pin or
peer-policy rejection may abort because there is no responder identity left to conceal.

The alternative — closing on a bad message — answers a question. "I am a seedkernel node
and that is not the key" is exactly the oracle §1 removes, and it is available to anyone
who can open a socket. Silence is the only response that says nothing, so every refusal
path funnels to the same place. In the code this looks like missing error handling, which
is why it is commented as load-bearing: the likeliest way to lose this property is someone
tidying up error paths.

The cost is that a refused connection occupies a socket until its deadline instead of being
dropped on sight, which promotes the half-open budgets from defence in depth to the thing
standing between a stranger and the node. Three measures bound this exposure:

- **No asymmetric cryptography before proof.** The accepting side verifies the contact-secret
  proof before generating ephemeral keys or invoking the KEM.
- **Separate budgets for proven and unproven callers**, so a flood without the contact
  secret cannot crowd out those that have it.
- **Evict the oldest rather than refuse the newest.** Refusing arrivals at a full budget
  would let a flood block peers before they could send their proof. The oldest unverified connection is overwhelmingly
  likely to be a stranger making no progress, while a legitimate caller occupies that budget
  for one round trip — so an attacker must cycle the whole budget faster than a round trip
  rather than merely fill it once. The same argument applies one tier up, which is why the
  verified budget evicts too.

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

**It is not what conceals the identities.** §4 does that, and an open node conceals just as
well. What the secret adds is narrower: a stranger costs no asymmetric cryptography; the
*caller's* identity is protected from an active attacker, since otherwise anyone answering
at a dialed address collects it at msg3 and `expectPeerId` cannot help because msg3 precedes
msg4; and active probing draws silence, so "a node speaks this protocol here" stops being
observable. In Noise's grading the first of those is worth nothing and the second moves the
initiator from 2 to 8 (§8.1).

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

### 6.3 Why the peer list runs after verification

A filter on an unproven key that refuses visibly is a membership oracle: name any key, watch
whether the response differs, and read the list off a node without holding a single private
key. On a list that tracks a social graph, that is the graph. So the check sees only
identities whose signature has verified, and refuses by silence.

It is optional and empty by default. Revocation is key rotation — a node dropping a peer
rotates its contact secret, a network splitting rotates its network key — so the list is a
convenience for expressing membership without re-keying, not a revocation mechanism.

**Peer admission depends on the transport.** The configured list is checked by the transport
against signature-verified identities. A malicious transport can bypass it or fabricate
attribution. The host confines the transport's service access and resource use (§14), but
relies on it for channel confidentiality, authentication and attribution.

## 7. Why one identity key, and not a key per purpose

A node signs for two purposes with one key: the handshake, under `DOMAIN_link_scope ‖
network_key` (with the transport's own `DOMAIN_channel ‖ transcript` inside), and an app's
scoped records, under `DOMAIN_guest ‖ author ‖ app`
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
| **Open** (no contact secret) | **2** — *"sent to an anonymous responder"* | *off the table* |
| **With a contact secret** | ~8 — encrypted with forward secrecy to a credentialled party | *off the table* |

The responder property has no Noise number because no Noise pattern withholds the
responder's static until the initiator has authenticated. The initiator column is exactly
what §6.1 exists to buy.

For comparison, the two nearest standard patterns: `XX` grades the responder **1**,
*"encrypted with forward secrecy, but can be probed by an anonymous initiator"*; `XK` grades
it **3**, not transmitted but with candidates checkable and replays linkable.

### 8.2 Why not Noise itself

Three reasons, in order of weight.

1. **Noise authenticates with static DH; this authenticates with signatures.** Signature
   replacement is an explicitly future extension, and the spec notes that every fundamental
   pattern can replace only one authentication DH with a signature — mutual signature
   authentication needs the deferred variants and does not exist today.
2. **Noise's static-key guidance costs us an address field.** A Noise static must be a DH
   key, so adopting Noise means a second long-term key per node, published in every address
   and 1,216 bytes if that long-term address key were hybrid X25519 + ML-KEM-768. §7 satisfies the *spirit* of that guidance — the
   identity key never takes a DH role — without publishing a DH key at all.
3. **No standard pattern gives the ordering in §4.**

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

**A recorded msg1 can be replayed.** Anyone who captures a valid msg1 can replay it and draw
a msg2. They cannot open it — no ephemeral private key — so they learn only that something
answered. Inherent to any design whose first message is not challenge-bound; Noise has it
too.

**The protocol is fingerprintable.** A cleartext `0x03` at offset 0 says "seedkernel". That
identifies the protocol, not the peer, and hiding it would cost the self-describing format
and the migration path of §14.1. First message indistinguishable from random is a separate
goal and belongs in its own suite.

**Impersonation after key compromise.** Seizing a node's master seed lets an attacker be
that node. Only §3's deferral limits the *retroactive* damage.

---

## 10. Invariants worth a named test

1. A node never transmits anything before opening the caller's msg1.
2. A wrong contact secret, a declined identity, and silence are mutually indistinguishable.
3. Neither identity appears in cleartext anywhere on the wire.
4. msg1 contains no identity, so a recording plus a later key seizure reveals none.
5. The receiver's identity does not go out to a caller it then declines.
6. Neither the contact secret nor the network key appears on the wire.
7. Nodes on different network keys never link.
8. Subkey derivation is deterministic: a node rebuilds its identity from the seed alone.
9. Only `close()` emits the end-of-stream record; every failure path is silent. *(§12.6.1)*
10. A graceful close asks the transport to flush. *(§12.6.1)*
11. An unproven connection costs zero asymmetric operations.
12. A member authenticates under a sustained flood, credentialled or not.
13. The channel Ed25519 key is never an argument to `crypto_scalarmult`. Worth a grep test
    in CI — the invariant most likely to be lost to a convenient refactor.

All but 13 are covered by `tests/transport-link.test.mjs` and `tests/transport-load.test.mjs`,
which pin them against the shipped transport bundle — through the real host stack, over an
instrumented in-process channel — rather than against a library object a test could hold.

**Where 5 lives, and why it is easy to lose.** The peer list is *configuration*, shipped to
the occupant at init and applied by it — a LINT rather than a gate, since a host checking a
key supplied by a malicious occupant cannot establish authentic attribution. What matters is
the *order*, and the invariant is entirely about order. The gate is asked
at the first point the peer is known and before this end has revealed anything about itself:
`onMsg3` when accepting, `onMsg4` when dialing. Asking it from `becomeAuthed()` instead
would be one message too late on the accepting side, because that is reached only after
msg4 — the receiver's identity and signature — is already on the wire. A concealed refusal
is also silence rather than a close: closing at msg3 would answer the same question the
ordering exists to leave unanswered. The lint takes a `conceal` flag for exactly that
distinction.

---

## 11. Hybrid key establishment (suite `0x03`)

**The KEM is bundle content.** `mlkem768.wasm` is the transport bundle's own import-free
module, reached under the bare name `mlkem` through the same private module map as
`ws.wasm`. It adds no host transform name, native KEM bridge or separately embedded host
artifact. The generic module ABI is pinned to 40 NIST ACVP cases.

The message widths are derived in one place from named field
lengths (`M1_LEN`…`M4_LEN`, `transport/src/ake.js`); the host never sees a handshake width. The key schedule takes a
*list* of shared secrets, so a KEM secret joins it rather than displacing anything. And
because the handshake publishes no long-term DH key, **a KEM never enters an address** —
addresses use `pk[.secret]@host:port`.

Msg1 carries the initiator's ML-KEM-768 encapsulation key and msg2 the responder's
ciphertext: exactly 1,265 and 1,168 bytes.
Session keys derive from the X25519 and KEM secrets both — hybrid, so the classical half
stays load-bearing while the PQ half is young. The worry that hybrid costs a round trip
belongs to a symmetric two-message layout; this one has four messages with explicit roles,
so the responder encapsulates at exactly the point it is already generating an ephemeral of
its own. Still four messages, still 1.5 RTT to the responder's authentication and 2 to the
initiator's, one encapsulation and one decapsulation per link.

**Where the KEM secret enters is the part that is quiet when wrong.** It is appended to the
schedule's ordered list, never XOR-ed into `ee` and never substituted for it. Msg2's seal
key is the first key available to both endpoints after encapsulation/decapsulation, and it
already derives from `[ee, kemSecret]`; msg3, msg4 and both session directions inherit the
same pair. The transcript chains complete messages, binding both the encapsulation key and
ciphertext.

**What must not change.** The transcript chain, the signature preimages, the contact-secret
and network-key mixes, the silence discipline, the address format, the record layer, and the
invariant that the bytes a node sends are the bytes it folds into the transcript.

**The DoS interaction.** A refused connection is held to its deadline, and msg1 is 1,265
bytes before either end has authenticated. `MAX_HANDSHAKE_FRAME_BYTES` is 8 KiB, clearing
both PQ widths with room while bounding a stranger to that cap times the
unverified budget. `MAX_QUEUE_BYTES` is unaffected: it bounds queued application
frames, not the handshake. What does change is the memory a stranger holds for
`UNVERIFIED_TIMEOUT_MS`, and — on any datagram path — that msg1 stops fitting one common-case
MTU. The contact-secret seal covers the KEM public key and is checked before the responder
performs encapsulation, so unauthenticated junk does not reach the expensive transform.
