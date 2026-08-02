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
| **Attribute** — watch a flow, learn which pair it belongs to | both identities travelling under the ephemeral–ephemeral secret (§3) |
| **Membership-test** — ask a node "would you talk to key P?" | silent refusal on every pre-auth path (§5) |

Two things it does not provide, stated here rather than buried: a node at a stable
`host:port` is still identified to anyone holding an address book and a packet capture, and
the cleartext suite byte still identifies the traffic as seedkernel. Concealment defeats
probing and flow attribution; hiding the communication graph itself is mixnet work and a
different project. §9 has the full list.

---

## 2. Shape

Four messages. The initiator opens with an ephemeral and a seal keyed by the receiver's
contact secret; the receiver answers with an ephemeral and a seal of its own; the caller
then names itself; and only then does the receiver name itself.

```
msg1  i→r   ephemeral + contact proof          — no identity
msg2  r→i   ephemeral + contact proof          — no identity
msg3  i→r   the caller names itself
msg4  r→i   the receiver answers, or does not
```

Wire layout, exact widths, the key schedule and the constants are normative and live in
[RUNTIME](RUNTIME.md) §12.6. Everything below is why they are that way.

## 3. Identities travel under the ephemeral–ephemeral secret

Neither public key appears in cleartext. Both are sealed under keys derived from `ee`,
which exists only for the life of the connection, so a node seized years later yields
nothing from a recording of one.

This is why identities wait for the third and fourth messages rather than the first. At
msg1 the only key in existence is long-term, so anything sealed there is sealed under a key
that lives for years — the property Noise names for its `IK` pattern and WireGuard
documents as a known limitation: compromising a responder's private key plus a traffic log
reveals who sent every recorded handshake. Deferring past `ee` makes concealment
forward-secret for both ends.

The handshake therefore uses **no long-term Diffie–Hellman key at all**. `ee` is ephemeral
on both sides; the contact secret and network key are KDF inputs. Two consequences worth
having: the Ed25519 identity key stays signing-only, as §12.6 requires, without the
Ed25519→Curve25519 conversion Secret Handshake needs; and a node address carries no DH key,
so the post-quantum suite will not change the address format (§11).

---

## 4. The caller names itself first

The receiver learns who is calling before it says who it is. A caller that fails
`admitPeer` is turned away having learned nothing — not even whether the identity it dialed
is live at that address.

This is what the fourth message buys, and it is the one place this design leaves the
standard patterns. Across all twelve fundamental and twenty-three deferred Noise patterns,
whenever the responder transmits its static key it does so in message 2, *before* the
initiator's. Receiver-decides-first has no standard pattern.

Someone must name themselves first; that is not solvable, only assignable. Because both
early messages carry a seal keyed by the contact secret, whoever goes first is exposed only
to a party already holding the credential. Assigning it to the caller is what lets the
receiver run its whitelist before revealing anything.

The cost is one round trip, once per connection, against a property that holds for every
connection forever.

---

## 5. Refusals are silent

Every pre-authentication failure does nothing at all and lets the deadline expire, so an
unauthorised caller cannot distinguish this node from a port that is not listening.

The alternative — closing on a bad message — answers a question. "I am a seedkernel node
and that is not the key" is exactly the oracle §1 removes, and it is available to anyone
who can open a socket. Silence is the only response that says nothing, so every refusal
path funnels to the same place. In the code this looks like missing error handling, which
is why it is commented as load-bearing: the likeliest way to lose this property is someone
tidying up error paths.

The cost is that a refused connection occupies a socket until its deadline instead of being
dropped on sight, which promotes the half-open budgets from defence in depth to the thing
standing between a stranger and the node. Three measures pay for it, and two of them exist
because measurement contradicted the design:

- **No cryptography before proof.** The accepting side used to generate an X25519 keypair in
  its *constructor*, so every inbound TCP connection bought a keygen before the peer had
  proved anything — the cheapest flood there is.
- **Separate budgets for proven and unproven callers**, so a flood without the contact
  secret cannot crowd out those that have it.
- **Evict the oldest rather than refuse the newest.** Separating the budgets was *not*
  sufficient on its own: a saturating flood turned each arriving peer away at the door,
  before it could send the message that would have promoted it. Promotion cannot rescue a
  connection that was never accepted. The oldest unverified connection is overwhelmingly
  likely to be a stranger making no progress, while a legitimate caller occupies that budget
  for one round trip — so an attacker must cycle the whole budget faster than a round trip
  rather than merely fill it once. The same argument applies one tier up, which is why the
  verified budget evicts too.

A correction to an earlier framing: silence did **not** make flooding materially worse. A
connection that opened a socket and said nothing already held a slot for the full deadline.
Silence only made garbage cost the same as silence.

Constants and measured numbers: [RUNTIME](RUNTIME.md) §12.6.2 and
`tests/net-link.load.test.mjs`.

## 6. Why three secrets and not one

A link is gated by a contact secret, a network key and an optional whitelist. What each
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

### 6.3 Why the whitelist runs after verification

A filter on an unproven key that refuses visibly is a membership oracle: name any key, watch
whether the response differs, and read the whitelist off a node without holding a single
private key. On a whitelist that tracks a social graph, that is the graph. So `admitPeer`
sees only identities whose signature has verified, and refuses by silence.

It is optional and empty by default. Revocation is key rotation — a node dropping a peer
rotates its contact secret, a network splitting rotates its network key — so the whitelist
is a convenience for expressing membership without re-keying, not a revocation mechanism.

## 7. Why purpose-bound keys, given domain separation

Every preimage in the system is already domain-separated, so deriving a separate key per
purpose ([RUNTIME](RUNTIME.md) §12.6.2b) looks redundant. It is not, and the reason is about
where each property lives.

Domain separation is a property of the **code**. It holds provided the prefix is applied, on
both the signing and the verifying side, on every path, forever. It is one refactor away
from being wrong, and being wrong is silent: signatures still verify, just for more things
than intended. A single omitted or mismatched prefix on a signing path turns that signer
into an oracle for every other purpose sharing the key.

Key separation is a property of the **keys**. The cap-bridge `SIGN` op cannot emit a channel
handshake signature because it does not hold the channel key, whatever happens to the
prefixes.

That distinction matters most where a signing oracle is deliberate, and `SIGN` is exactly
that: it signs guest-supplied bytes on request, exposed to guest code. Domain separation is
what makes it safe today; key separation is what keeps it safe after someone edits the
signing path.

This is the practice Noise asks for when it says a static key pair should not be used
outside the protocol it was generated for, and the reasoning behind libsodium's
`crypto_kdf`: one long-term secret, many purpose-bound subkeys.

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
| Master seed with purpose-bound subkeys | libsodium `crypto_kdf`; Noise's static-key-reuse guidance |
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
   and 1216 bytes once it goes hybrid. §7's subkey derivation satisfies the *spirit* of that
   guidance — no key serves two purposes — without publishing a DH key at all.
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
Ed25519 to Curve25519, which §12.6 rules out; and because it has no suite byte, so there is
nowhere to put an ML-KEM encapsulation key. §14.1 identifies the channel as the one
migration on a real deadline, which makes that the heaviest objection.

---

## 9. Limits

**The IP layer still identifies nodes.** A stable `host:port` is identified to anyone who
maps it once. Concealment defeats probing and flow attribution, not an observer who already
knows where to look.

**A recorded msg1 can be replayed.** Anyone who captures a valid msg1 can replay it and draw
a msg2. They cannot open it — no ephemeral private key — so they learn only that something
answered. Inherent to any design whose first message is not challenge-bound; Noise has it
too.

**The protocol is fingerprintable.** A cleartext `0x02` at offset 0 says "seedkernel". That
identifies the protocol, not the peer, and hiding it would cost the self-describing format
and the migration path of §14.1. First message indistinguishable from random is a separate
goal and belongs in its own suite.

**Impersonation after key compromise.** Seizing a node's master seed lets an attacker be
that node. Only §3's deferral limits the *retroactive* damage.

**Guest signature verification across nodes is unfinished.** §7 moves `SIGN` onto the guest
subkey, so `CAP.IDENTITY` now returns that subkey's public half while `senderPk` carries the
channel key. Nothing in the tree verifies a peer's guest signature today, but anything that
wants to will need the guest subkey published authentically. The natural home is the
handshake — msg3 and msg4 already carry a signed identity — but that is a §12.2 decision
about what guests are told, not a §12.6 one, and it is deliberately left open.

---

## 10. Invariants worth a named test

1. A node never transmits anything before opening the caller's msg1.
2. A wrong contact secret, a declined identity, and silence are mutually indistinguishable.
3. Neither identity appears in cleartext anywhere on the wire.
4. msg1 contains no identity, so a recording plus a later key seizure reveals none.
5. The receiver's identity does not go out to a caller it then declines.
6. Neither the contact secret nor the network key appears on the wire.
7. Nodes on different network keys never link.
8. Subkey derivation is deterministic, and no two purposes share a key.
9. Only `close()` emits the end-of-stream record; every failure path is silent. *(§12.6.1)*
10. A graceful close asks the transport to flush. *(§12.6.1)*
11. An unproven connection costs zero asymmetric operations.
12. A member authenticates under a sustained flood, credentialled or not.
13. The channel Ed25519 key is never an argument to `crypto_scalarmult`. Worth a grep test
    in CI — the invariant most likely to be lost to a convenient refactor.

All but 13 are covered by `tests/net-link.test.mjs` and `tests/net-link.load.test.mjs`.

---

## 11. The post-quantum landing (suite `0x03`)

**The primitive is already there.** `ml-kem-768/{keypair,encaps,decaps}` are in the host's
primitive catalog (`PRIMITIVE_NAMES`, §12.2), provisioned ahead of any caller because a
bundle is replaceable and the vocabulary it draws on is not. So `0x03` is a signed transport
bundle and one policy entry — no host rebuild on three targets, which is what the ordering
argument in §14.1 was protecting against.

**Already prepared for.** `SUITE_PARAMS` holds the per-suite message widths in one table, so
`0x03` is an entry. The key schedule takes a *list* of shared secrets, so a KEM secret joins
it rather than displacing anything. And because the handshake publishes no long-term DH key,
**a KEM never enters an address** — addresses stay `pk[.secret]@host:port` across the
migration, which is the part that would otherwise have hurt.

**What changes.** msg1 gains the initiator's ML-KEM-768 encapsulation key and msg2 the
responder's ciphertext: 81 → ~1.3 KB and 80 → ~1.3 KB. Session keys derive from the X25519
and KEM secrets both — hybrid, so the classical half stays load-bearing while the PQ half is
young.

**What must not change.** The transcript chain, the signature preimages, the contact-secret
and network-key mixes, the silence discipline, the address format, and the record layer.

**The DoS interaction.** A refused connection is held to its deadline, and msg1 grows ~16×.
`tests/net-link.load.test.mjs` exists and the budgets are hardened, but its numbers are for
an 81-byte msg1: re-run it against the new widths and re-check `MAX_HALF_OPEN_UNVERIFIED`
against the resulting memory profile rather than against connection count. Keep the ordering
when porting — the contact-secret seal on msg1 must be checked *before* KEM decapsulation,
or the cost of a junk connection rises with the KEM.
