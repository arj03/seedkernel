// domains.ts — the identifiers that bind a signature to its construction (README §16.1).
//
// Two families live here because they answer one question — "which cryptographic
// construction is this signature part of?" — at two levels. A *domain prefix* separates
// signing contexts; a *suite id* names the algorithms inside one. Both are covered by
// the signature that carries them, which is what makes each choosable by an endpoint and
// unforceable by an attacker in flight.
//
// Domain prefixes. Every signature this runtime makes commits to one of these before the
// message bytes. Their one job is disjointness: a signature made in one context — bundle
// manifest (§12.4), guest SIGN (§12.2), channel AUTH (§12.6) — must never verify in
// another, even over identical bytes, even when an attacker chooses the bytes. That is a
// property of the whole set, so the set lives in one file; adding a member means checking
// it against every other. Keep:
//   - a distinct literal, versioned (`-v1`); the trailing NUL (no member's body
//     contains one) keeps no member a prefix of another
//   - prepended before signing and verifying, never transmitted — zero wire cost
//
// The Go/native loader evaluates this very file via the generated bundles (§12.9),
// so its prefixes match by construction, not by a hand-copied constant.
const domain = (s: string) => new TextEncoder().encode(s);
/** Bundle manifest (§12.4): prefixes the manifest JSON, so a manifest signature
 *  can't double as an envelope wrapper over the same bytes. */
export const DOMAIN_MANIFEST = domain("seedkernel-manifest-sig-v1\0");
/** Bundle manifest author id (§12.4): prefixes the key material an author id is
 *  derived from under a multi-key suite. Not a signing context — the one member of
 *  this family that prefixes a *hash* — but it lives here for the same reason the
 *  others do: it must be disjoint from every signing prefix, so a derived author id
 *  can never also be a preimage someone signed. See `hybridAuthorId` (bundle.ts). */
export const DOMAIN_MANIFEST_AUTHOR = domain("seedkernel-manifest-author-v1\0");
/** Cap-bridge SIGN (§12.2): prefixes `scope ‖ msg`, scope host-derived from the
 *  manifest — a guest's signature stays in its bundle's namespace, not a key oracle. */
export const DOMAIN_GUEST = domain("seedkernel-guest-sig-v1\0");
/** Channel AUTH (§12.6): prefixes the AKE transcript, so an AUTH signature names
 *  one connection and no other. */
export const DOMAIN_CHANNEL = domain("seedkernel-channel-id-v1\0");
/** Subkey derivation (§12.9): `DOMAIN_subkey ‖ label ‖ master` hashed to a seed. Its own
 *  domain so a derived seed can never coincide with any other hash this system computes,
 *  and so the label space stays private to subkeys.ts. */
export const DOMAIN_SUBKEY = domain("seedkernel-subkey-v1\0");
// ── The guest seam's version ────────────────────────────────────────────────────
/** The guest ABI version — which shape of `host.call` a guest was written against
 *  (§12.2). A bundle's manifest declares it (`BundleGuest.abi`, §12.4) and the loader
 *  refuses a guest written for an ABI this host does not implement.
 *
 *  Bumped when an existing op changes what it RETURNS — an op moving across the
 *  sync/async line, a payload framing change. Adding an op does not: a guest written
 *  against ABI n that never calls the new op behaves identically, and one that does call
 *  it declares the domain and gets it.
 *
 *  The field exists because the failure it guards is silent. A guest that writes
 *  `host.call(FS_GET, k)` without awaiting gets a Promise where bytes were expected and
 *  reads `undefined` — a wrong answer, not an error, and one no amount of care at the
 *  call site turns into a loud one. Declaring the seam version makes it a refused load.
 *
 *  **It lives HERE, with the suite ids, rather than in cap-bridge.ts where the seam it
 *  versions is defined.** It is the same kind of thing they are — a number naming which
 *  version of a contract a signed document was written for, read by the loader before
 *  anything is trusted — and putting it here is what keeps the loader from importing the
 *  guest bridge to check a manifest field. That edge would drag the whole op catalog and
 *  preamble into every page that verifies a bundle, including handler-only shells
 *  (seedchat) that never build a bridge at all. cap-bridge.ts re-exports it, so a reader
 *  of the seam still finds the number next to the ops. */
export const GUEST_ABI_VERSION = 1;
/** The crypto primitives this host serves through the one `CAP.CRYPTO` op — the catalog
 *  a manifest's `guest.primitives` is checked against at load (phase 3a, task 8).
 *
 *  Here rather than in cap-bridge.ts for exactly the reason `GUEST_ABI_VERSION` is: the
 *  loader checks a manifest field before anything is trusted, and it should not have to
 *  import the op catalog and preamble to do it. cap-bridge.ts builds the dispatch map
 *  from this list and re-exports it, so the names and the transforms cannot drift.
 *
 *  **Adding a name here is the whole cost of a new algorithm** — no op number, no ABI
 *  rev, no capability domain. That is the point of a named catalog, and it is why a core
 *  vocabulary is provisioned ahead of need (§14.1): a bundle is replaceable, the
 *  vocabulary it draws on is not. */
export const PRIMITIVE_NAMES = [
    "blake2b-256",
    "ed25519/verify",
    "xchacha20/xor",
    "chacha20poly1305-ietf/seal",
    "chacha20poly1305-ietf/open",
    "x25519/dh",
    // ML-KEM-768 (FIPS 203), provisioned AHEAD of any caller — the whole point of the
    // rule above. The channel's post-quantum suite is content (a signed transport
    // bundle plus one policy entry), but only once its primitive exists on all three
    // targets, and a primitive is the one thing that cannot be delivered as a bundle.
    // Nothing in this tree calls these yet; §14.1 puts them on a clock rather than on
    // a credible break, so they land now.
    //
    // Derandomized, like every other entry: the coins are an argument, drawn by the
    // guest from `RANDOM` — an authority — so the catalog stays purely functional.
    "ml-kem-768/keypair",
    "ml-kem-768/encaps",
    "ml-kem-768/decaps",
] as const;

export type PrimitiveName = (typeof PRIMITIVE_NAMES)[number];
/** The capability domains only a SLOT occupant may declare (phase 3a, task 11).
 *
 *  `rawnet` is what the transport slot consumes — sockets behind opaque link ids, the
 *  whole of what the platform contributes to the network — and `transport` is what it
 *  provides back: the attributed peer, protocol id and correlation every other app's
 *  `net` domain reaches. Neither is an app capability. Splitting the two nets is what
 *  makes that statable at all: before it, `net` meant the structured thing and an app
 *  declaring it was implicitly being handed the transport's output and the platform's
 *  socket seam under one word.
 *
 *  Enforced at load, not at first use, and on the same argument that keeps
 *  `authorAllowlist` from admitting a slot claim: an authority class this large needs a
 *  deliberate per-slot policy decision, never a cap string an ordinary app can add to
 *  its own manifest and have quietly honoured.
 *
 *  `timer` is deliberately NOT here. It is an ordinary authority — small, host-bounded,
 *  and useful to any guest that needs a deadline — and the transport happening to want
 *  one is not a reason to make it a privilege.
 *
 *  Here rather than in cap-bridge.ts for the reason `GUEST_ABI_VERSION` is: the loader
 *  checks this against a manifest before anything is trusted, and should not have to
 *  import the op catalog to do it. */
export const SLOT_ONLY_DOMAINS: readonly string[] = ["rawnet", "transport"];
/** The guest ABIs this host can run. One entry today; a host supporting two seams at
 *  once (a migration window) lists both, and the loader admits a guest declaring either.
 *  Absent from this list ⇒ the load is refused with its own error, the same legibility
 *  failure as an unsupported manifest suite (§12.4). */
export const SUPPORTED_GUEST_ABIS: readonly number[] = [GUEST_ABI_VERSION];
// ── Algorithm suites ────────────────────────────────────────────────────────────
//
// A suite id is the first byte of the structure it governs *and* part of what that
// structure's signature covers, so an attacker can never edit it in flight: doing so
// only makes the two sides compute different preimages and the verify fail. Neither is
// negotiated — one suite per link, one per manifest, unknown ids refused — because the
// id's job is to make the format *self-describing*, not to pick between formats. That is
// what lets a later suite change every field width (an ML-KEM-768 encapsulation key is
// 1184 bytes where X25519 uses 32) while old and new stay unambiguous on the wire.
//
// The two are INDEPENDENT namespaces on independent clocks, and that is the whole reason
// they are named apart rather than sharing one constant. The channel suite protects a
// live key exchange, so it is exposed to harvest-now-decrypt-later and is the one under
// time pressure; the manifest suite protects an at-rest signature, which has no
// retroactive attack and can migrate late. They both read `0x01` today only because each
// is at its own genesis algorithms. Never read one as the other, and never assume they
// move together. See §14.1.
/** Channel handshake (§12.6): Ed25519 identity · ephemeral X25519 · ChaCha20-Poly1305.
 *  Both identities ride in cleartext; see SUITE_CHANNEL_CONCEALED. */
export const SUITE_CHANNEL_GENESIS = 0x01;
/** Channel handshake with concealed identities (§12.6.2): a long-term X25519 key per
 *  node in addition to the Ed25519 identity, and neither identity on the wire in clear.
 *
 *  The initiator proves prior knowledge of the responder's static key in its first
 *  message, so a node never speaks to a peer that does not already know it — which is
 *  what stops a scanner from reading identities off any listener it can reach. Both
 *  identities then travel under keys derived from the ephemeral-ephemeral DH, so
 *  seizing a node's long-term key later does not retroactively deanonymise the peers
 *  that dialled it. Same record layer as 0x01 below the handshake.
 *
 *  A node that accepts BOTH suites has the concealment of neither: a scanner offers
 *  0x01 and reads the cleartext HELLO. 0x01 acceptance is therefore a deployment
 *  setting to be turned off, not a permanent compatibility mode (§12.6.2 phase 5). */
export const SUITE_CHANNEL_CONCEALED = 0x02;
/** Bundle manifest (§12.4): Ed25519 detached signature over `DOMAIN_manifest ‖ suite ‖ json`. */
export const SUITE_MANIFEST_GENESIS = 0x01;
/** Bundle manifest (§12.4): **hybrid** Ed25519 + ML-DSA-65 (FIPS 204). Both signatures
 *  are made over `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖ json` and **both must
 *  verify** — the classical half stays load-bearing while the PQ half is young, so a
 *  flaw in ML-DSA fails *closed* (valid bundles rejected) rather than open (forged
 *  bundles admitted), and the bundle is no weaker than `0x01` against a classical
 *  attacker (§14.1).
 *
 *  This is the migration that can never get cheaper than a coordinated rebuild: a PQ
 *  verifier cannot be delivered as a bundle, because the classical verifier would be
 *  the thing admitting it. So it goes into the artifact *ahead* of need, unlike the
 *  channel suite, which is content and can wait for a credible break (§14.1). */
export const SUITE_MANIFEST_HYBRID_PQ = 0x02;
