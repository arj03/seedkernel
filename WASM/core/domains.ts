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
import { enc } from "./util.js";
const domain = (s: string) => enc.encode(s);
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
 *  Bumped when the seam's shape changes — the naming scheme of `host.call`'s first
 *  argument, a payload framing change, a name moving across the sync/async line.
 *  Adding a name to the catalog does not: a guest written against ABI n that never
 *  calls the new name behaves identically, and one that does call it declares the
 *  domain and gets it.
 *
 *  The field exists because the failure it guards is silent. A guest written against
 *  a different seam shape — a numbered op where this host reads a name, a synchronous
 *  return where this host settles a promise — reads `undefined` where bytes were
 *  expected, a wrong answer rather than an error, and one no amount of care at the call
 *  site turns into a loud one. Declaring the seam version makes it a refused load.
 *
 *  **It lives HERE, with the suite ids, rather than in cap-bridge.ts where the seam it
 *  versions is defined.** It is the same kind of thing they are — a number naming which
 *  version of a contract a signed document was written for, read by the loader before
 *  anything is trusted — and putting it here is what keeps the loader from importing the
 *  guest bridge to check a manifest field. That edge would drag the whole name catalog
 *  and preamble into every page that verifies a bundle, including pages that only
 *  inspect one and never build a bridge at all. cap-bridge.ts re-exports it, so a
 *  reader of the seam still finds the number next to the names. */
export const GUEST_ABI_VERSION = 2;
/** The crypto primitives this host serves through the `crypto/` prefix — the catalog
 *  a manifest's `guest.primitives` is checked against at load (§12.4).
 *
 *  Here rather than in cap-bridge.ts for exactly the reason `GUEST_ABI_VERSION` is: the
 *  loader checks a manifest field before anything is trusted, and it should not have to
 *  import the op catalog and preamble to do it. cap-bridge.ts dispatches through the
 *  `crypto/` prefix — its table keys are the template literal over this list, so the
 *  names and the transforms cannot drift.
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
    // guest from `node/random` — an authority — so the catalog stays purely functional.
    "ml-kem-768/keypair",
    "ml-kem-768/encaps",
    "ml-kem-768/decaps",
] as const;

export type PrimitiveName = (typeof PRIMITIVE_NAMES)[number];
/** The capability *domains* a bundle's manifest may declare in `guest.caps` (§12.4) —
 *  the granted prefixes of the name-addressed seam (§12.2). A domain IS its prefix: the
 *  bridge refuses any `host.call(name, …)` whose first path component is not one of
 *  these — or `crypto` and `module`, which are not here because they are never grants
 *  (§12.1). The vocabulary is closed, checked at load, so a manifest naming a domain
 *  this host has never heard of is a refused bundle rather than a cap that quietly
 *  grants nothing at first use. Adding a name to a domain here is the whole cost of a
 *  new op.
 *
 *  Here rather than in cap-bridge.ts for the reason `GUEST_ABI_VERSION` is: the loader
 *  checks a manifest's caps against this list before anything is trusted, and should not
 *  have to import the guest bridge to do it. cap-bridge.ts dispatches through a table
 *  whose every name must carry one of these prefixes (checked at construction), so the
 *  two cannot drift. */
export const CAP_DOMAINS: readonly string[] = ["node", "net", "fs", "clock", "timer", "link", "transport"];
/** The capability domains only the shell's transport MOUNT may declare (§12.5). `link` is
 *  what the mount consumes — sockets behind opaque link ids, the whole of what the
 *  platform contributes to the network — and `transport` is what it provides back: the
 *  attributed peer, protocol id and correlation every other app's `net` domain reaches.
 *  Neither is an app capability: a manifest declaring them is governed by the policy's
 *  transport half rather than its app half, and mounted as the node's transport rather
 *  than bound as an app. This list IS what says which bundle that is — there is no role
 *  field, because the caps already carry the fact and the signature already covers them.
 *  `timer` is deliberately NOT here: it is an ordinary authority, and the transport
 *  happening to want one is not a reason to make it a privilege.
 *
 *  A subset of `CAP_DOMAINS` — declared beside it, and derived from by the one predicate
 *  both admission paths ask (`mountOnlyCaps`, bundle.ts), so the vocabulary the app path
 *  refuses and the vocabulary the mount path requires cannot drift from each other or
 *  from the domains they name. */
export const MOUNT_ONLY_DOMAINS: readonly string[] = ["link", "transport"];
/** The guest ABIs this host can run. One entry today; a host supporting two seams at
 *  once (a migration window) lists both, and the loader admits a guest declaring either.
 *  Absent from this list ⇒ the load is refused with its own error, the same legibility
 *  failure as an unsupported manifest suite (§12.4). */
export const SUPPORTED_GUEST_ABIS: readonly number[] = [GUEST_ABI_VERSION];
// ── The manifest suite ──────────────────────────────────────────────────────────
//
// A suite id is the first byte of the structure it governs *and* part of what that
// structure's signature covers, so an attacker can never edit it in flight: doing so
// only makes the two sides compute different preimages and the verify fail. It is not
// negotiated — one suite per manifest, unknown ids refused — because the id's job is to
// make the format *self-describing*, not to pick between formats. That is what lets a
// later suite change every field width while old and new stay unambiguous on the wire.
//
// **The CHANNEL suite is not here, and the asymmetry is the point.** A manifest suite
// is read by the loader before anything is trusted, so it is the host's to declare — the
// same argument that puts the flood bounds in net-limits.ts. A channel suite is read by
// the AKE, which is entirely the transport bundle's program (transport/guest.js declares
// its own), so it is content: replaceable by shipping a new signed bundle, on its own
// clock. They are independent namespaces and always were; the channel half sat here only
// as a leftover of the pre-bundle transport. See §14.1, and docs/PROTOCOL.md for the
// channel suite ids themselves.
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
