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
/** Guest-seam SIGN (§12.2): prefixes `scope ‖ msg`, scope host-derived from the
 *  manifest — a guest's signature stays in its bundle's namespace, not a key oracle. */
export const DOMAIN_GUEST = domain("seedkernel-guest-sig-v1\0");
/** Channel AUTH (§12.6): prefixes the AKE transcript, so an AUTH signature names
 *  one connection and no other. */
export const DOMAIN_CHANNEL = domain("seedkernel-channel-id-v1\0");
/** Subkey derivation (§12.9): `DOMAIN_subkey ‖ label ‖ master` hashed to a seed. Its own
 *  domain so a derived seed can never coincide with any other hash this system computes,
 *  and so the label space stays private to subkeys.ts. */
export const DOMAIN_SUBKEY = domain("seedkernel-subkey-v1\0");
/** Author key-set derivation (§12.4): the label hashed with an author's Ed25519 seed to
 *  get the ML-DSA-65 seed of the same identity, so **one stored key is the whole author**
 *  and a rebuild from it is the same author id. See `hybridAuthorKeysFromSeed`
 *  (bundle.ts), which is the one implementation every consumer should call.
 *
 *  **These bytes are frozen.** The author id is a hash over both public keys, so changing
 *  this label re-derives the PQ half and therefore re-identifies *every* author built
 *  from a seed — new app keys, a dead freshness lineage, and every pinned id in every
 *  operator's policy file pointing at nobody. It is a KDF label rather than a signing
 *  prefix, hence no trailing NUL: it is never a signature preimage, and the disjointness
 *  rule above is about the prefixes that are. */
export const AUTHOR_MLDSA_SEED_LABEL = domain("seedkernel-author-mldsa-v1");
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
 *  **It lives HERE, with the suite ids, rather than in guest-seam.ts where the seam it
 *  versions is defined.** It is the same kind of thing they are — a number naming which
 *  version of a contract a signed document was written for, read by the loader before
 *  anything is trusted — and putting it here is what keeps the loader from importing the
 *  guest seam to check a manifest field. That edge would drag the whole name catalog
 *  and preamble into every page that verifies a bundle, including pages that only
 *  inspect one and never build a seam at all. guest-seam.ts re-exports it, so a
 *  reader of the seam still finds the number next to the names. */
export const GUEST_ABI_VERSION = 5;
/** The crypto primitives this host serves through the `crypto/` prefix — the pure half
 *  of the seam, and **not** something a manifest declares. `cryptoCatalog` (guest-seam.ts)
 *  is total over this list: a host that has that file has every name in it, so a partial
 *  catalog is unrepresentable and there is nothing for a bundle to require. What a guest
 *  needs from the pure half is covered by `abi` — the version of the seam it was written
 *  against, which is the version of everything in it.
 *
 *  Here rather than in guest-seam.ts for exactly the reason `GUEST_ABI_VERSION` is: it
 *  belongs with the vocabulary, and guest-seam.ts's table keys are the template literal
 *  over this list, so the names and the transforms cannot drift.
 *
 *  **Adding a name here is the whole cost of a new algorithm** — no op number, no ABI
 *  rev, no manifest field. That is the point of a named catalog, and it is why a core
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
/** The authorities: every name that reaches something no confined guest can hold — the
 *  node key (`node/sign` is scoped, never raw), the entropy source, a socket, the disk,
 *  the platform's clock and event loop. Together with the reserved ids below they are the
 *  manifest vocabulary: `guest.requires` names a subset of the two and nothing else, so
 *  the list an operator reads is the list of what the bundle can reach.
 *
 *  `crypto/*` and a bundle's own module names are not here, and that absence is the whole
 *  gate rule: a name is a grant iff it is a key of this table or a reserved id
 *  (`isGrant`), so the dispatcher never parses a name to decide *whether it is granted*
 *  (§12.1). They are also, for the same reason, not declarable — a manifest naming one is
 *  refused. Neither can be absent from a host (`cryptoCatalog` is total; a bundle's
 *  modules arrive with it), so requiring them would be a requirement on something that
 *  cannot fail, and it would bury the three or four names that carry the bundle's actual
 *  authority under a dozen that carry none.
 *
 *  **Every key here must contain a `/`, and no module name may lead with `_`.** Those two
 *  charset rules are what let ONE `host.call` carry three kinds of name and be told apart
 *  by the name alone: a `/` is the host's own, a leading `_` is a reserved id reaching
 *  another realm, and anything else is one of the asking bundle's own modules. A manifest
 *  holds module names to `[A-Za-z0-9_-]` minus a leading `_` (bundle.ts), so all three are
 *  disjoint by construction. `crypto/*` gets its slash from its template literal; this
 *  table is hand-written, so guest-seam.ts checks it at construction — a bare authority
 *  added here would shadow every app's module of that name.
 *
 *  Each name carries what it is granted *for*, and a privileged name's PREFIX is that
 *  privilege — `link/*` is granted under `link`, and a name's value is never a word for
 *  the kind of bundle that wants it. `"app"` is the unprivileged case — an ordinary
 *  authority any bundle may ask for, needing no operator grant beyond the right to load
 *  at all. Anything else names a PRIVILEGE an operator grants per author (`PRIVILEGES`,
 *  policy.ts). Today there is one: `link`, a byte duplex behind opaque link ids, which is
 *  the platform's whole contribution to the network and nothing else. `timer/*` is
 *  deliberately `"app"`: an ordinary authority, and the transport happening to want one
 *  is not a reason to make it a privilege.
 *
 *  **A privilege is one thing, not a pair of halves.** What the transport PROVIDES back
 *  is not an authority at all — it is an ordinary cross-realm call to the id it claims
 *  (`NET_PROTOCOL`), reached by the same mechanism an app is reached by. So there is
 *  nothing to claim in halves, nothing to check is claimed in full, and no second
 *  vocabulary: a name's value is a privilege or it is `"app"`.
 *
 *  The table IS what says which privileges a bundle reaches; there is no role field,
 *  because the requires already carry the fact and the signature already covers them.
 *  Adding a privileged name under a new value adds a privilege, and with it the policy
 *  key an operator grants it under — no second vocabulary, no third class.
 *
 *  The one-file rule: the seam's dispatch table is TYPED against `CapabilityName`
 *  (a key here without a handler is a compile error) and walked against its own key
 *  set at construction (the compiled-JS half the native target evaluates, and the
 *  check a typo'd extra key trips). Adding a name here is the whole cost of a new op. */
export const AUTHORITY_CALLS = {
    "node/sign": "app",
    "node/verify": "app",
    "node/identity": "app",
    "node/random": "app",
    "fs/get": "app",
    "fs/put": "app",
    "fs/list": "app",
    "fs/delete": "app",
    "fs/size": "app",
    "fs/stat": "app",
    "clock/now": "app",
    "timer/arm": "app",
    "timer/clear": "app",
    "link/open": "link",
    "link/send": "link",
    "link/close": "link",
    "link/stat": "link",
} as const;
export type CapabilityName = keyof typeof AUTHORITY_CALLS;
/** Whether a name is one of the host's own authorities — membership in the table above,
 *  never a parse of the name's text. This is the question the seam's dispatch asks (is
 *  there a handler for this?) and the one `privilegesOf` reads a value through.
 *
 *  `crypto/*` and a bundle's own module names are false here by being absent rather than
 *  by their prefix: a primitive is a function of its arguments and a module is the asking
 *  bundle's own, so neither reaches anything a guest does not already hold (§12.1). */
export function isAuthority(name: string): name is CapabilityName {
    return Object.prototype.hasOwnProperty.call(AUTHORITY_CALLS, name);
}
/** A PRIVILEGE — the unit an operator grants and a policy file is keyed on (policy.ts).
 *
 *  Derived from the catalog rather than declared beside it: the table is where a name's
 *  authority is written down, so the set of things an operator must say yes to is a
 *  function of that table and cannot fall behind it. Add a privileged name under a new
 *  value and its policy key exists; there is nowhere to forget to add it. */
export type Privilege = Exclude<(typeof AUTHORITY_CALLS)[CapabilityName], "app">;
export const PRIVILEGES: readonly Privilege[] = [
    ...new Set(Object.values(AUTHORITY_CALLS).filter((p): p is Privilege => p !== "app")),
];
/** Raw links — the privilege the node's transport is built out of (§12.6). Named because
 *  the shell wires the socket driver to whatever holds it — the one privilege whose grant
 *  also stands a host-side object up — not because admission treats it specially: to the
 *  policy it is one key among `PRIVILEGES`. */
export const PRIVILEGE_LINK = "link" satisfies Privilege;
// ── Reserved protocol ids: the cross-realm call ─────────────────────────────────
//
// A guest reaches another realm the same way an inbound frame does — by a protocol id,
// resolved through the routing the manifests already define (§12.10). Only a RESERVED
// id is callable, and the format already reserves them: a claim is held to an
// alphanumeric first character (bundle.ts), so a `_`-led id is one no ordinary app can
// spell. That is the whole of the rule, and it was already half-written.
//
// Two consequences worth stating, because they are what make the call safe rather than
// merely short. A guest→guest call never runs the callee inside the caller's frame —
// the callee is invoked on a later turn and the caller's promise is settled with what it
// returns, exactly as `fs/*` settles. And a callable id is a GRANT: it is declared in
// the manifest's `requires` like any authority, so the call graph an operator can read
// off the bundles is the call graph, and it stays acyclic because no id reaches back.
/** A reserved id — one the runtime answers or routes ahead of ordinary dispatch, and one
 *  no bundle's `protocols` may spell unless it holds the privilege that owns it. The test
 *  is the first character, which is also the charset rule (§12.10). */
export function isReservedProtocol(name: string): boolean {
    return name.charCodeAt(0) === 0x5f; // "_"
}
/** The id the transport claims, and the one every app's outbound network call names. It
 *  is an ordinary protocol claim — the transport is reached by the same call the host uses
 *  to dispatch an inbound frame, with the caller's app key prepended exactly as the
 *  sender's key is prepended inbound. */
export const NET_PROTOCOL = "_net";
/** The id the SHELL answers itself, ahead of dispatch — the transport's way back to the host
 *  for the two things that are genuinely pushes: a peer's cohort edge, and the teardown
 *  of a link the host handed over. Reserved for the same reason `_net` is, and answered
 *  by the shell rather than routed, which is exactly what §12.10 sets `_`-led ids aside
 *  for. */
export const SHELL_PROTOCOL = "_host";
/** Whether a name is a *grant* — the one question the seam's gate asks, and exactly what
 *  a manifest may declare in `guest.requires`. Two kinds, because there are two kinds of
 *  thing a guest cannot reach on its own: an authority the host owns, and a reserved id
 *  that reaches another realm. Everything else — `crypto/*`, the bundle's own modules —
 *  is false here and is not declarable, because neither can be absent from a host and a
 *  requirement on what cannot fail states nothing (§12.1). */
export function isGrant(name: string): boolean {
    return isAuthority(name) || isReservedProtocol(name);
}
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
// the AKE, which is entirely the transport bundle's program (transport/src/ake.js declares
// its own), so it is content: replaceable by shipping a new signed bundle, on its own
// clock. They are independent namespaces and always were; the channel half sat here only
// as a leftover of the pre-bundle transport. See §14.1, and docs/PROTOCOL.md for the
// channel suite ids themselves.
/** Bundle manifest (§12.4), and the ONLY manifest suite: **hybrid** Ed25519 + ML-DSA-65
 *  (FIPS 204). Both signatures are made over `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖
 *  json` and **both must verify** — the classical half stays load-bearing while the PQ
 *  half is young, so a flaw in ML-DSA fails *closed* (valid bundles rejected) rather than
 *  open (forged bundles admitted), and the bundle is no weaker than a classical-only one
 *  against a classical attacker (§14.1).
 *
 *  This is the migration that can never get cheaper than a coordinated rebuild: a PQ
 *  verifier cannot be delivered as a bundle, because the classical verifier would be
 *  the thing admitting it. So it goes into the artifact *ahead* of need, unlike the
 *  channel suite, which is content and can wait for a credible break (§14.1).
 *
 *  `0x01` was the Ed25519-only genesis suite and is **retired, not deprecated**: every
 *  target ships the PQ verifier and every artifact is built hybrid, so a second live
 *  value would have bought a second envelope branch, a second author-id derivation and a
 *  policy dial to eventually turn it off — machinery whose entire purpose was migrating a
 *  population that never existed. The byte is spent (§14.1): a later suite takes `0x03`,
 *  and an envelope opening `0x01` is refused as the unknown suite it now is. */
export const SUITE_MANIFEST_HYBRID_PQ = 0x02;
