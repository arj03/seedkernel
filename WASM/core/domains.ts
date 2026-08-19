// domains.ts — the identifiers that bind a signature to its construction (README §16.1).
//
// Two families, answering "which cryptographic construction is this signature part of?" at
// two levels: a *domain prefix* separates signing contexts, a *suite id* names the
// algorithms inside one. Both are covered by the signature that carries them.
//
// Every signature this runtime makes commits to a domain prefix before the message bytes,
// and their one job is disjointness — a signature made in one context must never verify in
// another, even over attacker-chosen bytes. That is a property of the whole SET, so the set
// lives in one file and adding a member means checking it against every other. Each is a
// distinct versioned literal ending in a NUL (no member's body contains one, so none is a
// prefix of another), prepended before signing and never transmitted.
//
// The native loader evaluates this very file (§12.9), so its prefixes match by
// construction rather than by a hand-copied constant.
import { enc } from "./util.js";
const domain = (s: string) => enc.encode(s);
/** Bundle manifest (§12.4): prefixes the manifest JSON, so a manifest signature
 *  can't double as an envelope wrapper over the same bytes. */
export const DOMAIN_MANIFEST = domain("seedkernel-manifest-sig-v1\0");
/** Bundle manifest author id (§12.4): prefixes the key material an author id is derived
 *  from (`hybridAuthorId`, bundle.ts). The one member of this family that prefixes a *hash*
 *  rather than a signature, and it lives here because it must be disjoint from every
 *  signing prefix — a derived author id must never also be a preimage someone signed. */
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
/** Author key-set derivation (§12.4): hashed with an author's Ed25519 seed to get the
 *  ML-DSA-65 seed of the same identity, so one stored key is the whole author
 *  (`hybridAuthorKeysFromSeed`, bundle.ts).
 *
 *  **These bytes are frozen.** The author id is a hash over both public keys, so changing
 *  the label re-identifies *every* author built from a seed: new app keys, a dead freshness
 *  lineage, and every pinned id in every policy file pointing at nobody. A KDF label rather
 *  than a signing prefix, hence no trailing NUL. */
export const AUTHOR_MLDSA_SEED_LABEL = domain("seedkernel-author-mldsa-v1");
// ── The guest seam's version ────────────────────────────────────────────────────
/** The guest ABI version — the shape of `host.call`, its sync/async boundary, payload
 *  framing, entrypoint protocol and preamble globals (§12.2). A bundle declares it in
 *  `BundleGuest.abi` and the loader refuses a shape it does not implement.
 *
 *  The preamble exposes the author's signed JSON as `APP` and this installation's
 *  per-load JSON as `LOCAL`. `link/config` contains immutable node identity and deployment
 *  limits; mutable addresses arrive as `addr` events. Bare module calls are asynchronous
 *  so the host can bound them (§4.3).
 *
 *  Adding a catalog name does not change the ABI. Changing an existing name, framing or
 *  preamble meaning does. The constant lives with the suite ids so manifest verification
 *  need not import the seam implementation; guest-seam.ts re-exports it. */
export const GUEST_ABI_VERSION = 8;
/** The crypto primitives this host serves through the `crypto/` prefix — the pure half of
 *  the seam, and NOT something a manifest declares: `cryptoCatalog` (guest-seam.ts) is
 *  total over this list, so a partial catalog is unrepresentable and there is nothing for a
 *  bundle to require. guest-seam.ts's table keys are the template literal over this list,
 *  so the names and the transforms cannot drift.
 *
 *  Adding a name here is the whole cost of a new algorithm — no op number, no ABI rev, no
 *  manifest field — which is why the vocabulary is provisioned ahead of need (§14.1): a
 *  bundle is replaceable, the vocabulary it draws on is not. */
export const PRIMITIVE_NAMES = [
    "blake2b-256",
    "ed25519/verify",
    "xchacha20/xor",
    "chacha20poly1305-ietf/seal",
    "chacha20poly1305-ietf/open",
    "x25519/dh",
    // ML-KEM-768 (FIPS 203), provisioned AHEAD of any caller — the point of the rule
    // above. The channel's post-quantum suite is content (a signed transport bundle plus a
    // policy entry), but only once its primitive exists on all three targets, and a
    // primitive is the one thing that cannot be delivered as a bundle.
    //
    // Derandomized like every other entry: the coins are an argument, drawn by the guest
    // from `node/random`, so the catalog stays purely functional.
    "ml-kem-768/keypair",
    "ml-kem-768/encaps",
    "ml-kem-768/decaps",
] as const;

export type PrimitiveName = (typeof PRIMITIVE_NAMES)[number];
/** The authorities: every name that reaches something no confined guest can hold — the node
 *  key (`node/sign` is scoped, never raw), the entropy source, a socket, the disk, the
 *  clock, the event loop. With the reserved ids below they are the manifest vocabulary, so
 *  the list an operator reads is the list of what a bundle can reach.
 *
 *  `crypto/*` and a bundle's own module names are absent, and that absence is the gate rule:
 *  a name is a grant iff it is a key here or a reserved id (`isGrant`), so the dispatcher
 *  never parses a name to decide whether it is granted (§12.1). Neither can be absent from
 *  a host, so declaring them would state nothing while burying the few names that carry
 *  real authority.
 *
 *  **Every key here must contain a `/`, and no module name may lead with `_`.** Those two
 *  charset rules are what let ONE `host.call` carry three kinds of name, told apart by the
 *  name alone. `crypto/*` gets its slash from its template literal; this table is
 *  hand-written, so guest-seam.ts checks it at construction — a bare authority here would
 *  shadow every app's module of that name.
 *
 *  Each name's VALUE is what it is granted for. `"app"` is the unprivileged case, needing
 *  no operator grant beyond the right to load at all; anything else names a PRIVILEGE an
 *  operator grants per author (`PRIVILEGES`, policy.ts). Today there is one, `link`.
 *  `timer/*` is deliberately `"app"` — the transport happening to want one is not a reason
 *  to make it a privilege.
 *
 *  A privilege is one thing, not a pair of halves: what the transport PROVIDES back is not
 *  an authority but an ordinary cross-realm call to the id it claims. So a name's value is
 *  a privilege or it is `"app"`, and there is no role field — the requires carry the fact
 *  and the signature covers them.
 *
 *  The one-file rule: the seam's dispatch table is TYPED against `CapabilityName` and
 *  walked against its own key set at construction, so adding a name here is the whole cost
 *  of a new op. */
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
    "link/config": "link",
    "link/open": "link",
    "link/send": "link",
    "link/close": "link",
    "link/stat": "link",
} as const;
export type CapabilityName = keyof typeof AUTHORITY_CALLS;
/** Whether a name is one of the host's own authorities — membership in the table above,
 *  never a parse of the name's text. `crypto/*` and a bundle's own modules are false here
 *  by being ABSENT rather than by their prefix. */
export function isAuthority(name: string): name is CapabilityName {
    return Object.prototype.hasOwnProperty.call(AUTHORITY_CALLS, name);
}
/** A PRIVILEGE — the unit an operator grants and a policy file is keyed on (policy.ts).
 *  Derived from the catalog rather than declared beside it, so the set of things an
 *  operator must say yes to cannot fall behind the table: add a privileged name under a new
 *  value and its policy key exists. */
export type Privilege = Exclude<(typeof AUTHORITY_CALLS)[CapabilityName], "app">;
export const PRIVILEGES: readonly Privilege[] = [
    ...new Set(Object.values(AUTHORITY_CALLS).filter((p): p is Privilege => p !== "app")),
];
/** Raw links — the privilege the node's transport is built out of (§12.6). Named because
 *  the shell wires the socket driver to whatever holds it, not because admission treats it
 *  specially: to the policy it is one key among `PRIVILEGES`. */
export const PRIVILEGE_LINK = "link" satisfies Privilege;
// ── Reserved protocol ids: the cross-realm call ─────────────────────────────────
//
// A guest reaches another realm the same way an inbound frame does — by a protocol id,
// resolved through the routing the manifests already define (§12.10). Only a RESERVED id
// is callable, and the format already reserves them: a claim is held to an alphanumeric
// first character (bundle.ts), so a `_`-led id is one no ordinary app can spell.
//
// Two consequences make the call safe rather than merely short. A guest→guest call never
// runs the callee inside the caller's frame — it is invoked on a later turn and settles the
// caller's promise, exactly as `fs/*` does. And a callable id is a GRANT, declared in
// `requires` like any authority, so the call graph an operator reads off the bundles is
// the call graph.
/** A reserved id — one routed between local realms ahead of ordinary dispatch. The
 *  spelling carries no authority on its own; two ids are singled out by name in
 *  `verifyManifest` — `_host`, which the shell answers rather than routes, and `_net`,
 *  which only a bundle reaching `link` may claim. The test is the first character, which
 *  is also the charset rule (§12.10). */
export function isReservedProtocol(name: string): boolean {
    return name.charCodeAt(0) === 0x5f; // "_"
}
/** The id the transport claims, and the one every app's outbound network call names. It is
 *  routed like any claim — the transport is reached by the same call the host uses to
 *  dispatch an inbound frame, with the caller's app key prepended exactly as the sender's
 *  key is prepended inbound. CALLING it is ungoverned, an ordinary `requires` entry any app
 *  may declare. CLAIMING it is not: this is where every accepted link's raw bytes are
 *  handed in, so `verifyManifest` refuses the claim to a bundle that does not reach
 *  `link`. */
export const NET_PROTOCOL = "_net";
/** The id the SHELL answers itself, ahead of dispatch — the transport's way back to the
 *  host for the things that are genuinely pushes: an inbound frame, and the auth or
 *  teardown of a link the host handed over. Answered rather than routed. */
export const SHELL_PROTOCOL = "_host";
/** Whether a name is a *grant* — the one question the seam's gate asks, and exactly what a
 *  manifest may declare in `guest.requires`. Two kinds, because there are two kinds of
 *  thing a guest cannot reach on its own: an authority the host owns, and a reserved id
 *  that reaches another realm. */
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
// structure's signature covers, so editing it in flight only makes the two sides compute
// different preimages. It is not negotiated — one suite per manifest, unknown ids refused —
// because its job is to make the format self-describing, which is what lets a later suite
// change every field width while old and new stay unambiguous.
//
// The CHANNEL suite is not here: a manifest suite is read by the loader before anything is
// trusted, so it is the host's to declare, while a channel suite is read by the AKE, which
// is entirely the transport bundle's program (transport/src/ake.js declares its own). See
// §14.1 and docs/PROTOCOL.md.
/** Bundle manifest (§12.4), and the ONLY manifest suite: **hybrid** Ed25519 + ML-DSA-65
 *  (FIPS 204). Both signatures are made over `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖
 *  json` and **both must verify** — the classical half stays load-bearing while the PQ
 *  half is young, so a flaw in ML-DSA fails *closed* (valid bundles rejected) rather than
 *  open (forged bundles admitted), and the bundle is no weaker than a classical-only one
 *  against a classical attacker (§14.1).
 *
 *  The one migration that can never get cheaper than a coordinated rebuild: a PQ verifier
 *  cannot be delivered as a bundle, because the classical verifier would be the thing
 *  admitting it. So it goes into the artifact *ahead* of need, unlike the channel suite.
 *
 *  `0x01` was the Ed25519-only genesis suite and is **retired, not deprecated** — every
 *  target ships the PQ verifier and every artifact is built hybrid, so a second live value
 *  would only have bought machinery for migrating a population that never existed. The byte
 *  is spent: a later suite takes `0x03`, and `0x01` is refused as an unknown suite. */
export const SUITE_MANIFEST_HYBRID_PQ = 0x02;
