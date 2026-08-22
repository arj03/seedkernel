// domains.ts — the identifiers binding a signature to its construction (README §16.1).
// Domain prefixes separate signing contexts, suite ids name the algorithms inside one, and
// the signature covers both. Every prefix is a distinct versioned literal ending in a NUL
// (no member's body contains one, so no prefix is a prefix of another), never transmitted.
// The set lives in one file because disjointness is a property of the whole; the native
// loader evaluates this very file (§12.9), so prefixes match by construction rather than a
// hand-copied constant.
import { enc } from "./util.js";
const domain = (s: string) => enc.encode(s);
/** Bundle manifest (§12.4): prefixes the manifest JSON, so a manifest signature
 *  can't double as an envelope wrapper over the same bytes. */
export const DOMAIN_MANIFEST = domain("seedkernel-manifest-sig-v1\0");
/** Bundle manifest author id (§12.4): prefixes the key material an author id is derived
 *  from (`hybridAuthorId`, bundle.ts) — the one member that prefixes a *hash* rather than a
 *  signature, so it must stay disjoint from every signing prefix. */
export const DOMAIN_MANIFEST_AUTHOR = domain("seedkernel-manifest-author-v1\0");
/** Guest-seam SIGN (§12.2): prefixes `scope ‖ msg`, scope host-derived from the manifest —
 *  a guest's signature stays in its bundle's namespace, not a key oracle. */
export const DOMAIN_GUEST = domain("seedkernel-guest-sig-v1\0");
/** Guest-seam SIGN for the slot holding the raw-link resource (§12.2, §12.6): prefixes
 *  the network key, so that slot's signatures name one network and never an app's
 *  namespace — the kernel owns the separation, nothing else. The format signed under it is
 *  the occupant's, carried in the opaque suffix the host never reads. */
export const DOMAIN_LINK_SCOPE = domain("seedkernel-link-scope-v1\0");
/** Subkey derivation (§12.9): `DOMAIN_subkey ‖ label ‖ master` hashed to a seed. Its own
 *  domain so a derived seed never coincides with any other hash this system computes. */
export const DOMAIN_SUBKEY = domain("seedkernel-subkey-v1\0");
/** Author key-set derivation (§12.4): hashed with an author's Ed25519 seed to get the
 *  ML-DSA-65 seed of the same identity, so one stored key is the whole author
 *  (`hybridAuthorKeysFromSeed`, bundle.ts). A KDF label rather than a signing prefix,
 *  hence no trailing NUL.
 *
 *  **These bytes are frozen.** The author id is a hash over both public keys, so changing
 *  the label re-identifies every author built from a seed: new app keys, a dead freshness
 *  lineage, and every pinned id in every policy file pointing at nobody. */
export const AUTHOR_MLDSA_SEED_LABEL = domain("seedkernel-author-mldsa-v1");
// ── The guest seam's version ────────────────────────────────────────────────────
/** The guest ABI version — the shape of `host.call`, its sync/async boundary, payload
 *  framing, entrypoint protocol and preamble globals (§12.2). A bundle declares it in
 *  `BundleGuest.abi` and the loader refuses a shape it does not implement. Preamble:
 *  the author's signed JSON as `APP`, this installation's per-load JSON as `LOCAL`;
 *  `link/config` is immutable node identity, mutable addresses arrive as `addr` events.
 *  Adding a catalog name does not change the ABI; changing an existing name, framing or
 *  preamble meaning does. */
export const GUEST_ABI_VERSION = 9;
/** The crypto primitives this host serves through the `crypto/` prefix — the pure half of
 *  the seam, and NOT something a manifest declares: `cryptoCatalog` (guest-seam.ts) is
 *  total over this list, so a partial catalog is unrepresentable and there is nothing for a
 *  bundle to require. Adding a name here is the whole cost of a new algorithm — no op
 *  number, no ABI rev, no manifest field — which is why the vocabulary is provisioned ahead
 *  of need (§14.1). */
export const PRIMITIVE_NAMES = [
    "blake2b-256",
    "ed25519/verify",
    "xchacha20/xor",
    "chacha20poly1305-ietf/seal",
    "chacha20poly1305-ietf/open",
    "x25519/dh",
    // ML-KEM-768 (FIPS 203), provisioned ahead of any caller — the point of the rule above: a
    // primitive is the one thing that cannot be delivered as a bundle. Derandomized like
    // every other entry — the coins come from `node/random`, so the catalog stays purely
    // functional.
    "ml-kem-768/keypair",
    "ml-kem-768/encaps",
    "ml-kem-768/decaps",
] as const;

export type PrimitiveName = (typeof PRIMITIVE_NAMES)[number];
/** The authorities: every name that reaches something no confined guest can hold — the node
 *  key (`node/sign` is scoped, never raw), the entropy source, a socket, the disk, the
 *  clock, the event loop. With the reserved ids below they are the manifest vocabulary. A
 *  name is a grant iff it is a key here or a reserved id (`isGrant`); the dispatcher never
 *  parses a name to decide (§12.1). `crypto/*` and a bundle's own modules are absent, and
 *  that absence is the gate rule.
 *
 *  **Every key here must contain a `/`, and no module name may lead with `_`** — those two
 *  charset rules are what let one `host.call` carry three kinds of name, told apart by the
 *  name alone. This table is hand-written, so guest-seam.ts checks it at construction.
 *
 *  Each name's VALUE is what it is granted for: `"app"` is the unprivileged case, needing
 *  no operator grant beyond the right to load at all; anything else names a PRIVILEGE an
 *  operator grants per author (`PRIVILEGES`, policy.ts). Raw links and claim delivery are
 *  deliberately separate privileges, and `timer/*` is deliberately `"app"` — the transport
 *  happening to want one is not a reason to make it a privilege. A privilege is one thing,
 *  not a pair of halves: what the transport provides back is an ordinary cross-realm call,
 *  so there is no role field. The seam's dispatch table is typed against
 *  `CapabilityName`, which is how the catalog and the implementation cannot drift. */
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
    "link/authenticated": "link",
    "link/down": "link",
    "link/sign": "link",
    "link/verify": "link",
    "route/deliver": "route",
} as const;
export type CapabilityName = keyof typeof AUTHORITY_CALLS;
/** Whether a name is one of the host's own authorities — membership in the table above,
 *  never a parse of the name's text. */
export function isAuthority(name: string): name is CapabilityName {
    return Object.prototype.hasOwnProperty.call(AUTHORITY_CALLS, name);
}
/** A PRIVILEGE — the unit an operator grants and a policy file is keyed on (policy.ts).
 *  Derived from the catalog rather than declared beside it, so the set an operator must say
 *  yes to cannot fall behind the table. */
export type Privilege = Exclude<(typeof AUTHORITY_CALLS)[CapabilityName], "app">;
export const PRIVILEGES: readonly Privilege[] = [
    ...new Set(Object.values(AUTHORITY_CALLS).filter((p): p is Privilege => p !== "app")),
];
/** Raw links — the privilege the node's transport is built out of (§12.6). Named so the
 *  shell can wire the socket driver to whatever holds it; admission treats it as one key
 *  among `PRIVILEGES`. */
export const PRIVILEGE_LINK = "link" satisfies Privilege;
/** Submission to the local claim router. Separate from raw links: possessing a link does
 *  not entitle a guest to invent attributed inbound requests. */
export const PRIVILEGE_ROUTE = "route" satisfies Privilege;
// ── Reserved protocol ids: the cross-realm call ─────────────────────────────────
//
// A guest reaches another realm as an inbound frame does — by a reserved protocol id,
// resolved through the routing the manifests already define (§12.10). A `_`-led id is
// callable and a claim cannot be `_`-led (bundle.ts), so the format reserves them. Two
// consequences make it safe rather than merely short: the call runs on a later turn and
// settles the caller's promise exactly as `fs/*` does, and a callable id is a GRANT
// declared in `requires` like any authority, so the call graph an operator reads off the
// bundles is the call graph.
/** A reserved id — one routed between local realms rather than accepted from a remote
 *  delivery. Its spelling carries no authority. */
export function isReservedProtocol(name: string): boolean {
    return name.charCodeAt(0) === 0x5f; // "_"
}
/** Whether a name is a *grant* — the question the seam's gate asks, and exactly what a
 *  manifest may declare in `guest.requires`: an authority the host owns, or a reserved id
 *  that reaches another realm. */
export function isGrant(name: string): boolean {
    return isAuthority(name) || isReservedProtocol(name);
}
/** The authorities that leave something behind. Typed against the catalog, so renaming a
 *  name here is a build error rather than a silently empty set. */
const IRREVERSIBLE: ReadonlySet<string> = new Set<CapabilityName>(["fs/put", "fs/delete", "route/deliver"]);
/** Whether reaching this name outlives the realm that reached it. The shell's seam refuses
 *  these until a slot's installation commits (shell-core.ts): a candidate evaluates its top
 *  level before the freshness mark and its claims land, and disposing that candidate is the
 *  only undo the shell has. A reserved id is one — the callee has run. Nothing else needs
 *  an entry: reads and `crypto/*` leave nothing behind, `timer/*` dies with the realm, and
 *  `link/*` answers only the slot that owns the raw-link binding. */
export function isIrreversible(name: string): boolean {
    return IRREVERSIBLE.has(name) || isReservedProtocol(name);
}
// ── The manifest suite ──────────────────────────────────────────────────────────
//
// A suite id is the first byte of the structure it governs and part of what that structure's
// signature covers, so editing it in flight only makes the two sides compute different
// preimages. It is not negotiated — one suite per manifest, unknown ids refused — because
// its job is to make the format self-describing, which is what lets a later suite change
// every field width while old and new stay unambiguous.
//
// The channel suite is not here: a manifest suite is read by the loader before anything is
// trusted, so the host declares it; a channel suite is read by the AKE, entirely the
// transport bundle's program (transport/src/ake.js declares its own). See §14.1 and
// docs/PROTOCOL.md.
/** Bundle manifest (§12.4), and the ONLY manifest suite: **hybrid** Ed25519 + ML-DSA-65
 *  (FIPS 204). Both signatures are over `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖
 *  json` and **both must verify** — the classical half stays load-bearing while the PQ
 *  half is young, so a flaw in ML-DSA fails *closed* (valid bundles rejected) rather than
 *  open (forged bundles admitted), and the bundle is no weaker than a classical-only one
 *  against a classical attacker (§14.1). A PQ verifier cannot be delivered as a bundle —
 *  the classical verifier would be the thing admitting it — so it goes into the artifact
 *  ahead of need, unlike the channel suite.
 *
 *  `0x01` was the Ed25519-only genesis suite and is **retired, not deprecated**: every
 *  target ships the PQ verifier and every artifact is built hybrid, so a second live value
 *  would only have bought machinery for migrating a population that never existed. `0x03`
 *  is next. */
export const SUITE_MANIFEST_HYBRID_PQ = 0x02;
