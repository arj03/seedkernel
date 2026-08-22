// domains.ts — signing prefixes + suite ids (§16.1). Every prefix ends in NUL; the
// set lives in one file so disjointness is a property of the whole. Native evaluates
// this same file (§12.9).
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
/** Author ML-DSA seed label (§16.1). KDF tag, not a signing prefix — frozen. */
export const AUTHOR_MLDSA_SEED_LABEL = domain("seedkernel-author-mldsa-v1");
/** Guest ABI version (§12.2). Adding a catalog name does not bump it; changing a name,
 *  framing, or preamble meaning does. */
export const GUEST_ABI_VERSION = 11;
/** Guest `crypto/` catalog. Total over this list; not a grant. Adding a name is the whole cost of a new algorithm. */
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
/** The authorities. A name is a grant iff it is a key here or a reserved id (`isGrant`);
 *  `crypto/*` and the bundle's own modules are absent, and that absence is the gate.
 *  Every key must contain `/` (guest-seam.ts checks at construction). The value is the
 *  privilege an operator grants, or `"app"` for the unprivileged case. `timer/*` is
 *  `"app"` on purpose. */
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
    "link/authenticated": "link",
    "link/down": "link",
    "link/sign": "link",
    "link/verify": "link",
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
 *  among `PRIVILEGES`. The link occupant is the attributer: inbound delivery of a request
 *  the occupant decoded off its links is that slot's return convention, never a second
 *  privilege. */
export const PRIVILEGE_LINK = "link" satisfies Privilege;
// Reserved `_`-led ids: local cross-realm calls (§12.10). A claim cannot be `_`-led
// (bundle.ts). Callable, granted in `requires`, invoked on a later turn.
/** A reserved id — routed between local realms, never from remote delivery. */
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
const IRREVERSIBLE: ReadonlySet<string> = new Set<CapabilityName>(["fs/put", "fs/delete"]);
/** Names that leave something behind. Refused until the slot commits (§3.1). Reserved
 *  ids included. Reads, `crypto/*`, `timer/*`, `link/*` are not. */
export function isIrreversible(name: string): boolean {
    return IRREVERSIBLE.has(name) || isReservedProtocol(name);
}
// Manifest suite: first byte of the envelope, covered by the signature. Channel suite
// lives in the transport bundle (ake.js), not here — §14.1.
/** Hybrid Ed25519 + ML-DSA-65. Both must verify. `0x01` is retired; `0x03` is next. */
export const SUITE_MANIFEST_HYBRID_PQ = 0x02;
