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
 *  framing, or preamble meaning does — and neither does the callee's own format after
 *  the caller id, which is content. A guest declares `handle` and reads
 *  `[caller 32][body …]`; everything past the caller is its own, so no further inbound
 *  vocabulary grows here. */
export const GUEST_ABI_VERSION = 13;
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
/** The host SERVICES — the unit a manifest declares and an operator grants. Each key is
 *  everything before the first `/` of the method names it fronts; `calls` is dispatch
 *  vocabulary, not a second grant — a manifest cannot reach for `node/sign` without also
 *  reaching `node/verify`, so there was never a finer boundary to hold. The value is the
 *  privilege an operator grants, or `"app"` for the unprivileged case. `timer` is `"app"`
 *  on purpose. */
export const HOST_SERVICES = {
    node: { privilege: "app", calls: ["sign", "verify", "identity", "random"] },
    fs: { privilege: "app", calls: ["get", "put", "list", "delete", "size", "stat"] },
    clock: { privilege: "app", calls: ["now"] },
    timer: { privilege: "app", calls: ["arm", "clear"] },
    link: { privilege: "link", calls: ["open", "send", "close", "stat", "authenticated", "down"] },
} as const;
export type ServiceName = keyof typeof HOST_SERVICES;
/** The full `service/call` vocabulary, as a template-literal union over the table above —
 *  what the dispatch table's keys are typed against (guest-seam.ts `HandlerKey`). */
export type CapabilityName = {
    [S in ServiceName]: `${S}/${(typeof HOST_SERVICES)[S]["calls"][number]}`;
}[ServiceName];
/** The full `service/call` vocabulary, flattened to a runtime list — the dispatch-table
 *  completeness check (guest-seam.ts `HANDLER_KEYS`) and the "near names" hint on a
 *  refused manifest (bundle.ts) both walk this rather than the table shape. */
export const AUTHORITY_CALLS: readonly CapabilityName[] = (Object.keys(HOST_SERVICES) as ServiceName[]).flatMap(
    (s) => (HOST_SERVICES[s].calls as readonly string[]).map((c) => `${s}/${c}` as CapabilityName),
);
const AUTHORITY_SET: ReadonlySet<string> = new Set(AUTHORITY_CALLS);
/** Whether a name is one of the host's own methods — membership in the catalog above,
 *  never a parse of the name's text. Dispatch granularity: what the seam's handler table
 *  is keyed on, not what a manifest declares. */
export function isAuthority(name: string): name is CapabilityName {
    return AUTHORITY_SET.has(name);
}
/** Whether a name is a host SERVICE — the vocabulary a manifest's `guest.requires` may
 *  name. An own-property check on `HOST_SERVICES`, never a parse. */
export function isService(name: string): name is ServiceName {
    return Object.prototype.hasOwnProperty.call(HOST_SERVICES, name);
}
/** The service a host method belongs to, or null when `name` is not one — split at the
 *  FIRST `/` and looked up in the table, never a semantic read of the text either side of
 *  it. What the seam's gate checks a `host.call` name's SERVICE against (guest-seam.ts). */
export function serviceOf(name: string): ServiceName | null {
    const i = name.indexOf("/");
    if (i < 0) return null;
    const svc = name.slice(0, i);
    return isService(svc) ? (svc as ServiceName) : null;
}
/** A PRIVILEGE — the unit an operator grants and a policy file is keyed on (policy.ts).
 *  Derived from the catalog rather than declared beside it, so the set an operator must say
 *  yes to cannot fall behind the table. */
export type Privilege = Exclude<(typeof HOST_SERVICES)[ServiceName]["privilege"], "app">;
export const PRIVILEGES: readonly Privilege[] = [
    ...new Set(Object.values(HOST_SERVICES).map((s) => s.privilege).filter((p): p is Privilege => p !== "app")),
];
/** Raw links — the privilege the node's transport is built out of (§12.6). Named so the
 *  shell can wire the socket driver to whatever holds it; admission treats it as one key
 *  among `PRIVILEGES`. The link occupant is the attributer: inbound delivery of a request
 *  the occupant decoded off its links is that slot's return convention, never a second
 *  privilege. */
export const PRIVILEGE_LINK = "link" satisfies Privilege;
/** The methods that leave something behind. Typed against the catalog, so renaming
 *  a name here is a build error rather than a silently empty set. A LOCAL service id
 *  (§12.10) is irreversible by the same rule, applied at the slot that knows which bare
 *  names its manifest declared (`isIrreversible` here covers only the dispatch-level
 *  half; shell-core.ts's `seamFor` folds in the slot's own local services). */
const IRREVERSIBLE: ReadonlySet<string> = new Set<CapabilityName>(["fs/put", "fs/delete"]);
/** Names that leave something behind, at DISPATCH granularity — refused until the slot
 *  commits (§3.1). Reads, `crypto/*`, `timer/*`, `link/*` are not; a local service id is
 *  the caller's to add (shell-core.ts). */
export function isIrreversible(name: string): boolean {
    return IRREVERSIBLE.has(name);
}
// Manifest suite: first byte of the envelope, covered by the signature. Channel suite
// lives in the transport bundle (ake.js), not here — §14.1.
/** Hybrid Ed25519 + ML-DSA-65. Both must verify. `0x01` is retired; `0x03` is next. */
export const SUITE_MANIFEST_HYBRID_PQ = 0x02;
