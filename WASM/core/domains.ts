// domains.ts — signing prefixes + suite ids (§16.1). Every prefix ends in NUL; the set
// lives in one file so disjointness is a property of the whole. Native evaluates this
// same file (§12.9).
import { enc } from "./util.js";
const domain = (s: string) => enc.encode(s);
/** Bundle manifest (§12.4): so a manifest signature can't double as an envelope wrapper. */
export const DOMAIN_MANIFEST = domain("seedkernel-manifest-sig-v1\0");
/** Bundle manifest author id (§12.4): the one member that prefixes a *hash* rather than a
 *  signature, so it must stay disjoint from every signing prefix. */
export const DOMAIN_MANIFEST_AUTHOR = domain("seedkernel-manifest-author-v1\0");
/** Guest-seam SIGN (§12.2): a guest's signature stays in its bundle's namespace, not a
 *  key oracle. */
export const DOMAIN_GUEST = domain("seedkernel-guest-sig-v1\0");
/** Guest-seam SIGN for the slot holding the raw-link resource (§12.2, §12.6): that slot's
 *  signatures name one network and never an app's namespace. */
export const DOMAIN_LINK_SCOPE = domain("seedkernel-link-scope-v1\0");
/** Subkey derivation (§12.9): its own domain so a derived seed never coincides with any
 *  other hash this system computes. */
export const DOMAIN_SUBKEY = domain("seedkernel-subkey-v1\0");
/** Author ML-DSA seed label (§16.1). KDF tag, not a signing prefix. */
export const AUTHOR_MLDSA_SEED_LABEL = domain("seedkernel-author-mldsa-v1");
/** Residual guest-visible host transforms. This is legacy vocabulary, not a menu of computations:
 *  a pure transform belongs in the bundle that uses it. Keep a name here only while the
 *  host itself already carries and calls the same implementation. */
export const HOST_TRANSFORM_NAMES = [
    "blake2b-256",
    "chacha20poly1305-ietf/seal",
    "chacha20poly1305-ietf/open",
    "x25519/dh",
] as const;

export type HostTransformName = (typeof HOST_TRANSFORM_NAMES)[number];
/** Host-service ABI (§12.2): `calls` enter the host; `events` enter the service occupant. */
export const HOST_SERVICES = {
    node: { privilege: "app", calls: ["sign", "verify", "identity", "random"] },
    fs: { privilege: "app", calls: ["get", "put", "list", "delete", "size", "stat"] },
    clock: { privilege: "app", calls: ["now"] },
    timer: { privilege: "app", calls: ["arm", "clear"] },
    link: {
        privilege: "link",
        calls: ["open", "send", "close", "stat", "deliver"],
        events: ["linkOpen", "linkBytes", "linkClosed"],
    },
} as const;
export type ServiceName = keyof typeof HOST_SERVICES;
export const LINK_EVENTS = HOST_SERVICES.link.events;
export type LinkEvent = (typeof LINK_EVENTS)[number];
/** The full `service/call` vocabulary as a template-literal union — what the dispatch
 *  table's keys are typed against (guest-seam.ts `HandlerKey`). */
export type CapabilityName = {
    [S in ServiceName]: `${S}/${(typeof HOST_SERVICES)[S]["calls"][number]}`;
}[ServiceName];
/** The full vocabulary, flattened to a runtime list for the dispatch-table completeness
 *  check (guest-seam.ts `HANDLER_KEYS`). */
export const AUTHORITY_CALLS: readonly CapabilityName[] = (Object.keys(HOST_SERVICES) as ServiceName[]).flatMap(
    (s) => (HOST_SERVICES[s].calls as readonly string[]).map((c) => `${s}/${c}` as CapabilityName),
);
/** Whether a name is a host SERVICE — the vocabulary a manifest's `guest.requires` may
 *  name. An own-property check, never a parse. */
export function isService(name: string): name is ServiceName {
    return Object.prototype.hasOwnProperty.call(HOST_SERVICES, name);
}
/** The service a host method belongs to, or null. Split at the FIRST `/` and looked up in
 *  the table — what the seam's gate checks a `host.call` name against (guest-seam.ts). */
export function serviceOf(name: string): ServiceName | null {
    const i = name.indexOf("/");
    if (i < 0) return null;
    const svc = name.slice(0, i);
    return isService(svc) ? (svc as ServiceName) : null;
}
/** A PRIVILEGE — the unit an operator grants and a policy file is keyed on (policy.ts).
 *  Derived from the catalog rather than declared beside it, so the set an operator must
 *  say yes to cannot fall behind the table. */
export type Privilege = Exclude<(typeof HOST_SERVICES)[ServiceName]["privilege"], "app">;
export const PRIVILEGES: readonly Privilege[] = [
    ...new Set(Object.values(HOST_SERVICES).map((s) => s.privilege).filter((p): p is Privilege => p !== "app")),
];
/** The link privilege (§12.6), named so the shell can wire the socket driver to whatever
 *  holds it. The link occupant is the attributer: `link/deliver` hands the host a request
 *  it decoded off its own links, under this one privilege and never a second — the call
 *  names no link, and all three of its arguments are the occupant's own to choose. */
export const PRIVILEGE_LINK = "link" satisfies Privilege;
/** Methods that leave something behind, typed against the catalog so a rename here is a
 *  build error. Refused until the slot commits (§3.1). A LOCAL service id (§12.10) is
 *  irreversible by the same rule, folded in by shell-core.ts's `seamFor`. */
const IRREVERSIBLE: ReadonlySet<string> = new Set<CapabilityName>(["fs/put", "fs/delete"]);
export function isIrreversible(name: string): boolean {
    return IRREVERSIBLE.has(name);
}
/** Calls whose outstanding COUNT a caller's own logic already bounds (an app awaits its
 *  own fan-out, windowed by its own concurrency policy) but whose outstanding BYTES it
 *  does not: `link/deliver` is fired by the link occupant once per inbound frame it
 *  decodes, with no caller-side window between one peer's request and the next — so it
 *  is the one host.call a realm's own byte budget (realm-queue.ts) must meter. Every
 *  host.call still counts against that realm's COUNT budget regardless. */
const BYTE_METERED: ReadonlySet<string> = new Set<CapabilityName>(["link/deliver"]);
export function isByteMetered(name: string): boolean {
    return BYTE_METERED.has(name);
}
// Manifest suite: first byte of the envelope, covered by the signature. Channel suite
// lives in the transport bundle (ake.js), not here — §14.1.
/** Hybrid Ed25519 + ML-DSA-65, both must verify. `0x01` retired, `0x03` next. */
export const SUITE_MANIFEST_HYBRID_PQ = 0x02;
