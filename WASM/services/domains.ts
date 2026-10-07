// Signing prefixes and suite ids (§16.1). Every prefix ends in NUL, and they all live in
// this one file so their disjointness can be checked in one place. Native evaluates this
// same file (§12.9).
import { enc } from "./util.js";
const domain = (s: string) => enc.encode(s);
/** Bundle manifest (§12.4), so a manifest signature cannot be reused as any other
 *  signature. */
export const DOMAIN_MANIFEST = domain("seedkernel-manifest-sig-v1\0");
/** Bundle manifest author id (§12.4). The only prefix here that goes into a hash instead
 *  of a signature, so it must stay disjoint from every signing prefix. */
export const DOMAIN_MANIFEST_AUTHOR = domain("seedkernel-manifest-author-v1\0");
/** Guest-seam signing (§12.2), so a guest's signatures stay in its app's namespace and
 *  the node key cannot be used as a general signing oracle. */
export const DOMAIN_GUEST = domain("seedkernel-guest-sig-v1\0");
/** Guest-seam signing for the slot holding `link` (§12.2, §12.6): that slot's signatures
 *  stay in the link domain, never in an app's namespace. */
export const DOMAIN_LINK_SCOPE = domain("seedkernel-link-scope-v1\0");
/** Subkey derivation (§12.6.2b): its own domain so a derived seed never equals any other
 *  hash this system computes. */
export const DOMAIN_SUBKEY = domain("seedkernel-subkey-v1\0");
/** Author ML-DSA seed label (§16.1). KDF tag, not a signing prefix. */
export const AUTHOR_MLDSA_SEED_LABEL = domain("seedkernel-author-mldsa-v1");
/** Host crypto transforms available to every guest without declaring them. New transforms
 *  belong in bundles, not here. Each of these stays because the host already ships the
 *  implementation, and a module cannot use the host's copy without exposing the memory
 *  the node key lives in (docs/SECURITY.md), so the list cannot shrink further.
 *
 *  Each exposes its algorithm's full standard interface (RFC 7693, RFC 8439), so a
 *  replacement transport can build a standard protocol without a host release
 *  (tests/noise-vectors.js). */
export const HOST_TRANSFORM_NAMES = [
  "blake2b",
  "chacha20poly1305-ietf/seal",
  "chacha20poly1305-ietf/open",
  "x25519/dh",
  "random",
] as const;

export type HostTransformName = (typeof HOST_TRANSFORM_NAMES)[number];
/** Host-service ABI (§12.2): `calls` go to the host; `events` go to the service occupant.
 *  Only what a confined realm cannot do itself; time and entropy need no declaration. */
export const HOST_SERVICES = {
  node: { calls: ["sign", "verify"] },
  fs: { calls: ["get", "put", "list", "delete", "size", "stat"] },
  timer: { calls: ["arm", "clear"] },
  link: {
    calls: ["open", "send", "close", "deliver", "status"],
    events: ["linkOpen", "linkBytes", "linkClosed"],
  },
} as const;
export type ServiceName = keyof typeof HOST_SERVICES;
/** Services with `events` have one occupant per node (slot-table.ts). */
export function isOccupiedService(name: string): boolean {
  return isService(name) && "events" in HOST_SERVICES[name];
}
export const LINK_EVENTS = HOST_SERVICES.link.events;
export type LinkEvent = (typeof LINK_EVENTS)[number];
/** One service's `service/call` vocabulary, typing its handlers (guest-seam.ts). */
export type ServiceMethod<S extends ServiceName> = `${S}/${(typeof HOST_SERVICES)[S]["calls"][number]}`;
/** Whether a name is a host service, by own-property check. */
export function isService(name: string): name is ServiceName {
  return Object.prototype.hasOwnProperty.call(HOST_SERVICES, name);
}
/** Whether the text before a name's first `/` is a host namespace (a service or `crypto`),
 *  where a local service id may not live (bundle.ts `validateManifest`). */
export function isHostNamespace(head: string): boolean {
  return head === "crypto" || isService(head);
}
// Manifest suite: first byte of the envelope, covered by the signature. The channel suite
// lives in the transport bundle (ake.js), not here (§14.1).
/** Hybrid Ed25519 + ML-DSA-65; both must verify. */
export const SUITE_MANIFEST_HYBRID_PQ = 0x02;
