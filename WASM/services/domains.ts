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
 *  signatures stay in the link domain and never an app's namespace. */
export const DOMAIN_LINK_SCOPE = domain("seedkernel-link-scope-v1\0");
/** Subkey derivation (§12.9): its own domain so a derived seed never coincides with any
 *  other hash this system computes. */
export const DOMAIN_SUBKEY = domain("seedkernel-subkey-v1\0");
/** Author ML-DSA seed label (§16.1). KDF tag, not a signing prefix. */
export const AUTHOR_MLDSA_SEED_LABEL = domain("seedkernel-author-mldsa-v1");
/** Residual guest-visible host transforms, ungated. Not a menu: a new transform belongs in
 *  its bundle. A name stays only while the host already ships the implementation, and a
 *  module cannot borrow the host's copy without exposing the memory the node key lives in
 *  (docs/SECURITY.md), so this list is at its floor.
 *
 *  Each takes its algorithm's whole standard interface (RFC 7693, RFC 8439), so a
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
/** Host-service ABI (§12.2): `calls` enter the host; `events` enter the service occupant.
 *  Only what a confined realm cannot reach for itself; time and entropy are ungated. */
export const HOST_SERVICES = {
  node: { calls: ["sign", "verify"] },
  fs: { calls: ["get", "put", "list", "delete", "size", "stat"] },
  timer: { calls: ["arm", "clear"] },
  link: {
    calls: ["open", "send", "close", "deliver"],
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
/** The full `service/call` vocabulary, typing the dispatch table (guest-seam.ts). */
export type HostMethod = {
  [S in ServiceName]: `${S}/${(typeof HOST_SERVICES)[S]["calls"][number]}`;
}[ServiceName];
/** Whether a name is a host service, by own-property check. */
export function isService(name: string): name is ServiceName {
  return Object.prototype.hasOwnProperty.call(HOST_SERVICES, name);
}
/** Whether the text before a name's first `/` is a host namespace (a service or `crypto`),
 *  where a local service id may not live (bundle.ts `validateManifest`). */
export function isHostNamespace(head: string): boolean {
  return head === "crypto" || isService(head);
}
/** The service a host method belongs to (text before the first `/`), or null. */
export function serviceOf(name: string): ServiceName | null {
  const i = name.indexOf("/");
  if (i < 0) return null;
  const svc = name.slice(0, i);
  return isService(svc) ? (svc as ServiceName) : null;
}
// Manifest suite: first byte of the envelope, covered by the signature. Channel suite
// lives in the transport bundle (ake.js), not here — §14.1.
/** Hybrid Ed25519 + ML-DSA-65, both must verify. `0x01` retired, `0x03` next. */
export const SUITE_MANIFEST_HYBRID_PQ = 0x02;
