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
/** The crypto primitives this host serves through the `crypto/` prefix — the pure half
 *  of the seam, and **not** something a manifest declares. `cryptoCatalog` (cap-bridge.ts)
 *  is total over this list: a host that has that file has every name in it, so a partial
 *  catalog is unrepresentable and there is nothing for a bundle to require. What a guest
 *  needs from the pure half is covered by `abi` — the version of the seam it was written
 *  against, which is the version of everything in it.
 *
 *  Here rather than in cap-bridge.ts for exactly the reason `GUEST_ABI_VERSION` is: it
 *  belongs with the vocabulary, and cap-bridge.ts's table keys are the template literal
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
 *  the platform's clock and event loop. This IS the manifest vocabulary: `guest.requires`
 *  names a subset of these keys and nothing else, so the list an operator reads is the
 *  list of what the bundle can reach.
 *
 *  `crypto/*` and `module/call` are not here, and that absence is the whole gate rule: a
 *  name is a grant iff it is a key of this table (`isGrant`), so the dispatcher never
 *  parses a name to decide (§12.1). They are also, for the same reason, not declarable —
 *  a manifest naming one is refused. Neither can be absent from a host (`cryptoCatalog`
 *  is total; a bundle's modules arrive with it), so requiring them would be a requirement
 *  on something that cannot fail, and it would bury the three or four names that carry
 *  the bundle's actual authority under a dozen that carry none.
 *
 *  Each name carries what it is granted *for*, which is the whole of the mount rule:
 *  `"app"` is an ordinary authority any bundle may ask for, and a `"mount:…"` value
 *  says the name is the transport mount's alone (§12.5) and which half of a transport
 *  it supplies — `mount:sockets` is what the mount consumes (the platform's whole
 *  contribution to the network, behind opaque link ids), `mount:report` is what it
 *  provides back (the attributed peer, protocol id and correlation every app's `net`
 *  names reach). A mount must name both halves or neither: a bundle with sockets and
 *  nowhere to report could only stand as a transport that is not one, so a partial
 *  claim is refused at the load rather than at the first dial. `timer/*` is
 *  deliberately `"app"` — an ordinary authority, and the transport happening to want
 *  one is not a reason to make it a privilege.
 *
 *  The table IS what says which bundle is the mount; there is no role field, because
 *  the requires already carry the fact and the signature already covers them.
 *
 *  The one-file rule: the bridge's dispatch table is TYPED against `CapabilityName`
 *  (a key here without a handler is a compile error) and walked against its own key
 *  set at construction (the compiled-JS half the native target evaluates, and the
 *  check a typo'd extra key trips). Adding a name here is the whole cost of a new op. */
export const AUTHORITY_CALLS = {
    "node/sign": "app",
    "node/identity": "app",
    "node/random": "app",
    "net/send": "app",
    "net/peers": "app",
    "fs/get": "app",
    "fs/put": "app",
    "fs/list": "app",
    "fs/delete": "app",
    "fs/size": "app",
    "fs/stat": "app",
    "clock/now": "app",
    "timer/arm": "app",
    "timer/clear": "app",
    "link/open": "mount:sockets",
    "link/send": "mount:sockets",
    "link/close": "mount:sockets",
    "link/stat": "mount:sockets",
    "transport/deliver": "mount:report",
    "transport/settle": "mount:report",
    "transport/link-auth": "mount:report",
    "transport/peer-edge": "mount:report",
    "transport/ready": "mount:report",
    "transport/link-down": "mount:report",
} as const;
export type CapabilityName = keyof typeof AUTHORITY_CALLS;
/** Whether a name is a *grant* — the one question the bridge's gate asks, and the one
 *  the manifest does not answer. `crypto/*` and `module/call` are false here by being
 *  absent from `AUTHORITY_CALLS` rather than by a parse of their prefix: a primitive is
 *  a function of its arguments and a module is the asking bundle's own, so neither
 *  reaches anything a guest does not already hold (§12.1). */
export function isGrant(name: string): name is CapabilityName {
    return Object.prototype.hasOwnProperty.call(AUTHORITY_CALLS, name);
}
/** The mount halves (§12.5), derived from the catalog so there is no second list to
 *  keep in step with the names. A manifest naming any mount-only authority is the
 *  transport mount, governed by the policy's transport half rather than its app half;
 *  `mountGroups` (bundle.ts) is the ONE predicate both admission paths ask, and a mount
 *  must cover every group here. */
export type MountGroup = Exclude<(typeof AUTHORITY_CALLS)[CapabilityName], "app">;
export const MOUNT_GROUPS: readonly MountGroup[] = [
    ...new Set(Object.values(AUTHORITY_CALLS).filter((g): g is MountGroup => g !== "app")),
];
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
