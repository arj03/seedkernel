// domains.ts — the signing-domain prefix family (README §16.1).
//
// Every signature this runtime makes commits to one of these prefixes before the
// message bytes. Their one job is disjointness: a signature made in one context —
// bundle manifest (§12.4), guest SIGN (§12.2), channel AUTH (§12.6) — must never
// verify in another, even over identical bytes, even when an attacker chooses the
// bytes. That is a property of the whole set, so the set lives in one file; adding a
// member means checking it against every other. Keep:
//   - a distinct literal, versioned (`-v1`); the trailing NUL (no member's body
//     contains one) keeps no member a prefix of another
//   - prepended before signing and verifying, never transmitted — zero wire cost
//
// The Go/native loader evaluates this very file via the generated bundles (§12.9),
// so its prefixes match by construction, not by a hand-copied constant.

const domain = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Bundle manifest (§12.4): prefixes the manifest JSON, so a manifest signature
 *  can't double as an envelope wrapper over the same bytes. */
export const DOMAIN_MANIFEST = domain("seedkernel-manifest-sig-v1\0");

/** Cap-bridge SIGN (§12.2): prefixes `scope ‖ msg`, scope host-derived from the
 *  manifest — a guest's signature stays in its bundle's namespace, not a key oracle. */
export const DOMAIN_GUEST = domain("seedkernel-guest-sig-v1\0");

/** Channel AUTH (§12.6): prefixes the AKE transcript, so an AUTH signature names
 *  one connection and no other. */
export const DOMAIN_CHANNEL = domain("seedkernel-channel-id-v1\0");
