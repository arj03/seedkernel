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

// ── Algorithm suites ────────────────────────────────────────────────────────────
//
// A suite id is the first byte of the structure it governs *and* part of what that
// structure's signature covers, so an attacker can never edit it in flight: doing so
// only makes the two sides compute different preimages and the verify fail. Neither is
// negotiated — one suite per link, one per manifest, unknown ids refused — because the
// id's job is to make the format *self-describing*, not to pick between formats. That is
// what lets a later suite change every field width (an ML-KEM-768 encapsulation key is
// 1184 bytes where X25519 uses 32) while old and new stay unambiguous on the wire.
//
// The two are INDEPENDENT namespaces on independent clocks, and that is the whole reason
// they are named apart rather than sharing one constant. The channel suite protects a
// live key exchange, so it is exposed to harvest-now-decrypt-later and is the one under
// time pressure; the manifest suite protects an at-rest signature, which has no
// retroactive attack and can migrate late. They both read `0x01` today only because each
// is at its own genesis algorithms. Never read one as the other, and never assume they
// move together. See §14.1.

/** Channel handshake (§12.6): Ed25519 identity · ephemeral X25519 · ChaCha20-Poly1305. */
export const SUITE_CHANNEL_GENESIS = 0x01;

/** Bundle manifest (§12.4): Ed25519 detached signature over `DOMAIN_manifest ‖ suite ‖ json`. */
export const SUITE_MANIFEST_GENESIS = 0x01;
