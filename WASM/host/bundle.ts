// The app bundle format (README §12.4). A bundle is *signed content* the generic
// shell loads from a single file: a set of WASM handler modules, an optional
// zero-authority guest program, and a signed manifest declaring the modules, the
// kernel names they bind at, and — when there is a guest — the capabilities it holds.
// The shell verifies the manifest signature, governs it against its policy (author +
// module hashes), and installs the modules; the guest's `caps` describe the seam it is
// wired over, honored by the generic cap bridge (README §12.2).
//
// The FORMAT here is application-neutral; seedstore fills in storage content
// (its build-bundle script). A bundle is ONE blob — the container below — holding:
//
//   manifest.bundle    signed manifest envelope, per suite (§12.4, §14.1):
//                        0x01  [suite(1)][edPk(32)][edSig(64)][utf8 json]
//                        0x02  [suite(1)][edPk(32)][mlDsaPk(1952)]
//                              [edSig(64)][mlDsaSig(3309)][utf8 json]
//   <name>.wasm        each handler module, named by its manifest `name`
//   guest.js           the safe-js guest program, if the manifest declares one
//
// There is no directory form: a bundle is a value, not a path. That is what lets the
// same bytes be read from disk, carried over a data channel, and stashed in browser
// storage without a second format or a second load path — and it is why the manifest
// names no filenames (a signed name would be one more thing every target must
// validate). The file a module lives in is `<name>.wasm`, by construction.
//
// The manifest commits to every module's genesisHash and the loader verifies the bytes
// against it, so a verified module is admitted directly under its declared kernel name
// (§12.4) — there is no separate per-module install envelope. A live update is not a
// separate mechanism: it is a bundle whose manifest `version` is higher, which
// freshness requires and the same-author rule (§12.5) admits.
import { concatBytes, toHex, enc, dec } from "../core/util.js";
import { DOMAIN_MANIFEST, DOMAIN_MANIFEST_AUTHOR, SUITE_MANIFEST_GENESIS, SUITE_MANIFEST_HYBRID_PQ, SUPPORTED_GUEST_ABIS, PRIMITIVE_NAMES, CAP_DOMAINS, SLOT_ONLY_DOMAINS, } from "../core/domains.js";
import { checkHandlerMemory, DEFAULT_MAX_HANDLER_MEMORY_BYTES } from "../core/wasm-limits.js";

export interface BundleModule {
    /** Logical name, e.g. "codec". Three jobs, one value: the module's file in the
     *  container (`<name>.wasm`), the key the guest addresses it by through module/call
     *  (the bridge resolves it to the kernel name), and — with the manifest `app` — the
     *  kernel name derived from it (`kernelNameFor`). Unique within a manifest, and
     *  restricted to `[A-Za-z0-9_-]` so it is unambiguous as a filename. */
    name: string;
    /** genesisHash(wasm) hex — content integrity for the module bytes (§5.1, §12.4). */
    hash: string;
}

/** The crypto a bundle load needs, in libsodium-wrappers method names so a raw libsodium
 *  satisfies it directly (as does the native loader's Go-backed `sodium`, §12.9): verify
 *  the manifest signature, and hash content with the genesis hash.
 *
 *  It adds nothing to `ManifestVerifier` since the hash moved there (a multi-key suite
 *  derives its author id by hashing, §14.1) — the name survives because it is what the
 *  shell's `ShellSodium` and every call site are written against, and because the two
 *  answer different questions: one is "what does a *load* need", the other "what does a
 *  *manifest* need". */
export interface BundleCrypto extends ManifestVerifier {
}

/** The zero-authority guest program and everything about it. `caps` and `config` live
 *  HERE rather than at the top level because both are the guest's alone: the manifest's
 *  caps are the guest's entire authority (§12.2) and config only ever becomes its
 *  injected `APP`. WASM handlers carry no authority and read no config, so a
 *  handler-only bundle (the chat demo) simply omits this object — and "no guest ⇒ zero
 *  authority" is then the schema's shape rather than a rule prose has to state. */
export interface BundleGuest {
    /** genesisHash(utf8(source)) hex of `guest.js`. */
    hash: string;
    /** Which host seam this guest was written against (`GUEST_ABI_VERSION`, §12.2).
     *  Required, and checked at load: a guest declaring an ABI this host does not
     *  implement is refused with its own error rather than run against a seam that no
     *  longer means what it meant.
     *
     *  Required and not optional-with-a-default because the default would have to be the
     *  oldest ABI, which is exactly the population a bump exists to catch — and because a
     *  guest author who never thought about the seam version is indistinguishable from one
     *  who meant the old one. There is nothing to infer here, so the format asks. */
    abi: number;
    /** Capability *domains* (`CAP_DOMAINS`, core/domains.ts) granted to the guest —
     *  the prefixes the bridge enforces on its `host.call` names (§12.2), and the only
     *  backends the shell wires. Required whenever a guest exists; an empty array is a
     *  guest with no authority at all.
     *
     *  Only *authorities* appear here. Crypto primitives do not — they reach nothing, so
     *  there is nothing to grant; see `primitives` below and the note on the `crypto/`
     *  prefix in cap-bridge.ts. */
    caps: string[];
    /** The host crypto primitives this guest calls by name (`PRIMITIVE_NAMES`, the
     *  bare names under the `crypto/` prefix: "blake2b-256", "x25519/dh",
     *  "chacha20poly1305-ietf/seal", …).
     *
     *  **A compatibility declaration, not a capability one.** It grants nothing; it lets a
     *  host that cannot serve a name refuse the load *by name* instead of failing at the
     *  guest's first call — the same legibility `abi` buys for the seam version, which is
     *  why it sits here beside `abi` rather than inside `caps`. Optional: a guest that
     *  calls no primitive declares none. */
    primitives?: string[];
    /** App-structural constants the guest needs as injected globals (e.g. storage
     *  k/m/blockSize). Opaque to the runtime — the shell forwards it verbatim into the
     *  guest preamble as `const APP = …`.
     *
     *  NB what does NOT belong here: anything the runtime already derives from the
     *  admitted manifest. The author's key, the app name, the guest signing prefix and
     *  the modules' kernel names all arrive as `const BUNDLE` (cap-bridge
     *  `bundlePreamble`). Restating one of those here would be a build-time copy of a
     *  load-time fact — and a copy that silently disagrees is a verify mismatch with
     *  nothing pointing at the cause. */
    config?: Record<string, string | number>;
}

export type BundleRole = typeof BUNDLE_ROLES[number];

export interface BundleManifest {
    app: string;
    /** Monotonic version of the coherent set (README §12.4). Enforced at load against
     *  a persisted per-`(author, app)` high-water mark: a load whose `version` is below
     *  the mark is refused as a downgrade. An integer, not a label. */
    version: number;
    /** Protocol ids this app can serve (README §12.10). Absent ⇒ `[app]`, so an app that
     *  speaks only its own protocol declares nothing.
     *
     *  A DECLARATION, not a claim. It makes the app *eligible* for a binding and confers no
     *  traffic on its own: delivery follows the shell's user-owned `protocol id → app key`
     *  table, so any number of bundles may declare the same id without contending for
     *  anything. That separation — landing code is authorized by policy, receiving messages
     *  is chosen by the user — is what lets the loader hold no ownership state at all. */
    handles?: string[];
    /** The slot this bundle claims, or absent for an ordinary app (README §12.4, §12.5).
     *  Signed, so what a bundle claims to be is the author's statement and not the
     *  deliverer's, and one of `BUNDLE_ROLES` or the load is refused.
     *
     *  Admission is what keys off it, and it is the way a slot differs from an app: a slot
     *  occupant is an authority grant, not a preference, so the ordinary author allowlist
     *  does NOT admit one — it needs a per-slot decision (`roleAllowlist`). Freshness is
     *  not: a slot occupant carries the same `(author, app)` high-water mark as any other
     *  bundle, so each author keeps their own version lineage (§12.4). */
    role?: BundleRole;
    modules: BundleModule[];
    /** The guest program, or absent for a handler-only bundle (app modules bound as
     *  handlers, no zero-authority realm — e.g. the chat demo). Present ⇒ the loader
     *  integrity-checks `guest.js` and hands the source back for the shell to run in a
     *  confined realm (§12.2). */
    guest?: BundleGuest;
}

/** The surface *verifying* a manifest needs (a subset of libsodium). Deliberately
 *  separate from `ManifestCrypto`: a loader only ever checks signatures, so it is
 *  handed no way to make one — and a target whose realm exposes only a verifier
 *  (the native loader, README §12.9) can still run the shared loader below. */
export interface ManifestVerifier {
    crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
    /** The genesis hash, needed here — not just for content integrity — because a
     *  multi-key suite derives its 32-byte author id by hashing its key set
     *  (`hybridAuthorId`). */
    crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
    /** ML-DSA-65 verify (FIPS 204), the PQ half of suite `0x02` (§14.1).
     *
     *  **Optional, and its absence is the feature detect.** A host that has not linked a
     *  PQ verifier refuses `0x02` with its own error rather than reporting a bad
     *  signature — the same distinction an unknown suite gets, for the same reason: "this
     *  bundle wants a host I am not" is an operator's problem, not an attacker's doing.
     *  All three targets supply it from the same mldsa65.wasm (`pq.ts`, and
     *  native/mldsa.go through wazero), so the option exists for hosts outside this
     *  tree that embed the loader without the PQ artifact — not as a gap in it. */
    ml_dsa65_verify_detached?(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
}

/** The surface *signing* a manifest needs — the build-side of the format. */
export interface ManifestCrypto extends ManifestVerifier {
    crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
    /** Required only to sign suite `0x02`; `signManifestHybrid` throws without it. */
    ml_dsa65_sign_detached?(message: Uint8Array, sk: Uint8Array): Uint8Array;
}

/** An author's key set under the hybrid suite (§12.4). Both keys are the author's
 *  identity — see `hybridAuthorId` for why neither alone is. */
export interface HybridAuthorKeys {
    ed: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    mlDsa: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
}

/** The public half of whatever key set signed a manifest. `mlDsa` is present exactly
 *  when the suite is `0x02` — so "was this bundle PQ-signed?" is answered by reading a
 *  field, not by re-deriving anything. */
export interface ManifestAuthorKeys {
    ed: Uint8Array;
    mlDsa?: Uint8Array;
}

/** What a verified envelope yields. `author` is 32 bytes under every suite — the
 *  Ed25519 key under `0x01`, the derived id under `0x02` (`hybridAuthorId`) — so every
 *  consumer downstream (names, policy, freshness, bindings) is suite-agnostic and needs
 *  no change when a suite is added. `authorKeys` and `suite` are for the few callers
 *  that legitimately care *how* it was signed: a policy that requires PQ signing
 *  (§12.5), or a shell showing an operator what they are admitting. */
export interface VerifiedManifest {
    author: Uint8Array;
    authorKeys: ManifestAuthorKeys;
    /** The manifest suite id the envelope was signed under (`SUITE_MANIFEST_*`). */
    suite: number;
    manifest: BundleManifest;
}

/** The persisted bundle-freshness high-water mark per `(author, app)` (README §12.4),
 *  plus the set of author keys this host has written off (§12.5).
 *
 *  Host-local state that survives reboots, so an older signed bundle cannot silently
 *  replace a newer one — the guest is loaded wholesale from the bundle at every boot
 *  and carries no `seq` of its own.
 *
 *  The two live in one store because they are the same KIND of thing — persisted
 *  operator decisions about an author, read on the same load path, written through
 *  the same atomic seam — and because the dead-key set is worth nothing if a
 *  truncated write can drop it. The name still says "freshness" for the older half;
 *  renaming it would touch every target for no behavioural gain. */
export interface FreshnessStore {
    /** The highest `version` ever loaded for this `(author, app)`, or −Infinity if none. */
    get(author: Uint8Array, app: string): number;
    /** Advance the mark to `version` (monotonic; a lower value never rewinds it). */
    set(author: Uint8Array, app: string, version: number): void;
    /** Has this author key been written off (§12.5)? Checked on every load. */
    isRevoked(author: Uint8Array): boolean;
    /** Write off an author key permanently. Monotonic like the marks: nothing in the
     *  runtime removes a key from this set, so an author re-added to the policy's
     *  allowlist by a later edit stays refused. Undoing it is an out-of-band operator
     *  action on the store file, symmetric with rolling a freshness mark back. */
    revoke(author: Uint8Array): void;
}

/** The one host power a bundle load needs, as one call: land a bundle's modules on the
 *  handler table, all or none. `KernelHost` satisfies it; the native loader forwards it
 *  over its Go bridge (README §12.9).
 *
 *  **Atomicity is the host's, not the caller's.** A bundle is admitted as a unit (§12.4),
 *  so "every module lands or none does" is a property of the install itself — and the
 *  host is the only party that can honor it, because it is the party holding the
 *  half-built instances when the third module turns out to be malformed. Handing the
 *  caller an instantiate/bind/discard triad instead would make every target re-implement
 *  the same accumulate-and-release loop, and a target that forgot the release would leak
 *  a linear memory plus its compiled code per rejected bundle — silently, on the path
 *  that runs when something is already wrong.
 *
 *  Hashing is deliberately NOT here — it is `genesisHash(sodium, …)`, so the component
 *  that owns the handler table needs no crypto at all (§3). */
export interface BundleHost {
    /** Compile, instantiate and validate every module against the §4 ABI, then bind each
     *  at its `name`. Binding displaces whatever was at a name — the caller already ran
     *  the admission policy (§12.4, §12.5).
     *
     *  Throws on any structural failure (not valid wasm, missing exports, scratch out of
     *  bounds, invalid scratchSize) **with the table untouched**: nothing is bound unless
     *  everything validated, and whatever was built before the failure is released. */
    bindAll(mods: { name: string; wasm: Uint8Array }[]): void;
}

export interface VerifiedBundle {
    /** The manifest author's 32-byte id: the Ed25519 public key under suite `0x01`, the
     *  key-set hash under `0x02` (`hybridAuthorId`). Every signature the suite requires
     *  verified under it. */
    author: Uint8Array;
    /** The public key(s) that actually signed, and the suite they signed under — what a
     *  policy inspects to insist on PQ signing (§12.5), and what a shell shows an
     *  operator being asked to consent. */
    authorKeys: ManifestAuthorKeys;
    suite: number;
    manifest: BundleManifest;
    /** Every module's verified bytes, in manifest order. */
    modules: {
        mod: BundleModule;
        wasm: Uint8Array;
    }[];
    /** The verified guest source, or `""` for a handler-only bundle that declared none. */
    guestSource: string;
}

/** What the shell returns from `loadBundleBlob`: everything the manifest proved,
 *  minus the raw module bytes already bound into the handler table. The guest source
 *  is `""` for a handler-only bundle that declared none. */
export type LoadedBundle = Omit<VerifiedBundle, "modules">;

/** The manifest envelope's name inside the container. */
export const MANIFEST_FILE = "manifest.bundle";
/** The guest program's name inside the container (§12.4 — fixed, never declared). */
export const GUEST_FILE = "guest.js";
/** A module's name inside the container, derived from its logical name. */
export function moduleFile(name: string): string { return name + ".wasm"; }
/** An app's identity: `"<author hex>:<app>"` (§12.4). One value, three jobs — the
 *  freshness high-water key (FreshnessMarks below), the prefix of every one of the app's
 *  kernel names (`kernelNameFor`), and what a shell's protocol bindings point at (§12.10).
 *  Both halves are signed, so an app key is derived from the manifest and never declared.
 *
 *  The author hex is fixed-length, so the key parses unambiguously even though `app` is
 *  free to contain `:` itself. */
export function appKeyFor(author: Uint8Array, app: string): string {
    return toHex(author) + ":" + app;
}
/** The kernel name a bundle module binds at: `"<author hex>:<app>:<module name>"` — the
 *  app key plus the module (§5.1). Derived, never declared: the manifest carries no
 *  bind-name field, so there is nothing in it to forge, and all three components are
 *  already covered by the author's signature.
 *
 *  **Ownership is structural.** Because the author's key leads the name, one author's
 *  names are unreachable to another: a second author shipping an app called `chat` derives
 *  entirely different names and binds alongside, never over. Squat-resistance is a property
 *  of the namespace rather than a rule the admission policy has to enforce, which is why
 *  the loader keeps no ownership register and the policy has no "who holds this name"
 *  clause (§12.5). The author is the FULL hex, never truncated — a short prefix would be
 *  grindable, and an admitted author could generate a key matching another's first bytes
 *  and land on their names, which is exactly the collision this derivation exists to make
 *  unrepresentable.
 *
 *  The name parses from both ends: the author is fixed-length hex and a module name cannot
 *  contain `:` (NAME_RE), so the last colon always separates the module and everything
 *  between the two is the `app`.
 *
 *  Kernel names never leave the host. Nothing on the wire names another node's
 *  handler: a peer sends a protocol id or an opcode and the receiving host resolves it
 *  through its own bindings (§12.10) to whichever app it holds. A guest reaches its own
 *  modules by logical name through module/call, and the bridge resolves the logical name
 *  to the kernel name — so the guest never sees a kernel name at all. This needs to be
 *  collision-free within one node, not agreed across a deployment. */
export function kernelNameFor(author: Uint8Array, app: string, moduleName: string): string {
    return appKeyFor(author, app) + ":" + moduleName;
}
/** The genesis hash (BLAKE2b-256, §5.1) — the one system hash. A module's `bytesHash`,
 *  a manifest's `modules[].hash` — the definitive declaration of which bytes are authorized.
 *  value over the same bytes.
 *
 *  A free function taking the crypto, not a method on the host: hashing is the loader's
 *  business, and routing it through the handler table's owner would put a crypto
 *  dependency inside a component that is otherwise a `Map` (§3). */
export function genesisHash(sodium: BundleCrypto, data: Uint8Array): Uint8Array {
    return sodium.crypto_generichash(32, data, null);
}
/** The protocol ids a manifest offers to serve (README §12.10), defaulting to `[app]`.
 *  One place applies the default so a shell never has to remember it. */
export function handlesOf(manifest: BundleManifest): string[] {
    return manifest.handles && manifest.handles.length > 0 ? manifest.handles : [manifest.app];
}
/** The slots a bundle may claim (README §12.4). A slot is a *role* every other node
 *  must interoperate with, and there is exactly one occupant of it per host — where an
 *  ordinary app is a node-local choice that contends with nothing (§12.10).
 *
 *  A closed vocabulary, checked at load, so an unknown slot is a refused bundle rather
 *  than an unenforced string. That is deliberate even though it means a new slot needs a
 *  host rev: a slot is an authority class with its own admission (`roleAllowlist`,
 *  §12.5) and its own freshness floor, and neither can be honoured for a name this host
 *  has never heard of. A bundle claiming an unknown slot would otherwise be admitted as
 *  an ordinary app — the exact confusion the field exists to prevent.
 *
 *  `transport` is the only member today: the AKE, record layer and link routing (§12.6),
 *  which sees all plaintext and holds the session keys. */
export const BUNDLE_ROLES = ["transport"];
/** The fs keyspace prefix for one app (README §12.2).
 *
 *  A hash of the app key rather than the app key itself, because the key must double as
 *  a *filename* component: both fs backends restrict keys to `[A-Za-z0-9._-]`, which
 *  `"<author hex>:<app>"` fails on its colons, and an author-chosen `app` cannot be
 *  trusted to stay inside any charset. Hashing solves both at once — the output is hex,
 *  and it is fixed-length, so two distinct app keys cannot produce prefixes where one
 *  is an extension of the other.
 *
 *  128 bits of the digest: this separates namespaces, it does not authenticate them —
 *  reaching another app's data still requires forging its author key, which is what
 *  actually holds the boundary. */
export function appScopeFor(crypto: BundleCrypto, author: Uint8Array, app: string): string {
    const key = enc.encode(appKeyFor(author, app));
    return toHex(genesisHash(crypto, key)).slice(0, 32) + "-";
}
const SUITE_LEN = 1;
const PK_LEN = 32;
const SIG_LEN = 64;
const OFF_PK = SUITE_LEN, OFF_SIG = OFF_PK + PK_LEN, OFF_JSON = OFF_SIG + SIG_LEN;
// Suite 0x02 widths (FIPS 204 ML-DSA-65). Duplicated from pq.ts *deliberately*: these
// are the envelope's field widths, which are frozen by the format, where pq.ts's are
// the primitive's. The loader must be able to parse a hybrid envelope on a host with no
// PQ implementation linked at all — it refuses it, but it refuses it as an unsupported
// suite rather than as a truncated blob.
const ML_DSA_PK_LEN = 1952;
const ML_DSA_SIG_LEN = 3309;
// [suite(1)][edPk(32)][mlDsaPk(1952)][edSig(64)][mlDsaSig(3309)][json]
//
// Both public keys precede both signatures, so the key material is one contiguous run
// and so is the signature material — a later suite adding a third key extends each run
// rather than interleaving a new pair, and the offsets stay readable.
const H_OFF_ED_PK = SUITE_LEN;
const H_OFF_ML_PK = H_OFF_ED_PK + PK_LEN;
const H_OFF_ED_SIG = H_OFF_ML_PK + ML_DSA_PK_LEN;
const H_OFF_ML_SIG = H_OFF_ED_SIG + SIG_LEN;
const H_OFF_JSON = H_OFF_ML_SIG + ML_DSA_SIG_LEN;
/** Module names double as filenames and as the guest's module keys, so they are held
 *  to an unambiguous charset. With the container keyed by name (never joined to a
 *  path) a traversal name could not escape anything, but a name that needs quoting or
 *  normalizing to be used as either is a name the format should not accept at all. */
const NAME_RE = /^[A-Za-z0-9_-]+$/;
// Domain-separation prefix for the manifest signature (README §12.4, §16.1):
// `"seedkernel-manifest-sig-v1\0"` — from the one domain family (domains.ts, §16.1).
// Prepended to the manifest JSON before signing/verifying, never stored in the
// envelope — the disjoint prefix means a manifest signature can never double as a
// guest SIGN (DOMAIN_guest, §12.2) or channel-handshake (DOMAIN_channel, §12.6)
// signature over the same bytes.
/** Canonical manifest bytes. The signed envelope carries these verbatim, and the
 *  verifier parses the exact bytes it checked, so no separate canonicalisation is
 *  needed — the bytes *are* the manifest. */
export function encodeManifest(m: BundleManifest): Uint8Array {
    return enc.encode(JSON.stringify(m));
}
/** The signed preimage: `DOMAIN_manifest ‖ suite ‖ json`. The prefix is signed but not
 *  stored; the suite byte is signed *and* stored (envelope byte 0), which is the point —
 *  a verifier reads it to know the field widths, and the signature it then checks
 *  commits to the same byte, so an attacker who rewrites it only invalidates the
 *  manifest. Algorithm confusion between two suites is unrepresentable rather than
 *  merely unlikely (§14.1). */
function manifestPreimage(suite: number, json: Uint8Array): Uint8Array {
    return concatBytes([DOMAIN_MANIFEST, Uint8Array.of(suite), json]);
}
/** The suite `0x02` preimage: `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖ json`, signed
 *  by **both** keys.
 *
 *  Each signature therefore commits to the *other* key, which is what makes the pair a
 *  pair rather than two signatures that happen to travel together. Without it an
 *  attacker holding one broken half could keep the sound half's key and signature and
 *  substitute its own for the broken one; the id would change (below), but the two
 *  signatures would each still be valid over what they signed. Binding the key set into
 *  both preimages makes that splice fail at verification rather than only at policy. */
function hybridPreimage(suite: number, edPk: Uint8Array, mlDsaPk: Uint8Array, json: Uint8Array): Uint8Array {
    return concatBytes([DOMAIN_MANIFEST, Uint8Array.of(suite), edPk, mlDsaPk, json]);
}
/** The author id under a multi-key suite: `genesisHash(DOMAIN_manifest_author ‖ suite ‖
 *  edPk ‖ mlDsaPk)`.
 *
 *  **Why the id is not simply the Ed25519 key.** The author id is what policy admits
 *  (§12.5), what freshness is keyed by, and what leads every kernel name (§5.1) — so it
 *  is the thing an attacker must reproduce to land on an author's names. If it were the
 *  Ed25519 key alone, then an attacker who eventually breaks Ed25519 forges that half
 *  and supplies a *freshly generated* ML-DSA key for the other: both signatures verify,
 *  the id is unchanged, and hybrid signing has bought nothing at exactly the moment it
 *  was supposed to pay. Hashing the whole key set makes the id unreachable without both
 *  private keys, which is the property "hybrid" is supposed to name.
 *
 *  **Why a hash and not a longer id.** 32 bytes is load-bearing far outside this file —
 *  `appKeyFor` parses a fixed-length author prefix, policy files list 64 hex characters,
 *  bindings and freshness marks are keyed by it. A suite that widened the id would
 *  change all of that; hashing keeps every one of them untouched while the key material
 *  under it changes shape. The one cost is that an author migrating from `0x01` to
 *  `0x02` gets a *new* identity — new kernel names, a fresh freshness lineage, a new
 *  policy entry. That is a real cost and it is the honest one: the new identity is a
 *  different (stronger) statement about who signed, so pretending it is the old one
 *  would be the bug. Operators run both entries during an overlap.
 *
 *  **The suite is fixed inside, not a parameter.** This derivation is `0x02`'s, and the
 *  suite byte is in the preimage so it cannot collide with another suite's id over the
 *  same keys. A later multi-key suite writes its own function rather than passing a
 *  different byte to this one — its key set is a different shape, so there is nothing to
 *  share but the mistake of deriving two identities the same way. */
export function hybridAuthorId(sodium: ManifestVerifier, edPk: Uint8Array, mlDsaPk: Uint8Array): Uint8Array {
    return sodium.crypto_generichash(32, concatBytes([DOMAIN_MANIFEST_AUTHOR, Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), edPk, mlDsaPk]), null);
}
/** Sign a manifest → envelope `[suite(1)][authorPk(32)][sig(64)][utf8 json]`. */
export function signManifest(sodium: ManifestCrypto, sk: Uint8Array, pk: Uint8Array, m: BundleManifest): Uint8Array {
    const json = encodeManifest(m);
    const suite = SUITE_MANIFEST_GENESIS;
    const sig = sodium.crypto_sign_detached(manifestPreimage(suite, json), sk);
    return concatBytes([Uint8Array.of(suite), pk, sig, json]);
}
/** Sign a manifest under the hybrid suite → envelope
 *  `[0x02][edPk(32)][mlDsaPk(1952)][edSig(64)][mlDsaSig(3309)][utf8 json]`.
 *
 *  Both signatures are over the same preimage, so there is no ordering to get wrong and
 *  nothing a verifier must reconstruct in a particular sequence. Throws if the crypto
 *  has no ML-DSA signer — a build that cannot produce the PQ half must fail at the
 *  build, never quietly emit a `0x01` envelope the author believed was hybrid. */
export function signManifestHybrid(sodium: ManifestCrypto, keys: HybridAuthorKeys, m: BundleManifest): Uint8Array {
    if (!sodium.ml_dsa65_sign_detached) {
        throw new Error("bundle: no ML-DSA-65 signer — cannot sign manifest suite 0x02");
    }
    const json = encodeManifest(m);
    const suite = SUITE_MANIFEST_HYBRID_PQ;
    const pre = hybridPreimage(suite, keys.ed.publicKey, keys.mlDsa.publicKey, json);
    const edSig = sodium.crypto_sign_detached(pre, keys.ed.privateKey);
    const mlSig = sodium.ml_dsa65_sign_detached(pre, keys.mlDsa.privateKey);
    return concatBytes([
        Uint8Array.of(suite), keys.ed.publicKey, keys.mlDsa.publicKey, edSig, mlSig, json,
    ]);
}
/** Structural check on a parsed manifest. Runs only *after* the signature
 *  verified, so this is not a security boundary — it turns a manifest the author
 *  signed but got wrong (a missing/mistyped field) into a clean, loud rejection
 *  instead of a raw TypeError surfacing deep in the loader, and lets the rest of
 *  the runtime treat every field as present and correctly typed (matching the
 *  fail-loud posture of parsePolicy). Note `caps` and `abi` are required *inside*
 *  `guest`: the capability declaration and the seam the guest was written against are
 *  never optional where a guest exists, and never present where one doesn't. Whether
 *  this host *implements* the declared `abi` is a separate question, answered by
 *  verifyManifest — this is shape only. */
function isValidManifest(m: unknown): m is BundleManifest {
    if (typeof m !== "object" || m === null || Array.isArray(m))
        return false;
    const o = m as Record<string, unknown>;
    // `app` is load-bearing beyond reporting: it scopes the guest's signing namespace
    // (guestSignScope), keys the freshness high-water mark, and is half of every module's
    // kernel name (kernelNameFor). An empty one would yield the bind name ":codec".
    if (typeof o.app !== "string" || o.app.length === 0)
        return false;
    if (typeof o.version !== "number" || !Number.isInteger(o.version))
        return false;
    // `handles` is optional (absent ⇒ [app], see handlesOf). Present, it must be a list of
    // non-empty strings — it is only ever compared against a protocol id off the wire, so
    // the shape is the whole check: an id confers nothing until a user binds it (§12.10).
    if (o.handles !== undefined) {
        if (!Array.isArray(o.handles))
            return false;
        for (const h of o.handles)
            if (typeof h !== "string" || h.length === 0)
                return false;
    }
    // `role` is optional (absent ⇒ an ordinary app) and closed: an unrecognized slot name
    // is a rejection, never an ignored field. See BUNDLE_ROLES.
    if (o.role !== undefined) {
        if (typeof o.role !== "string" || !BUNDLE_ROLES.includes(o.role))
            return false;
    }
    if (!Array.isArray(o.modules))
        return false;
    const seen = new Set();
    for (const mod of o.modules) {
        if (typeof mod !== "object" || mod === null)
            return false;
        const mm = mod;
        if (typeof mm.name !== "string" || !NAME_RE.test(mm.name))
            return false;
        if (typeof mm.hash !== "string")
            return false;
        // Names key both the container and the guest's module map, so a duplicate is
        // ambiguous rather than merely redundant.
        if (seen.has(mm.name))
            return false;
        seen.add(mm.name);
    }
    // A handler-only bundle is ONE pure transform (§4): nothing else can reach its
    // modules — a handler cannot call another handler (§4.2) and with no guest there is
    // no module/call to drive them — so there is no second module to dispatch and no
    // `entry` field to pick one. The single module IS the app's inbound entry, and
    // anything multi-module ships a guest, which dispatches itself (§12.10).
    if (o.guest === undefined && o.modules.length !== 1)
        return false;
    if (o.guest !== undefined) {
        const g = o.guest as Record<string, unknown>;
        if (typeof g !== "object" || g === null || Array.isArray(g))
            return false;
        if (typeof g.hash !== "string")
            return false;
        if (typeof g.abi !== "number" || !Number.isInteger(g.abi))
            return false;
        if (!Array.isArray(g.caps) || g.caps.some((c: unknown) => typeof c !== "string"))
            return false;
        if (g.primitives !== undefined
            && (!Array.isArray(g.primitives) || g.primitives.some((p: unknown) => typeof p !== "string")))
            return false;
        if (g.config !== undefined) {
            if (typeof g.config !== "object" || g.config === null || Array.isArray(g.config))
                return false;
            for (const v of Object.values(g.config)) {
                if (typeof v !== "string" && typeof v !== "number")
                    return false;
            }
        }
    }
    return true;
}
/** Verify a manifest envelope; returns the author id + parsed manifest, or null
 *  if a signature is bad. Throws `bundle: malformed manifest` when the body is
 *  validly signed but is not parseable JSON of the expected shape — a signed-but-
 *  broken manifest is a fail-loud condition, not an untrusted input to drop — and
 *  throws on a suite this host cannot check at all (unknown id, or `0x02` with no
 *  ML-DSA verifier linked), which is a legibility failure rather than a verdict. */
export function verifyManifest(sodium: ManifestVerifier, env: Uint8Array): VerifiedManifest | null {
    if (env.length < SUITE_LEN)
        return null;
    // Suite before offsets: another suite's key and signature are other widths, so
    // parsing first would read its bytes at this suite's positions. Unlike a bad
    // signature this is not an authenticity verdict but a legibility one — "this bundle
    // wants a host I am not" — so it throws with its own message rather than returning
    // null, which would surface to the operator as `manifest signature invalid` and send
    // them hunting the wrong problem. Nothing secret is revealed by the distinction: the
    // suite byte is attacker-chosen and public either way.
    const suite = env[0];
    let author;
    let authorKeys;
    let json;
    if (suite === SUITE_MANIFEST_GENESIS) {
        if (env.length < OFF_JSON)
            return null;
        author = env.slice(OFF_PK, OFF_SIG);
        authorKeys = { ed: author };
        const sig = env.slice(OFF_SIG, OFF_JSON);
        json = env.slice(OFF_JSON);
        if (!sodium.crypto_sign_verify_detached(sig, manifestPreimage(suite, json), author))
            return null;
    }
    else if (suite === SUITE_MANIFEST_HYBRID_PQ) {
        // A host with no PQ verifier linked in cannot form an opinion about this bundle, so
        // it says so — the one thing it must not do is treat "I cannot check the PQ half"
        // as "the PQ half is fine" and fall back to the Ed25519 signature alone, which is
        // precisely the downgrade the suite exists to prevent (§14.1).
        if (!sodium.ml_dsa65_verify_detached) {
            throw new Error("bundle: unsupported manifest suite 0x02 — this host has no ML-DSA-65 verifier");
        }
        if (env.length < H_OFF_JSON)
            return null;
        const edPk = env.slice(H_OFF_ED_PK, H_OFF_ML_PK);
        const mlPk = env.slice(H_OFF_ML_PK, H_OFF_ED_SIG);
        const edSig = env.slice(H_OFF_ED_SIG, H_OFF_ML_SIG);
        const mlSig = env.slice(H_OFF_ML_SIG, H_OFF_JSON);
        json = env.slice(H_OFF_JSON);
        const pre = hybridPreimage(suite, edPk, mlPk, json);
        // BOTH, always. Not "either", which would be no stronger than the weaker half, and
        // not "the PQ one where present", which would be a young algorithm carrying the
        // whole weight. A break in either half rejects valid bundles (an operator's
        // problem, recoverable) instead of admitting forged ones (unrecoverable).
        if (!sodium.crypto_sign_verify_detached(edSig, pre, edPk))
            return null;
        if (!sodium.ml_dsa65_verify_detached(mlSig, pre, mlPk))
            return null;
        author = hybridAuthorId(sodium, edPk, mlPk);
        authorKeys = { ed: edPk, mlDsa: mlPk };
    }
    else {
        throw new Error(`bundle: unsupported manifest suite 0x${suite.toString(16).padStart(2, "0")}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(dec.decode(json));
    }
    catch {
        throw new Error("bundle: malformed manifest (not JSON)");
    }
    if (!isValidManifest(parsed))
        throw new Error("bundle: malformed manifest");
    // Guest ABI support (§12.2), the same KIND of check as the suite above and refused the
    // same way: "this bundle wants a host I am not" is a legibility failure, not an
    // authenticity verdict, so it throws with its own message rather than returning null.
    // It sits here, at the one place a manifest becomes a value the rest of the runtime
    // trusts, so no target can forget it and no inspecting shell shows an operator a guest
    // it could never run.
    if (parsed.guest && !SUPPORTED_GUEST_ABIS.includes(parsed.guest.abi)) {
        throw new Error(`bundle: guest ABI ${parsed.guest.abi} is not implemented by this host (supported: ${SUPPORTED_GUEST_ABIS.join(", ")})`);
    }
    // The declared primitives, checked the same way and for the same reason: "this bundle
    // wants a host I am not". Not a grant — a primitive reaches nothing — so it is refused
    // here as an incompatibility rather than gated later as an authority.
    for (const p of parsed.guest?.primitives ?? []) {
        if (!(PRIMITIVE_NAMES as readonly string[]).includes(p)) {
            throw new Error(`bundle: this host has no crypto primitive "${p}" (manifest guest.primitives; this host serves: ${PRIMITIVE_NAMES.join(", ")})`);
        }
    }
    // The capability vocabulary (§12.2) is CLOSED — an unknown domain is a refused
    // manifest, not a cap that quietly grants nothing at first use — and `link` and
    // `transport` (§12.5) are the slot occupant's; an app declaring either is refused
    // too. Both are AUTHORITY checks, so they belong at the point the manifest becomes
    // trusted, before any policy predicate is shown a bundle it must never admit.
    if (parsed.role === undefined) {
        for (const c of parsed.guest?.caps ?? []) {
            if (SLOT_ONLY_DOMAINS.includes(c)) {
                throw new Error(`bundle: capability domain "${c}" belongs to a slot occupant, and ${parsed.app} claims no role (§12.4)`);
            }
        }
    }
    for (const c of parsed.guest?.caps ?? []) {
        if (!(CAP_DOMAINS as readonly string[]).includes(c)) {
            throw new Error(`bundle: unknown capability domain "${c}" (this host grants: ${CAP_DOMAINS.join(", ")})`);
        }
    }
    return { author, authorKeys, suite, manifest: parsed };
}
/** True if `bytes` content hashes to the declared genesisHash hex (integrity). */
export function contentMatches(bytes: Uint8Array, declaredHex: string, genesisHash: (b: Uint8Array) => Uint8Array): boolean {
    return toHex(genesisHash(bytes)) === declaredHex.toLowerCase();
}
// ── The container (README §12.4) ─────────────────────────────────────────────
//
// A bundle is one blob. This is pure *framing*, not a signed format of its own: the
// manifest envelope inside carries the author's signature and its module hashes
// protect the bytes, so the container only names the files and can be repacked by
// anyone without weakening anything. Layout (integers big-endian):
//
//   "SKB1" (4) │ count u16 │ count× ( nameLen u16 │ name utf8 │ dataLen u32 │ data )
const ARCHIVE_MAGIC = [0x53, 0x4b, 0x42, 0x31]; // "SKB1"
/** Serialize a set of named bundle files into one bundle blob (format above). */
export function packBundle(files: Record<string, Uint8Array>): Uint8Array {
    const names = Object.keys(files);
    const header = new Uint8Array(6);
    header.set(ARCHIVE_MAGIC, 0);
    new DataView(header.buffer).setUint16(4, names.length, false);
    const parts: Uint8Array[] = [header];
    for (const name of names) {
        const nameBytes = enc.encode(name);
        const data = files[name];
        const rec = new Uint8Array(2 + nameBytes.length + 4);
        const dv = new DataView(rec.buffer);
        dv.setUint16(0, nameBytes.length, false);
        rec.set(nameBytes, 2);
        dv.setUint32(2 + nameBytes.length, data.length, false);
        parts.push(rec, data);
    }
    return concatBytes(parts);
}
/** Parse a bundle blob back into its `{ file: bytes }` map. Throws on a mis-magicked
 *  or truncated blob — a malformed container is a fail-loud condition, like a
 *  malformed manifest, not an untrusted input to silently drop. */
export function unpackBundle(blob: Uint8Array): Record<string, Uint8Array> {
    if (blob.length < 6 || !ARCHIVE_MAGIC.every((b, i) => blob[i] === b)) {
        throw new Error("bundle: not a bundle blob");
    }
    const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
    const count = dv.getUint16(4, false);
    const files: Record<string, Uint8Array> = {};
    let off = 6;
    for (let i = 0; i < count; i++) {
        if (off + 2 > blob.length)
            throw new Error("bundle: truncated blob");
        const nameLen = dv.getUint16(off, false);
        off += 2;
        if (off + nameLen + 4 > blob.length)
            throw new Error("bundle: truncated blob");
        const name = dec.decode(blob.subarray(off, off + nameLen));
        off += nameLen;
        const dataLen = dv.getUint32(off, false);
        off += 4;
        if (off + dataLen > blob.length)
            throw new Error("bundle: truncated blob");
        files[name] = blob.slice(off, off + dataLen);
        off += dataLen;
    }
    return files;
}
/** The freshness *arithmetic*: the `(author, app)` key derivation, the monotonic
 *  never-rewind rule, the per-slot role floors, the revocation set, and the
 *  `{ marks, roles, revoked }` serialization. All of it is target-independent, so
 *  it lives here and every target subclasses this with its own persistence seam
 *  (`persist`) rather than restating the rules — the author hex is fixed-length, so
 *  the key is unambiguous. On its own this is an in-memory store: `persist` does
 *  nothing, which is exactly right for a test. */
export class FreshnessMarks {
    marks = new Map();
    /** Author keys written off (§12.5), as lowercase hex. */
    revoked = new Set();
    /** Seed from a persisted
     *  `{ marks: { "authorHex:app": version }, revoked: [hex] }`
     *  blob. Absent or unreadable input ⇒ start empty (−∞ for every key, nothing
     *  revoked); a target's loader hands in null rather than throwing, since a missing
     *  store is the first-boot case.
     *
     *  Note that "unreadable ⇒ start empty" also means "start UNREVOKED", which is why
     *  `persist` must be atomic on every target.
     *
     *  A store written before revocation existed — a bare `{ "authorHex:app": version }`
     *  map — THROWS rather than reading as empty. It would otherwise parse as no marks
     *  at all, silently discarding every downgrade guard on the one boot after a host
     *  upgrade, with the next stale bundle accepted and nothing anywhere saying why. An
     *  operator must be told to migrate or delete the file; the shape is unambiguous
     *  (a bare map has neither key), so this can never fire on a store this version
     *  wrote. Any other unrecognized key is ignored rather than refused — dropping one
     *  discards nothing a guard was ever earned on. */
    constructor(json?: string | null) {
        if (json) {
            let raw;
            try {
                const parsed = JSON.parse(json);
                if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
                    raw = parsed;
                }
            }
            catch { /* malformed ⇒ start empty */ }
            if (raw) {
                if (raw.marks === undefined && raw.revoked === undefined && Object.keys(raw).length > 0) {
                    throw new Error("freshness store: this file predates author revocation (§12.5) and holds only high-water marks. " +
                        'Reading it as-is would silently drop every downgrade guard. Migrate it to {"marks":{…},"revoked":[]} ' +
                        "or delete it to start from no marks.");
                }
                const marks = raw.marks;
                if (typeof marks === "object" && marks !== null && !Array.isArray(marks)) {
                    for (const [k, v] of Object.entries(marks)) {
                        if (typeof v === "number")
                            this.marks.set(k, v);
                    }
                }
                if (Array.isArray(raw.revoked)) {
                    for (const a of raw.revoked)
                        if (typeof a === "string")
                            this.revoked.add(a.toLowerCase());
                }
            }
        }
    }
    /** Serialize the marks and the dead-key set for `persist`. */
    serialize(): string {
        const marks: Record<string, number> = {};
        for (const [k, v] of this.marks)
            marks[k] = v;
        return JSON.stringify({ marks, revoked: [...this.revoked] });
    }
    /** Write the serialized state durably. The base store is in-memory only; a target
     *  overrides this with its atomic-write seam (README §12.4 requires the write be
     *  atomic — a truncated store reads back as "nothing known", silently discarding
     *  every downgrade guard AND every revocation). */
    persist(_json: string): void { }
    key(author: Uint8Array, app: string): string { return appKeyFor(author, app); }
    get(author: Uint8Array, app: string): number {
        const v = this.marks.get(this.key(author, app));
        return v === undefined ? -Infinity : v;
    }
    set(author: Uint8Array, app: string, version: number): void {
        const k = this.key(author, app);
        const cur = this.marks.get(k);
        if (cur !== undefined && cur >= version)
            return; // monotonic: never rewound
        this.marks.set(k, version);
        this.persist(this.serialize());
    }
    isRevoked(author: Uint8Array): boolean {
        return this.revoked.has(toHex(author));
    }
    revoke(author: Uint8Array): void {
        const hex = toHex(author);
        if (this.revoked.has(hex))
            return;
        this.revoked.add(hex);
        this.persist(this.serialize());
    }
}
/** Authenticate and integrity-check a bundle blob (README §12.4 steps 1, 4a, 5a).
 *  Verifies the manifest signature, then hashes every module and the guest against
 *  what the manifest commits to. Throws on anything that does not check out.
 *
 *  This function has no host and no policy by construction, so "nothing has landed"
 *  is a property of its type rather than of reading it carefully. A caller may show
 *  the result to a user, or hand it straight to `installBundle`. */
export function verifyBundle(sodium: BundleCrypto, blob: Uint8Array): VerifiedBundle {
    const files = unpackBundle(blob);
    const env = files[MANIFEST_FILE];
    if (!env)
        throw new Error("bundle: no manifest in the blob");
    const v = verifyManifest(sodium, env);
    if (!v)
        throw new Error("bundle: manifest signature invalid");
    const read = (file: string) => {
        const b = files[file];
        if (!b)
            throw new Error(`bundle: missing file ${file}`);
        return b;
    };
    const result = {
        author: v.author,
        authorKeys: v.authorKeys,
        suite: v.suite,
        manifest: v.manifest,
        modules: v.manifest.modules.map((mod) => ({ mod, wasm: read(moduleFile(mod.name)) })),
        guestSource: v.manifest.guest ? dec.decode(read(GUEST_FILE)) : "",
    };
    // Integrity: hash every module and the guest against the manifest's signed hashes.
    // This is inside verifyBundle (not a separate step) because the manifest hashes are
    // the definitive declaration of what the author authorized — a verified signature
    // over a manifest whose hashes weren't yet checked is not yet a verified bundle.
    for (const { mod, wasm } of result.modules) {
        if (!contentMatches(wasm, mod.hash, (b) => genesisHash(sodium, b))) {
            throw new Error(`bundle: ${mod.name} content hash mismatch`);
        }
    }
    if (v.manifest.guest) {
        if (!contentMatches(enc.encode(result.guestSource), v.manifest.guest.hash, (b) => genesisHash(sodium, b))) {
            throw new Error("bundle: guest content hash mismatch");
        }
    }
    return result;
}
/** Land a verified bundle (README §12.4 steps 3, 4b): enforce version freshness,
 *  then instantiate every verified module (pure, no table effect) and bind them all
 *  atomically. If any module fails to instantiate the whole load fails — a half-landed
 *  bundle is exactly the incoherent state the manifest exists to prevent.
 *
 *  Admission (§12.5) runs BEFORE this function, between verifyBundle and installBundle.
 *  By the time a bundle reaches here the decision is already settled — this function
 *  only handles mechanics (freshness + instantiate + bind), not governance.
 *
 *  There is no per-module admission callback: the manifest's `modules[].hash` commits to
 *  exactly which bytes are authorized, and `verifyBundle` already proved the bytes match.
 *  Trusting the author means trusting everything the author signed.
 *
 *  `deferMark` is for the one load whose "actually loaded" boundary is NOT this
 *  function's: a slot occupant is only loaded once its driver STANDS, which happens
 *  after this returns (shell-core `loadBundleBlob` → `installTransport`). A realm
 *  built from the guest source can fail there, and the node then keeps the transport
 *  it had — so advancing the mark inside would raise the (author, app) mark before that
 *  was known, bricking a rollback to the last good version
 *  (the exact outcome the downgrade refusals above exist to prevent). The caller
 *  passes `deferMark` for a role bundle and advances at the point the load is
 *  complete (§12.4: "the mark must record the highest version that actually loaded"). */
export function installBundle(host: BundleHost, v: VerifiedBundle, freshness?: FreshnessStore, deferMark = false): LoadedBundle {
    // Freshness (README §12.4 step 3): the `version` is an enforced monotonic integer
    // (verifyManifest already shape-checked it). Refuse a load below the persisted
    // `(author, app)` high-water mark as a downgrade — nothing lands — otherwise advance
    // the mark. Equal versions reload (an ordinary reboot re-reads the same bundle);
    // the mark is never rewound.
    const version = v.manifest.version;
    if (freshness) {
        // Revocation (§12.5) before freshness. A stolen key satisfies freshness trivially
        // — it signs `version + 1` — so this is the check that has anything to say about
        // it, and it must speak first or the load succeeds. It sits HERE rather than in
        // the admission predicate (§12.5) because a predicate is a pure function of the
        // bundle and every target writes its own: `admitAll` would silently have no
        // revocation, and an OFFER-delivered bundle (§11) is exactly the path that needs
        // one. One check on the one install path covers every target.
        if (freshness.isRevoked(v.author)) {
            throw new Error(`bundle: author ${toHex(v.author)} is revoked on this host — refusing ${v.manifest.app} v${version}`);
        }
        const highWater = freshness.get(v.author, v.manifest.app);
        if (version < highWater) {
            throw new Error(`bundle: version ${version} is below the (author, app) freshness high-water mark ${highWater} — downgrade refused`);
        }
        // A slot occupant is checked no differently: versions are an author's own lineage,
        // so a bundle claiming a slot carries the ordinary `(author, app)` mark and nothing
        // second keyed to the role. A floor keyed to the slot would bind every author of it
        // to one shared version line — B could not replace A's v5 without numbering above
        // it, a sequence with no owner — and it would buy protection only where an attacker
        // chooses which signed bundle arrives. Nothing delivers a bundle but the operator
        // (§12.4), so the answer to "two trusted authors, one stale" is to trust one author
        // per slot at a time (§12.5).
        // NB: the mark is advanced at the *end* of this function, only after every module
        // has instantiated and bound — not here. See below.
    }
    // The §4.3 memory bound, read off the bytes BEFORE the host instantiates them —
    // instantiation is what allocates the declared initial memory, so a host-side check
    // could only run after the damage. It sits here, on the shared admission path, rather
    // than inside each host's bind: this is an admission rule, and §3 puts admission rules
    // in the one compiled implementation both targets evaluate. Every module is checked
    // before ANY is handed down, so a bundle whose second module is over the ceiling never
    // reaches the host at all.
    for (const { wasm } of v.modules) {
        checkHandlerMemory(wasm, DEFAULT_MAX_HANDLER_MEMORY_BYTES);
    }
    // One transactional call: every module lands or none does, and the host owns that
    // guarantee (BundleHost). Each lands under the kernel name DERIVED from the signed
    // `(author, app, name)` triple (§5.1). No per-module `.install` envelope means no
    // 64 KB envelope cap and no boot-time seq — an equal-version reload just re-installs,
    // and a higher-version bundle from the same author lands on the same names because the
    // same key derives them.
    try {
        host.bindAll(v.modules.map(({ mod, wasm }) => ({
            name: kernelNameFor(v.author, v.manifest.app, mod.name),
            wasm,
        })));
    }
    catch (e) {
        throw new Error(`bundle: module ${(e as Error).message}`);
    }
    // Advance the freshness mark only now — after a fully successful load (or, with
    // `deferMark`, leave it to the caller at its own completion point). Advancing it
    // during the downgrade check above would brick rollback: a partially written or
    // corrupt *newer* bundle — manifest intact and signed, but one module or the guest
    // wrong — would raise the mark to the new version, then throw. Nothing runs, yet
    // reloading the known-good older bundle is now refused as a downgrade until an
    // operator hand-edits the freshness file. The mark must record the highest version
    // that actually loaded (README §12.4). Integrity was verified by verifyBundle before
    // this function was called, so the freshness advance is always behind a successful
    // verify — and, with `deferMark`, behind the driver standing as well.
    if (freshness && !deferMark) {
        freshness.set(v.author, v.manifest.app, version);
    }
    return {
        manifest: v.manifest, author: v.author, authorKeys: v.authorKeys, suite: v.suite,
        guestSource: v.guestSource,
    };
}
