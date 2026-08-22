// App bundle format (§12.4): signed manifest envelope + modules + guest.js.
// Every name is derived; the manifest commits to every file hash.
import { concatBytes, toHex, enc, dec, errMessage } from "../core/util.js";
import { DOMAIN_MANIFEST, DOMAIN_MANIFEST_AUTHOR, AUTHOR_MLDSA_SEED_LABEL, SUITE_MANIFEST_HYBRID_PQ, GUEST_ABI_VERSION, AUTHORITY_CALLS, PRIVILEGES, isAuthority, isGrant, isReservedProtocol, type Privilege, } from "../core/domains.js";
import { checkModuleMemory, DEFAULT_MAX_MODULE_MEMORY_BYTES } from "../core/wasm-limits.js";

export interface BundleModule {
    /** Logical name: both the module's file in the container (`<name>.wasm`) and the key
     *  the guest addresses it by through `host.call`. Unique within a manifest; NAME_RE
     *  below keeps it from spelling either other kind of host-call name (§12.2). */
    name: string;
    /** genesisHash(wasm) hex — content integrity for the module bytes (§12.4). */
    hash: string;
}

/** A value representable by the manifest's signed JSON encoding. App configuration is
 *  schema-free here: its shape and meaning belong to the bundle that reads it. */
export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export interface JsonObject {
    [key: string]: JsonValue;
}

/** The crypto a bundle load needs, in libsodium-wrappers method names so a raw libsodium
 *  satisfies it directly. Identical to `ManifestVerifier` today; kept separate because call
 *  sites are written against "what a *load* needs", not "what a *manifest* needs". */
export interface BundleCrypto extends ManifestVerifier {
}

/** The zero-authority guest program. `requires` and `config` live here rather than at the
 *  top level because both are the guest's alone: WASM modules carry no authority and read
 *  no config. */
export interface BundleGuest {
    /** genesisHash(utf8(source)) hex of `guest.js`. */
    hash: string;
    /** Which host seam this guest was written against (`GUEST_ABI_VERSION`, §12.2).
     *  Required, not optional-with-a-default: the default would have to be the oldest ABI,
     *  exactly the population a bump exists to catch. */
    abi: number;
    /** Exactly the authorities this guest is granted (`AUTHORITY_CALLS`, core/domains.ts).
     *  Matched at the seam by exact match, and closed — a name this host does not grant is a
     *  refused manifest, not a requirement that quietly grants nothing at first use.
     *  `crypto/*` and the bundle's own module names are not declarable, so the list an
     *  operator reads is the bundle's whole reach. Empty is the common case. */
    requires: string[];
    /** The app's signed configuration, injected unchanged into the guest preamble as
     *  `const APP`. Its schema is the app's alone; the one shape the runtime insists on is
     *  an object, since a guest reads config by name and a signed scalar would leave every
     *  `APP.x` undefined at run time instead of failing the load. Absent ≡ `{}`. Nothing
     *  the runtime already derives belongs here: identity is read through the seam
     *  (`node/identity`) and the signing namespace is applied host-side (§12.4). */
    config?: JsonObject;
}

export interface BundleManifest {
    app: string;
    /** Monotonic version of the coherent set (§12.4), enforced at load against a persisted
     *  per-`(author, app)` high-water mark. An integer, not a label. */
    version: number;
    /** Wire protocol id(s) this app serves (§12.10). Optional: an initiator-only
     *  bundle claims nothing. A claim is not authority. */
    protocols?: string[];
    modules: BundleModule[];
    /** The guest program — required. Modules are the pure transforms it drives. */
    guest: BundleGuest;
}

/** The surface *verifying* a manifest needs (a subset of libsodium). Separate from
 *  `ManifestCrypto` so a loader is handed no way to sign — which is also what lets a
 *  verify-only realm (the native loader, §12.9) run the shared loader below. */
export interface ManifestVerifier {
    crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
    /** The genesis hash — content integrity, and the author id (`hybridAuthorId`). */
    crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
    /** ML-DSA-65 verify (FIPS 204), the PQ half of the manifest suite (§14.1). Required:
     *  the suite is hybrid, so a host without it cannot check any manifest at all.
     *  `verifyManifest` re-checks at runtime for the untyped caller with a partial
     *  libsodium, and refuses rather than falling back to the Ed25519 half alone. */
    ml_dsa65_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
}

/** The surface *signing* a manifest needs — the build-side of the format. */
export interface ManifestCrypto extends ManifestVerifier {
    crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
    /** The PQ half of the signature; `signManifest` throws without it. */
    ml_dsa65_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
}

/** An author's key set (§12.4). Both keys together are the identity — see `hybridAuthorId`
 *  for why neither alone is. "hybrid" names the *construction*, so only the things whose
 *  shape would differ under another suite keep the qualifier. */
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

/** The public half of the key set that signed a manifest — both keys, always. */
export interface ManifestAuthorKeys {
    ed: Uint8Array;
    mlDsa: Uint8Array;
}

/** What a verified envelope yields. `author` is the 32-byte derived key-set id
 *  (`hybridAuthorId`), the one kind of identity everything downstream reads; `authorKeys`
 *  is for the caller that cares *which keys* signed — a shell showing an operator what it
 *  is being asked to admit. */
export interface VerifiedManifest {
    author: Uint8Array;
    authorKeys: ManifestAuthorKeys;
    manifest: BundleManifest;
}

/** The persisted bundle-freshness high-water mark per `(author, app)` (§12.4), plus the set
 *  of author keys this host has written off (§12.5). One store because a truncated write
 *  must not be able to drop the dead-key set. */
export interface FreshnessStore {
    /** The highest `version` ever loaded for this `(author, app)`, or −Infinity if none. */
    get(author: Uint8Array, app: string): number;
    /** Advance the mark to `version` (monotonic; a lower value never rewinds it). */
    set(author: Uint8Array, app: string, version: number): void;
    /** Has this author key been written off (§12.5)? Checked on every load. */
    isRevoked(author: Uint8Array): boolean;
    /** Write off an author key permanently. Monotonic like the marks: nothing in the
     *  runtime removes a key from this set, so an author re-added to the policy allowlist
     *  stays refused. Undoing it is an out-of-band edit of the store file. */
    revoke(author: Uint8Array): void;
    /** Roll a mark back to a captured previous value — the one legal rewind, for the load
     *  that raised the mark and then failed to persist it, so in-memory state matches the
     *  store the retry will persist against. `previous` is what `get` returned before the
     *  load (−Infinity when unmarked). */
    resetMark(author: Uint8Array, app: string, previous: number): void;
}

/** One module invocation's answer: the transform's bytes (null when it failed), and `ms` —
 *  the module's own processing time, measured on the worker that ran it. The seam bills the
 *  caller's execution budget the actual compute, never the issue-to-settle wall clock: a
 *  burst of fire-and-forget calls serialized through one worker would otherwise charge their
 *  queue wait quadratically (§12.3). */
export interface ModuleResult {
    bytes: Uint8Array | null;
    ms: number;
}

/** One slot's private pure modules. The builder owns partial-instance cleanup, because it
 *  is the target holding those resources when a later module fails. */
export interface PureModules {
    call(name: string, payload: Uint8Array, deadlineMs?: number): Promise<ModuleResult>;
    dispose(): void;
}

/** The one target-specific power a bundle load needs: build all of its pure modules or
 *  build none. JS returns closures over worker-backed instances; native returns closures
 *  over an opaque Go-owned slot. */
export interface PureModuleLoader {
    build(mods: { name: string; wasm: Uint8Array }[]): PureModules | Promise<PureModules>;
    /** Optional ceiling on a module's declared linear memory this target holds its own
     *  isolates to (§4.3), in bytes. Absent ⇒ `DEFAULT_MAX_MODULE_MEMORY_BYTES`.
     *
     *  Declared here rather than applied: `loadBundleModules` takes the tighter of this and
     *  the shared ceiling, so "a target may hold itself to less, none may be looser" is a
     *  property of the composition, and each module's sections are walked once on the one
     *  path both targets share. */
    maxModuleMemoryBytes?: number;
}

export interface VerifiedBundle {
    /** The manifest author's 32-byte id (`hybridAuthorId`); both signatures verified under
     *  the keys it commits to. */
    author: Uint8Array;
    /** The public keys that actually signed — what a shell shows an operator being asked
     *  to consent. */
    authorKeys: ManifestAuthorKeys;
    manifest: BundleManifest;
    /** Every module's verified bytes, in manifest order. */
    modules: {
        mod: BundleModule;
        wasm: Uint8Array;
    }[];
    /** The verified guest source. */
    guestSource: string;
}

/** What the shell returns from `loadBundleBlob`: verified metadata and guest source,
 *  without retaining the raw module bytes after the private instances are built. */
export type LoadedBundle = Omit<VerifiedBundle, "modules">;

/** The manifest envelope's name inside the container. */
export const MANIFEST_FILE = "manifest.bundle";
/** The guest program's name inside the container (§12.4 — fixed, never declared). */
export const GUEST_FILE = "guest.js";
/** A module's name inside the container, derived from its logical name. */
export function moduleFile(name: string): string { return name + ".wasm"; }
/** App identity `"<author hex>:<app>"` (§12.4) — freshness, scope, uninstall/revoke. */
export function appKeyFor(author: Uint8Array, app: string): string {
    return toHex(author) + ":" + app;
}
/** The genesis hash (BLAKE2b-256) — the one system hash. A free function taking the crypto
 *  rather than a host method, so target module builders need no crypto dependency. */
export function genesisHash(sodium: BundleCrypto, data: Uint8Array): Uint8Array {
    return sodium.crypto_generichash(32, data, null);
}
/** Which privileges (§12.5) a manifest's `requires` reach — the catalog values of the
 *  authorities it names (`AUTHORITY_CALLS`), read off the table and never off a prefix
 *  parsed out of a name. Empty ⇒ an ordinary app; reserved ids contribute none.
 *
 *  Not folded into `verifyManifest`: a manifest naming `link/open` is well-formed, and
 *  whether this node grants it is policy, decided where the policy is in hand (shell-core). */
export function privilegesOf(manifest: BundleManifest): Privilege[] {
    const reached = manifest.guest.requires.filter(isAuthority).map((n) => AUTHORITY_CALLS[n]);
    return PRIVILEGES.filter((p) => reached.includes(p));
}
/** The fs keyspace prefix for one app (§12.2). A hash of the app key rather than the key
 *  itself, because it must double as a *filename* component: both fs backends restrict keys
 *  to `[A-Za-z0-9._-]`, which the colons fail and an author-chosen `app` cannot be trusted
 *  to satisfy. Fixed-length hex also means no prefix can extend another.
 *
 *  128 bits: this separates namespaces, it does not authenticate them — reaching another
 *  app's data still requires forging its author key, which is what holds the boundary. */
export function appScopeFor(crypto: BundleCrypto, author: Uint8Array, app: string): string {
    const key = enc.encode(appKeyFor(author, app));
    return toHex(genesisHash(crypto, key)).slice(0, 32) + "-";
}
const SUITE_LEN = 1;
const PK_LEN = 32;
const SIG_LEN = 64;
// ML-DSA-65 widths (FIPS 204), duplicated from pq.ts *deliberately*: these are the
// envelope's frozen field widths, where pq.ts's are the primitive's. A host with no PQ
// implementation linked must still parse an envelope, so it can refuse it as a suite it
// cannot check rather than as a truncated blob.
const ML_DSA_PK_LEN = 1952;
const ML_DSA_SIG_LEN = 3309;
// Both public keys precede both signatures, so key material is one contiguous run and so is
// signature material — a later suite adding a third key extends each run rather than
// interleaving a new pair, and the offsets stay readable.
const OFF_ED_PK = SUITE_LEN;
const OFF_ML_PK = OFF_ED_PK + PK_LEN;
const OFF_ED_SIG = OFF_ML_PK + ML_DSA_PK_LEN;
const OFF_ML_SIG = OFF_ED_SIG + SIG_LEN;
const OFF_JSON = OFF_ML_SIG + ML_DSA_SIG_LEN;
/** Module names double as filenames and as the guest's module keys, so they are held to an
 *  unambiguous charset — and, since one `host.call` carries three kinds of name, to a first
 *  character that cannot be either of the other two: a `/` would spell a host authority, a
 *  leading `_` a reserved protocol id (core/domains.ts). */
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;
/** A protocol id's charset (§12.10): alphanumeric first, then alphanumerics and `._/-`, at
 *  most 64 bytes. These travel on the wire and are what a receiving host routes by, so the
 *  whitespace, control and lookalike characters an operator could not tell apart are out. */
const PROTO_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$/;
/** A reserved protocol id: the same charset behind a leading `_`. These are local
 *  cross-realm service names — the only ids a guest may *call* (core/domains.ts), and ones
 *  inbound delivery refuses (shell-core.ts). Shape only: no spelling carries authority. */
const RESERVED_PROTO_RE = /^_[A-Za-z0-9._/-]{1,63}$/;
/** Canonical manifest bytes. The signed envelope carries these verbatim and the verifier
 *  parses the exact bytes it checked, so there is no separate canonicalisation step — the
 *  bytes *are* the manifest. */
export function encodeManifest(m: BundleManifest): Uint8Array {
    return enc.encode(JSON.stringify(m));
}
/** Signed preimage: `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖ json`. Both keys
 *  sign, and each commits to the other, so the pair cannot be taken apart. */
function manifestPreimage(edPk: Uint8Array, mlDsaPk: Uint8Array, json: Uint8Array): Uint8Array {
    return concatBytes([DOMAIN_MANIFEST, Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), edPk, mlDsaPk, json]);
}
/** Author id: `genesisHash(DOMAIN_manifest_author ‖ suite ‖ edPk ‖ mlDsaPk)`.
 *  The whole key set, so the id is unreachable without both private keys. */
export function hybridAuthorId(sodium: ManifestVerifier, edPk: Uint8Array, mlDsaPk: Uint8Array): Uint8Array {
    return sodium.crypto_generichash(32, concatBytes([DOMAIN_MANIFEST_AUTHOR, Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), edPk, mlDsaPk]), null);
}
/** What deriving an author's key set needs: the two keygens and the hash between them. */
export interface AuthorSeedCrypto {
    crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
    crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
    ml_dsa65_keypair_from_seed(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
}
/** Author key set from one 32-byte seed (§16.1). Pass the seed, not libsodium's 64-byte sk. */
export function hybridAuthorKeysFromSeed(sodium: AuthorSeedCrypto, seed: Uint8Array): HybridAuthorKeys {
    if (seed.length !== 32) {
        throw new Error(`bundle: an author seed is 32 bytes, got ${seed.length}` +
            " (holding libsodium's 64-byte secret key? pass sk.slice(0, 32))");
    }
    return {
        ed: sodium.crypto_sign_seed_keypair(seed),
        mlDsa: sodium.ml_dsa65_keypair_from_seed(
            sodium.crypto_generichash(32, concatBytes([seed, AUTHOR_MLDSA_SEED_LABEL]), null)),
    };
}
/** Sign a manifest into its envelope (§12.4). Both signatures are over the same preimage, so
 *  there is no ordering to get wrong. Throws without an ML-DSA signer: there is no second
 *  envelope to fall back to, so a build that cannot produce the PQ half fails at the build. */
export function signManifest(sodium: ManifestCrypto, keys: HybridAuthorKeys, m: BundleManifest): Uint8Array {
    if (!sodium.ml_dsa65_sign_detached) {
        throw new Error("bundle: no ML-DSA-65 signer — cannot sign a manifest");
    }
    const json = encodeManifest(m);
    const pre = manifestPreimage(keys.ed.publicKey, keys.mlDsa.publicKey, json);
    const edSig = sodium.crypto_sign_detached(pre, keys.ed.privateKey);
    const mlSig = sodium.ml_dsa65_sign_detached(pre, keys.mlDsa.privateKey);
    return concatBytes([
        Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), keys.ed.publicKey, keys.mlDsa.publicKey,
        edSig, mlSig, json,
    ]);
}
function isJsonValueAt(value: unknown, ancestors: Set<object>): value is JsonValue {
    if (value === null || typeof value === "string" || typeof value === "boolean")
        return true;
    if (typeof value === "number")
        return Number.isFinite(value);
    if (typeof value !== "object")
        return false;
    const object = value as object;
    if (ancestors.has(object))
        return false;
    const proto = Object.getPrototypeOf(object);
    if (!Array.isArray(value) && proto !== Object.prototype && proto !== null)
        return false;
    ancestors.add(object);
    try {
        return (Array.isArray(value) ? value : Object.values(value))
            .every((item) => isJsonValueAt(item, ancestors));
    }
    finally {
        ancestors.delete(object);
    }
}

/** True for exactly the values the signed manifest JSON can carry. Cycles, exotic prototypes
 *  and non-finite numbers are refused rather than silently changed by `JSON.stringify`. The
 *  prototype test is *this* realm's, so a value parsed in another realm is refused too — an
 *  embedder holding one re-parses it here. */
export function isJsonValue(value: unknown): value is JsonValue {
    try {
        return isJsonValueAt(value, new Set());
    }
    catch {
        return false;
    }
}

/** True for a JSON object — the shape both config channels carry. Exported because
 *  `localConfig` comes from an untyped embedding, where the type guarantees nothing. */
export function isJsonObject(value: unknown): value is JsonObject {
    return isJsonValue(value) && typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Structural check on a parsed manifest, run only *after* the signature verified — so not a
 *  security boundary: it turns a manifest the author signed but got wrong into a loud
 *  rejection instead of a TypeError deep in the loader. Shape only; whether this host
 *  *implements* the declared `abi`, or serves a required name, is `validateManifest`'s. */
function isValidManifest(m: unknown): m is BundleManifest {
    if (typeof m !== "object" || m === null || Array.isArray(m))
        return false;
    const o = m as Record<string, unknown>;
    // appSignScope encodes the app name in one length byte, so a name over 255 UTF-8 bytes
    // would verify and install but throw on the guest's first call — refused here, where
    // the error names the rule.
    if (typeof o.app !== "string" || o.app.length === 0)
        return false;
    if (enc.encode(o.app).length > 255)
        return false;
    if (typeof o.version !== "number" || !Number.isInteger(o.version))
        return false;
    // The claimed protocol ids (§12.10), checked like the module names below and for the
    // same reason: they are keys, so a duplicate is ambiguous rather than merely redundant.
    // Absent is legal (an initiator-only app claims nothing), as is `[]`.
    if (o.protocols !== undefined) {
        if (!Array.isArray(o.protocols))
            return false;
        const claimed = new Set();
        for (const p of o.protocols) {
            // Both shapes are well *formed* here; who may claim the reserved one is
            // answered in verifyManifest below.
            if (typeof p !== "string" || !(PROTO_RE.test(p) || RESERVED_PROTO_RE.test(p)))
                return false;
            if (claimed.has(p))
                return false;
            claimed.add(p);
        }
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
        if (seen.has(mm.name))
            return false;
        seen.add(mm.name);
    }
    // A manifest that *omits* `guest` entirely is caught by name in verifyManifest; this is
    // the shape check for one that declared a broken guest.
    if (o.guest === undefined)
        return false;
    {
        const g = o.guest as Record<string, unknown>;
        if (typeof g !== "object" || g === null || Array.isArray(g))
            return false;
        if (typeof g.hash !== "string")
            return false;
        if (typeof g.abi !== "number" || !Number.isInteger(g.abi))
            return false;
        if (!Array.isArray(g.requires) || g.requires.some((r: unknown) => typeof r !== "string"))
            return false;
        if (g.config !== undefined && !isJsonObject(g.config))
            return false;
    }
    return true;
}
/** The checks `verifyManifest` runs after a signature verifies and `authorBundle` runs
 *  *before* signing — one copy, so what a verifier refuses is exactly what an author refuses
 *  to sign. Shape and vocabulary only; whether *this* node grants a well-formed authority
 *  name is policy (§12.5), which lives in the shell. */
function validateManifest(manifest: unknown): asserts manifest is BundleManifest {
    if (!isValidManifest(manifest))
        throw new Error("bundle: malformed manifest");
    // Guest ABI support (§12.2) — the same kind of check as the suite, refused the same way,
    // at the one place a manifest becomes a value the rest of the runtime trusts.
    if (manifest.guest.abi !== GUEST_ABI_VERSION) {
        throw new Error(`bundle: guest ABI ${manifest.guest.abi} is not implemented by this host (supported: ${GUEST_ABI_VERSION})`);
    }
    // The declared requires. The vocabulary (§12.2) is closed and is the authorities alone:
    // an unknown name — `crypto/blake2b-256` included — is a refused manifest, not a grant
    // that quietly reaches nothing at first use. Well-formedness only: `link/open` is in the
    // vocabulary, and whether this node grants it is the shell's call (§12.5).
    for (const r of manifest.guest.requires) {
        // A reserved id grants over another *realm* rather than over a host authority, so it
        // is not in the catalog and only its shape can be wrong. Whether anything claims it
        // is answered at the call (guest-seam.ts): an app may legitimately be installed
        // before the local service that answers it.
        if (isReservedProtocol(r)) {
            if (!RESERVED_PROTO_RE.test(r)) {
                throw new Error(`bundle: "${r}" is not a well-formed reserved id (manifest guest.requires; "_" then alphanumerics and ._/-, at most 64 bytes)`);
            }
            continue;
        }
        if (!isGrant(r)) {
            // The authorities sharing the rejected name's prefix, not the whole list: a
            // misspelled `fs/exists`, or a bare `fs`, is answered by the `fs/` names.
            const prefix = r.includes("/") ? r.slice(0, r.indexOf("/") + 1) : r + "/";
            const near = Object.keys(AUTHORITY_CALLS).filter((n) => n.startsWith(prefix));
            const hint = near.length > 0
                ? `this host grants: ${near.join(", ")}`
                : `no authority under "${prefix}" exists — a pure name (crypto/*, or one of this bundle's own modules) is not a grant and is not declared`;
            throw new Error(`bundle: this host has no authority "${r}" (manifest guest.requires; ${hint})`);
        }
    }
}
/** Verify a manifest envelope; returns the author id + parsed manifest, or null if a
 *  signature is bad. Throws when the body is validly signed but not parseable JSON of the
 *  expected shape — a signed-but-broken manifest is fail-loud, not an untrusted input to
 *  drop — and on a suite this host cannot check at all, which is a legibility failure rather
 *  than a verdict. */
export function verifyManifest(sodium: ManifestVerifier, env: Uint8Array): VerifiedManifest | null {
    if (env.length < SUITE_LEN)
        return null;
    // Suite before offsets: another suite's keys and signatures are other widths, so parsing
    // first would read its bytes at this suite's positions. A legibility failure ("this
    // bundle wants a host I am not"), not an authenticity verdict, so it throws rather than
    // sending the operator after a bad signature. The suite byte is attacker-chosen and
    // public, so the distinction reveals nothing. The retired Ed25519-only suite is refused
    // here as a suite this host lacks (§14.1).
    const suite = env[0];
    if (suite !== SUITE_MANIFEST_HYBRID_PQ) {
        throw new Error(`bundle: unsupported manifest suite 0x${suite.toString(16).padStart(2, "0")}`);
    }
    // A host with no PQ verifier cannot form an opinion, so it says so. What it must not do
    // is read "I cannot check the PQ half" as "the PQ half is fine" and fall back to the
    // Ed25519 signature alone — the downgrade the suite exists to prevent (§14.1).
    if (!sodium.ml_dsa65_verify_detached) {
        throw new Error("bundle: unsupported manifest suite 0x02 — this host has no ML-DSA-65 verifier");
    }
    if (env.length < OFF_JSON)
        return null;
    const edPk = env.slice(OFF_ED_PK, OFF_ML_PK);
    const mlPk = env.slice(OFF_ML_PK, OFF_ED_SIG);
    const edSig = env.slice(OFF_ED_SIG, OFF_ML_SIG);
    const mlSig = env.slice(OFF_ML_SIG, OFF_JSON);
    const json = env.slice(OFF_JSON);
    const pre = manifestPreimage(edPk, mlPk, json);
    // Both, always: a break in either half then rejects valid bundles (recoverable) instead
    // of admitting forged ones (not).
    if (!sodium.crypto_sign_verify_detached(edSig, pre, edPk))
        return null;
    if (!sodium.ml_dsa65_verify_detached(mlSig, pre, mlPk))
        return null;
    const author = hybridAuthorId(sodium, edPk, mlPk);
    const authorKeys = { ed: edPk, mlDsa: mlPk };
    let parsed;
    try {
        parsed = JSON.parse(dec.decode(json));
    }
    catch {
        throw new Error("bundle: malformed manifest (not JSON)");
    }
    // Refused by name rather than as a shape error: this is the manifest a bundle written
    // against the old module-only format produces, so the rule is worth spelling out.
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
        && (parsed as Record<string, unknown>).guest === undefined) {
        throw new Error("bundle: this manifest declares no guest, and every app is a guest (§12.4) — the modules are the library it drives, so ship the guest that drives them");
    }
    // The same vocabulary the author checks before signing (`validateManifest`, shared with
    // `authorBundle`): one copy, so the author's checks cannot fall behind the verifier's.
    validateManifest(parsed);
    return { author, authorKeys, manifest: parsed };
}
/** True if `bytes` content hashes to the declared genesisHash hex (integrity). */
export function contentMatches(bytes: Uint8Array, declaredHex: string, genesisHash: (b: Uint8Array) => Uint8Array): boolean {
    return toHex(genesisHash(bytes)) === declaredHex.toLowerCase();
}
// ── The container (§12.4) ────────────────────────────────────────────────────
//
// Pure *framing*, not a signed format of its own: the manifest envelope inside carries the
// author's signature and its module hashes protect the bytes, so anyone can repack a bundle
// without weakening it. Layout, integers big-endian:
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
/** Parse a bundle blob back into its `{ file: bytes }` map. Throws on a mis-magicked or
 *  truncated blob — fail-loud, like a malformed manifest. */
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
/** Where a data directory's freshness marks live: a *sibling* of the directory, never a file
 *  inside it — an `fs`-capable guest writes files inside the dir, so a mark kept there would
 *  be a downgrade guard the guarded party can edit. Shared rather than restated per target,
 *  because two hosts computing it differently would put a node's marks where its next boot
 *  does not look, which reads as "no marks": every guard silently dropped. */
export function freshnessPathFor(dir: string): string {
    return dir.replace(/[/\\]+$/, "") + ".freshness.json";
}
/** The freshness *arithmetic*: the `(author, app)` key, the monotonic never-rewind rule, the
 *  revocation set and the `{ marks, revoked }` serialization (§12.4). Target-independent, so
 *  each target subclasses it with its own persistence seam (`persist`). On its own this is
 *  an in-memory store. */
export class FreshnessMarks {
    marks = new Map();
    /** Author keys written off (§12.5), as lowercase hex. */
    revoked = new Set();
    /** Seed from `{ marks, revoked }`. Absent input = first boot: start empty,
     *  which is "unrevoked" — so a target's `persist` must be atomic. Bare
     *  pre-revocation maps throw rather than reading as empty (would discard
     *  every downgrade guard); unknown keys are ignored. */
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
                // The legacy guard above catches only the old shape; a new-shaped store with
                // wrong-typed fields (`{"marks":"garbage"}`) would read as "no marks,
                // nothing revoked" just as silently. Guard data that exists but cannot be
                // read is a corrupt store, not an empty one.
                const marks = raw.marks;
                if (marks !== undefined) {
                    if (typeof marks !== "object" || marks === null || Array.isArray(marks)) {
                        throw new Error('freshness store: corrupt file — "marks" must be an object of {appKey: version} pairs');
                    }
                    for (const [k, v] of Object.entries(marks)) {
                        // Versions are manifest-verified integers; anything else silently
                        // changes what a downgrade check means (a float 2.5 re-prices every
                        // version below it).
                        if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
                            throw new Error(`freshness store: corrupt file — mark "${k}" is not a non-negative integer version (got ${JSON.stringify(v)})`);
                        }
                        this.marks.set(k, v);
                    }
                }
                const revoked = raw.revoked;
                if (revoked !== undefined) {
                    if (!Array.isArray(revoked)) {
                        throw new Error('freshness store: corrupt file — "revoked" must be an array of hex author ids');
                    }
                    for (const a of revoked) {
                        if (typeof a !== "string") {
                            throw new Error(`freshness store: corrupt file — a revoked entry is not a string (got ${JSON.stringify(a)})`);
                        }
                        this.revoked.add(a.toLowerCase());
                    }
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
    /** Write the serialized state durably. In-memory here; a target overrides it with its
     *  atomic-write seam — a truncated store reads back as "nothing known", discarding every
     *  downgrade guard and every revocation. */
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
    resetMark(author: Uint8Array, app: string, previous: number): void {
        const k = this.key(author, app);
        if (previous === -Infinity) this.marks.delete(k);
        else this.marks.set(k, previous);
    }
    revoke(author: Uint8Array): void {
        const hex = toHex(author);
        if (this.revoked.has(hex))
            return;
        this.revoked.add(hex);
        // Same rule as a mark that could not be persisted: in-memory state mirrors the store.
        // Keeping the key revoked in memory looks safer, but it makes the retry a silent
        // no-op (the early return above) while nothing ever reaches disk, and the next boot
        // admits the author anyway. Rolling back keeps `revoke` retryable.
        try {
            this.persist(this.serialize());
        }
        catch (e) {
            this.revoked.delete(hex);
            throw new Error(`freshness store: the revocation could not be persisted — ${hex} is NOT revoked: ${errMessage(e)}. ` +
                "Fix the store and revoke again.", { cause: e });
        }
    }
}
/** Authenticate and integrity-check a bundle blob (§12.4): verify the manifest signature,
 *  then hash every module and the guest against what it commits to. Throws on anything that
 *  does not check out. Takes no host and no policy, so "nothing has landed" is a property of
 *  the type. */
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
        manifest: v.manifest,
        modules: v.manifest.modules.map((mod) => ({ mod, wasm: read(moduleFile(mod.name)) })),
        guestSource: dec.decode(read(GUEST_FILE)),
    };
    // Inside verifyBundle rather than a separate step: the manifest hashes are the definitive
    // declaration of what the author authorized, so a verified signature over unchecked
    // hashes is not yet a verified bundle.
    for (const { mod, wasm } of result.modules) {
        if (!contentMatches(wasm, mod.hash, (b) => genesisHash(sodium, b))) {
            throw new Error(`bundle: ${mod.name} content hash mismatch`);
        }
    }
    if (!contentMatches(enc.encode(result.guestSource), v.manifest.guest.hash, (b) => genesisHash(sodium, b))) {
        throw new Error("bundle: guest content hash mismatch");
    }
    return result;
}
/** The raw materials for a new signed bundle — everything `authorBundle` hashes, assembles
 *  into a manifest, validates, signs and packs. `verifyBundle`'s mirror image.
 *  `modules[].hash` and `guest.hash` are *derived* here, never supplied, so there is no way
 *  to construct a bundle whose manifest and content disagree (§12.4). */
export interface UnsignedBundle {
    app: string;
    /** Monotonic per-(author, app) freshness mark (§12.4) — the caller's to bump. */
    version: number;
    protocols?: string[];
    modules: { name: string; wasm: Uint8Array }[];
    /** The guest program's source *text*: the manifest commits to its UTF-8 encoding (see
     *  `authorBundle`), so a string is the only shape that can be authored and also verify —
     *  arbitrary bytes with no valid UTF-8 round-trip would be a bundle that cannot come
     *  back. */
    guestSource: string;
    guestRequires: string[];
    guestConfig?: JsonObject;
}
/** What `authorBundle` returns: the packed signed blob, the manifest it signed, and the
 *  author id it is signed under — so a caller that logs or records what it just published
 *  reads it off the value rather than re-parsing the blob or recomputing the id. */
export interface AuthoredBundle {
    blob: Uint8Array;
    manifest: BundleManifest;
    /** The 32-byte key-set id of the signer (`hybridAuthorId`). */
    author: Uint8Array;
}
/** Build a new signed bundle from its raw materials (§12.4): hash every module and the
 *  guest, assemble the manifest, validate it with the verifier's own checks
 *  (`validateManifest`) so a bundle that verifier would refuse fails here at the author's
 *  desk rather than at first install, then sign (`signManifest`) and pack (`packBundle`).
 *  The one call every bundle author makes, and the mirror of `verifyBundle`. */
export function authorBundle(sodium: ManifestCrypto, keys: HybridAuthorKeys, input: UnsignedBundle): AuthoredBundle {
    const modules: BundleModule[] = input.modules.map(({ name, wasm }) => ({
        name, hash: toHex(genesisHash(sodium, wasm)),
    }));
    // The guest lives in the blob as its UTF-8 encoding; the manifest hashes those exact
    // bytes, and `verifyBundle` decodes them back to this text before re-checking.
    const guestBytes = enc.encode(input.guestSource);
    const guest: BundleGuest = {
        hash: toHex(genesisHash(sodium, guestBytes)),
        abi: GUEST_ABI_VERSION,
        requires: input.guestRequires,
        ...(input.guestConfig !== undefined ? { config: input.guestConfig } : {}),
    };
    const manifest: BundleManifest = {
        app: input.app,
        version: input.version,
        ...(input.protocols !== undefined ? { protocols: input.protocols } : {}),
        modules,
        guest,
    };
    validateManifest(manifest);
    const env = signManifest(sodium, keys, manifest);
    const files: Record<string, Uint8Array> = { [MANIFEST_FILE]: env, [GUEST_FILE]: guestBytes };
    for (const { name, wasm } of input.modules) files[moduleFile(name)] = wasm;
    return {
        blob: packBundle(files),
        manifest,
        author: hybridAuthorId(sodium, keys.ed.publicKey, keys.mlDsa.publicKey),
    };
}
/** Build a verified bundle's private modules, all or none (§3.1). Admission already ran. */
export async function loadBundleModules(host: PureModuleLoader, v: VerifiedBundle): Promise<PureModules> {
    // The §4.3 memory bound, read off the bytes *before* the host instantiates them —
    // instantiation is what allocates the declared initial memory, so a host-side check could
    // only run after the damage. Every module is checked before any is handed down.
    //
    // The number is the tighter of what a bundle may land and what this loader holds its own
    // isolates to (`PureModuleLoader.maxModuleMemoryBytes`), composed here because this is
    // the only call site: no second place for the rule to be got wrong, no module walked twice.
    const maxBytes = Math.min(DEFAULT_MAX_MODULE_MEMORY_BYTES, host.maxModuleMemoryBytes ?? Infinity);
    for (const { wasm } of v.modules) {
        checkModuleMemory(wasm, maxBytes);
    }
    // One transactional call: every module stands or none does, and the target owns that
    // guarantee because it holds the half-built instances.
    try {
        return await host.build(v.modules.map(({ mod, wasm }) => ({ name: mod.name, wasm })));
    }
    catch (e) {
        throw new Error(`bundle: module ${errMessage(e)}`, { cause: e });
    }
}
