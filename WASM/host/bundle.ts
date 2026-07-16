// The app bundle format (README §13.4). A bundle is *signed
// content* the generic shell loads from a file: a set of WASM handler modules, a
// zero-authority guest program, and a signed manifest declaring the op catalog +
// the capabilities the bundle needs. The shell verifies the manifest signature,
// governs it against its policy (author + module hashes), and installs the
// modules; the manifest's `caps` describe the seam the app's guest is wired
// over — honored by the generic cap bridge (README §13.2).
//
// The FORMAT here is application-neutral; seedstore fills in storage content
// (its build-bundle script). On disk a bundle is a directory:
//
//   manifest.bundle    signed manifest envelope [authorPk(32)][sig(64)][utf8 json]
//   <module>.wasm       each handler module
//   <guest>.js          the safe-js guest program
//
// The manifest commits to every module's genesisHash and the shell verifies the
// bytes against it, so the loader installs the verified module directly under its
// declared kernel name (§13.4) — there is no separate per-module install envelope.
// A live update over the relay is an ordinary signed §7.2 install (the wire path).

import { concatBytes, toHex } from "./util.js";

export interface BundleModule {
  /** Logical name, e.g. "codec". */
  name: string;
  /** The module's filename within the bundle (`<name>.wasm`). */
  file: string;
  /** genesisHash(wasm) hex — content integrity for the .wasm file, and the
   *  module's `bytes_hash` in the synthesized install record (§7.1, §13.4). */
  hash: string;
  /** Kernel name the loader binds the module at via SetHandler
   *  (deriveBootstrapName/deriveScopedName hex). The manifest is the authoritative
   *  source of the bind name now that modules install directly (§13.4). */
  kernelName: string;
}

export interface BundleManifest {
  app: string;
  /** Monotonic version of the coherent set (README §13.4). Enforced at load against
   *  a persisted per-`(author, app)` high-water mark: a load whose `version` is below
   *  the mark is refused as a downgrade. An integer, not a label. */
  version: number;
  modules: BundleModule[];
  /** The safe-js guest program: its filename + genesisHash(utf8(source)) hex. */
  guest: { file: string; hash: string };
  /** Capability *domains* (cap-bridge `CAP_DOMAINS` keys: "crypto" | "net" | "fs" |
   *  "module" | "clock") the bundle's guest is granted. The shell expands these to
   *  the concrete allowed op set and wires only the matching backends — so this is
   *  the enforced capability declaration, not just documentation. */
  caps: string[];
  /** App-specific constants the guest needs as injected globals (e.g. storage
   *  k/m/blockSize + the codec/reputation kernel names). Opaque to the runtime —
   *  the shell forwards it verbatim into the guest preamble as `const APP = …`. */
  config?: Record<string, string | number>;
}

/** The signing surface a manifest needs (a subset of libsodium). */
export interface ManifestCrypto {
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
}

const PK_LEN = 32;
const SIG_LEN = 64;

// Domain-separation prefix for the manifest signature (README §13.4, §17.1):
// `"seedkernel-manifest-sig-v1\0"`. Prepended to the manifest JSON before
// signing/verifying, never stored in the envelope — the disjoint prefix means a
// manifest signature can never double as an envelope-wrapper (DOMAIN_env, §6.3)
// or channel-handshake (DOMAIN, §13.6) signature over the same bytes.
const DOMAIN_MANIFEST = new TextEncoder().encode("seedkernel-manifest-sig-v1\0");

/** Canonical manifest bytes. The signed envelope carries these verbatim, and the
 *  verifier parses the exact bytes it checked, so no separate canonicalisation is
 *  needed — the bytes *are* the manifest. */
export function encodeManifest(m: BundleManifest): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(m));
}

/** The signed preimage: `DOMAIN_manifest ‖ json`. The prefix is signed but not
 *  stored — the envelope carries only the raw json. */
function manifestPreimage(json: Uint8Array): Uint8Array {
  return concatBytes([DOMAIN_MANIFEST, json]);
}

/** Sign a manifest → envelope `[authorPk(32)][sig(64)][utf8 json]`. */
export function signManifest(sodium: ManifestCrypto, sk: Uint8Array, pk: Uint8Array, m: BundleManifest): Uint8Array {
  const json = encodeManifest(m);
  const sig = sodium.crypto_sign_detached(manifestPreimage(json), sk);
  return concatBytes([pk, sig, json]);
}

/** Structural check on a parsed manifest. Runs only *after* the signature
 *  verified, so this is not a security boundary — it turns a manifest the author
 *  signed but got wrong (a missing/mistyped field) into a clean, loud rejection
 *  instead of a raw TypeError surfacing deep in the loader, and lets the rest of
 *  the runtime treat every field as present and correctly typed (matching the
 *  fail-loud posture of parsePolicy). `caps` is required here — the enforced
 *  capability declaration is never optional. */
function isValidManifest(m: unknown): m is BundleManifest {
  if (typeof m !== "object" || m === null || Array.isArray(m)) return false;
  const o = m as Record<string, unknown>;
  if (typeof o.app !== "string") return false;
  if (typeof o.version !== "number" || !Number.isInteger(o.version)) return false;
  if (!Array.isArray(o.modules)) return false;
  for (const mod of o.modules) {
    if (typeof mod !== "object" || mod === null) return false;
    const mm = mod as Record<string, unknown>;
    if (typeof mm.name !== "string" || typeof mm.file !== "string" ||
        typeof mm.hash !== "string" || typeof mm.kernelName !== "string") return false;
  }
  const g = o.guest as Record<string, unknown> | null;
  if (typeof g !== "object" || g === null ||
      typeof g.file !== "string" || typeof g.hash !== "string") return false;
  if (!Array.isArray(o.caps) || o.caps.some((c) => typeof c !== "string")) return false;
  if (o.config !== undefined) {
    if (typeof o.config !== "object" || o.config === null || Array.isArray(o.config)) return false;
    for (const v of Object.values(o.config as Record<string, unknown>)) {
      if (typeof v !== "string" && typeof v !== "number") return false;
    }
  }
  return true;
}

/** Verify a manifest envelope; returns the author key + parsed manifest, or null
 *  if the signature is bad. Throws `bundle: malformed manifest` when the body is
 *  validly signed but is not parseable JSON of the expected shape — a signed-but-
 *  broken manifest is a fail-loud condition, not an untrusted input to drop. */
export function verifyManifest(sodium: ManifestCrypto, env: Uint8Array): { author: Uint8Array; manifest: BundleManifest } | null {
  if (env.length < PK_LEN + SIG_LEN) return null;
  const author = env.slice(0, PK_LEN);
  const sig = env.slice(PK_LEN, PK_LEN + SIG_LEN);
  const json = env.slice(PK_LEN + SIG_LEN);
  if (!sodium.crypto_sign_verify_detached(sig, manifestPreimage(json), author)) return null;
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder().decode(json)); }
  catch { throw new Error("bundle: malformed manifest (not JSON)"); }
  if (!isValidManifest(parsed)) throw new Error("bundle: malformed manifest");
  return { author, manifest: parsed };
}

/** True if `bytes` content hashes to the declared genesisHash hex (integrity). */
export function contentMatches(bytes: Uint8Array, declaredHex: string, genesisHash: (b: Uint8Array) => Uint8Array): boolean {
  return toHex(genesisHash(bytes)) === declaredHex.toLowerCase();
}
