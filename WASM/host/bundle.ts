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
//   <module>.install    its author-signed install envelope (dispatched verbatim)
//   <guest>.js          the safe-js guest program
//
// "Later pushed over the relay as signed installs" is the same `.install`
// envelopes, sent rather than read from disk.

import { concatBytes, toHex } from "./util.js";

export interface BundleModule {
  /** Logical name, e.g. "codec". */
  name: string;
  /** The module's filename within the bundle (`<name>.wasm`). */
  file: string;
  /** genesisHash(wasm) hex — content integrity for the .wasm file. */
  hash: string;
  /** Filename of the module's pre-signed install envelope within the bundle. */
  install: string;
  /** Kernel name the install binds (deriveBootstrapName/deriveScopedName hex), so
   *  the loader can confirm the module actually registered. */
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

/** Verify a manifest envelope; returns the author key + parsed manifest, or null
 *  if the signature is bad or the body is not valid manifest JSON. */
export function verifyManifest(sodium: ManifestCrypto, env: Uint8Array): { author: Uint8Array; manifest: BundleManifest } | null {
  if (env.length < PK_LEN + SIG_LEN) return null;
  const author = env.slice(0, PK_LEN);
  const sig = env.slice(PK_LEN, PK_LEN + SIG_LEN);
  const json = env.slice(PK_LEN + SIG_LEN);
  if (!sodium.crypto_sign_verify_detached(sig, manifestPreimage(json), author)) return null;
  try { return { author, manifest: JSON.parse(new TextDecoder().decode(json)) as BundleManifest }; }
  catch { return null; }
}

/** True if `bytes` content hashes to the declared genesisHash hex (integrity). */
export function contentMatches(bytes: Uint8Array, declaredHex: string, genesisHash: (b: Uint8Array) => Uint8Array): boolean {
  return toHex(genesisHash(bytes)) === declaredHex.toLowerCase();
}
