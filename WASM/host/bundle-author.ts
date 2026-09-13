// Offline app-bundle authoring (§12.4). Runtime shells import only bundle.ts, which has no
// signing or packing surface; this module depends on the verifier's manifest validation so
// an author's accepted vocabulary cannot drift behind what a loader will accept.
import { concatBytes, enc } from "../core/util.js";
import { AUTHOR_MLDSA_SEED_LABEL, SUITE_MANIFEST_HYBRID_PQ } from "../core/domains.js";
import { callerOf, readOp, writeOp } from "../core/op-frame.js";
import {
  hybridAuthorId,
  bundleSigningInput,
  validateManifest,
  type BundleGuest,
  type BundleManifest,
  type BundleModule,
  type JsonObject,
  type ManifestVerifier,
} from "./bundle.js";

/** The surface *signing* a manifest needs — the build-side of the format. */
export interface ManifestCrypto extends ManifestVerifier {
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  /** The PQ half of the signature; `signBundle` throws without it. */
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

/** What deriving an author's key set needs: the two keygens and the hash between them. */
export interface AuthorSeedCrypto {
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  ml_dsa65_keypair_from_seed(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
}

/** Canonical manifest bytes. The signed envelope carries these verbatim and the verifier
 *  parses the exact bytes it checked, so there is no separate canonicalisation step — the
 *  bytes *are* the manifest. */
export function encodeManifest(m: BundleManifest): Uint8Array {
  return enc.encode(JSON.stringify(m));
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

/** Frame the signed body: manifest, guest, modules in manifest order. Every length is
 *  a u32 big-endian byte count and is covered by both signatures. */
export function encodeBundleBody(m: BundleManifest, guest: Uint8Array, modules: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const bytes of [encodeManifest(m), guest, ...modules]) {
    if (bytes.length > 0xffffffff) throw new Error("bundle: body field exceeds u32 length");
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, bytes.length, false);
    parts.push(length, bytes);
  }
  return concatBytes(parts);
}

/** Sign the whole bundle. Low-level writer for tests as well as authorBundle; validation
 *  belongs to authorBundle so tests can sign malformed manifests and body layouts. */
export function signBundle(sodium: ManifestCrypto, keys: HybridAuthorKeys, m: BundleManifest,
  guest: Uint8Array, modules: Uint8Array[]): Uint8Array {
  if (!sodium.ml_dsa65_sign_detached) {
    throw new Error("bundle: no ML-DSA-65 signer — cannot sign a bundle");
  }
  const body = encodeBundleBody(m, guest, modules);
  const pre = bundleSigningInput(sodium, keys.ed.publicKey, keys.mlDsa.publicKey, body);
  const edSig = sodium.crypto_sign_detached(pre, keys.ed.privateKey);
  const mlSig = sodium.ml_dsa65_sign_detached(pre, keys.mlDsa.privateKey);
  return concatBytes([
    Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), keys.ed.publicKey, keys.mlDsa.publicKey,
    edSig, mlSig, body,
  ]);
}

/** The raw materials for a new signed bundle. */
export interface UnsignedBundle {
  app: string;
  /** Monotonic per-(author, app) freshness mark (§12.4) — the caller's to bump. */
  version: number;
  protocols?: string[];
  services?: string[];
  modules: { name: string; wasm: Uint8Array }[];
  /** Source text; the manifest commits to its UTF-8 encoding. */
  guestSource: string;
  /** The host SERVICES this guest is granted — `manifest.guest.requires`. */
  guestRequires: string[];
  /** The local service ids this guest calls — `manifest.guest.calls`. Omitted ≡ none. */
  guestCalls?: string[];
  guestConfig?: JsonObject;
}

/** What `authorBundle` returns: the blob, signed manifest, and derived author id. */
export interface AuthoredBundle {
  blob: Uint8Array;
  manifest: BundleManifest;
  author: Uint8Array;
}

/** Assemble, validate with the verifier's checks, and sign the entire bundle. */
export function authorBundle(sodium: ManifestCrypto, keys: HybridAuthorKeys, input: UnsignedBundle): AuthoredBundle {
  const modules: BundleModule[] = input.modules.map(({ name }) => ({ name }));
  const guestBytes = enc.encode(input.guestSource);
  const guest: BundleGuest = {
    requires: input.guestRequires,
    ...(input.guestCalls !== undefined ? { calls: input.guestCalls } : {}),
    ...(input.guestConfig !== undefined ? { config: input.guestConfig } : {}),
  };
  const manifest: BundleManifest = {
    app: input.app,
    version: input.version,
    ...(input.protocols !== undefined ? { protocols: input.protocols } : {}),
    ...(input.services !== undefined ? { services: input.services } : {}),
    modules,
    guest,
  };
  validateManifest(manifest);
  return {
    blob: signBundle(sodium, keys, manifest, guestBytes, input.modules.map(({ wasm }) => wasm)),
    manifest,
    author: hybridAuthorId(sodium, keys.ed.publicKey, keys.mlDsa.publicKey),
  };
}

/** The canonical op-frame functions as flat guest source for a build tool to inline before
 *  signing. Their implementations live only in op-frame.ts; serializing the compiled,
 *  self-contained functions gives an import-free guest the exact code host callers run.
 *
 *  Newlines are forced to LF: every caller inlines this into a guest it then SIGNS, and the
 *  compiler's line endings are a property of the machine that built this file, not of the
 *  program. */
export function guestOpFraming(): string {
  const src = [callerOf, readOp, writeOp].map((fn) => fn.toString()).join("\n");
  return `
// op-frame: kernel raw-link event ABI; optional framing for application bodies.
${src}
`.replace(/\r\n/g, "\n");
}
