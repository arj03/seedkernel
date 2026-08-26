// Offline app-bundle authoring (§12.4). Runtime shells import only bundle.ts, which has no
// signing or packing surface; this module depends on the verifier's manifest validation so
// an author's accepted vocabulary cannot drift behind what a loader will accept.
import { concatBytes, toHex, enc } from "../core/util.js";
import { AUTHOR_MLDSA_SEED_LABEL, DOMAIN_MANIFEST, SUITE_MANIFEST_HYBRID_PQ } from "../core/domains.js";
import {
    GUEST_FILE,
    MANIFEST_FILE,
    genesisHash,
    hybridAuthorId,
    moduleFile,
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

/** Sign a manifest into its envelope (§12.4). Both signatures are over the same preimage, so
 *  there is no ordering to get wrong. Throws without an ML-DSA signer: there is no second
 *  envelope to fall back to, so a build that cannot produce the PQ half fails at the build. */
export function signManifest(sodium: ManifestCrypto, keys: HybridAuthorKeys, m: BundleManifest): Uint8Array {
    if (!sodium.ml_dsa65_sign_detached) {
        throw new Error("bundle: no ML-DSA-65 signer — cannot sign a manifest");
    }
    const json = encodeManifest(m);
    const pre = concatBytes([
        DOMAIN_MANIFEST, Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ),
        keys.ed.publicKey, keys.mlDsa.publicKey, json,
    ]);
    const edSig = sodium.crypto_sign_detached(pre, keys.ed.privateKey);
    const mlSig = sodium.ml_dsa65_sign_detached(pre, keys.mlDsa.privateKey);
    return concatBytes([
        Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), keys.ed.publicKey, keys.mlDsa.publicKey,
        edSig, mlSig, json,
    ]);
}

/** Serialize a set of named bundle files into one bundle blob (bundle.ts container format). */
export function packBundle(files: Record<string, Uint8Array>): Uint8Array {
    const names = Object.keys(files);
    const header = new Uint8Array(6);
    header.set([0x53, 0x4b, 0x42, 0x31], 0); // "SKB1"
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

/** The raw materials for a new signed bundle — hashes are derived, never supplied. */
export interface UnsignedBundle {
    app: string;
    /** Monotonic per-(author, app) freshness mark (§12.4) — the caller's to bump. */
    version: number;
    protocols?: string[];
    services?: string[];
    modules: { name: string; wasm: Uint8Array }[];
    /** Source text; the manifest commits to its UTF-8 encoding. */
    guestSource: string;
    guestRequires: string[];
    guestConfig?: JsonObject;
}

/** What `authorBundle` returns: the blob, signed manifest, and derived author id. */
export interface AuthoredBundle {
    blob: Uint8Array;
    manifest: BundleManifest;
    author: Uint8Array;
}

/** Hash, assemble, validate with the verifier's checks, sign and pack a bundle. */
export function authorBundle(sodium: ManifestCrypto, keys: HybridAuthorKeys, input: UnsignedBundle): AuthoredBundle {
    const modules: BundleModule[] = input.modules.map(({ name, wasm }) => ({
        name, hash: toHex(genesisHash(sodium, wasm)),
    }));
    const guestBytes = enc.encode(input.guestSource);
    const guest: BundleGuest = {
        hash: toHex(genesisHash(sodium, guestBytes)),
        requires: input.guestRequires,
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
    const env = signManifest(sodium, keys, manifest);
    const files: Record<string, Uint8Array> = { [MANIFEST_FILE]: env, [GUEST_FILE]: guestBytes };
    for (const { name, wasm } of input.modules) files[moduleFile(name)] = wasm;
    return {
        blob: packBundle(files),
        manifest,
        author: hybridAuthorId(sodium, keys.ed.publicKey, keys.mlDsa.publicKey),
    };
}

/** The op-frame codec as flat guest source for a build tool to inline before signing:
 *  `"use strict"` safe and import-free. Here rather than beside the TypeScript in
 *  host/op-frame.ts so a browser shell does not vendor a source emitter; run.mjs holds
 *  the two in step. */
export function guestOpFraming(): string {
    return `
// op-frame: optional client framing; seedkernel reads none of these body bytes.
const callerOf = (arg) => {
  const caller = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) {
    if (caller[i] !== 0) fromHost = false;
  }
  return { fromHost, caller, body: arg.subarray(32) };
};
const readOp = (body) => {
  const n = body.length > 0 ? body[0] : -1;
  if (n < 0 || body.length < 1 + n) throw new Error("op-frame: malformed op envelope");
  let op = "";
  for (let i = 0; i < n; i++) op += String.fromCharCode(body[1 + i]);
  return { op, args: body.subarray(1 + n) };
};
const writeOp = (op, args) => {
  if (op.length < 1 || op.length > 255) throw new Error("op-frame: op name must be 1..255 bytes");
  const out = new Uint8Array(1 + op.length + args.length);
  out[0] = op.length;
  for (let i = 0; i < op.length; i++) {
    const c = op.charCodeAt(i);
    if (c > 127) throw new Error("op-frame: op name must be ASCII");
    out[1 + i] = c;
  }
  out.set(args, 1 + op.length);
  return out;
};
`;
}
