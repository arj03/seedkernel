// Offline app-bundle authoring (§12.4). A running host imports only bundle.ts, which cannot
// sign or pack; this module reuses the verifier's manifest validation so an author cannot
// sign what install would refuse.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";
import type ts from "typescript";
import { concatBytes, enc, Fifo, fromHex, toHex } from "../services/util.js";
import { engineSodium, type HostSodium } from "../host/sodium-engine.js";
import { randomBytes, syncWebEngine } from "../host/platform-web.js";
import { AUTHOR_MLDSA_SEED_LABEL, DOMAIN_HOST, DOMAIN_MANIFEST, SUITE_MANIFEST_HYBRID_PQ } from "../services/domains.js";
import { callerOf, readOp, writeOp, OpArgs } from "../services/op-frame.js";
import { utf8Encode, utf8Decode } from "../services/utf8.js";
import type { Keypair } from "../services/subkeys.js";
import { HOST_PART_NAMES, type HostManifest, type HostParts } from "../host/host-blob.js";
import {
  hybridAuthorId,
  envelopeSigningInput,
  validateManifest,
  type BundleGuest,
  type BundleManifest,
  type BundleModule,
  type JsonObject,
  type ManifestVerifier,
} from "../host/bundle.js";

/** What signing a manifest needs. */
export interface ManifestCrypto extends ManifestVerifier {
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  /** The PQ half of the signature. */
  ml_dsa65_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
}

/** An author's key set (§12.4). Both keys together are the identity (`hybridAuthorId`).
 *  Only names whose shape depends on the suite carry "hybrid". */
export interface HybridAuthorKeys {
  ed: Keypair;
  mlDsa: Keypair;
}

/** What deriving an author's key set needs: the two keygens and the hash between them. */
export interface AuthorSeedCrypto {
  crypto_sign_seed_keypair(seed: Uint8Array): Keypair;
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  ml_dsa65_keypair_from_seed(seed: Uint8Array): Keypair;
}

/** Manifest bytes. The signed envelope carries these verbatim and the verifier parses the
 *  exact bytes it checked, so no separate canonicalization is needed. */
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

/** A build script's author: the host's crypto over the package's wasm, and the key set from
 *  `--key <hex seed>` in `argv`, else from `keyFile` under `root`, which the first build
 *  writes, so each clone has its own author (§12.5). Both halves derive from the seed. */
export function buildAuthor(root: string, keyFile: string, argv: string[]): { sodium: HostSodium; keys: HybridAuthorKeys } {
  const sodium = engineSodium(syncWebEngine, readFileSync(join(root, "browser", "libsodium.wasm")),
    readFileSync(join(root, "browser", "mldsa65.wasm")), randomBytes);
  const flag = argv.indexOf("--key");
  const keyPath = join(root, keyFile);
  let seed: Uint8Array;
  if (flag >= 0 && argv[flag + 1]) {
    seed = fromHex(argv[flag + 1]);
  } else if (existsSync(keyPath)) {
    seed = fromHex(readFileSync(keyPath, "utf8").trim());
  } else {
    seed = randomBytes(32);
    writeFileSync(keyPath, toHex(seed) + "\n", { mode: 0o600 });
    console.log(`  wrote ${keyFile} (keep it; this clone's builds are signed by it)`);
  }
  return { sodium, keys: hybridAuthorKeysFromSeed(sodium, seed) };
}

/** Frame parts as a signed body: each a u32 big-endian byte count, then the bytes, all
 *  covered by both signatures. */
function encodeParts(fields: Uint8Array[]): Uint8Array {
  const body = new OpArgs();
  for (const bytes of fields) body.blob(bytes);
  return body.build();
}

/** Frame a bundle's body: manifest, guest, modules in manifest order. */
export function encodeBundleBody(m: BundleManifest, guest: Uint8Array, modules: Uint8Array[]): Uint8Array {
  return encodeParts([encodeManifest(m), guest, ...modules]);
}

/** Sign a body under `domain` as a suite 0x02 envelope. */
function signEnvelope(sodium: ManifestCrypto, keys: HybridAuthorKeys, domain: Uint8Array,
  body: Uint8Array): Uint8Array {
  const pre = envelopeSigningInput(sodium, domain, keys.ed.publicKey, keys.mlDsa.publicKey, body);
  const edSig = sodium.crypto_sign_detached(pre, keys.ed.privateKey);
  const mlSig = sodium.ml_dsa65_sign_detached(pre, keys.mlDsa.privateKey);
  return concatBytes([
    Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), keys.ed.publicKey, keys.mlDsa.publicKey,
    edSig, mlSig, body,
  ]);
}

/** Sign the whole bundle. A low-level writer used by authorBundle and by tests; it does
 *  not validate, so tests can sign malformed manifests and body layouts. */
export function signBundle(sodium: ManifestCrypto, keys: HybridAuthorKeys, m: BundleManifest,
  guest: Uint8Array, modules: Uint8Array[]): Uint8Array {
  return signEnvelope(sodium, keys, DOMAIN_MANIFEST, encodeBundleBody(m, guest, modules));
}

/** Sign a host blob (host-blob.ts). */
export function signHostBlob(sodium: ManifestCrypto, keys: HybridAuthorKeys, manifest: HostManifest,
  parts: HostParts): Uint8Array {
  return signEnvelope(sodium, keys, DOMAIN_HOST,
    encodeParts([enc.encode(JSON.stringify(manifest)), ...HOST_PART_NAMES.map((n) => parts[n])]));
}

/** The raw materials for a new signed bundle. */
export interface UnsignedBundle {
  app: string;
  /** Monotonic per-(author, app) version (§12.4); the caller increments it. */
  version: number;
  protocols?: string[];
  services?: string[];
  modules: { name: string; wasm: Uint8Array }[];
  /** Source text; the manifest commits to its UTF-8 encoding. */
  guestSource: string;
  /** Everything this guest reaches: host services and local service ids
   *  (`manifest.guest.requires`). */
  guestRequires: string[];
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
  const guestBytes = enc.encode(stripComments(input.guestSource));
  const guest: BundleGuest = {
    requires: input.guestRequires,
    ...(input.guestConfig !== undefined ? { config: input.guestConfig } : {}),
  };
  // Round-tripped, so what is validated is what a verifier parses from the signed bytes.
  const manifest: BundleManifest = JSON.parse(JSON.stringify({
    app: input.app,
    version: input.version,
    ...(input.protocols !== undefined ? { protocols: input.protocols } : {}),
    ...(input.services !== undefined ? { services: input.services } : {}),
    modules,
    guest,
  }));
  validateManifest(manifest);
  return {
    blob: signBundle(sodium, keys, manifest, guestBytes, input.modules.map(({ wasm }) => wasm)),
    manifest,
    author: hybridAuthorId(sodium, keys.ed.publicKey, keys.mlDsa.publicKey),
  };
}

/** A guest's source without its comments, which nothing running reads: what `authorBundle`
 *  signs. TypeScript's parser finds them, so a `//` in a string, a template or a regular
 *  expression is never taken for one, and each is cut from the text as it stands, which is
 *  never reprinted. A comment alone on its lines takes them with it; one beside code takes
 *  the whitespace before it, and one that spans lines leaves the line break that semicolon
 *  insertion reads. */
export function stripComments(source: string): string {
  const parser = createRequire(import.meta.url)("typescript") as typeof ts;
  const src = source.replace(/\r\n?/g, "\n");
  const file = parser.createSourceFile("guest.js", src,
    { languageVersion: parser.ScriptTarget.Latest, jsDocParsingMode: parser.JSDocParsingMode.ParseNone }, false,
    parser.ScriptKind.JS);
  // Every comment is trivia of a token: trailing the one before it on its line, or else
  // leading the one after it.
  const comments = new Map<number, number>();
  const visit = (node: ts.Node): void => {
    for (const c of parser.getLeadingCommentRanges(src, node.pos) ?? []) comments.set(c.pos, c.end);
    for (const c of parser.getTrailingCommentRanges(src, node.end) ?? []) comments.set(c.pos, c.end);
    for (const child of node.getChildren(file)) visit(child);
  };
  visit(file);
  let out = "", at = 0;
  for (const [pos, end] of [...comments].sort((a, b) => a[0] - b[0])) {
    const lineStart = src.lastIndexOf("\n", pos - 1) + 1;
    const next = src.indexOf("\n", end), lineEnd = next < 0 ? src.length : next;
    if (lineStart >= at && src.slice(lineStart, pos).trim() === "" && src.slice(end, lineEnd).trim() === "") {
      out += src.slice(at, lineStart);
      at = lineEnd + 1;
    } else {
      out += src.slice(at, pos).replace(/[ \t]+$/, "");
      out += src.slice(pos, end).includes("\n") ? "\n" : /\s/.test(src[end] ?? "\n") ? "" : " ";
      at = end;
    }
  }
  return out + src.slice(at);
}

/** The op-frame functions as flat guest source, for a build tool to inline before signing.
 *  They are implemented only in op-frame.ts; serializing the compiled functions gives an
 *  import-free guest the same code the host runs.
 *
 *  Newlines are forced to LF because callers sign the result, and the compiled line
 *  endings depend on the machine that built this file. */
export function guestOpFraming(): string {
  const src = [callerOf, readOp, writeOp, utf8Encode, utf8Decode, Fifo].map((fn) => fn.toString()).join("\n");
  return `
// op-frame: the host's raw-link event ABI; optional framing for application bodies; UTF-8,
// which a realm has no TextEncoder for; the host's queue.
${src}
`.replace(/\r\n/g, "\n");
}
