// The app bundle format (README §12.4). A bundle is *signed
// content* the generic shell loads from a file: a set of WASM handler modules, a
// zero-authority guest program, and a signed manifest declaring the op catalog +
// the capabilities the bundle needs. The shell verifies the manifest signature,
// governs it against its policy (author + module hashes), and installs the
// modules; the manifest's `caps` describe the seam the app's guest is wired
// over — honored by the generic cap bridge (README §12.2).
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
// declared kernel name (§12.4) — there is no separate per-module install envelope.
// A live update over the relay is an ordinary signed §7.2 install (the wire path).

import { concatBytes, fromHex, toHex } from "./util.js";
import type { ShellPolicy } from "./policy.js";

export interface BundleModule {
  /** Logical name, e.g. "codec". */
  name: string;
  /** The module's filename within the bundle (`<name>.wasm`). */
  file: string;
  /** genesisHash(wasm) hex — content integrity for the .wasm file, and the
   *  module's `bytes_hash` in the synthesized install record (§7.1, §12.4). */
  hash: string;
  /** Kernel name the loader binds the module at via SetHandler
   *  (deriveBootstrapName/deriveScopedName hex). The manifest is the authoritative
   *  source of the bind name now that modules install directly (§12.4). */
  kernelName: string;
}

export interface BundleManifest {
  app: string;
  /** Monotonic version of the coherent set (README §12.4). Enforced at load against
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

/** The surface *verifying* a manifest needs (a subset of libsodium). Deliberately
 *  separate from `ManifestCrypto`: a loader only ever checks signatures, so it is
 *  handed no way to make one — and a target whose realm exposes only a verifier
 *  (the native loader, README §12.9) can still run the shared loader below. */
export interface ManifestVerifier {
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
}

/** The surface *signing* a manifest needs — the build-side of the format. */
export interface ManifestCrypto extends ManifestVerifier {
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
}

const PK_LEN = 32;
const SIG_LEN = 64;

// Domain-separation prefix for the manifest signature (README §12.4, §16.1):
// `"seedkernel-manifest-sig-v1\0"`. Prepended to the manifest JSON before
// signing/verifying, never stored in the envelope — the disjoint prefix means a
// manifest signature can never double as an envelope-wrapper (DOMAIN_env, §6.3)
// or channel-handshake (DOMAIN, §12.6) signature over the same bytes.
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
export function verifyManifest(sodium: ManifestVerifier, env: Uint8Array): { author: Uint8Array; manifest: BundleManifest } | null {
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

// ── Freshness (README §12.4 step 3) ──────────────────────────────────────────

/** The persisted bundle-freshness high-water mark per `(author, app)` (README §12.4).
 *  Host-local state that survives reboots, so an older signed bundle directory cannot
 *  silently replace a newer one — the guest is loaded wholesale from the directory at
 *  every boot and carries no `seq` of its own. */
export interface FreshnessStore {
  /** The highest `version` ever loaded for this `(author, app)`, or −Infinity if none. */
  get(author: Uint8Array, app: string): number;
  /** Advance the mark to `version` (monotonic; a lower value never rewinds it). */
  set(author: Uint8Array, app: string, version: number): void;
}

/** The freshness *arithmetic*: the `(author, app)` key derivation, the monotonic
 *  never-rewind rule, and the `{ "authorHex:app": version }` serialization. All of
 *  it is target-independent, so it lives here and every target subclasses this with
 *  its own persistence seam (`persist`) rather than restating the rules — the author
 *  hex is fixed-length, so the key is unambiguous. On its own this is an in-memory
 *  store: `persist` does nothing, which is exactly right for a test. */
export class FreshnessMarks implements FreshnessStore {
  protected readonly marks = new Map<string, number>();

  /** Seed from a persisted `{ "authorHex:app": version }` blob. Absent, unreadable
   *  or malformed input ⇒ start empty (−∞ for every key); a target's loader hands in
   *  null rather than throwing, since a missing store is the first-boot case. */
  protected load(json: string | null): void {
    if (!json) return;
    try {
      const raw = JSON.parse(json) as Record<string, unknown>;
      for (const [k, v] of Object.entries(raw)) if (typeof v === "number") this.marks.set(k, v);
    } catch { /* malformed ⇒ start empty */ }
  }

  /** Serialize the marks for `persist`. */
  protected serialize(): string {
    const obj: Record<string, number> = {};
    for (const [k, v] of this.marks) obj[k] = v;
    return JSON.stringify(obj);
  }

  /** Write the serialized marks durably. The base store is in-memory only; a target
   *  overrides this with its atomic-write seam (README §12.4 requires the write be
   *  atomic — a truncated store reads back as "no marks", silently discarding every
   *  downgrade guard). */
  protected persist(_json: string): void {}

  private key(author: Uint8Array, app: string): string { return toHex(author) + ":" + app; }

  get(author: Uint8Array, app: string): number {
    const v = this.marks.get(this.key(author, app));
    return v === undefined ? -Infinity : v;
  }

  set(author: Uint8Array, app: string, version: number): void {
    const k = this.key(author, app);
    const cur = this.marks.get(k);
    if (cur !== undefined && cur >= version) return; // monotonic: never rewound
    this.marks.set(k, version);
    this.persist(this.serialize());
  }
}

// ── Loading (README §12.4) ───────────────────────────────────────────────────

/** The bundle directory as the loader sees it: named files it can read. The fs is a
 *  platform seam — Node reads the directory, the native loader hands in bytes its Go
 *  bridge already read — so the *order* of checks below (the security-relevant part)
 *  is written once for both. */
export interface BundleSource {
  /** Raw bytes of `file`. Throws if absent. */
  read(file: string): Uint8Array;
  /** UTF-8 text of `file`. Throws if absent. */
  readText(file: string): string;
}

/** The host powers loading a bundle needs: hash bytes with the genesis suite, and
 *  land a verified module under the install policy. `KernelHost` satisfies it; the
 *  native loader supplies the same two members over its Go bridge (README §12.9). */
export interface BundleHost {
  genesisHash(data: Uint8Array): Uint8Array;
  installBundleModule(name: Uint8Array, wasm: Uint8Array, authorPubKey: Uint8Array): boolean;
}

export interface LoadedBundle {
  manifest: BundleManifest;
  author: Uint8Array;
  guestSource: string;
  /** Logical names of the modules that registered on the kernel. */
  installed: string[];
}

/** Load a signed bundle: verify the manifest signature, require its author to be in
 *  the policy, enforce version freshness, integrity-check each module against its
 *  declared content hash, install each verified module directly under its declared
 *  kernel name (synthesizing the record with the manifest author, under the same
 *  install policy — §12.4), and integrity-check the guest. Returns the parsed
 *  manifest + guest source + which modules registered.
 *
 *  This is the whole §12.4 load order in one place, over the `BundleSource` /
 *  `BundleHost` seams — the checks and their sequence are the protocol, so no target
 *  restates them (README §12.9). */
export function loadBundle(
  host: BundleHost,
  sodium: ManifestVerifier,
  policy: ShellPolicy,
  src: BundleSource,
  freshness?: FreshnessStore,
): LoadedBundle {
  const v = verifyManifest(sodium, src.read("manifest.bundle"));
  if (!v) throw new Error("bundle: manifest signature invalid");
  if (!policy.authors.map((a) => a.toLowerCase()).includes(toHex(v.author))) {
    throw new Error("bundle: manifest author is not in the policy's allowed set");
  }
  // Freshness (README §12.4 step 3): the `version` is an enforced monotonic integer
  // (verifyManifest already shape-checked it). Refuse a load below the persisted
  // `(author, app)` high-water mark as a downgrade — nothing lands — otherwise advance
  // the mark. Equal versions reload (an ordinary reboot re-reads the same directory);
  // the mark is never rewound.
  const version = v.manifest.version;
  if (freshness) {
    const highWater = freshness.get(v.author, v.manifest.app);
    if (version < highWater) {
      throw new Error(`bundle: version ${version} is below the (author, app) freshness high-water mark ${highWater} — downgrade refused`);
    }
    // NB: the mark is advanced at the *end* of this function, only after every module
    // and the guest have integrity-checked and installed — not here. See below.
  }
  const gh = (b: Uint8Array) => host.genesisHash(b);
  // Verify everything, then land anything (README §12.4 "mismatch ⇒ reject; nothing
  // has landed"). Read + integrity-check every module and the guest FIRST, holding
  // the verified bytes in memory; only once the whole set checks out do we install.
  // A mismatch anywhere throws before any SetHandler runs, so a bad file can never
  // leave a partial bundle installed on the kernel.
  const verified: { mod: BundleModule; wasm: Uint8Array }[] = [];
  for (const mod of v.manifest.modules) {
    const wasm = src.read(mod.file);
    if (!contentMatches(wasm, mod.hash, gh)) throw new Error(`bundle: ${mod.name} content hash mismatch`);
    verified.push({ mod, wasm });
  }
  const guestSource = src.readText(v.manifest.guest.file);
  if (!contentMatches(new TextEncoder().encode(guestSource), v.manifest.guest.hash, gh)) {
    throw new Error("bundle: guest content hash mismatch");
  }
  // Everything integrity-checked — install the verified bytes. Each module lands
  // directly under its kernel name, synthesizing the install record with the manifest
  // author (§12.4). No per-module `.install` envelope means no 64 KB envelope cap and
  // no boot-time seq — an equal-version reload just re-installs. A module the policy
  // refuses does not abort the load: it is simply reported as not installed.
  const installed: string[] = [];
  for (const { mod, wasm } of verified) {
    if (host.installBundleModule(fromHex(mod.kernelName), wasm, v.author)) installed.push(mod.name);
  }
  // Advance the freshness mark only now — after a fully successful load. Advancing it
  // during the downgrade check above (before the per-module and guest hash checks) would
  // brick rollback: a partially written or corrupt *newer* bundle — manifest intact and
  // signed, but one module or the guest file wrong — would raise the mark to the new
  // version, then throw. Nothing runs, yet reloading the known-good older directory is now
  // refused as a downgrade until an operator hand-edits the freshness file. The mark must
  // record the highest version that actually loaded (README §12.4).
  if (freshness) freshness.set(v.author, v.manifest.app, version);
  return { manifest: v.manifest, author: v.author, guestSource, installed };
}
