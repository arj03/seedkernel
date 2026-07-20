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
// bytes against it, so the loader admits the verified module directly under its
// declared kernel name (§12.4) — there is no separate per-module install envelope.
// A live update is not a separate mechanism: it is a bundle whose manifest `version`
// is higher, which freshness requires and the same-author rule (§12.5) admits.

import { concatBytes, toHex } from "./util.js";
import { DOMAIN_MANIFEST } from "./domains.js";
import type { ShellPolicy } from "./policy.js";
import type { Signer } from "./kernel-host.js";

export interface BundleModule {
  /** Logical name, e.g. "codec". */
  name: string;
  /** The module's filename within the bundle (`<name>.wasm`). */
  file: string;
  /** genesisHash(wasm) hex — content integrity for the .wasm file, and the
   *  module's `bytes_hash` in the loader's install record (§5.1, §12.4). */
  hash: string;
  /** Kernel name the loader binds the module at via SetHandler — the name itself
   *  (`deriveBootstrapName`'s ASCII, or `deriveScopedName`'s hex), carried verbatim
   *  into the table. The manifest is the authoritative source of the bind name now
   *  that the loader admits modules directly (§12.4). */
  kernelName: string;
}

export interface BundleManifest {
  app: string;
  /** Monotonic version of the coherent set (README §12.4). Enforced at load against
   *  a persisted per-`(author, app)` high-water mark: a load whose `version` is below
   *  the mark is refused as a downgrade. An integer, not a label. */
  version: number;
  modules: BundleModule[];
  /** The safe-js guest program: its filename + genesisHash(utf8(source)) hex.
   *  Optional — a handler-only bundle (app modules bound as handlers, no zero-authority
   *  realm — e.g. the chat demo) omits it. Present ⇒ the loader integrity-checks the
   *  source and hands it back for the shell to run in a confined realm (§12.2). */
  guest?: { file: string; hash: string };
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
// `"seedkernel-manifest-sig-v1\0"` — from the one domain family (domains.ts, §16.1).
// Prepended to the manifest JSON before signing/verifying, never stored in the
// envelope — the disjoint prefix means a manifest signature can never double as a
// guest SIGN (DOMAIN_guest, §12.2) or channel-handshake (DOMAIN_channel, §12.6)
// signature over the same bytes.

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
  if (o.guest !== undefined) {
    const g = o.guest as Record<string, unknown> | null;
    if (typeof g !== "object" || g === null ||
        typeof g.file !== "string" || typeof g.hash !== "string") return false;
  }
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

// ── Admission: the loader's install records (README §12.4) ───────────────────
//
// Binding a module IS the loader's job — there is no separate "module registry". The
// store below holds one host-side table, `installations[name] → {author, bytesHash}`,
// read only here and never over the wire, and drives the one admission step: hash the
// verified bytes, consult the admission policy (§12.5), and on approval instantiate +
// SetHandler the module and record `(author, bytesHash)`. A raw SetHandler that mutates a
// slot (the host's own `register` / `removeHandler`, §3.1) forgets that slot's record
// first, so an old author is never carried onto brand-new bytes.

/** A single install record (README §12.4): who signed the bundle that bound the bytes,
 *  and the bytes' content id. */
export interface InstallRecord {
  readonly author: Signer;
  /** genesisHash(wasm) (§5.1) — the same id a manifest's `modules[].hash` and a policy
   *  `modules` allowlist carry. */
  readonly bytesHash: Uint8Array;
}

/** The admission decision (README §12.5): given a verified module and the record already
 *  at its name (or null), return true to bind it, false to refuse. The default is
 *  `buildAdmit` (policy.ts); a deployment that needs more — an M-of-N quorum, an HSM
 *  console, bytecode validation over `wasm` — supplies its own in its place. It runs once
 *  per module at load time, never on a message path, so it may be arbitrarily expensive. */
export type AdmitPolicy = (
  name: string,
  author: Signer,
  bytesHash: Uint8Array,
  wasm: Uint8Array,
  current: InstallRecord | null,
) => boolean;

/** The host powers the record store runs over (README §12.4): hash with the genesis hash,
 *  instantiate + bind a verified handler, and ask whether a name is already bound.
 *  `KernelHost` satisfies it; the native loader supplies the same three over its Go bridge
 *  (README §12.9), so the admission below is not re-derived in a second language. */
export interface RecordHost {
  genesisHash(data: Uint8Array): Uint8Array;
  /** Instantiate handler bytes against the §4 ABI and bind them at `name`. */
  _installWasmHandler(name: string, wasm: Uint8Array): boolean;
  /** True if a handler already occupies `name` — used to refuse overlaying a hand-seeded
   *  slot on a first install (README §12.4). */
  isRegistered(name: string): boolean;
}

/** The loader's install records + admission step (README §12.4). Held by the host that
 *  binds handlers (KernelHost, the native loader), so a raw SetHandler over a recorded name
 *  can `forget` its record. This is NOT a wire surface: there is no install message, no
 *  seq, no replay table — the signed manifest is the one authentication and `admit` the one
 *  authorization. */
export class InstallRecords {
  private readonly installations = new Map<string, InstallRecord>();
  private admitPolicy: AdmitPolicy | null = null;

  constructor(private readonly host: RecordHost) {}

  /** Wire the admission policy (README §12.5). Null (the boot default) refuses every bind,
   *  so admission is opt-in for the deployment (README §14). */
  setPolicy(admit: AdmitPolicy | null): void { this.admitPolicy = admit; }

  /** The install record at `name`, or null. Host-side only — there is no wire query; the
   *  admission policy already receives the resolved `current` record. */
  lookup(name: string): InstallRecord | null {
    return this.installations.get(name) ?? null;
  }

  /** Drop any record at `name`. The host calls it when a raw SetHandler (re)binds or unbinds
   *  the slot (§3.1), so a stale `(author, bytesHash)` can't misattribute brand-new bytes.
   *  Idempotent. */
  forget(name: string): void { this.installations.delete(name); }

  /** Admit one verified module (README §12.4): hash the bytes, refuse to overlay a
   *  hand-seeded slot, consult the policy, then instantiate + bind and record
   *  `(author, bytesHash)`. The whole admission, and the only path that mutates the kernel
   *  table with a record behind it — the bundle loader calls it once per module through
   *  `host.installBundleModule`, with the manifest author.
   *
   *  A bundle carries no per-module signature or seq: the signed manifest already
   *  authenticated the coherent set and committed to each module's `genesisHash` (§12.4), so
   *  a second per-module proof would be pure redundancy. Returns true on success, false if
   *  no policy is wired or the policy refuses. */
  admit(name: string, wasm: Uint8Array, author: Signer): boolean {
    if (name.length === 0 || wasm.length === 0) return false;
    const bytesHash = this.host.genesisHash(wasm);
    const current = this.installations.get(name) ?? null;
    // Refuse to overlay a hand-seeded slot: no record but the kernel already resolves the
    // name means a deliberately wired handler the loader will not silently replace (§12.4).
    if (current == null && this.host.isRegistered(name)) return false;
    if (!this.admitPolicy) return false;
    let approved = false;
    try { approved = this.admitPolicy(name, author, bytesHash, wasm, current); }
    catch { approved = false; }
    if (!approved) return false;
    // Instantiate + SetHandler first, then record — in that order, so a record never points
    // at a slot we failed to populate.
    if (!this.host._installWasmHandler(name, wasm)) return false;
    this.installations.set(name, {
      author: { algoId: author.algoId, publicKey: author.publicKey.slice() },
      bytesHash,
    });
    return true;
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

/** The host powers loading a bundle needs: hash bytes with the genesis hash, and
 *  land a verified module under the install policy. `KernelHost` satisfies it; the
 *  native loader supplies the same two members over its Go bridge (README §12.9). */
export interface BundleHost {
  genesisHash(data: Uint8Array): Uint8Array;
  installBundleModule(name: string, wasm: Uint8Array, authorPubKey: Uint8Array): boolean;
}

export interface LoadedBundle {
  manifest: BundleManifest;
  author: Uint8Array;
  /** The verified guest source, or `""` for a handler-only bundle that declared no
   *  guest — the shell runs a realm only when this is non-empty. */
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
  // A handler-only bundle (the chat demo: app modules, no zero-authority realm) omits
  // the guest — there is nothing to integrity-check and guestSource stays empty. A
  // bundle that DOES declare a guest is checked exactly as a module is (§12.4).
  let guestSource = "";
  if (v.manifest.guest) {
    guestSource = src.readText(v.manifest.guest.file);
    if (!contentMatches(new TextEncoder().encode(guestSource), v.manifest.guest.hash, gh)) {
      throw new Error("bundle: guest content hash mismatch");
    }
  }
  // Everything integrity-checked — install the verified bytes. Each module lands
  // directly under its kernel name, synthesizing the install record with the manifest
  // author (§12.4). No per-module `.install` envelope means no 64 KB envelope cap and
  // no boot-time seq — an equal-version reload just re-installs. A module the policy
  // refuses does not abort the load: it is simply reported as not installed.
  const installed: string[] = [];
  for (const { mod, wasm } of verified) {
    if (host.installBundleModule(mod.kernelName, wasm, v.author)) installed.push(mod.name);
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

// ── Archive: a bundle as a single blob (README §12.4) ────────────────────────
//
// On disk a bundle is a directory (a `BundleSource`); to hand one to a peer over a data
// channel — or stash it in browser storage — it needs a single-blob serialization. This
// is pure *framing*, not a signed format of its own: the manifest envelope inside still
// carries the author's signature, and its module hashes still protect the bytes, exactly
// as in a directory. The container only names the files. Layout (integers big-endian):
//
//   "SKB1" (4) │ count u16 │ count× ( nameLen u16 │ name utf8 │ dataLen u32 │ data )
//
// `unpackBundle` yields the same `{ file: bytes }` map a `BundleSource` reads, so a
// packed bundle and a bundle directory load through the identical §12.4 path.

const ARCHIVE_MAGIC = [0x53, 0x4b, 0x42, 0x31]; // "SKB1"

/** Serialize a set of named bundle files into one blob (format above). */
export function packBundle(files: Record<string, Uint8Array>): Uint8Array {
  const names = Object.keys(files);
  const enc = new TextEncoder();
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

/** Parse a blob produced by `packBundle` back into its `{ file: bytes }` map. Throws on
 *  a mis-magicked or truncated blob — a malformed archive is a fail-loud condition, like
 *  a malformed manifest, not an untrusted input to silently drop. */
export function unpackBundle(blob: Uint8Array): Record<string, Uint8Array> {
  if (blob.length < 6 || !ARCHIVE_MAGIC.every((b, i) => blob[i] === b)) {
    throw new Error("bundle: not a bundle archive");
  }
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const count = dv.getUint16(4, false);
  const dec = new TextDecoder();
  const files: Record<string, Uint8Array> = {};
  let off = 6;
  for (let i = 0; i < count; i++) {
    if (off + 2 > blob.length) throw new Error("bundle: truncated archive");
    const nameLen = dv.getUint16(off, false); off += 2;
    if (off + nameLen + 4 > blob.length) throw new Error("bundle: truncated archive");
    const name = dec.decode(blob.subarray(off, off + nameLen)); off += nameLen;
    const dataLen = dv.getUint32(off, false); off += 4;
    if (off + dataLen > blob.length) throw new Error("bundle: truncated archive");
    files[name] = blob.slice(off, off + dataLen); off += dataLen;
  }
  return files;
}
