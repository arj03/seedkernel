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
//   manifest.bundle    signed manifest envelope [authorPk(32)][sig(64)][utf8 json]
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

import { concatBytes, toHex } from "./util.js";
import { DOMAIN_MANIFEST, SUITE_MANIFEST_GENESIS } from "./domains.js";
import type { ShellPolicy } from "./policy.js";

/** The manifest envelope's name inside the container. */
export const MANIFEST_FILE = "manifest.bundle";
/** The guest program's name inside the container (§12.4 — fixed, never declared). */
export const GUEST_FILE = "guest.js";
/** A module's name inside the container, derived from its logical name. */
export function moduleFile(name: string): string { return name + ".wasm"; }

export interface BundleModule {
  /** Logical name, e.g. "codec". Four jobs, one value: the module's file in the
   *  container (`<name>.wasm`), the key the guest addresses it by (`BUNDLE.modules`),
   *  how the loader reports it, and — with the manifest `app` — the kernel name it
   *  binds at (`kernelNameFor`). Unique within a manifest, and restricted to
   *  `[A-Za-z0-9_-]` so it is unambiguous as a filename. */
  name: string;
  /** genesisHash(wasm) hex — content integrity for the module bytes, and the
   *  module's `bytes_hash` in the loader's install record (§5.1, §12.4). */
  hash: string;
}

/** The kernel name a bundle module binds at: `"<app>:<module name>"` (§5.1). Derived,
 *  never declared — the manifest carries no bind-name field, so there is nothing in it
 *  to forge. Both inputs are already signed, so what the loader binds is exactly what
 *  the author authenticated, and the derivation is unambiguous because a module name
 *  cannot contain `:` (NAME_RE) — the last colon always separates the two.
 *
 *  Kernel names are node-local table keys. Nothing on the wire names another node's
 *  handler: a peer sends an app id or a protocol opcode and the receiving host resolves
 *  it through its own table, and a guest reaches its own modules by logical name through
 *  `BUNDLE.modules`. So this needs to be collision-free within one node, not agreed
 *  across a deployment — scoping by `app` is exactly that much. It is deliberately NOT
 *  in the `"seedkernel.bootstrap.v1:"` namespace: those names are hand-seeded via
 *  SetHandler (§9), and keeping the two disjoint is what stops an admitted bundle from
 *  landing on a bootstrap slot. */
export function kernelNameFor(app: string, moduleName: string): string {
  return app + ":" + moduleName;
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
  /** Capability *domains* (cap-bridge `CAP_DOMAINS` keys: "crypto" | "net" | "fs" |
   *  "module" | "clock") granted to the guest. The shell expands these to the concrete
   *  allowed op set and wires only the matching backends — so this is the enforced
   *  capability declaration, not just documentation. Required whenever a guest exists;
   *  an empty array is a guest with no authority at all. */
  caps: string[];
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

export interface BundleManifest {
  app: string;
  /** Monotonic version of the coherent set (README §12.4). Enforced at load against
   *  a persisted per-`(author, app)` high-water mark: a load whose `version` is below
   *  the mark is refused as a downgrade. An integer, not a label. */
  version: number;
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
}

/** The surface *signing* a manifest needs — the build-side of the format. */
export interface ManifestCrypto extends ManifestVerifier {
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
}

const SUITE_LEN = 1;
const PK_LEN = 32;
const SIG_LEN = 64;
const OFF_PK = SUITE_LEN, OFF_SIG = OFF_PK + PK_LEN, OFF_JSON = OFF_SIG + SIG_LEN;

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
  return new TextEncoder().encode(JSON.stringify(m));
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

/** Sign a manifest → envelope `[suite(1)][authorPk(32)][sig(64)][utf8 json]`. */
export function signManifest(sodium: ManifestCrypto, sk: Uint8Array, pk: Uint8Array, m: BundleManifest): Uint8Array {
  const json = encodeManifest(m);
  const suite = SUITE_MANIFEST_GENESIS;
  const sig = sodium.crypto_sign_detached(manifestPreimage(suite, json), sk);
  return concatBytes([Uint8Array.of(suite), pk, sig, json]);
}

/** Structural check on a parsed manifest. Runs only *after* the signature
 *  verified, so this is not a security boundary — it turns a manifest the author
 *  signed but got wrong (a missing/mistyped field) into a clean, loud rejection
 *  instead of a raw TypeError surfacing deep in the loader, and lets the rest of
 *  the runtime treat every field as present and correctly typed (matching the
 *  fail-loud posture of parsePolicy). Note `caps` is required *inside* `guest`: the
 *  enforced capability declaration is never optional where a guest exists, and never
 *  present where one doesn't. */
function isValidManifest(m: unknown): m is BundleManifest {
  if (typeof m !== "object" || m === null || Array.isArray(m)) return false;
  const o = m as Record<string, unknown>;
  // `app` is load-bearing beyond reporting: it scopes the guest's signing namespace
  // (guestSignScope), keys the freshness high-water mark, and is half of every module's
  // kernel name (kernelNameFor). An empty one would yield the bind name ":codec".
  if (typeof o.app !== "string" || o.app.length === 0) return false;
  if (typeof o.version !== "number" || !Number.isInteger(o.version)) return false;
  if (!Array.isArray(o.modules)) return false;
  const seen = new Set<string>();
  for (const mod of o.modules) {
    if (typeof mod !== "object" || mod === null) return false;
    const mm = mod as Record<string, unknown>;
    if (typeof mm.name !== "string" || !NAME_RE.test(mm.name)) return false;
    if (typeof mm.hash !== "string") return false;
    // Names key both the container and the guest's module map, so a duplicate is
    // ambiguous rather than merely redundant.
    if (seen.has(mm.name)) return false;
    seen.add(mm.name);
  }
  if (o.guest !== undefined) {
    const g = o.guest as Record<string, unknown> | null;
    if (typeof g !== "object" || g === null || Array.isArray(g)) return false;
    if (typeof g.hash !== "string") return false;
    if (!Array.isArray(g.caps) || g.caps.some((c) => typeof c !== "string")) return false;
    if (g.config !== undefined) {
      if (typeof g.config !== "object" || g.config === null || Array.isArray(g.config)) return false;
      for (const v of Object.values(g.config as Record<string, unknown>)) {
        if (typeof v !== "string" && typeof v !== "number") return false;
      }
    }
  }
  return true;
}

/** Verify a manifest envelope; returns the author key + parsed manifest, or null
 *  if the signature is bad. Throws `bundle: malformed manifest` when the body is
 *  validly signed but is not parseable JSON of the expected shape — a signed-but-
 *  broken manifest is a fail-loud condition, not an untrusted input to drop. */
export function verifyManifest(sodium: ManifestVerifier, env: Uint8Array): { author: Uint8Array; manifest: BundleManifest } | null {
  if (env.length < OFF_JSON) return null;
  // Suite before offsets: another suite's key and signature are other widths, so
  // parsing first would read its bytes at this suite's positions. Unlike a bad
  // signature this is not an authenticity verdict but a legibility one — "this bundle
  // wants a host I am not" — so it throws with its own message rather than returning
  // null, which would surface to the operator as `manifest signature invalid` and send
  // them hunting the wrong problem. Nothing secret is revealed by the distinction: the
  // suite byte is attacker-chosen and public either way.
  const suite = env[0];
  if (suite !== SUITE_MANIFEST_GENESIS) {
    throw new Error(`bundle: unsupported manifest suite 0x${suite.toString(16).padStart(2, "0")}`);
  }
  const author = env.slice(OFF_PK, OFF_SIG);
  const sig = env.slice(OFF_SIG, OFF_JSON);
  const json = env.slice(OFF_JSON);
  if (!sodium.crypto_sign_verify_detached(sig, manifestPreimage(suite, json), author)) return null;
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

/** Parse a bundle blob back into its `{ file: bytes }` map. Throws on a mis-magicked
 *  or truncated blob — a malformed container is a fail-loud condition, like a
 *  malformed manifest, not an untrusted input to silently drop. */
export function unpackBundle(blob: Uint8Array): Record<string, Uint8Array> {
  if (blob.length < 6 || !ARCHIVE_MAGIC.every((b, i) => blob[i] === b)) {
    throw new Error("bundle: not a bundle blob");
  }
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const count = dv.getUint16(4, false);
  const dec = new TextDecoder();
  const files: Record<string, Uint8Array> = {};
  let off = 6;
  for (let i = 0; i < count; i++) {
    if (off + 2 > blob.length) throw new Error("bundle: truncated blob");
    const nameLen = dv.getUint16(off, false); off += 2;
    if (off + nameLen + 4 > blob.length) throw new Error("bundle: truncated blob");
    const name = dec.decode(blob.subarray(off, off + nameLen)); off += nameLen;
    const dataLen = dv.getUint32(off, false); off += 4;
    if (off + dataLen > blob.length) throw new Error("bundle: truncated blob");
    files[name] = blob.slice(off, off + dataLen); off += dataLen;
  }
  return files;
}

// ── Freshness (README §12.4 step 3) ──────────────────────────────────────────

/** The persisted bundle-freshness high-water mark per `(author, app)` (README §12.4).
 *  Host-local state that survives reboots, so an older signed bundle cannot silently
 *  replace a newer one — the guest is loaded wholesale from the bundle at every boot
 *  and carries no `seq` of its own. */
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
  /** The manifest author's 32-byte Ed25519 public key. The runtime fixes one signing
   *  algorithm (§16.1), so an author IS a key — there is no algorithm id to carry. */
  readonly author: Uint8Array;
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
  author: Uint8Array,
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
  admit(name: string, wasm: Uint8Array, author: Uint8Array): boolean {
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
    this.installations.set(name, { author: author.slice(), bytesHash });
    return true;
  }
}

// ── Loading (README §12.4) ───────────────────────────────────────────────────
//
// The load is two halves, and they are separate functions because they have genuinely
// different powers:
//
//   verifyBundle   authenticity + integrity. Pure: no host, no policy, no persistence,
//                  nothing lands. Given a blob it either yields every verified byte or
//                  throws.
//   installBundle  governance + effect. Takes what verifyBundle proved, applies the
//                  deployment's policy and freshness, and binds modules.
//
// Splitting them is what lets a shell INSPECT a bundle before consenting to it — the
// browser shows an app's author and metadata and waits for the user (§12.4) — without
// hand-rolling a second copy of the verification order, which is exactly the drift the
// shared loader exists to prevent. `loadBundle` is the two composed, and is what a
// non-interactive target calls.

export interface VerifiedBundle {
  /** The manifest author's public key (the signature verified under it). */
  author: Uint8Array;
  manifest: BundleManifest;
  /** Every module's verified bytes, in manifest order. */
  modules: { mod: BundleModule; wasm: Uint8Array }[];
  /** The verified guest source, or `""` for a handler-only bundle that declared none. */
  guestSource: string;
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

/** Authenticate and integrity-check a bundle blob (README §12.4 steps 1, 4a, 5a).
 *  Verifies the manifest signature, then hashes every module and the guest against
 *  what the manifest commits to. Throws on anything that does not check out.
 *
 *  This function has no host and no policy by construction, so "nothing has landed"
 *  is a property of its type rather than of reading it carefully. A caller may show
 *  the result to a user, or hand it straight to `installBundle`. */
export function verifyBundle(sodium: ManifestVerifier, blob: Uint8Array): VerifiedBundle {
  const files = unpackBundle(blob);
  const env = files[MANIFEST_FILE];
  if (!env) throw new Error("bundle: no manifest in the blob");
  const v = verifyManifest(sodium, env);
  if (!v) throw new Error("bundle: manifest signature invalid");

  const read = (file: string): Uint8Array => {
    const b = files[file];
    if (!b) throw new Error(`bundle: missing file ${file}`);
    return b;
  };
  return {
    author: v.author,
    manifest: v.manifest,
    modules: v.manifest.modules.map((mod) => ({ mod, wasm: read(moduleFile(mod.name)) })),
    guestSource: v.manifest.guest ? new TextDecoder().decode(read(GUEST_FILE)) : "",
  };
}

/** The integrity half of `verifyBundle`, split out so the hashing runs against a host's
 *  genesis hash (which `verifyBundle` has no access to). Called by `installBundle`
 *  before anything lands, and callable on its own by a shell that wants to show a
 *  content id before consenting. Throws on the first mismatch. */
export function checkBundleIntegrity(v: VerifiedBundle, genesisHash: (b: Uint8Array) => Uint8Array): void {
  for (const { mod, wasm } of v.modules) {
    if (!contentMatches(wasm, mod.hash, genesisHash)) {
      throw new Error(`bundle: ${mod.name} content hash mismatch`);
    }
  }
  // A handler-only bundle has nothing to check here; one that DOES declare a guest is
  // checked exactly as a module is (§12.4).
  if (v.manifest.guest) {
    if (!contentMatches(new TextEncoder().encode(v.guestSource), v.manifest.guest.hash, genesisHash)) {
      throw new Error("bundle: guest content hash mismatch");
    }
  }
}

/** Govern a verified bundle and land it (README §12.4 steps 2, 3, 4b): require the
 *  author to be in the policy, enforce version freshness, integrity-check every module
 *  and the guest against the host's genesis hash, then install each verified module
 *  under the kernel name derived from the manifest's signed `(app, name)` pair
 *  (synthesizing the install record with the manifest author, under the same policy —
 *  §12.4).
 *
 *  The integrity check runs before any install, so a mismatch anywhere throws with
 *  nothing bound — a bad file can never leave a partial bundle on the kernel. */
export function installBundle(
  host: BundleHost,
  policy: ShellPolicy,
  v: VerifiedBundle,
  freshness?: FreshnessStore,
): LoadedBundle {
  if (!policy.authors.map((a) => a.toLowerCase()).includes(toHex(v.author))) {
    throw new Error("bundle: manifest author is not in the policy's allowed set");
  }
  // Freshness (README §12.4 step 3): the `version` is an enforced monotonic integer
  // (verifyManifest already shape-checked it). Refuse a load below the persisted
  // `(author, app)` high-water mark as a downgrade — nothing lands — otherwise advance
  // the mark. Equal versions reload (an ordinary reboot re-reads the same bundle);
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
  checkBundleIntegrity(v, (b) => host.genesisHash(b));
  // Everything integrity-checked — install the verified bytes. Each module lands under
  // the kernel name DERIVED from the signed `(app, name)` pair, synthesizing the install
  // record with the manifest author (§12.4). No per-module `.install` envelope means no
  // 64 KB envelope cap and no boot-time seq — an equal-version reload just re-installs. A
  // module the policy refuses does not abort the load: it is simply reported as not
  // installed.
  const installed: string[] = [];
  for (const { mod, wasm } of v.modules) {
    const kernelName = kernelNameFor(v.manifest.app, mod.name);
    if (host.installBundleModule(kernelName, wasm, v.author)) installed.push(mod.name);
  }
  // Advance the freshness mark only now — after a fully successful load. Advancing it
  // during the downgrade check above (before the integrity checks) would brick rollback:
  // a partially written or corrupt *newer* bundle — manifest intact and signed, but one
  // module or the guest wrong — would raise the mark to the new version, then throw.
  // Nothing runs, yet reloading the known-good older bundle is now refused as a
  // downgrade until an operator hand-edits the freshness file. The mark must record the
  // highest version that actually loaded (README §12.4).
  if (freshness) freshness.set(v.author, v.manifest.app, version);
  return { manifest: v.manifest, author: v.author, guestSource: v.guestSource, installed };
}

/** Load a signed bundle blob: `verifyBundle` then `installBundle`. This is the whole
 *  §12.4 load order in one call — the checks and their sequence are the protocol, so no
 *  target restates them (README §12.9). */
export function loadBundle(
  host: BundleHost,
  sodium: ManifestVerifier,
  policy: ShellPolicy,
  blob: Uint8Array,
  freshness?: FreshnessStore,
): LoadedBundle {
  return installBundle(host, policy, verifyBundle(sodium, blob), freshness);
}
