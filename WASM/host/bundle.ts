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
 *  Kernel names are node-local table keys. Nothing on the wire names another node's
 *  handler: a peer sends a protocol id or an opcode and the receiving host resolves it
 *  through its own bindings (§12.10) to whichever app it holds, and a guest reaches its own
 *  modules by logical name through `BUNDLE.modules`. So this needs to be collision-free
 *  within one node, not agreed across a deployment. */
export function kernelNameFor(author: Uint8Array, app: string, moduleName: string): string {
  return appKeyFor(author, app) + ":" + moduleName;
}

/** The crypto a bundle load needs, in libsodium-wrappers method names so a raw libsodium
 *  satisfies it directly (as does the native loader's Go-backed `sodium`, §12.9): verify
 *  the manifest signature, and hash content with the genesis hash. */
export interface BundleCrypto extends ManifestVerifier {
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
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
  /** Protocol ids this app can serve (README §12.10). Absent ⇒ `[app]`, so an app that
   *  speaks only its own protocol declares nothing.
   *
   *  A DECLARATION, not a claim. It makes the app *eligible* for a binding and confers no
   *  traffic on its own: delivery follows the shell's user-owned `protocol id → app key`
   *  table, so any number of bundles may declare the same id without contending for
   *  anything. That separation — landing code is authorized by policy, receiving messages
   *  is chosen by the user — is what lets the loader hold no ownership state at all. */
  handles?: string[];
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
  // `handles` is optional (absent ⇒ [app], see handlesOf). Present, it must be a list of
  // non-empty strings — it is only ever compared against a protocol id off the wire, so
  // the shape is the whole check: an id confers nothing until a user binds it (§12.10).
  if (o.handles !== undefined) {
    if (!Array.isArray(o.handles)) return false;
    for (const h of o.handles) if (typeof h !== "string" || h.length === 0) return false;
  }
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

  private key(author: Uint8Array, app: string): string { return appKeyFor(author, app); }

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
// Binding a module IS the loader's job — there is no separate "module registry", and no
// ownership register either. `admit` below is a pure function of the bundle in front of
// it: hash the verified bytes, ask the policy, and on approval instantiate + SetHandler.
//
// What a register would once have answered — "who owns this name?" — has no content now
// that the author is derived INTO the name (`kernelNameFor`, §5.1). A name is reachable
// only to the key that derives it, so the only bundle that can re-bind a name is one
// signed by the author whose name it is. The kernel table is the host's only install
// state, so nothing can drift out of step with it.

/** The one host power a bundle load needs: instantiate handler bytes against the §4 ABI
 *  and bind them at `name`. `KernelHost` satisfies it; the native loader forwards the same
 *  single call over its Go bridge (README §12.9).
 *
 *  Hashing is deliberately NOT here — it is `genesisHash(sodium, …)`, so the component
 *  that owns the handler table needs no crypto at all (§3). */
export interface BundleHost {
  installWasmHandler(name: string, wasm: Uint8Array): boolean;
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
export function verifyBundle(sodium: BundleCrypto, blob: Uint8Array): VerifiedBundle {
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
  const result: VerifiedBundle = {
    author: v.author,
    manifest: v.manifest,
    modules: v.manifest.modules.map((mod) => ({ mod, wasm: read(moduleFile(mod.name)) })),
    guestSource: v.manifest.guest ? new TextDecoder().decode(read(GUEST_FILE)) : "",
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
    if (!contentMatches(new TextEncoder().encode(result.guestSource), v.manifest.guest.hash, (b) => genesisHash(sodium, b))) {
      throw new Error("bundle: guest content hash mismatch");
    }
  }
  return result;
}

/** Govern a verified bundle and land it (README §12.4 steps 2, 3, 4b): require the
 *  author to be in the policy, enforce version freshness, then install each verified
 *  module under the kernel name derived from the manifest's signed `(author, app, name)`
 *  triple (§5.1).
 *
 *  There is no per-module admission callback: the manifest's `modules[].hash` commits to
 *  exactly which bytes are authorized, and `verifyBundle` already proved the bytes match.
 *  Trusting the author means trusting everything the author signed. */
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
  // Modules were integrity-checked by verifyBundle (§12.4 steps 4a, 5a) — install the
  // verified bytes. Each module lands under the kernel name DERIVED from the signed
  // `(author, app, name)` triple (§5.1). No per-module `.install` envelope means no
  // 64 KB envelope cap and no boot-time seq — an equal-version reload just re-installs,
  // and a higher-version bundle from the same author lands on the same names because the
  // same key derives them.
  //
  // `installBundle` reports only the modules that actually bound: integrity proves the
  // bytes are what the author signed, but not that they are a valid §4 handler, so a
  // hash-correct module that won't instantiate (or is missing the ABI exports) returns
  // `false` here. That is not fatal — the other modules still land — but it must not be
  // reported as installed, or `installed` would claim a kernel name that isn't bound.
  const installed: string[] = [];
  for (const { mod, wasm } of v.modules) {
    const kernelName = kernelNameFor(v.author, v.manifest.app, mod.name);
    if (host.installWasmHandler(kernelName, wasm)) installed.push(mod.name);
  }
  // Advance the freshness mark only now — after a fully successful load. Advancing it
  // during the downgrade check above would brick rollback: a partially written or corrupt
  // *newer* bundle — manifest intact and signed, but one module or the guest wrong —
  // would raise the mark to the new version, then throw. Nothing runs, yet reloading the
  // known-good older bundle is now refused as a downgrade until an operator hand-edits
  // the freshness file. The mark must record the highest version that actually loaded
  // (README §12.4). Integrity was verified by verifyBundle before this function was
  // called, so the freshness advance is always behind a successful verify.
  if (freshness) freshness.set(v.author, v.manifest.app, version);
  return { manifest: v.manifest, author: v.author, guestSource: v.guestSource, installed };
}

/** Load a signed bundle blob: `verifyBundle` then `installBundle`. This is the whole
 *  §12.4 load order in one call — the checks and their sequence are the protocol, so no
 *  target restates them (README §12.9). */
export function loadBundle(
  host: BundleHost,
  sodium: BundleCrypto,
  policy: ShellPolicy,
  blob: Uint8Array,
  freshness?: FreshnessStore,
): LoadedBundle {
  return installBundle(host, policy, verifyBundle(sodium, blob), freshness);
}
