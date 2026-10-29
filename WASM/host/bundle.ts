// App bundle format (§12.4): one signed body, manifest + guest + modules in manifest order.
import { concatBytes, toHex, isHex64, isRecord, enc, dec, errMessage, readU32BE, type JsonValue, type JsonObject } from "./util.js";
import { DOMAIN_MANIFEST, DOMAIN_MANIFEST_AUTHOR, SUITE_MANIFEST_HYBRID_PQ, HOST_SERVICES, isService, isHostNamespace } from "./domains.js";
import { checkModuleLimits, moduleFootprintBytes, DEFAULT_MAX_BUNDLE_MODULES, DEFAULT_MAX_MODULE_MEMORY_BYTES } from "./wasm-limits.js";
export type { JsonValue, JsonObject };

export interface BundleModule {
  /** The logical key the guest addresses through `host.call`; unique in the manifest. */
  name: string;
}

/** The zero-authority guest program. `requires` and `config` are the guest's alone:
 *  modules carry no authority and read no config. */
export interface BundleGuest {
  /** Everything this guest reaches outside itself: host services and local service ids of
   *  co-resident guests (§12.10). Declares services, never methods (`fs/get`); this list
   *  is the guest's whole reach as an operator sees it. */
  requires: string[];
  /** The app's signed configuration, injected as `const APP`. Must be an object, so a
   *  mistake fails the load rather than leaving every `APP.x` undefined (§12.4). */
  config?: JsonObject;
}

export interface BundleManifest {
  app: string;
  /** Monotonic integer version (§12.4), checked against a persisted per-`(author, app)`
   *  high-water mark. */
  version: number;
  /** Protocol ids a peer may send to this slot (§12.10). A claim is not authority. */
  protocols?: string[];
  /** Local service ids a co-resident guest may reach with `host.call`, never a peer
   *  (§12.10). May overlap `protocols`: a name in both is reachable by both audiences. */
  services?: string[];
  modules: BundleModule[];
  /** The guest program (required). Modules are the pure transforms it drives. */
  guest: BundleGuest;
}

/** The libsodium subset verifying a manifest needs; install is handed no way to sign. */
export interface ManifestVerifier {
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  /** The genesis hash: content integrity, and the author id (`hybridAuthorId`). */
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  /** ML-DSA-65 verify (FIPS 204), the PQ half of the hybrid suite (§14.1). Required:
   *  there is no Ed25519-only fallback. */
  ml_dsa65_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
}

/** The public keys that signed a manifest; always both. */
export interface ManifestAuthorKeys {
  ed: Uint8Array;
  mlDsa: Uint8Array;
}

/** Per-`(author, app)` freshness marks (§12.4) and revoked author keys (§12.5), in one
 *  store so a truncated write cannot drop the revocations. */
export interface FreshnessStore {
  /** The highest `version` ever loaded for this `(author, app)`, or −Infinity if none. */
  get(author: Uint8Array, app: string): number;
  /** Advance the mark (never rewinds). Throws, leaving the mark unchanged, if the write
   *  does not land. */
  set(author: Uint8Array, app: string, version: number): void;
  /** Has this author key been revoked (§12.5)? Checked on every load. */
  isRevoked(author: Uint8Array): boolean;
  /** Revoke an author key permanently, even if it is still in the allowlist. */
  revoke(author: Uint8Array): void;
}

/** One module invocation's answer: its bytes (null on failure) and `ms`, the module's own
 *  processing time, which the caller is billed (§12.3). */
export interface ModuleResult {
  bytes: Uint8Array | null;
  ms: number;
}

/** One slot's private pure modules. The builder cleans up partial instances. */
export interface PureModules {
  call(name: string, payload: Uint8Array, deadlineMs?: number): Promise<ModuleResult>;
  dispose(): void;
}

/** Build all of a bundle's pure modules or none: worker-backed on JS, a Go-owned slot on
 *  the native target. */
export interface PureModuleLoader {
  build(mods: { name: string; wasm: Uint8Array }[]): PureModules | Promise<PureModules>;
}

export interface VerifiedBundle {
  /** The author's 32-byte id (`hybridAuthorId`). */
  author: Uint8Array;
  /** The public keys that signed, for a consent prompt. */
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

/** Verified metadata and guest source, without the module bytes. */
export type LoadedBundle = Omit<VerifiedBundle, "modules">;

/** The genesis hash (BLAKE2b-256), the one system hash. */
export function genesisHash(sodium: ManifestVerifier, data: Uint8Array): Uint8Array {
  return sodium.crypto_generichash(32, data, null);
}

/** Whether the signed manifest requires the node's exclusive raw-link service. */
export function reachesLink(manifest: BundleManifest): boolean {
  return manifest.guest.requires.includes("link");
}

/** The fs prefix for one app label (§12.2): 128 bits of lowercase hex, so it is a safe
 *  filename on case-folding filesystems and no prefix extends another. Separates
 *  namespaces; does not authenticate them. */
export function appScopeFor(crypto: ManifestVerifier, app: string): string {
  return toHex(genesisHash(crypto, enc.encode(app))).slice(0, 32) + "-";
}

const SUITE_LEN = 1;
const PK_LEN = 32;
const SIG_LEN = 64;
// ML-DSA-65 widths, duplicated from pq.ts so a host with no PQ implementation can still
// parse the envelope.
const ML_DSA_PK_LEN = 1952;
const ML_DSA_SIG_LEN = 3309;
// All keys, then all signatures, so a later suite can extend each run.
const OFF_ED_PK = SUITE_LEN;
const OFF_ML_PK = OFF_ED_PK + PK_LEN;
const OFF_ED_SIG = OFF_ML_PK + ML_DSA_PK_LEN;
const OFF_ML_SIG = OFF_ED_SIG + SIG_LEN;
const OFF_BODY = OFF_ML_SIG + ML_DSA_SIG_LEN;

/** Module names: no `/`, so none collides with a host method. `validateManifest` checks
 *  collisions with local service ids. */
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;

/** The claim charset (§12.10) for `protocols`, `services` and local ids in
 *  `guest.requires`. No whitespace, control or lookalike characters. A leading `_` is a
 *  convention (`_net`), not a reservation. */
const CLAIM_RE = /^[A-Za-z0-9_][A-Za-z0-9._/-]{0,63}$/;

/** Both keys sign `domain ‖ suite ‖ keys ‖ BLAKE2b-256(body)`: `DOMAIN_manifest` for an
 *  app bundle, `DOMAIN_host` for a host blob. */
export function envelopeSigningInput(sodium: ManifestVerifier, domain: Uint8Array, edPk: Uint8Array,
  mlDsaPk: Uint8Array, body: Uint8Array): Uint8Array {
  return concatBytes([domain, Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), edPk, mlDsaPk, genesisHash(sodium, body)]);
}

/** Author id: `genesisHash(DOMAIN_manifest_author ‖ suite ‖ edPk ‖ mlDsaPk)`. */
export function hybridAuthorId(sodium: ManifestVerifier, edPk: Uint8Array, mlDsaPk: Uint8Array): Uint8Array {
  return sodium.crypto_generichash(32, concatBytes([DOMAIN_MANIFEST_AUTHOR, Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), edPk, mlDsaPk]), null);
}

/** Control, line-separator, bidi and zero-width characters. */
const UNSAFE_LABEL = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/;

/** Shape check on a verified manifest, so an author's mistake is rejected up front
 *  instead of surfacing as a TypeError deep in install. */
function isValidManifest(o: unknown): o is BundleManifest {
  if (!isRecord(o)) return false;
  // appSignScope encodes the name in one length byte. A lone surrogate would encode as
  // U+FFFD and share another label's scope; a control or bidi character could forge the
  // operator's console line.
  if (typeof o.app !== "string" || o.app.length === 0) return false;
  if (!o.app.isWellFormed() || enc.encode(o.app).length > 255 || UNSAFE_LABEL.test(o.app)) return false;
  if (typeof o.version !== "number" || !Number.isSafeInteger(o.version) || o.version < 0) return false;
  // Uniqueness is per list (§12.10); the same name in both is reachable either way.
  for (const list of [o.protocols, o.services]) {
    if (list === undefined) continue;
    if (!Array.isArray(list)) return false;
    const claimed = new Set<string>();
    for (const p of list) {
      if (typeof p !== "string" || !CLAIM_RE.test(p)) return false;
      if (claimed.has(p)) return false;
      claimed.add(p);
    }
  }
  if (!Array.isArray(o.modules) || o.modules.length > DEFAULT_MAX_BUNDLE_MODULES) return false;
  const seen = new Set<string>();
  for (const mod of o.modules) {
    if (typeof mod !== "object" || mod === null) return false;
    if (typeof mod.name !== "string" || !NAME_RE.test(mod.name)) return false;
    if (seen.has(mod.name)) return false;
    seen.add(mod.name);
  }
  // An omitted `guest` is refused by name in verifyBundle.
  const g = o.guest;
  if (!isRecord(g)) return false;
  if (!Array.isArray(g.requires) || g.requires.some((r: unknown) => typeof r !== "string")) return false;
  if (g.config !== undefined && !isRecord(g.config)) return false;
  return true;
}

/** Shape and vocabulary checks shared by `verifyBundle` and `authorBundle`, so an author
 *  refuses to sign exactly what a verifier refuses. */
export function validateManifest(manifest: unknown): asserts manifest is BundleManifest {
  if (!isValidManifest(manifest)) throw new Error("bundle: malformed manifest");
  // A local id may not sit in a host namespace or match one of this bundle's modules, so
  // each `host.call` name means one thing. Whether anything claims it is checked at call
  // time, since the service may be installed later.
  const moduleNames = new Set(manifest.modules.map((m) => m.name));
  for (const r of manifest.guest.requires) {
    if (isService(r)) continue;
    const slash = r.indexOf("/");
    const head = slash < 0 ? r : r.slice(0, slash);
    if (isHostNamespace(head)) {
      const fix = isService(head) ? ` — declare the SERVICE "${head}" instead` : "";
      throw new Error(`bundle: "${r}" (manifest guest.requires) is a host method, not a service or a local service id${fix} (this host's services: ${Object.keys(HOST_SERVICES).join(", ")})`);
    }
    if (!CLAIM_RE.test(r)) {
      throw new Error(`bundle: "${r}" (manifest guest.requires) is neither one of this host's services (${Object.keys(HOST_SERVICES).join(", ")}) nor a well-formed local service id (alphanumeric-or-"_" first, then alphanumerics and ._/-, at most 64 bytes)`);
    }
    if (moduleNames.has(r)) {
      throw new Error(`bundle: "${r}" is both a local service id (manifest guest.requires) and one of this bundle's own module names — a host.call name means one thing, so declare one or the other`);
    }
  }
}

/** What an authenticated envelope carries: its author and the signed body. */
export interface VerifiedEnvelope {
  author: Uint8Array;
  authorKeys: ManifestAuthorKeys;
  body: Uint8Array;
}

/** Authenticate a suite 0x02 envelope signed under `domain`; errors name `what` it is. */
export function verifyEnvelope(sodium: ManifestVerifier, env: Uint8Array, domain: Uint8Array,
  what: string): VerifiedEnvelope {
  // Never fall back to Ed25519 alone: that is the downgrade the suite exists to prevent.
  if (env[0] === SUITE_MANIFEST_HYBRID_PQ && !sodium.ml_dsa65_verify_detached) {
    throw new Error(`${what}: unsupported manifest suite 0x02 — this host has no ML-DSA-65 verifier`);
  }
  const body = envelopeBody(env, what);
  // Only the keys outlive this call (`authorKeys`), so only they are copied. A Node
  // Buffer's slice() aliases.
  const edPk = new Uint8Array(env.subarray(OFF_ED_PK, OFF_ML_PK));
  const mlPk = new Uint8Array(env.subarray(OFF_ML_PK, OFF_ED_SIG));
  const edSig = env.slice(OFF_ED_SIG, OFF_ML_SIG);
  const mlSig = env.slice(OFF_ML_SIG, OFF_BODY);
  const pre = envelopeSigningInput(sodium, domain, edPk, mlPk, body);
  // Always check both, so a broken half rejects valid ones instead of admitting forged ones.
  if (!sodium.crypto_sign_verify_detached(edSig, pre, edPk)) throw new Error(`${what}: signature invalid`);
  if (!sodium.ml_dsa65_verify_detached(mlSig, pre, mlPk)) throw new Error(`${what}: signature invalid`);
  return { author: hybridAuthorId(sodium, edPk, mlPk), authorKeys: { ed: edPk, mlDsa: mlPk }, body };
}

/** A suite 0x02 envelope's body, unauthenticated: what a loader reads of a host blob, whose
 *  signatures the host that staged it checked (§12.9). */
export function envelopeBody(env: Uint8Array, what: string): Uint8Array {
  if (env.length < SUITE_LEN) throw new Error(`${what}: signature invalid`);
  // Suite first, since other suites have other widths. An unknown suite is reported as
  // such, not as a bad signature; the byte is public (§14.1).
  if (env[0] !== SUITE_MANIFEST_HYBRID_PQ) {
    throw new Error(`${what}: unsupported manifest suite 0x${env[0].toString(16).padStart(2, "0")}`);
  }
  if (env.length < OFF_BODY) throw new Error(`${what}: signature invalid`);
  return env.subarray(OFF_BODY);
}

/** A body's u32 big-endian length-prefixed parts, read in order. A bundle's lengths are
 *  interpreted only after the signatures over them authenticate. */
export function bodyReader(body: Uint8Array, what: string): { next(): Uint8Array; done(): boolean } {
  let off = 0;
  return {
    next() {
      if (off + 4 > body.length) throw new Error(`${what}: truncated body`);
      const length = readU32BE(body, off);
      off += 4;
      if (length > body.length - off) throw new Error(`${what}: truncated body`);
      const bytes = body.subarray(off, off + length);
      off += length;
      return bytes;
    },
    done: () => off === body.length,
  };
}

/** Authenticate the whole bundle, then parse its body: u32 BE length-prefixed manifest
 *  JSON, guest UTF-8, then one WASM per manifest module. Returned bytes own their storage. */
export function verifyBundle(sodium: ManifestVerifier, env: Uint8Array): VerifiedBundle {
  const { author, authorKeys, body } = verifyEnvelope(sodium, env, DOMAIN_MANIFEST, "bundle");
  const parts = bodyReader(body, "bundle");
  const json = parts.next();
  let parsed;
  try {
    parsed = JSON.parse(dec.decode(json));
  } catch {
    throw new Error("bundle: malformed manifest (not JSON)");
  }
  // A manifest with no guest gets its own error.
  if (isRecord(parsed) && parsed.guest === undefined) {
    throw new Error("bundle: this manifest declares no guest, and every app is a guest (§12.4) — the modules are the library it drives, so ship the guest that drives them");
  }
  validateManifest(parsed);
  const guestSource = dec.decode(parts.next());
  const modules = parsed.modules.map((mod) => ({ mod, wasm: new Uint8Array(parts.next()) }));
  if (!parts.done()) throw new Error("bundle: trailing bytes in body");
  return { author, authorKeys, manifest: parsed, guestSource, modules };
}

/** Where a data directory's freshness marks live: beside it, never inside it, where a
 *  guest with `fs` could edit its own downgrade guard. */
export function freshnessPathFor(dir: string): string {
  return dir.replace(/[/\\]+$/, "") + ".freshness.json";
}

/** The freshness store's logic and `{ marks, revoked }` serialization (§12.4). A target
 *  supplies `persist`; without one it is in-memory. */
export class FreshnessMarks {
  private readonly marks = new Map<string, number>();
  /** Revoked author keys (§12.5), as lowercase hex. */
  private readonly revoked = new Set<string>();
  /** Seed from `{ marks, revoked }`; absent input means first boot. `persist` must be
   *  atomic and throw if the write failed, since a lost store silently un-revokes. */
  constructor(json?: string | null, private readonly persist: (json: string) => void = () => {}) {
    if (json !== undefined && json !== null) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(json);
      } catch (e) {
        throw new Error(`freshness store: corrupt file — malformed JSON: ${errMessage(e)}. ` +
          "Delete it to start from no marks.", { cause: e });
      }
      if (!isRecord(parsed)) {
        throw new Error("freshness store: corrupt file — root must be an object with marks and revoked fields");
      }
      if (parsed.marks === undefined || parsed.revoked === undefined) {
        throw new Error('freshness store: corrupt file — expected both "marks" and "revoked" fields. ' +
          "Delete it to start from no marks.");
      }
      const marks = parsed.marks;
      if (!isRecord(marks)) {
        throw new Error('freshness store: corrupt file — "marks" must be an object of {"<author hex>:<app>": version} pairs');
      }
      for (const [k, v] of Object.entries(marks)) {
        // The app suffix is arbitrary text; validate the author prefix and a non-empty rest.
        if (!isHex64(k.slice(0, 64)) || k[64] !== ":" || k.length === 65) {
          throw new Error(`freshness store: corrupt file — mark key ${JSON.stringify(k)} is not "<author hex>:<app>"`);
        }
        if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
          throw new Error(`freshness store: corrupt file — mark "${k}" is not a non-negative safe-integer version (got ${JSON.stringify(v)})`);
        }
        // Lowercased, or a hand-edited uppercase mark would guard nothing.
        this.marks.set(k.slice(0, 64).toLowerCase() + k.slice(64), v);
      }
      const revoked = parsed.revoked;
      if (!Array.isArray(revoked)) {
        throw new Error('freshness store: corrupt file — "revoked" must be an array of hex author ids');
      }
      for (const a of revoked) {
        if (typeof a !== "string" || !isHex64(a)) {
          throw new Error(`freshness store: corrupt file — a revoked entry is not a 32-byte author id in hex (got ${JSON.stringify(a)})`);
        }
        this.revoked.add(a.toLowerCase());
      }
    }
  }
  /** Serialize the marks and revoked keys for `persist`. */
  serialize(): string {
    const marks: Record<string, number> = {};
    for (const [k, v] of this.marks) marks[k] = v;
    return JSON.stringify({ marks, revoked: [...this.revoked] });
  }
  /** `"<author hex>:<app>"`: each author has its own mark per label. */
  private key(author: Uint8Array, app: string): string { return toHex(author) + ":" + app; }
  get(author: Uint8Array, app: string): number {
    const v = this.marks.get(this.key(author, app));
    return v === undefined ? -Infinity : v;
  }
  set(author: Uint8Array, app: string, version: number): void {
    if (!Number.isSafeInteger(version) || version < 0) {
      throw new Error(`freshness store: refusing invalid version ${JSON.stringify(version)} (expected a non-negative safe integer)`);
    }
    const k = this.key(author, app);
    const cur = this.marks.get(k);
    if (cur !== undefined && cur >= version) return; // monotonic: never rewound
    this.marks.set(k, version);
    // Roll back, or a retry would hit the early return and never persist.
    try {
      this.persist(this.serialize());
    } catch (e) {
      if (cur === undefined) this.marks.delete(k);
      else this.marks.set(k, cur);
      throw new Error(`freshness store: the mark for '${app}' could not be persisted — it stays at ` +
        `${cur === undefined ? "unset" : cur}: ${errMessage(e)}. Fix the store and load again.`, { cause: e });
    }
  }
  isRevoked(author: Uint8Array): boolean {
    return this.revoked.has(toHex(author));
  }
  revoke(author: Uint8Array): void {
    const hex = toHex(author);
    if (this.revoked.has(hex)) return;
    this.revoked.add(hex);
    // Roll back, as in `set`.
    try {
      this.persist(this.serialize());
    } catch (e) {
      this.revoked.delete(hex);
      throw new Error(`freshness store: the revocation could not be persisted — ${hex} is NOT revoked: ${errMessage(e)}. ` +
        "Fix the store and revoke again.", { cause: e });
    }
  }
}

/** A module call with no answer: a trap, an overrun, an unknown name or a module gone. */
export const MODULE_FAILED: ModuleResult = Object.freeze({ bytes: null, ms: 0 });

/** One slot's modules, all or none (§3.1), as each target's loader builds them: each made
 *  by `make`, side by side, and a set one of them fails releases the rest. A call by a name
 *  the set does not hold fails. */
export async function moduleSet<M>(mods: { name: string; wasm: Uint8Array }[],
  make: (wasm: Uint8Array) => M | Promise<M>,
  call: (m: M, payload: Uint8Array, deadlineMs?: number) => Promise<ModuleResult>,
  release: (m: M) => void): Promise<PureModules> {
  const made = await Promise.allSettled(mods.map(async ({ wasm }) => make(wasm)));
  const built = new Map<string, M>();
  let failure: Error | undefined;
  for (const [i, r] of made.entries()) {
    if (r.status === "fulfilled") {
      built.set(mods[i].name, r.value);
    } else {
      failure ??= new Error(`${mods[i].name}: ${errMessage(r.reason)}`, { cause: r.reason });
    }
  }
  if (failure) {
    for (const m of built.values()) release(m);
    throw failure;
  }
  return {
    call: (name, payload, deadlineMs) => {
      const m = built.get(name);
      return m === undefined ? Promise.resolve(MODULE_FAILED) : call(m, payload, deadlineMs);
    },
    dispose: () => {
      for (const m of built.values()) release(m);
      built.clear();
    },
  };
}

/** Build a verified bundle's private modules, all or none (§3.1). Admission already ran. */
export async function loadBundleModules(host: PureModuleLoader, v: VerifiedBundle): Promise<PureModules> {
  // The §4.3 bound, per module and in total, read from the bytes before anything is
  // instantiated. The same on every target, and applied only here.
  const maxBytes = DEFAULT_MAX_MODULE_MEMORY_BYTES;
  let bundleBytes = 0;
  for (const { wasm } of v.modules) {
    bundleBytes += moduleFootprintBytes(checkModuleLimits(wasm, maxBytes));
    if (bundleBytes > maxBytes) {
      throw new Error(`bundle: modules declare ${bundleBytes} aggregate bytes of memory and tables, above the host budget of ${maxBytes}`);
    }
  }
  // The target enforces all-or-none, since it holds the half-built instances.
  try {
    return await host.build(v.modules.map(({ mod, wasm }) => ({ name: mod.name, wasm })));
  } catch (e) {
    throw new Error(`bundle: module ${errMessage(e)}`, { cause: e });
  }
}
