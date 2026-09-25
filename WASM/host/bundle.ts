// App bundle format (§12.4): one signed body, manifest + guest + modules in manifest order.
import { concatBytes, toHex, isHex64, enc, dec, errMessage, type JsonValue, type JsonObject } from "../services/util.js";
import { DOMAIN_MANIFEST, DOMAIN_MANIFEST_AUTHOR, SUITE_MANIFEST_HYBRID_PQ, HOST_SERVICES, isService, isHostNamespace } from "../services/domains.js";
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
   *  co-resident guests (§12.10). The unit declared is the service, never a method
   *  (`fs/get`); this list is the whole reach an operator reads. */
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
  /** The guest program — required. Modules are the pure transforms it drives. */
  guest: BundleGuest;
}

/** The libsodium subset verifying a manifest needs; install is handed no way to sign. */
export interface ManifestVerifier {
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  /** The genesis hash — content integrity, and the author id (`hybridAuthorId`). */
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  /** ML-DSA-65 verify (FIPS 204), the PQ half of the hybrid suite (§14.1). Required:
   *  there is no Ed25519-only fallback. */
  ml_dsa65_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
}

/** The public half of the key set that signed a manifest — both keys, always. */
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
  /** Has this author key been written off (§12.5)? Checked on every load. */
  isRevoked(author: Uint8Array): boolean;
  /** Write off an author key permanently, even if it reappears in the allowlist. */
  revoke(author: Uint8Array): void;
}

/** One module invocation's answer: its bytes (null on failure) and `ms`, the module's own
 *  processing time, which is what the caller is billed (§12.3). */
export interface ModuleResult {
  bytes: Uint8Array | null;
  ms: number;
}

/** One slot's private pure modules. The builder cleans up partial instances. */
export interface PureModules {
  call(name: string, payload: Uint8Array, deadlineMs?: number): Promise<ModuleResult>;
  dispose(): void;
}

/** Build all of a bundle's pure modules or none — worker-backed on JS, a Go-owned slot
 *  natively. */
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
// ML-DSA-65 widths, duplicated from pq.ts on purpose: these are the envelope's frozen field
// widths, parseable by a host with no PQ implementation.
const ML_DSA_PK_LEN = 1952;
const ML_DSA_SIG_LEN = 3309;
// Keys, then signatures, each one contiguous run, so a later suite extends rather than
// interleaves.
const OFF_ED_PK = SUITE_LEN;
const OFF_ML_PK = OFF_ED_PK + PK_LEN;
const OFF_ED_SIG = OFF_ML_PK + ML_DSA_PK_LEN;
const OFF_ML_SIG = OFF_ED_SIG + SIG_LEN;
const OFF_BODY = OFF_ML_SIG + ML_DSA_SIG_LEN;

/** Module names: no `/`, which every host name carries, so none collides with a host
 *  method. Collisions with local service ids are `validateManifest`'s. */
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;

/** The claim charset (§12.10) for `protocols`, `services` and local ids in
 *  `guest.requires`. No whitespace, control or lookalike characters. A leading `_` is a
 *  convention (`_net`), not a reservation. */
const CLAIM_RE = /^[A-Za-z0-9_][A-Za-z0-9._/-]{0,63}$/;

/** Both keys sign `DOMAIN_manifest ‖ suite ‖ keys ‖ BLAKE2b-256(body)`. */
export function bundleSigningInput(sodium: ManifestVerifier, edPk: Uint8Array, mlDsaPk: Uint8Array, body: Uint8Array): Uint8Array {
  return concatBytes([DOMAIN_MANIFEST, Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), edPk, mlDsaPk, genesisHash(sodium, body)]);
}

/** Author id: `genesisHash(DOMAIN_manifest_author ‖ suite ‖ edPk ‖ mlDsaPk)`. */
export function hybridAuthorId(sodium: ManifestVerifier, edPk: Uint8Array, mlDsaPk: Uint8Array): Uint8Array {
  return sodium.crypto_generichash(32, concatBytes([DOMAIN_MANIFEST_AUTHOR, Uint8Array.of(SUITE_MANIFEST_HYBRID_PQ), edPk, mlDsaPk]), null);
}

function isJsonValueAt(value: unknown, ancestors: Set<object>): value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object") return false;
  const object = value as object;
  if (ancestors.has(object)) return false;
  const proto = Object.getPrototypeOf(object);
  if (!Array.isArray(value) && proto !== Object.prototype && proto !== null) return false;
  ancestors.add(object);
  try {
    return (Array.isArray(value) ? value : Object.values(value))
      .every((item) => isJsonValueAt(item, ancestors));
  } finally {
    ancestors.delete(object);
  }
}

/** True for exactly the values signed manifest JSON can carry: no cycles, exotic (or
 *  cross-realm) prototypes, or non-finite numbers, which `JSON.stringify` would change. */
export function isJsonValue(value: unknown): value is JsonValue {
  try {
    return isJsonValueAt(value, new Set());
  } catch {
    return false;
  }
}

/** True for a JSON object, the shape both config channels carry. */
export function isJsonObject(value: unknown): value is JsonObject {
  return isJsonValue(value) && typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Shape check on a verified manifest: turns an author's mistake into a loud rejection
 *  rather than a TypeError deep in install. Not a security boundary. */
function isValidManifest(m: unknown): m is BundleManifest {
  if (typeof m !== "object" || m === null || Array.isArray(m)) return false;
  const o = m as Record<string, unknown>;
  // appSignScope encodes the name in one length byte.
  if (typeof o.app !== "string" || o.app.length === 0) return false;
  if (enc.encode(o.app).length > 255) return false;
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
  const g = o.guest as Record<string, unknown>;
  if (typeof g !== "object" || g === null || Array.isArray(g)) return false;
  if (!Array.isArray(g.requires) || g.requires.some((r: unknown) => typeof r !== "string")) return false;
  if (g.config !== undefined && !isJsonObject(g.config)) return false;
  return true;
}

/** Shape and vocabulary checks shared by `verifyBundle` and `authorBundle`, so an author
 *  refuses to sign exactly what a verifier refuses. Grants are policy (§12.5). */
export function validateManifest(manifest: unknown): asserts manifest is BundleManifest {
  if (!isValidManifest(manifest)) throw new Error("bundle: malformed manifest");
  // A local id may not live in a host namespace or spell one of this bundle's modules, so
  // one `host.call` name means one thing. Whether anything claims it is answered at the
  // call, since the service may be installed later.
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

/** Authenticate the whole bundle, then parse its body: u32 BE length-prefixed manifest
 *  JSON, guest UTF-8, then one WASM per manifest module. Returned bytes own their storage. */
export function verifyBundle(sodium: ManifestVerifier, env: Uint8Array): VerifiedBundle {
  if (env.length < SUITE_LEN) throw new Error("bundle: signature invalid");
  // Suite first: other suites have other widths. An unknown suite says so rather than
  // reporting a bad signature; the byte is public (§14.1).
  const suite = env[0];
  if (suite !== SUITE_MANIFEST_HYBRID_PQ) {
    throw new Error(`bundle: unsupported manifest suite 0x${suite.toString(16).padStart(2, "0")}`);
  }
  // Never fall back to Ed25519 alone: that is the downgrade the suite exists to prevent.
  if (!sodium.ml_dsa65_verify_detached) {
    throw new Error("bundle: unsupported manifest suite 0x02 — this host has no ML-DSA-65 verifier");
  }
  if (env.length < OFF_BODY) throw new Error("bundle: signature invalid");
  // Only the keys outlive this call (`authorKeys`), so only they own their bytes — a Node Buffer's slice() aliases.
  const edPk = new Uint8Array(env.subarray(OFF_ED_PK, OFF_ML_PK));
  const mlPk = new Uint8Array(env.subarray(OFF_ML_PK, OFF_ED_SIG));
  const edSig = env.slice(OFF_ED_SIG, OFF_ML_SIG);
  const mlSig = env.slice(OFF_ML_SIG, OFF_BODY);
  const body = env.subarray(OFF_BODY);
  const pre = bundleSigningInput(sodium, edPk, mlPk, body);
  // Both, always: a broken half then rejects valid bundles instead of admitting forged ones.
  if (!sodium.crypto_sign_verify_detached(edSig, pre, edPk)) throw new Error("bundle: signature invalid");
  if (!sodium.ml_dsa65_verify_detached(mlSig, pre, mlPk)) throw new Error("bundle: signature invalid");
  const author = hybridAuthorId(sodium, edPk, mlPk);
  const authorKeys = { ed: edPk, mlDsa: mlPk };
  // Lengths and JSON are interpreted only after both signatures authenticate the body.
  const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
  let off = 0;
  const read = () => {
    if (off + 4 > body.length) throw new Error("bundle: truncated body");
    const length = dv.getUint32(off, false);
    off += 4;
    if (length > body.length - off) throw new Error("bundle: truncated body");
    const bytes = body.subarray(off, off + length);
    off += length;
    return bytes;
  };
  const json = read();
  let parsed;
  try {
    parsed = JSON.parse(dec.decode(json));
  } catch {
    throw new Error("bundle: malformed manifest (not JSON)");
  }
  // Refused by name: this is what the old module-only format produces.
  if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
    && (parsed as Record<string, unknown>).guest === undefined) {
    throw new Error("bundle: this manifest declares no guest, and every app is a guest (§12.4) — the modules are the library it drives, so ship the guest that drives them");
  }
  validateManifest(parsed);
  const guestSource = dec.decode(read());
  const modules = parsed.modules.map((mod) => ({ mod, wasm: new Uint8Array(read()) }));
  if (off !== body.length) throw new Error("bundle: trailing bytes in body");
  return { author, authorKeys, manifest: parsed, guestSource, modules };
}

/** Where a data directory's freshness marks live: a sibling, never inside it, where an
 *  `fs`-capable guest could edit its own downgrade guard. */
export function freshnessPathFor(dir: string): string {
  return dir.replace(/[/\\]+$/, "") + ".freshness.json";
}

/** The freshness store's logic and `{ marks, revoked }` serialization (§12.4). A target
 *  supplies `persist`; without one it is in-memory. */
export class FreshnessMarks {
  private readonly marks = new Map<string, number>();
  /** Author keys written off (§12.5), as lowercase hex. */
  private readonly revoked = new Set<string>();
  /** Seed from `{ marks, revoked }`; absent input is a first boot. `persist` must be
   *  atomic and must throw if the write did not land, since an empty store is
   *  "unrevoked". */
  constructor(json?: string | null, private readonly persist: (json: string) => void = () => {}) {
    if (json !== undefined && json !== null) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(json);
      } catch (e) {
        throw new Error(`freshness store: corrupt file — malformed JSON: ${errMessage(e)}. ` +
          "Delete it to start from no marks.", { cause: e });
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error("freshness store: corrupt file — root must be an object with marks and revoked fields");
      }
      const raw = parsed as Record<string, unknown>;
      if (raw.marks === undefined || raw.revoked === undefined) {
        throw new Error('freshness store: corrupt file — expected both "marks" and "revoked" fields. ' +
          "Delete it to start from no marks.");
      }
      const marks = raw.marks;
      if (typeof marks !== "object" || marks === null || Array.isArray(marks)) {
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
      const revoked = raw.revoked;
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
  /** Serialize the marks and the dead-key set for `persist`. */
  serialize(): string {
    const marks: Record<string, number> = {};
    for (const [k, v] of this.marks) marks[k] = v;
    return JSON.stringify({ marks, revoked: [...this.revoked] });
  }
  /** `"<author hex>:<app>"`: another author on the same label has its own count. */
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

/** Build a verified bundle's private modules, all or none (§3.1). Admission already ran. */
export async function loadBundleModules(host: PureModuleLoader, v: VerifiedBundle): Promise<PureModules> {
  // The §4.3 bound, per module and aggregate, read off the bytes before any instantiation
  // allocates them. One number for every target, applied only here.
  const maxBytes = DEFAULT_MAX_MODULE_MEMORY_BYTES;
  let bundleBytes = 0;
  for (const { wasm } of v.modules) {
    bundleBytes += moduleFootprintBytes(checkModuleLimits(wasm, maxBytes));
    if (bundleBytes > maxBytes) {
      throw new Error(`bundle: modules declare ${bundleBytes} aggregate bytes of memory and tables, above the host budget of ${maxBytes}`);
    }
  }
  // All or none; the target owns that because it holds the half-built instances.
  try {
    return await host.build(v.modules.map(({ mod, wasm }) => ({ name: mod.name, wasm })));
  } catch (e) {
    throw new Error(`bundle: module ${errMessage(e)}`, { cause: e });
  }
}
