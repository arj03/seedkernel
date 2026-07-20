// The shell's admission policy (README §12.5). It turns a small JSON config — "which
// keys you allow" — into the loader's `AdmitPolicy`: a **closed author-key set** plus an
// optional **module-hash allowlist**, with a same-author rule on updates that makes names
// squat-resistant (the first admitted author to bind a name owns it; only that key may
// update it). This is the only governance the generic runtime carries: everything else —
// codec, reputation, the storage guest — arrives in a signed bundle whose manifest author
// must clear this gate (§12.4). A deployment that needs more replaces the whole `AdmitPolicy`
// (a quorum, an HSM console, bytecode validation); the file is the declarative common case.

import type { AdmitPolicy } from "./bundle.js";
import { bytesEqual, toHex } from "./util.js";

export interface ShellPolicy {
  /** Closed set of author Ed25519 public keys (hex) permitted to sign a bundle manifest
   *  (§12.4 step 2) and bind a name (§12.5). */
  authors: string[];
  /** Optional allowlist of module `bytesHash`es (hex — `genesisHash(wasm)`, the
   *  same id a manifest's `modules[].hash` uses). Omitted ⇒ any module from an
   *  allowed author is accepted; present ⇒ the admitted hash must be listed. */
  modules?: string[];
}

/** Parse + validate a policy config. Throws on malformed input so a typo in the
 *  allowed-keys file fails the boot loudly rather than silently widening trust. */
export function parsePolicy(json: string): ShellPolicy {
  let raw: unknown;
  try { raw = JSON.parse(json); }
  catch (e) { throw new Error(`policy: invalid JSON (${(e as Error).message})`); }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("policy: expected a JSON object");
  }
  const o = raw as Record<string, unknown>;
  const hexList = (v: unknown, field: string): string[] => {
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      throw new Error(`policy: "${field}" must be an array of hex strings`);
    }
    return (v as string[]).map((s) => s.toLowerCase());
  };
  const authors = hexList(o.authors, "authors");
  if (authors.length === 0) throw new Error('policy: "authors" must list at least one allowed author key');
  const policy: ShellPolicy = { authors };
  if (o.modules !== undefined) policy.modules = hexList(o.modules, "modules");
  return policy;
}

/** The policy a shell runs under given its (optional) config file. A *provided*
 *  config is parsed strictly by `parsePolicy` — a typo fails the boot loudly rather
 *  than silently widening trust — and an **omitted** one is deny-all: an empty author
 *  set, so the node boots and serves but every install is refused (README §14).
 *
 *  The default lives here, in the shared core, precisely because it is a security
 *  posture: every target (the Node shell, the native loader) resolves "no policy
 *  configured" through this one function, so a target cannot drift into a permissive
 *  default of its own. */
export function policyFromJson(json: string | null | undefined): ShellPolicy {
  return json ? parsePolicy(json) : { authors: [] };
}

/** The default admission decision (README §12.5): the loader's `admit` derived from a
 *  policy file. Three conjoined checks —
 *    1. `author ∈ authors` — the closed author set gates WHO may bind a name;
 *    2. `bytesHash ∈ modules` if that field is present — pins WHICH binaries may land;
 *    3. when a record already exists at the name, the new author equals the recorded one —
 *       *trust the original author*: the first author to bind a name owns it, so a second
 *       allowed author cannot hijack the slot (squat-resistance, the reason the loader keeps
 *       a record per name).
 *  An empty author set (the omitted-policy default) admits nothing — every bind fails
 *  check 1. The refusal to overlay a hand-seeded slot is structural in the loader
 *  (`InstallRecords.admit`), so it holds regardless of which `AdmitPolicy` is wired. */
export function buildAdmit(policy: ShellPolicy): AdmitPolicy {
  const authors = new Set(policy.authors.map((s) => s.toLowerCase()));
  const modules = policy.modules ? new Set(policy.modules.map((s) => s.toLowerCase())) : null;

  return (_name, author, bytesHash, _wasm, current) => {
    if (!authors.has(toHex(author))) return false;                   // closed author set
    if (modules && !modules.has(toHex(bytesHash))) return false;     // module-hash allowlist
    // squat-resistance: only the recorded author may update the name.
    if (current && !bytesEqual(current.author, author)) return false;
    return true;
  };
}
