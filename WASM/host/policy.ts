// The shell's admission policy (README §12.5): a single predicate — `admit(v)` —
// that answers exactly one question: "may this verified bundle land on this host?"
// Admission is one seam between verifyBundle and installBundle (§12.4), and one
// policy answers it. Governance is the one predicate; mechanics is installBundle.
//
// Three constructors cover the three deployment postures:
//   authorAllowlist  — a file-backed closed set of author keys
//   admitAll         — "the bundle my operator handed me" (StorageNode posture)
//   interactive      — the caller writes their own, e.g. a per-bundle consent dialog
//
// Deny-all stays the default: the absent predicate admits nothing.

import type { VerifiedBundle } from "./bundle.js";
import { toHex } from "./util.js";

/** The single admission seam.
 *  `(v: VerifiedBundle) → bool | Promise<bool>`.
 *  Return `true` to admit, `false` or throw to reject. */
export type AdmitPredicate = (v: VerifiedBundle) => boolean | Promise<boolean>;

/** The default: nothing is admitted.
 *  A node with no configured predicate boots, serves, and refuses every install. */
export const denyAll: AdmitPredicate = () => false;

/** Any verified bundle is admitted — "the bundle my operator handed me IS the
 *  trust decision." A StorageNode loads exactly the one bundle it was configured
 *  with; the choice of bundle already settled admission. */
export const admitAll: AdmitPredicate = () => true;

/** A predicate that checks the manifest author's public key against a closed set.
 *  `authors` strings are hex Ed25519 pubkeys, case-insensitive. */
export function authorAllowlist(authors: string[]): AdmitPredicate {
  const set = new Set(authors.map((a) => a.toLowerCase()));
  return (v) => set.has(toHex(v.author));
}

/** Parse a policy config file and return an AdmitPredicate.
 *  Throws on malformed input — a typo fails the boot loudly rather than
 *  silently widening trust. */
export function parsePolicy(json: string): AdmitPredicate {
  let raw: unknown;
  try { raw = JSON.parse(json); }
  catch (e) { throw new Error(`policy: invalid JSON (${(e as Error).message})`); }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("policy: expected a JSON object");
  }
  const o = raw as Record<string, unknown>;
  if (!Array.isArray(o.authors) || o.authors.some((x) => typeof x !== "string")) {
    throw new Error('policy: "authors" must be an array of hex strings');
  }
  const authors = (o.authors as string[]).map((s) => s.toLowerCase());
  if (authors.length === 0) throw new Error('policy: "authors" must list at least one allowed author key');
  return authorAllowlist(authors);
}

/** The predicate a shell runs under given its (optional) config file.
 *  A provided config is parsed strictly by `parsePolicy` — a typo fails the
 *  boot loudly. An omitted one is deny-all: the node boots, serves, and every
 *  install is refused (README §14).
 *
 *  The default lives here, in the shared core, so every target — the Node shell,
 *  the native loader — resolves "no policy configured" through this one function
 *  and cannot drift into a permissive default of its own. */
export function policyFromJson(json: string | null | undefined): AdmitPredicate {
  return json ? parsePolicy(json) : denyAll;
}
