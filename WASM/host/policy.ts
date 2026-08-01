// The shell's admission policy (README §12.5): a single predicate — `admit(v)` —
// that answers exactly one question: "may this verified bundle land on this host?"
// Admission is one seam between verifyBundle and installBundle (§12.4), and one
// policy answers it. Governance is the one predicate; mechanics is installBundle.
//
// Three constructors cover the three deployment postures:
//   authorAllowlist  — a file-backed closed set of author ids
//   admitAll         — "the bundle my operator handed me" (StorageNode posture)
//   interactive      — the caller writes their own, e.g. a per-bundle consent dialog
//
// A fourth, `manifestSuiteAllowlist`, is an axis rather than a posture: which signature
// suites (§12.4) an operator will accept, composed with any of the above through
// `allOf`. It is policy and not verifier logic because "can this host check suite N"
// and "will this deployment trust suite N" are different questions — a node finishing a
// post-quantum migration answers yes to the first for 0x01 and no to the second.
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

/** A predicate that checks the manifest author's id against a closed set.
 *  `authors` strings are hex author ids, case-insensitive — an Ed25519 pubkey under
 *  manifest suite `0x01`, the derived key-set id under the hybrid suite `0x02`
 *  (`hybridAuthorId`, §12.4). One 32-byte id either way, so an operator pins an
 *  identity here without knowing which suite produced it. */
export function authorAllowlist(authors: string[]): AdmitPredicate {
  const set = new Set(authors.map((a) => a.toLowerCase()));
  return (v) => set.has(toHex(v.author));
}

/** A predicate restricting which manifest signature suites may land (§12.4, §14.1).
 *
 *  The verifier accepts every suite it can *check*; this is the separate question of
 *  which ones an operator is willing to *trust*, and it is policy because the answer is
 *  deployment-specific: a node that has finished migrating sets `[2]` and stops
 *  accepting Ed25519-only manifests, which is the only way the classical suite ever
 *  actually goes away. Absent, every supported suite is admitted. */
export function manifestSuiteAllowlist(suites: number[]): AdmitPredicate {
  const set = new Set(suites);
  return (v) => set.has(v.suite);
}

/** Every predicate must admit (logical AND, short-circuiting). Rejections stay
 *  distinguishable because a predicate that wants to explain itself throws. */
export function allOf(...predicates: AdmitPredicate[]): AdmitPredicate {
  return async (v) => {
    for (const p of predicates) if (!(await p(v))) return false;
    return true;
  };
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
  // `manifestSuites` is optional and, like everything else here, strict: a typo'd or
  // empty list fails the boot rather than quietly widening (or emptying) what lands.
  // Absent ⇒ any suite the host can verify.
  if (o.manifestSuites === undefined) return authorAllowlist(authors);
  if (!Array.isArray(o.manifestSuites)
    || o.manifestSuites.some((x) => typeof x !== "number" || !Number.isInteger(x))) {
    throw new Error('policy: "manifestSuites" must be an array of integer suite ids');
  }
  const suites = o.manifestSuites as number[];
  if (suites.length === 0) throw new Error('policy: "manifestSuites" must list at least one suite id');
  return allOf(authorAllowlist(authors), manifestSuiteAllowlist(suites));
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
