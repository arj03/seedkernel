// The shell's admission policy (README §12.5): a single predicate — `admit(v)` —
// that answers exactly one question: "may this verified bundle land on this host?"
// Admission is one seam between verifyBundle and installBundle (§12.4), and one
// policy answers it. Governance is the one predicate; mechanics is installBundle.
//
// Three constructors cover the three deployment postures:
//   authorAllowlist  — a file-backed closed set of author ids, for ordinary APPS
//   admitAll         — "the bundle my operator handed me" (StorageNode posture)
//   interactive      — the caller writes their own, e.g. a per-bundle consent dialog
//
// `roleAllowlist` is not a fourth posture but a second admission CLASS, cutting across
// all three: a bundle claiming a slot (§12.4) is an authority grant — the transport sees
// all plaintext and holds the session keys — where an ordinary app is a preference. The
// two are composed with `anyOf` and partition the bundles between them, so trusting an
// author for apps never silently trusts them for the channel.
//
// `manifestSuiteAllowlist` is an axis rather than a posture: which signature
// suites (§12.4) an operator will accept, composed with any of the above through
// `allOf`. It is policy and not verifier logic because "can this host check suite N"
// and "will this deployment trust suite N" are different questions — a node finishing a
// post-quantum migration answers yes to the first for 0x01 and no to the second.
//
// Deny-all stays the default: the absent predicate admits nothing.

import { BUNDLE_ROLES, type VerifiedBundle } from "./bundle.js";
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
 *  with; the choice of bundle already settled admission.
 *
 *  Slot occupants included: the operator naming one blob is a decision about that blob,
 *  whatever it claims to be. The distinction `authorAllowlist` draws exists because an
 *  allowlist admits bundles the operator has never seen; this admits exactly one they
 *  chose. */
export const admitAll: AdmitPredicate = () => true;

/** A predicate that checks the manifest author's id against a closed set.
 *  `authors` strings are hex author ids, case-insensitive — an Ed25519 pubkey under
 *  manifest suite `0x01`, the derived key-set id under the hybrid suite `0x02`
 *  (`hybridAuthorId`, §12.4). One 32-byte id either way, so an operator pins an
 *  identity here without knowing which suite produced it.
 *
 *  **This is the APP allowlist, and it refuses a bundle claiming a slot.** Admitting an
 *  ordinary app risks that app; admitting a transport risks the channel, which sees all
 *  plaintext and holds the session keys (§12.4). "I trust this author's chat app" is not
 *  the same decision as "I trust this author to be my transport", and an author
 *  allowlist that answered both would silently turn the first into the second — an
 *  author already trusted for apps could ship a bundle with `role: "transport"` and land
 *  it with no further consent. Slot occupants go through `roleAllowlist`. */
export function authorAllowlist(authors: string[]): AdmitPredicate {
  const set = new Set(authors.map((a) => a.toLowerCase()));
  return (v) => v.manifest.role === undefined && set.has(toHex(v.author));
}

/** The slot-occupant counterpart of `authorAllowlist` (§12.4, §12.5): a per-slot set of
 *  authors trusted to fill THAT slot, and nothing else.
 *
 *  `slots` maps a role name to its allowed author ids (hex, case-insensitive). A bundle
 *  claiming no slot is refused here — the two predicates partition the bundles rather
 *  than overlapping, so composing them with `anyOf` gives each kind exactly one place it
 *  can be admitted from, and neither can widen the other. A slot with no entry, or an
 *  author not in it, is refused: there is no "trusted everywhere" author.
 *
 *  It mirrors the observer distinction in §12.10 — a capability grant held to a
 *  different bar than "which chat app do I want" — and it is the reason `role` is in the
 *  signed manifest at all. */
export function roleAllowlist(slots: Record<string, string[]>): AdmitPredicate {
  const byRole = new Map<string, Set<string>>();
  for (const [role, authors] of Object.entries(slots)) {
    byRole.set(role, new Set(authors.map((a) => a.toLowerCase())));
  }
  return (v) => {
    const role = v.manifest.role;
    if (role === undefined) return false;
    return byRole.get(role)?.has(toHex(v.author)) ?? false;
  };
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

/** Any predicate admits (logical OR, short-circuiting). For predicates that partition
 *  the bundles — `authorAllowlist` takes apps, `roleAllowlist` takes slot occupants —
 *  where AND would admit nothing at all. A predicate that throws to explain itself still
 *  aborts the whole disjunction: an explained refusal is a decision, not a "no" to try
 *  the next alternative against. */
export function anyOf(...predicates: AdmitPredicate[]): AdmitPredicate {
  return async (v) => {
    for (const p of predicates) if (await p(v)) return true;
    return false;
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
  // `roles` is optional and absent means the strongest thing it can mean: no author may
  // occupy any slot on this host. A deployment that wants a replaceable transport says
  // so with a second, deliberate list — `{"roles": {"transport": ["<hex>"]}}` — which is
  // the whole point of the field (§12.5). Every slot name is checked against
  // BUNDLE_ROLES, so a typo'd role is a boot failure rather than a list that admits
  // nothing and looks like it should.
  //
  // Without it the app allowlist stands alone, uncomposed: `anyOf` of one predicate is
  // the same decision but an async one, and a policy that answers synchronously today
  // should keep doing so — a caller that forgot to await would read a Promise as `true`.
  let kind: AdmitPredicate = authorAllowlist(authors);
  if (o.roles !== undefined) {
    if (typeof o.roles !== "object" || o.roles === null || Array.isArray(o.roles)) {
      throw new Error('policy: "roles" must be an object mapping a slot name to its allowed authors');
    }
    const slots: Record<string, string[]> = {};
    for (const [role, list] of Object.entries(o.roles as Record<string, unknown>)) {
      if (!(BUNDLE_ROLES as readonly string[]).includes(role)) {
        throw new Error(`policy: unknown slot "${role}" in "roles" (known: ${BUNDLE_ROLES.join(", ")})`);
      }
      if (!Array.isArray(list) || list.some((x) => typeof x !== "string")) {
        throw new Error(`policy: "roles.${role}" must be an array of hex author ids`);
      }
      if (list.length === 0) throw new Error(`policy: "roles.${role}" must list at least one author (omit the slot to allow none)`);
      slots[role] = list as string[];
    }
    kind = anyOf(authorAllowlist(authors), roleAllowlist(slots));
  }
  // `manifestSuites` is optional and, like everything else here, strict: a typo'd or
  // empty list fails the boot rather than quietly widening (or emptying) what lands.
  // Absent ⇒ any suite the host can verify.
  if (o.manifestSuites === undefined) return kind;
  if (!Array.isArray(o.manifestSuites)
    || o.manifestSuites.some((x) => typeof x !== "number" || !Number.isInteger(x))) {
    throw new Error('policy: "manifestSuites" must be an array of integer suite ids');
  }
  const suites = o.manifestSuites as number[];
  if (suites.length === 0) throw new Error('policy: "manifestSuites" must list at least one suite id');
  // The suite axis applies to apps and slot occupants alike — it is about how a bundle
  // was signed, not about what it claims to be — so it ANDs over the disjunction.
  return allOf(kind, manifestSuiteAllowlist(suites));
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
