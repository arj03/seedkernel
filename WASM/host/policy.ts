// The shell's admission policy (README §12.5). Two predicates, because there are two
// admission CLASSES — ordinary apps and the node's transport — and each answers exactly
// one question: "may this verified bundle land, as this?" Admission is the one seam
// between verifyBundle and installBundle (§12.4), on the one install path. Governance is
// these predicates; mechanics is installBundle.
//
// The two are separate because the risks are: admitting an ordinary app risks that app;
// mounting a transport risks the channel, which sees all plaintext and holds the session
// keys (§12.4). "I trust this author's chat app" is not the same decision as "I trust
// this author to be my transport", and one predicate answering both would silently turn
// the first into the second.
//
// **What picks the class is not here.** There is no `role` field: the shell reads it off
// `guest.requires` (`mountGroups`, over the catalog's mount halves) before it asks
// anything of this file. That dispatch
// runs only the strict way — naming `link/open` moves a bundle onto `transport`, never onto
// `apps` — so an author cannot reach the looser predicate by editing a manifest, and a
// permissive `apps` predicate is a bad configuration rather than a path to sockets.
//
// Three constructors cover the three deployment postures, and compose into either class:
//   authorAllowlist  — a file-backed closed set of author ids
//   admitAll         — "the bundle my operator handed me" (StorageNode posture)
//   interactive      — the caller writes their own, e.g. a per-bundle consent dialog
//
// `manifestSuiteAllowlist` is an axis rather than a posture: which signature
// suites (§12.4) an operator will accept, composed with any of the above through
// `allOf`. It is policy and not verifier logic because "can this host check suite N"
// and "will this deployment trust suite N" are different questions — a node finishing a
// post-quantum migration answers yes to the first for 0x01 and no to the second.
//
// Deny-all stays the default, for both: the absent predicate admits nothing.

import { toHex } from "../core/util.js";
import type { VerifiedBundle } from "./bundle.js";

/** One admission seam.
 *  `(v: VerifiedBundle) → bool | Promise<bool>`.
 *  Return `true` to admit, `false` or throw to reject. */
export type AdmitPredicate = (v: VerifiedBundle) => boolean | Promise<boolean>;

/** What a policy file resolves to: one predicate per admission class. A record rather
 *  than a single predicate branching internally, because the branch is the shell's
 *  (over the manifest's requires) and a predicate reached through the wrong field would be
 *  the one bug this whole split exists to prevent. */
export interface AdmissionPolicy {
  /** Governs a bundle naming no mount-only name — an ordinary app. */
  apps: AdmitPredicate;
  /** Governs a bundle naming the mount-only names — the node's transport. */
  transport: AdmitPredicate;
}

/** The default: nothing is admitted.
 *  A node with no configured predicate boots, serves, and refuses every install. */
export const denyAll: AdmitPredicate = () => false;

/** Any verified bundle is admitted — "the bundle my operator handed me IS the
 *  trust decision." A StorageNode loads exactly the one bundle it was configured
 *  with; the choice of bundle already settled admission.
 *
 *  Safe for the transport too, and for the same reason it is safe for apps:
 *  the operator naming one blob is a decision about that blob. The distinction
 *  `authorAllowlist` draws exists because an allowlist admits bundles the operator has
 *  never seen; this admits exactly the ones they chose. */
export const admitAll: AdmitPredicate = () => true;

/** A predicate that checks the manifest author's id against a closed set.
 *  `authors` strings are hex author ids, case-insensitive — an Ed25519 pubkey under
 *  manifest suite `0x01`, the derived key-set id under the hybrid suite `0x02`
 *  (`hybridAuthorId`, §12.4). One 32-byte id either way, so an operator pins an
 *  identity here without knowing which suite produced it.
 *
 *  It says nothing about which class it guards: the same constructor builds the app
 *  allowlist and the transport allowlist, and a policy file that wants one author trusted
 *  for both says so twice. That is the point — trusting an author is per-class, and there
 *  is no "trusted everywhere" author. */
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

/** Any predicate admits (logical OR, short-circuiting). For a class an operator wants
 *  decided more than one way — an allowlist OR a consent dialog — where AND would mean
 *  both. A predicate that throws to explain itself still aborts the whole disjunction:
 *  an explained refusal is a decision, not a "no" to try the next alternative against. */
export function anyOf(...predicates: AdmitPredicate[]): AdmitPredicate {
  return async (v) => {
    for (const p of predicates) if (await p(v)) return true;
    return false;
  };
}

/** One author list, parsed strictly. Shared by both classes so `authors` and
 *  `transportAuthors` cannot diverge in what they accept — a typo or an empty list
 *  fails the boot on either, rather than quietly widening (or emptying) what lands. */
function authorList(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((x) => typeof x !== "string")) {
    throw new Error(`policy: "${name}" must be an array of hex author ids`);
  }
  if (value.length === 0) {
    throw new Error(`policy: "${name}" must list at least one author (omit it to allow none)`);
  }
  return value as string[];
}

/** Parse a policy config file into the two predicates a shell runs under.
 *  Throws on malformed input — a typo fails the boot loudly rather than
 *  silently widening trust.
 *
 *  `authors` governs ordinary app loads; `transportAuthors` governs the transport.
 *  Either may be omitted and the omission means the strongest thing it can mean: that
 *  class admits nothing. A node with only `authors` runs apps and has no network, which
 *  is a deliberate configuration ("this node does not speak to anyone", §14) and not an
 *  error — so the two lists sit adjacent here, where an operator can see both decisions
 *  at once, while neither is anywhere a bundle author can reach. */
export function parsePolicy(json: string): AdmissionPolicy {
  let raw: unknown;
  try { raw = JSON.parse(json); }
  catch (e) { throw new Error(`policy: invalid JSON (${(e as Error).message})`); }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("policy: expected a JSON object");
  }
  const o = raw as Record<string, unknown>;
  // The pre-mount vocabulary, refused by name rather than ignored. A file written for
  // the `role`-field design would otherwise parse into an app-only policy and leave the
  // node silently without a network — the one failure mode a transport misconfiguration
  // must never have, since "no transport" is also a legitimate configuration and would
  // look identical.
  if (o.roles !== undefined) {
    throw new Error('policy: "roles" is gone — the transport mounts only through an explicit load, so list its authors under "transportAuthors" instead');
  }
  const appAuthors = o.authors === undefined ? undefined : authorList(o.authors, "authors");
  const transportAuthors = o.transportAuthors === undefined
    ? undefined
    : authorList(o.transportAuthors, "transportAuthors");
  // A file naming neither is a mistake, not a deny-all: deny-all is what an ABSENT
  // policy already means (`policyFromJson`), so an operator who wrote a file and got
  // nothing from it wanted something.
  if (!appAuthors && !transportAuthors) {
    throw new Error('policy: provide "authors", "transportAuthors", or both');
  }
  let apps = appAuthors ? authorAllowlist(appAuthors) : denyAll;
  let transport = transportAuthors ? authorAllowlist(transportAuthors) : denyAll;
  // `manifestSuites` is optional and, like everything else here, strict.
  // Absent ⇒ any suite the host can verify.
  if (o.manifestSuites === undefined) return { apps, transport };
  if (!Array.isArray(o.manifestSuites)
    || o.manifestSuites.some((x) => typeof x !== "number" || !Number.isInteger(x))) {
    throw new Error('policy: "manifestSuites" must be an array of integer suite ids');
  }
  const suites = o.manifestSuites as number[];
  if (suites.length === 0) throw new Error('policy: "manifestSuites" must list at least one suite id');
  // The suite axis applies to both classes — it is about how a bundle was signed, not
  // about what it is landing as — so it ANDs into each.
  const suiteOk = manifestSuiteAllowlist(suites);
  apps = allOf(apps, suiteOk);
  transport = allOf(transport, suiteOk);
  return { apps, transport };
}

/** The policy a shell runs under given its (optional) config file.
 *  A provided config is parsed strictly by `parsePolicy` — a typo fails the
 *  boot loudly. An omitted one is deny-all for both: the node boots, serves,
 *  has no network, and every install is refused (README §14).
 *
 *  The default lives here, in the shared core, so every target — the Node shell,
 *  the native loader — resolves "no policy configured" through this one function
 *  and cannot drift into a permissive default of its own. */
export function policyFromJson(json: string | null | undefined): AdmissionPolicy {
  return json ? parsePolicy(json) : { apps: denyAll, transport: denyAll };
}
