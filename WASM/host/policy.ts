// The shell's admission predicate (README §12.5) — ONE pure function, asked once, on
// the one install path. Admission is the single seam between verifyBundle and
// installBundle (§12.4): governance is this file, mechanics is installBundle.
//
// **One predicate, not a scatter of gates.** Admission is a revocation check, two
// coherence rules about the claim itself, a version floor, and a per-class operator
// predicate composed into one `Admit` at shell construction and evaluated in one call —
// so "the policy said yes but freshness said no" cannot happen: there is one answer from
// one call. Everything a gate needs arrives as `AdmissionContext`, so the predicate is a
// pure function of `(bundle, context)` — no store, no I/O, no order to get wrong.
//
// That is why EVERY pure question about a bundle belongs here rather than beside the call
// in the shell. A rule that refuses a bundle from outside the predicate is a second
// decision point, and a second decision point is where "nothing has landed until the
// predicate says yes" stops being a property of the type and starts being a property of
// how carefully the load path was read.
//
// The host's own four — `notRevoked`, `wholePrivileges`, `mountClaimsNoProtocol` and
// `freshVersion` — are composed by the SHELL, not by the operator. That matters: they are
// invariants rather than posture, so `admitAll` must not be a way to lose them, and an
// OFFER-delivered bundle (§11) is exactly the path that would.
//
// **Trust is per PRIVILEGE, and the privileges are the catalog's.** Admitting an
// ordinary app risks that app; granting the mount risks the channel, which sees all
// plaintext and holds the session keys (§12.4). "I trust this author's chat app" is not
// "I trust this author to be my transport", so those are separate answers — but the
// thing an operator says yes to is the CAPABILITY, not a name for the kind of bundle
// that wants it. `byPrivilege` keeps the answers separate over `PRIVILEGES` (domains.ts),
// so the next authority that is too dangerous to hand out freely gets its own operator
// grant by appearing in the catalog under a new prefix, with no third class here and no
// second vocabulary for an operator to learn.
//
// **What a bundle reaches is not decided here.** There is no `role` field in a manifest
// and no class the shell assigns: the shell reads the privileges off `guest.requires`
// (`grantGroups`, over the catalog) and hands them in as `ctx.privileges`. That runs
// only the strict way — naming `link/open` puts `mount` in the set, and nothing takes
// one out — so an author cannot shed a grant by editing a manifest, and a permissive
// `authors` list is a bad configuration rather than a path to sockets.
//
// Three constructors cover the three deployment postures, and compose into any grant:
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
// Deny-all stays the default: the absent predicate admits nothing.

import { toHex } from "../core/util.js";
import { GROUPS_BY_PRIVILEGE, PRIVILEGE_MOUNT, PRIVILEGES, type Privilege } from "../core/domains.js";
import { grantGroups, privilegesOf, type VerifiedBundle } from "./bundle.js";

/** Everything a gate needs, read ONCE by the shell and handed to the predicate —
 *  which is what makes the predicate pure and its order irrelevant. */
export interface AdmissionContext {
  /** The privileges this bundle's `requires` reach (§12.5), derived by the shell from
   *  the catalog and never from anything the bundle says about itself. Empty ⇒ it
   *  reaches none and is an ordinary app. */
  privileges: readonly Privilege[];
  /** The persisted `(author, app)` freshness high-water mark, or −Infinity if this
   *  pair has never loaded on this host (README §12.4). */
  highWater: number;
  /** Has this host written this author key off (§12.5)? */
  revoked: boolean;
}

/** The ONE admission seam. `(v, ctx) → bool | Promise<bool>`.
 *  Return `true` to admit, `false` to reject silently, or throw to reject with a
 *  reason — which is how a rejection stays distinguishable without a result type. */
export type Admit = (v: VerifiedBundle, ctx: AdmissionContext) => boolean | Promise<boolean>;

/** The default: nothing is admitted.
 *  A node with no configured predicate boots, serves, and refuses every install. */
export const denyAll: Admit = () => false;

/** Any verified bundle is admitted — "the bundle my operator handed me IS the
 *  trust decision." A StorageNode loads exactly the one bundle it was configured
 *  with; the choice of bundle already settled admission.
 *
 *  Safe for the mount too, and for the same reason it is safe for apps: the operator
 *  naming one blob is a decision about that blob. The distinction `authorAllowlist`
 *  draws exists because an allowlist admits bundles the operator has never seen; this
 *  admits exactly the ones they chose.
 *
 *  It cannot be a way to lose revocation or the downgrade guard: those are composed by
 *  the shell around whatever the operator supplies, not by the operator (`hostGates`). */
export const admitAll: Admit = () => true;

/** Refuse anything signed by a written-off author key (§12.5).
 *
 *  A stolen key satisfies freshness trivially — it signs `version + 1` — so this is the
 *  check that has anything to say about it, and it runs before every other, including
 *  the operator's: an interactive shell puts a consent dialog in its predicate, and a
 *  written-off key must never reach the prompt. */
export const notRevoked: Admit = (v, ctx) => {
  if (ctx.revoked) {
    throw new Error(`bundle: author ${toHex(v.author)} is revoked on this host — refusing ${v.manifest.app} v${v.manifest.version}`);
  }
  return true;
};

/** Refuse a load below the persisted `(author, app)` high-water mark as a downgrade
 *  (README §12.4). Equal versions reload — an ordinary reboot re-reads the same bundle.
 *
 *  The mounted transport is checked no differently: versions are an author's own
 *  lineage, so the mount carries the ordinary `(author, app)` mark and nothing second
 *  keyed to the slot. A floor keyed to the slot would bind every author of the mount to
 *  one shared version line — B could not replace A's v5 without numbering above it, a
 *  sequence with no owner — and would buy protection only where an attacker chooses
 *  which signed bundle arrives. Nothing delivers a bundle but the operator (§12.4). */
export const freshVersion: Admit = (v, ctx) => {
  if (v.manifest.version < ctx.highWater) {
    throw new Error(`bundle: version ${v.manifest.version} is below the (author, app) freshness high-water mark ${ctx.highWater} — downgrade refused`);
  }
  return true;
};

/** Every half of a privilege, or none of it (§12.5). A bundle with no `mount:sockets`
 *  name has no sockets and one with no `mount:report` name has nowhere to report, so a
 *  partial claim could only stand as a transport that is not one — refused at the load
 *  rather than at the first dial.
 *
 *  A gate rather than a check the shell runs beside the predicate, because it is the same
 *  KIND of thing as the two above — a pure question about a verified bundle, answered
 *  before anything lands — and because being a gate is what keeps it in front of the
 *  operator's predicate on every target. The hole it closes needs that: a partial claim
 *  reaches no privilege, so a bundle naming `link/open` alone would otherwise fall
 *  through `byPrivilege` to the UNPRIVILEGED base and be admitted by the ordinary app
 *  list. */
export const wholePrivileges: Admit = (v) => {
  const groups = grantGroups(v.manifest);
  for (const priv of privilegesOf(v.manifest)) {
    const missing = (GROUPS_BY_PRIVILEGE.get(priv) ?? []).filter((g) => !groups.includes(g));
    if (missing.length > 0) {
      throw new Error(`bundle: a bundle claims every half of a privilege or none; ${v.manifest.app} declares ${groups.join(", ")} but nothing for ${missing.join(", ")} (§12.5)`);
    }
  }
  return true;
};

/** A mount claims no protocol ids (§12.10). It is not an app: it receives no dispatch, so
 *  a frame naming one of these ids could never arrive, and a claim that can never be
 *  honored is a manifest that has misread the format rather than a line to ignore. */
export const mountClaimsNoProtocol: Admit = (v) => {
  const claimed = v.manifest.protocols ?? [];
  if (claimed.length > 0 && privilegesOf(v.manifest).includes(PRIVILEGE_MOUNT)) {
    throw new Error(`bundle: a transport claims no protocol ids; ${v.manifest.app} claims ${claimed.join(", ")} — a mount receives no dispatch (§12.10)`);
  }
  return true;
};

/** The host's own half of admission, in the order it must run: revocation first (a
 *  written-off key never reaches a consent prompt), then the two coherence gates — which
 *  are facts about the bundle alone, so a malformed claim is reported as itself rather
 *  than as whatever host state it happens to also fall foul of — then the downgrade
 *  guard. The shell composes this AROUND the operator's predicate on every target, so no
 *  posture — not `admitAll`, not an interactive dialog that always says yes — can be a
 *  way to lose any of them. Exported so a target assembling its own load path gets the
 *  same gates, in the same order, from the same place. */
export const hostGates: Admit = allOf(notRevoked, wholePrivileges, mountClaimsNoProtocol, freshVersion);

/** A predicate that checks the manifest author's id against a closed set.
 *  `authors` strings are hex author ids, case-insensitive — an Ed25519 pubkey under
 *  manifest suite `0x01`, the derived key-set id under the hybrid suite `0x02`
 *  (`hybridAuthorId`, §12.4). One 32-byte id either way, so an operator pins an
 *  identity here without knowing which suite produced it.
 *
 *  It says nothing about what it guards: the same constructor builds the list of authors
 *  who may load at all and the list of those who may hold a given privilege, and a policy
 *  file that wants one author trusted for both says so twice. That is the point —
 *  trusting an author is per-capability, and there is no "trusted everywhere" author. */
export function authorAllowlist(authors: string[]): Admit {
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
export function manifestSuiteAllowlist(suites: number[]): Admit {
  const set = new Set(suites);
  return (v) => set.has(v.suite);
}

/** Trust keyed on CAPABILITY: `base` decides a bundle that reaches no privilege, and a
 *  bundle that reaches some must be admitted by the grant of **every one** of them
 *  (§12.5).
 *
 *  A combinator rather than a record the runtime holds several of, because which
 *  privileges are in play is the shell's answer — over the manifest's `requires`, before
 *  it asks anything of this file — and a runtime that carried the predicates separately
 *  could reach the wrong one, which is the single bug this split exists to prevent. Here
 *  there is one predicate and the capability set is an argument to it.
 *
 *  A privilege with no entry in `grants` denies, so widening `base` can never widen a
 *  grant by omission, and a privilege added to the catalog is refused everywhere until an
 *  operator has said something about it — the safe direction for the one edit that
 *  silently changes what a policy file means. */
export function byPrivilege(p: { base: Admit; grants: Readonly<Partial<Record<Privilege, Admit>>> }): Admit {
  return async (v, ctx) => {
    if (ctx.privileges.length === 0) return p.base(v, ctx);
    for (const priv of ctx.privileges) {
      const granted = p.grants[priv];
      if (!granted || !(await granted(v, ctx))) return false;
    }
    return true;
  };
}

/** Every predicate must admit (logical AND, short-circuiting). Rejections stay
 *  distinguishable because a predicate that wants to explain itself throws. */
export function allOf(...predicates: Admit[]): Admit {
  return async (v, ctx) => {
    for (const p of predicates) if (!(await p(v, ctx))) return false;
    return true;
  };
}

/** Any predicate admits (logical OR, short-circuiting). For a class an operator wants
 *  decided more than one way — an allowlist OR a consent dialog — where AND would mean
 *  both. A predicate that throws to explain itself still aborts the whole disjunction:
 *  an explained refusal is a decision, not a "no" to try the next alternative against. */
export function anyOf(...predicates: Admit[]): Admit {
  return async (v, ctx) => {
    for (const p of predicates) if (await p(v, ctx)) return true;
    return false;
  };
}

/** One author list, parsed strictly. Shared by every list in the file so `authors` and
 *  the grants cannot diverge in what they accept — a typo or an empty list fails the
 *  boot on any of them, rather than quietly widening (or emptying) what lands. */
function authorList(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((x) => typeof x !== "string")) {
    throw new Error(`policy: "${name}" must be an array of hex author ids`);
  }
  if (value.length === 0) {
    throw new Error(`policy: "${name}" must list at least one author (omit it to allow none)`);
  }
  return value as string[];
}

/** Parse a policy config file into the one predicate a shell runs under.
 *  Throws on malformed input — a typo fails the boot loudly rather than
 *  silently widening trust.
 *
 *      { "authors": ["<hex>"], "grants": { "mount": ["<hex>"] }, "manifestSuites": [2] }
 *
 *  `authors` is who may load a bundle that reaches no privilege; each key of `grants` is
 *  a privilege from the catalog (`PRIVILEGES`) and lists who may hold THAT. An operator
 *  therefore reads the risk itself — "these authors may be the node's transport" — rather
 *  than a name for the kind of bundle that carries it, and a privilege added to the
 *  catalog is a new key here rather than a new class.
 *
 *  Anything omitted means the strongest thing it can mean: nobody. A node with only
 *  `authors` runs apps and has no network, which is a deliberate configuration ("this
 *  node does not speak to anyone", §14) and not an error — so every decision sits in one
 *  object where an operator sees them at once, while none of it is anywhere a bundle
 *  author can reach.
 *
 *  An unknown key under `grants` is refused rather than ignored, and that is the whole
 *  value of naming privileges from the catalog: a misspelled grant is the failure mode
 *  where a node comes up looking configured and silently holds nothing. */
export function parsePolicy(json: string): Admit {
  let raw: unknown;
  try { raw = JSON.parse(json); }
  catch (e) { throw new Error(`policy: invalid JSON (${(e as Error).message})`); }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("policy: expected a JSON object");
  }
  const o = raw as Record<string, unknown>;
  // Superseded vocabularies, refused BY NAME rather than ignored. Either would otherwise
  // parse into an app-only policy and leave the node silently without a network — the one
  // failure mode a transport misconfiguration must never have, since "no transport" is
  // also a legitimate configuration and would look identical.
  if (o.roles !== undefined) {
    throw new Error('policy: "roles" is gone — a bundle declares no role; grant the capability instead, as "grants": { "mount": [...] }');
  }
  if (o.transportAuthors !== undefined) {
    throw new Error('policy: "transportAuthors" is gone — the transport is not a class, it is the "mount" privilege; write "grants": { "mount": [...] }');
  }
  const appAuthors = o.authors === undefined ? undefined : authorList(o.authors, "authors");
  const grants: Partial<Record<Privilege, Admit>> = {};
  const granted: string[] = [];
  if (o.grants !== undefined) {
    if (typeof o.grants !== "object" || o.grants === null || Array.isArray(o.grants)) {
      throw new Error('policy: "grants" must be an object mapping a privilege to its author list');
    }
    for (const [name, value] of Object.entries(o.grants as Record<string, unknown>)) {
      if (!(PRIVILEGES as readonly string[]).includes(name)) {
        throw new Error(`policy: "${name}" is not a privilege this host grants (grants: ${PRIVILEGES.join(", ")})`);
      }
      grants[name as Privilege] = authorAllowlist(authorList(value, `grants.${name}`));
      granted.push(name);
    }
  }
  // A file granting nothing to nobody is a mistake, not a deny-all: deny-all is what an
  // ABSENT policy already means (`policyFromJson`), so an operator who wrote a file and
  // got nothing from it wanted something.
  if (!appAuthors && granted.length === 0) {
    throw new Error('policy: provide "authors", "grants", or both');
  }
  let base = appAuthors ? authorAllowlist(appAuthors) : denyAll;
  // `manifestSuites` is optional and, like everything else here, strict.
  // Absent ⇒ any suite the host can verify.
  if (o.manifestSuites !== undefined) {
    if (!Array.isArray(o.manifestSuites)
      || o.manifestSuites.some((x) => typeof x !== "number" || !Number.isInteger(x))) {
      throw new Error('policy: "manifestSuites" must be an array of integer suite ids');
    }
    const suites = o.manifestSuites as number[];
    if (suites.length === 0) throw new Error('policy: "manifestSuites" must list at least one suite id');
    // The suite axis cuts across every grant — it is about how a bundle was signed, not
    // about what it reaches — so it ANDs into each.
    const suiteOk = manifestSuiteAllowlist(suites);
    base = allOf(base, suiteOk);
    for (const name of granted) grants[name as Privilege] = allOf(grants[name as Privilege]!, suiteOk);
  }
  return byPrivilege({ base, grants });
}

/** The policy a shell runs under given its (optional) config file.
 *  A provided config is parsed strictly by `parsePolicy` — a typo fails the
 *  boot loudly. An omitted one is deny-all: the node boots, serves, has no
 *  network, and every install is refused (README §14).
 *
 *  The default lives here, in the shared core, so every target — the Node shell,
 *  the native loader — resolves "no policy configured" through this one function
 *  and cannot drift into a permissive default of its own. */
export function policyFromJson(json: string | null | undefined): Admit {
  return json ? parsePolicy(json) : denyAll;
}
