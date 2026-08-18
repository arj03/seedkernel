// The shell's admission predicate (README §12.5) — ONE pure function, asked once, on
// the one install path. Admission is the single seam between verifyBundle and
// installBundle (§12.4): governance is this file, mechanics is installBundle.
//
// **One predicate, not a scatter of gates.** A revocation check, a version floor and a
// per-capability operator predicate compose into one `Admit` at shell construction and are
// evaluated in one call, so "the policy said yes but freshness said no" cannot happen.
// Everything a gate needs arrives as `AdmissionContext`, which is what makes the predicate
// a pure function of `(bundle, context)` — no store, no I/O, no order to get wrong.
//
// So EVERY pure question about a bundle belongs here rather than beside the call in the
// shell: a rule that refuses a bundle from outside the predicate is a second decision
// point, and that is where "nothing has landed until the predicate says yes" stops being a
// property of the type. The host's own two are composed by the SHELL rather than the
// operator, because they are invariants rather than posture — `admitAll` must not be a way
// to lose them.
//
// **Trust is per PRIVILEGE, and the privileges are the catalog's.** Admitting an ordinary
// app risks that app; granting `link` risks the channel, which sees all plaintext and holds
// the session keys (§12.4). What an operator says yes to is the CAPABILITY, not a name for
// the kind of bundle that wants it, so the next authority too dangerous to hand out freely
// gets its own grant by appearing in the catalog — no third class, no second vocabulary.
//
// What a bundle reaches is not decided here: the shell reads it off `guest.requires`
// (`privilegesOf`) and hands it in as `ctx.privileges`. That runs only the strict way, so
// an author cannot shed a grant by editing a manifest and a permissive `authors` list is a
// bad configuration rather than a path to sockets.
//
// Deny-all stays the default: the absent predicate admits nothing.

import { toHex } from "../core/util.js";
import { PRIVILEGES, type Privilege } from "../core/domains.js";
import { type VerifiedBundle } from "./bundle.js";

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

/** Any verified bundle is admitted — "the bundle my operator handed me IS the trust
 *  decision". Safe for the transport too, and for the same reason: an allowlist admits
 *  bundles the operator has never seen, while this admits exactly the ones they chose. It
 *  cannot be a way to lose revocation or the downgrade guard, which the shell composes
 *  around whatever the operator supplies (`hostGates`). */
export const admitAll: Admit = () => true;

/** Refuse anything signed by a written-off author key (§12.5). A stolen key satisfies
 *  freshness trivially — it signs `version + 1` — so this is the check with anything to
 *  say about it, and it runs before every other, including the operator's: a written-off
 *  key must never reach a consent prompt. */
export const notRevoked: Admit = (v, ctx) => {
  if (ctx.revoked) {
    throw new Error(`bundle: author ${toHex(v.author)} is revoked on this host — refusing ${v.manifest.app} v${v.manifest.version}`);
  }
  return true;
};

/** Refuse a load below the persisted `(author, app)` high-water mark as a downgrade
 *  (README §12.4). Equal versions reload — an ordinary reboot re-reads the same bundle.
 *
 *  The transport is checked no differently: versions are an author's own lineage, so it
 *  carries the ordinary `(author, app)` mark and nothing keyed to the slot. A slot-keyed
 *  floor would bind every transport author to one shared version line — B could not
 *  replace A's v5 without numbering above it — and would buy protection only where an
 *  attacker chooses which signed bundle arrives, which nothing does (§12.4). */
export const freshVersion: Admit = (v, ctx) => {
  if (v.manifest.version < ctx.highWater) {
    throw new Error(`bundle: version ${v.manifest.version} is below the (author, app) freshness high-water mark ${ctx.highWater} — downgrade refused`);
  }
  return true;
};

/** The host's own half of admission, in the order it must run: revocation first (a
 *  written-off key never reaches a consent prompt), then the downgrade guard. The shell
 *  composes this AROUND the operator's predicate on every target, so no posture can be a
 *  way to lose either. Exported so a target assembling its own load path gets the same
 *  gates, in the same order, from the same place. */
export const hostGates: Admit = allOf(notRevoked, freshVersion);

/** A predicate that checks the manifest author's id against a closed set. `authors` are hex
 *  author ids, case-insensitive — the derived key-set id (`hybridAuthorId`, §12.4).
 *
 *  It says nothing about what it guards: the same constructor builds the list of authors
 *  who may load at all and the list of those who may hold a privilege, so a file wanting
 *  one author trusted for both says so twice. There is no "trusted everywhere" author. */
export function authorAllowlist(authors: string[]): Admit {
  const set = new Set(authors.map((a) => a.toLowerCase()));
  return (v) => set.has(toHex(v.author));
}

/** Trust keyed on CAPABILITY: `base` decides a bundle that reaches no privilege, and a
 *  bundle that reaches some must be admitted by the grant of **every one** of them
 *  (§12.5).
 *
 *  A combinator rather than a record the runtime holds several of: which privileges are in
 *  play is the shell's answer over the manifest's `requires`, and a runtime carrying the
 *  predicates separately could reach the wrong one — the single bug this split prevents.
 *
 *  A privilege with no entry in `grants` denies, so widening `base` can never widen a grant
 *  by omission, and a privilege added to the catalog is refused everywhere until an
 *  operator has said something about it. */
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

/** One author list, parsed strictly. Shared by every list in the file so `authors` and the
 *  grants cannot diverge in what they accept: a typo or an empty list fails the boot on any
 *  of them rather than quietly widening (or emptying) what lands. */
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
 *      { "authors": ["<hex>"], "grants": { "link": ["<hex>"] } }
 *
 *  `authors` is who may load a bundle that reaches no privilege; each key of `grants` is a
 *  privilege from the catalog (`PRIVILEGES`) and lists who may hold THAT — so an operator
 *  reads the risk itself rather than a name for the kind of bundle that carries it.
 *
 *  Anything omitted means the strongest thing it can mean: nobody. A node with only
 *  `authors` runs apps and has no network, which is a deliberate configuration (§14).
 *
 *  An unknown key is refused rather than ignored, at the top level and under `grants`
 *  alike: a misspelled key would otherwise come up looking configured while holding
 *  nothing, indistinguishable from a node configured to hold nothing on purpose. */
export function parsePolicy(json: string): Admit {
  let raw: unknown;
  try { raw = JSON.parse(json); }
  catch (e) { throw new Error(`policy: invalid JSON (${(e as Error).message})`); }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("policy: expected a JSON object");
  }
  const o = raw as Record<string, unknown>;
  for (const key of Object.keys(o)) {
    if (key !== "authors" && key !== "grants") {
      throw new Error(`policy: "${key}" is not a policy key (the file is "authors", "grants", or both)`);
    }
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
  const base = appAuthors ? authorAllowlist(appAuthors) : denyAll;
  return byPrivilege({ base, grants });
}

/** The policy a shell runs under given its (optional) config file. An omitted one is
 *  deny-all: the node boots, serves, has no network, and every install is refused (§14).
 *  The default lives here so no target can drift into a permissive one of its own. */
export function policyFromJson(json: string | null | undefined): Admit {
  return json ? parsePolicy(json) : denyAll;
}
