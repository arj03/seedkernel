// Admission predicate (§12.5): one pure function of (verified bundle, AdmissionContext),
// asked once between verifyBundle and slot construction. Host gates (revocation, freshness)
// wrap the operator's predicate so admitAll cannot lose them, and are asked again at commit,
// where the facts they read may have moved. Deny-all is the default.


import { toHex } from "../core/util.js";
import { PRIVILEGES, type Privilege } from "../core/domains.js";
import { type VerifiedBundle } from "./bundle.js";

/** Everything a gate needs, read by the shell and handed to the predicate — which is what
 *  makes the predicate pure and its order irrelevant. */
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

/** The half of the context that MOVES: what a `revoke` or another load changes under a
 *  load already in flight. */
export type HostFacts = Pick<AdmissionContext, "highWater" | "revoked">;

/** The ONE admission seam. `(v, ctx) → bool | Promise<bool>`.
 *  Return `true` to admit, `false` to reject silently, or throw to reject with a
 *  reason — which is how a rejection stays distinguishable without a result type. */
export type Admit = (v: VerifiedBundle, ctx: AdmissionContext) => boolean | Promise<boolean>;

/** The default: nothing is admitted.
 *  A node with no configured predicate boots, serves, and refuses every install. */
export const denyAll: Admit = () => false;

/** Any verified bundle is admitted. Shell still composes hostGates around it. */
export const admitAll: Admit = () => true;

/** Revocation (§12.5) before the downgrade guard (§12.4), so a written-off key never reaches
 *  an interactive consent dialog. Equal versions reload, transport included. Sync and
 *  throwing: the loader asks it again in the commit window, which cannot await. */
export function checkHostGates(v: VerifiedBundle, facts: HostFacts): void {
  if (facts.revoked) {
    throw new Error(`bundle: author ${toHex(v.author)} is revoked on this host — refusing ${v.manifest.app} v${v.manifest.version}`);
  }
  if (v.manifest.version < facts.highWater) {
    throw new Error(`bundle: version ${v.manifest.version} is below the (author, app) freshness high-water mark ${facts.highWater} — downgrade refused`);
  }
}

/** The same gates as a predicate. Shell composes this around the operator's predicate so no
 *  posture can lose them. */
export const hostGates: Admit = (v, ctx) => { checkHostGates(v, ctx); return true; };

/** Admit authors whose hex id is in the closed set (§12.4). */
export function authorAllowlist(authors: string[]): Admit {
  const set = new Set(authors.map((a) => a.toLowerCase()));
  return (v) => set.has(toHex(v.author));
}

/** Trust keyed on capability (§12.5): `base` for a bundle that reaches none; every
 *  named grant for one that does. A missing grant denies. */
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

/** Logical AND, short-circuiting. A throw keeps the refusal distinguishable. */
export function allOf(...predicates: Admit[]): Admit {
  return async (v, ctx) => {
    for (const p of predicates) if (!(await p(v, ctx))) return false;
    return true;
  };
}

/** One author list, parsed strictly — shared by `authors` and every grant. */
function authorList(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((x) => typeof x !== "string")) {
    throw new Error(`policy: "${name}" must be an array of hex author ids`);
  }
  if (value.length === 0) {
    throw new Error(`policy: "${name}" must list at least one author (omit it to allow none)`);
  }
  return value as string[];
}

/** Parse a policy file into the one predicate a shell runs under (§12.5).
 *  `{ "authors": ["<hex>"], "grants": { "link": ["<hex>"] } }`. Omitted = nobody;
 *  unknown keys fail the boot. A grant is a veto over the booted transport blob. */
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
