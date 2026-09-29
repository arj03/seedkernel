// Admission predicate (§12.5): a pure function of the verified bundle, asked once for an
// ordinary app between verifyBundle and slot construction. The host gates (revocation,
// freshness) run before it for every bundle, transport included, and again at commit,
// since what they read may have changed by then. Ordinary apps default to deny-all.

import { isHex64, toHex } from "../services/util.js";
import { type FreshnessStore, type VerifiedBundle } from "./bundle.js";

/** The admission seam. Return `true` to admit, `false` to reject silently, or throw to
 *  reject with a reason. */
export type Admit = (v: VerifiedBundle) => boolean | Promise<boolean>;

/** The default: a node with no configured predicate refuses every ordinary app install. */
export const denyAll: Admit = () => false;

/** Any verified bundle is admitted. The shell still applies its own gates first. */
export const admitAll: Admit = () => true;

/** Revocation (§12.5), then the downgrade guard (§12.4), so a revoked key never reaches an
 *  interactive consent dialog. Equal versions reload, transport included. Synchronous and
 *  read from the store on each call, because install asks again in the commit window,
 *  which cannot await, and a `revoke` or another load may have changed either fact. */
export function checkHostGates(v: VerifiedBundle, store: FreshnessStore): void {
  if (store.isRevoked(v.author)) {
    throw new Error(`bundle: author ${toHex(v.author)} is revoked on this host — refusing ${v.manifest.app} v${v.manifest.version}`);
  }
  const highWater = store.get(v.author, v.manifest.app);
  if (v.manifest.version < highWater) {
    throw new Error(`bundle: version ${v.manifest.version} is below the (author, app) freshness high-water mark ${highWater} — downgrade refused`);
  }
}

/** Admit authors whose hex id is in the closed set (§12.4). */
export function authorAllowlist(authors: string[]): Admit {
  const set = new Set(authors.map((a) => a.toLowerCase()));
  return (v) => set.has(toHex(v.author));
}

/** Parse the app-author policy, `{ "authors": ["<hex>"] }`. Link authorization comes from
 *  boot selection or explicit owner replacement, never from this file. */
export function parsePolicy(json: string): Admit {
  let raw: unknown;
  try { raw = JSON.parse(json); }
  catch (e) { throw new Error(`policy: invalid JSON (${(e as Error).message})`); }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("policy: expected a JSON object");
  }
  const o = raw as Record<string, unknown>;
  for (const key of Object.keys(o)) {
    if (key !== "authors") throw new Error(`policy: "${key}" is not a policy key (expected "authors")`);
  }
  if (!Array.isArray(o.authors) || o.authors.some((a) => typeof a !== "string" || !isHex64(a))) {
    throw new Error('policy: "authors" must be an array of 64-character hex author ids');
  }
  return authorAllowlist(o.authors);
}

/** An absent policy admits no apps. Transport selection is a separate decision. */
export function policyFromJson(json: string | null | undefined): Admit {
  return json ? parsePolicy(json) : denyAll;
}
