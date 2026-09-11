// Admission predicate (§12.5): one pure function of the verified bundle, asked once for an
// ordinary app between verifyBundle and slot construction. The host's gates (revocation,
// freshness) run before it for every bundle, transport included, so no posture can lose
// them, and are asked again at commit, where the facts they read may have moved. Deny-all
// is the default for ordinary apps.


import { toHex } from "../core/util.js";
import { type FreshnessStore, type VerifiedBundle } from "./bundle.js";

/** The ONE admission seam. `(v) → bool | Promise<bool>`.
 *  Return `true` to admit, `false` to reject silently, or throw to reject with a
 *  reason — which is how a rejection stays distinguishable without a result type. */
export type Admit = (v: VerifiedBundle) => boolean | Promise<boolean>;

/** The default: nothing is admitted.
 *  A node with no configured predicate refuses every ordinary app install. */
export const denyAll: Admit = () => false;

/** Any verified bundle is admitted. The shell still applies its own gates first. */
export const admitAll: Admit = () => true;

/** Revocation (§12.5) before the downgrade guard (§12.4), so a written-off key never reaches
 *  an interactive consent dialog. Equal versions reload, transport included. Sync and
 *  throwing, and read off the store at the call: the loader asks it again in the commit
 *  window, which cannot await, and a `revoke` or another load may have moved both facts. */
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
  if (!Array.isArray(o.authors) || o.authors.some((a) => typeof a !== "string" || !/^[0-9a-f]{64}$/i.test(a))) {
    throw new Error('policy: "authors" must be an array of 64-character hex author ids');
  }
  return authorAllowlist(o.authors);
}

/** An absent policy admits no apps. Transport selection is a separate explicit decision. */
export function policyFromJson(json: string | null | undefined): Admit {
  return json ? parsePolicy(json) : denyAll;
}
