// The shell's admission predicate (README §12.5) — ONE pure function, asked once, on
// the one install path. Admission is the single seam between verifyBundle and
// installBundle (§12.4): governance is this file, mechanics is installBundle.
//
// **One predicate, not four gates.** A load used to pass through a revocation check, a
// version floor, and a per-class operator predicate, each in a different file and each
// with its own place in a carefully ordered sequence — so "the policy said yes but
// freshness said no" was a real interleaving somebody had to keep right. They are now
// one `Admit`, composed at shell construction and evaluated in one call. Everything a
// gate used to read for itself arrives as `AdmissionContext`, so the predicate is a pure
// function of `(bundle, context)` — no store, no I/O, no order to get wrong.
//
// The host's own two — `notRevoked` and `freshVersion` — are composed by the SHELL, not
// by the operator. That matters: they are invariants rather than posture, so `admitAll`
// must not be a way to lose them, and an OFFER-delivered bundle (§11) is exactly the
// path that would.
//
// **Two admission classes remain, as a combinator.** Admitting an ordinary app risks
// that app; mounting a transport risks the channel, which sees all plaintext and holds
// the session keys (§12.4). "I trust this author's chat app" is not "I trust this author
// to be my transport", so `byRole` keeps the two answers separate — but it answers
// through the same predicate the runtime already calls, so the runtime never picks
// between two of them.
//
// **What picks the class is not here.** There is no `role` field in a manifest: the
// shell reads it off `guest.requires` (`mountGroups`, over the catalog's mount halves)
// and hands it in as `ctx.role`. That dispatch runs only the strict way — naming
// `link/open` moves a bundle onto `mount`, never onto `app` — so an author cannot reach
// the looser branch by editing a manifest, and a permissive `app` predicate is a bad
// configuration rather than a path to sockets.
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
// Deny-all stays the default: the absent predicate admits nothing.

import { toHex } from "../core/util.js";
import type { VerifiedBundle } from "./bundle.js";

/** Which admission class a bundle is landing as, decided by the shell from the
 *  manifest's `requires` and never by anything the bundle says about itself. */
export type AdmissionRole = "app" | "mount";

/** Everything a gate used to read for itself, read ONCE by the shell and handed to the
 *  predicate — which is what makes the predicate pure and its order irrelevant. */
export interface AdmissionContext {
  /** `"mount"` iff the manifest names the mount-only groups (§12.5). */
  role: AdmissionRole;
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

/** The host's own half of admission, in the order it must run: revocation first (a
 *  written-off key never reaches a consent prompt), then the downgrade guard. The shell
 *  composes this AROUND the operator's predicate on every target, so no posture — not
 *  `admitAll`, not an interactive dialog that always says yes — can be a way to lose
 *  either one. Exported so a target assembling its own load path gets the same two, in
 *  the same order, from the same place. */
export const hostGates: Admit = allOf(notRevoked, freshVersion);

/** A predicate that checks the manifest author's id against a closed set.
 *  `authors` strings are hex author ids, case-insensitive — an Ed25519 pubkey under
 *  manifest suite `0x01`, the derived key-set id under the hybrid suite `0x02`
 *  (`hybridAuthorId`, §12.4). One 32-byte id either way, so an operator pins an
 *  identity here without knowing which suite produced it.
 *
 *  It says nothing about which class it guards: the same constructor builds the app
 *  allowlist and the mount allowlist, and a policy file that wants one author trusted
 *  for both says so twice. That is the point — trusting an author is per-class, and there
 *  is no "trusted everywhere" author. */
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

/** The two admission CLASSES as one predicate: `ctx.role` picks the branch (§12.5).
 *
 *  A combinator rather than a record the runtime holds two of, because the branch is the
 *  shell's — over the manifest's `requires`, before it asks anything of this file — and a
 *  runtime that carried both predicates could reach the wrong one, which is the single
 *  bug this whole split exists to prevent. Here there is one predicate and the class is
 *  an argument to it. Both halves are required, so widening apps can never widen the
 *  mount by omission. */
export function byRole(p: { app: Admit; mount: Admit }): Admit {
  return (v, ctx) => (ctx.role === "mount" ? p.mount : p.app)(v, ctx);
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

/** Parse a policy config file into the one predicate a shell runs under.
 *  Throws on malformed input — a typo fails the boot loudly rather than
 *  silently widening trust.
 *
 *  `authors` governs ordinary app loads; `transportAuthors` governs the mount. Either
 *  may be omitted and the omission means the strongest thing it can mean: that class
 *  admits nothing. A node with only `authors` runs apps and has no network, which is a
 *  deliberate configuration ("this node does not speak to anyone", §14) and not an
 *  error — so the two lists sit adjacent here, where an operator can see both decisions
 *  at once, while neither is anywhere a bundle author can reach. */
export function parsePolicy(json: string): Admit {
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
  let app = appAuthors ? authorAllowlist(appAuthors) : denyAll;
  let mount = transportAuthors ? authorAllowlist(transportAuthors) : denyAll;
  // `manifestSuites` is optional and, like everything else here, strict.
  // Absent ⇒ any suite the host can verify.
  if (o.manifestSuites !== undefined) {
    if (!Array.isArray(o.manifestSuites)
      || o.manifestSuites.some((x) => typeof x !== "number" || !Number.isInteger(x))) {
      throw new Error('policy: "manifestSuites" must be an array of integer suite ids');
    }
    const suites = o.manifestSuites as number[];
    if (suites.length === 0) throw new Error('policy: "manifestSuites" must list at least one suite id');
    // The suite axis applies to both classes — it is about how a bundle was signed, not
    // about what it is landing as — so it ANDs into each.
    const suiteOk = manifestSuiteAllowlist(suites);
    app = allOf(app, suiteOk);
    mount = allOf(mount, suiteOk);
  }
  return byRole({ app, mount });
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
