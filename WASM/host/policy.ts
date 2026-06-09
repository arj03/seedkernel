// The shell's install policy loader (the runtime split, "the minimal shell:
// allowed keys + an untrusted relay"). It turns a small JSON config — "which keys
// you allow" — into the installer's §7.4 `ApproveInstall` callback, narrowing the
// open reference posture (`referencePolicy(host, () => true, () => true)`, which
// accepts any audited author) down to a **closed author-key set**, an optional
// **module-hash allowlist**, and an optional **capability allowlist**. This is the
// only governance the generic runtime carries: everything else — codec,
// reputation, the storage guest — arrives as signed installs that must clear this
// gate.

import type { KernelHost } from "./kernel-host.js";
import type { ApproveInstall } from "./installer.js";
import { referencePolicy } from "./installer.js";
import { toHex } from "./util.js";

export interface ShellPolicy {
  /** Closed set of author Ed25519 public keys (hex) permitted to bind a name. */
  authors: string[];
  /** Optional allowlist of module `bytesHash`es (hex). Omitted ⇒ any module from
   *  an allowed author is accepted; present ⇒ the install's hash must be listed. */
  modules?: string[];
  /** Optional allowlist of capability ids (hex) an install may declare or escalate
   *  to. Omitted/empty ⇒ no capability may be granted (every escalation denied). */
  caps?: string[];
}

/** Parse + validate a policy config. Throws on malformed input so a typo in the
 *  allowed-keys file fails the boot loudly rather than silently widening trust. */
export function parsePolicy(json: string): ShellPolicy {
  let raw: unknown;
  try { raw = JSON.parse(json); }
  catch (e) { throw new Error(`policy: invalid JSON (${(e as Error).message})`); }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("policy: expected a JSON object");
  }
  const o = raw as Record<string, unknown>;
  const hexList = (v: unknown, field: string): string[] => {
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      throw new Error(`policy: "${field}" must be an array of hex strings`);
    }
    return (v as string[]).map((s) => s.toLowerCase());
  };
  const authors = hexList(o.authors, "authors");
  if (authors.length === 0) throw new Error('policy: "authors" must list at least one allowed author key');
  const policy: ShellPolicy = { authors };
  if (o.modules !== undefined) policy.modules = hexList(o.modules, "modules");
  if (o.caps !== undefined) policy.caps = hexList(o.caps, "caps");
  return policy;
}

/** Build the §7.4 `ApproveInstall` callback for a policy. Authors gate WHO may
 *  bind a name (+ an optional module-hash allowlist); caps gate WHAT an install
 *  may acquire — the reference policy treats every cap on a first install as an
 *  escalation, so the cap allowlist is enforced through the acknowledgement hook. */
export function buildApproveInstall(host: KernelHost, policy: ShellPolicy): ApproveInstall {
  const authors = new Set(policy.authors.map((s) => s.toLowerCase()));
  const modules = policy.modules ? new Set(policy.modules.map((s) => s.toLowerCase())) : null;
  const caps = new Set((policy.caps ?? []).map((s) => s.toLowerCase()));
  const capsAllowed = (requested: readonly Uint8Array[]): boolean =>
    requested.every((c) => caps.has(toHex(c)));

  return referencePolicy(
    host,
    (_name, author, bytesHash) => {
      if (!authors.has(toHex(author.publicKey))) return false;       // closed author set
      if (modules && !modules.has(toHex(bytesHash))) return false;   // module-hash allowlist
      return true;
    },
    (_name, _author, addedCaps) => capsAllowed(addedCaps),           // capability allowlist
  );
}
