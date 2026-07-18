// The shell's install policy loader (the runtime split, "the minimal shell:
// allowed keys + an untrusted relay"). It turns a small JSON config — "which keys
// you allow" — into the registry's §7.4 `ApproveInstall` callback, narrowing the
// open reference posture (`referencePolicy(host, () => true)`, which accepts any
// audited author) down to a **closed author-key set** plus an optional
// **module-hash allowlist**. This is the only governance the generic runtime
// carries: everything else — codec, reputation, the storage guest — arrives in a
// signed bundle whose manifest author must clear this gate (§12.4).

import type { ApproveInstall, InstallerHost } from "./installer.js";
import { referencePolicy } from "./installer.js";
import { toHex } from "./util.js";

export interface ShellPolicy {
  /** Closed set of author Ed25519 public keys (hex) permitted to bind a name. */
  authors: string[];
  /** Optional allowlist of module `bytesHash`es (hex — `genesisHash(wasm)`, the
   *  same id a manifest's `modules[].hash` uses). Omitted ⇒ any module from an
   *  allowed author is accepted; present ⇒ the install's hash must be listed. */
  modules?: string[];
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
  return policy;
}

/** The policy a shell runs under given its (optional) config file. A *provided*
 *  config is parsed strictly by `parsePolicy` — a typo fails the boot loudly rather
 *  than silently widening trust — and an **omitted** one is deny-all: an empty author
 *  set, so the node boots and serves but every install is refused (README §14).
 *
 *  The default lives here, in the shared core, precisely because it is a security
 *  posture: every target (the Node shell, the native loader) resolves "no policy
 *  configured" through this one function, so a target cannot drift into a permissive
 *  default of its own. */
export function policyFromJson(json: string | null | undefined): ShellPolicy {
  return json ? parsePolicy(json) : { authors: [] };
}

/** Build the §7.4 `ApproveInstall` callback for a policy: a closed author set
 *  gates WHO may bind a name, and an optional module-hash allowlist pins WHICH
 *  binaries (`genesisHash(wasm)`) may land. An empty author set (the omitted-policy
 *  default) admits nothing — every first install fails the `authors` check below. */
export function buildApproveInstall(host: InstallerHost, policy: ShellPolicy): ApproveInstall {
  const authors = new Set(policy.authors.map((s) => s.toLowerCase()));
  const modules = policy.modules ? new Set(policy.modules.map((s) => s.toLowerCase())) : null;

  return referencePolicy(
    host,
    (_name, author, bytesHash) => {
      if (!authors.has(toHex(author.publicKey))) return false;       // closed author set
      if (modules && !modules.has(toHex(bytesHash))) return false;   // module-hash allowlist
      return true;
    },
  );
}
