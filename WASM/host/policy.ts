// The shell's install policy loader (the runtime split, "the minimal shell:
// allowed keys + an untrusted relay"). It turns a small JSON config — "which keys
// you allow" — into the installer's §7.4 `ApproveInstall` callback, narrowing the
// open reference posture (`referencePolicy(host, () => true)`, which accepts any
// audited author) down to a **closed author-key set** plus an optional
// **module-hash allowlist**. This is the only governance the generic runtime
// carries: everything else — codec, reputation, the storage guest — arrives as
// signed installs that must clear this gate.

import type { KernelHost } from "./kernel-host.js";
import type { ApproveInstall } from "./installer.js";
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

/** Build the §7.4 `ApproveInstall` callback for a policy: a closed author set
 *  gates WHO may bind a name, and an optional module-hash allowlist pins WHICH
 *  binaries (`genesisHash(wasm)`) may land. */
export function buildApproveInstall(host: KernelHost, policy: ShellPolicy): ApproveInstall {
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
