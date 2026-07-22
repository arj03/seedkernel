// The shell's admission policy (README §12.5): a closed set of author keys permitted
// to sign a bundle manifest (§12.4). It needs no name rule and no per-module gate:
// kernel names derive from the author's key (§5.1), so squat-resistance is structural,
// and the signed manifest's `modules[].hash` is the definitive declaration of which
// bytes are authorized. Trusting an author means trusting everything they sign.
//
// This is the only governance the generic runtime carries: everything else — codec,
// reputation, the storage guest — arrives in a signed bundle whose manifest author
// must clear this gate (§12.4).

export interface ShellPolicy {
  /** Closed set of author Ed25519 public keys (hex) permitted to sign a bundle
   *  manifest and bind names (§12.4–§12.5). */
  authors: string[];
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
  if (!Array.isArray(o.authors) || o.authors.some((x) => typeof x !== "string")) {
    throw new Error('policy: "authors" must be an array of hex strings');
  }
  const authors = (o.authors as string[]).map((s) => s.toLowerCase());
  if (authors.length === 0) throw new Error('policy: "authors" must list at least one allowed author key');
  return { authors };
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
