// Installer module (README §7). A host-side module that turns signed install
// messages into kernel state changes under a deployer-supplied policy. The
// installer is "host-side" because it has to instantiate WebAssembly modules
// — a JS API that no WASM handler can reach on its own.
//
// Owns:
//   - install records keyed by name (author, bytes_hash)
//   - canonical-pubkey-keyed seq high-water counters, kept in a table SEPARATE
//     from the install records so removal can't rewind them (§4.4, §7.1)
//   - the deployer-supplied policy callback (§7.3)
//
// A signature suite is an ordinary handler installed at its slot name (§6.4);
// the installer has no special case for it — it flows through the same
// SetHandler path as any other install.
//
// The installer is a pure sink: its only wire-facing handler is the (blocked)
// `install` mutator. Install records are read host-side via `lookup` — there is
// no `installer.lookup` / `installer.caps_of` query message. Bridges authorize
// their callers by pinning `kernel.caller` (README §8), not by consulting a
// capability index.
//
// Optional — deployments that don't want message-driven installation simply
// skip registerInstaller and the deployment is frozen.

import { nameKey, type Handler, type KernelHost, type Signer } from "./kernel-host.js";
import { readU32BE, toHex } from "./util.js";

// Replay identity is the canonical public key ONLY — never (algo_id, pubkey).
// A public key is one identity, so its seq high-water mark must be a single
// monotonic namespace: the same key reused across suites (§6.4 rotation) shares
// one counter rather than getting a fresh `last_seen == 0` per algo_id that
// would accept a replay once per suite. algo_id is folded into the signed
// preimage now (§6.3), so it is authenticated and cannot be flipped on a
// captured message anyway — but this keying is prior to that: replay state is a
// property of the key, not the suite (§4.4). The signature layer rejects
// non-canonical / small-order keys before they reach here, so equal key bytes
// mean the same identity.
function signerKey(pubKey: Uint8Array): string {
  return toHex(pubKey);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** A single install record (README §7.1). */
export interface InstallRecord {
  readonly author: Signer;
  /** Content hash of the installed WASM module (`genesisHash(wasm)`, §7.1) — the
   *  same identifier a manifest's `modules[].hash` and a policy allowlist use. */
  readonly bytesHash: Uint8Array;
}

/** Install-approval callback (README §7.3). Receives every piece of relevant
 *  state and returns true to honor the install or false to drop. Deployers
 *  wire whatever policy fits their environment — operator console, M-of-N
 *  quorum, content-hash allowlist, etc. With no callback wired, every install
 *  is dropped (installation is opt-in for the deployment). */
export type ApproveInstall = (
  name: Uint8Array,
  author: Signer,
  bytesHash: Uint8Array,
  wasm: Uint8Array,
  existing: InstallRecord | null,
) => boolean;

/** The first-install branch of the reference policy (README §7.4). Called
 *  when no install record exists for the target name. Deployers wire this to
 *  whatever rule they want for "who may claim a new name." Common values:
 *  an author allowlist, a naming-convention check, or `return true` for an
 *  open registry. */
export type FirstInstallPolicy = (
  name: Uint8Array,
  author: Signer,
  bytesHash: Uint8Array,
) => boolean;

/** The reference policy (README §7.4). Two rules for WHO may bind a name:
 *   1. First install at a name → defer to `firstInstall`. (If no record exists
 *      but the kernel slot is occupied, the slot was SetHandler-seeded — a
 *      bootstrap entry — so refuse.)
 *   2. Subsequent install → author must match existing.author.
 *
 *  Returns an ApproveInstall the deployer can hand to setApproveInstall. */
export function referencePolicy(
  host: KernelHost,
  firstInstall: FirstInstallPolicy,
): ApproveInstall {
  return (name, author, bytesHash, _wasm, existing) => {
    if (existing == null) {
      // Refuse to overlay a SetHandler-seeded slot.
      if (host.isRegistered(name)) return false;
      return firstInstall(name, author, bytesHash);
    }
    if (existing.author.algoId !== author.algoId) return false;
    return bytesEqual(existing.author.publicKey, author.publicKey);
  };
}

export class Installer {
  // name → install record. README §7.1.
  private installations = new Map<string, InstallRecord>();
  // Canonical-pubkey-keyed seq high-water mark for the §4.4 replay prefix.
  // Kept DELIBERATELY SEPARATE from `installations` (README §7.1): remove()
  // clears the record but must NOT touch this map, so the high-water mark is
  // tombstone-forever and re-installing after a remove cannot rewind the
  // sequence. (It also has to live apart structurally — the `install` handler
  // is SetHandler-seeded and has no install record to hang a counter on.)
  //
  // LIMITATION: in-memory only — tombstone-forever holds for the lifetime of
  // this host instance, not across process / page restarts. A persistent
  // deployment must commit (installations + lastSeen) atomically.
  private lastSeen = new Map<string, number>();
  private _approveInstall: ApproveInstall | null = null;

  constructor(
    private readonly host: KernelHost,
  ) {}

  /** Wire the deployer-supplied install-approval callback (README §7.3).
   *  No callback wired = every install is dropped. */
  setApproveInstall(callback: ApproveInstall | null): void {
    this._approveInstall = callback;
  }

  /** Read-only access to the install record at `name`, if any. Host-side only —
   *  there is no wire query (README §7.6); the policy callback already receives
   *  the resolved `existing` record, and bridges pin `kernel.caller`. */
  lookup(name: Uint8Array): InstallRecord | null {
    return this.installations.get(nameKey(name)) ?? null;
  }

  /** Host-side `installer.remove(name)` (README §7.5). Clears the record and
   *  calls SetHandler(name, null). Suite slots (§6.4) are ordinary handler
   *  installs and take exactly this path. Does NOT touch `lastSeen`: the replay
   *  high-water marks are tombstone-forever (§4.4). Returns true if a record
   *  was removed. */
  remove(name: Uint8Array): boolean {
    const key = nameKey(name);
    const rec = this.installations.get(key);
    if (!rec) return false;
    this.installations.delete(key);
    this.host.removeHandler(name);
    return true;
  }

  /** Called by KernelHost when a name is rebound via setHandler / register /
   *  removeHandler. Drops any matching install record so a stale record can't
   *  mislead lookup. Idempotent. */
  _onKernelSlotMutated(name: Uint8Array): void {
    this.installations.delete(nameKey(name));
  }

  /** Install a bundle module directly (README §12.4), synthesizing its install
   *  record instead of consuming a signed install envelope. The bundle's signed
   *  manifest already authenticated the coherent set and committed to each
   *  module's `genesisHash` — the loader verified the bytes against it — so the
   *  per-module `.install` envelope, a second signature re-proving the same thing
   *  under the same policy, was redundant; this replaces it. The **same policy
   *  still runs** (author set, module-hash allowlist, first-install/same-author),
   *  but there is deliberately **no `seq`**: a bundle's freshness guard is the
   *  manifest's monotonic `version` (§12.4), so an equal-version reload re-installs
   *  cleanly here rather than being dropped as a replay of an already-consumed seq.
   *  Because it does not go through the kernel's envelope path, a bundled module is
   *  not bound by the §2.2 64 KB cap. `author` is the manifest author. Wire installs
   *  (§7.2) are unchanged. Returns true on success, false if no policy is wired or
   *  the policy refuses. */
  installDirect(name: Uint8Array, wasm: Uint8Array, author: Signer): boolean {
    if (name.length === 0 || wasm.length === 0) return false;
    const bytesHash = this.host.genesisHash(wasm);
    const existing = this.installations.get(nameKey(name)) ?? null;
    if (!this._approveInstall) return false;
    let approved = false;
    try {
      approved = this._approveInstall(name, author, bytesHash, wasm, existing);
    } catch {
      approved = false;
    }
    if (!approved) return false;
    if (!this.host._installWasmHandler(name, wasm)) return false;
    this.installations.set(nameKey(name), {
      author: { algoId: author.algoId, publicKey: author.publicKey.slice() },
      bytesHash,
    });
    return true;
  }

  /** Handler the host registers under the install name (§7.2). */
  readonly handler: Handler = (_name, payload, _host) => {
    this._handle(payload);
    return null;
  };

  /** Returns true if `seq` is fresh for this signer (strictly greater than
   *  the last seq accepted from them) and updates the high-water mark. */
  private _consumeSeq(signer: Signer, seq: number): boolean {
    const k = signerKey(signer.publicKey);
    const last = this.lastSeen.get(k);
    if (last !== undefined && seq <= last) return false;
    this.lastSeen.set(k, seq);
    return true;
  }

  private _handle(payload: Uint8Array): void {
    // 1. Identify the author (drop unsigned installs).
    const author = this.host.currentTopSigner;
    if (!author) return;

    // 2. Parse the payload (§7.2): [seq u32][name_len u8][name][wasm].
    if (payload.length < 4) return;
    let o = 0;
    const seq = readU32BE(payload, o); o += 4;
    if (o + 1 > payload.length) return;
    const nameLen = payload[o]; o += 1;
    if (nameLen === 0) return;
    if (o + nameLen > payload.length) return;
    const name = payload.slice(o, o + nameLen); o += nameLen;

    const wasmBytes = payload.slice(o);
    if (wasmBytes.length === 0) return;

    // 3. bytes_hash is the content id of the WASM module (§7.1): genesisHash(wasm),
    //    the same identifier a manifest's modules[].hash and a policy allowlist use.
    const bytesHash = this.host.genesisHash(wasmBytes);

    // 4. Consume seq (§4.4 replay protection). Runs before the policy call
    //    so a single replay can't keep re-running an expensive policy.
    if (!this._consumeSeq(author, seq)) return;

    // 5. Fetch existing record (if any) for the policy callback.
    const existing = this.installations.get(nameKey(name)) ?? null;

    // 6. Policy decides. No callback wired = drop.
    if (!this._approveInstall) return;
    let approved = false;
    try {
      approved = this._approveInstall(name, author, bytesHash, wasmBytes, existing);
    } catch {
      approved = false;
    }
    if (!approved) return;

    // 7. Instantiate against the standard handler ABI (§4) and SetHandler.
    //    A suite install (§6.4) is an ordinary handler at its slot name — no
    //    special-casing; it takes this same path.
    if (!this.host._installWasmHandler(name, wasmBytes)) return;

    // 8. Record. Stored after the kernel state change so a record never
    //    points at a slot we failed to populate.
    this.installations.set(nameKey(name), {
      author: { algoId: author.algoId, publicKey: author.publicKey.slice() },
      bytesHash,
    });
  }
}
