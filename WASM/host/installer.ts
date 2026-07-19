// Module registry (README §7). A host-side helper that binds verified WASM bytes
// into the kernel's handler table under a deployer-supplied policy, and records
// each binding's (author, bytes_hash). It is "host-side" because it has to
// instantiate WebAssembly modules — a JS API that no WASM handler can reach on
// its own.
//
// This is NOT a distinct onion layer or a wire protocol. There is no `install`
// message, no signature-wrapped install envelope, and no dispatch path onto it:
// code arrives as a signed bundle (README §12.4), and the bundle loader calls
// `installDirect` to admit each verified module. "Installing a handler" is just
// `handlers[name] = wasm_bytes`, gated by the same author/hash policy that gates
// the bundle manifest — not a policy-managed special operation of its own.
//
// Owns:
//   - install records keyed by name (author, bytes_hash) — README §7.1
//   - the deployer-supplied policy callback (README §7.3)
//   - installDirect: hash → policy → instantiate → SetHandler → record
//
// Install records are read host-side via `lookup` (README §7.6) — there is no
// wire query; the policy callback already receives the resolved record.

import type { Signer } from "./kernel-host.js";
import { bytesEqual, toHex } from "./util.js";

/** The host seam the registry runs over (README §7). Deliberately narrow:
 *  instantiating WASM, hashing with the genesis suite, unbinding a name, and
 *  asking whether a slot is occupied are the only host powers a bind needs, and
 *  naming them here is what lets this module — the protocol — be compiled once and
 *  run on every target. `KernelHost` satisfies it structurally; the native loader
 *  (README §12.9) supplies the same four members backed by its Go bridge, so the
 *  admission rules below are not re-derived in a second language. */
export interface InstallerHost {
  /** Hash bytes with the genesis suite (SHA-3-256) — a module's `bytes_hash` (§7.1). */
  genesisHash(data: Uint8Array): Uint8Array;
  /** Instantiate handler bytes and bind them at `name` (§7.2 step 6). */
  _installWasmHandler(name: Uint8Array, wasm: Uint8Array): boolean;
  /** Unbind `name` (§7.5). */
  removeHandler(name: Uint8Array): boolean;
  /** True if `name` already holds a handler — used to refuse overlaying a
   *  SetHandler-seeded bootstrap slot on a first install (§7.4). */
  isRegistered(name: Uint8Array): boolean;
}

/** A single install record (README §7.1). */
export interface InstallRecord {
  readonly author: Signer;
  /** Content hash of the installed WASM module (`genesisHash(wasm)`, §7.1) — the
   *  same identifier a manifest's `modules[].hash` and a policy allowlist use. */
  readonly bytesHash: Uint8Array;
}

/** Install-approval callback (README §7.3). Receives every piece of relevant
 *  state and returns true to honor the bind or false to refuse. Deployers
 *  wire whatever policy fits their environment — an author allowlist, a
 *  content-hash allowlist, etc. With no callback wired, every bind is refused
 *  (admission is opt-in for the deployment). */
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
  host: InstallerHost,
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

/** The module registry (README §7). Holds the install records and the policy
 *  callback, and exposes `installDirect` — the single admission step the bundle
 *  loader (README §12.4) calls once it has verified a module's bytes against the
 *  signed manifest. There is no wire surface: no `install` handler, no `seq`, no
 *  replay table. The manifest signature is the one authentication, and the policy
 *  is the one authorization. */
export class Installer {
  // name → install record. README §7.1.
  private installations = new Map<string, InstallRecord>();
  private _approveInstall: ApproveInstall | null = null;

  constructor(
    private readonly host: InstallerHost,
  ) {}

  /** Wire the deployer-supplied install-approval callback (README §7.3).
   *  No callback wired = every bind is refused. */
  setApproveInstall(callback: ApproveInstall | null): void {
    this._approveInstall = callback;
  }

  /** Read-only access to the install record at `name`, if any. Host-side only —
   *  there is no wire query (README §7.6); the policy callback already receives
   *  the resolved `existing` record. */
  lookup(name: Uint8Array): InstallRecord | null {
    return this.installations.get(toHex(name)) ?? null;
  }

  /** Host-side `installer.remove(name)` (README §7.5). Clears the record and
   *  calls SetHandler(name, null). Returns true if a record was removed. */
  remove(name: Uint8Array): boolean {
    const key = toHex(name);
    const rec = this.installations.get(key);
    if (!rec) return false;
    this.installations.delete(key);
    this.host.removeHandler(name);
    return true;
  }

  /** Called by KernelHost when a name is rebound via `register` or unbound via
   *  `removeHandler`. Drops any matching install record so a stale record can't
   *  mislead lookup. Idempotent. */
  _onKernelSlotMutated(name: Uint8Array): void {
    this.installations.delete(toHex(name));
  }

  /** Hash, gate on the policy, instantiate, record — the whole admission (§7.2),
   *  and the **only** path that mutates kernel state. The bundle loader
   *  (README §12.4) calls this for each module once it has verified the bytes
   *  against the signed manifest.
   *
   *  A bundle carries no per-module signature or `seq`: the signed manifest
   *  already authenticated the coherent set and committed to each module's
   *  `genesisHash` — the loader verified the bytes against it — so a second
   *  per-module signature re-proving the same thing under the same policy would be
   *  pure redundancy. A bundle's freshness guard is the manifest's monotonic
   *  `version` (§12.4), so an equal-version reload re-binds cleanly here. Because
   *  it never crosses the kernel's envelope path, a bundled module is not bound by
   *  the §2.2 64 KB cap.
   *
   *  `author` is the manifest author. Returns true on success, false if no policy
   *  is wired or the policy refuses. */
  installDirect(name: Uint8Array, wasm: Uint8Array, author: Signer): boolean {
    if (name.length === 0 || wasm.length === 0) return false;
    const bytesHash = this.host.genesisHash(wasm);
    const existing = this.installations.get(toHex(name)) ?? null;
    if (!this._approveInstall) return false;
    let approved = false;
    try {
      approved = this._approveInstall(name, author, bytesHash, wasm, existing);
    } catch {
      approved = false;
    }
    if (!approved) return false;
    // Instantiate against the standard handler ABI (§4) and SetHandler, then
    // record — in that order, so a record never points at a slot we failed to
    // populate.
    if (!this.host._installWasmHandler(name, wasm)) return false;
    this.installations.set(toHex(name), {
      author: { algoId: author.algoId, publicKey: author.publicKey.slice() },
      bytesHash,
    });
    return true;
  }
}
