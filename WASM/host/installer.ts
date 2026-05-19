// Installer module (README §7). A host-side module that turns signed install
// messages into kernel state changes under a deployer-supplied policy. The
// installer is "host-side" because it has to instantiate WebAssembly modules
// — a JS API that no WASM handler can reach on its own.
//
// Owns:
//   - install records keyed by name (author, bytes_hash, declared caps, parent)
//   - per-(algoId, pubkey) seq high-water counters (§4.4 replay protection)
//   - the suite-slot map (which install names route to the suite registry
//     instead of the kernel handler table — §6.4)
//   - the deployer-supplied policy callback (§7.3)
//
// Optional — deployments that don't want message-driven installation simply
// skip registerInstaller and the deployment is frozen.

import { readU32BE, type Handler, type KernelHost, type Signer } from "./kernel-host.js";

function nameKey(name: Uint8Array): string {
  let s = "";
  for (let i = 0; i < name.length; i++) s += name[i].toString(16).padStart(2, "0");
  return s;
}

const signerKeyCache = new WeakMap<Uint8Array, string>();
function signerKey(algoId: number, pubKey: Uint8Array): string {
  const cached = signerKeyCache.get(pubKey);
  if (cached !== undefined) return cached;
  let s = `${algoId}:`;
  for (let i = 0; i < pubKey.length; i++) s += pubKey[i].toString(16).padStart(2, "0");
  signerKeyCache.set(pubKey, s);
  return s;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** A single install record (README §7.1). */
export interface InstallRecord {
  readonly author: Signer;
  readonly bytesHash: Uint8Array;
  readonly declaredCaps: readonly Uint8Array[];
  /** The predecessor's bytes_hash, or null if this install claimed no parent. */
  readonly parent: Uint8Array | null;
}

/** Suite-slot configuration (README §6.4). Installs landing on `name` are
 *  routed to the suite registry under `algoId` instead of through SetHandler.
 *  The host validates pubkey/sig sizes on each verify call against this entry. */
export interface SuiteSlot {
  readonly algoId: number;
  readonly pubkeyLen: number;
  readonly sigMaxLen: number;
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
  declaredCaps: readonly Uint8Array[],
  parent: Uint8Array | null,
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
  declaredCaps: readonly Uint8Array[],
) => boolean;

/** The reference policy (README §7.4):
 *  - First install at a name → defer to `firstInstall`.
 *  - Subsequent install → author must match existing.author AND
 *    parent must equal existing.bytes_hash.
 *  - If no record exists but the kernel slot is occupied, the slot was seeded
 *    via host-side SetHandler (a bootstrap entry). Refuse.
 *
 *  Returns an ApproveInstall the deployer can hand to setApproveInstall. */
export function referencePolicy(
  host: KernelHost,
  firstInstall: FirstInstallPolicy,
): ApproveInstall {
  return (name, author, bytesHash, _wasm, declaredCaps, parent, existing) => {
    if (existing == null) {
      // Refuse to overlay a SetHandler-seeded slot.
      if (host.isRegistered(name)) return false;
      return firstInstall(name, author, bytesHash, declaredCaps);
    }
    if (existing.author.algoId !== author.algoId) return false;
    if (!bytesEqual(existing.author.publicKey, author.publicKey)) return false;
    if (parent == null) return false;
    if (!bytesEqual(existing.bytesHash, parent)) return false;
    return true;
  };
}

export class Installer {
  // name → install record. README §7.1.
  private installations = new Map<string, InstallRecord>();
  // Per-(signer) seq high-water mark for the §4.4 replay prefix. Persists
  // across removal (tombstone-forever) so re-installing after a remove cannot
  // rewind the sequence.
  //
  // LIMITATION: in-memory only — tombstone-forever holds for the lifetime of
  // this host instance, not across process / page restarts. A persistent
  // deployment must commit (installations + lastSeen + suiteSlots) atomically.
  private lastSeen = new Map<string, number>();
  // Suite-slot routing (README §6.4). Deployer-populated via registerSuiteSlot.
  private suiteSlots = new Map<string, SuiteSlot>();
  private _approveInstall: ApproveInstall | null = null;

  constructor(
    private readonly host: KernelHost,
    /** The name that signed install messages target (§7.2). */
    private readonly installName: Uint8Array,
  ) {}

  /** Wire the deployer-supplied install-approval callback (README §7.3).
   *  No callback wired = every install is dropped. */
  setApproveInstall(callback: ApproveInstall | null): void {
    this._approveInstall = callback;
  }

  /** Declare that installs landing on `name` should be instantiated under
   *  the suite ABI (§6.6) and placed in the suite registry under `algoId`,
   *  rather than going through SetHandler (§6.4). The deployer calls this
   *  before any suite install for `algoId` reaches the installer. */
  registerSuiteSlot(name: Uint8Array, slot: SuiteSlot): void {
    this.suiteSlots.set(nameKey(name), { ...slot });
  }

  /** Read-only access to the install record at `name`, if any. */
  lookup(name: Uint8Array): InstallRecord | null {
    return this.installations.get(nameKey(name)) ?? null;
  }

  /** Declared capabilities for `name`, or [] for unknown / SetHandler-seeded
   *  slots (README §8.3). */
  capsOf(name: Uint8Array): readonly Uint8Array[] {
    const rec = this.installations.get(nameKey(name));
    return rec ? rec.declaredCaps : [];
  }

  /** Host-side `installer.remove(name)` (README §7.5). For ordinary handler
   *  installs: clears the record and calls SetHandler(name, null). For suite
   *  slots: clears the record and removes the suite registry entry — the
   *  kernel handler table is not touched (the slot was never in it). Returns
   *  true if a record was removed. */
  remove(name: Uint8Array): boolean {
    const key = nameKey(name);
    const rec = this.installations.get(key);
    if (!rec) return false;
    const slot = this.suiteSlots.get(key);
    this.installations.delete(key);
    if (slot) this.host._unregisterSuite(slot.algoId);
    else this.host.removeHandler(name);
    return true;
  }

  /** Called by KernelHost when a name is rebound via setHandler / register /
   *  removeHandler. Drops any matching install record (and suite entry) so
   *  stale records can't mislead lookup / caps_of. Idempotent. */
  _onKernelSlotMutated(name: Uint8Array): void {
    const key = nameKey(name);
    const rec = this.installations.get(key);
    if (!rec) return;
    const slot = this.suiteSlots.get(key);
    this.installations.delete(key);
    if (slot) this.host._unregisterSuite(slot.algoId);
  }

  /** Handler the host registers under the install name (§7.2). */
  readonly handler: Handler = (_name, payload, _host) => {
    this._handle(payload);
    return null;
  };

  /** Handler the host registers under `installer.lookup`. Payload:
   *      [name_len u8][name ..]
   *  Response:
   *      [0]                              if not installed
   *      [1] [algo u16 BE][pk_len u16 BE][pk ..]
   *          [hash_len u8][bytes_hash ..]
   *          [parent_len u8][parent_hash ..]   (parent_len = 0 means none) */
  readonly lookupHandler: Handler = (_name, payload, _host) => {
    if (payload.length < 1) return new Uint8Array([0]);
    const nameLen = payload[0];
    if (payload.length < 1 + nameLen) return new Uint8Array([0]);
    const target = payload.slice(1, 1 + nameLen);
    const rec = this.installations.get(nameKey(target));
    if (!rec) return new Uint8Array([0]);
    const pk = rec.author.publicKey;
    const parentLen = rec.parent ? rec.parent.length : 0;
    const size = 1 + 2 + 2 + pk.length + 1 + rec.bytesHash.length + 1 + parentLen;
    const out = new Uint8Array(size);
    let o = 0;
    out[o++] = 1;
    out[o++] = (rec.author.algoId >> 8) & 0xff;
    out[o++] = rec.author.algoId & 0xff;
    out[o++] = (pk.length >> 8) & 0xff;
    out[o++] = pk.length & 0xff;
    out.set(pk, o); o += pk.length;
    out[o++] = rec.bytesHash.length;
    out.set(rec.bytesHash, o); o += rec.bytesHash.length;
    out[o++] = parentLen;
    if (rec.parent) out.set(rec.parent, o);
    return out;
  };

  /** Handler the host registers under `installer.caps_of` (§7.6). Payload:
   *      [name_len u8][name ..]
   *  Response:
   *      [count u8] [cap_id_len u8][cap_id ..]* */
  readonly capsOfHandler: Handler = (_name, payload, _host) => {
    if (payload.length < 1) return new Uint8Array([0]);
    const nameLen = payload[0];
    if (payload.length < 1 + nameLen) return new Uint8Array([0]);
    const target = payload.slice(1, 1 + nameLen);
    const caps = this.capsOf(target);
    let size = 1;
    for (const c of caps) size += 1 + c.length;
    const out = new Uint8Array(size);
    let o = 0;
    out[o++] = caps.length;
    for (const c of caps) {
      out[o++] = c.length;
      out.set(c, o); o += c.length;
    }
    return out;
  };

  /** Returns true if `seq` is fresh for this signer (strictly greater than
   *  the last seq accepted from them) and updates the high-water mark. */
  private _consumeSeq(signer: Signer, seq: number): boolean {
    const k = signerKey(signer.algoId, signer.publicKey);
    const last = this.lastSeen.get(k);
    if (last !== undefined && seq <= last) return false;
    this.lastSeen.set(k, seq);
    return true;
  }

  private _handle(payload: Uint8Array): void {
    // 1. Identify the author (drop unsigned installs).
    const author = this.host.currentTopSigner;
    if (!author) return;

    // 2. Parse the payload (§7.2).
    if (payload.length < 4) return;
    let o = 0;
    const seq = readU32BE(payload, o); o += 4;
    if (o + 1 > payload.length) return;
    const nameLen = payload[o]; o += 1;
    if (nameLen === 0) return;
    if (o + nameLen > payload.length) return;
    const name = payload.slice(o, o + nameLen); o += nameLen;

    if (o + 1 > payload.length) return;
    const capsCount = payload[o]; o += 1;
    const declaredCaps: Uint8Array[] = [];
    for (let i = 0; i < capsCount; i++) {
      if (o + 1 > payload.length) return;
      const capIdLen = payload[o]; o += 1;
      if (o + capIdLen > payload.length) return;
      declaredCaps.push(payload.slice(o, o + capIdLen));
      o += capIdLen;
    }

    if (o + 1 > payload.length) return;
    const parentLen = payload[o]; o += 1;
    if (o + parentLen > payload.length) return;
    const parent: Uint8Array | null = parentLen > 0
      ? payload.slice(o, o + parentLen)
      : null;
    o += parentLen;

    const wasmBytes = payload.slice(o);
    if (wasmBytes.length === 0) return;

    // 3. bytes_hash covers the entire install payload (§7.1).
    const bytesHash = this.host.genesisHash(payload);

    // 4. Consume seq (§4.4 replay protection). Runs before the policy call
    //    so a single replay can't keep re-running an expensive policy.
    if (!this._consumeSeq(author, seq)) return;

    // 5. Fetch existing record (if any) for the policy callback.
    const existing = this.installations.get(nameKey(name)) ?? null;

    // 6. Policy decides. No callback wired = drop.
    if (!this._approveInstall) return;
    let approved = false;
    try {
      approved = this._approveInstall(
        name, author, bytesHash, wasmBytes,
        declaredCaps, parent, existing,
      );
    } catch {
      approved = false;
    }
    if (!approved) return;

    // 7. Suite-slot vs handler-slot routing.
    const slot = this.suiteSlots.get(nameKey(name));
    if (slot) {
      const ok = this.host._registerSuite(
        slot.algoId, slot.pubkeyLen, slot.sigMaxLen, wasmBytes,
      );
      if (!ok) return;
    } else {
      const ok = this.host._installWasmHandler(name, wasmBytes);
      if (!ok) return;
    }

    // 8. Record. Stored after the kernel state change so a record never
    //    points at a slot we failed to populate.
    this.installations.set(nameKey(name), {
      author: { algoId: author.algoId, publicKey: author.publicKey.slice() },
      bytesHash,
      declaredCaps: declaredCaps.map((c) => c.slice()),
      parent: parent ? parent.slice() : null,
    });
  }
}
