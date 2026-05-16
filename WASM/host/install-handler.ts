// Install handler (README §3.2). A host-side handler that turns signed install
// messages into SetHandler calls. Optional: deployments that don't want
// message-driven installation simply omit it. The install handler is "host-side"
// because it has to instantiate WebAssembly modules — a JS API that no WASM
// module can reach on its own.
//
// Pipeline:
//   1. Read the top signer (drop unsigned installs).
//   2. Trust check: top signer must be trusted for this install schema.
//      Runs *before* the seq consumption so untrusted signers cannot grow
//      the per-signer high-water-mark table indefinitely (§4.4 cheap-drop
//      guidance).
//   3. Consume the §4.4 sequence number and update the per-signer high-water
//      mark; replays drop here, before any further state change.
//   4. Parse declared caps and target_schema_id from the payload.
//   5. Replacement policy:
//        - if our attribution table has a row, the new installer must match;
//        - if there's no row but the kernel slot is occupied, the slot was
//          seeded via SetHandler (a bootstrap entry) and we refuse.
//   6. approveInstall callback decides — no callback wired = drop.
//   7. Ask the host to instantiate the WASM module and SetHandler the result.
//   8. Record installer attribution + declared caps for revocation cascades
//      and capability.of_handler queries.

import { readU32BE, type ApproveInstall, type Handler, type KernelHost, type Signer } from "./kernel-host.js";

function schemaKey(schemaId: Uint8Array): string {
  let s = "";
  for (let i = 0; i < schemaId.length; i++) s += schemaId[i].toString(16).padStart(2, "0");
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

export class InstallHandler {
  // (algoId, pubKey) per target_schema_id of every install we performed.
  // Keyed by schemaKey(targetSchemaId). README §3.2 calls this the install
  // handler's "own table"; it lives here, not in the kernel.
  private installerAttribution = new Map<string, { algoId: number; pubKey: Uint8Array }>();
  // Per-(signer) high-water mark for the §4.4 seq prefix on install payloads.
  // Persists across revocation (tombstone-forever) so re-granting trust to a
  // key cannot rewind its sequence and unlock replay of older install messages.
  //
  // LIMITATION: in-memory only — tombstone-forever holds for the lifetime
  // of this host instance, not across process / page restarts. This map is
  // item (5) in the persistence inventory in assembly/bootstrap/trust.ts;
  // see that note for the full set of state that must commit atomically and
  // the replay holes that open if any subset is persisted alone. The
  // installerAttribution map below is item (6) on the same list.
  private lastSeen = new Map<string, number>();
  private _approveInstall: ApproveInstall | null = null;

  constructor(
    private readonly host: KernelHost,
    private readonly installSchemaId: Uint8Array,
  ) {}

  /** Wire the deployer-supplied install-approval callback (README §3.2 step 4).
   *  No callback wired = every install is dropped after the trust check. */
  setApproveInstall(callback: ApproveInstall | null): void {
    this._approveInstall = callback;
  }

  /** The Handler that the host registers under the install schema_id. The
   *  kernel pipeline routes a signed envelope to this callback the same way
   *  it routes any other handler. */
  readonly handler: Handler = (_schemaId, payload, _host) => {
    this._handle(payload);
    return null;
  };

  /** README §3.2 RevokeInstallsBy. Removes the kernel entry for `schemaId`
   *  iff the installing signer matches `(algoId, pubKey)` exactly. Wired
   *  into the trust module's OnRevoked cascade by the host. */
  revokeInstallsBy(algoId: number, pubKey: Uint8Array, schemaId: Uint8Array): boolean {
    const key = schemaKey(schemaId);
    const attrib = this.installerAttribution.get(key);
    if (!attrib) return false;
    if (attrib.algoId !== algoId) return false;
    if (attrib.pubKey.length !== pubKey.length) return false;
    for (let i = 0; i < attrib.pubKey.length; i++) {
      if (attrib.pubKey[i] !== pubKey[i]) return false;
    }
    // Removing the kernel entry also drops its cap-index row via
    // KernelHost._dropHostMaps. The attribution row is ours to clear.
    this.host.removeHandler(schemaId);
    this.installerAttribution.delete(key);
    return true;
  }

  /** Returns true if `seq` is fresh for this signer (strictly greater than
   *  the last seq accepted from them) and updates the high-water mark. Returns
   *  false on replay — caller drops the message without applying any state
   *  change. The bump happens unconditionally on any fresh seq so a sender
   *  cannot retry by re-signing with the same seq. */
  private _consumeSeq(signer: Signer, seq: number): boolean {
    const k = signerKey(signer.algoId, signer.publicKey);
    const last = this.lastSeen.get(k);
    if (last !== undefined && seq <= last) return false;
    this.lastSeen.set(k, seq);
    return true;
  }

  private _handle(payload: Uint8Array): void {
    // ── identify the signer (drop unsigned installs) ─────────────────
    const installer: Signer | null = this.host.currentTopSigner;
    if (!installer) return;

    // ── trust check on the install schema (README §3.2 step 2) ───────
    // Runs *before* seq consumption so untrusted signers cannot pollute
    // the per-signer high-water-mark table (§4.4 cheap-drop guidance —
    // each entry is permanent under the tombstone-forever rule, so an
    // attacker generating fresh keypairs would otherwise grow lastSeen
    // without bound). [H-2]
    if (!this.host.isTrustedByCurrentSigners(this.installSchemaId)) return;

    // ── consume seq (§4.4 replay protection) ─────────────────────────
    // Runs after the trust check but still before any state mutation.
    // A malformed payload (too short to even contain a seq) is dropped
    // without consuming.
    if (payload.length < 4) return;
    const seq = readU32BE(payload, 0);
    if (!this._consumeSeq(installer, seq)) return;
    let offset = 4;

    // ── parse capability header ──────────────────────────────────────
    if (offset >= payload.length) return;
    const capsCount = payload[offset]; offset++;
    const declaredCaps: Uint8Array[] = [];
    for (let i = 0; i < capsCount; i++) {
      if (offset >= payload.length) return; // malformed
      const capIdLen = payload[offset]; offset++;
      if (offset + capIdLen > payload.length) return; // malformed
      declaredCaps.push(payload.slice(offset, offset + capIdLen));
      offset += capIdLen;
    }

    // ── parse target schema_id ───────────────────────────────────────
    if (offset + 1 > payload.length) return;
    const targetLen = payload[offset]; offset++;
    if (targetLen === 0) return;
    if (offset + targetLen > payload.length) return;
    const targetSchemaId = payload.slice(offset, offset + targetLen);
    offset += targetLen;

    const wasmBytes = payload.slice(offset);
    if (wasmBytes.length === 0) return;

    // ── replacement policy (README §3.2) ─────────────────────────────
    const targetKey = schemaKey(targetSchemaId);
    const prior = this.installerAttribution.get(targetKey);
    if (prior) {
      if (prior.algoId !== installer.algoId) return;
      if (prior.pubKey.length !== installer.publicKey.length) return;
      for (let i = 0; i < prior.pubKey.length; i++) {
        if (prior.pubKey[i] !== installer.publicKey[i]) return;
      }
    } else if (this.host.isRegistered(targetSchemaId)) {
      // Slot occupied with no attribution row → seeded via SetHandler. Refuse.
      return;
    }

    // ── approveInstall callback ──────────────────────────────────────
    if (!this._approveInstall) return;
    // Hash before the callback so the operator can compare against an
    // audited-binary allowlist without having to re-hash the bytes.
    const wasmHash = this.host.genesisHash(wasmBytes);
    let approved = false;
    try {
      approved = this._approveInstall(targetSchemaId, declaredCaps, installer, wasmHash);
    } catch {
      approved = false;
    }
    if (!approved) return;

    // ── ask the host to instantiate + setHandler the WASM module ─────
    const ok = this.host.installWasmHandler(targetSchemaId, declaredCaps, wasmBytes);
    if (!ok) return;

    // ── record attribution for revocation cascades ───────────────────
    this.installerAttribution.set(targetKey, {
      algoId: installer.algoId,
      pubKey: installer.publicKey.slice(),
    });
  }
}
