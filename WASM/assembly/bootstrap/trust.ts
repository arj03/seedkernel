// Trust module (README §7). Owns the flat whitelist keyed by
// (algo_id, pubkey, schema_id) and the trust.grant handler (§7.2).
// Also owns handle_signature_register (§6.4) because that handler requires
// a trust check, which needs direct access to the trust table.
//
// Uses the signer stack from signature.ts to identify the granter and to
// check is_trusted_by_current_signers.

import {
  Signer, signerStack,
  readBytes, readU16BE, readU32BE,
  registerSuiteMeta, unregisterSuiteMeta, hasSuiteMeta,
} from "./signature";

// ─── host imports ────────────────────────────────────────────────────────

@external("env", "on_trust_revoked")
declare function onTrustRevoked(algoId: i32, pubPtr: i32, pubLen: i32, schemaPtr: i32, schemaLen: i32): void;

// Instantiates a suite WASM module and stores it in the host's suite registry.
// Returns 1 on success, 0 on failure. Pointers are into this module's memory.
@external("env", "suite_register")
declare function hostSuiteRegister(
  algoId: i32,
  pubkeyLen: i32, sigMaxLen: i32, hashLen: i32,
  wasmPtr: i32, wasmLen: i32
): i32;

// ─── trust table ─────────────────────────────────────────────────────────
//
// Flat whitelist keyed by (algo_id, pubkey, schema_id).
// Each entry records who granted it (for cascading revocation).
// Mirrors TrustModule in C#.

class TrustEntry {
  algoId: u16;
  pubKey: Uint8Array;
  schemaId: Uint8Array;
  granterAlgoId: i32; // -1 = root seed (no granter)
  granterPubKey: Uint8Array | null;

  constructor(
    algoId: u16,
    pubKey: Uint8Array,
    schemaId: Uint8Array,
    granterAlgoId: i32,
    granterPubKey: Uint8Array | null
  ) {
    this.algoId = algoId;
    this.pubKey = pubKey;
    this.schemaId = schemaId;
    this.granterAlgoId = granterAlgoId;
    this.granterPubKey = granterPubKey;
  }
}

const trustTable: TrustEntry[] = [];

// ─── per-mutating-handler replay protection (README §4.4) ────────────────
//
// Every mutating handler in the §4.4 blocklist consumes a u32 sequence
// number from the start of its payload and rejects seq <= last_seen for the
// top signer. Storage is one entry per (algoId, pubKey) per handler; entries
// persist across revocation (tombstone-forever) so re-granting trust to a
// key cannot rewind its sequence and unlock replay of older messages.
//
// LIMITATION: these tables are in-memory only. Tombstone-forever holds
// for the lifetime of this kernel instance — not across process / page
// restarts. The README §4.4 wording is stronger than what this code
// delivers in isolation.
//
// A deployment that wants persistent trust MUST commit the following
// state ATOMICALLY (all-or-nothing across a crash). Persisting any
// proper subset re-opens replay or correctness holes that are otherwise
// closed:
//
//   1. trustTable                  — who is trusted, and the granter
//                                    chain needed for §7.2 cascading
//                                    revocation.
//   2. trustGrantSeqs              — per-signer seq high-water mark for
//                                    handle_trust_grant. Without this,
//                                    any pre-restart-recorded trust.grant
//                                    envelope replays against an empty
//                                    table after reload.
//   3. sigRegisterSeqs             — same, for handle_signature_register.
//                                    Replay here re-installs a recorded
//                                    suite WASM under the signer's old
//                                    authority.
//   4. storedTrustGrantId,         — schema_ids these handlers gate on.
//      storedSigRegisterId           Both fail-closed if zero-length, so
//                                    persisting (1)–(3) without (4)
//                                    locks the deployment out rather
//                                    than leaking authority — but it
//                                    still leaves the trust table
//                                    holding subjects no one can
//                                    administer.
//   5. InstallHandler.lastSeen     — per-signer seq high-water mark for
//                                    the §3.2 install handler. Lives in
//                                    host JS (host/install-handler.ts)
//                                    but shares (2)/(3)'s replay hazard:
//                                    a recorded install envelope replays
//                                    against the empty post-restart map
//                                    and re-installs a (possibly long
//                                    revoked) WASM handler.
//   6. InstallHandler.installerAttribution
//                                  — target_schema_id → (algoId, pubKey)
//                                    of the installer. Required for the
//                                    §7.3 revocation cascade to find
//                                    which kernel slots to remove when
//                                    an installer's key is revoked.
//                                    Losing this strands installed
//                                    handlers in the kernel after their
//                                    installer's trust is gone.
//   7. KernelHost.suiteRegistry    — registered suite WASM bytes (host
//      WASM bytes                    JS). Without these, algoIds in (1)
//                                    become meaningless after restart;
//                                    signed envelopes from those signers
//                                    fail to verify at all because there
//                                    is no suite to dispatch to. The
//                                    size meta inside the bootstrap-side
//                                    suite registry is necessary but
//                                    not sufficient — the host needs the
//                                    instantiable bytes too.

class SeqEntry {
  algoId: u16;
  pubKey: Uint8Array;
  lastSeq: u32;
  constructor(algoId: u16, pubKey: Uint8Array, lastSeq: u32) {
    this.algoId = algoId;
    this.pubKey = pubKey;
    this.lastSeq = lastSeq;
  }
}

function findSeq(table: SeqEntry[], algoId: u16, pubKey: Uint8Array): i32 {
  for (let i = 0; i < table.length; i++) {
    const e = table[i];
    if (e.algoId == algoId && bytesEqual(e.pubKey, pubKey)) return i;
  }
  return -1;
}

/** Returns true if `seq` is fresh (strictly greater than the last seq seen
 *  from this signer for this handler) and updates the table. Returns false
 *  on replay (seq <= last_seen) — the caller drops the message without
 *  applying any state change. The bump happens unconditionally on any fresh
 *  seq so that a sender cannot retry by re-signing with the same seq. */
function consumeSeq(table: SeqEntry[], algoId: u16, pubKey: Uint8Array, seq: u32): bool {
  const idx = findSeq(table, algoId, pubKey);
  if (idx < 0) {
    table.push(new SeqEntry(algoId, pubKey, seq));
    return true;
  }
  if (seq <= table[idx].lastSeq) return false;
  table[idx].lastSeq = seq;
  return true;
}

const trustGrantSeqs: SeqEntry[] = [];
const sigRegisterSeqs: SeqEntry[] = [];

function bytesEqual(a: Uint8Array, b: Uint8Array): bool {
  if (a.length != b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

function findTrust(algoId: u16, pubKey: Uint8Array, schemaId: Uint8Array): i32 {
  for (let i = 0; i < trustTable.length; i++) {
    const e = trustTable[i];
    if (e.algoId == algoId && bytesEqual(e.pubKey, pubKey) && bytesEqual(e.schemaId, schemaId))
      return i;
  }
  return -1;
}

/** Walk the granter chain from a target trust entry. Returns true if the
 *  signer (algoId, pubKey) appears anywhere in the chain — including as the
 *  immediate granter. Stops at root entries (granterAlgoId < 0) and at broken
 *  chains (a granter who is not themselves trusted for trust.grant).
 *
 *  Used by handle_trust_grant to enforce §7.2: a key trusted for trust.grant
 *  can revoke only entries whose chain of granters leads back to itself.
 *
 *  Path length is bounded by trustTable.length; chains cannot be cyclic
 *  because trustGrant() rejects duplicate (algoId, pubKey, schemaId) triples,
 *  so each subject has at most one trust.grant entry. */
function isInGranterChain(
  signerAlgoId: u16,
  signerPubKey: Uint8Array,
  targetIdx: i32
): bool {
  if (storedTrustGrantId.length == 0) return false;

  let curAlgo: i32 = trustTable[targetIdx].granterAlgoId;
  let curPub: Uint8Array | null = trustTable[targetIdx].granterPubKey;

  for (let depth = 0; depth <= trustTable.length; depth++) {
    if (curAlgo < 0 || curPub == null) return false; // root seed or broken
    if (curAlgo == (signerAlgoId as i32) && bytesEqual(curPub, signerPubKey)) return true;
    // Walk up: a granter's authority comes from their own trust.grant entry.
    const upIdx = findTrust(curAlgo as u16, curPub, storedTrustGrantId);
    if (upIdx < 0) return false; // granter no longer trusted for trust.grant
    curAlgo = trustTable[upIdx].granterAlgoId;
    curPub = trustTable[upIdx].granterPubKey;
  }
  return false;
}

function trustGrant(
  algoId: u16,
  pubKey: Uint8Array,
  schemaId: Uint8Array,
  granterAlgoId: i32,
  granterPubKey: Uint8Array | null
): bool {
  if (findTrust(algoId, pubKey, schemaId) >= 0) return false;
  trustTable.push(new TrustEntry(algoId, pubKey, schemaId, granterAlgoId, granterPubKey));
  return true;
}

function trustRevoke(algoId: u16, pubKey: Uint8Array, schemaId: Uint8Array): void {
  // BFS cascading revocation.
  // NOTE: cascades across ALL schemas granted by the revoked key, not just
  // the schema being revoked (§7.3). This is intentional: revoking a key
  // invalidates the entire subtree it created, regardless of schema.
  const qAlgo: u16[] = [algoId];
  const qPub: Uint8Array[] = [pubKey];
  const qSchema: Uint8Array[] = [schemaId];
  let qHead: i32 = 0;

  while (qHead < qAlgo.length) {
    const vAlgo = qAlgo[qHead];
    const vPub = qPub[qHead];
    const vSchema = qSchema[qHead];
    qHead++;

    const idx = findTrust(vAlgo, vPub, vSchema);
    if (idx < 0) continue;

    trustTable.splice(idx, 1);

    // Enqueue all keys granted by (vAlgo, vPub), across all schemas.
    for (let i = trustTable.length - 1; i >= 0; i--) {
      const e = trustTable[i];
      if (
        e.granterAlgoId == (vAlgo as i32) &&
        e.granterPubKey != null &&
        bytesEqual(e.granterPubKey!, vPub)
      ) {
        qAlgo.push(e.algoId);
        qPub.push(e.pubKey);
        qSchema.push(e.schemaId);
      }
    }

    onTrustRevoked(
      vAlgo as i32,
      vPub.dataStart as i32,
      vPub.length,
      vSchema.dataStart as i32,
      vSchema.length
    );
  }
}

// ─── exported trust API ──────────────────────────────────────────────────

export function trust_grant(
  algoId: i32,
  pubPtr: i32, pubLen: i32,
  schemaPtr: i32, schemaLen: i32,
  granterAlgoId: i32,
  granterPubPtr: i32, granterPubLen: i32
): i32 {
  // algoId is wire-level u16; reject anything outside that range so
  // values like 0x10001 don't silently truncate to 1 via `as u16`.
  if (algoId < 0 || algoId > 0xffff) return 0;
  if (granterAlgoId > 0xffff) return 0;
  const pubKey = readBytes(pubPtr, pubLen);
  const schemaId = readBytes(schemaPtr, schemaLen);
  let gPub: Uint8Array | null = null;
  if (granterAlgoId >= 0 && granterPubLen > 0) {
    gPub = readBytes(granterPubPtr, granterPubLen);
  }
  return trustGrant(algoId as u16, pubKey, schemaId, granterAlgoId, gPub) ? 1 : 0;
}

export function trust_revoke(
  algoId: i32,
  pubPtr: i32, pubLen: i32,
  schemaPtr: i32, schemaLen: i32
): void {
  if (algoId < 0 || algoId > 0xffff) return;
  const pubKey = readBytes(pubPtr, pubLen);
  const schemaId = readBytes(schemaPtr, schemaLen);
  trustRevoke(algoId as u16, pubKey, schemaId);
}

export function is_trusted(
  algoId: i32,
  pubPtr: i32, pubLen: i32,
  schemaPtr: i32, schemaLen: i32
): i32 {
  if (algoId < 0 || algoId > 0xffff) return 0;
  const pubKey = readBytes(pubPtr, pubLen);
  const schemaId = readBytes(schemaPtr, schemaLen);
  return findTrust(algoId as u16, pubKey, schemaId) >= 0 ? 1 : 0;
}

/** Check whether the top (innermost / direct) signer is trusted for schemaId.
 *  Top-only to match handle_trust_grant and handle_signature_register: in a
 *  hybrid signature stack, the inner signer is the one whose intent is being
 *  registered; outer wrappers add attestation but do not transfer authority. */
export function is_trusted_by_current_signers(schemaPtr: i32, schemaLen: i32): i32 {
  if (signerStack.length == 0) return 0;
  const schemaId = readBytes(schemaPtr, schemaLen);
  const top = signerStack[signerStack.length - 1];
  return findTrust(top.algoId, top.pubKey, schemaId) >= 0 ? 1 : 0;
}

// ─── trust.grant handler (README §7.2) ──────────────────────────────────
//
// Payload: [seq u32 BE][action u8 (0=grant,1=revoke)][algo_id u16][pubkey_len u16][pubkey ..][schema_id_len u8][schema_id ..]
//
// Mirrors TrustModule.CreateGrantHandler in C#: checks trust internally so
// only signers trusted for the trust.grant schema can mutate the table.

// Stored trust.grant schema_id — set once during bootstrap via set_trust_grant_id.
let storedTrustGrantId: Uint8Array = new Uint8Array(0);

export function set_trust_grant_id(ptr: i32, len: i32): void {
  storedTrustGrantId = readBytes(ptr, len);
}

export function handle_trust_grant(payloadPtr: i32, payloadLen: i32): void {
  const payload = readBytes(payloadPtr, payloadLen);
  // 4 (seq) + 1 (action) + 2 (algo) + 2 (pubkey_len) = 9 minimum before var bytes.
  if (payload.length < 9) return;

  // Must have a verified signer (message arrived through signature wrapper)
  if (signerStack.length == 0) return;
  const granter = signerStack[signerStack.length - 1];

  // Fail-closed if the trust.grant schema_id has not been seeded by the host
  // (set_trust_grant_id never called). Without this the trust check below
  // would degrade to allow-all (M-1).
  if (storedTrustGrantId.length == 0) return;
  // Only signers trusted for the trust.grant schema may mutate the table
  if (findTrust(granter.algoId, granter.pubKey, storedTrustGrantId) < 0) return;

  let o: i32 = 0;
  // Replay protection (§4.4): consume seq before any state change.
  const seq = readU32BE(payload, o); o += 4;
  if (!consumeSeq(trustGrantSeqs, granter.algoId, granter.pubKey, seq)) return;

  const action = payload[o]; o += 1;
  // Only 0=grant and 1=revoke are defined (README §7.2). Reject other values
  // so future action codes don't get silently coerced into "revoke".
  if (action > 1) return;
  const revoke = action != 0;

  const targetAlgoId = readU16BE(payload, o); o += 2;

  // pubkey_len is u16 BE (§7.2 widening) so PQ keys fit.
  if (o + 2 > payload.length) return;
  const pkLen = readU16BE(payload, o) as i32; o += 2;
  if (pkLen <= 0) return;
  if (o + pkLen > payload.length) return;
  const targetPub = payload.slice(o, o + pkLen); o += pkLen;

  if (o + 1 > payload.length) return;
  const sidLen = payload[o] as i32; o += 1;
  if (sidLen <= 0) return;
  if (o + sidLen > payload.length) return;
  const targetSchema = payload.slice(o, o + sidLen);

  if (revoke) {
    // §7.2: a key trusted for trust.grant can revoke only entries whose
    // chain of granters leads back to itself. Without this check, any one
    // trust.grant-trusted key can revoke another's grants and trigger the
    // cascade — an authority leak between admins (H-1).
    const targetIdx = findTrust(targetAlgoId, targetPub, targetSchema);
    if (targetIdx < 0) return; // no such entry — drop quietly
    if (!isInGranterChain(granter.algoId, granter.pubKey, targetIdx)) return;
    trustRevoke(targetAlgoId, targetPub, targetSchema);
  } else {
    trustGrant(targetAlgoId, targetPub, targetSchema, granter.algoId as i32, granter.pubKey);
  }
}

// ─── signature.register handler (README §6.4) ────────────────────────────
//
// Payload: [seq u32 BE][algo_id u16][hash_len u8][pubkey_len u16][sig_max_len u16][name_len u8][name ..][wasm ..]
//
// Lives here (rather than signature.ts) because it needs access to the trust
// table to check the signer's authority before installing a new algorithm suite.
// A malicious suite could accept any signature, so this is the most privileged
// operation in the system.
//
// The seq prefix is the §4.4 replay-protection obligation. signature.register
// also has the per-algoId duplicate-rejection rule below as defense-in-depth,
// but the seq check is unconditional — uniform rule across all mutating
// handlers, no carve-outs for handlers with alternative protection.

// Stored signature.register schema_id — set once during bootstrap.
let storedSigRegisterId: Uint8Array = new Uint8Array(0);

export function set_sig_register_id(ptr: i32, len: i32): void {
  storedSigRegisterId = readBytes(ptr, len);
}

export function handle_signature_register(payloadPtr: i32, payloadLen: i32): void {
  // Must have a verified signer
  if (signerStack.length == 0) return;
  const granter = signerStack[signerStack.length - 1];

  // Fail-closed if the signature.register schema_id has not been seeded by
  // the host (set_sig_register_id never called). Without this guard the
  // trust check below would degrade to allow-all (M-1).
  if (storedSigRegisterId.length == 0) return;
  // Only the top (innermost) signer authorizes — mirrors handle_trust_grant.
  // Installing a signature suite is the highest-privilege operation in the
  // system: a malicious suite can accept any signature. We therefore require
  // the immediate signer (not just *any* signer in a hybrid stack) to hold
  // the signature.register grant.
  if (findTrust(granter.algoId, granter.pubKey, storedSigRegisterId) < 0) return;

  // Minimum header: seq(4) + algo_id(2) + hash_len(1) + pubkey_len(2) + sig_max_len(2) + name_len(1) = 12 bytes
  const payload = readBytes(payloadPtr, payloadLen);
  if (payload.length < 12) return;

  let o: i32 = 0;
  // Replay protection (§4.4): consume seq before any state change.
  const seq = readU32BE(payload, o); o += 4;
  if (!consumeSeq(sigRegisterSeqs, granter.algoId, granter.pubKey, seq)) return;

  const algoId = readU16BE(payload, o); o += 2;
  if (algoId == 0x0000) return; // genesis suite cannot be replaced
  // Reject duplicate registration. Without this the host would overwrite its
  // suite WASM while this module's size metadata stayed pointing at the old
  // suite — handle_signature would then validate inputs with stale sizes
  // before passing them to a module that expects different ones.
  if (hasSuiteMeta(algoId as i32)) return;

  const hashLen  = payload[o] as i32;          o += 1;
  const pubkeyLen = readU16BE(payload, o) as i32; o += 2;
  const sigMaxLen = readU16BE(payload, o) as i32; o += 2;
  // Reject zero-sized metadata (S3): a malicious or buggy installer could
  // otherwise register a suite where handle_signature would accept an empty
  // signer / signature and forward the call to suite.verify with zero-length
  // inputs. Genuine suites always have positive sizes.
  if (hashLen <= 0) return;
  if (pubkeyLen <= 0) return;
  if (sigMaxLen <= 0) return;
  const nameLen  = payload[o] as i32;          o += 1;
  if (o + nameLen > payload.length) return;
  o += nameLen; // skip human-readable name

  const wasmLen = payload.length - o;
  if (wasmLen <= 0) return;

  // register meta FIRST, then call into the host. If host instantiation
  // fails we roll back the meta entry — this keeps the two registries in
  // lockstep even if the host's WebAssembly.Module / Instance creation
  // throws (which the host wraps in try/catch and surfaces as result == 0).
  if (registerSuiteMeta(algoId as i32, pubkeyLen, sigMaxLen) == 0) return;

  const result = hostSuiteRegister(
    algoId as i32, pubkeyLen, sigMaxLen, hashLen,
    payload.dataStart as i32 + o, wasmLen
  );
  if (result == 0) {
    // Host failed to instantiate the suite WASM. Roll back the meta entry
    // so a later register with a corrected binary can succeed instead of
    // being permanently locked out by the duplicate-rejection rule.
    unregisterSuiteMeta(algoId as i32);
    return;
  }
}
