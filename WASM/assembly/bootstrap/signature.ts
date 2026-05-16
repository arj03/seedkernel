// Signature module (README §6). Handles Ed25519 and pluggable-suite signature
// verification, the signer stack (§6.5), and outbound wrap().
//
// The signer stack lives entirely here — the host never writes to it directly.
// The host drives the push/pop lifecycle:
//   1. call handle_signature()  → returns 1 if verified, signer pushed
//   2. host dispatches inner envelope through kernel
//   3. call pop_signer()        → pops the signer
//
// Exports used by trust.ts (not WASM exports):
//   Signer, signerStack, readBytes, readU16BE, registerSuiteMeta, unregisterSuiteMeta

// ─── host imports ────────────────────────────────────────────────────────

@external("env", "ed25519_verify")
declare function ed25519Verify(pubPtr: i32, sigPtr: i32, dataPtr: i32, dataLen: i32): i32;

// Called by handle_signature for non-genesis algorithm suites (§6.1).
// Pointers are into this module's linear memory.
@external("env", "suite_verify")
declare function suiteVerify(
  algoId: i32,
  pubPtr: i32, pubLen: i32,
  sigPtr: i32, sigLen: i32,
  dataPtr: i32, dataLen: i32
): i32;

// ─── constants ───────────────────────────────────────────────────────────

export const GENESIS_ALGO_ID: u16 = 0x0000;
export const GENESIS_PUBKEY_LEN: i32 = 32;
export const GENESIS_SIG_LEN: i32 = 64;

// Max number of nested signature wrappers per inbound message. Each layer
// costs one verify; without a cap a 64 KB envelope (~140 B per wrapper for
// Ed25519 with SHA-3 schema_ids) can force ~475 verifies (~45 ms CPU).
// 4 supports hybrid+rotation use cases without amplification.
export const MAX_SIGNATURE_DEPTH: i32 = 4;

// ─── memory helpers (imported by trust.ts) ───────────────────────────────

export function readBytes(ptr: i32, len: i32): Uint8Array {
  const out = new Uint8Array(len);
  memory.copy(out.dataStart, ptr, len);
  return out;
}

export function readU16BE(arr: Uint8Array, offset: i32): u16 {
  return ((arr[offset] as u16) << 8) | (arr[offset + 1] as u16);
}

export function readU32BE(arr: Uint8Array, offset: i32): u32 {
  return ((arr[offset] as u32) << 24) |
         ((arr[offset + 1] as u32) << 16) |
         ((arr[offset + 2] as u32) << 8) |
          (arr[offset + 3] as u32);
}

export function alloc(size: i32): i32 {
  return heap.alloc(size) as i32;
}

export function dealloc(ptr: i32): void {
  heap.free(ptr);
}

// ─── pluggable suite registry (README §6.1) ──────────────────────────────
//
// The genesis suite (0x0000) is always available via the ed25519_verify host
// import. Additional suites are registered at runtime via handle_signature_register
// (in trust.ts) which calls registerSuiteMeta here and registers the suite WASM
// via the suite_register host import.

class SuiteMeta {
  algoId: u16;
  pubkeyLen: i32;
  sigMaxLen: i32;
  constructor(algoId: u16, pubkeyLen: i32, sigMaxLen: i32) {
    this.algoId = algoId;
    this.pubkeyLen = pubkeyLen;
    this.sigMaxLen = sigMaxLen;
  }
}

const suiteRegistry: SuiteMeta[] = [];

function findSuiteMetaIndex(algoId: u16): i32 {
  for (let i = 0; i < suiteRegistry.length; i++) {
    if (suiteRegistry[i].algoId == algoId) return i;
  }
  return -1;
}

function findSuiteMeta(algoId: u16): SuiteMeta | null {
  const idx = findSuiteMetaIndex(algoId);
  return idx >= 0 ? suiteRegistry[idx] : null;
}

/** Called by trust.ts after a successful signature.register message to record
 *  size metadata for the new suite. Must not be called for algo 0x0000.
 *  Returns 1 on success, 0 if the algoId was already registered. Duplicate
 *  registration is rejected because the host's suite WASM and this metadata
 *  would otherwise drift — the new WASM would be validated against old sizes. */
export function registerSuiteMeta(algoId: i32, pubkeyLen: i32, sigMaxLen: i32): i32 {
  if (findSuiteMeta(algoId as u16) != null) return 0;
  suiteRegistry.push(new SuiteMeta(algoId as u16, pubkeyLen, sigMaxLen));
  return 1;
}

/** Remove a previously-registered suite's metadata. Used as a rollback when
 *  hostSuiteRegister fails *after* registerSuiteMeta succeeded — without this
 *  the bootstrap-side registry would be left with a meta entry pointing at a
 *  suite the host never instantiated, and a subsequent register attempt for
 *  that algoId would be permanently locked out by the duplicate-rejection
 *  rule. Genesis (0x0000) cannot be removed — it lives outside the registry
 *  and is always available via the host's ed25519_verify import (README §6.2). */
export function unregisterSuiteMeta(algoId: i32): i32 {
  if ((algoId as u16) == GENESIS_ALGO_ID) return 0;
  const idx = findSuiteMetaIndex(algoId as u16);
  if (idx < 0) return 0;
  suiteRegistry.splice(idx, 1);
  return 1;
}

/** True if the given algoId is already in the suite metadata registry. */
export function hasSuiteMeta(algoId: i32): bool {
  return findSuiteMeta(algoId as u16) != null;
}

// ─── signer stack (README §6.5) ─────────────────────────────────────────
//
// Mirrors SignatureModule._signerStack in C#. Exported so trust.ts can read
// the top signer for grant authorization.

export class Signer {
  algoId: u16;
  pubKey: Uint8Array;
  constructor(algoId: u16, pubKey: Uint8Array) {
    this.algoId = algoId;
    this.pubKey = pubKey;
  }
}

export const signerStack: Signer[] = [];

export function get_signer_count(): i32 {
  return signerStack.length;
}

/** Pubkey length of signer at index, or -1 if out of range. Lets the caller
 *  size its buffer before calling read_signer for variable-length suites. */
export function signer_pubkey_len(index: i32): i32 {
  if (index < 0 || index >= signerStack.length) return -1;
  return signerStack[index].pubKey.length;
}

/** Read signer at index into caller-supplied buffers.
 *  Writes algo_id as a u16 big-endian at outAlgoPtr (2 bytes), writes pubkey
 *  into outPubPtr. Returns the pubkey length written, or -1 if the index is
 *  out of range OR outPubMaxLen is smaller than the signer's pubkey.
 *  Refuses to truncate — call signer_pubkey_len(index) first when the suite
 *  may use larger-than-Ed25519 keys. */
export function read_signer(index: i32, outAlgoPtr: i32, outPubPtr: i32, outPubMaxLen: i32): i32 {
  if (index < 0 || index >= signerStack.length) return -1;
  const s = signerStack[index];
  if (s.pubKey.length > outPubMaxLen) return -1;
  store<u8>(outAlgoPtr, (s.algoId >> 8) as u8);
  store<u8>(outAlgoPtr + 1, (s.algoId & 0xff) as u8);
  memory.copy(outPubPtr, s.pubKey.dataStart, s.pubKey.length);
  return s.pubKey.length;
}

/** Pop the top signer. Called by the host after the inner dispatch returns (§6.5). */
export function pop_signer(): void {
  if (signerStack.length > 0) signerStack.pop();
}

// ─── signature handler (README §6.3, §6.5) ──────────────────────────────
//
// Payload: [algo_id u16][signer_len u8][signer ..][sig_len u16][sig ..][inner_envelope ..]
//
// Returns 1 if verified (signer pushed, inner bytes available via get_inner_ptr/len),
// 0 if the message should be dropped.
//
// Inner bytes are stored in the module-level _innerBuffer (a GC root) so the
// pointer returned by get_inner_ptr() remains valid after handle_signature returns.

let _innerBuffer: Uint8Array = new Uint8Array(0);

export function get_inner_ptr(): i32 { return _innerBuffer.dataStart as i32; }
export function get_inner_len(): i32 { return _innerBuffer.length; }

export function handle_signature(payloadPtr: i32, payloadLen: i32): i32 {
  // Reject before parsing — nesting count is the signer stack length, since
  // every accepted wrapper pushes exactly one signer for the duration of the
  // inner dispatch.
  if (signerStack.length >= MAX_SIGNATURE_DEPTH) return 0;
  const payload = readBytes(payloadPtr, payloadLen);
  // 2 (algo) + 2 (signer_len) + 2 (sig_len) = 6 minimum before any var bytes.
  if (payload.length < 6) return 0;

  let o: i32 = 0;
  const algoId = readU16BE(payload, o); o += 2;

  // Determine expected key/sig sizes for this algorithm.
  let expectedPubkeyLen: i32;
  let expectedSigLen: i32;
  let isGenesis: bool = false;

  if (algoId == GENESIS_ALGO_ID) {
    expectedPubkeyLen = GENESIS_PUBKEY_LEN;
    expectedSigLen = GENESIS_SIG_LEN;
    isGenesis = true;
  } else {
    const meta = findSuiteMeta(algoId);
    if (meta == null) return 0; // unknown algorithm suite
    expectedPubkeyLen = meta.pubkeyLen;
    expectedSigLen = meta.sigMaxLen;
  }

  // signer_len is u16 BE (§6.3) so post-quantum suites with multi-kilobyte
  // public keys fit. Always 2 bytes.
  const signerLen = readU16BE(payload, o) as i32; o += 2;
  if (signerLen != expectedPubkeyLen) return 0;
  if (o + signerLen > payload.length) return 0;
  const signerOffset = o;
  o += signerLen;

  if (o + 2 > payload.length) return 0;
  const sigLen = readU16BE(payload, o) as i32; o += 2;
  if (isGenesis) {
    if (sigLen != expectedSigLen) return 0; // Ed25519 sigs are always exactly 64 bytes
  } else {
    if (sigLen > expectedSigLen) return 0; // other suites may use variable-length sigs up to max
  }
  if (o + sigLen > payload.length) return 0;
  const sigOffset = o;
  o += sigLen;

  const innerOffset = o;
  const innerLen = payload.length - o;
  if (innerLen <= 0) return 0;

  let valid: i32;
  if (isGenesis) {
    valid = ed25519Verify(
      payload.dataStart as i32 + signerOffset,
      payload.dataStart as i32 + sigOffset,
      payload.dataStart as i32 + innerOffset,
      innerLen
    );
  } else {
    valid = suiteVerify(
      algoId as i32,
      payload.dataStart as i32 + signerOffset, signerLen,
      payload.dataStart as i32 + sigOffset, sigLen,
      payload.dataStart as i32 + innerOffset, innerLen
    );
  }
  if (valid == 0) return 0;

  const pubKey = payload.slice(signerOffset, signerOffset + signerLen);
  signerStack.push(new Signer(algoId, pubKey));

  // Store a copy in the module-level buffer so get_inner_ptr() stays valid
  // after this function returns (payload is a local and would otherwise be freed).
  _innerBuffer = payload.slice(innerOffset);

  return 1;
}
