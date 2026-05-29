// Signature module (README §6). Handles Ed25519 and pluggable-suite signature
// verification, the signer stack (§6.5), and the signature wrapper handler.
//
// The signer stack lives entirely here — the host never writes to it directly.
// The host drives the push/pop lifecycle:
//   1. call handle_signature()  → returns 1 if verified, signer pushed
//   2. host dispatches inner envelope through kernel
//   3. call pop_signer()        → pops the signer
//
// Authorization is the installer's job (README §7), not this module's.

// ─── host imports ────────────────────────────────────────────────────────

@external("env", "ed25519_verify")
declare function ed25519Verify(pubPtr: i32, sigPtr: i32, dataPtr: i32, dataLen: i32): i32;

// Called by handle_signature for non-genesis algorithm suites (§6.1, §6.4).
// The host owns the suite registry: it looks up algoId, validates pub/sig
// sizes against the suite's declared metadata, and dispatches to the suite's
// verify export. Pointers are into this module's linear memory.
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

// Max nested `signature` wrappers per inbound message (README §2.3). Bounds
// the per-message verify cost so a single 64 KB envelope cannot force hundreds
// of crypto verifications on the single-threaded dispatch loop.
export const MAX_SIGNATURE_DEPTH: i32 = 4;

// ─── memory helpers ──────────────────────────────────────────────────────

function readBytes(ptr: i32, len: i32): Uint8Array {
  const out = new Uint8Array(len);
  memory.copy(out.dataStart, ptr, len);
  return out;
}

function readU16BE(arr: Uint8Array, offset: i32): u16 {
  return ((arr[offset] as u16) << 8) | (arr[offset + 1] as u16);
}

export function alloc(size: i32): i32 {
  return heap.alloc(size) as i32;
}

export function dealloc(ptr: i32): void {
  heap.free(ptr);
}

// ─── signer stack (README §6.5) ─────────────────────────────────────────

class Signer {
  algoId: u16;
  pubKey: Uint8Array;
  constructor(algoId: u16, pubKey: Uint8Array) {
    this.algoId = algoId;
    this.pubKey = pubKey;
  }
}

const signerStack: Signer[] = [];

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
// Payload: [algo_id u16][signer_len u16 BE][signer ..][sig_len u16 BE][sig ..][inner_envelope ..]
//
// Returns 1 if verified (signer pushed, inner bytes available via get_inner_ptr/len),
// 0 if the message should be dropped.
//
// For non-genesis suites the host validates pub_len / sig_len against the
// suite's declared metadata before calling suite.verify, so this module only
// has to bounds-check the wrapper structure against the payload length.
//
// Inner bytes are stored in the module-level _innerBuffer (a GC root) so the
// pointer returned by get_inner_ptr() remains valid after handle_signature returns.

let _innerBuffer: Uint8Array = new Uint8Array(0);

export function get_inner_ptr(): i32 { return _innerBuffer.dataStart as i32; }
export function get_inner_len(): i32 { return _innerBuffer.length; }

export function handle_signature(payloadPtr: i32, payloadLen: i32): i32 {
  // README §2.3: reject before doing any verify work if the stack is full.
  // Cheap, no parsing required, kills the wrapper-nesting amplification vector.
  if (signerStack.length >= MAX_SIGNATURE_DEPTH) return 0;

  const payload = readBytes(payloadPtr, payloadLen);
  // Need at least 4 bytes to read algo_id (2) + signer_len (2); the variable
  // signer / sig_len / sig / inner regions are bound-checked individually
  // below.
  if (payload.length < 4) return 0;

  let o: i32 = 0;
  const algoId = readU16BE(payload, o); o += 2;
  const isGenesis: bool = algoId == GENESIS_ALGO_ID;

  // signer_len is u16 BE (§6.3) so post-quantum suites with multi-kilobyte
  // public keys fit. Always 2 bytes.
  const signerLen = readU16BE(payload, o) as i32; o += 2;
  if (signerLen <= 0) return 0;
  if (isGenesis && signerLen != GENESIS_PUBKEY_LEN) return 0;
  if (o + signerLen > payload.length) return 0;
  const signerOffset = o;
  o += signerLen;

  if (o + 2 > payload.length) return 0;
  const sigLen = readU16BE(payload, o) as i32; o += 2;
  if (sigLen <= 0) return 0;
  if (isGenesis && sigLen != GENESIS_SIG_LEN) return 0;
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
    // Host validates suite-registered sizes; returns 0 for unknown algoId or
    // a size mismatch.
    valid = suiteVerify(
      algoId as i32,
      payload.dataStart as i32 + signerOffset, signerLen,
      payload.dataStart as i32 + sigOffset, sigLen,
      payload.dataStart as i32 + innerOffset, innerLen
    );
  }
  if (valid == 0) return 0;

  const pubKey = payload.slice(signerOffset, signerOffset + signerLen);

  // Store a copy in the module-level buffer so get_inner_ptr() stays valid
  // after this function returns (payload is a local and would otherwise be freed).
  // This MUST happen before the signer is pushed: both slices allocate and can
  // therefore abort/throw on OOM. The host's drop path (handle_signature
  // returning 0, or throwing) does NOT pop, so a signer pushed before a later
  // throw would leak onto the stack and mis-attribute the next message. Keeping
  // the push as the last fallible operation makes "pushed" ⟺ "returned 1".
  _innerBuffer = payload.slice(innerOffset);
  signerStack.push(new Signer(algoId, pubKey));

  return 1;
}
