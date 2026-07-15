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

// Verify a signature under the suite for `algoId` (README §6.4, §6.6). A suite
// is an ordinary handler installed at the slot `hash(SUITE_SLOT_PREFIX +
// algo_id_hex)`; the host derives that slot name and dispatches the verify
// request this module builds at [reqPtr, reqLen) to the handler there — genesis
// (algo_id 0x0000) included, seeded as a host-serviced suite handler at boot.
// A suite verifies, nothing else, so the request carries no op selector (§6.6):
//   [pubkey_len u16][pubkey][sig_len u16][sig][data ..]
// where `data` is the full signed preimage DOMAIN_env ‖ algo_id ‖ signer_len ‖
// signer ‖ inner_envelope (§6.3). The signer is length-prefixed so the preimage is
// self-delimiting — a variable-length-key suite cannot re-split (signer, inner) to
// forge a collision. Returns 1 iff the suite reports the signature valid; an unknown
// algo_id (no handler at the slot) returns 0.
@external("env", "suite_verify")
declare function suiteVerify(algoId: i32, reqPtr: i32, reqLen: i32): i32;

// ─── constants ───────────────────────────────────────────────────────────

// Max nested `signature` wrappers per inbound message (README §2.3). Bounds
// the per-message verify cost so a single 64 KB envelope cannot force hundreds
// of crypto verifications on the single-threaded dispatch loop.
export const MAX_SIGNATURE_DEPTH: i32 = 4;

// DOMAIN_env (README §6.3, §17.1): "seedkernel-envelope-sig-v1\0". Prepended to
// the signed preimage before verifying, never transmitted, so an envelope
// signature cannot double as any other protocol's signature over the same bytes.
const DOMAIN_ENV: Uint8Array = domainEnv();
function domainEnv(): Uint8Array {
  const s = "seedkernel-envelope-sig-v1";
  const out = new Uint8Array(s.length + 1);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) as u8;
  out[s.length] = 0; // trailing NUL
  return out;
}

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
// The suite handler validates pub_len / sig_len for its algorithm, so this
// module only bounds-checks the wrapper structure against the payload length
// and hands the suite a well-formed request. Genesis is not special-cased — it
// is just the suite at algo_id 0x0000 (README §6.4).
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

  // signer_len is u16 BE (§6.3) so post-quantum suites with multi-kilobyte
  // public keys fit. Always 2 bytes.
  const signerLen = readU16BE(payload, o) as i32; o += 2;
  if (signerLen <= 0) return 0;
  if (o + signerLen > payload.length) return 0;
  const signerOffset = o;
  o += signerLen;

  if (o + 2 > payload.length) return 0;
  const sigLen = readU16BE(payload, o) as i32; o += 2;
  if (sigLen <= 0) return 0;
  if (o + sigLen > payload.length) return 0;
  const sigOffset = o;
  o += sigLen;

  const innerOffset = o;
  const innerLen = payload.length - o;
  if (innerLen <= 0) return 0;

  // Build the suite verify request (§6.6):
  //   [signer_len u16][signer][sig_len u16][sig][data]
  // where data is the signed preimage DOMAIN_env ‖ algo_id ‖ signer_len ‖ signer ‖
  // inner (§6.3). Assembling data here — prepending the domain and the outer fields to
  // the inner envelope — is what gives every suite domain separation and outer-field
  // binding for free; the suite just verifies sig over data. The signer is length-
  // prefixed inside `data` too, so the (signer, inner) boundary is unambiguous and a
  // future variable-length-key suite cannot splice a different split onto the same bytes.
  const dataLen = DOMAIN_ENV.length + 2 + 2 + signerLen + innerLen;
  const reqLen = 2 + signerLen + 2 + sigLen + dataLen;
  const req = new Uint8Array(reqLen);
  let w: i32 = 0;
  req[w++] = ((signerLen >> 8) & 0xff) as u8;
  req[w++] = (signerLen & 0xff) as u8;
  req.set(payload.subarray(signerOffset, signerOffset + signerLen), w); w += signerLen;
  req[w++] = ((sigLen >> 8) & 0xff) as u8;
  req[w++] = (sigLen & 0xff) as u8;
  req.set(payload.subarray(sigOffset, sigOffset + sigLen), w); w += sigLen;
  // data: DOMAIN_env ‖ algo_id ‖ signer_len ‖ signer ‖ inner
  req.set(DOMAIN_ENV, w); w += DOMAIN_ENV.length;
  req[w++] = ((algoId >> 8) & 0xff) as u8;
  req[w++] = (algoId & 0xff) as u8;
  req[w++] = ((signerLen >> 8) & 0xff) as u8;
  req[w++] = (signerLen & 0xff) as u8;
  req.set(payload.subarray(signerOffset, signerOffset + signerLen), w); w += signerLen;
  req.set(payload.subarray(innerOffset, innerOffset + innerLen), w); w += innerLen;

  // Unknown algo_id → no handler at the slot → host returns 0 (drop).
  const valid = suiteVerify(algoId as i32, req.dataStart as i32, reqLen);
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
