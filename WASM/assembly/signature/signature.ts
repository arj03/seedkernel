// Signature module (README §6). Parses the `signature` wrapper, assembles the
// domain-separated suite request, and dispatches it to the algorithm suite for
// `algo_id` by plain `kernel.call` to the suite's slot name (§6.4, §6.6).
//
// It is a standard scratch-ABI handler (§4): the host stages the wrapper payload
// at `scratch`, calls `handle(len)`, and reads the result back from `scratch`.
// The module is STATELESS — it holds no signer stack and drives no dispatch. On a
// verified wrapper it returns the verified signer together with the inner
// envelope for the host to push and re-dispatch (§6.5); the signer stack and the
// whole push/dispatch/pop lifecycle live in the host, so "pushed ⟺ verified" is a
// host-local invariant that no allocation failure here can break.
//
// It performs no cryptography: the actual verify is the suite handler (§6.6),
// reached below via kernel.call. Authorization is the installer's job (README §7).

// ─── host imports ────────────────────────────────────────────────────────

// kernel.call (README §4.2): synchronous dispatch to the handler registered for a
// name — here the signature suite at its slot (§6.4). The suite's `[valid u8]`
// response is written into this module's `scratch`; the return value is the
// response length, or -1 on error (no handler at the slot, depth exceeded).
@external("kernel", "call")
declare function kernelCall(namePtr: i32, nameLen: i32, payloadPtr: i32, payloadLen: i32): i32;

// ─── scratch region (README §4.1) ────────────────────────────────────────

// The host stages the wrapper payload here and reads the handler's output here.
// Sized to the §2.2 envelope ceiling: the input wrapper and the returned inner
// envelope are each bounded by the 64 KB max envelope, and the host requires a
// handler to reserve at least the 128 KB default I/O region before it will drive
// it (§4.1).
const SCRATCH_SIZE: i32 = 0x20000; // 128 KB
export let scratch: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;

// Suite slot-name prefix (README §6.4). A suite is an ordinary handler at the
// LITERAL-ASCII slot `"seedkernel.suite.v1:" + algo_id_hex` (4 lowercase hex
// digits). Bootstrap/suite slot names are plain ASCII, not genesis-hash-derived
// (§5.1), so this module builds the name itself and reaches the suite with a
// plain `kernel.call` — genesis (algo_id 0x0000) included, seeded as a suite
// handler at boot.
const SUITE_SLOT_PREFIX = "seedkernel.suite.v1:";

// DOMAIN_env (README §6.3, §16.1): "seedkernel-envelope-sig-v1\0". Prepended to
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

// ─── helpers ─────────────────────────────────────────────────────────────

function readU16BE(arr: Uint8Array, offset: i32): u16 {
  return ((arr[offset] as u16) << 8) | (arr[offset + 1] as u16);
}

/** Build a suite's slot name (README §6.4): `"seedkernel.suite.v1:" + algo_id_hex`
 *  as literal ASCII, algo_id formatted as 4 lowercase hex digits. Names are opaque
 *  bytes and not genesis-hash-derived (§5.1), so the module builds this itself and
 *  reaches the suite by plain `kernel.call`. */
function suiteSlotName(algoId: u16): Uint8Array {
  const HEX = "0123456789abcdef";
  const p = SUITE_SLOT_PREFIX;
  const out = new Uint8Array(p.length + 4);
  for (let i = 0; i < p.length; i++) out[i] = p.charCodeAt(i) as u8;
  out[p.length]     = HEX.charCodeAt((algoId >> 12) & 0xf) as u8;
  out[p.length + 1] = HEX.charCodeAt((algoId >> 8) & 0xf) as u8;
  out[p.length + 2] = HEX.charCodeAt((algoId >> 4) & 0xf) as u8;
  out[p.length + 3] = HEX.charCodeAt(algoId & 0xf) as u8;
  return out;
}

// ─── signature handler (README §6.3, §6.6) ───────────────────────────────
//
// Input (staged at scratch by the host): the `signature` wrapper payload
//   [algo_id u16][signer_len u16][signer][sig_len u16][sig][inner_envelope]
//
// Output (written at scratch), return value = its length, on a VERIFIED wrapper:
//   [algo_id u16][signer_len u16][signer][inner_envelope]
// — the verified signer and the inner envelope, for the host to push onto the
// signer stack and re-dispatch (§6.5). The output drops sig_len + sig, so it is
// strictly smaller than the input and always fits the same scratch region.
//
// Returns 0 (no output) if the wrapper is malformed or the suite reports the
// signature invalid — the host then drops the message. Verification is fail-safe:
// an unknown algo_id has no handler at its slot, so kernel.call returns -1 and the
// message drops, exactly like a suite reporting "invalid".

export function handle(inputLen: i32): i32 {
  // Copy the wrapper out of scratch first: the suite's response (below) lands in
  // scratch and would otherwise clobber the bytes we are still parsing.
  const payload = new Uint8Array(inputLen);
  memory.copy(payload.dataStart, scratch, inputLen);

  // Need at least 4 bytes to read algo_id (2) + signer_len (2); the variable
  // signer / sig_len / sig / inner regions are bound-checked individually below.
  if (payload.length < 4) return 0;

  let o: i32 = 0;
  const algoId = readU16BE(payload, o); o += 2;

  // signer_len is u16 BE (§6.3) so post-quantum suites with multi-kilobyte public
  // keys fit. Always 2 bytes.
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

  // Reach the suite by plain `kernel.call` to its slot name (§6.4, §6.6). The suite
  // writes its `[valid u8]` response into our scratch. An unknown algo_id has no
  // handler at the slot, so kernel.call returns -1 → drop, the same fail-safe as a
  // suite reporting "invalid".
  const slot = suiteSlotName(algoId);
  const respLen = kernelCall(slot.dataStart as i32, slot.length, req.dataStart as i32, reqLen);
  if (respLen < 1) return 0;
  if (load<u8>(scratch) != 1) return 0;

  // Verified. Write [algo_id u16][signer_len u16][signer][inner] at scratch for the
  // host to read, push, and re-dispatch (§6.5). We read `valid` from scratch above
  // before overwriting it here; `payload` is a private heap copy, so writing the
  // output back into scratch cannot disturb the source bytes.
  let out: i32 = 0;
  store<u8>(scratch + out, ((algoId >> 8) & 0xff) as u8); out += 1;
  store<u8>(scratch + out, (algoId & 0xff) as u8); out += 1;
  store<u8>(scratch + out, ((signerLen >> 8) & 0xff) as u8); out += 1;
  store<u8>(scratch + out, (signerLen & 0xff) as u8); out += 1;
  memory.copy(scratch + out, payload.dataStart + signerOffset, signerLen); out += signerLen;
  memory.copy(scratch + out, payload.dataStart + innerOffset, innerLen); out += innerLen;
  return out;
}
