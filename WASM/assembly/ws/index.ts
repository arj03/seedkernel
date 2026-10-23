// The per-byte work of RFC 6455 as a pure module: masking, and the opening handshake's
// accept value.
//
// Byte transformation whose cost is per byte suits a WASM module with no host imports. It
// imports nothing but the AS runtime and ships as a module of the transport bundle, whose
// guest holds the socket, the RNG, the leftover receive buffer and the frame headers
// (transport/src/framing.js). No per-connection state.
//
// ABI (§4): the host writes a request at the exported `scratch` offset, calls
// handle(input_len), and reads the response from `scratch`.
//   request  = [op u8] [args ...]
//   response = [bytes ...]   (length is handle()'s return value; 0 = error)
//
// Ops:
//   OP_MASK   (1) args [frame]       -> the frame with its payload XORed under the key its
//                                       header carries: masks a client frame, or unmasks
//                                       one a server reads. The header is the caller's.
//   OP_ACCEPT (2) args [key bytes]   -> base64(sha1(key ‖ GUID)) bytes (28)
//   OP_BASE64 (3) args [bytes]       -> base64(bytes)

// The ABI ops, handshake GUID and scratch sizes are in assembly/ws/abi.ts.
import { OP_MASK, OP_ACCEPT, OP_BASE64, WS_GUID, SCRATCH_SIZE } from "./abi";

const PRIV_SIZE: i32 = 1 << 16;                // handshake scratch (sha1 + base64)

const B64: string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// priv layout (handshake only, small inputs)
const PRIV_MSG_OFF: i32 = 0;        // key ‖ GUID
const PRIV_DIGEST_OFF: i32 = 4096;  // 20-byte sha1
const PRIV_WORK_OFF: i32 = 8192;    // sha1 padded message + W[80]

export let scratch: i32 = 0;
/** How much I/O space the host may use at `scratch` (§4.1). One WS frame may be a whole
 *  MAX_FRAME_BYTES message, which the host's 128 KB default would refuse. */
export const scratchSize: i32 = SCRATCH_SIZE;
let priv: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;
priv = heap.alloc(PRIV_SIZE) as i32;

@inline
function storeBE(p: i32, v: i32): void {
  store<u8>(p, ((v >>> 24) & 255) as u8);
  store<u8>(p + 1, ((v >>> 16) & 255) as u8);
  store<u8>(p + 2, ((v >>> 8) & 255) as u8);
  store<u8>(p + 3, (v & 255) as u8);
}

@inline
function b64char(idx: i32): u8 {
  return B64.charCodeAt(idx) as u8;
}

/** XOR `len` bytes at `ptr` with the RFC 6455 masking key m0..m3, eight bytes at a time.
 *
 *  The key repeats every four octets counted from the payload's start (RFC 6455 §5.3),
 *  and the run starts there, so one little-endian word covers every group and the doubled
 *  word covers two. Every frame a browser sends is masked, so this is on the whole
 *  client-to-server data path.
 *
 *  Alignment is declared as 1 because the data is unaligned: a payload starts after a
 *  2/4/10-byte header plus the key. Wasm allows unaligned access anyway (the immediate is
 *  only a hint), so the accurate hint costs nothing. */
function maskRun(ptr: i32, len: i32, m0: i32, m1: i32, m2: i32, m3: i32): void {
  // Little-endian, so byte i of the word is the key octet for payload offset i.
  const word: u32 = (m0 as u32) | ((m1 as u32) << 8) | ((m2 as u32) << 16) | ((m3 as u32) << 24);
  const dword: u64 = (word as u64) | ((word as u64) << 32);
  let i = 0;
  const eights = len & ~7;
  for (; i < eights; i += 8) {
    store<u64>(ptr + i, load<u64>(ptr + i, 0, 1) ^ dword, 0, 1);
  }
  if (i + 4 <= len) {
    store<u32>(ptr + i, load<u32>(ptr + i, 0, 1) ^ word, 0, 1);
    i += 4;
  }
  for (; i < len; i++) {
    const mb = i & 3;
    const mask = mb == 0 ? m0 : (mb == 1 ? m1 : (mb == 2 ? m2 : m3));
    store<u8>(ptr + i, ((load<u8>(ptr + i) as i32) ^ mask) as u8);
  }
}

/** base64-encode [inPtr, inPtr+inLen) into outPtr; returns the byte length. */
function base64(inPtr: i32, inLen: i32, outPtr: i32): i32 {
  let o = 0;
  for (let i = 0; i < inLen; i += 3) {
    const b0 = load<u8>(inPtr + i) as i32;
    const has1 = i + 1 < inLen;
    const has2 = i + 2 < inLen;
    const b1 = has1 ? (load<u8>(inPtr + i + 1) as i32) : 0;
    const b2 = has2 ? (load<u8>(inPtr + i + 2) as i32) : 0;
    store<u8>(outPtr + o, b64char(b0 >> 2)); o++;
    store<u8>(outPtr + o, b64char(((b0 & 3) << 4) | (b1 >> 4))); o++;
    store<u8>(outPtr + o, has1 ? b64char(((b1 & 15) << 2) | (b2 >> 6)) : (61 as u8)); o++; // '='
    store<u8>(outPtr + o, has2 ? b64char(b2 & 63) : (61 as u8)); o++;
  }
  return o;
}

/** SHA-1 of [msgPtr, msgPtr+msgLen) to 20 bytes at outPtr. workPtr needs
 *  pad(msgLen) + 320 bytes of scratch. */
function sha1(msgPtr: i32, msgLen: i32, outPtr: i32, workPtr: i32): void {
  const total = ((msgLen + 1 + 8 + 63) >> 6) << 6;
  memory.fill(workPtr, 0, total);
  memory.copy(workPtr, msgPtr, msgLen);
  store<u8>(workPtr + msgLen, 0x80);
  const bits = msgLen * 8; // msgLen ≪ 2^28, so the high 32 bits are zero
  storeBE(workPtr + total - 4, bits);

  let h0: i32 = 0x67452301, h1: i32 = 0xefcdab89, h2: i32 = 0x98badcfe, h3: i32 = 0x10325476, h4: i32 = 0xc3d2e1f0;
  const wPtr = workPtr + total; // 80 × i32

  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) {
      const b = workPtr + off + i * 4;
      store<i32>(wPtr + i * 4,
        ((load<u8>(b) as i32) << 24) | ((load<u8>(b + 1) as i32) << 16) |
        ((load<u8>(b + 2) as i32) << 8) | (load<u8>(b + 3) as i32));
    }
    for (let i = 16; i < 80; i++) {
      const v = load<i32>(wPtr + (i - 3) * 4) ^ load<i32>(wPtr + (i - 8) * 4) ^
                load<i32>(wPtr + (i - 14) * 4) ^ load<i32>(wPtr + (i - 16) * 4);
      store<i32>(wPtr + i * 4, (v << 1) | (v >>> 31));
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f: i32, k: i32;
      if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const tmp = ((a << 5) | (a >>> 27)) + f + e + k + load<i32>(wPtr + i * 4);
      e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = tmp;
    }
    h0 = h0 + a; h1 = h1 + b; h2 = h2 + c; h3 = h3 + d; h4 = h4 + e;
  }

  storeBE(outPtr, h0); storeBE(outPtr + 4, h1); storeBE(outPtr + 8, h2);
  storeBE(outPtr + 12, h3); storeBE(outPtr + 16, h4);
}

/** Mask or unmask a whole frame's payload under the key its header carries, from
 *  [op][frame], answering the frame. The caller built or checked the header; a frame too
 *  short for the header its second byte declares is refused. */
function opMask(input_len: i32): i32 {
  const len = input_len - 1;
  if (len < 2) return 0;
  const len7 = (load<u8>(scratch + 2) as i32) & 0x7f;
  const head = (len7 == 127 ? 10 : (len7 == 126 ? 4 : 2)) + 4;
  if (len < head) return 0;
  // Drop the op byte (memmove-safe), then read the key from where it now sits.
  memory.copy(scratch, scratch + 1, len);
  const k = scratch + head - 4;
  maskRun(scratch + head, len - head,
    load<u8>(k) as i32, load<u8>(k + 1) as i32, load<u8>(k + 2) as i32, load<u8>(k + 3) as i32);
  return len;
}

/** base64(sha1(key ‖ GUID)), the RFC 6455 server accept value. */
function opAccept(input_len: i32): i32 {
  const keyLen = input_len - 1;
  if (keyLen < 0 || keyLen + WS_GUID.length > 4096) return 0;
  const msg = priv + PRIV_MSG_OFF;
  memory.copy(msg, scratch + 1, keyLen);
  for (let i = 0; i < WS_GUID.length; i++) store<u8>(msg + keyLen + i, WS_GUID.charCodeAt(i) as u8);
  const msgLen = keyLen + WS_GUID.length;
  sha1(msg, msgLen, priv + PRIV_DIGEST_OFF, priv + PRIV_WORK_OFF);
  return base64(priv + PRIV_DIGEST_OFF, 20, scratch);
}

/** base64 of the request bytes (used for a client Sec-WebSocket-Key). */
function opBase64(input_len: i32): i32 {
  const n = input_len - 1;
  if (n < 0 || n > 4096) return 0;
  memory.copy(priv + PRIV_MSG_OFF, scratch + 1, n);
  return base64(priv + PRIV_MSG_OFF, n, scratch);
}

export function handle(input_len: i32): i32 {
  if (input_len < 1) return 0;
  const op = load<u8>(scratch) as i32;
  if (op == OP_MASK) return opMask(input_len);
  if (op == OP_ACCEPT) return opAccept(input_len);
  if (op == OP_BASE64) return opBase64(input_len);
  return 0;
}
