// ws — RFC 6455 framing + opening-handshake bytes as a no-capability module.
//
// WebSocket exists only because browsers cannot speak raw TCP, so its wire codec
// is pure byte transformation — exactly the shape of a no-cap WASM handler like
// `codec` (PLAN-runtime-split.md). It imports nothing but the AS runtime: no
// kernel.call, no fs, no net. The host owns the socket and the RNG and pumps
// bytes through this module; this module only frames/deframes and computes the
// handshake accept (sha1 + base64), holding no per-connection state — the host
// keeps the residual buffer, exactly as a stateless transform should.
//
// ABI (same as codec): the host stages a request at the exported `scratch`
// offset, calls handle(input_len), and reads the response from `scratch`.
//   request  = [op u8] [args ...]
//   response = [bytes ...]   (length is handle()'s return value; 0 = error)
//
// Ops:
//   OP_ENCODE     (1) args [opcode u8][maskFlag u8][mask 4?][payload]  → frame
//   OP_DECODE_ONE (2) args [expectMasked u8][buf ...]
//        → [status u8] then, if status==1:
//          [opcode u8][consumed u32 BE][payloadLen u32 BE][payload ...]
//          status 0 = need more bytes; status 2 = protocol error
//   OP_ACCEPT     (3) args [key bytes]   → base64(sha1(key ‖ GUID)) bytes (28)
//   OP_BASE64     (4) args [bytes]       → base64(bytes)

const SCRATCH_SIZE: i32 = 4 << 20;             // 4 MB — one WS frame, generous (§27)
const MAX_FRAME_PAYLOAD: i32 = SCRATCH_SIZE - 16;
const PRIV_SIZE: i32 = 1 << 16;                // handshake scratch (sha1 + base64)

const OP_ENCODE: i32 = 1;
const OP_DECODE_ONE: i32 = 2;
const OP_ACCEPT: i32 = 3;
const OP_BASE64: i32 = 4;

const GUID: string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const B64: string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// priv layout (handshake only — small inputs)
const PRIV_MSG_OFF: i32 = 0;        // key ‖ GUID
const PRIV_DIGEST_OFF: i32 = 4096;  // 20-byte sha1
const PRIV_WORK_OFF: i32 = 8192;    // sha1 padded message + W[80]

export let scratch: i32 = 0;
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

/** SHA-1 of [msgPtr, msgPtr+msgLen) → 20 bytes at outPtr. workPtr needs
 *  pad(msgLen) + 320 bytes of scratch. */
function sha1(msgPtr: i32, msgLen: i32, outPtr: i32, workPtr: i32): void {
  const total = ((msgLen + 1 + 8 + 63) >> 6) << 6;
  memory.fill(workPtr, 0, total);
  memory.copy(workPtr, msgPtr, msgLen);
  store<u8>(workPtr + msgLen, 0x80);
  const bits = msgLen * 8; // msgLen ≪ 2^28, so the high 32 bits are zero
  store<u8>(workPtr + total - 4, ((bits >>> 24) & 255) as u8);
  store<u8>(workPtr + total - 3, ((bits >>> 16) & 255) as u8);
  store<u8>(workPtr + total - 2, ((bits >>> 8) & 255) as u8);
  store<u8>(workPtr + total - 1, (bits & 255) as u8);

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

/** Encode one RFC 6455 frame from [op][opcode][maskFlag][mask 4?][payload]. */
function opEncode(input_len: i32): i32 {
  if (input_len < 3) return 0;
  const opcode = load<u8>(scratch + 1) as i32;
  const maskFlag = (load<u8>(scratch + 2) as i32) != 0;
  const inMaskLen = maskFlag ? 4 : 0;
  if (input_len < 3 + inMaskLen) return 0;
  // Read the mask into locals before any move overwrites it.
  let m0: i32 = 0, m1: i32 = 0, m2: i32 = 0, m3: i32 = 0;
  if (maskFlag) {
    m0 = load<u8>(scratch + 3) as i32; m1 = load<u8>(scratch + 4) as i32;
    m2 = load<u8>(scratch + 5) as i32; m3 = load<u8>(scratch + 6) as i32;
  }
  const payloadIn = scratch + 3 + inMaskLen;
  const payloadLen = input_len - 3 - inMaskLen;

  let outHeaderLen = 2;
  if (payloadLen >= 65536) outHeaderLen = 10;
  else if (payloadLen >= 126) outHeaderLen = 4;
  const outMaskLen = maskFlag ? 4 : 0;
  const outPayloadPos = outHeaderLen + outMaskLen;
  const outTotal = outPayloadPos + payloadLen;
  if (outTotal > SCRATCH_SIZE) return 0;

  // Move the payload to its output position (memmove-safe), then lay the header.
  memory.copy(scratch + outPayloadPos, payloadIn, payloadLen);

  store<u8>(scratch, (0x80 | (opcode & 0x0f)) as u8); // FIN=1
  if (payloadLen < 126) {
    store<u8>(scratch + 1, payloadLen as u8);
  } else if (payloadLen < 65536) {
    store<u8>(scratch + 1, 126);
    store<u8>(scratch + 2, ((payloadLen >>> 8) & 255) as u8);
    store<u8>(scratch + 3, (payloadLen & 255) as u8);
  } else {
    store<u8>(scratch + 1, 127);
    store<u8>(scratch + 2, 0); store<u8>(scratch + 3, 0);
    store<u8>(scratch + 4, 0); store<u8>(scratch + 5, 0);
    store<u8>(scratch + 6, ((payloadLen >>> 24) & 255) as u8);
    store<u8>(scratch + 7, ((payloadLen >>> 16) & 255) as u8);
    store<u8>(scratch + 8, ((payloadLen >>> 8) & 255) as u8);
    store<u8>(scratch + 9, (payloadLen & 255) as u8);
  }
  if (maskFlag) {
    store<u8>(scratch + 1, (load<u8>(scratch + 1) | 0x80) as u8);
    store<u8>(scratch + outHeaderLen, m0 as u8);
    store<u8>(scratch + outHeaderLen + 1, m1 as u8);
    store<u8>(scratch + outHeaderLen + 2, m2 as u8);
    store<u8>(scratch + outHeaderLen + 3, m3 as u8);
    for (let i = 0; i < payloadLen; i++) {
      const mb = i & 3;
      const mask = mb == 0 ? m0 : (mb == 1 ? m1 : (mb == 2 ? m2 : m3));
      const p = scratch + outPayloadPos + i;
      store<u8>(p, ((load<u8>(p) as i32) ^ mask) as u8);
    }
  }
  return outTotal;
}

/** Parse one frame from [op][expectMasked u8][buf ...]. */
function opDecodeOne(input_len: i32): i32 {
  const expectMasked = (load<u8>(scratch + 1) as i32) != 0;
  const bufPtr = scratch + 2;
  const bufLen = input_len - 2;

  if (bufLen < 2) { store<u8>(scratch, 0); return 1; }
  const b0 = load<u8>(bufPtr) as i32;
  const b1 = load<u8>(bufPtr + 1) as i32;
  if ((b0 & 0x80) == 0) { store<u8>(scratch, 2); return 1; }       // fragmented (FIN=0)
  const opcode = b0 & 0x0f;
  const masked = (b1 & 0x80) != 0;
  if (masked != expectMasked) { store<u8>(scratch, 2); return 1; } // bad mask direction

  let payloadLen = b1 & 0x7f;
  let headerLen = 2;
  if (payloadLen == 126) {
    if (bufLen < 4) { store<u8>(scratch, 0); return 1; }
    payloadLen = ((load<u8>(bufPtr + 2) as i32) << 8) | (load<u8>(bufPtr + 3) as i32);
    headerLen = 4;
  } else if (payloadLen == 127) {
    if (bufLen < 10) { store<u8>(scratch, 0); return 1; }
    const high = ((load<u8>(bufPtr + 2) as i32) << 24) | ((load<u8>(bufPtr + 3) as i32) << 16) |
                 ((load<u8>(bufPtr + 4) as i32) << 8) | (load<u8>(bufPtr + 5) as i32);
    payloadLen = ((load<u8>(bufPtr + 6) as i32) << 24) | ((load<u8>(bufPtr + 7) as i32) << 16) |
                 ((load<u8>(bufPtr + 8) as i32) << 8) | (load<u8>(bufPtr + 9) as i32);
    if (high != 0 || payloadLen < 0 || payloadLen > MAX_FRAME_PAYLOAD) { store<u8>(scratch, 2); return 1; }
    headerLen = 10;
  }
  if (payloadLen > MAX_FRAME_PAYLOAD) { store<u8>(scratch, 2); return 1; }

  const maskLen = masked ? 4 : 0;
  const totalFrame = headerLen + maskLen + payloadLen;
  if (bufLen < totalFrame) { store<u8>(scratch, 0); return 1; }

  // Read mask into locals before moving the payload over the header region.
  let m0: i32 = 0, m1: i32 = 0, m2: i32 = 0, m3: i32 = 0;
  if (masked) {
    m0 = load<u8>(bufPtr + headerLen) as i32; m1 = load<u8>(bufPtr + headerLen + 1) as i32;
    m2 = load<u8>(bufPtr + headerLen + 2) as i32; m3 = load<u8>(bufPtr + headerLen + 3) as i32;
  }
  const payloadSrc = bufPtr + headerLen + maskLen;
  memory.copy(scratch + 10, payloadSrc, payloadLen); // memmove-safe

  store<u8>(scratch, 1);                 // status = frame
  store<u8>(scratch + 1, opcode as u8);
  storeBE(scratch + 2, totalFrame);      // consumed
  storeBE(scratch + 6, payloadLen);      // payloadLen
  if (masked) {
    for (let i = 0; i < payloadLen; i++) {
      const mb = i & 3;
      const mask = mb == 0 ? m0 : (mb == 1 ? m1 : (mb == 2 ? m2 : m3));
      const p = scratch + 10 + i;
      store<u8>(p, ((load<u8>(p) as i32) ^ mask) as u8);
    }
  }
  return 10 + payloadLen;
}

/** base64(sha1(key ‖ GUID)) — the RFC 6455 server accept value. */
function opAccept(input_len: i32): i32 {
  const keyLen = input_len - 1;
  if (keyLen < 0 || keyLen + GUID.length > 4096) return 0;
  const msg = priv + PRIV_MSG_OFF;
  memory.copy(msg, scratch + 1, keyLen);
  for (let i = 0; i < GUID.length; i++) store<u8>(msg + keyLen + i, GUID.charCodeAt(i) as u8);
  const msgLen = keyLen + GUID.length;
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
  if (op == OP_ENCODE) return opEncode(input_len);
  if (op == OP_DECODE_ONE) return opDecodeOne(input_len);
  if (op == OP_ACCEPT) return opAccept(input_len);
  if (op == OP_BASE64) return opBase64(input_len);
  return 0;
}
