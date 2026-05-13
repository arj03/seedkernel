// Chat backend v1 — text-only.
//
// Wire format:  payload = [type u8][body ..]   type = 0x00 (text)
// Render:       [type u8][pk_len u8][pk ..][body ..]
//
// All scratch staging, signer lookup, and host-bridge wiring is in
// ../seedkernel/handler.ts. This file owns the scratch + priv buffers
// (so the host's `scratch` Global export points into the app's memory)
// and writes the v1 protocol's `handle()`.

import {
  init, isConfigured, loadTopSignerPubkey, forwardToHost,
  PRIV_USER_OFF, PK_LEN,
} from "../seedkernel/handler";

export { configure } from "../seedkernel/handler";

const SCRATCH_SIZE: i32 = 0x20000; // 128 KB
const PRIVATE_SIZE: i32 = 0x20000; // 128 KB

// Reserved bytes immediately before the staged input body, sized to hold
// the v1 render header [type u8][pk_len u8][pk PK_LEN] = 34 bytes. Rounding
// up to 64 leaves room for a future header field without touching memory math.
const RENDER_HEADER_MAX: i32 = 64;
const STAGING_OFF: i32 = PRIV_USER_OFF;

export let scratch: i32 = 0;
let priv: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;
priv = heap.alloc(PRIVATE_SIZE) as i32;
init(scratch, priv);

export function handle(input_len: i32): i32 {
  if (!isConfigured() || input_len < 1) return 0;
  const type = load<u8>(scratch);
  if (type != 0) return 0;                  // v1 only knows text

  // Stage the input where kernel.call won't clobber it. The render header
  // is written into the reserved bytes immediately before the body so the
  // body is never copied twice.
  const stagedInput = priv + STAGING_OFF + RENDER_HEADER_MAX;
  const tailRoom = PRIVATE_SIZE - STAGING_OFF - RENDER_HEADER_MAX;
  if (input_len + 64 > tailRoom) return 0;
  memory.copy(stagedInput, scratch, input_len);
  const stagedBody = stagedInput + 1;
  const bodyLen = input_len - 1;

  const pkSrc = loadTopSignerPubkey();       // clobbers scratch
  if (pkSrc < 0) return 0;
  const stagedPk = stagedInput + input_len + 16;
  memory.copy(stagedPk, pkSrc, PK_LEN);

  // [type u8][pk_len u8][pk PK_LEN] — written backward into reserved bytes.
  const headerLen = 1 + 1 + PK_LEN;
  const renderBuf = stagedBody - headerLen;
  let o = renderBuf;
  store<u8>(o, type); o++;
  store<u8>(o, PK_LEN); o++;
  memory.copy(o, stagedPk, PK_LEN); o += PK_LEN;

  forwardToHost(renderBuf, headerLen + bodyLen);
  return 0;
}
