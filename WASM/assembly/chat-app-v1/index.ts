// Chat backend v1 — text-only.
//
// A pure-transform handler (README §4): the shell stages the input at `scratch`,
// calls `handle`, and reads the render bytes back from `scratch`. No kernel.call,
// no signer query, no UI bridge — the sender identity is prepended by the shell
// (the AKE channel already authenticated it), and the render bytes are the return
// value the shell forwards to the iframe.
//
// Input:   [pk PK_LEN][type u8][body ..]   type = 0x00 (text)
// Render:  [type u8][pk_len u8][pk ..][body ..]

import { PRIV_USER_OFF, PK_LEN } from "../seedkernel/handler";

const SCRATCH_SIZE: i32 = 0x20000; // 128 KB
const PRIVATE_SIZE: i32 = 0x20000; // 128 KB

// Reserved bytes immediately before the staged input body, sized to hold the v1
// render header [type u8][pk_len u8][pk PK_LEN] = 34 bytes. Rounded up to 64.
const RENDER_HEADER_MAX: i32 = 64;
const STAGING_OFF: i32 = PRIV_USER_OFF;

export let scratch: i32 = 0;
let priv: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;
priv = heap.alloc(PRIVATE_SIZE) as i32;

export function handle(input_len: i32): i32 {
  // Input: [pk PK_LEN][type u8][body]. The shell prepends the authenticated sender pk.
  if (input_len < PK_LEN + 1) return 0;
  const type = load<u8>(scratch + PK_LEN);
  if (type != 0) return 0;                  // v1 only knows text
  const bodyLen = input_len - PK_LEN - 1;

  // Stage the input into priv so we can rebuild scratch as the render output.
  const stagedInput = priv + STAGING_OFF + RENDER_HEADER_MAX;
  const tailRoom = PRIVATE_SIZE - STAGING_OFF - RENDER_HEADER_MAX;
  if (input_len + 16 + PK_LEN > tailRoom) return 0;
  memory.copy(stagedInput, scratch, input_len);
  const stagedBody = stagedInput + PK_LEN + 1;
  const stagedPk = stagedInput + input_len + 16;
  memory.copy(stagedPk, stagedInput, PK_LEN);

  // [type u8][pk_len u8][pk PK_LEN] — written into reserved bytes before the body.
  const headerLen = 1 + 1 + PK_LEN;
  const renderBuf = stagedBody - headerLen;
  let o = renderBuf;
  store<u8>(o, type); o++;
  store<u8>(o, PK_LEN); o++;
  memory.copy(o, stagedPk, PK_LEN); o += PK_LEN;

  const renderLen = headerLen + bodyLen;
  memory.copy(scratch, renderBuf, renderLen);
  return renderLen;
}
