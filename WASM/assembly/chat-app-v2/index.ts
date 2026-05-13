// Chat backend v2 — adds image (jpeg) and nick on top of v1's text protocol.
//
// Wire format:  payload = [type u8][body ..]
//   type 0  text    body = utf-8 text
//   type 1  image   body = jpeg bytes
//   type 2  nick    body = utf-8 nick (the signer's new nick)
//
// Render:       [type u8][pk_len u8][pk ..][nick_len u8][nick ..][body ..]
//
// The handler keeps a small (pubkey -> nick) table in private memory so
// every render envelope can be tagged with the signer's most recent
// known nick — even on text/image messages where the signer didn't
// re-announce a nick.

import {
  init, isConfigured, loadTopSignerPubkey, forwardToHost,
  PRIV_USER_OFF, PK_LEN,
} from "../seedkernel/handler";

export { configure } from "../seedkernel/handler";

const SCRATCH_SIZE: i32 = 0x20000; // 128 KB
const PRIVATE_SIZE: i32 = 0x20000; // 128 KB

const MAX_NICK_LEN: i32 = 32;
const NICK_SLOTS: i32 = 32;
// per-slot: [used u8][nick_len u8][pk PK_LEN][nick MAX_NICK_LEN]
const SLOT_BYTES: i32 = 1 + 1 + PK_LEN + MAX_NICK_LEN;
const NICK_TABLE_BYTES: i32 = NICK_SLOTS * SLOT_BYTES;

// Reserved bytes immediately before the staged input body, sized to hold
// [type u8][pk_len u8][pk PK_LEN][nick_len u8][nick MAX_NICK_LEN] = 67.
// Rounded up to leave room for a future field without touching memory math.
const RENDER_HEADER_MAX: i32 = 80;

const NICK_OFF: i32 = PRIV_USER_OFF;
const STAGING_OFF: i32 = NICK_OFF + NICK_TABLE_BYTES;

export let scratch: i32 = 0;
let priv: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;
priv = heap.alloc(PRIVATE_SIZE) as i32;
init(scratch, priv);

function bytesEqual(aPtr: i32, bPtr: i32, len: i32): bool {
  for (let i = 0; i < len; i++) {
    if (load<u8>(aPtr + i) != load<u8>(bPtr + i)) return false;
  }
  return true;
}

function findNickSlot(pkPtr: i32): i32 {
  for (let i = 0; i < NICK_SLOTS; i++) {
    const off = priv + NICK_OFF + i * SLOT_BYTES;
    if (load<u8>(off) == 0) continue;
    if (bytesEqual(off + 2, pkPtr, PK_LEN)) return off;
  }
  return -1;
}

function setNick(pkPtr: i32, nickPtr: i32, nickLen: i32): void {
  let slot = findNickSlot(pkPtr);
  if (slot < 0) {
    for (let i = 0; i < NICK_SLOTS; i++) {
      const off = priv + NICK_OFF + i * SLOT_BYTES;
      if (load<u8>(off) == 0) { slot = off; break; }
    }
  }
  if (slot < 0) return;  // table full — drop silently
  const clamped = nickLen > MAX_NICK_LEN ? MAX_NICK_LEN : nickLen;
  store<u8>(slot, 1);
  store<u8>(slot + 1, clamped);
  memory.copy(slot + 2, pkPtr, PK_LEN);
  if (clamped > 0) memory.copy(slot + 2 + PK_LEN, nickPtr, clamped);
}

export function handle(input_len: i32): i32 {
  if (!isConfigured() || input_len < 1) return 0;
  const type = load<u8>(scratch);
  if (type > 2) return 0;

  // Stage the input — kernel.call will clobber scratch.
  const stagedInput = priv + STAGING_OFF + RENDER_HEADER_MAX;
  const tailRoom = PRIVATE_SIZE - STAGING_OFF - RENDER_HEADER_MAX;
  if (input_len + 64 > tailRoom) return 0;
  memory.copy(stagedInput, scratch, input_len);
  const stagedBody = stagedInput + 1;
  const bodyLen = input_len - 1;

  const pkSrc = loadTopSignerPubkey();         // clobbers scratch
  if (pkSrc < 0) return 0;
  const stagedPk = stagedInput + input_len + 16;
  memory.copy(stagedPk, pkSrc, PK_LEN);

  // Update nick table BEFORE rendering so the nick message itself shows
  // the new nick already attached to its signer.
  if (type == 2) {
    setNick(stagedPk, stagedBody, bodyLen);
  }

  let nickP: i32 = 0;
  let nLen: i32 = 0;
  const slot = findNickSlot(stagedPk);
  if (slot >= 0) {
    nLen = load<u8>(slot + 1) as i32;
    nickP = slot + 2 + PK_LEN;
  }

  // [type u8][pk_len u8][pk PK_LEN][nick_len u8][nick nLen] — written into
  // the reserved bytes immediately before stagedBody so the body is not
  // copied twice.
  const headerLen = 1 + 1 + PK_LEN + 1 + nLen;
  const renderBuf = stagedBody - headerLen;
  let o = renderBuf;
  store<u8>(o, type); o++;
  store<u8>(o, PK_LEN); o++;
  memory.copy(o, stagedPk, PK_LEN); o += PK_LEN;
  store<u8>(o, nLen); o++;
  if (nLen > 0) { memory.copy(o, nickP, nLen); o += nLen; }

  forwardToHost(renderBuf, headerLen + bodyLen);
  return 0;
}
